"""Shared plumbing of the OpenCTI alert actions.

- One OpenCTI client, feature detector and Security Platform resolution per
  alert run, cached in the KV Store across runs.
- Per-result error accounting: process_event returns 2 when at least one
  result failed, so Splunk reports the alert action failure (#18).
- Follow-ups (timeline milestones) that need the container created by the
  bundle: bundles are ingested asynchronously by the OpenCTI workers, so
  follow-ups run after every result was sent, once the containers exist
  (bounded wait). A follow-up whose container is still not ingested, or that
  failed, is parked in the add-on state collection and retried by the next
  alert runs (follow-ups are idempotent).
"""

import json
import time

from addon_config import is_true, settings_from_alert_helper
from addon_state import KVStoreCache, MemoryCache, connect_service, state_key, utc_now_iso
from constants import ADDON_NAME
from opencti_features import OpenCTIFeatureDetector
from program_actions import run_followup
from security_platform import SecurityPlatformResolver
from utils import parse_iso

ALERT_FAILURE_EXIT_CODE = 2
# Total seconds an alert run waits for the containers it created.
FOLLOWUP_WAIT_SECONDS = 60
FOLLOWUP_POLL_SECONDS = (2, 3, 5, 5, 10, 10, 10, 15)
FOLLOWUP_PARKED_PREFIX = "alert_followup|"
# A parked follow-up is retried by later alert runs within this delay...
FOLLOWUP_PARKED_SECONDS = 86400
# ...and dropped once it failed (not merely waited) this many times.
FOLLOWUP_MAX_FAILURES = 5
FOLLOWUP_RETRIED_PER_RUN = 100

EXISTING_OBJECTS_QUERY = """
query SplunkExistingObjects($filters: FilterGroup, $first: Int) {
  stixCoreObjects(first: $first, filters: $filters) {
    edges { node { id standard_id } }
  }
}
"""


class HelperLogger:
    """logging.Logger-like adapter over the alert action helper."""

    def __init__(self, helper):
        self.helper = helper

    def debug(self, message):
        self.helper.log_debug(message)

    def info(self, message):
        self.helper.log_info(message)

    def warning(self, message):
        self.helper.log_warn(message)

    warn = warning

    def error(self, message):
        self.helper.log_error(message)


def parse_labels(raw):
    """
    :param raw: comma separated labels
    :return: list of non-empty, stripped labels
    """
    if not raw:
        return []
    return [label for label in (x.strip() for x in str(raw).split(",")) if label]


class AlertContext:
    def __init__(self, helper, settings=None, client=None):
        self.helper = helper
        self.logger = HelperLogger(helper)
        self.settings = settings or settings_from_alert_helper(helper)
        self.client = client or self.settings.build_client()
        self._service = None
        self._cache = None
        self._detector = None
        self._resolver = None
        self.followups = []

    @property
    def payload(self):
        return getattr(self.helper, "settings", None) or {}

    @property
    def search_name(self):
        return getattr(self.helper, "search_name", None) or self.payload.get("search_name") or "Splunk alert"

    @property
    def results_link(self):
        return self.payload.get("results_link") or ""

    @property
    def sid(self):
        """:return: Splunk search id of the triggered alert ("" when unknown)"""
        return self.payload.get("sid") or ""

    @property
    def service(self):
        if self._service is None:
            self._service = connect_service(
                self.helper.session_key, ADDON_NAME, self.payload.get("server_uri")
            )
        return self._service

    @property
    def cache(self):
        if self._cache is None:
            try:
                self._cache = KVStoreCache(self.service)
            except Exception as ex:
                self.logger.warning(f"Add-on state collection unavailable, caching in memory only: {ex}")
                self._cache = MemoryCache()
        return self._cache

    @property
    def detector(self):
        if self._detector is None:
            self._detector = OpenCTIFeatureDetector(
                self.client, logger=self.logger, cache=self.cache, ttl=self.settings.feature_cache_ttl
            )
        return self._detector

    @property
    def resolver(self):
        if self._resolver is None:
            self._resolver = SecurityPlatformResolver(
                self.client,
                self.detector,
                self.settings.platform,
                server_name=self.settings.server_name,
                cache=self.cache,
                logger=self.logger,
            )
        return self._resolver

    @property
    def platform(self):
        """:return: the Splunk Security Platform node, or None"""
        return self.resolver.resolve()

    def param(self, name, default=None):
        value = self.helper.get_param(name)
        return default if value is None else value

    def flag(self, name, default=False):
        return is_true(self.helper.get_param(name), default)

    def defer(self, entity_id, description, kind, params):
        """
        Run the follow-up ``kind`` (program_actions.run_followup) once the
        object ``entity_id`` exists in OpenCTI.

        :param entity_id: STIX id of the object created by a bundle
        :param description: for logs
        :param kind: program_actions.FOLLOWUP_*
        :param params: JSON parameters (a later alert run may run it)
        """
        self.followups.append({"entity_id": entity_id, "description": description, "kind": kind, "params": params})

    def _existing(self, ids):
        found = set()
        for start in range(0, len(ids), 100):
            chunk = ids[start:start + 100]
            data = self.client.graphql_query(EXISTING_OBJECTS_QUERY, {
                "first": len(chunk) * 2,
                "filters": {"mode": "and", "filters": [{"key": ["ids"], "values": chunk}], "filterGroups": []},
            })
            for edge in ((data.get("stixCoreObjects") or {}).get("edges")) or []:
                node = (edge or {}).get("node") or {}
                for key in ("id", "standard_id"):
                    if node.get(key):
                        found.add(node[key])
        return found

    def _found(self, ids):
        try:
            return self._existing(sorted(set(ids)))
        except Exception as ex:
            self.logger.warning(f"Unable to check the objects created in OpenCTI: {ex}")
            return set()

    def _run_followup(self, followup):
        """:return: True when done, False when it failed"""
        try:
            run_followup(self, followup.get("kind"), followup.get("entity_id"), followup.get("params") or {})
            return True
        except Exception as ex:
            self.logger.warning(f"{followup.get('description')} for {followup.get('entity_id')} failed: {ex}")
            return False

    def _parked_prefix(self):
        return f"{FOLLOWUP_PARKED_PREFIX}{self.client.opencti_url}|"

    def _park(self, followup, reason):
        """:return: True when parked for the next alert runs"""
        description, entity_id = followup["description"], followup["entity_id"]
        if not getattr(self.cache, "persistent", False):
            self.logger.warning(
                f"{description} for {entity_id} skipped: {reason}, and the add-on state collection is "
                "unavailable to retry it"
            )
            return False
        params = followup.get("params") or {}
        # One entry per follow-up, triggered alert and container
        key = self._parked_prefix() + state_key(
            followup["kind"], entity_id, params.get("search_name"), params.get("sid")
        )
        try:
            self.cache.set(key, dict(followup, parked_at=utc_now_iso()))
        except Exception as ex:
            self.logger.error(f"{description} for {entity_id} lost: {reason}, and it cannot be parked: {ex}")
            return False
        self.logger.warning(f"{description} for {entity_id} deferred: {reason}; the next alert runs retry it")
        return True

    @staticmethod
    def _parked_problem(followup):
        """:return: why a parked record cannot be retried, "" when it can"""
        if not followup.get("entity_id") or not followup.get("kind"):
            return "malformed record"
        if not isinstance(followup.get("params") or {}, dict) or not str(followup.get("failures") or 0).isdigit():
            return "malformed record"
        parked_at = parse_iso(followup.get("parked_at"))
        if parked_at is None or time.time() - parked_at.timestamp() > FOLLOWUP_PARKED_SECONDS:
            return f"not ingested by OpenCTI within {FOLLOWUP_PARKED_SECONDS // 3600}h"
        return ""

    def _retry_one(self, key, followup, found):
        if followup["entity_id"] not in found:
            return
        if self._run_followup(followup):
            self.cache.release(key)
            return
        failures = int(followup.get("failures") or 0) + 1
        if failures < FOLLOWUP_MAX_FAILURES:
            self.cache.set(key, dict(followup, failures=failures))
            return
        self.logger.error(
            f"{followup.get('description')} for {followup['entity_id']} dropped after {failures} failed attempts"
        )
        self.cache.release(key)

    def _retry_parked(self):
        """Run the follow-ups parked by earlier alert runs whose objects now exist."""
        if not getattr(self.cache, "persistent", False):
            return
        try:
            parked = self.cache.items(self._parked_prefix(), limit=FOLLOWUP_RETRIED_PER_RUN)
        except Exception as ex:
            self.logger.warning(f"Parked follow-ups not retried: {ex}")
            return
        live = []
        for key, followup in parked:
            problem = self._parked_problem(followup)
            if not problem:
                live.append((key, followup))
                continue
            self.logger.error(f"{followup.get('description')} for {followup.get('entity_id')} dropped: {problem}")
            try:
                self.cache.release(key)
            except Exception as ex:
                self.logger.warning(f"Parked follow-up {key} not released: {ex}")
        found = self._found([followup["entity_id"] for _, followup in live]) if live else set()
        # One entry failing never keeps the others waiting
        for key, followup in live:
            try:
                self._retry_one(key, followup, found)
            except Exception as ex:
                self.logger.warning(f"Parked follow-up {key} not retried: {ex}")
        # items() returns the least recently written entries first: the ones still
        # waiting go behind the others, so beyond FOLLOWUP_RETRIED_PER_RUN parked
        # entries the runs take them in turn instead of the same ones every time.
        waiting = [(key, followup) for key, followup in live if followup["entity_id"] not in found]
        if waiting:
            try:
                self.cache.touch(waiting)
            except Exception as ex:
                self.logger.warning(f"Parked follow-ups not moved behind the others: {ex}")

    def run_followups(self, sleep=time.sleep, budget=FOLLOWUP_WAIT_SECONDS):
        """
        Retry the follow-ups parked by earlier alert runs, then run those of
        this run once their objects exist. A follow-up whose object is not
        ingested within ``budget``, or that failed, is parked (not a failure
        of the alert: follow-ups are idempotent).

        :return: number of follow-ups of this run that could not run yet
        """
        pending = list(self.followups)
        self.followups = []
        self._retry_parked()
        failed = []
        waited = 0.0
        attempt = 0
        while pending:
            found = self._found([followup["entity_id"] for followup in pending])
            remaining = []
            for followup in pending:
                if followup["entity_id"] not in found:
                    remaining.append(followup)
                elif not self._run_followup(followup):
                    failed.append(followup)
            pending = remaining
            if not pending:
                break
            delay = FOLLOWUP_POLL_SECONDS[min(attempt, len(FOLLOWUP_POLL_SECONDS) - 1)]
            if waited + delay > budget:
                break
            sleep(delay)
            waited += delay
            attempt += 1
        for followup in pending:
            self._park(followup, f"{followup['entity_id']} was not ingested by OpenCTI within {int(budget)}s")
        for followup in failed:
            self._park(dict(followup, failures=1), "it failed")
        return len(pending) + len(failed)


def run_alert(helper, action_name, handler, context_factory=AlertContext):
    """
    Process every result of the alert with ``handler(context, event)``.

    :param helper: ModularAlertBase
    :param action_name: alert action name (logs)
    :param handler: callable returning True on success
    :param context_factory: AlertContext (tests inject a fake)
    :return: process exit code: 0 when every result succeeded, 2 otherwise
    """
    helper.log_info(f"Alert action {action_name} started.")
    helper.set_log_level(helper.log_level)
    try:
        context = context_factory(helper)
    except Exception as ex:
        helper.log_error(f"Alert action {action_name} cannot start: {ex}")
        return ALERT_FAILURE_EXIT_CODE
    total = 0
    failures = 0
    for event in helper.get_events():
        total += 1
        helper.log_debug("event={}".format(json.dumps(event)))
        try:
            succeeded = handler(context, event)
        except Exception as ex:
            helper.log_error(f"Alert action {action_name} failed on result {event.get('rid', total - 1)}: {ex}")
            succeeded = False
        if not succeeded:
            failures += 1
    context.run_followups()
    if failures:
        helper.log_error(f"Alert action {action_name}: {failures} of {total} results failed")
        return ALERT_FAILURE_EXIT_CODE
    helper.log_info(f"Alert action {action_name} completed: {total} results processed")
    return 0
