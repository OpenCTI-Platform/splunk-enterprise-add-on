"""Shared plumbing of the OpenCTI alert actions.

- One OpenCTI client, feature detector and Security Platform resolution per
  alert run, cached in the KV Store across runs.
- Per-result error accounting: process_event returns 2 when at least one
  result failed, so Splunk reports the alert action failure (#18).
- Follow-ups (timeline milestones, Case Autopilot launches) that need the
  container created by the bundle: bundles are ingested asynchronously by
  the OpenCTI workers, so follow-ups run after every result was sent, once
  the containers exist (bounded wait).
"""

import json
import time

from addon_config import is_true, settings_from_alert_helper
from addon_state import KVStoreCache, MemoryCache, connect_service
from constants import ADDON_NAME
from opencti_features import OpenCTIFeatureDetector
from security_platform import SecurityPlatformResolver

ALERT_FAILURE_EXIT_CODE = 2
# Total seconds an alert run waits for the containers it created.
FOLLOWUP_WAIT_SECONDS = 60
FOLLOWUP_POLL_SECONDS = (2, 3, 5, 5, 10, 10, 10, 15)

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

    def defer(self, entity_id, description, action):
        """
        Run ``action()`` once the object ``entity_id`` exists in OpenCTI.

        :param entity_id: STIX id of the object created by a bundle
        :param description: for logs
        :param action: callable without arguments
        """
        self.followups.append((entity_id, description, action))

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

    def run_followups(self, sleep=time.sleep, budget=FOLLOWUP_WAIT_SECONDS):
        """
        :return: number of follow-ups that could not run (not failures of
            the alert: they are retried by the next run of the alert, the
            follow-ups being idempotent)
        """
        if not self.followups:
            return 0
        pending = list(self.followups)
        self.followups = []
        waited = 0.0
        attempt = 0
        while pending:
            ids = sorted({entity_id for entity_id, _, _ in pending})
            try:
                found = self._existing(ids)
            except Exception as ex:
                self.logger.warning(f"Unable to check the objects created in OpenCTI: {ex}")
                found = set()
            remaining = []
            for entity_id, description, action in pending:
                if entity_id not in found:
                    remaining.append((entity_id, description, action))
                    continue
                try:
                    action()
                except Exception as ex:
                    self.logger.warning(f"{description} for {entity_id} failed: {ex}")
            pending = remaining
            if not pending:
                break
            delay = FOLLOWUP_POLL_SECONDS[min(attempt, len(FOLLOWUP_POLL_SECONDS) - 1)]
            if waited + delay > budget:
                break
            sleep(delay)
            waited += delay
            attempt += 1
        for entity_id, description, _ in pending:
            self.logger.warning(
                f"{description} skipped: {entity_id} was not ingested by OpenCTI within {int(budget)}s "
                "(the next run of this alert adds it, the operation is idempotent)"
            )
        return len(pending)


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
