"""Shared plumbing of the OpenCTI alert actions.

- One OpenCTI client, feature detector and Security Platform resolution per
  alert run, cached in the KV Store across runs.
- Per-result error accounting: process_event returns 2 when at least one
  result failed, so Splunk reports the alert action failure (#18).
"""

import json

from addon_config import is_true, settings_from_alert_helper
from addon_state import KVStoreCache, MemoryCache, connect_service
from constants import ADDON_NAME
from opencti_features import OpenCTIFeatureDetector
from security_platform import SecurityPlatformResolver

ALERT_FAILURE_EXIT_CODE = 2


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

    @property
    def payload(self):
        return getattr(self.helper, "settings", None) or {}

    @property
    def search_name(self):
        return getattr(self.helper, "search_name", None) or self.payload.get("search_name") or "Splunk alert"

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
    if failures:
        helper.log_error(f"Alert action {action_name}: {failures} of {total} results failed")
        return ALERT_FAILURE_EXIT_CODE
    helper.log_info(f"Alert action {action_name} completed: {total} results processed")
    return 0
