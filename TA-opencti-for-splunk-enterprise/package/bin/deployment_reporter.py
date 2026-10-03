"""Deployment write-back: tell OpenCTI which indicators are live in Splunk.

The modular input calls ``report()`` after each KV Store / index write (or
failure, or removal) of an indicator. Reports are queued, deduplicated per
indicator (the last state wins), and flushed in batches through
``indicatorReportDeployments`` (or one ``indicatorReportDeployment`` per
indicator on platforms without the batch mutation), under a rate limit.
OpenCTI applies the reports idempotently, so a replay after a restart only
refreshes ``last_sync_at``; drift left by a crash between a write and a flush
is repaired by the reconciliation search (openctireconcile).
"""

import logging
import time
from collections import OrderedDict
from datetime import datetime, timezone

from addon_state import state_key, utc_now_iso
from app_connector_helper import OpenCTIGraphQLError
from opencti_features import FEATURE_DEPLOYMENT, FEATURE_DEPLOYMENT_BATCH
from security_platform import PLATFORM_MISSING_ERROR
from utils import parse_iso, to_iso

STATUS_DEPLOYED = "deployed"
STATUS_REMOVED = "removed"
STATUS_FAILED = "failed"
STATUS_EXPIRED = "expired"
STATUSES = (STATUS_DEPLOYED, STATUS_REMOVED, STATUS_FAILED, STATUS_EXPIRED)

MAX_BATCH_SIZE = 500  # server side limit of indicatorReportDeployments
MAX_PENDING = 20000  # memory bound of the queue
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = (15.0, 60.0, 300.0)
# Longest a short-lived command waits on the backoff before exiting (drain)
DRAIN_MAX_WAIT_SECONDS = 90.0
ERROR_MESSAGE_MAX = 5000
EXTERNAL_ID_MAX = 1000

REPORT_ONE_MUTATION = """
mutation SplunkIndicatorReportDeployment(
  $indicatorId: StixRef!
  $platformId: StixRef!
  $status: IndicatorDeploymentStatus!
  $externalId: String
  $metadata: IndicatorDeploymentMetadataInput
) {
  indicatorReportDeployment(
    indicatorId: $indicatorId
    platformId: $platformId
    status: $status
    externalId: $externalId
    metadata: $metadata
  ) { id deployment_status }
}
"""

REPORT_BATCH_MUTATION = """
mutation SplunkIndicatorReportDeployments($platformId: StixRef!, $reports: [IndicatorDeploymentReportInput!]!) {
  indicatorReportDeployments(platformId: $platformId, reports: $reports) {
    processed created updated unchanged
    errors { indicatorId message }
  }
}
"""


def removal_status(payload, now=None):
    """
    Decide whether the removal of an indicator from Splunk is an expiry.

    :param payload: STIX indicator as received from the stream
    :param now: aware datetime (tests)
    :return: STATUS_EXPIRED when valid_until is in the past, STATUS_REMOVED otherwise
    """
    now = now or datetime.now(timezone.utc)
    valid_until = parse_iso((payload or {}).get("valid_until"))
    if valid_until is not None and valid_until <= now:
        return STATUS_EXPIRED
    return STATUS_REMOVED


def reported_status(status):
    """
    :return: the status sent to OpenCTI. OpenCTI reserves "expired" to removals
        no consumer confirmed: an indicator Splunk dropped at its valid_until is
        reported removed, with removed_at = valid_until.
    """
    return STATUS_REMOVED if status == STATUS_EXPIRED else status


def is_retryable(error):
    """
    :param error: OpenCTIGraphQLError
    :return: True for transport, HTTP and rate-limit failures, False for a
        GraphQL rejection of the report itself
    """
    if not error.errors:
        return True
    return error.mentions("rate limit") or error.mentions("too many")


class RateLimiter:
    """Token bucket: at most ``per_minute`` calls per rolling minute, bursts allowed."""

    def __init__(self, per_minute, clock=time.monotonic, sleep=time.sleep):
        self.capacity = max(1, int(per_minute))
        self.rate = self.capacity / 60.0
        self.tokens = float(self.capacity)
        self.clock = clock
        self.sleep = sleep
        self.updated = clock()

    def _refill(self):
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now

    def acquire(self):
        """Block until a call is allowed. :return: seconds waited"""
        self._refill()
        waited = 0.0
        if self.tokens < 1:
            waited = (1 - self.tokens) / self.rate
            self.sleep(waited)
            self._refill()
        self.tokens = max(0.0, self.tokens - 1)
        return waited


class DeploymentReport:
    __slots__ = ("indicator_id", "status", "external_id", "error_message", "removed_at", "deployed_at", "synced_at", "attempts")

    def __init__(self, indicator_id, status, external_id=None, error_message=None, removed_at=None, deployed_at=None):
        if status not in STATUSES:
            raise ValueError(f"Unknown deployment status {status!r}")
        self.indicator_id = indicator_id
        self.status = status
        self.external_id = str(external_id)[:EXTERNAL_ID_MAX] if external_id else None
        self.error_message = str(error_message)[:ERROR_MESSAGE_MAX] if error_message else None
        self.removed_at = to_iso(removed_at)
        self.deployed_at = to_iso(deployed_at)
        self.synced_at = to_iso(datetime.now(timezone.utc))
        self.attempts = 0

    def metadata(self):
        metadata = {"last_sync_at": self.synced_at}
        if self.deployed_at and self.status == STATUS_DEPLOYED:
            metadata["deployed_at"] = self.deployed_at
        if self.removed_at and self.status in (STATUS_REMOVED, STATUS_EXPIRED):
            metadata["removed_at"] = self.removed_at
        if self.error_message and self.status == STATUS_FAILED:
            metadata["error_message"] = self.error_message
        return metadata

    def as_batch_input(self):
        entry = {"indicatorId": self.indicator_id, "status": self.status, "metadata": self.metadata()}
        if self.external_id:
            entry["externalId"] = self.external_id
        return entry

    def as_record(self, result, error=None):
        """
        :param result: "ok" or "error"
        :return: opencti_deployments KV record
        """
        if result == "error":
            message = error or self.error_message or ""
        else:
            message = self.error_message if self.status == STATUS_FAILED else ""
        return {
            "_key": state_key(self.indicator_id),
            "indicator_id": self.indicator_id,
            "status": self.status,
            "external_id": self.external_id or "",
            "result": result,
            "error": message or "",
            "reported_at": utc_now_iso(),
        }


class DeploymentReporter:
    def __init__(
        self,
        client,
        detector,
        platform_id,
        batch_size=100,
        flush_interval=10.0,
        rate_per_minute=60,
        logger=None,
        state_sink=None,
        clock=time.monotonic,
        sleep=time.sleep,
        on_platform_missing=None,
    ):
        """
        :param client: SplunkAppConnectorHelper
        :param detector: OpenCTIFeatureDetector
        :param platform_id: id of the Splunk Security Platform in OpenCTI, or
            a callable returning it (resolved lazily, None when unavailable)
        :param batch_size: reports per call (1-500)
        :param flush_interval: seconds after which a partial batch is sent
        :param rate_per_minute: maximum write-back calls per minute
        :param state_sink: optional callable(list of KV records) keeping the
            local view of the write-back (opencti_deployments collection)
        :param on_platform_missing: optional callable run when OpenCTI does not
            know the platform id (SecurityPlatformResolver.invalidate); the
            reports are retried and the next flush resolves the platform again
        """
        self.client = client
        self.detector = detector
        self._platform_id = platform_id
        self.batch_size = max(1, min(int(batch_size or 100), MAX_BATCH_SIZE))
        self.flush_interval = float(flush_interval)
        self.limiter = RateLimiter(rate_per_minute, clock=clock, sleep=sleep)
        self.logger = logger or logging.getLogger(__name__)
        self.state_sink = state_sink
        self.on_platform_missing = on_platform_missing
        self.clock = clock
        self.sleep = sleep
        self.pending = OrderedDict()
        self.last_flush = clock()
        self.retry_after = 0.0
        self.stats = {"sent": 0, "created": 0, "updated": 0, "unchanged": 0, "errors": 0, "dropped": 0, "deferred": 0}

    @property
    def platform_id(self):
        return self._platform_id() if callable(self._platform_id) else self._platform_id

    @property
    def enabled(self):
        # Either mutation carries the reports (_send picks the batch one when present).
        available = self.detector.has(FEATURE_DEPLOYMENT_BATCH) or self.detector.require(
            FEATURE_DEPLOYMENT, "Indicator deployment write-back"
        )
        return available and bool(self.platform_id)

    def report(self, indicator_id, status, external_id=None, error_message=None, removed_at=None, deployed_at=None):
        """Queue a deployment state. The most recent state of an indicator wins.

        :return: True when queued, False when the write-back is unavailable
        """
        if not indicator_id or not self.enabled:
            return False
        status = reported_status(status)
        report = DeploymentReport(indicator_id, status, external_id, error_message, removed_at, deployed_at)
        self.pending.pop(indicator_id, None)
        self.pending[indicator_id] = report
        while len(self.pending) > MAX_PENDING:
            dropped_id, _ = self.pending.popitem(last=False)
            self.stats["dropped"] += 1
            self.logger.warning(
                f"Deployment write-back queue full, dropped the oldest report ({dropped_id}); "
                "the reconciliation search repairs it"
            )
        if len(self.pending) >= self.batch_size and self.clock() >= self.retry_after:
            self.flush()
        return True

    def flush_if_due(self):
        if self.pending and self.clock() - self.last_flush >= self.flush_interval:
            self.flush()

    def flush(self, force=False):
        """
        Send pending reports, batch by batch, stopping at the first transport
        failure (the failed batch stays queued with a backoff).

        :param force: ignore the retry backoff (final flush)
        :return: number of reports accepted by OpenCTI
        """
        self.last_flush = self.clock()
        if not self.pending or (not force and self.clock() < self.retry_after):
            return 0
        sent = 0
        while self.pending:
            batch = []
            while self.pending and len(batch) < self.batch_size:
                _, report = self.pending.popitem(last=False)
                batch.append(report)
            accepted = self._send(batch)
            if accepted is None:
                break
            sent += accepted
        return sent

    def drain(self, max_wait=DRAIN_MAX_WAIT_SECONDS):
        """
        Final flush of a short-lived command: the reports a transient failure
        left queued are retried through the backoff, waiting at most
        ``max_wait`` seconds in total. The reports still queued then are
        counted as deferred and logged; the next reconciliation run plans them
        again.

        :return: number of reports accepted by OpenCTI
        """
        sent = self.flush(force=True)
        waited = 0.0
        while self.pending:
            wait = max(0.0, self.retry_after - self.clock())
            if waited + wait > max_wait:
                break
            if wait:
                self.sleep(wait)
                waited += wait
            sent += self.flush(force=True)
        if self.pending:
            self.stats["deferred"] += len(self.pending)
            self.logger.warning(
                f"Deployment write-back: {len(self.pending)} reports not accepted before exit, "
                "the next reconciliation run reports them again"
            )
            self.pending.clear()
        return sent

    def _send(self, batch):
        if self.detector.has(FEATURE_DEPLOYMENT_BATCH):
            return self._send_batch(batch)
        sent = 0
        for index, report in enumerate(batch):
            accepted = self._send_one(report)
            if accepted is None:
                for remaining in batch[index + 1:]:
                    self._requeue(remaining)
                return None
            sent += accepted
        return sent

    def _requeue(self, report):
        if report.indicator_id not in self.pending:
            self.pending[report.indicator_id] = report
            self.pending.move_to_end(report.indicator_id, last=False)

    def _defer(self, reports, error):
        """Keep the reports for a later flush, or drop them after MAX_ATTEMPTS."""
        attempts = 0
        for report in reports:
            report.attempts += 1
            attempts = max(attempts, report.attempts)
            if report.attempts < MAX_ATTEMPTS:
                self._requeue(report)
            else:
                self.stats["errors"] += 1
                self.logger.error(
                    f"Deployment write-back of {report.indicator_id} ({report.status}) abandoned after "
                    f"{MAX_ATTEMPTS} attempts, the reconciliation search repairs it: {error}"
                )
                self._record([report.as_record("error", str(error))])
        backoff = RETRY_BACKOFF_SECONDS[min(attempts, len(RETRY_BACKOFF_SECONDS)) - 1] if attempts else 0
        self.retry_after = self.clock() + backoff

    def _platform_missing(self, error):
        """
        :return: True when OpenCTI rejected the platform id itself
        """
        if not error.mentions(PLATFORM_MISSING_ERROR):
            return False
        self.logger.warning("OpenCTI does not know the Splunk Security Platform anymore: resolving it again")
        if self.on_platform_missing is not None:
            self.on_platform_missing()
        return True

    def _record(self, records):
        if self.state_sink is None or not records:
            return
        try:
            self.state_sink(records)
        except Exception as ex:
            self.logger.warning(f"Unable to store the deployment write-back state in the KV Store: {ex}")

    def _send_batch(self, batch):
        self.limiter.acquire()
        try:
            data = self.client.graphql_query(REPORT_BATCH_MUTATION, {
                "platformId": self.platform_id,
                "reports": [report.as_batch_input() for report in batch],
            })
        except OpenCTIGraphQLError as ex:
            self.logger.warning(f"Deployment write-back batch of {len(batch)} reports failed: {ex}")
            self._platform_missing(ex)
            self._defer(batch, ex)
            return None
        self.retry_after = 0.0
        result = data.get("indicatorReportDeployments") or {}
        errors = {}
        for error in result.get("errors") or []:
            errors[error.get("indicatorId")] = error.get("message") or "unknown error"
        records = []
        for report in batch:
            message = errors.get(report.indicator_id)
            if message is None:
                records.append(report.as_record("ok"))
            else:
                self.stats["errors"] += 1
                self.logger.error(f"Deployment write-back of {report.indicator_id} rejected by OpenCTI: {message}")
                records.append(report.as_record("error", message))
        for key in ("created", "updated", "unchanged"):
            self.stats[key] += int(result.get(key) or 0)
        accepted = len(batch) - len(errors)
        self.stats["sent"] += accepted
        self._record(records)
        self.logger.info(
            f"Deployment write-back: {len(batch)} reports sent to OpenCTI "
            f"(created={result.get('created', 0)} updated={result.get('updated', 0)} "
            f"unchanged={result.get('unchanged', 0)} rejected={len(errors)})"
        )
        return accepted

    def _send_one(self, report):
        self.limiter.acquire()
        variables = {
            "indicatorId": report.indicator_id,
            "platformId": self.platform_id,
            "status": report.status,
            "externalId": report.external_id,
            "metadata": report.metadata(),
        }
        try:
            self.client.graphql_query(REPORT_ONE_MUTATION, variables)
        except OpenCTIGraphQLError as ex:
            if self._platform_missing(ex) or is_retryable(ex):
                self.logger.warning(f"Deployment write-back of {report.indicator_id} failed: {ex}")
                self._defer([report], ex)
                return None
            self.stats["errors"] += 1
            self.logger.error(f"Deployment write-back of {report.indicator_id} rejected by OpenCTI: {ex}")
            self._record([report.as_record("error", str(ex))])
            return 0
        self.retry_after = 0.0
        self.stats["sent"] += 1
        self._record([report.as_record("ok")])
        return 1
