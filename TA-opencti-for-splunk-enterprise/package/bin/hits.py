"""Indicator hit reporting (| openctireporthits).

The shipped "OpenCTI - Indicator hits" searches match the opencti_indicators
KV Store against CIM data over non-overlapping, snapped windows and pipe one
row per indicator (indicator_id, hit_count, first_hit, last_hit) into the
command, which reports them to OpenCTI on the Splunk Security Platform:
- ``indicatorReportHits`` (innovation 10): increments the hit counter of the
  deployed-on relationship and of the stable hits sighting;
- on platforms without it, a STIX sighting Indicator -> Security Platform
  carrying the window and the count.
Every report is also kept in the opencti_indicator_hits collection (bounded
recent windows), which the IOC validation proof reads.
"""

import json
import logging
import time

import stix2

from addon_state import state_key, utc_now_iso
from app_connector_helper import OpenCTIGraphQLError
from deployment_reporter import RateLimiter, is_retryable
from opencti_features import FEATURE_HITS, FEATURE_SECURITY_PLATFORM
from utils import generate_identity_id, generate_sighting_id, to_epoch, to_iso

MAX_RECENT_WINDOWS = 50
SIGHTINGS_PER_BUNDLE = 200
RETRY_DELAYS_SECONDS = (2, 10)

HITS_MUTATION = """
mutation SplunkIndicatorHits($indicatorId: StixRef!, $platformId: StixRef!, $count: Int!, $lastHit: DateTime, $firstHit: DateTime) {
  indicatorReportHits(indicatorId: $indicatorId, platformId: $platformId, count: $count, lastHit: $lastHit, firstHit: $firstHit) {
    id
  }
}
"""

STATUS_REPORTED = "reported"
STATUS_REPORTED_AS_SIGHTING = "reported_as_sighting"
STATUS_DUPLICATE = "duplicate"
STATUS_INVALID = "invalid"
STATUS_ERROR = "error"
STATUS_NO_PLATFORM = "skipped_no_platform"


class HitRow:
    __slots__ = ("indicator_id", "count", "first_hit", "last_hit", "value", "indicator_type")

    def __init__(self, indicator_id, count, first_hit, last_hit, value="", indicator_type=""):
        self.indicator_id = indicator_id
        self.count = count
        self.first_hit = first_hit
        self.last_hit = last_hit
        self.value = value
        self.indicator_type = indicator_type


def parse_hit_row(record, id_field="indicator_id", count_field="hit_count", first_field="first_hit", last_field="last_hit"):
    """
    :param record: search result row
    :return: HitRow
    :raise ValueError: on a row that cannot be reported
    """
    indicator_id = str(record.get(id_field) or "").strip()
    if not indicator_id.startswith("indicator--"):
        raise ValueError(f"{id_field} must hold the indicator STIX id, got {indicator_id!r}")
    try:
        count = int(float(str(record.get(count_field) or "0")))
    except ValueError:
        raise ValueError(f"{count_field} is not a number: {record.get(count_field)!r}")
    if count < 1:
        raise ValueError(f"{count_field} must be at least 1")
    last_hit = to_epoch(record.get(last_field)) or to_epoch(record.get("_time"))
    if last_hit is None:
        raise ValueError(f"{last_field} is missing")
    first_hit = to_epoch(record.get(first_field)) or last_hit
    if first_hit > last_hit:
        first_hit, last_hit = last_hit, first_hit
    value = record.get("value")
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    return HitRow(
        indicator_id, count, first_hit, last_hit,
        value=str(value or ""), indicator_type=str(record.get("type") or ""),
    )


def hit_history_key(platform_id, indicator_id):
    """Hit histories are per Security Platform: a re-resolved platform starts afresh."""
    return state_key(platform_id, indicator_id)


def load_windows(record):
    try:
        windows = json.loads((record or {}).get("recent_windows") or "[]")
    except ValueError:
        return []
    return [w for w in windows if isinstance(w, list) and len(w) == 3]


def is_replay(existing, row):
    """A window ending at or before the last reported hit was already counted."""
    last = to_epoch((existing or {}).get("last_hit"))
    return last is not None and row.last_hit <= last


def merge_hit_history(existing, row, status, platform_id):
    """
    :param existing: opencti_indicator_hits record or None
    :param row: HitRow just reported
    :return: the updated record
    """
    existing = existing or {}
    windows = load_windows(existing)
    windows.append([row.first_hit, row.last_hit, row.count])
    windows = windows[-MAX_RECENT_WINDOWS:]
    first = to_epoch(existing.get("first_hit"))
    last = to_epoch(existing.get("last_hit"))
    return {
        "_key": hit_history_key(platform_id, row.indicator_id),
        "indicator_id": row.indicator_id,
        "value": row.value or existing.get("value", ""),
        "type": row.indicator_type or existing.get("type", ""),
        "platform_id": platform_id,
        "hit_count": int(existing.get("hit_count") or 0) + row.count,
        "first_hit": to_iso(min(first, row.first_hit) if first is not None else row.first_hit),
        "last_hit": to_iso(max(last, row.last_hit) if last is not None else row.last_hit),
        "recent_windows": json.dumps(windows),
        "last_status": status,
        "last_reported_at": utc_now_iso(),
    }


def hits_sighting(row, platform_ref, author):
    """Sighting reporting a hit window on platforms without indicatorReportHits."""
    first_seen = to_iso(row.first_hit)
    last_seen = to_iso(row.last_hit)
    return stix2.Sighting(
        id=generate_sighting_id(row.indicator_id, [platform_ref], first_seen, last_seen),
        created_by_ref=author.id,
        description="Indicator hits observed in Splunk (OpenCTI for Splunk Enterprise add-on)",
        sighting_of_ref=row.indicator_id,
        first_seen=first_seen,
        last_seen=last_seen,
        count=row.count,
        where_sighted_refs=[platform_ref],
        allow_custom=True,
        custom_properties={"x_opencti_negative": False},
    )


class HitReporter:
    def __init__(self, client, detector, platform, history, logger=None, rate_per_minute=120, author_name="Splunk",
                 sleep=time.sleep):
        """
        :param client: SplunkAppConnectorHelper
        :param detector: OpenCTIFeatureDetector
        :param platform: Splunk Security Platform node (id, standard_id) or None
        :param history: addon_state.KVCollection over opencti_indicator_hits (or a fake)
        """
        self.client = client
        self.detector = detector
        self.platform = platform or {}
        self.history = history
        self.logger = logger or logging.getLogger(__name__)
        self.limiter = RateLimiter(rate_per_minute)
        self.sleep = sleep
        self.author = stix2.Identity(
            id=generate_identity_id(author_name, "system"), name=author_name, identity_class="system"
        )
        # Latest history per indicator for this search: replays inside one
        # search are detected before the KV Store is written.
        self._latest = {}
        # Fallback sightings waiting for flush(), with the history they record
        self._pending_sightings = []

    def _with_retry(self, call):
        """
        Run ``call`` again on transport and rate-limit failures: the next search
        reports the next window, so a window not sent now is lost.
        """
        for delay in RETRY_DELAYS_SECONDS:
            try:
                self.limiter.acquire()
                return call()
            except OpenCTIGraphQLError as ex:
                if not is_retryable(ex):
                    raise
                self.logger.warning(f"Hit report failed, retrying in {delay} s: {ex}")
                self.sleep(delay)
        self.limiter.acquire()
        return call()

    def _report_mutation(self, row):
        self._with_retry(lambda: self.client.graphql_query(HITS_MUTATION, {
            "indicatorId": row.indicator_id,
            "platformId": self.platform["id"],
            "count": row.count,
            "firstHit": to_iso(row.first_hit),
            "lastHit": to_iso(row.last_hit),
        }))

    def _history(self, indicator_id):
        if indicator_id in self._latest:
            return self._latest[indicator_id]
        return self.history.get(hit_history_key(self.platform.get("id"), indicator_id))

    def report(self, record, **fields):
        """
        Report the hits of one row. Mutation reports are sent right away;
        fallback sightings are sent by flush(), which the caller runs after
        the rows of a chunk and which tells which of them failed.

        :param record: search result row
        :param fields: field names (id_field, count_field, first_field, last_field)
        :return: dict merged into the output row (opencti_hit_status, opencti_hit_message)
        """
        try:
            row = parse_hit_row(record, **fields)
        except ValueError as ex:
            return {"opencti_hit_status": STATUS_INVALID, "opencti_hit_message": str(ex)}
        if not self.platform.get("id"):
            return {
                "opencti_hit_status": STATUS_NO_PLATFORM,
                "opencti_hit_message": "No Splunk Security Platform (Configuration > Security Platform)",
            }
        existing = self._history(row.indicator_id)
        if is_replay(existing, row):
            return {"opencti_hit_status": STATUS_DUPLICATE, "opencti_hit_message": "window already reported"}
        if self.detector.require(FEATURE_HITS, "Indicator hit reporting through indicatorReportHits"):
            try:
                self._report_mutation(row)
            except OpenCTIGraphQLError as ex:
                self.logger.error(f"Hit report of {row.indicator_id} failed: {ex}")
                return {"opencti_hit_status": STATUS_ERROR, "opencti_hit_message": str(ex)[:1000]}
            history = merge_hit_history(existing, row, STATUS_REPORTED, self.platform.get("id"))
            self._latest[row.indicator_id] = history
            error = self._save([history])
            return {
                "opencti_hit_status": STATUS_REPORTED,
                "opencti_hit_message": f"hit history not stored in the KV Store: {error}" if error else "",
            }
        if self.detector.require(FEATURE_SECURITY_PLATFORM, "Indicator hit sightings"):
            history = merge_hit_history(existing, row, STATUS_REPORTED_AS_SIGHTING, self.platform.get("id"))
            self._latest[row.indicator_id] = history
            self._pending_sightings.append(
                (row.indicator_id, hits_sighting(row, self.platform["standard_id"], self.author), history)
            )
            return {"opencti_hit_status": STATUS_REPORTED_AS_SIGHTING, "opencti_hit_message": ""}
        return {"opencti_hit_status": STATUS_NO_PLATFORM, "opencti_hit_message": "no Security Platform support"}

    def _save(self, records):
        """
        :return: None, or the error when the history could not be stored (the
            IOC validation proof then cross-checks the hits OpenCTI recorded)
        """
        if not records:
            return None
        try:
            self.history.upsert(records)
        except Exception as ex:
            self.logger.warning(f"Unable to store the hit history in the KV Store: {ex}")
            return str(ex)[:500]
        return None

    def flush(self):
        """
        Send the pending fallback sightings in bundles of SIGHTINGS_PER_BUNDLE.
        The history of a sighting is stored only once its bundle was accepted.

        :return: dict indicator id -> error message, for the sightings not sent
        """
        failed = {}
        pending, self._pending_sightings = self._pending_sightings, []
        for start in range(0, len(pending), SIGHTINGS_PER_BUNDLE):
            chunk = pending[start:start + SIGHTINGS_PER_BUNDLE]
            bundle = stix2.Bundle(objects=[self.author] + [sighting for _, sighting, _ in chunk], allow_custom=True)
            try:
                self.client.register()
                serialized = bundle.serialize()
                self._with_retry(lambda: self.client.send_stix_bundle(serialized))
            except Exception as ex:
                self.logger.error(f"{len(chunk)} hit sightings not sent to OpenCTI: {ex}")
                for indicator_id, _, _ in chunk:
                    failed[indicator_id] = str(ex)[:1000]
                    # The window was not counted: a later report of it is not a replay.
                    self._latest.pop(indicator_id, None)
                continue
            self.logger.info(f"{len(chunk)} hit sightings sent to OpenCTI")
            self._save([history for _, _, history in chunk])
        return failed
