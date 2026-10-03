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

import stix2

from addon_state import state_key, utc_now_iso
from app_connector_helper import OpenCTIGraphQLError
from deployment_reporter import RateLimiter
from opencti_features import FEATURE_HITS, FEATURE_SECURITY_PLATFORM
from utils import generate_identity_id, generate_sighting_id, to_epoch, to_iso

MAX_RECENT_WINDOWS = 50
SIGHTINGS_PER_BUNDLE = 200

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
        "_key": state_key(row.indicator_id),
        "indicator_id": row.indicator_id,
        "value": row.value or existing.get("value", ""),
        "type": row.indicator_type or existing.get("type", ""),
        "platform_id": platform_id or existing.get("platform_id", ""),
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
    def __init__(self, client, detector, platform, history, logger=None, rate_per_minute=120, author_name="Splunk"):
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
        self.author = stix2.Identity(
            id=generate_identity_id(author_name, "system"), name=author_name, identity_class="system"
        )
        self._sightings = []
        self._pending_records = []

    def _report_mutation(self, row):
        self.limiter.acquire()
        self.client.graphql_query(HITS_MUTATION, {
            "indicatorId": row.indicator_id,
            "platformId": self.platform["id"],
            "count": row.count,
            "firstHit": to_iso(row.first_hit),
            "lastHit": to_iso(row.last_hit),
        })

    def report(self, record, **fields):
        """
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
        existing = self.history.get(state_key(row.indicator_id))
        if is_replay(existing, row):
            return {"opencti_hit_status": STATUS_DUPLICATE, "opencti_hit_message": "window already reported"}
        try:
            if self.detector.require(FEATURE_HITS, "Indicator hit reporting through indicatorReportHits"):
                self._report_mutation(row)
                status = STATUS_REPORTED
            elif self.detector.require(FEATURE_SECURITY_PLATFORM, "Indicator hit sightings"):
                self._sightings.append(hits_sighting(row, self.platform["standard_id"], self.author))
                status = STATUS_REPORTED_AS_SIGHTING
            else:
                return {"opencti_hit_status": STATUS_NO_PLATFORM, "opencti_hit_message": "no Security Platform support"}
        except OpenCTIGraphQLError as ex:
            self.logger.error(f"Hit report of {row.indicator_id} failed: {ex}")
            return {"opencti_hit_status": STATUS_ERROR, "opencti_hit_message": str(ex)[:1000]}
        self._pending_records.append(merge_hit_history(existing, row, status, self.platform.get("id")))
        if status == STATUS_REPORTED:
            self._save_records()
        elif len(self._sightings) >= SIGHTINGS_PER_BUNDLE:
            self.flush()
        return {"opencti_hit_status": status, "opencti_hit_message": ""}

    def _save_records(self):
        if self._pending_records:
            records, self._pending_records = self._pending_records, []
            try:
                self.history.upsert(records)
            except Exception as ex:
                self.logger.warning(f"Unable to store the hit history in the KV Store: {ex}")

    def flush(self):
        """Send the fallback sightings bundle, then store the history."""
        if self._sightings:
            sightings, self._sightings = self._sightings, []
            bundle = stix2.Bundle(objects=[self.author] + sightings, allow_custom=True)
            self.client.register()
            self.limiter.acquire()
            self.client.send_stix_bundle(bundle.serialize())
            self.logger.info(f"{len(sightings)} hit sightings sent to OpenCTI")
        self._save_records()
