"""IOC validation proof (| openctivalidation).

OpenCTI (innovation 10) asks OpenAEV to run benign tests built from
indicators deployed on security platforms. For the requests that target the
Splunk Security Platform, Splunk can prove the outcome from its own data: the
"OpenCTI - Indicator hits" searches record every hit window per indicator in
opencti_indicator_hits, and a test is

- detected when a hit window of the indicator overlaps the test window
  (dispatch -> completion, widened by the configured grace period);
- missed when the request is completed, the grace period is over and no hit
  window overlaps;
- requested (no result yet) otherwise.

Outcomes are written back once per request and indicator:
``iocValidationReportResults`` when the platform has it (requested on
OpenCTI-Platform/opencti#18680), otherwise a STIX bundle with the deployed-on
relationship carrying validation_status / validation_run_id /
last_validation_at and, for a miss, a sighting with x_opencti_negative.
"""

import logging
from datetime import datetime, timedelta, timezone

import stix2

from addon_state import state_key, utc_now_iso
from hits import load_windows
from opencti_features import FEATURE_HITS, FEATURE_IOC_VALIDATION, FEATURE_IOC_VALIDATION_RESULTS
from utils import generate_identity_id, generate_relation_id, generate_validation_sighting_id, to_epoch, to_iso

OUTCOME_DETECTED = "detected"
OUTCOME_MISSED = "missed"
# Still waiting for a result: the OpenCTI validation status of the pair
OUTCOME_PENDING = "requested"

# Requests whose tests may be running or done
ACTIVE_STATUSES = ("sent", "awaiting_approval", "running", "completed", "partial")
TERMINAL_STATUSES = ("completed", "partial")
MAX_PAGES = 5
PAGE_SIZE = 100
# Requests older than this are not examined again
LOOKBACK_DAYS = 30
# Clock skew tolerated before the dispatch time
DISPATCH_SKEW_SECONDS = 300

REQUESTS_QUERY = """
query SplunkIocValidationRequests($first: Int, $after: ID) {
  iocValidationRequests(first: $first, after: $after, orderBy: updated_at, orderMode: desc) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        name
        status
        created_at
        updated_at
        dispatched_at
        completed_at
        platforms { id standard_id }
        iocs { indicator_id observable_type value test_kind }
        deployments {
          id
          validation_status
          validation_run_id
          %s
          from { ... on Indicator { id standard_id } }
          to { ... on SecurityPlatform { id standard_id } }
        }
      }
    }
  }
}
"""

REPORT_RESULTS_MUTATION = """
mutation SplunkIocValidationResults($id: ID!, $platformId: StixRef!, $results: [IocValidationPairResultInput!]!) {
  iocValidationReportResults(id: $id, platformId: $platformId, results: $results) { id }
}
"""


def _dt(value):
    epoch = to_epoch(value)
    return datetime.fromtimestamp(epoch, timezone.utc) if epoch is not None else None


def validation_window(request, grace_minutes):
    """
    :param request: IocValidationRequest node
    :param grace_minutes: indexing / hits search lag tolerated after completion
    :return: (start, end_or_None, decide_after_or_None) as aware datetimes
    """
    start = _dt(request.get("dispatched_at")) or _dt(request.get("created_at"))
    start = start - timedelta(seconds=DISPATCH_SKEW_SECONDS) if start else None
    end = _dt(request.get("completed_at")) if request.get("status") in TERMINAL_STATUSES else None
    grace = timedelta(minutes=grace_minutes)
    decide_after = end + grace if end else None
    return start, end, decide_after


def decide_outcome(start, end, decide_after, hit_windows, grace_minutes, now, platform_last_hit=None):
    """
    :param start: test window start (aware datetime)
    :param end: completion time or None while running
    :param decide_after: time after which a miss can be declared, or None
    :param hit_windows: [[first_epoch, last_epoch, count], ...]
    :param now: aware datetime
    :param platform_last_hit: last hit OpenCTI recorded on the deployment
        (epoch), the cross-check of the local hit history
    :return: (outcome, first matching hit epoch or None)
    """
    if start is None:
        return OUTCOME_PENDING, None
    upper = (end + timedelta(minutes=grace_minutes)) if end else now
    low, high = start.timestamp(), upper.timestamp()
    matches = [w for w in hit_windows if float(w[1]) >= low and float(w[0]) <= high]
    if matches:
        return OUTCOME_DETECTED, min(max(float(w[0]), low) for w in matches)
    if platform_last_hit is not None and low <= platform_last_hit <= high:
        return OUTCOME_DETECTED, platform_last_hit
    if decide_after is not None and now >= decide_after:
        if platform_last_hit is not None and platform_last_hit > high and not any(
            float(w[0]) <= platform_last_hit <= float(w[1]) for w in hit_windows
        ):
            # A later hit the local history does not hold: the history is
            # incomplete (lost KV Store write), a miss cannot be proven.
            return OUTCOME_PENDING, None
        return OUTCOME_MISSED, None
    return OUTCOME_PENDING, None


def _platform_matches(node, platform):
    if not isinstance(node, dict):
        return False
    ids = {platform.get("id"), platform.get("standard_id")} - {None}
    return bool(ids & {node.get("id"), node.get("standard_id")})


class ValidationProver:
    def __init__(self, client, detector, platform, hits_history, results, grace_minutes=30, writeback=True,
                 logger=None, now=None, author_name="Splunk"):
        """
        :param client: SplunkAppConnectorHelper
        :param detector: OpenCTIFeatureDetector
        :param platform: Splunk Security Platform node (id, standard_id)
        :param hits_history: KVCollection over opencti_indicator_hits
        :param results: KVCollection over opencti_validation_results
        """
        self.client = client
        self.detector = detector
        self.platform = platform or {}
        self.hits_history = hits_history
        self.results = results
        self.grace_minutes = int(grace_minutes)
        self.writeback = bool(writeback)
        self.logger = logger or logging.getLogger(__name__)
        self.now = now or datetime.now(timezone.utc)
        self.author = stix2.Identity(
            id=generate_identity_id(author_name, "system"), name=author_name, identity_class="system"
        )

    def requests(self):
        """Active requests targeting this platform, newest first, bounded."""
        horizon = self.now - timedelta(days=LOOKBACK_DAYS)
        after = None
        for _ in range(MAX_PAGES):
            hit_fields = "last_hit_at" if self.detector.has(FEATURE_HITS) else ""
            data = self.client.graphql_query(REQUESTS_QUERY % hit_fields, {"first": PAGE_SIZE, "after": after})
            connection = data.get("iocValidationRequests") or {}
            for edge in connection.get("edges") or []:
                node = (edge or {}).get("node") or {}
                updated = _dt(node.get("updated_at"))
                if updated is not None and updated < horizon:
                    return
                if node.get("status") not in ACTIVE_STATUSES:
                    continue
                if any(_platform_matches(p, self.platform) for p in node.get("platforms") or []):
                    yield node
            page = connection.get("pageInfo") or {}
            if not page.get("hasNextPage"):
                return
            after = page.get("endCursor")

    def pairs(self, request):
        """
        :return: list of (indicator internal id, indicator STIX id, ioc,
            deployment) for the pairs of this platform still waiting for a result
        """
        deployments = {}
        for deployment in request.get("deployments") or []:
            if not _platform_matches(deployment.get("to"), self.platform):
                continue
            source = deployment.get("from") or {}
            deployments[source.get("id")] = (deployment, source.get("standard_id"))
        pairs = []
        for ioc in request.get("iocs") or []:
            indicator_internal_id = ioc.get("indicator_id")
            entry = deployments.get(indicator_internal_id)
            if entry is None:
                continue
            deployment, standard_id = entry
            if deployment.get("validation_status") not in (None, "requested"):
                continue
            pairs.append((indicator_internal_id, standard_id, ioc, deployment))
        return pairs

    def _report(self, request, decided):
        """
        :param decided: list of (standard_id, outcome, observed_epoch, ioc)
        """
        if self.detector.has(FEATURE_IOC_VALIDATION_RESULTS):
            results = []
            for standard_id, outcome, observed, ioc in decided:
                entry = {"indicatorId": standard_id, "status": outcome}
                entry["observedAt"] = to_iso(observed) if observed else to_iso(self.now)
                if outcome == OUTCOME_MISSED:
                    entry["evidence"] = "No matching event in Splunk during the test window"
                results.append(entry)
            self.client.graphql_query(REPORT_RESULTS_MUTATION, {
                "id": request["id"], "platformId": self.platform["id"], "results": results,
            })
            return "iocValidationReportResults"
        objects = [self.author]
        platform_ref = self.platform["standard_id"]
        for standard_id, outcome, observed, ioc in decided:
            validated_at = to_iso(observed) if observed else to_iso(self.now)
            objects.append(stix2.Relationship(
                id=generate_relation_id("deployed-on", standard_id, platform_ref),
                relationship_type="deployed-on",
                source_ref=standard_id,
                target_ref=platform_ref,
                created_by_ref=self.author.id,
                allow_custom=True,
                custom_properties={
                    "validation_status": outcome,
                    "validation_run_id": request["id"],
                    "last_validation_at": validated_at,
                },
            ))
            if outcome == OUTCOME_MISSED:
                window_end = to_iso(self.now)
                objects.append(stix2.Sighting(
                    id=generate_validation_sighting_id(standard_id, platform_ref, request["id"]),
                    created_by_ref=self.author.id,
                    description=(
                        f"IOC validation request '{request.get('name')}': no matching event in Splunk "
                        f"for the {ioc.get('test_kind')} test of {ioc.get('value')}"
                    ),
                    sighting_of_ref=standard_id,
                    first_seen=window_end,
                    last_seen=window_end,
                    count=1,
                    where_sighted_refs=[platform_ref],
                    allow_custom=True,
                    custom_properties={"x_opencti_negative": True},
                ))
        self.client.register()
        self.client.send_stix_bundle(stix2.Bundle(objects=objects, allow_custom=True).serialize())
        return "bundle"

    def run(self):
        """
        :return: list of output rows, one per (request, indicator) examined
        """
        if not self.platform.get("id"):
            self.logger.info("IOC validation proof skipped: no Splunk Security Platform")
            return []
        if not self.detector.require(FEATURE_IOC_VALIDATION, "IOC validation proof"):
            return []
        rows = []
        for request in self.requests():
            start, end, decide_after = validation_window(request, self.grace_minutes)
            decided = []
            for internal_id, standard_id, ioc, deployment in self.pairs(request):
                key = state_key(request["id"], standard_id, self.platform["id"])
                previous = self.results.get(key) or {}
                row = {
                    "request_id": request["id"],
                    "request_name": request.get("name"),
                    "request_status": request.get("status"),
                    "indicator_id": standard_id,
                    "value": ioc.get("value"),
                    "observable_type": ioc.get("observable_type"),
                    "test_kind": ioc.get("test_kind"),
                }
                if previous.get("reported") in (True, "true", "1", 1):
                    row.update({"outcome": previous.get("outcome"), "reported": "already"})
                    rows.append(row)
                    continue
                history = self.hits_history.get(state_key(standard_id)) or {}
                outcome, observed = decide_outcome(
                    start, end, decide_after, load_windows(history), self.grace_minutes, self.now,
                    platform_last_hit=to_epoch(deployment.get("last_hit_at")),
                )
                row["outcome"] = outcome
                row["first_matching_hit"] = to_iso(observed) if observed else ""
                if outcome != OUTCOME_PENDING:
                    decided.append((standard_id, outcome, observed, ioc))
                row["reported"] = "no"
                rows.append(row)
            if decided and self.writeback:
                try:
                    channel = self._report(request, decided)
                except Exception as ex:
                    self.logger.error(f"IOC validation results of request {request['id']} not reported: {ex}")
                    channel = None
                records = []
                for standard_id, outcome, observed, ioc in decided:
                    records.append({
                        "_key": state_key(request["id"], standard_id, self.platform["id"]),
                        "request_id": request["id"],
                        "request_name": request.get("name") or "",
                        "indicator_id": standard_id,
                        "value": ioc.get("value") or "",
                        "test_kind": ioc.get("test_kind") or "",
                        "outcome": outcome,
                        "first_matching_hit": to_iso(observed) if observed else "",
                        "reported": channel is not None,
                        "channel": channel or "",
                        "decided_at": utc_now_iso(),
                    })
                for row in rows:
                    if row["request_id"] == request["id"] and row.get("reported") == "no" and row["outcome"] != OUTCOME_PENDING:
                        row["reported"] = channel or "error"
                try:
                    self.results.upsert(records)
                except Exception as ex:
                    self.logger.warning(f"Unable to store the validation outcomes in the KV Store: {ex}")
        return rows
