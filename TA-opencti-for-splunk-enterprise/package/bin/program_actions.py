"""OpenCTI program calls made by the alert actions, each feature detected.

- Timeline milestone on the Incident / Case-Incident created by an alert
  (innovation 11, timelineEventAdd, idempotent through external_id).
- Run Case Autopilot on that container (innovation 02, investigationRunAdd,
  Enterprise Edition), at most once per container.
- Indicator resolution for sightings (#57, #67): by STIX id, or by value
  through the opencti_indicators KV Store and OpenCTI's exact pattern.
- Hunt run targets for hunt evidence (innovation 01, huntRun) and the
  evidence write-back (huntRunEvidenceAdd, requested on #18671).
"""

import re
import time
import uuid
from datetime import datetime, timezone

from addon_state import state_key, take_over, utc_now_iso
from app_connector_helper import OpenCTIGraphQLError
from constants import INDICATORS_KVSTORE_NAME
from opencti_features import (
    FEATURE_CASE_AUTOPILOT,
    FEATURE_HUNT_EVIDENCE,
    FEATURE_HUNTS,
    FEATURE_TIMELINE,
)
from stix_converter import indicator_patterns, pattern_indicator
from utils import parse_iso, to_iso

AUTOPILOT_RESERVATION_SECONDS = 3600
FOLLOWUP_TIMELINE = "timeline_milestone"
FOLLOWUP_CASE_AUTOPILOT = "case_autopilot"
CASE_INSENSITIVE_KINDS = frozenset({"domain", "ipv4", "ipv6", "email_addr", "file_hash"})

TIMELINE_TITLE_MAX = 512
TIMELINE_DESCRIPTION_MAX = 10000
TIMELINE_EXTERNAL_ID_MAX = 256
# indicator_id of the shipped detection searches (the milestone pivots to it)
INDICATOR_ID_RE = re.compile(r"^indicator--[0-9a-fA-F-]{36}$")

TIMELINE_ADD_MUTATION = """
mutation SplunkTimelineMilestone($input: TimelineEventAddInput!) {
  timelineEventAdd(input: $input) { id }
}
"""

AUTOPILOT_ADD_MUTATION = """
mutation SplunkCaseAutopilot($subjectId: ID!, $policyId: ID) {
  investigationRunAdd(subjectId: $subjectId, policyId: $policyId) { id }
}
"""

INDICATOR_BY_ID_QUERY = """
query SplunkSightedIndicator($id: String!) {
  indicator(id: $id) { id standard_id pattern revoked }
}
"""

INDICATORS_BY_PATTERN_QUERY = """
query SplunkIndicatorsByPattern($filters: FilterGroup) {
  indicators(first: 10, filters: $filters, orderBy: created_at, orderMode: desc) {
    edges { node { id standard_id pattern revoked } }
  }
}
"""

HUNT_RUN_QUERY = """
query SplunkHuntRun($id: String!) {
  huntRun(id: $id) {
    id
    hunt_id
    hunt { id name huntTargets { id standard_id entity_type } }
  }
}
"""

HUNT_EVIDENCE_MUTATION = """
mutation SplunkHuntRunEvidence($id: ID!, $input: HuntRunEvidenceAddInput!) {
  huntRunEvidenceAdd(id: $id, input: $input) { id }
}
"""

EVIDENCE_INGESTED_QUERY = """
query SplunkEvidenceIngested($id: String!) {
  stixObjectOrStixRelationship(id: $id) {
    ... on BasicObject { id }
    ... on BasicRelationship { id }
  }
}
"""

# The OpenCTI workers ingest a pushed bundle asynchronously: the evidence is
# attached to the run once it exists, after at most these waits.
EVIDENCE_INGESTION_DELAYS_SECONDS = (1, 2, 4, 8)
# Evidence still not ingested is attached by a later report of the same run,
# within this delay.
EVIDENCE_PENDING_SECONDS = 86400
# Far above one attachment (ingestion wait included): an older claim is stale.
EVIDENCE_CLAIM_SECONDS = 600

# Types a hunt evidence sighting can target (sighting_of_ref must be an SDO)
HUNT_SIGHTABLE_TYPES = {
    "Indicator", "Attack-Pattern", "Intrusion-Set", "Malware", "Campaign",
    "Threat-Actor-Group", "Threat-Actor-Individual", "Tool", "Infrastructure",
}


# region timeline milestone
def build_milestone_input(container_id, search_name, trigger_time, event_time=None, results_link="", sid=None,
                          author_id=None, element_id=None):
    """
    Field values agreed with innovation 11 on OpenCTI-Platform/opencti#18681.

    :param container_id: STIX id of the Incident / Case-Incident
    :param search_name: Splunk alert name
    :param trigger_time: when the alert fired (datetime)
    :param event_time: time of the Splunk result (datetime or None)
    :param results_link: link to the Splunk search results
    :param sid: Splunk search id of the triggered alert
    :param author_id: Splunk Security Platform id (createdBy)
    :param element_id: indicator the alert is about
    :return: TimelineEventAddInput
    """
    title = f"Splunk alert: {search_name}"[:TIMELINE_TITLE_MAX]
    lines = [f"Splunk alert '{search_name}' triggered at {to_iso(trigger_time)}."]
    if event_time is not None:
        lines.append(f"Matching event time: {to_iso(event_time)}.")
    if results_link:
        lines.append(f"Splunk search results: {results_link}")
    milestone = {
        "container_id": container_id,
        "event_time": to_iso(trigger_time),
        "precision": "exact",
        # A Splunk alert is a detection: this lane drives the first_detection anchor
        "lane": "detection",
        "kind": "milestone",
        "title": title,
        "description": "\n".join(lines)[:TIMELINE_DESCRIPTION_MAX],
        # One milestone per triggered alert and container: retries update it
        "external_id": (f"splunk:{sid}" if sid else f"splunk-alert:{state_key(search_name, container_id)}")[
            :TIMELINE_EXTERNAL_ID_MAX
        ],
    }
    if author_id:
        milestone["createdBy"] = author_id
    if element_id:
        milestone["element_id"] = element_id
    return milestone


def _platform_id(context):
    try:
        platform = context.platform
    except Exception as ex:
        context.logger.warning(f"Timeline milestone added without its author: {ex}")
        return None
    return (platform or {}).get("id")


def add_timeline_milestone(context, container_id, event_time=None, trigger_time=None, search_name=None,
                           results_link=None, sid=None, element_id=None):
    """
    :param context: alert_common.AlertContext
    :param search_name: alert that created the container (default: the running alert)
    :param results_link: its search results (default: those of the running alert)
    :param sid: Splunk search id of the triggered alert
    :param element_id: indicator the alert is about, when known
    :return: True when added, False when the platform has no timeline
    """
    if not context.detector.require(FEATURE_TIMELINE, "Timeline milestone"):
        return False
    milestone = build_milestone_input(
        container_id,
        context.search_name if search_name is None else search_name,
        trigger_time or datetime.now(timezone.utc),
        event_time,
        context.results_link if results_link is None else results_link,
        sid,
        _platform_id(context),
        element_id,
    )
    try:
        context.client.graphql_query(TIMELINE_ADD_MUTATION, {"input": milestone})
    except OpenCTIGraphQLError as ex:
        # The timeline rejects an element or author the account cannot load: the milestone matters more.
        unknown = [key for key, marker in (("element_id", "element cannot be found"),
                                           ("createdBy", "author cannot be found"))
                   if key in milestone and marker in str(ex)]
        if not unknown:
            raise
        context.logger.warning(f"Timeline milestone on {container_id} added without {', '.join(unknown)}: {ex}")
        context.client.graphql_query(TIMELINE_ADD_MUTATION, {
            "input": {key: value for key, value in milestone.items() if key not in unknown},
        })
    context.logger.info(f"Timeline milestone added on {container_id}")
    return True
# endregion


def _event_time(event):
    try:
        return datetime.fromtimestamp(float(event.get("_time")), timezone.utc) if event.get("_time") else None
    except (TypeError, ValueError):
        return None


def schedule_container_followups(context, container_id, event):
    """
    Defer the timeline milestone and the Case Autopilot run of a container
    created by an alert until OpenCTI has ingested it (alert_common).

    :param context: alert_common.AlertContext
    :param container_id: STIX id of the Incident / Case-Incident
    :param event: the Splunk result
    """
    if context.flag("timeline_milestone", True) and context.detector.require(FEATURE_TIMELINE, "Timeline milestone"):
        indicator_id = str(event.get("indicator_id") or "").strip()
        context.defer(container_id, "Timeline milestone", FOLLOWUP_TIMELINE, {
            "search_name": context.search_name,
            "results_link": context.results_link,
            "sid": context.sid,
            "trigger_time": to_iso(datetime.now(timezone.utc)),
            "event_time": to_iso(_event_time(event)),
            "element_id": indicator_id if INDICATOR_ID_RE.match(indicator_id) else None,
        })
    if context.flag("run_case_autopilot", False) and context.detector.require(
        FEATURE_CASE_AUTOPILOT, "Run Case Autopilot"
    ):
        context.defer(container_id, "Run Case Autopilot", FOLLOWUP_CASE_AUTOPILOT, {
            "policy_id": context.param("autopilot_policy_id", ""),
        })


def run_followup(context, kind, container_id, params):
    """
    Run a follow-up deferred by schedule_container_followups, possibly parked
    by an earlier alert run: everything it needs is in ``params``.

    :param context: alert_common.AlertContext
    :param kind: FOLLOWUP_TIMELINE or FOLLOWUP_CASE_AUTOPILOT
    :param params: JSON parameters recorded when it was deferred
    """
    if kind == FOLLOWUP_TIMELINE:
        return add_timeline_milestone(
            context,
            container_id,
            params.get("event_time"),
            params.get("trigger_time"),
            params.get("search_name"),
            params.get("results_link"),
            params.get("sid"),
            params.get("element_id"),
        )
    if kind == FOLLOWUP_CASE_AUTOPILOT:
        return run_case_autopilot(context, container_id, params.get("policy_id"))
    raise ValueError(f"Unknown follow-up {kind}")


# region Case Autopilot
def _stale_reservation(marker, now=None):
    """
    :return: True for a pending reservation older than AUTOPILOT_RESERVATION_SECONDS
        (the process holding it died before recording the run)
    """
    if marker.get("status") != "pending":
        return False
    reserved_at = parse_iso(marker.get("reserved_at"))
    if reserved_at is None:
        return True
    now = now or datetime.now(timezone.utc)
    return (now - reserved_at).total_seconds() > AUTOPILOT_RESERVATION_SECONDS


def run_case_autopilot(context, container_id, policy_id=None):
    """
    Run Case Autopilot once per container (repeated alerts on the same
    incident do not start new runs).

    :param context: alert_common.AlertContext
    :return: id of the run, or None when skipped
    """
    if not context.detector.require(FEATURE_CASE_AUTOPILOT, "Run Case Autopilot"):
        return None
    if not getattr(context.cache, "persistent", False):
        # Without the add-on state collection every run of the alert would start a new run
        context.logger.warning(
            f"Run Case Autopilot skipped for {container_id}: the add-on state collection "
            "is unavailable, so a run already started for it cannot be detected"
        )
        return None
    marker = f"autopilot|{context.client.opencti_url}|{container_id}"
    existing = context.cache.get(marker)
    if existing and not _stale_reservation(existing):
        context.logger.info(f"Case Autopilot already run for {container_id}")
        return None
    if existing:
        context.logger.warning(f"Case Autopilot reservation for {container_id} never completed, retrying")
    # Atomic: of concurrent alert runs on one container, one only starts a run.
    # The takeover keys stay: a process that read the stale reservation late
    # can never take it over again once the run is recorded.
    reservation = {"status": "pending", "reserved_at": utc_now_iso()}
    if take_over(context.cache, marker, reservation, _stale_reservation) is None:
        context.logger.info(f"Case Autopilot already being started for {container_id}")
        return None
    try:
        data = context.client.graphql_query(AUTOPILOT_ADD_MUTATION, {
            "subjectId": container_id,
            "policyId": (policy_id or "").strip() or None,
        })
    except Exception:
        context.cache.release(marker)
        raise
    run = data.get("investigationRunAdd") or {}
    try:
        context.cache.set(marker, {"run_id": run.get("id"), "launched_at": utc_now_iso()})
    except Exception as ex:
        context.logger.error(
            f"Case Autopilot run {run.get('id')} started for {container_id} but not recorded in the "
            f"add-on state collection; another run may start once the reservation expires "
            f"({AUTOPILOT_RESERVATION_SECONDS}s): {ex}"
        )
        return run.get("id")
    context.logger.info(f"Case Autopilot run {run.get('id')} started for {container_id}")
    return run.get("id")
# endregion


# region indicator resolution for sightings
def _usable(node):
    return isinstance(node, dict) and node.get("standard_id") and not node.get("revoked")


def find_indicator_by_id(client, indicator_id):
    """
    :return: STIX id of the indicator, or None when not readable
    """
    data = client.graphql_query(INDICATOR_BY_ID_QUERY, {"id": indicator_id})
    node = data.get("indicator")
    return node.get("standard_id") if isinstance(node, dict) and node.get("standard_id") else None


def find_indicator_in_kvstore(kv_collection, value, kind=None, main_type=None):
    """
    :param kv_collection: addon_state.KVCollection over opencti_indicators
    :param value: observable value
    :param kind: observable kind; only case-insensitive kinds also match the
        lower and upper case forms of the value
    :param main_type: OpenCTI main observable type the indicator must have
        (an entry that does not record it is accepted)
    :return: STIX id of a non-revoked indicator holding this value, or None
    """
    # KV Store queries are case sensitive; a URL path is too, unlike hosts and hashes
    candidates = [value]
    if kind in CASE_INSENSITIVE_KINDS:
        for candidate in (value.lower(), value.upper()):
            if candidate not in candidates:
                candidates.append(candidate)
    for candidate in candidates:
        records = kv_collection.query(query={"value": candidate}, limit=10, fields=["id", "revoked", "main_observable_type"])
        for record in records or []:
            if not record.get("id") or str(record.get("revoked", "false")).lower() in ("true", "1"):
                continue
            recorded_type = record.get("main_observable_type")
            if main_type and recorded_type and recorded_type.lower() != main_type.lower():
                continue
            return record["id"]
    return None


def find_indicator_by_pattern(client, patterns):
    """
    :param patterns: equivalent STIX patterns
    :return: STIX id of a non-revoked indicator with one of these patterns, or None
    """
    filters = {
        "mode": "and",
        "filters": [{"key": ["pattern"], "values": list(patterns), "operator": "eq", "mode": "or"}],
        "filterGroups": [],
    }
    data = client.graphql_query(INDICATORS_BY_PATTERN_QUERY, {"filters": filters})
    for edge in ((data.get("indicators") or {}).get("edges")) or []:
        node = (edge or {}).get("node") or {}
        if _usable(node):
            return node["standard_id"]
    return None


def resolve_sighted_indicator(context, sighting_of_type, value, kind):
    """
    :param context: alert_common.AlertContext
    :param sighting_of_type: "indicator_id" or "<kind>_indicator"
    :param value: Sighting of Value
    :param kind: observable kind for "<kind>_indicator" types
    :return: indicator dict for stix_converter.convert_to_sighting
    :raise ValueError: when the indicator cannot be used
    """
    value = (value or "").strip()
    if sighting_of_type == "indicator_id":
        if not value.startswith("indicator--"):
            raise ValueError(f"Sighting of Value must be an indicator STIX id (indicator--<uuid>), got {value!r}")
        found = find_indicator_by_id(context.client, value)
        if found is None:
            raise ValueError(f"Indicator {value} not found in OpenCTI or not readable by the add-on account")
        return {"id": found}
    patterns, main_type = indicator_patterns(kind, value)
    case_insensitive = kind in CASE_INSENSITIVE_KINDS
    if case_insensitive:
        # OpenCTI pattern filters are case sensitive too
        for variant in (value.lower(), value.upper()):
            patterns += [p for p in indicator_patterns(kind, variant)[0] if p not in patterns]
    try:
        from addon_state import KVCollection

        found = find_indicator_in_kvstore(KVCollection(context.service, INDICATORS_KVSTORE_NAME), value, kind, main_type)
        if found:
            return {"id": found}
    except Exception as ex:
        context.logger.warning(f"opencti_indicators lookup failed, asking OpenCTI: {ex}")
    found = find_indicator_by_pattern(context.client, patterns)
    if found:
        return {"id": found}
    # Unknown to OpenCTI: create it from this single value (#57), one indicator whatever the case
    return pattern_indicator(kind, value.lower() if case_insensitive else value)
# endregion


# region hunts
def hunt_targets(context, hunt_run_id):
    """
    :return: (targets STIX ids, hunt name) of the hunt behind the run; empty
        when the platform has no hunts or the run is unknown
    """
    if not context.detector.require(FEATURE_HUNTS, "Hunt run lookup"):
        return [], None
    data = context.client.graphql_query(HUNT_RUN_QUERY, {"id": hunt_run_id})
    run = data.get("huntRun")
    if not run:
        raise ValueError(f"Hunt run {hunt_run_id} not found in OpenCTI or not readable by the add-on account")
    hunt = run.get("hunt") or {}
    targets = [
        target.get("standard_id")
        for target in hunt.get("huntTargets") or []
        if isinstance(target, dict) and target.get("standard_id") and target.get("entity_type") in HUNT_SIGHTABLE_TYPES
    ]
    return targets, hunt.get("name")


def _ingested(context, object_ids):
    """
    :return: the ids among object_ids that OpenCTI already holds
    """
    present = []
    for object_id in object_ids:
        data = context.client.graphql_query(EVIDENCE_INGESTED_QUERY, {"id": object_id})
        if data.get("stixObjectOrStixRelationship"):
            present.append(object_id)
    return present


def wait_for_ingestion(context, object_ids, delays=EVIDENCE_INGESTION_DELAYS_SECONDS):
    """
    :return: (ids OpenCTI holds, ids still not ingested after the waits)
    """
    pending = list(object_ids)
    for delay in (0,) + tuple(delays):
        if delay:
            time.sleep(delay)
        present = set(_ingested(context, pending))
        pending = [object_id for object_id in pending if object_id not in present]
        if not pending:
            break
    return [object_id for object_id in object_ids if object_id not in pending], pending


def _pending_prefix(hunt_run_id):
    return f"hunt_evidence_pending|{hunt_run_id}|"


def _park(context, hunt_run_id, item):
    # One entry per parked report: concurrent reports never overwrite each other.
    context.cache.set(f"{_pending_prefix(hunt_run_id)}{uuid.uuid4().hex}", item)


def _stale_claim(value):
    """:return: True for a claim older than EVIDENCE_CLAIM_SECONDS (its holder died)"""
    claimed_at = parse_iso(value.get("claimed_at"))
    return claimed_at is None or time.time() - claimed_at.timestamp() > EVIDENCE_CLAIM_SECONDS


def _claim(cache, claim):
    """
    Atomic: of concurrent reports of the run, one only holds the claim; a stale
    claim is taken over (addon_state.take_over).

    :return: takeover keys to release with the claim once done, None when not claimed
    """
    return take_over(cache, claim, {"claimed_at": utc_now_iso()}, _stale_claim)


def _attach_pending(context, hunt_run_id):
    """Attach the evidence of earlier reports of this run that is now ingested."""
    prefix = _pending_prefix(hunt_run_id)
    for key, item in context.cache.items(prefix):
        if "|" in key[len(prefix):]:
            continue
        claim = f"{key}|claim"
        parked_at = parse_iso(item.get("parked_at"))
        if parked_at is None or time.time() - parked_at.timestamp() > EVIDENCE_PENDING_SECONDS:
            context.logger.warning(
                f"Hunt evidence {item.get('result_ids')} never ingested by OpenCTI: not attached to run {hunt_run_id}"
            )
            context.cache.release(key)
            context.cache.release(claim)
            for takeover, _ in context.cache.items(f"{claim}|takeover|"):
                context.cache.release(takeover)
            continue
        takeovers = _claim(context.cache, claim)
        if takeovers is None:
            continue
        try:
            # The listing may predate another report that attached this entry.
            item = context.cache.get(key)
            if not item:
                continue
            result_ids = item.get("result_ids")
            if not isinstance(result_ids, list) or not all(isinstance(object_id, str) for object_id in result_ids):
                context.logger.warning(f"Malformed deferred hunt evidence {key} of run {hunt_run_id} dropped")
                context.cache.release(key)
                continue
            present = _ingested(context, result_ids)
            if present:
                payload = {k: v for k, v in item.items() if k != "parked_at"}
                payload["result_ids"] = present
                context.client.graphql_query(HUNT_EVIDENCE_MUTATION, {"id": hunt_run_id, "input": payload})
            remaining = [object_id for object_id in result_ids if object_id not in present]
            if not remaining:
                context.cache.release(key)
            elif present:
                context.cache.set(key, dict(item, result_ids=remaining, hits_count=0))
        except Exception as ex:
            # One entry failing never keeps the others of the run waiting
            context.logger.warning(f"Deferred hunt evidence {key} of run {hunt_run_id} not attached yet: {ex}")
        finally:
            context.cache.release(claim)
            for takeover in takeovers:
                context.cache.release(takeover)


def report_hunt_evidence(context, hunt_run_id, result_ids, hits_count, platform_id=None, observed_at=None):
    """
    Attach the evidence objects to the hunt run when the platform supports it,
    once OpenCTI ingested them. Objects still not ingested are attached by a
    later report of the same run.

    :return: True when attached, False when the mutation is absent
    :raise ValueError: when no object was ingested yet (attachment deferred)
    """
    if not context.detector.require(FEATURE_HUNT_EVIDENCE, "Hunt evidence attachment to the run"):
        return False
    try:
        _attach_pending(context, hunt_run_id)
    except Exception as ex:
        context.logger.warning(f"Deferred hunt evidence of run {hunt_run_id} not attached yet: {ex}")
    payload = {
        "hits_count": int(hits_count),
        "source": "splunk-alert-action",
    }
    if platform_id:
        payload["security_platform_id"] = platform_id
    if observed_at is not None:
        payload["observed_at"] = to_iso(observed_at)
    ingested, pending = wait_for_ingestion(context, list(result_ids))
    deferred = "they are attached by the next evidence report of the run"
    if pending and getattr(context.cache, "persistent", False):
        # The hits of this report are counted once, by its first attachment.
        parked = dict(payload, result_ids=pending, parked_at=utc_now_iso())
        if ingested:
            parked["hits_count"] = 0
        _park(context, hunt_run_id, parked)
    elif pending:
        deferred = "the KV Store is unavailable to defer them, so they are not attached"
    if not ingested:
        raise ValueError(f"{len(pending)} evidence objects not ingested by OpenCTI yet: {deferred}")
    context.client.graphql_query(HUNT_EVIDENCE_MUTATION, {"id": hunt_run_id, "input": dict(payload, result_ids=ingested)})
    if pending:
        context.logger.warning(f"{len(pending)} hunt evidence objects not ingested by OpenCTI yet: {deferred}")
    return True
# endregion
