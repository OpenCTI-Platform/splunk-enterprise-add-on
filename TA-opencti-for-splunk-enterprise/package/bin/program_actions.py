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

from datetime import datetime, timezone

from addon_state import state_key, utc_now_iso
from constants import INDICATORS_KVSTORE_NAME
from opencti_features import (
    FEATURE_CASE_AUTOPILOT,
    FEATURE_HUNT_EVIDENCE,
    FEATURE_HUNTS,
    FEATURE_TIMELINE,
)
from stix_converter import indicator_patterns, pattern_indicator
from utils import to_iso

TIMELINE_TITLE_MAX = 512
TIMELINE_DESCRIPTION_MAX = 10000
TIMELINE_EXTERNAL_ID_MAX = 256

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

# Types a hunt evidence sighting can target (sighting_of_ref must be an SDO)
HUNT_SIGHTABLE_TYPES = {
    "Indicator", "Attack-Pattern", "Intrusion-Set", "Malware", "Campaign",
    "Threat-Actor-Group", "Threat-Actor-Individual", "Tool", "Infrastructure",
}


# region timeline milestone
def build_milestone_input(container_id, search_name, trigger_time, event_time=None, results_link=""):
    """
    :param container_id: STIX id of the Incident / Case-Incident
    :param search_name: Splunk alert name
    :param trigger_time: when the alert fired (datetime)
    :param event_time: time of the Splunk result (datetime or None)
    :param results_link: link to the Splunk search results
    :return: TimelineEventAddInput
    """
    title = f"Splunk alert: {search_name}"[:TIMELINE_TITLE_MAX]
    lines = [f"Splunk alert '{search_name}' triggered at {to_iso(trigger_time)}."]
    if event_time is not None:
        lines.append(f"Matching event time: {to_iso(event_time)}.")
    if results_link:
        lines.append(f"Splunk search results: {results_link}")
    return {
        "container_id": container_id,
        "event_time": to_iso(trigger_time),
        "precision": "exact",
        "lane": "custom",
        "kind": "milestone",
        "title": title,
        "description": "\n".join(lines)[:TIMELINE_DESCRIPTION_MAX],
        # One milestone per alert and container: re-runs update it
        "external_id": f"splunk-alert:{state_key(search_name, container_id)}"[:TIMELINE_EXTERNAL_ID_MAX],
    }


def add_timeline_milestone(context, container_id, event_time=None, trigger_time=None):
    """
    :param context: alert_common.AlertContext
    :return: True when added, False when the platform has no timeline
    """
    if not context.detector.require(FEATURE_TIMELINE, "Timeline milestone"):
        return False
    milestone = build_milestone_input(
        container_id,
        context.search_name,
        trigger_time or datetime.now(timezone.utc),
        event_time,
        context.results_link,
    )
    context.client.graphql_query(TIMELINE_ADD_MUTATION, {"input": milestone})
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
    trigger_time = datetime.now(timezone.utc)
    if context.flag("timeline_milestone", True) and context.detector.require(FEATURE_TIMELINE, "Timeline milestone"):
        event_time = _event_time(event)
        context.defer(
            container_id,
            "Timeline milestone",
            lambda: add_timeline_milestone(context, container_id, event_time, trigger_time),
        )
    if context.flag("run_case_autopilot", False) and context.detector.require(
        FEATURE_CASE_AUTOPILOT, "Run Case Autopilot"
    ):
        policy_id = context.param("autopilot_policy_id", "")
        context.defer(
            container_id,
            "Run Case Autopilot",
            lambda: run_case_autopilot(context, container_id, policy_id),
        )


# region Case Autopilot
def run_case_autopilot(context, container_id, policy_id=None):
    """
    Run Case Autopilot once per container (repeated alerts on the same
    incident do not start new runs).

    :param context: alert_common.AlertContext
    :return: id of the run, or None when skipped
    """
    if not context.detector.require(FEATURE_CASE_AUTOPILOT, "Run Case Autopilot"):
        return None
    marker = f"autopilot|{context.client.opencti_url}|{container_id}"
    if context.cache.get(marker):
        context.logger.info(f"Case Autopilot already run for {container_id}")
        return None
    data = context.client.graphql_query(AUTOPILOT_ADD_MUTATION, {
        "subjectId": container_id,
        "policyId": (policy_id or "").strip() or None,
    })
    run = data.get("investigationRunAdd") or {}
    context.cache.set(marker, {"run_id": run.get("id"), "launched_at": utc_now_iso()})
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


def find_indicator_in_kvstore(kv_collection, value):
    """
    :param kv_collection: addon_state.KVCollection over opencti_indicators
    :param value: observable value
    :return: STIX id of a non-revoked indicator holding this value, or None
    """
    # KV Store queries are case sensitive; lookups (and hashes) are not
    candidates = []
    for candidate in (value, value.lower(), value.upper()):
        if candidate not in candidates:
            candidates.append(candidate)
    for candidate in candidates:
        records = kv_collection.query(query={"value": candidate}, limit=10, fields=["id", "revoked"])
        for record in records or []:
            if record.get("id") and str(record.get("revoked", "false")).lower() not in ("true", "1"):
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
    patterns, _ = indicator_patterns(kind, value)
    try:
        from addon_state import KVCollection

        found = find_indicator_in_kvstore(KVCollection(context.service, INDICATORS_KVSTORE_NAME), value)
        if found:
            return {"id": found}
    except Exception as ex:
        context.logger.warning(f"opencti_indicators lookup failed, asking OpenCTI: {ex}")
    found = find_indicator_by_pattern(context.client, patterns)
    if found:
        return {"id": found}
    # Unknown to OpenCTI: create it from this single value (#57)
    return pattern_indicator(kind, value)
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


def report_hunt_evidence(context, hunt_run_id, result_ids, hits_count, platform_id=None, observed_at=None):
    """
    Attach the evidence objects to the hunt run when the platform supports it.

    :return: True when attached, False when the mutation is absent
    """
    if not context.detector.require(FEATURE_HUNT_EVIDENCE, "Hunt evidence attachment to the run"):
        return False
    payload = {
        "result_ids": list(result_ids),
        "hits_count": int(hits_count),
        "source": "splunk-alert-action",
    }
    if platform_id:
        payload["security_platform_id"] = platform_id
    if observed_at is not None:
        payload["observed_at"] = to_iso(observed_at)
    context.client.graphql_query(HUNT_EVIDENCE_MUTATION, {"id": hunt_run_id, "input": payload})
    return True
# endregion
