"""OpenCTI program calls made by the alert actions, each feature detected.

- Run Case Autopilot on the Incident / Case-Incident created by an alert
  (innovation 02, investigationRunAdd, Enterprise Edition), at most once per
  container.
"""

from datetime import datetime, timezone

from addon_state import take_over, utc_now_iso
from opencti_features import FEATURE_CASE_AUTOPILOT
from utils import parse_iso

AUTOPILOT_RESERVATION_SECONDS = 3600
FOLLOWUP_CASE_AUTOPILOT = "case_autopilot"

AUTOPILOT_ADD_MUTATION = """
mutation SplunkCaseAutopilot($subjectId: ID!, $policyId: ID) {
  investigationRunAdd(subjectId: $subjectId, policyId: $policyId) { id }
}
"""

AUTOPILOT_RUNS_QUERY = """
query SplunkCaseAutopilotRuns($subjectId: String) {
  investigationRuns(subjectId: $subjectId, first: 1) { edges { node { id } } }
}
"""


class FollowupWaiting(Exception):
    """A follow-up that cannot run yet and has not failed: it stays parked (alert_common)."""


def schedule_container_followups(context, container_id, event, container_name=None):
    """
    Defer the Case Autopilot run of a container created by an alert until
    OpenCTI has ingested it (alert_common).

    :param context: alert_common.AlertContext
    :param container_id: STIX id of the Incident / Case-Incident
    :param event: the Splunk result
    :param container_name: name of the Incident / Case-Incident
    """
    if context.flag("run_case_autopilot", False) and context.detector.require(
        FEATURE_CASE_AUTOPILOT, "Run Case Autopilot"
    ):
        context.defer(container_id, "Run Case Autopilot", FOLLOWUP_CASE_AUTOPILOT, {
            "policy_id": context.param("autopilot_policy_id", ""),
            "container_name": container_name,
            "search_name": context.search_name,
        })


def run_followup(context, kind, container_id, params):
    """
    Run a follow-up deferred by schedule_container_followups, possibly parked
    by an earlier alert run: everything it needs is in ``params``.

    :param context: alert_common.AlertContext
    :param kind: FOLLOWUP_CASE_AUTOPILOT
    :param params: JSON parameters recorded when it was deferred
    """
    if kind == FOLLOWUP_CASE_AUTOPILOT:
        return run_case_autopilot(context, container_id, params.get("policy_id"),
                                  params.get("container_name"), params.get("search_name"))
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


def _log_quoted(value):
    """Double-quoted for the log line the Case Autopilot dashboard tab extracts with rex."""
    return '"' + " ".join(str(value or "").replace('"', "'").split()) + '"'


def existing_autopilot_run(context, container_id):
    """:return: id of a Case Autopilot run OpenCTI already holds for this container, or None"""
    data = context.client.graphql_query(AUTOPILOT_RUNS_QUERY, {"subjectId": container_id})
    for edge in ((data.get("investigationRuns") or {}).get("edges")) or []:
        node = (edge or {}).get("node") or {}
        if node.get("id"):
            return node["id"]
    return None


def run_case_autopilot(context, container_id, policy_id=None, container_name=None, search_name=None):
    """
    Run Case Autopilot once per container (repeated alerts on the same
    incident do not start new runs). OpenCTI is the reference: a container
    that already has a run is never given another one, whatever the add-on
    state says, so a retry after an unanswered request never starts twice.

    :param context: alert_common.AlertContext
    :param container_name: name of the Incident / Case-Incident (logged for the dashboard)
    :param search_name: alert that created the container (default: the running alert)
    :return: id of the run started, or None when skipped
    :raise FollowupWaiting: another alert run is starting it
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
        if existing.get("status") == "pending":
            raise FollowupWaiting(f"Case Autopilot is being started for {container_id} by another alert run")
        context.logger.info(f"Case Autopilot already run for {container_id}")
        return None
    if existing:
        context.logger.warning(f"Case Autopilot reservation for {container_id} never completed, retrying")
    # Atomic: of concurrent alert runs on one container, one only starts a run.
    # The takeover keys stay: a process that read the stale reservation late
    # can never take it over again once the run is recorded.
    reservation = {"status": "pending", "reserved_at": utc_now_iso()}
    if take_over(context.cache, marker, reservation, _stale_reservation) is None:
        raise FollowupWaiting(f"Case Autopilot is being started for {container_id} by another alert run")
    try:
        known_run = existing_autopilot_run(context, container_id)
        if known_run is None:
            data = context.client.graphql_query(AUTOPILOT_ADD_MUTATION, {
                "subjectId": container_id,
                "policyId": (policy_id or "").strip() or None,
            })
    except Exception:
        # Safe to retry: the next attempt asks OpenCTI first
        context.cache.release(marker)
        raise
    run_id = known_run or (data.get("investigationRunAdd") or {}).get("id")
    try:
        context.cache.set(marker, {"run_id": run_id, "launched_at": utc_now_iso()})
    except Exception as ex:
        context.logger.error(
            f"Case Autopilot run {run_id} of {container_id} not recorded in the add-on state collection "
            f"(the next attempt finds it in OpenCTI): {ex}"
        )
    if known_run:
        context.logger.info(f"Case Autopilot run {known_run} already exists for {container_id}: not started again")
        return None
    context.logger.info(
        f"Case Autopilot run {run_id} started for {container_id} on {_log_quoted(container_name)} "
        f"for the alert {_log_quoted(context.search_name if search_name is None else search_name)}"
    )
    return run_id
# endregion
