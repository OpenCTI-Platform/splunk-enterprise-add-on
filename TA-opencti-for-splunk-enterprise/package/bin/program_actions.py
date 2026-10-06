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


def schedule_container_followups(context, container_id, event):
    """
    Defer the Case Autopilot run of a container created by an alert until
    OpenCTI has ingested it (alert_common).

    :param context: alert_common.AlertContext
    :param container_id: STIX id of the Incident / Case-Incident
    :param event: the Splunk result
    """
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
    :param kind: FOLLOWUP_CASE_AUTOPILOT
    :param params: JSON parameters recorded when it was deferred
    """
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
