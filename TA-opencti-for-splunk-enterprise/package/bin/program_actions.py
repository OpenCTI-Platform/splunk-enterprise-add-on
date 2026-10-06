"""OpenCTI program calls made by the alert actions, each feature detected.

- Timeline milestone on the Incident / Case-Incident created by an alert
  (innovation 11, timelineEventAdd, idempotent through external_id).
"""

import re
from datetime import datetime, timezone

from addon_state import state_key
from app_connector_helper import OpenCTIGraphQLError
from opencti_features import FEATURE_TIMELINE
from utils import to_iso

FOLLOWUP_TIMELINE = "timeline_milestone"

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
    Defer the timeline milestone of a container created by an alert until
    OpenCTI has ingested it (alert_common).

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


def run_followup(context, kind, container_id, params):
    """
    Run a follow-up deferred by schedule_container_followups, possibly parked
    by an earlier alert run: everything it needs is in ``params``.

    :param context: alert_common.AlertContext
    :param kind: FOLLOWUP_TIMELINE
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
    raise ValueError(f"Unknown follow-up {kind}")
