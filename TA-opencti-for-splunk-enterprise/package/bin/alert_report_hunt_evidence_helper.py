# encoding = utf-8
from alert_common import parse_labels, run_alert
from program_actions import hunt_targets, report_hunt_evidence as attach_hunt_evidence
from stix_converter import convert_to_hunt_evidence, sighting_count
from utils import to_epoch
from splunktaucclib.alert_actions_base import ModularAlertBase  # type: ignore


def report_hunt_evidence(context, event):
    """
    :param context: alert_common.AlertContext
    :param event: the Splunk result
    :return: True on success
    """
    helper = context.helper
    hunt_run_id = (helper.get_param("hunt_run_id") or event.get("hunt_run_id") or "").strip()
    params = {
        "tlp": helper.get_param("tlp"),
        "labels": parse_labels(helper.get_param("labels")),
        "observables_extraction": helper.get_param("observables_extraction") or "cim_model",
        "count": helper.get_param("count"),
        "search_name": context.search_name,
    }
    helper.log_debug(f"Alert params={params} hunt_run_id={hunt_run_id}")

    try:
        targets, hunt_name = hunt_targets(context, hunt_run_id) if hunt_run_id else ([], None)
        platform = context.platform
        platform_ref = platform.get("standard_id") if platform else None
        bundle, result_ids = convert_to_hunt_evidence(
            alert_params=params,
            event=event,
            hunt_run_id=hunt_run_id,
            platform_ref=platform_ref,
            targets=targets,
        )
    except Exception as ex:
        helper.log_error(
            "Unable to report hunt evidence, "
            "an exception occurred while converting event to STIX, "
            f"exception: {str(ex)}"
        )
        return False

    try:
        context.client.register()
        context.client.send_stix_bundle(bundle=bundle)
    except Exception as ex:
        helper.log_error(
            "Unable to report hunt evidence, "
            "an exception occurred while sending the STIX bundle, "
            f"exception: {str(ex)}"
        )
        return False
    helper.log_info(
        f"Hunt evidence for run {hunt_run_id} ({hunt_name or 'unknown hunt'}) sent: "
        f"{len(result_ids)} objects, {len(targets)} hunt targets sighted"
    )

    try:
        attach_hunt_evidence(
            context,
            hunt_run_id,
            result_ids,
            hits_count=sighting_count(params["count"]),
            platform_id=platform.get("id") if platform else None,
            observed_at=to_epoch(event.get("_time")),
        )
    except Exception as ex:
        # The evidence itself is in OpenCTI (bundle above), only the link to the run failed.
        helper.log_warn(f"Hunt evidence sent but not attached to run {hunt_run_id}: {ex}")
    return True


def process_event(helper: ModularAlertBase, *args, **kwargs):
    """
    :param helper:
    :param args:
    :param kwargs:
    :return: 0 when every result was sent, 2 otherwise
    """
    return run_alert(helper, "report_hunt_evidence", report_hunt_evidence)
