# encoding = utf-8
from alert_common import parse_labels, run_alert
from program_actions import schedule_container_followups
from stix_converter import convert_to_incident_response
from splunktaucclib.alert_actions_base import ModularAlertBase  # type: ignore


def create_incident_response(context, event):
    """
    :param context: alert_common.AlertContext
    :param event: the Splunk result
    :return: True on success
    """
    helper = context.helper
    params = {
        "name": helper.get_param("name"),
        "description": helper.get_param("description"),
        "type": helper.get_param("type"),
        "severity": helper.get_param("severity"),
        "priority": helper.get_param("priority"),
        "labels": parse_labels(helper.get_param("labels")),
        "tlp": helper.get_param("tlp"),
        "observables_extraction": helper.get_param("observables_extraction"),
        "incident_key": helper.get_param("incident_key"),
        "sid": context.sid,
    }
    helper.log_debug("Alert params={}".format(params))

    # convert to_stix
    try:
        bundle, case_id = convert_to_incident_response(
            alert_params=params,
            event=event,
            return_id=True,
            used_ids=getattr(context, "container_ids", None),
        )
    except Exception as ex:
        helper.log_error(
            "Unable to create incident response case, "
            "an exception occurred while converting event to STIX, "
            f"exception: {str(ex)}"
        )
        return False

    try:
        context.client.register()
    except Exception as ex:
        helper.log_error(
            "Unable to create incident response case, "
            "an exception occurred while registering App as OpenCTI "
            "connector, "
            f"exception: {str(ex)}"
        )
        return False

    try:
        context.client.send_stix_bundle(bundle=bundle)
        helper.log_info("STIX bundle has been sent successfully")
    except Exception as ex:
        helper.log_error(f"Unable to create incident response case, "
                         f"an exception occurred while sending STIX bundle, "
                         f"exception: {str(ex)}")
        return False

    schedule_container_followups(context, case_id, event)
    return True


def process_event(helper: ModularAlertBase, *args, **kwargs):
    """
    :param helper:
    :param args:
    :param kwargs:
    :return: 0 when every result was sent, 2 otherwise (#18)
    """
    return run_alert(helper, "create_incident_response", create_incident_response)
