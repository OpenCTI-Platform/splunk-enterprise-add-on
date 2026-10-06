# encoding = utf-8
from alert_common import parse_labels, run_alert
from program_actions import schedule_container_followups
from stix_converter import convert_to_incident
from splunktaucclib.alert_actions_base import ModularAlertBase  # type: ignore


def create_incident(context, event):
    """
    :param context: alert_common.AlertContext
    :param event: the Splunk result
    :return: True on success
    """
    helper = context.helper
    helper.log_info(helper.get_param("observables_extraction"))

    params = {
        "name": helper.get_param("name"),
        "description": helper.get_param("description"),
        "type": helper.get_param("type"),
        "severity": helper.get_param("severity"),
        "labels": parse_labels(helper.get_param("labels")),
        "tlp": helper.get_param("tlp"),
        "observables_extraction": helper.get_param("observables_extraction"),
    }
    helper.log_debug(f"Alert params={params}")

    # convert to_stix
    try:
        bundle, incident_id = convert_to_incident(
            alert_params=params,
            event=event,
            return_id=True,
        )
    except Exception as ex:
        helper.log_error(
            "Unable to create incident, "
            "an exception occurred while converting event to STIX, "
            f"exception: {str(ex)}"
        )
        return False

    try:
        context.client.register()
    except Exception as ex:
        helper.log_error(
            "Unable to create incident, "
            "an exception occurred while registering App as OpenCTI "
            "connector, "
            f"exception: {str(ex)}"
        )
        return False

    try:
        context.client.send_stix_bundle(bundle=bundle)
        helper.log_info("STIX bundle has been sent successfully")
    except Exception as ex:
        helper.log_error(f"Unable to create incident, "
                         f"an exception occurred while sending STIX bundle, "
                         f"exception: {str(ex)}")
        return False

    schedule_container_followups(context, incident_id, event, container_name=params["name"])
    return True


def process_event(helper: ModularAlertBase, *args, **kwargs):
    """
    :param helper:
    :param args:
    :param kwargs:
    :return: 0 when every result was sent, 2 otherwise (#18)
    """
    return run_alert(helper, "create_incident", create_incident)
