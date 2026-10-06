# encoding = utf-8
from alert_common import parse_labels, run_alert
from program_actions import resolve_sighted_indicator
from stix_converter import INDICATOR_SIGHTING_TYPES, SIGHTING_OF_INDICATOR_ID, convert_to_sighting, sighting_indicator_type
from splunktaucclib.alert_actions_base import ModularAlertBase  # type: ignore


def create_sighting(context, event):
    """
    :param context: alert_common.AlertContext
    :param event: the Splunk result
    :return: True on success
    """
    helper = context.helper
    params = {
        "sighting_of_value": helper.get_param("sighting_of_value"),
        "sighting_of_type": helper.get_param("sighting_of_type"),
        "where_sighted_value": helper.get_param("where_sighted_value"),
        "where_sighted_type": helper.get_param("where_sighted_type"),
        "count": helper.get_param("count"),
        "labels": parse_labels(helper.get_param("labels")),
        "tlp": helper.get_param("tlp"),
    }
    helper.log_debug(f"Alert params={params}")

    sighting_of_type = sighting_indicator_type(params["sighting_of_type"])
    if sighting_of_type != (params["sighting_of_type"] or ""):
        helper.log_info(f"Sighting of Type {params['sighting_of_type']} sights the indicator ({sighting_of_type})")
    try:
        indicator = None
        if sighting_of_type == SIGHTING_OF_INDICATOR_ID or sighting_of_type in INDICATOR_SIGHTING_TYPES:
            indicator = resolve_sighted_indicator(
                context,
                sighting_of_type,
                params["sighting_of_value"],
                INDICATOR_SIGHTING_TYPES.get(sighting_of_type),
            )
        platform_ref = None
        if context.flag("sighted_on_platform", True):
            platform = context.platform
            platform_ref = platform.get("standard_id") if platform else None
        bundle = convert_to_sighting(
            alert_params=params,
            event=event,
            platform_ref=platform_ref,
            indicator=indicator,
        )
    except Exception as ex:
        helper.log_error(
            "Unable to create sighting, "
            "an exception occurred while converting event to STIX, "
            f"exception: {str(ex)}"
        )
        return False

    try:
        context.client.register()
    except Exception as ex:
        helper.log_error(
            "Unable to create sighting, "
            "an exception occurred while registering App as OpenCTI "
            "connector, "
            f"exception: {str(ex)}"
        )
        return False

    try:
        context.client.send_stix_bundle(bundle=bundle)
        helper.log_info("STIX bundle has been sent successfully")
    except Exception as ex:
        helper.log_error(f"Unable to create sighting, "
                         f"an exception occurred while sending STIX bundle, "
                         f"exception: {str(ex)}")
        return False
    return True


def process_event(helper: ModularAlertBase, *args, **kwargs):
    """
    :param helper:
    :param args:
    :param kwargs:
    :return: 0 when every result was sent, 2 otherwise (#18)
    """
    return run_alert(helper, "create_sighting", create_sighting)
