# encoding = utf-8
import json
from app_connector_helper import SplunkAppConnectorHelper
from stix_converter import convert_to_sighting
from constants import CONNECTOR_NAME, CONNECTOR_ID
from splunktaucclib.alert_actions_base import ModularAlertBase


def create_sighting(helper, event):
    """
    :param helper:
    :param event:
    :return:
    """
    if helper.get_param("labels"):
        labels = [x.strip() for x in helper.get_param("labels").split(',')]
    else:
        labels = []
    # remove potential empty labels
    labels = list(filter(None, labels))

    params = {
        "sighting_of_value": helper.get_param("sighting_of_value"),
        "sighting_of_type": helper.get_param("sighting_of_type"),
        "where_sighted_value": helper.get_param("where_sighted_value"),
        "where_sighted_type": helper.get_param("where_sighted_type"),
        "labels": labels,
        "tlp": helper.get_param("tlp"),
    }

    helper.log_debug(f"Alert params={params}")

    opencti_url = helper.get_global_setting("opencti_url")
    opencti_api_key = helper.get_global_setting("opencti_api_key")
    proxies = helper.get_proxy()

    splunk_app_connector = SplunkAppConnectorHelper(
        connector_id=CONNECTOR_ID,
        connector_name=CONNECTOR_NAME,
        opencti_url=opencti_url,
        opencti_api_key=opencti_api_key,
        proxies=proxies
    )

    # convert to_stix
    bundle = convert_to_sighting(
        alert_params=params,
        event=event
    )

    # going to register App as an OpenCTI connector
    # TODO: Do this only on time (at first run)
    try:
        splunk_app_connector.register()
    except Exception as ex:
        helper.log_error(f"Unable to create sighting, "
                         f"an exception occurred while registering App as OpenCTI connector, "
                         f"exception: {str(ex)}")
        return

    try:
        splunk_app_connector.send_stix_bundle(bundle=bundle)
        helper.log_info("STIX bundle has been sent successfully")
    except Exception as ex:
        helper.log_error(f"Unable to create sighting, "
                         f"an exception occurred while sending STIX bundle,"
                         f"exception: {str(ex)}")
        return


def process_event(helper: ModularAlertBase, *args, **kwargs):
    """
    :param helper:
    :param args:
    :param kwargs:
    :return:
    """
    helper.log_info("Alert action create_sighting started.")
    helper.set_log_level(helper.log_level)

    events = helper.get_events()
    for event in events:
        helper.log_debug("event={}".format(json.dumps(event)))
        create_sighting(helper, event)

    return 0
