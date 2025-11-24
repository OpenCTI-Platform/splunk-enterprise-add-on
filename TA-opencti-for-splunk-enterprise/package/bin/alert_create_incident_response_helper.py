# encoding = utf-8
import json
from datetime import datetime, timezone

from app_connector_helper import SplunkAppConnectorHelper
from stix_converter import convert_to_incident_response
from constants import CONNECTOR_NAME, CONNECTOR_ID
from splunktaucclib.alert_actions_base import ModularAlertBase


def create_incident_response(helper, event):
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
        "name": helper.get_param("name"),
        "description": helper.get_param("description"),
        "type": helper.get_param("type"),
        "severity": helper.get_param("severity"),
        "priority": helper.get_param("priority"),
        "labels": labels,
        "tlp": helper.get_param("tlp"),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "observables_extraction": helper.get_param("observables_extraction")
    }
    helper.log_debug("Alert params={}".format(params))

    opencti_url = helper.get_global_setting("opencti_url")
    opencti_api_key = helper.get_global_setting("opencti_api_key")
    proxies = helper.get_proxy()

    # init splunk connector helper
    splunk_app_connector = SplunkAppConnectorHelper(
        connector_id=CONNECTOR_ID,
        connector_name=CONNECTOR_NAME,
        opencti_url=opencti_url,
        opencti_api_key=opencti_api_key,
        proxies=proxies
    )

    # convert to_stix
    bundle = convert_to_incident_response(
        alert_params=params,
        event=event
    )

    # going to register App as an OpenCTI connector
    # TODO: Do this only on time (at first run)
    try:
        splunk_app_connector.register()
    except Exception as ex:
        helper.log_error(f"Unable to create incident response case, "
                         f"an exception occurred while registering App as OpenCTI connector, "
                         f"exception: {str(ex)}")
        return

    try:
        splunk_app_connector.send_stix_bundle(bundle=bundle)
        helper.log_info("STIX bundle has been sent successfully")
    except Exception as ex:
        helper.log_error(f"Unable to create incident response case, "
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
    helper.log_info("Alert action create_incident_response started.")
    helper.set_log_level(helper.log_level)

    events = helper.get_events()
    for event in events:
        helper.log_debug("event={}".format(json.dumps(event)))
        create_incident_response(helper, event)

    return 0
