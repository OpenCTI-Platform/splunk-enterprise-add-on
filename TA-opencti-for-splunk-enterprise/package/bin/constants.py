import os
import logging

# Hard-coded OpenCTI connector identifier.
CONNECTOR_ID = "a6edc906-2f9f-5fb2-a373-efac406f0ef3"
CONNECTOR_NAME = "Splunk Enterprise App"  # hard-coded opencti connector name
ADDON_NAME = "TA-opencti-for-splunk-enterprise"
INDICATORS_KVSTORE_NAME = "opencti_indicators"
REPORTS_KVSTORE_NAME = "opencti_reports"
MARKINGS_KVSTORE_NAME = "opencti_markings"
IDENTITIES_KVSTORE_NAME = "opencti_identities"


def resolve_ssl_verify(ca_bundle_path=""):
    """
    Resolve the value to pass as ``verify=`` to requests/SSEClient.

    :param ca_bundle_path: optional path to a PEM-formatted CA bundle file.
    :return:
        - A file path string if ca_bundle_path is provided and the file exists
        - True to use the default certificate store
    """
    if ca_bundle_path and ca_bundle_path.strip():
        path = ca_bundle_path.strip()
        if os.path.isfile(path):
            return path
        warning_msg = (
            "CA bundle path '%s' not found, "
            "falling back to default certificate store"
        )
        logging.getLogger(__name__).warning(warning_msg, path)

    return True
