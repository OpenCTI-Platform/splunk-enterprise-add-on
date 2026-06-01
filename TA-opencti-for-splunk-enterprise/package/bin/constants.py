import os
import logging

# Hard-coded OpenCTI connector identifier.
CONNECTOR_ID = "a6edc906-2f9f-5fb2-a373-efac406f0ef3"
CONNECTOR_NAME = "Splunk Enterprise App"  # hard-coded opencti connector name
ADDON_NAME = "TA-opencti-for-splunk-enterprise"
VERIFY_SSL = True  # Default: secure. On-prem only: set to False at own risk.
INDICATORS_KVSTORE_NAME = "opencti_indicators"
REPORTS_KVSTORE_NAME = "opencti_reports"
MARKINGS_KVSTORE_NAME = "opencti_markings"
IDENTITIES_KVSTORE_NAME = "opencti_identities"


def resolve_ssl_verify(ca_bundle_path=""):
    """
    Resolve the value to pass as ``verify=`` to requests/SSEClient.

    Three-tier cascade:
    1. If VERIFY_SSL is explicitly set to False -> return False (on-prem escape hatch)
    2. If ca_bundle_path is provided and exists -> return the path (custom CA)
    3. Otherwise -> return True (default system/certifi store)

    :param ca_bundle_path: optional path to a PEM-formatted CA bundle file.
    :return: False, a file path string, or True
    """
    if not VERIFY_SSL:
        logging.getLogger(__name__).warning(
            "VERIFY_SSL is set to False - SSL verification is disabled. "
            "This is NOT recommended and will fail Splunk Cloud Vetting."
        )
        return False

    if ca_bundle_path and ca_bundle_path.strip():
        path = ca_bundle_path.strip()
        if os.path.isfile(path):
            return path
        logging.getLogger(__name__).warning(
            "CA bundle path '%s' not found, "
            "falling back to default certificate store",
            path,
        )

    return True
