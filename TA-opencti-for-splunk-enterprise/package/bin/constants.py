import os

CONNECTOR_ID = "a6edc906-2f9f-5fb2-a373-efac406f0ef3"  # hard-coded opencti connector Identifier
CONNECTOR_NAME = "Splunk Enterprise App"  # hard-coded opencti connector name
ADDON_NAME = "TA-opencti-for-splunk-enterprise"
INDICATORS_KVSTORE_NAME = "opencti_indicators"
REPORTS_KVSTORE_NAME = "opencti_reports"
MARKINGS_KVSTORE_NAME = "opencti_markings"
IDENTITIES_KVSTORE_NAME = "opencti_identities"


def resolve_ssl_verify(verify_ssl, ca_bundle_path=""):
    """
    Resolve the value to pass as ``verify=`` to requests/SSEClient.

    :param verify_ssl: bool or truthy value — whether to verify the SSL certificate.
    :param ca_bundle_path: optional path to a PEM-formatted CA bundle file.
    :return:
        - False if verify_ssl is disabled
        - A file path string if ca_bundle_path is provided and the file exists
        - True to use the default certificate store
    """
    # Normalise: UCC checkboxes arrive as "0"/"1" strings
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.strip() == "1"

    if not verify_ssl:
        return False

    if ca_bundle_path and ca_bundle_path.strip():
        path = ca_bundle_path.strip()
        if os.path.isfile(path):
            return path
        # Path provided but does not exist — warn via print since we have no
        # logger reference here; callers should log this themselves.

    return True
