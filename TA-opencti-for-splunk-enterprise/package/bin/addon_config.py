"""Add-on settings of the alert actions.

Alert actions read the values through ``helper.get_global_setting`` (see
alert_common.py) into an ``AddonSettings``.
"""

from constants import CONNECTOR_ID, CONNECTOR_NAME, resolve_ssl_verify
from security_platform import PlatformSettings

# Configuration > Security Platform tab (globalConfig.json, stanza "platform")
PLATFORM_STANZA = "platform"
DEFAULTS = {
    "security_platform_id": "",
    "security_platform_auto_create": "1",
    "security_platform_name": "",
    "feature_cache_ttl": "60",
}


def is_true(value, default=False):
    """
    :param value: UCC checkbox value ("0" / "1"), bool, or None
    :return: bool
    """
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "t", "y", "on")


def to_int(value, default, minimum=None, maximum=None):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        number = default
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


class AddonSettings:
    def __init__(self, account, platform=None, proxy_settings=None, user_agent=None, server_name=""):
        """
        :param account: dict with opencti_url, opencti_api_key, ca_bundle_path
        :param platform: dict of the platform tab fields (see DEFAULTS)
        :param proxy_settings: proxy dict (either shape, see utils.get_proxy_config)
        :param user_agent: User-Agent sent to OpenCTI
        :param server_name: Splunk server name
        """
        account = account or {}
        values = dict(DEFAULTS)
        values.update({k: v for k, v in (platform or {}).items() if v is not None})
        self.opencti_url = (account.get("opencti_url") or "").strip().rstrip("/")
        self.opencti_api_key = account.get("opencti_api_key") or ""
        self.ca_bundle_path = account.get("ca_bundle_path") or ""
        self.proxy_settings = proxy_settings or {}
        self.user_agent = user_agent
        self.server_name = server_name or ""
        self.platform = PlatformSettings.from_mapping(values)
        self.feature_cache_ttl = to_int(values.get("feature_cache_ttl"), 60, 1, 1440) * 60

    @property
    def ssl_verify(self):
        return resolve_ssl_verify(self.ca_bundle_path)

    def build_client(self, connector_id=CONNECTOR_ID, connector_name=CONNECTOR_NAME):
        from app_connector_helper import SplunkAppConnectorHelper

        if not self.opencti_url or not self.opencti_api_key:
            raise ValueError(
                "OpenCTI URL and API key must be configured (Configuration > Account)"
            )
        return SplunkAppConnectorHelper(
            connector_id=connector_id,
            connector_name=connector_name,
            opencti_url=self.opencti_url,
            opencti_api_key=self.opencti_api_key,
            proxy_settings=self.proxy_settings,
            verify=self.ssl_verify,
            user_agent=self.user_agent,
        )


def settings_from_alert_helper(helper):
    """
    :param helper: splunktaucclib ModularAlertBase
    :return: AddonSettings built from the alert action helper
    """
    import utils

    account = {
        "opencti_url": helper.get_global_setting("opencti_url"),
        "opencti_api_key": helper.get_global_setting("opencti_api_key"),
        "ca_bundle_path": helper.get_global_setting("ca_bundle_path") or "",
    }
    platform = {}
    for key in DEFAULTS:
        try:
            value = helper.get_global_setting(key)
        except Exception:
            value = None
        if value is not None:
            platform[key] = value
    server_name = (getattr(helper, "settings", None) or {}).get("server_host") or ""
    return AddonSettings(
        account=account,
        platform=platform,
        proxy_settings=helper.get_proxy() or {},
        user_agent=utils.get_user_agent(helper.session_key),
        server_name=server_name,
    )
