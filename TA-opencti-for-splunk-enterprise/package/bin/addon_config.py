"""Add-on settings shared by the modular input and the custom search commands."""

from constants import ADDON_NAME, CONNECTOR_ID, CONNECTOR_NAME, resolve_ssl_verify
from security_platform import PlatformSettings

SETTINGS_CONF = "ta-opencti-for-splunk-enterprise_settings"
SETTINGS_REALM = f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-{SETTINGS_CONF}"

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


def _stanza(conf, name):
    try:
        return conf.get(name) or {}
    except Exception:
        return {}


def load_settings(session_key, logger=None):
    """
    Read the add-on configuration through splunkd (decrypting the API key).

    :param session_key: Splunk session key
    :return: AddonSettings
    """
    import solnlib.conf_manager as conf_manager  # type: ignore
    from solnlib import splunkenv  # type: ignore
    import utils

    cfm = conf_manager.ConfManager(session_key, ADDON_NAME, realm=SETTINGS_REALM)
    conf = cfm.get_conf(SETTINGS_CONF)
    account = _stanza(conf, "account")
    platform = _stanza(conf, PLATFORM_STANZA)
    # The proxy stanza always ships (its type has a default), so a read failure
    # means a configured proxy is unusable: never fall back to a direct connection.
    try:
        proxy_settings = conf_manager.get_proxy_dict(
            logger=logger,
            session_key=session_key,
            app_name=ADDON_NAME,
            conf_name=SETTINGS_CONF,
        ) or {}
    except Exception as ex:
        raise RuntimeError(f"Proxy settings unreadable, not connecting to OpenCTI: {ex}") from ex
    server_name = ""
    try:
        server_name = splunkenv.get_splunk_host_info(session_key)[0]
    except Exception as ex:
        if logger is not None:
            logger.info(f"Splunk server name unreadable: {ex}")
    return AddonSettings(
        account=account,
        platform=platform,
        proxy_settings=proxy_settings,
        user_agent=utils.get_user_agent(session_key),
        server_name=server_name,
    )
