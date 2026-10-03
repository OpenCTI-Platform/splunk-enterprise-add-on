"""Shared context of the OpenCTI custom search commands.

The commands run on the search head (never distributed), as the user of the
search: scheduled searches shipped by the add-on run as the app owner, which
can read the encrypted OpenCTI API key. An interactive user without the
list_storage_passwords capability gets a clear error.
"""

import logging

from addon_config import load_settings
from addon_state import KVCollection, KVStoreCache, MemoryCache, connect_service
from constants import ADDON_NAME
from opencti_features import OpenCTIFeatureDetector
from security_platform import SecurityPlatformResolver


def command_logger(name):
    """
    :return: logger writing to the add-on log files (taopenctiforsplunkenterprise:log
        sourcetype), falling back to the standard logging module outside Splunk
    """
    try:
        import solnlib.log as log  # type: ignore

        return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{name}")
    except Exception:
        return logging.getLogger(name)


class CommandContext:
    def __init__(self, command, name):
        """
        :param command: splunklib SearchCommand
        :param name: command name (log file suffix)
        """
        info = command.metadata.searchinfo
        self.session_key = info.session_key
        self.splunkd_uri = getattr(info, "splunkd_uri", None)
        self.logger = command_logger(name)
        self.settings = load_settings(self.session_key, self.logger)
        self.client = self.settings.build_client()
        self.service = connect_service(self.session_key, ADDON_NAME, self.splunkd_uri)
        try:
            self.cache = KVStoreCache(self.service)
        except Exception as ex:
            self.logger.warning(f"Add-on state collection unavailable, caching in memory only: {ex}")
            self.cache = MemoryCache()
        self.detector = OpenCTIFeatureDetector(
            self.client, logger=self.logger, cache=self.cache, ttl=self.settings.feature_cache_ttl
        )
        self._resolver = SecurityPlatformResolver(
            self.client,
            self.detector,
            self.settings.platform,
            server_name=self.settings.server_name,
            cache=self.cache,
            logger=self.logger,
        )

    @property
    def platform(self):
        return self._resolver.resolve()

    def collection(self, name):
        return KVCollection(self.service, name)
