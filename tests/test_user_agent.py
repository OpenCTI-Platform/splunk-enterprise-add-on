"""
Tests for the app-specific User-Agent sent to OpenCTI (#51).

Requires the app's pinned runtime libraries (requests, solnlib, stix2). From
the repository root:
    python3 -m venv .venv && .venv/bin/pip install -r TA-opencti-for-splunk-enterprise/package/lib/requirements.txt
    .venv/bin/python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from unittest import mock

APP_BIN = os.path.join(os.path.dirname(__file__), "..", "TA-opencti-for-splunk-enterprise", "package", "bin")
sys.path.insert(0, os.path.abspath(APP_BIN))

import requests  # noqa: E402
import utils  # noqa: E402
from app_connector_helper import SplunkAppConnectorHelper  # noqa: E402
from constants import ADDON_NAME  # noqa: E402

USER_AGENT = "TA-opencti-for-splunk-enterprise/1.1.0"


def _connector(user_agent=None):
    return SplunkAppConnectorHelper(
        connector_id="id",
        connector_name="name",
        opencti_url="https://opencti.example",
        opencti_api_key="key",
        proxy_settings={},
        user_agent=user_agent,
    )


class GetUserAgentTest(unittest.TestCase):

    def setUp(self):
        utils.get_app_version.cache_clear()

    def test_version_read_from_app_conf_through_splunkd(self):
        with mock.patch.object(utils.splunkenv, "get_conf_key_value", return_value="1.1.0") as get_conf:
            self.assertEqual(utils.get_user_agent("session-key"), USER_AGENT)
        get_conf.assert_called_once_with(
            "app", "launcher", "version", app_name=ADDON_NAME, session_key="session-key"
        )

    def test_version_is_read_once_per_process(self):
        with mock.patch.object(utils.splunkenv, "get_conf_key_value", return_value="1.1.0") as get_conf:
            utils.get_user_agent("session-key")
            utils.get_user_agent("session-key")
        get_conf.assert_called_once()

    def test_falls_back_to_unknown_when_version_cannot_be_read(self):
        with mock.patch.object(utils.splunkenv, "get_conf_key_value", side_effect=KeyError("launcher")):
            self.assertEqual(utils.get_user_agent("session-key"), f"{ADDON_NAME}/unknown")

    def test_falls_back_to_unknown_outside_splunk(self):
        # no splunkd here: solnlib raises ImportError, which must not break requests
        self.assertEqual(utils.get_user_agent("session-key"), f"{ADDON_NAME}/unknown")


class ConnectorUserAgentTest(unittest.TestCase):

    def test_user_agent_sent_with_graphql_requests(self):
        response = mock.Mock(status_code=200)
        response.json.return_value = {"data": {"stixBundlePush": "ok"}}
        with mock.patch("app_connector_helper.requests.post", return_value=response) as post:
            _connector(USER_AGENT).send_stix_bundle(bundle="{}")
        self.assertEqual(post.call_args.kwargs["headers"]["User-Agent"], USER_AGENT)
        self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer key")

    def test_requests_default_kept_without_user_agent(self):
        self.assertNotIn("User-Agent", _connector().headers)

    def test_lowercase_header_overrides_requests_default(self):
        # the stream input passes "user-agent" to SSEClient, which forwards it to requests
        request = requests.Request("GET", "https://opencti.example/stream/x", headers={"user-agent": USER_AGENT})
        prepared = requests.Session().prepare_request(request)
        self.assertEqual(prepared.headers["User-Agent"], USER_AGENT)


if __name__ == "__main__":
    unittest.main()
