"""
Tests for the registration of the Splunk App as an OpenCTI connector (#79).

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

from app_connector_helper import GraphQLError, SplunkAppConnectorHelper  # noqa: E402

OK = {"data": {"result": True}}
INVALID_CONNECTOR = {"errors": [{"message": "Invalid bundle"}], "data": None}


def _response(payload, status_code=200):
    return mock.Mock(status_code=status_code, content=b"", **{"json.return_value": payload})


def _connector():
    return SplunkAppConnectorHelper(
        connector_id="a6edc906-2f9f-5fb2-a373-efac406f0ef3",
        connector_name="Splunk Enterprise App",
        opencti_url="https://opencti.example",
        opencti_api_key="key",
        proxy_settings={},
    )


def _operations(post):
    """GraphQL operations sent, in order: stixBundlePush, registerConnector, pingConnector."""
    operations = []
    for call in post.call_args_list:
        query = call.kwargs["json"]["query"]
        operations.append(next(op for op in ("stixBundlePush", "registerConnector", "pingConnector") if op in query))
    return operations


class SendStixBundleTest(unittest.TestCase):

    def _send(self, *payloads):
        with mock.patch("app_connector_helper.requests.post", side_effect=list(payloads)) as post:
            self.registered = _connector().send_stix_bundle(bundle="{}")
        return post

    def test_registered_connector_is_not_registered_again(self):
        post = self._send(_response(OK))
        self.assertEqual(_operations(post), ["stixBundlePush"])
        self.assertFalse(self.registered)

    def test_unregistered_connector_registers_then_pushes_again(self):
        post = self._send(_response(INVALID_CONNECTOR), _response(OK), _response(OK), _response(OK))
        self.assertEqual(_operations(post), ["stixBundlePush", "registerConnector", "pingConnector", "stixBundlePush"])
        self.assertTrue(self.registered)

    def test_ping_declares_an_external_schedule(self):
        post = self._send(_response(INVALID_CONNECTOR), _response(OK), _response(OK), _response(OK))
        variables = post.call_args_list[2].kwargs["json"]["variables"]
        self.assertTrue(variables["connectorInfo"]["run_and_terminate"])

    def test_ping_failure_does_not_block_the_push(self):
        # OpenCTI < 6.2.12 has no connectorInfo
        post = self._send(_response(INVALID_CONNECTOR), _response(OK), _response(INVALID_CONNECTOR), _response(OK))
        self.assertEqual(_operations(post)[-1], "stixBundlePush")

    def test_second_push_failure_is_raised(self):
        with self.assertRaises(GraphQLError):
            self._send(_response(INVALID_CONNECTOR), _response(OK), _response(OK), _response(INVALID_CONNECTOR))

    def test_registration_failure_raises_the_push_error(self):
        push_error = {"errors": [{"message": "push error"}]}
        with self.assertRaisesRegex(GraphQLError, "push error"):
            self._send(_response(push_error), _response({"errors": [{"message": "register error"}]}))

    def test_http_error_is_raised_without_retry(self):
        with mock.patch("app_connector_helper.requests.post", return_value=_response(OK, status_code=502)) as post:
            with self.assertRaisesRegex(Exception, "HTTP 502"):
                _connector().send_stix_bundle(bundle="{}")
        self.assertEqual(_operations(post), ["stixBundlePush"])


class RegisterTest(unittest.TestCase):

    def test_register_requests_only_the_connector_id(self):
        with mock.patch("app_connector_helper.requests.post", return_value=_response(OK)) as post:
            _connector().register()
        query = post.call_args.kwargs["json"]["query"]
        self.assertNotIn("connection", query)
        self.assertNotIn("pass", query)

    def test_register_raises_graphql_errors(self):
        with mock.patch("app_connector_helper.requests.post", return_value=_response(INVALID_CONNECTOR)):
            with self.assertRaises(GraphQLError):
                _connector().register()


if __name__ == "__main__":
    unittest.main()
