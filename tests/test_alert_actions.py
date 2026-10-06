"""Tests for the alert action plumbing: exit codes (#18) and GraphQL errors (#19)."""
import unittest
from unittest import mock

from program_fakes import FakeAlertContext, FakeAlertHelper

import alert_common
from app_connector_helper import OpenCTIGraphQLError, SplunkAppConnectorHelper


def _run(handler, helper, context):
    return alert_common.run_alert(helper, "test", handler, context_factory=lambda _helper: context)


class GraphQLErrorTest(unittest.TestCase):
    """#19: register() and send_stix_bundle() go through graphql_query error checking."""

    def setUp(self):
        SplunkAppConnectorHelper._registered.clear()
        self.connector = SplunkAppConnectorHelper("id", "name", "https://opencti.example", "key", {})

    def _response(self, payload, status=200):
        response = mock.Mock(status_code=status, content=b"body")
        response.json.return_value = payload
        return response

    def test_bundle_push_with_graphql_errors_raises(self):
        with mock.patch("app_connector_helper.requests.post", return_value=self._response({"errors": [{"message": "FORBIDDEN"}]})):
            with self.assertRaises(OpenCTIGraphQLError) as caught:
                self.connector.send_stix_bundle("{}")
        self.assertTrue(caught.exception.mentions("forbidden"))

    def test_register_with_graphql_errors_raises(self):
        with mock.patch("app_connector_helper.requests.post", return_value=self._response({"errors": [{"message": "denied"}]})):
            with self.assertRaises(OpenCTIGraphQLError):
                self.connector.register()

    def test_register_once_per_process(self):
        payload = {"data": {"registerConnector": {"id": "id", "connector_state": None, "connector_user_id": "u"}}}
        with mock.patch("app_connector_helper.requests.post", return_value=self._response(payload)) as post:
            self.connector.register()
            self.connector.register()
        self.assertEqual(post.call_count, 1)

    def test_http_error_raises_with_status(self):
        with mock.patch("app_connector_helper.requests.post", return_value=self._response({}, status=502)):
            with self.assertRaises(OpenCTIGraphQLError) as caught:
                self.connector.send_stix_bundle("{}")
        self.assertEqual(caught.exception.status_code, 502)

    def test_network_error_raises(self):
        import requests

        with mock.patch("app_connector_helper.requests.post", side_effect=requests.ConnectionError("down")):
            with self.assertRaises(OpenCTIGraphQLError):
                self.connector.graphql_query("query { about { version } }")

    def test_requests_have_a_timeout(self):
        with mock.patch("app_connector_helper.requests.post", return_value=self._response({"data": {"stixBundlePush": "ok"}})) as post:
            self.connector.send_stix_bundle("{}")
        self.assertIsNotNone(post.call_args.kwargs["timeout"])


class ExitCodeTest(unittest.TestCase):
    """#18: process_event reports failures to Splunk."""

    def test_zero_when_every_result_succeeds(self):
        helper = FakeAlertHelper(events=[{}, {}])
        self.assertEqual(_run(lambda c, e: True, helper, FakeAlertContext(helper)), 0)

    def test_non_zero_when_a_result_fails(self):
        helper = FakeAlertHelper(events=[{}, {}, {}])
        results = iter([True, False, True])
        self.assertEqual(_run(lambda c, e: next(results), helper, FakeAlertContext(helper)), 2)
        self.assertIn("1 of 3 results failed", helper.errors()[-1])

    def test_exception_in_a_result_is_a_failure(self):
        helper = FakeAlertHelper(events=[{"rid": "0"}])

        def boom(context, event):
            raise ValueError("bad result")

        self.assertEqual(_run(boom, helper, FakeAlertContext(helper)), 2)

    def test_unusable_configuration_is_a_failure(self):
        helper = FakeAlertHelper(events=[{}])

        def factory(_helper):
            raise ValueError("OpenCTI URL and API key must be configured")

        self.assertEqual(alert_common.run_alert(helper, "test", lambda c, e: True, context_factory=factory), 2)


class HelperLoggerTest(unittest.TestCase):
    def test_maps_levels(self):
        helper = FakeAlertHelper()
        logger = alert_common.HelperLogger(helper)
        logger.info("i")
        logger.warning("w")
        logger.error("e")
        logger.debug("d")
        self.assertEqual([level for level, _ in helper.logs], ["info", "warning", "error", "debug"])

    def test_parse_labels(self):
        self.assertEqual(alert_common.parse_labels(" a, ,b ,"), ["a", "b"])
        self.assertEqual(alert_common.parse_labels(None), [])


if __name__ == "__main__":
    unittest.main()
