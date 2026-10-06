"""Tests for the OpenCTI GraphQL client: every failure raises OpenCTIGraphQLError (#19)."""
import unittest
from unittest import mock

import requests

import program_fakes  # noqa: F401  (paths and Splunk-only module stubs)

from app_connector_helper import GRAPHQL_TIMEOUT, OpenCTIGraphQLError, SplunkAppConnectorHelper


class GraphQLClientTest(unittest.TestCase):
    """register() and send_stix_bundle() go through graphql_query error checking."""

    def setUp(self):
        SplunkAppConnectorHelper._registered.clear()
        self.connector = SplunkAppConnectorHelper("id", "name", "https://opencti.example/", "key", {})

    def _response(self, payload=None, status=200, json_error=None):
        response = mock.Mock(status_code=status, content=b"body")
        if json_error is not None:
            response.json.side_effect = json_error
        else:
            response.json.return_value = payload
        return response

    def _post(self, response=None, side_effect=None):
        return mock.patch("app_connector_helper.requests.post", return_value=response, side_effect=side_effect)

    def test_success_returns_the_data_member(self):
        with self._post(self._response({"data": {"about": {"version": "7"}}})) as post:
            self.assertEqual(self.connector.graphql_query("query { about { version } }"), {"about": {"version": "7"}})
        self.assertEqual(post.call_args.kwargs["url"], "https://opencti.example/graphql")

    def test_http_200_with_graphql_errors_raises_with_the_messages(self):
        errors = [{"message": "FORBIDDEN_ACCESS"}, {"message": "Validation failed"}]
        with self._post(self._response({"data": None, "errors": errors})):
            with self.assertRaises(OpenCTIGraphQLError) as caught:
                self.connector.graphql_query("query { about { version } }")
        self.assertEqual(caught.exception.errors, errors)
        self.assertEqual(caught.exception.status_code, 200)
        self.assertEqual(caught.exception.messages(), ["FORBIDDEN_ACCESS", "Validation failed"])
        self.assertTrue(caught.exception.mentions("forbidden_access"))

    def test_bundle_push_with_graphql_errors_raises(self):
        with self._post(self._response({"errors": [{"message": "FORBIDDEN"}]})):
            with self.assertRaises(OpenCTIGraphQLError) as caught:
                self.connector.send_stix_bundle("{}")
        self.assertTrue(caught.exception.mentions("forbidden"))

    def test_bundle_push_without_acknowledgement_raises(self):
        with self._post(self._response({"data": {}})):
            with self.assertRaises(OpenCTIGraphQLError):
                self.connector.send_stix_bundle("{}")

    def test_register_with_graphql_errors_raises(self):
        with self._post(self._response({"errors": [{"message": "denied"}]})):
            with self.assertRaises(OpenCTIGraphQLError):
                self.connector.register()

    def test_register_once_per_process(self):
        payload = {"data": {"registerConnector": {"id": "id", "connector_state": None, "connector_user_id": "u"}}}
        with self._post(self._response(payload)) as post:
            self.connector.register()
            self.connector.register()
        self.assertEqual(post.call_count, 1)

    def test_non_200_raises_with_the_status(self):
        with self._post(self._response({}, status=502)):
            with self.assertRaises(OpenCTIGraphQLError) as caught:
                self.connector.send_stix_bundle("{}")
        self.assertEqual(caught.exception.status_code, 502)
        self.assertEqual(caught.exception.errors, [])

    def test_malformed_json_raises(self):
        with self._post(self._response(json_error=ValueError("Expecting value"))):
            with self.assertRaises(OpenCTIGraphQLError) as caught:
                self.connector.graphql_query("query { about { version } }")
        self.assertEqual(caught.exception.status_code, 200)
        self.assertIn("non-JSON", str(caught.exception))

    def test_unexpected_payload_raises(self):
        with self._post(self._response(["not", "an", "object"])):
            with self.assertRaises(OpenCTIGraphQLError):
                self.connector.graphql_query("query { about { version } }")

    def test_transport_error_raises_without_graphql_errors(self):
        with self._post(side_effect=requests.ConnectionError("down")):
            with self.assertRaises(OpenCTIGraphQLError) as caught:
                self.connector.graphql_query("query { about { version } }")
        self.assertEqual(caught.exception.errors, [], "transport failures carry no GraphQL error (retryable)")
        self.assertIsNone(caught.exception.status_code)

    def test_requests_have_a_timeout(self):
        with self._post(self._response({"data": {"stixBundlePush": "ok"}})) as post:
            self.connector.send_stix_bundle("{}")
        self.assertEqual(post.call_args.kwargs["timeout"], GRAPHQL_TIMEOUT)


if __name__ == "__main__":
    unittest.main()
