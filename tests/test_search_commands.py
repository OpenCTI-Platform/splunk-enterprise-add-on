"""Tests for the custom search command wrappers (#68)."""
import unittest
from types import SimpleNamespace
from unittest import mock

from program_fakes import FakeClient, FakeDetector, FakeKV, FakeLogger, graphql_error

import openctiprovides
import openctireconcile
import openctireporthits
import openctivalidation
from addon_config import AddonSettings
from opencti_features import FEATURE_DEPLOYED_ON, FEATURE_PROVIDES, FEATURE_SECURITY_PLATFORM

PLATFORM = {"id": "platform-internal", "standard_id": "identity--5b1fb3f9-2d4e-5f2c-9c6a-1d0f1e2f3a4b"}
IND = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac9"


class FakeCommandContext:
    def __init__(self, client=None, features=(), platform=PLATFORM, collections=None):
        self.client = client or FakeClient()
        self.detector = FakeDetector(features)
        self.platform = platform
        self.logger = FakeLogger()
        self.settings = AddonSettings({"opencti_url": "https://opencti.example", "opencti_api_key": "k"}, server_name="sh01")
        self.collections = collections if collections is not None else {}

    def collection(self, name):
        return self.collections.setdefault(name, FakeKV())


class ReportHitsCommandTest(unittest.TestCase):
    def test_sighting_bundle_failure_marks_the_rows(self):
        client = FakeClient()

        def failing_bundle(bundle):
            raise graphql_error("bundle rejected")

        client.send_stix_bundle = failing_bundle
        context = FakeCommandContext(client, (FEATURE_SECURITY_PLATFORM,))
        command = openctireporthits.OpenCTIReportHitsCommand()
        with mock.patch.object(openctireporthits, "CommandContext", return_value=context):
            rows = list(command.transform([{"indicator_id": IND, "hit_count": "2", "last_hit": "1727000000"}]))
        self.assertEqual(rows[0]["opencti_hit_status"], "error")
        self.assertIn("bundle rejected", rows[0]["opencti_hit_message"])

    def test_context_is_built_once_per_search(self):
        context = FakeCommandContext(FakeClient(), (FEATURE_SECURITY_PLATFORM,))
        command = openctireporthits.OpenCTIReportHitsCommand()
        with mock.patch.object(openctireporthits, "CommandContext", return_value=context) as factory:
            list(command.transform([]))
            list(command.transform([]))
        self.assertEqual(factory.call_count, 1)


class ValidationCommandTest(unittest.TestCase):
    def test_no_request(self):
        context = FakeCommandContext()
        command = openctivalidation.OpenCTIValidationCommand()
        with mock.patch.object(openctivalidation, "CommandContext", return_value=context):
            rows = list(command.generate())
        self.assertNotIn("outcome", rows[0])


class ReconcileCommandTest(unittest.TestCase):
    def test_deployments_mode(self):
        client = FakeClient({
            "SplunkPlatformDeployments": {"stixCoreRelationships": {"pageInfo": {"hasNextPage": False}, "edges": []}},
        })
        kv = FakeKV([{"_key": "k1", "id": IND}])
        context = FakeCommandContext(client, (FEATURE_DEPLOYED_ON,), collections={"opencti_indicators": kv})
        command = openctireconcile.OpenCTIReconcileCommand()
        with mock.patch.object(openctireconcile, "CommandContext", return_value=context):
            rows = list(command.generate())
        self.assertEqual(rows[-1]["action"], "summary")
        self.assertEqual(rows[0]["action"], "deploy")

    def test_knowledge_mode(self):
        context = FakeCommandContext()
        command = openctireconcile.OpenCTIReconcileCommand()
        command.mode = "knowledge"
        with mock.patch.object(openctireconcile, "CommandContext", return_value=context):
            rows = list(command.generate())
        self.assertEqual(rows[0]["action"], "skipped")


class ProvidesCommandTest(unittest.TestCase):
    def test_publishes_rows(self):
        client = FakeClient({
            "SplunkDataComponents": {"dataComponents": {"edges": [{"node": {"id": "dc-1", "name": "Process Creation"}}]}},
            "SplunkProvides": {"stixCoreRelationshipAdd": {"id": "rel"}},
        })
        context = FakeCommandContext(client, (FEATURE_PROVIDES,))
        command = openctiprovides.OpenCTIProvidesCommand()
        command._finished = True
        with mock.patch.object(openctiprovides, "CommandContext", return_value=context):
            rows = list(command.transform([{"data_component": "Process Creation", "sources": "sourcetype:sysmon", "event_count": "9"}]))
        self.assertEqual(rows[0]["status"], "declared")


class CommandContextTest(unittest.TestCase):
    def test_builds_client_detector_and_platform(self):
        import command_common

        settings = AddonSettings({"opencti_url": "https://opencti.example", "opencti_api_key": "k"},
                                 platform={"security_platform_auto_create": "0"})
        command = SimpleNamespace(metadata=SimpleNamespace(searchinfo=SimpleNamespace(session_key="s", splunkd_uri="https://127.0.0.1:8089")))
        with mock.patch.object(command_common, "load_settings", return_value=settings), \
                mock.patch.object(command_common, "connect_service", return_value=mock.Mock()) as connect, \
                mock.patch.object(command_common, "KVStoreCache", side_effect=Exception("no kv")):
            context = command_common.CommandContext(command, "test")
            self.assertEqual(context.client.opencti_url, "https://opencti.example")
            connect.assert_called_once_with("s", "TA-opencti-for-splunk-enterprise", "https://127.0.0.1:8089")
            with mock.patch.object(context.detector, "require", return_value=True), \
                    mock.patch.object(context.detector, "snapshot", return_value={"features": []}):
                self.assertIsNone(context.platform, "auto creation disabled and no id")


if __name__ == "__main__":
    unittest.main()
