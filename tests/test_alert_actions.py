"""Tests for the alert actions (#18, #19, #47, #57, #67, timeline and Case Autopilot, #68)."""
import json
import unittest
from unittest import mock

from program_fakes import (
    FakeAlertContext,
    FakeAlertHelper,
    FakeClient,
    FakeDetector,
    FakeKV,
    graphql_error,
)

import alert_common
import alert_create_incident_helper
import alert_create_incident_response_helper
import alert_create_sighting_helper
import program_actions
from app_connector_helper import OpenCTIGraphQLError, SplunkAppConnectorHelper
from opencti_features import FEATURE_CASE_AUTOPILOT, FEATURE_TIMELINE
from stix_converter import convert_to_incident, convert_to_sighting, indicator_patterns
from utils import generate_indicator_id

PLATFORM = {"id": "platform-internal", "standard_id": "identity--5b1fb3f9-2d4e-5f2c-9c6a-1d0f1e2f3a4b", "name": "Splunk sh01"}
INDICATOR_ID = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac9"
EVENT = {"_time": "1727000000", "_raw": "dns query evil.example", "_cd": "1:2", "host": "sh01"}


def _objects(bundle, stix_type):
    return [o for o in json.loads(bundle)["objects"] if o["type"] == stix_type]


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

    def test_sighting_action_failure_returns_non_zero(self):
        helper = FakeAlertHelper(
            params={"sighting_of_type": "domain_observable", "sighting_of_value": "evil.example",
                    "where_sighted_type": "system", "where_sighted_value": "", "tlp": "tlp_green",
                    "sighted_on_platform": "1"},
            events=[EVENT],
        )
        client = FakeClient()
        client.send_stix_bundle = mock.Mock(side_effect=graphql_error("invalid bundle"))
        context = FakeAlertContext(helper, client=client, platform=PLATFORM)
        self.assertEqual(_run(alert_create_sighting_helper.create_sighting, helper, context), 2)
        self.assertTrue(any("sending STIX bundle" in m for m in helper.errors()))


class SightingTest(unittest.TestCase):
    """#57 and #67: sightings of Indicators, on the Splunk Security Platform."""

    PARAMS = {"tlp": "tlp_amber", "where_sighted_type": "system", "where_sighted_value": "", "labels": ["splunk"]}

    def test_indicator_sighting_references_the_indicator(self):
        bundle = convert_to_sighting(
            dict(self.PARAMS, sighting_of_type="indicator_id", sighting_of_value=INDICATOR_ID, count="4"),
            dict(EVENT, first_seen="1726990000", last_seen="1727000000"),
            platform_ref=PLATFORM["standard_id"],
            indicator={"id": INDICATOR_ID},
        )
        sighting = _objects(bundle, "sighting")[0]
        self.assertEqual(sighting["sighting_of_ref"], INDICATOR_ID)
        self.assertEqual(sighting["where_sighted_refs"], [PLATFORM["standard_id"]])
        self.assertEqual(sighting["count"], 4)
        self.assertNotIn("x_opencti_sighting_of_ref", sighting)
        self.assertEqual(_objects(bundle, "indicator"), [], "no placeholder nor copy of an existing indicator")
        self.assertTrue(sighting["first_seen"].startswith("2024-09-22T07:26:40"))
        self.assertTrue(sighting["last_seen"].startswith("2024-09-22T10:13:20"))

    def test_platform_and_selected_system(self):
        bundle = convert_to_sighting(
            dict(self.PARAMS, sighting_of_type="indicator_id", where_sighted_value="dc01"),
            EVENT, platform_ref=PLATFORM["standard_id"], indicator={"id": INDICATOR_ID},
        )
        refs = _objects(bundle, "sighting")[0]["where_sighted_refs"]
        self.assertEqual(len(refs), 2)
        self.assertIn(PLATFORM["standard_id"], refs)

    def test_created_indicator_has_the_deterministic_pattern_id(self):
        patterns, main_type = indicator_patterns("domain", "evil.example")
        indicator = {"id": generate_indicator_id(patterns[0]), "create": True, "pattern": patterns[0],
                     "name": "evil.example", "main_observable_type": main_type}
        bundle = convert_to_sighting(dict(self.PARAMS, sighting_of_type="domain_indicator", sighting_of_value="evil.example"),
                                     EVENT, platform_ref=PLATFORM["standard_id"], indicator=indicator)
        created = _objects(bundle, "indicator")[0]
        self.assertEqual(created["pattern"], "[domain-name:value = 'evil.example']")
        self.assertEqual(created["x_opencti_main_observable_type"], "Domain-Name")
        self.assertEqual(created["id"], _objects(bundle, "sighting")[0]["sighting_of_ref"])

    def test_observable_sighting_kept_and_platform_aware(self):
        bundle = convert_to_sighting(dict(self.PARAMS, sighting_of_type="ipv4_observable", sighting_of_value="1.2.3.4",
                                          where_sighted_value="fw01"), EVENT, platform_ref=PLATFORM["standard_id"])
        sighting = _objects(bundle, "sighting")[0]
        self.assertIn("x_opencti_sighting_of_ref", sighting)
        self.assertIn(PLATFORM["standard_id"], sighting["where_sighted_refs"])

    def test_legacy_observable_sighting_id_unchanged_without_platform(self):
        params = dict(self.PARAMS, sighting_of_type="ipv4_observable", sighting_of_value="1.2.3.4", where_sighted_value="fw01")
        first = _objects(convert_to_sighting(params, EVENT), "sighting")[0]["id"]
        second = _objects(convert_to_sighting(params, dict(EVENT, _time="1727009999")), "sighting")[0]["id"]
        self.assertEqual(first, second, "historical id seed: observable + where sighted")

    def test_nothing_to_sight_on(self):
        with self.assertRaises(ValueError):
            convert_to_sighting(dict(self.PARAMS, sighting_of_type="indicator_id"), EVENT, indicator={"id": INDICATOR_ID})

    def test_hash_patterns(self):
        self.assertEqual(indicator_patterns("file_hash", "a" * 64)[0][0], "[file:hashes.'SHA-256' = '" + "a" * 64 + "']")
        self.assertEqual(indicator_patterns("file_hash", "b" * 32)[0][0], "[file:hashes.MD5 = '" + "b" * 32 + "']")
        with self.assertRaises(ValueError):
            indicator_patterns("file_hash", "nothex")

    def test_pattern_value_is_escaped(self):
        self.assertEqual(indicator_patterns("url", "http://x/a'b")[0][0], "[url:value = 'http://x/a\\'b']")


class IndicatorResolutionTest(unittest.TestCase):
    def _context(self, client, kv=None):
        helper = FakeAlertHelper()
        context = FakeAlertContext(helper, client=client)
        context.service = mock.Mock()
        patcher = mock.patch("addon_state.KVCollection", return_value=kv or FakeKV())
        patcher.start()
        self.addCleanup(patcher.stop)
        return context

    def test_by_id(self):
        client = FakeClient({"SplunkSightedIndicator": {"indicator": {"id": "i", "standard_id": INDICATOR_ID}}})
        self.assertEqual(program_actions.resolve_sighted_indicator(self._context(client), "indicator_id", INDICATOR_ID, None),
                         {"id": INDICATOR_ID})

    def test_unknown_id_is_an_error(self):
        client = FakeClient({"SplunkSightedIndicator": {"indicator": None}})
        with self.assertRaises(ValueError):
            program_actions.resolve_sighted_indicator(self._context(client), "indicator_id", INDICATOR_ID, None)
        with self.assertRaises(ValueError):
            program_actions.resolve_sighted_indicator(self._context(client), "indicator_id", "evil.example", None)

    def test_by_value_from_the_kv_store_first(self):
        kv = FakeKV([{"_key": "k1", "id": INDICATOR_ID, "value": "evil.example", "revoked": False}])
        client = FakeClient()
        result = program_actions.resolve_sighted_indicator(self._context(client, kv), "domain_indicator", "evil.example", "domain")
        self.assertEqual(result, {"id": INDICATOR_ID})
        self.assertEqual(client.calls, [])

    def test_revoked_kv_entries_are_ignored_then_opencti_pattern(self):
        kv = FakeKV([{"_key": "k1", "id": "indicator--old", "value": "evil.example", "revoked": True}])
        client = FakeClient({"SplunkIndicatorsByPattern": {"indicators": {"edges": [
            {"node": {"id": "i", "standard_id": INDICATOR_ID, "revoked": False}}]}}})
        result = program_actions.resolve_sighted_indicator(self._context(client, kv), "domain_indicator", "evil.example", "domain")
        self.assertEqual(result, {"id": INDICATOR_ID})
        values = client.calls_of("SplunkIndicatorsByPattern")[0]["filters"]["filters"][0]["values"]
        self.assertIn("[domain-name:value = 'evil.example']", values)

    def test_unknown_value_creates_the_indicator(self):
        client = FakeClient({"SplunkIndicatorsByPattern": {"indicators": {"edges": []}}})
        result = program_actions.resolve_sighted_indicator(self._context(client), "ipv4_indicator", "1.2.3.4", "ipv4")
        self.assertTrue(result["create"])
        self.assertEqual(result["pattern"], "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(result["id"], generate_indicator_id("[ipv4-addr:value = '1.2.3.4']"))


class IncidentKeyTest(unittest.TestCase):
    """#47: distinct results never merge, the same result keeps upserting."""

    PARAMS = {"name": "Brute force", "description": "", "type": "alert", "severity": "high", "labels": [],
              "tlp": "tlp_clear", "observables_extraction": "disable"}

    def _id(self, event, key=None):
        return convert_to_incident(dict(self.PARAMS, incident_key=key), event, return_id=True)[1]

    def test_same_second_indexed_events_never_collide(self):
        ids = {self._id({"_time": "1727000000", "_raw": f"event {i}", "_cd": f"1:{i}"}) for i in range(300)}
        self.assertEqual(len(ids), 300)

    def test_explicit_key_separates_transforming_rows(self):
        a = self._id({"_time": "1727000000", "user": "bob"}, key="bob")
        b = self._id({"_time": "1727000000", "user": "eve"}, key="eve")
        self.assertNotEqual(a, b)
        self.assertEqual(a, self._id({"_time": "1727000000", "user": "bob", "count": "9"}, key="bob"))

    def test_rows_without_identity_keep_the_historical_id(self):
        from utils import generate_incident_id
        from datetime import datetime, timezone

        created = datetime.fromtimestamp(1727000000, timezone.utc)
        self.assertEqual(self._id({"_time": "1727000000", "rid": "0"}), generate_incident_id("Brute force", created))


class FollowupTest(unittest.TestCase):
    def test_incident_schedules_timeline_and_autopilot(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "timeline_milestone": "1", "run_case_autopilot": "1", "autopilot_policy_id": "policy-1"},
                                 events=[EVENT])
        client = FakeClient({
            "SplunkTimelineMilestone": {"timelineEventAdd": {"id": "event-1"}},
            "SplunkCaseAutopilot": {"investigationRunAdd": {"id": "run-1"}},
        })
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_TIMELINE, FEATURE_CASE_AUTOPILOT)))
        self.assertEqual(_run(alert_create_incident_helper.create_incident, helper, context), 0)
        milestone = client.calls_of("SplunkTimelineMilestone")[0]["input"]
        incident_id = _objects(client.bundles[0], "incident")[0]["id"]
        self.assertEqual(milestone["container_id"], incident_id)
        self.assertEqual((milestone["lane"], milestone["kind"]), ("custom", "milestone"))
        self.assertEqual(milestone["title"], "Splunk alert: Brute force")
        self.assertIn("https://splunk/results", milestone["description"])
        self.assertTrue(milestone["external_id"].startswith("splunk-alert:"))
        self.assertEqual(client.calls_of("SplunkCaseAutopilot")[0], {"subjectId": incident_id, "policyId": "policy-1"})

    def test_case_autopilot_runs_once_per_container(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "timeline_milestone": "0", "run_case_autopilot": "1"},
                                 events=[EVENT, EVENT])
        client = FakeClient({"SplunkCaseAutopilot": {"investigationRunAdd": {"id": "run-1"}}})
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_CASE_AUTOPILOT,)))
        _run(alert_create_incident_response_helper.create_incident_response, helper, context)
        self.assertEqual(len(client.calls_of("SplunkCaseAutopilot")), 1)

    def test_nothing_scheduled_on_older_platforms(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "timeline_milestone": "1", "run_case_autopilot": "1"},
                                 events=[EVENT])
        context = FakeAlertContext(helper, detector=FakeDetector())
        self.assertEqual(_run(alert_create_incident_helper.create_incident, helper, context), 0)
        self.assertEqual(context.client.calls, [])

    def test_followups_wait_for_ingestion_then_run(self):
        helper = FakeAlertHelper()
        seen = iter([set(), {"incident--1"}])
        context = alert_common.AlertContext(helper, settings=mock.Mock(), client=FakeClient())
        context._existing = lambda ids: next(seen)
        done = []
        context.defer("incident--1", "Timeline milestone", lambda: done.append(1))
        slept = []
        self.assertEqual(context.run_followups(sleep=slept.append, budget=60), 0)
        self.assertEqual(done, [1])
        self.assertEqual(slept, [2])

    def test_followups_give_up_within_the_budget(self):
        helper = FakeAlertHelper()
        context = alert_common.AlertContext(helper, settings=mock.Mock(), client=FakeClient())
        context._existing = lambda ids: set()
        context.defer("incident--1", "Timeline milestone", lambda: None)
        slept = []
        self.assertEqual(context.run_followups(sleep=slept.append, budget=10), 1)
        self.assertLessEqual(sum(slept), 10)
        self.assertTrue(any("skipped" in m for level, m in helper.logs if level == "warning"))

    def test_existing_objects_query(self):
        client = FakeClient({"SplunkExistingObjects": {"stixCoreObjects": {"edges": [
            {"node": {"id": "internal", "standard_id": "incident--1"}}]}}})
        context = alert_common.AlertContext(FakeAlertHelper(), settings=mock.Mock(), client=client)
        self.assertIn("incident--1", context._existing(["incident--1"]))

    def test_milestone_input_limits(self):
        from datetime import datetime, timezone

        milestone = program_actions.build_milestone_input("incident--1", "x" * 600, datetime.now(timezone.utc))
        self.assertEqual(len(milestone["title"]), 512)
        self.assertLessEqual(len(milestone["external_id"]), 256)


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
