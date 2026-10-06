"""Tests for the incident alert actions: timeline milestones and their follow-ups (#18, #68)."""
import json
import unittest
from unittest import mock

from program_fakes import FakeAlertContext, FakeAlertHelper, FakeCache, FakeClient, FakeDetector, graphql_error

import alert_common
import alert_create_incident_helper
import alert_create_incident_response_helper
import program_actions
from addon_state import MemoryCache, utc_now_iso
from app_connector_helper import OpenCTIGraphQLError
from opencti_features import FEATURE_TIMELINE

PLATFORM = {"id": "platform-internal", "standard_id": "identity--5b1fb3f9-2d4e-5f2c-9c6a-1d0f1e2f3a4b", "name": "Splunk sh01"}
INDICATOR_ID = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac9"
EVENT = {"_time": "1727000000", "_raw": "dns query evil.example", "_cd": "1:2", "host": "sh01"}


def _objects(bundle, stix_type):
    return [o for o in json.loads(bundle)["objects"] if o["type"] == stix_type]


def _run(handler, helper, context):
    return alert_common.run_alert(helper, "test", handler, context_factory=lambda _helper: context)


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


class FollowupTest(unittest.TestCase):
    def test_incident_schedules_the_milestone(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "timeline_milestone": "1"},
                                 events=[EVENT])
        client = FakeClient({"SplunkTimelineMilestone": {"timelineEventAdd": {"id": "event-1"}}})
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_TIMELINE,)))
        self.assertEqual(_run(alert_create_incident_helper.create_incident, helper, context), 0)
        milestone = client.calls_of("SplunkTimelineMilestone")[0]["input"]
        incident_id = _objects(client.bundles[0], "incident")[0]["id"]
        self.assertEqual(milestone["container_id"], incident_id)
        self.assertEqual((milestone["lane"], milestone["kind"]), ("detection", "milestone"))
        self.assertEqual(milestone["title"], "Splunk alert: Brute force")
        self.assertIn("https://splunk/results", milestone["description"])
        self.assertTrue(milestone["external_id"].startswith("splunk-alert:"), "no sid in the payload")
        self.assertNotIn("createdBy", milestone, "no Security Platform resolved")
        self.assertNotIn("element_id", milestone)

    def test_incident_response_schedules_the_milestone(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "priority": "P2"},
                                 events=[EVENT])
        client = FakeClient({"SplunkTimelineMilestone": {"timelineEventAdd": {"id": "event-1"}}})
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_TIMELINE,)))
        self.assertEqual(_run(alert_create_incident_response_helper.create_incident_response, helper, context), 0)
        case_id = _objects(client.bundles[0], "case-incident")[0]["id"]
        self.assertEqual(client.calls_of("SplunkTimelineMilestone")[0]["input"]["container_id"], case_id,
                         "the milestone is on by default")

    def test_disabled_milestone_is_not_scheduled(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "timeline_milestone": "0"},
                                 events=[EVENT])
        context = FakeAlertContext(helper, detector=FakeDetector((FEATURE_TIMELINE,)))
        self.assertEqual(_run(alert_create_incident_helper.create_incident, helper, context), 0)
        self.assertEqual(context.client.calls, [])

    def test_milestone_carries_the_alert_sid_platform_and_indicator(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "timeline_milestone": "1"},
                                 events=[dict(EVENT, indicator_id=INDICATOR_ID)],
                                 settings={"search_name": "Brute force", "results_link": "https://splunk/results",
                                           "sid": "scheduler__admin__search__RMD5_at_1727000000_42"})
        client = FakeClient({"SplunkTimelineMilestone": {"timelineEventAdd": {"id": "event-1"}}})
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_TIMELINE,)), platform=PLATFORM)
        self.assertEqual(_run(alert_create_incident_helper.create_incident, helper, context), 0)
        milestone = client.calls_of("SplunkTimelineMilestone")[0]["input"]
        self.assertEqual(milestone["external_id"], "splunk:scheduler__admin__search__RMD5_at_1727000000_42")
        self.assertEqual(milestone["createdBy"], PLATFORM["id"])
        self.assertEqual(milestone["element_id"], INDICATOR_ID)

    def test_milestone_retried_without_an_unknown_element(self):
        calls = []

        def timeline(variables):
            calls.append(variables["input"])
            if "element_id" in variables["input"]:
                return graphql_error("Timeline element cannot be found")
            return {"timelineEventAdd": {"id": "event-1"}}

        client = FakeClient({"SplunkTimelineMilestone": timeline})
        context = FakeAlertContext(FakeAlertHelper(), client=client, detector=FakeDetector((FEATURE_TIMELINE,)),
                                   platform=PLATFORM)
        self.assertTrue(program_actions.add_timeline_milestone(context, "incident--1", element_id=INDICATOR_ID))
        self.assertEqual(len(calls), 2)
        self.assertNotIn("element_id", calls[1])
        self.assertEqual(calls[1]["createdBy"], PLATFORM["id"], "only the unknown field is dropped")
        self.assertTrue(context.logger.has("warning", "without element_id"))

    def test_milestone_other_errors_are_raised(self):
        client = FakeClient({"SplunkTimelineMilestone": graphql_error("Container not found")})
        context = FakeAlertContext(FakeAlertHelper(), client=client, detector=FakeDetector((FEATURE_TIMELINE,)))
        with self.assertRaises(OpenCTIGraphQLError):
            program_actions.add_timeline_milestone(context, "incident--1", element_id=INDICATOR_ID)
        self.assertEqual(len(client.calls_of("SplunkTimelineMilestone")), 1)

    def test_nothing_scheduled_on_older_platforms(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "timeline_milestone": "1"},
                                 events=[EVENT])
        context = FakeAlertContext(helper, detector=FakeDetector())
        self.assertEqual(_run(alert_create_incident_helper.create_incident, helper, context), 0)
        self.assertEqual(context.client.calls, [])

    @staticmethod
    def _followup_context(client=None, cache=None, helper=None, ingested=None):
        client = client or FakeClient({"SplunkTimelineMilestone": {"timelineEventAdd": {"id": "event-1"}}})
        context = alert_common.AlertContext(helper or FakeAlertHelper(), settings=mock.Mock(), client=client)
        context._detector = FakeDetector((FEATURE_TIMELINE,))
        context._cache = FakeCache() if cache is None else cache
        if ingested is not None:
            context._existing = ingested
        return context

    @staticmethod
    def _defer_milestone(context, entity_id="incident--1"):
        context.defer(entity_id, "Timeline milestone", program_actions.FOLLOWUP_TIMELINE, {
            "search_name": "Brute force",
            "results_link": "https://splunk/results",
            "trigger_time": "2026-10-03T10:00:00.000Z",
            "event_time": None,
        })

    @staticmethod
    def _parked(cache):
        return cache.items(alert_common.FOLLOWUP_PARKED_PREFIX)

    def test_followups_wait_for_ingestion_then_run(self):
        seen = iter([set(), {"incident--1"}])
        context = self._followup_context(ingested=lambda ids: next(seen))
        self._defer_milestone(context)
        slept = []
        self.assertEqual(context.run_followups(sleep=slept.append, budget=60), 0)
        self.assertEqual(len(context.client.calls_of("SplunkTimelineMilestone")), 1)
        self.assertEqual(slept, [2])
        self.assertEqual(self._parked(context.cache), [])

    def test_followups_not_ingested_are_run_by_a_later_alert_run(self):
        cache = FakeCache()
        context = self._followup_context(cache=cache, ingested=lambda ids: set())
        self._defer_milestone(context)
        slept = []
        self.assertEqual(context.run_followups(sleep=slept.append, budget=10), 1)
        self.assertLessEqual(sum(slept), 10)
        self.assertEqual(context.client.calls_of("SplunkTimelineMilestone"), [])
        self.assertEqual(len(self._parked(cache)), 1)
        # Any later OpenCTI alert action run, once OpenCTI ingested the incident
        other = FakeAlertHelper(settings={"search_name": "Other alert", "results_link": "https://splunk/other"})
        later = self._followup_context(cache=cache, helper=other, ingested=lambda ids: set(ids))
        self.assertEqual(later.run_followups(sleep=slept.append), 0)
        milestone = later.client.calls_of("SplunkTimelineMilestone")[0]["input"]
        self.assertEqual(milestone["container_id"], "incident--1")
        self.assertEqual(milestone["title"], "Splunk alert: Brute force", "the parked alert, not the running one")
        self.assertIn("https://splunk/results", milestone["description"])
        self.assertEqual(milestone["event_time"], "2026-10-03T10:00:00.000Z")
        self.assertEqual(self._parked(cache), [])

    def test_failed_followup_is_retried_then_dropped(self):
        cache = FakeCache()
        client = FakeClient({"SplunkTimelineMilestone": graphql_error("timeline unavailable")})
        context = self._followup_context(client=client, cache=cache, ingested=lambda ids: set(ids))
        self._defer_milestone(context)
        self.assertEqual(context.run_followups(sleep=lambda delay: None), 1)
        self.assertEqual([value["failures"] for _, value in self._parked(cache)], [1])
        helper = FakeAlertHelper()
        for _ in range(alert_common.FOLLOWUP_MAX_FAILURES - 1):
            self._followup_context(client=client, cache=cache, helper=helper,
                                   ingested=lambda ids: set(ids)).run_followups()
        self.assertEqual(self._parked(cache), [])
        self.assertEqual(len(client.calls_of("SplunkTimelineMilestone")), alert_common.FOLLOWUP_MAX_FAILURES)
        self.assertTrue(any("dropped after" in m for level, m in helper.logs if level == "error"))

    def test_parked_followups_beyond_one_run_are_taken_in_turn(self):
        cache = FakeCache()
        prefix = self._followup_context(cache=cache)._parked_prefix()
        total = alert_common.FOLLOWUP_RETRIED_PER_RUN + 20
        for number in range(total):
            cache.set(f"{prefix}{number:04d}", {"entity_id": f"incident--{number}", "description": "Timeline milestone",
                                                "kind": program_actions.FOLLOWUP_TIMELINE, "params": {},
                                                "parked_at": utc_now_iso()})
        checked = []

        def nothing_ingested(ids):
            checked.extend(ids)
            return set()
        self._followup_context(cache=cache, ingested=nothing_ingested).run_followups()
        self.assertEqual(len(checked), alert_common.FOLLOWUP_RETRIED_PER_RUN)
        # The next run starts with the entries the first one did not reach
        later = self._followup_context(cache=cache, ingested=lambda ids: set(ids))
        later.run_followups()
        milestones = {call["input"]["container_id"] for call in later.client.calls_of("SplunkTimelineMilestone")}
        unreached = {f"incident--{n}" for n in range(alert_common.FOLLOWUP_RETRIED_PER_RUN, total)}
        self.assertEqual(milestones & unreached, unreached)
        self.assertEqual(len(self._parked(cache)), total - alert_common.FOLLOWUP_RETRIED_PER_RUN)

    def test_parked_followup_expires(self):
        cache = FakeCache()
        context = self._followup_context(cache=cache, ingested=lambda ids: set(ids))
        key = context._parked_prefix() + "expired"
        cache.set(key, {"entity_id": "incident--1", "description": "Timeline milestone",
                        "kind": program_actions.FOLLOWUP_TIMELINE, "params": {}, "parked_at": "2020-01-01T00:00:00Z"})
        self.assertEqual(context.run_followups(), 0)
        self.assertIsNone(cache.get(key))
        self.assertEqual(context.client.calls_of("SplunkTimelineMilestone"), [])

    def test_malformed_parked_followups_never_block_the_others(self):
        cache = FakeCache()
        context = self._followup_context(cache=cache, ingested=lambda ids: set(ids))
        prefix = context._parked_prefix()
        valid = {"entity_id": "incident--1", "description": "Timeline milestone", "kind": program_actions.FOLLOWUP_TIMELINE,
                 "params": {"search_name": "Brute force"}, "parked_at": utc_now_iso()}
        cache.set(prefix + "a-bad-params", dict(valid, params="not a dict"))
        cache.set(prefix + "b-bad-failures", dict(valid, failures="many"))
        cache.set(prefix + "c-no-entity", dict(valid, entity_id=None))
        cache.set(prefix + "d-raises", dict(valid, entity_id="incident--2"))
        cache.set(prefix + "e-valid", valid)
        real_set = cache.set

        def flaky_set(key, value):
            if key.endswith("d-raises"):
                raise RuntimeError("KV down")
            real_set(key, value)

        cache.set = flaky_set
        client = context.client
        client.handlers["SplunkTimelineMilestone"] = lambda variables: (
            graphql_error("boom") if variables["input"]["container_id"] == "incident--2"
            else {"timelineEventAdd": {"id": "event-1"}})
        context.run_followups()
        self.assertEqual([key[len(prefix):] for key, _ in self._parked(cache)], ["d-raises"])
        self.assertEqual([call["input"]["container_id"] for call in client.calls_of("SplunkTimelineMilestone")],
                         ["incident--2", "incident--1"])

    def test_parked_followups_of_another_platform_are_left_alone(self):
        cache = FakeCache()
        key = f"{alert_common.FOLLOWUP_PARKED_PREFIX}https://other.example|x"
        parked = {"entity_id": "incident--1", "description": "Timeline milestone",
                  "kind": program_actions.FOLLOWUP_TIMELINE, "params": {}, "parked_at": utc_now_iso()}
        cache.set(key, parked)
        context = self._followup_context(cache=cache, ingested=lambda ids: set(ids))
        context.run_followups()
        self.assertEqual(cache.get(key), parked)
        self.assertEqual(context.client.calls_of("SplunkTimelineMilestone"), [])

    def test_followups_without_state_collection_are_skipped(self):
        helper = FakeAlertHelper()
        context = self._followup_context(cache=MemoryCache(), helper=helper, ingested=lambda ids: set())
        self._defer_milestone(context)
        self.assertEqual(context.run_followups(sleep=lambda delay: None, budget=0), 1)
        self.assertTrue(any("state collection is unavailable" in m for level, m in helper.logs if level == "warning"))

    def test_unknown_followup_kind(self):
        with self.assertRaises(ValueError):
            program_actions.run_followup(FakeAlertContext(FakeAlertHelper()), "unknown", "incident--1", {})

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
