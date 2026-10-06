"""Tests for the incident alert actions: Case Autopilot runs and their follow-ups (#18, #68)."""
import json
import unittest
from unittest import mock

from program_fakes import FakeAlertContext, FakeAlertHelper, FakeCache, FakeClient, FakeDetector, graphql_error

import alert_common
import alert_create_incident_helper
import alert_create_incident_response_helper
import program_actions
from addon_state import MemoryCache, takeover_key
from opencti_features import FEATURE_CASE_AUTOPILOT

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
    def test_incident_schedules_case_autopilot(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "run_case_autopilot": "1", "autopilot_policy_id": "policy-1"},
                                 events=[EVENT])
        client = FakeClient({"SplunkCaseAutopilot": {"investigationRunAdd": {"id": "run-1"}}})
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_CASE_AUTOPILOT,)))
        self.assertEqual(_run(alert_create_incident_helper.create_incident, helper, context), 0)
        incident_id = _objects(client.bundles[0], "incident")[0]["id"]
        self.assertEqual(client.calls_of("SplunkCaseAutopilot")[0], {"subjectId": incident_id, "policyId": "policy-1"})

    def test_case_autopilot_is_off_by_default(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable"},
                                 events=[EVENT])
        context = FakeAlertContext(helper, detector=FakeDetector((FEATURE_CASE_AUTOPILOT,)))
        self.assertEqual(_run(alert_create_incident_helper.create_incident, helper, context), 0)
        self.assertEqual(context.client.calls, [])

    def test_case_autopilot_runs_once_per_container(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "run_case_autopilot": "1"},
                                 events=[EVENT, EVENT])
        client = FakeClient({"SplunkCaseAutopilot": {"investigationRunAdd": {"id": "run-1"}}})
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_CASE_AUTOPILOT,)))
        _run(alert_create_incident_response_helper.create_incident_response, helper, context)
        self.assertEqual(len(client.calls_of("SplunkCaseAutopilot")), 1)

    def test_case_autopilot_skipped_without_persistent_state(self):
        from addon_state import MemoryCache

        client = FakeClient({"SplunkCaseAutopilot": {"investigationRunAdd": {"id": "run-1"}}})
        context = FakeAlertContext(FakeAlertHelper(), client=client, detector=FakeDetector((FEATURE_CASE_AUTOPILOT,)))
        context.cache = MemoryCache()
        self.assertIsNone(program_actions.run_case_autopilot(context, "incident--x"))
        self.assertEqual(client.calls_of("SplunkCaseAutopilot"), [])
        self.assertTrue(any("state collection" in line for _, line in context.logger.lines))

    def test_case_autopilot_marker_write_failure_is_reported(self):
        client = FakeClient({"SplunkCaseAutopilot": {"investigationRunAdd": {"id": "run-1"}}})
        context = FakeAlertContext(FakeAlertHelper(), client=client, detector=FakeDetector((FEATURE_CASE_AUTOPILOT,)))
        context.cache.set = mock.Mock(side_effect=RuntimeError("KV Store down"))
        self.assertEqual(program_actions.run_case_autopilot(context, "incident--x"), "run-1")
        self.assertTrue(context.logger.has("error", "reservation expires"))
        self.assertIsNone(program_actions.run_case_autopilot(context, "incident--x"), "the pending reservation blocks a second run")
        self.assertEqual(len(client.calls_of("SplunkCaseAutopilot")), 1)

    def _autopilot_context(self, response=None):
        client = FakeClient({"SplunkCaseAutopilot": response or {"investigationRunAdd": {"id": "run-1"}}})
        context = FakeAlertContext(FakeAlertHelper(), client=client, detector=FakeDetector((FEATURE_CASE_AUTOPILOT,)))
        return context, client, f"autopilot|{client.opencti_url}|incident--x"

    def test_case_autopilot_reserved_by_a_concurrent_run_is_skipped(self):
        context, client, marker = self._autopilot_context()
        context.cache.reserve(marker, {"status": "pending", "reserved_at": program_actions.utc_now_iso()})
        self.assertIsNone(program_actions.run_case_autopilot(context, "incident--x"))
        self.assertEqual(client.calls_of("SplunkCaseAutopilot"), [])

    def test_case_autopilot_lost_reservation_race_is_skipped(self):
        context, client, _ = self._autopilot_context()
        context.cache.reserve = mock.Mock(return_value=False)
        self.assertIsNone(program_actions.run_case_autopilot(context, "incident--x"))
        self.assertEqual(client.calls_of("SplunkCaseAutopilot"), [])

    def test_case_autopilot_stale_reservation_is_retried(self):
        context, client, marker = self._autopilot_context()
        context.cache.set(marker, {"status": "pending", "reserved_at": "2020-01-01T00:00:00Z"})
        self.assertEqual(program_actions.run_case_autopilot(context, "incident--x"), "run-1")
        self.assertEqual(context.cache.get(marker)["run_id"], "run-1")

    def test_case_autopilot_stale_reservation_is_reclaimed_once(self):
        context, client, marker = self._autopilot_context()
        stale = {"status": "pending", "reserved_at": "2020-01-01T00:00:00Z"}
        context.cache.set(marker, stale)
        real_get = context.cache.get
        # Both processes read the stale reservation before either reclaims it.
        context.cache.get = lambda key: stale if key == marker else real_get(key)
        self.assertEqual(program_actions.run_case_autopilot(context, "incident--x"), "run-1")
        self.assertIsNone(program_actions.run_case_autopilot(context, "incident--x"))
        self.assertEqual(len(client.calls_of("SplunkCaseAutopilot")), 1)
        self.assertEqual(real_get(marker)["run_id"], "run-1", "the loser never touches the winner's marker")

    def test_case_autopilot_dead_takeover_is_taken_over(self):
        context, client, marker = self._autopilot_context()
        stale = {"status": "pending", "reserved_at": "2020-01-01T00:00:00Z"}
        context.cache.set(marker, stale)
        # The process that took the stale reservation over died before rewriting it.
        context.cache.set(takeover_key(marker, stale), dict(stale, lease="dead"))
        self.assertEqual(program_actions.run_case_autopilot(context, "incident--x"), "run-1")
        self.assertEqual(context.cache.get(marker)["run_id"], "run-1")

    def test_case_autopilot_live_takeover_is_left_to_it(self):
        context, client, marker = self._autopilot_context()
        stale = {"status": "pending", "reserved_at": "2020-01-01T00:00:00Z"}
        context.cache.set(marker, stale)
        live = {"status": "pending", "reserved_at": program_actions.utc_now_iso()}
        context.cache.set(takeover_key(marker, stale), live)
        self.assertIsNone(program_actions.run_case_autopilot(context, "incident--x"))
        self.assertEqual(client.calls_of("SplunkCaseAutopilot"), [])

    def test_case_autopilot_failure_releases_the_reservation(self):
        context, client, marker = self._autopilot_context(graphql_error("policy not found"))
        with self.assertRaises(Exception):
            program_actions.run_case_autopilot(context, "incident--x")
        self.assertIsNone(context.cache.get(marker), "the next run of the alert retries")

    def test_nothing_scheduled_on_older_platforms(self):
        helper = FakeAlertHelper(params={"name": "Brute force", "tlp": "tlp_clear", "observables_extraction": "disable",
                                         "run_case_autopilot": "1"},
                                 events=[EVENT])
        context = FakeAlertContext(helper, detector=FakeDetector())
        self.assertEqual(_run(alert_create_incident_helper.create_incident, helper, context), 0)
        self.assertEqual(context.client.calls, [])

    @staticmethod
    def _followup_context(client=None, cache=None, helper=None, ingested=None):
        client = client or FakeClient({"SplunkCaseAutopilot": {"investigationRunAdd": {"id": "run-1"}}})
        context = alert_common.AlertContext(helper or FakeAlertHelper(), settings=mock.Mock(), client=client)
        context._detector = FakeDetector((FEATURE_CASE_AUTOPILOT,))
        context._cache = FakeCache() if cache is None else cache
        if ingested is not None:
            context._existing = ingested
        return context

    @staticmethod
    def _defer_autopilot(context, entity_id="incident--1"):
        context.defer(entity_id, "Run Case Autopilot", program_actions.FOLLOWUP_CASE_AUTOPILOT, {"policy_id": "policy-1"})

    @staticmethod
    def _parked(cache):
        return cache.items(alert_common.FOLLOWUP_PARKED_PREFIX)

    def test_followups_wait_for_ingestion_then_run(self):
        seen = iter([set(), {"incident--1"}])
        context = self._followup_context(ingested=lambda ids: next(seen))
        self._defer_autopilot(context)
        slept = []
        self.assertEqual(context.run_followups(sleep=slept.append, budget=60), 0)
        self.assertEqual(len(context.client.calls_of("SplunkCaseAutopilot")), 1)
        self.assertEqual(slept, [2])
        self.assertEqual(self._parked(context.cache), [])

    def test_followups_not_ingested_are_run_by_a_later_alert_run(self):
        cache = FakeCache()
        context = self._followup_context(cache=cache, ingested=lambda ids: set())
        self._defer_autopilot(context)
        slept = []
        self.assertEqual(context.run_followups(sleep=slept.append, budget=10), 1)
        self.assertLessEqual(sum(slept), 10)
        self.assertEqual(context.client.calls_of("SplunkCaseAutopilot"), [])
        self.assertEqual(len(self._parked(cache)), 1)
        # Any later OpenCTI alert action run, once OpenCTI ingested the incident
        other = FakeAlertHelper(settings={"search_name": "Other alert", "results_link": "https://splunk/other"})
        later = self._followup_context(cache=cache, helper=other, ingested=lambda ids: set(ids))
        self.assertEqual(later.run_followups(sleep=slept.append), 0)
        self.assertEqual(later.client.calls_of("SplunkCaseAutopilot"), [{"subjectId": "incident--1", "policyId": "policy-1"}],
                         "the parked policy, not a parameter of the running alert")
        self.assertEqual(self._parked(cache), [])

    def test_failed_followup_is_retried_then_dropped(self):
        cache = FakeCache()
        client = FakeClient({"SplunkCaseAutopilot": graphql_error("investigation engine unavailable")})
        context = self._followup_context(client=client, cache=cache, ingested=lambda ids: set(ids))
        self._defer_autopilot(context)
        self.assertEqual(context.run_followups(sleep=lambda delay: None), 1)
        self.assertEqual([value["failures"] for _, value in self._parked(cache)], [1])
        helper = FakeAlertHelper()
        for _ in range(alert_common.FOLLOWUP_MAX_FAILURES - 1):
            self._followup_context(client=client, cache=cache, helper=helper,
                                   ingested=lambda ids: set(ids)).run_followups()
        self.assertEqual(self._parked(cache), [])
        self.assertEqual(len(client.calls_of("SplunkCaseAutopilot")), alert_common.FOLLOWUP_MAX_FAILURES)
        self.assertTrue(any("dropped after" in m for level, m in helper.logs if level == "error"))

    def test_parked_followup_expires(self):
        cache = FakeCache()
        context = self._followup_context(cache=cache, ingested=lambda ids: set(ids))
        key = context._parked_prefix() + "expired"
        cache.set(key, {"entity_id": "incident--1", "description": "Run Case Autopilot",
                        "kind": program_actions.FOLLOWUP_CASE_AUTOPILOT, "params": {}, "parked_at": "2020-01-01T00:00:00Z"})
        self.assertEqual(context.run_followups(), 0)
        self.assertIsNone(cache.get(key))
        self.assertEqual(context.client.calls_of("SplunkCaseAutopilot"), [])

    def test_malformed_parked_followups_never_block_the_others(self):
        cache = FakeCache()
        context = self._followup_context(cache=cache, ingested=lambda ids: set(ids))
        prefix = context._parked_prefix()
        valid = {"entity_id": "incident--1", "description": "Run Case Autopilot", "kind": program_actions.FOLLOWUP_CASE_AUTOPILOT,
                 "params": {"policy_id": ""}, "parked_at": program_actions.utc_now_iso()}
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
        client.handlers["SplunkCaseAutopilot"] = lambda variables: (
            graphql_error("boom") if variables["subjectId"] == "incident--2"
            else {"investigationRunAdd": {"id": "run-1"}})
        context.run_followups()
        self.assertEqual([key[len(prefix):] for key, _ in self._parked(cache)], ["d-raises"])
        self.assertEqual([call["subjectId"] for call in client.calls_of("SplunkCaseAutopilot")],
                         ["incident--2", "incident--1"])

    def test_parked_followups_of_another_platform_are_left_alone(self):
        cache = FakeCache()
        key = f"{alert_common.FOLLOWUP_PARKED_PREFIX}https://other.example|x"
        parked = {"entity_id": "incident--1", "description": "Run Case Autopilot",
                  "kind": program_actions.FOLLOWUP_CASE_AUTOPILOT, "params": {}, "parked_at": program_actions.utc_now_iso()}
        cache.set(key, parked)
        context = self._followup_context(cache=cache, ingested=lambda ids: set(ids))
        context.run_followups()
        self.assertEqual(cache.get(key), parked)
        self.assertEqual(context.client.calls_of("SplunkCaseAutopilot"), [])

    def test_followups_without_state_collection_are_skipped(self):
        helper = FakeAlertHelper()
        context = self._followup_context(cache=MemoryCache(), helper=helper, ingested=lambda ids: set())
        self._defer_autopilot(context)
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
