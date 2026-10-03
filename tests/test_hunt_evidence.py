"""Tests for the Report hunt evidence alert action (WS-D, #68)."""
import json
import unittest
from unittest import mock

from program_fakes import FakeAlertContext, FakeAlertHelper, FakeClient, FakeDetector, graphql_error

import alert_common
import alert_report_hunt_evidence_helper as action
import program_actions
from addon_state import takeover_key
from opencti_features import FEATURE_HUNT_EVIDENCE, FEATURE_HUNTS
from stix_converter import convert_to_hunt_evidence
from utils import generate_observed_data_id

INGESTED = {"stixObjectOrStixRelationship": {"id": "internal"}}
NOT_INGESTED = {"stixObjectOrStixRelationship": None}

PLATFORM = {"id": "platform-internal", "standard_id": "identity--5b1fb3f9-2d4e-5f2c-9c6a-1d0f1e2f3a4b"}
TECHNIQUE = "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5"
INDICATOR = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac9"
EVENT = {"_time": "1727000000", "host": "sh01", "dest_ip": "10.1.2.3", "user": "bob", "count": "3", "hunt_run_id": "run-1"}
PARAMS = {"tlp": "tlp_amber", "labels": ["hunt"], "observables_extraction": "cim_model", "count": "3", "search_name": "Hunt T1071"}


def _objects(bundle, stix_type):
    return [o for o in json.loads(bundle)["objects"] if o["type"] == stix_type]


class ConverterTest(unittest.TestCase):
    def test_observed_data_and_target_sightings_carry_the_run_id(self):
        bundle, result_ids = convert_to_hunt_evidence(PARAMS, EVENT, "run-1", PLATFORM["standard_id"], [TECHNIQUE, INDICATOR])
        observed = _objects(bundle, "observed-data")[0]
        self.assertEqual(observed["number_observed"], 3)
        self.assertEqual(observed["x_opencti_hunt_run_id"], "run-1")
        self.assertEqual(len(observed["object_refs"]), 2)
        sightings = _objects(bundle, "sighting")
        self.assertEqual({s["sighting_of_ref"] for s in sightings}, {TECHNIQUE, INDICATOR})
        self.assertTrue(all(s["where_sighted_refs"] == [PLATFORM["standard_id"]] for s in sightings))
        self.assertTrue(all(s["x_opencti_hunt_run_id"] == "run-1" for s in sightings))
        self.assertTrue(all("run-1" in s["description"] for s in sightings))
        self.assertEqual(len(result_ids), 3)

    def test_evidence_ids_are_the_opencti_standard_ids(self):
        bundle, first = convert_to_hunt_evidence(PARAMS, EVENT, "run-1", PLATFORM["standard_id"], [TECHNIQUE])
        observed = _objects(bundle, "observed-data")[0]
        # OpenCTI keys an Observed-Data on its objects only, a sighting on its
        # target, where sighted and window: the same observation reported by
        # two runs is one object, linked to each run by huntRunEvidenceAdd.
        self.assertEqual(observed["id"], generate_observed_data_id(observed["object_refs"]))
        other_run = convert_to_hunt_evidence(PARAMS, EVENT, "run-2", PLATFORM["standard_id"], [TECHNIQUE])[1]
        self.assertEqual(first, other_run)
        later = convert_to_hunt_evidence(PARAMS, dict(EVENT, _time="1727003600"), "run-1",
                                         PLATFORM["standard_id"], [TECHNIQUE])[1]
        self.assertEqual(first[0], later[0])
        self.assertNotEqual(first[1], later[1], "a sighting of another window is another sighting")

    def test_without_platform_the_author_is_where_sighted(self):
        bundle, _ = convert_to_hunt_evidence(PARAMS, EVENT, "run-1", None, [TECHNIQUE])
        author = _objects(bundle, "identity")[0]["id"]
        self.assertEqual(_objects(bundle, "sighting")[0]["where_sighted_refs"], [author])

    def test_errors(self):
        with self.assertRaises(ValueError):
            convert_to_hunt_evidence(PARAMS, EVENT, "", PLATFORM["standard_id"], [TECHNIQUE])
        with self.assertRaises(ValueError):
            convert_to_hunt_evidence(dict(PARAMS, observables_extraction="disable"), EVENT, "run-1", None, [])


class ActionTest(unittest.TestCase):
    def _hunt_run(self, targets):
        return {"huntRun": {"id": "run-1", "hunt_id": "hunt-1", "hunt": {"id": "hunt-1", "name": "C2 over DNS", "huntTargets": targets}}}

    def test_reports_targets_and_attaches_evidence(self):
        client = FakeClient({
            "SplunkHuntRun": self._hunt_run([
                {"id": "t1", "standard_id": TECHNIQUE, "entity_type": "Attack-Pattern"},
                {"id": "t2", "standard_id": "report--1", "entity_type": "Report"},
            ]),
            "SplunkHuntRunEvidence": {"huntRunEvidenceAdd": {"id": "run-1"}},
            "SplunkEvidenceIngested": INGESTED,
        })
        helper = FakeAlertHelper(params={"hunt_run_id": "run-1", "tlp": "tlp_green", "count": "3"}, events=[EVENT])
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_HUNTS, FEATURE_HUNT_EVIDENCE)),
                                   platform=PLATFORM)
        code = alert_common.run_alert(helper, "report_hunt_evidence", action.report_hunt_evidence, context_factory=lambda h: context)
        self.assertEqual(code, 0)
        sightings = _objects(client.bundles[0], "sighting")
        self.assertEqual([s["sighting_of_ref"] for s in sightings], [TECHNIQUE], "only sightable hunt targets")
        evidence = client.calls_of("SplunkHuntRunEvidence")[0]
        self.assertEqual(evidence["id"], "run-1")
        self.assertEqual(evidence["input"]["hits_count"], 3)
        self.assertEqual(evidence["input"]["security_platform_id"], "platform-internal")
        self.assertEqual(len(evidence["input"]["result_ids"]), 2)

    def test_older_platform_sends_the_evidence_without_the_run_link(self):
        helper = FakeAlertHelper(params={"hunt_run_id": "run-1", "tlp": "tlp_green"}, events=[EVENT])
        client = FakeClient()
        context = FakeAlertContext(helper, client=client, detector=FakeDetector(), platform=None)
        code = alert_common.run_alert(helper, "report_hunt_evidence", action.report_hunt_evidence, context_factory=lambda h: context)
        self.assertEqual(code, 0)
        self.assertEqual(len(_objects(client.bundles[0], "observed-data")), 1)
        self.assertEqual(client.calls, [])

    def test_unknown_run_fails_the_result(self):
        client = FakeClient({"SplunkHuntRun": {"huntRun": None}})
        helper = FakeAlertHelper(params={"hunt_run_id": "run-x", "tlp": "tlp_green"}, events=[EVENT])
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_HUNTS,)), platform=PLATFORM)
        code = alert_common.run_alert(helper, "report_hunt_evidence", action.report_hunt_evidence, context_factory=lambda h: context)
        self.assertEqual(code, 2)

    def test_link_failure_fails_the_result_and_parks_the_evidence(self):
        client = FakeClient({
            "SplunkHuntRun": self._hunt_run([{"id": "t1", "standard_id": TECHNIQUE, "entity_type": "Attack-Pattern"}]),
            "SplunkHuntRunEvidence": graphql_error("run is locked"),
            "SplunkEvidenceIngested": INGESTED,
        })
        helper = FakeAlertHelper(params={"hunt_run_id": "run-1", "tlp": "tlp_green", "count": "4"}, events=[EVENT])
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_HUNTS, FEATURE_HUNT_EVIDENCE)),
                                   platform=PLATFORM)
        code = alert_common.run_alert(helper, "report_hunt_evidence", action.report_hunt_evidence, context_factory=lambda h: context)
        self.assertEqual(code, 2)
        self.assertTrue(any("not attached" in message for message in helper.errors()))
        [(_, parked)] = context.cache.items("hunt_evidence_pending|run-1|")
        self.assertEqual(sorted(parked["result_ids"]), sorted(client.calls_of("SplunkHuntRunEvidence")[0]["input"]["result_ids"]))
        self.assertEqual(parked["hits_count"], 4, "the retry carries the hits of this report")

    def test_deferred_attachment_does_not_fail_the_result(self):
        client = FakeClient({
            "SplunkHuntRun": self._hunt_run([{"id": "t1", "standard_id": TECHNIQUE, "entity_type": "Attack-Pattern"}]),
            "SplunkEvidenceIngested": NOT_INGESTED,
        })
        helper = FakeAlertHelper(params={"hunt_run_id": "run-1", "tlp": "tlp_green"}, events=[EVENT])
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_HUNTS, FEATURE_HUNT_EVIDENCE)),
                                   platform=PLATFORM)
        with mock.patch.object(program_actions.time, "sleep"):
            code = alert_common.run_alert(helper, "report_hunt_evidence", action.report_hunt_evidence,
                                          context_factory=lambda h: context)
        self.assertEqual(code, 0)
        self.assertTrue(any("deferred" in m for level, m in helper.logs if level == "info"))
        self.assertEqual(len(context.cache.items("hunt_evidence_pending|run-1|")), 1)

    def test_evidence_partly_lost_without_a_persistent_cache_fails_the_report(self):
        context = self._evidence_context({"observed-data--1"})
        context.cache.persistent = False
        with mock.patch.object(program_actions.time, "sleep"):
            with self.assertRaisesRegex(ValueError, "KV Store is unavailable"):
                program_actions.report_hunt_evidence(context, "run-1", ["observed-data--1", "sighting--2"], 1)
        self.assertEqual([call["input"]["result_ids"] for call in context.client.calls_of("SplunkHuntRunEvidence")],
                         [["observed-data--1"]], "the ingested part is attached first")

    def _evidence_context(self, ingested):
        client = FakeClient({
            "SplunkHuntRunEvidence": {"huntRunEvidenceAdd": {"id": "run-1"}},
            "SplunkEvidenceIngested": lambda variables: INGESTED if variables["id"] in ingested else NOT_INGESTED,
        })
        return FakeAlertContext(FakeAlertHelper(), client=client,
                                detector=FakeDetector((FEATURE_HUNTS, FEATURE_HUNT_EVIDENCE)), platform=PLATFORM)

    def test_evidence_is_attached_once_ingested(self):
        ingested = set()
        context = self._evidence_context(ingested)
        waits = []

        def sleep(delay):
            waits.append(delay)
            if len(waits) == 2:
                ingested.update({"observed-data--1", "sighting--1"})

        with mock.patch.object(program_actions.time, "sleep", side_effect=sleep):
            self.assertTrue(program_actions.report_hunt_evidence(context, "run-1", ["observed-data--1", "sighting--1"], 3))
        self.assertEqual(waits, [1, 2])
        evidence = context.client.calls_of("SplunkHuntRunEvidence")
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["input"]["result_ids"], ["observed-data--1", "sighting--1"])

    def test_evidence_not_ingested_is_attached_by_the_next_report(self):
        ingested = set()
        context = self._evidence_context(ingested)
        with mock.patch.object(program_actions.time, "sleep"):
            with self.assertRaises(program_actions.HuntEvidenceDeferred):
                program_actions.report_hunt_evidence(context, "run-1", ["observed-data--1"], 3, observed_at=1727000000)
            self.assertEqual(context.client.calls_of("SplunkHuntRunEvidence"), [])
            ingested.update({"observed-data--1", "sighting--2"})
            program_actions.report_hunt_evidence(context, "run-1", ["sighting--2"], 1)
        evidence = context.client.calls_of("SplunkHuntRunEvidence")
        self.assertEqual([call["input"]["result_ids"] for call in evidence], [["observed-data--1"], ["sighting--2"]])
        self.assertEqual(evidence[0]["input"]["hits_count"], 3, "the deferred link keeps its own report")
        self.assertEqual(evidence[0]["input"]["observed_at"], "2024-09-22T10:13:20.000Z")
        self.assertNotIn("parked_at", evidence[0]["input"])
        self.assertEqual(context.cache.items("hunt_evidence_pending|run-1|"), [])

    def test_concurrent_reports_park_their_evidence_apart(self):
        ingested = set()
        context = self._evidence_context(ingested)
        with mock.patch.object(program_actions.time, "sleep"):
            for object_id in ("observed-data--1", "observed-data--2"):
                with self.assertRaises(program_actions.HuntEvidenceDeferred):
                    program_actions.report_hunt_evidence(context, "run-1", [object_id], 1)
            self.assertEqual(len(context.cache.items("hunt_evidence_pending|run-1|")), 2)
            ingested.update({"observed-data--1", "observed-data--2", "sighting--3"})
            program_actions.report_hunt_evidence(context, "run-1", ["sighting--3"], 1)
        attached = sorted(call["input"]["result_ids"][0] for call in context.client.calls_of("SplunkHuntRunEvidence"))
        self.assertEqual(attached, ["observed-data--1", "observed-data--2", "sighting--3"])
        self.assertEqual(context.cache.items("hunt_evidence_pending|run-1|"), [])

    def test_evidence_claimed_by_another_report_is_left_to_it(self):
        context = self._evidence_context({"observed-data--1", "sighting--2"})
        parked = {"result_ids": ["observed-data--1"], "hits_count": 1, "source": "splunk-alert-action",
                  "parked_at": program_actions.utc_now_iso()}
        context.cache.set("hunt_evidence_pending|run-1|a", parked)
        context.cache.set("hunt_evidence_pending|run-1|a|claim", {"claimed_at": program_actions.utc_now_iso()})
        with mock.patch.object(program_actions.time, "sleep"):
            program_actions.report_hunt_evidence(context, "run-1", ["sighting--2"], 1)
        self.assertEqual([call["input"]["result_ids"] for call in context.client.calls_of("SplunkHuntRunEvidence")],
                         [["sighting--2"]])
        self.assertEqual(context.cache.get("hunt_evidence_pending|run-1|a"), parked)

    def test_stale_claim_is_taken_over_once(self):
        context = self._evidence_context({"observed-data--1", "sighting--2"})
        context.cache.set("hunt_evidence_pending|run-1|a", {
            "result_ids": ["observed-data--1"], "hits_count": 1, "source": "splunk-alert-action",
            "parked_at": program_actions.utc_now_iso(),
        })
        claim = "hunt_evidence_pending|run-1|a|claim"
        stale = {"claimed_at": "2020-01-01T00:00:00Z"}
        context.cache.set(claim, stale)
        context.cache.set(takeover_key(claim, stale), {"claimed_at": program_actions.utc_now_iso()})
        with mock.patch.object(program_actions.time, "sleep"):
            program_actions.report_hunt_evidence(context, "run-1", ["sighting--2"], 1)
        self.assertEqual(len(context.client.calls_of("SplunkHuntRunEvidence")), 1, "another report took it over")
        del context.cache.values[takeover_key(claim, stale)]
        with mock.patch.object(program_actions.time, "sleep"):
            program_actions.report_hunt_evidence(context, "run-1", ["sighting--2"], 1)
        attached = [call["input"]["result_ids"] for call in context.client.calls_of("SplunkHuntRunEvidence")]
        self.assertEqual(attached, [["sighting--2"], ["observed-data--1"], ["sighting--2"]])
        self.assertEqual(context.cache.items("hunt_evidence_pending|run-1|"), [])

    def test_dead_takeover_of_a_claim_is_taken_over(self):
        context = self._evidence_context({"observed-data--1", "sighting--2"})
        context.cache.set("hunt_evidence_pending|run-1|a", {
            "result_ids": ["observed-data--1"], "hits_count": 1, "source": "splunk-alert-action",
            "parked_at": program_actions.utc_now_iso(),
        })
        claim = "hunt_evidence_pending|run-1|a|claim"
        stale = {"claimed_at": "2020-01-01T00:00:00Z"}
        context.cache.set(claim, stale)
        # The report that took the stale claim over died before rewriting it.
        context.cache.set(takeover_key(claim, stale), dict(stale, lease="dead"))
        with mock.patch.object(program_actions.time, "sleep"):
            program_actions.report_hunt_evidence(context, "run-1", ["sighting--2"], 1)
        attached = [call["input"]["result_ids"] for call in context.client.calls_of("SplunkHuntRunEvidence")]
        self.assertEqual(attached, [["observed-data--1"], ["sighting--2"]])
        self.assertEqual(context.cache.items("hunt_evidence_pending|run-1|"), [], "claim and takeovers released")

    def test_entry_attached_after_the_listing_is_not_attached_again(self):
        context = self._evidence_context({"observed-data--1", "sighting--2"})
        key = "hunt_evidence_pending|run-1|a"
        listed = {"result_ids": ["observed-data--1"], "hits_count": 1, "parked_at": program_actions.utc_now_iso()}
        context.cache.items = lambda prefix, limit=100: [(key, listed)]
        with mock.patch.object(program_actions.time, "sleep"):
            program_actions.report_hunt_evidence(context, "run-1", ["sighting--2"], 1)
        self.assertEqual([call["input"]["result_ids"] for call in context.client.calls_of("SplunkHuntRunEvidence")],
                         [["sighting--2"]])

    def test_malformed_or_failing_deferred_evidence_never_blocks_the_others(self):
        context = self._evidence_context({"observed-data--1", "observed-data--2", "sighting--3"})
        parked_at = program_actions.utc_now_iso()
        context.cache.set("hunt_evidence_pending|run-1|a", {"result_ids": "observed-data--1", "parked_at": parked_at})
        context.cache.set("hunt_evidence_pending|run-1|b", {"result_ids": ["observed-data--1"], "hits_count": 1,
                                                            "bad": True, "parked_at": parked_at})
        context.cache.set("hunt_evidence_pending|run-1|c", {"result_ids": ["observed-data--2"], "hits_count": 1,
                                                            "parked_at": parked_at})
        accept = context.client.handlers["SplunkHuntRunEvidence"]
        context.client.handlers["SplunkHuntRunEvidence"] = (
            lambda variables: graphql_error("unknown field bad") if "bad" in variables["input"] else accept
        )
        with mock.patch.object(program_actions.time, "sleep"):
            program_actions.report_hunt_evidence(context, "run-1", ["sighting--3"], 1)
        self.assertIsNone(context.cache.get("hunt_evidence_pending|run-1|a"), "malformed entry dropped")
        self.assertIsNotNone(context.cache.get("hunt_evidence_pending|run-1|b"), "failing entry kept for a later report")
        self.assertIsNone(context.cache.get("hunt_evidence_pending|run-1|c"), "attached despite the failing one")
        self.assertIsNone(context.cache.get("hunt_evidence_pending|run-1|b|claim"), "claim released")

    def test_evidence_is_not_parked_without_a_persistent_cache(self):
        context = self._evidence_context(set())
        context.cache.persistent = False
        with mock.patch.object(program_actions.time, "sleep"):
            with self.assertRaisesRegex(ValueError, "KV Store is unavailable"):
                program_actions.report_hunt_evidence(context, "run-1", ["observed-data--1"], 1)
        self.assertEqual(context.cache.values, {})

    def test_hits_of_a_partly_ingested_report_are_counted_once(self):
        ingested = {"observed-data--1"}
        context = self._evidence_context(ingested)
        with mock.patch.object(program_actions.time, "sleep"):
            program_actions.report_hunt_evidence(context, "run-1", ["observed-data--1", "sighting--1", "sighting--2"], 3)
            ingested.add("sighting--1")
            program_actions.report_hunt_evidence(context, "run-1", ["observed-data--1"], 2)
            ingested.add("sighting--2")
            program_actions.report_hunt_evidence(context, "run-1", ["observed-data--1"], 1)
        evidence = [(call["input"]["result_ids"], call["input"]["hits_count"])
                    for call in context.client.calls_of("SplunkHuntRunEvidence")]
        self.assertEqual(evidence, [
            (["observed-data--1"], 3),
            (["sighting--1"], 0), (["observed-data--1"], 2),
            (["sighting--2"], 0), (["observed-data--1"], 1),
        ])

    def test_evidence_never_ingested_is_dropped_after_a_day(self):
        context = self._evidence_context({"sighting--2"})
        context.cache.set("hunt_evidence_pending|run-1|old", {
            "result_ids": ["observed-data--lost"], "hits_count": 1, "source": "splunk-alert-action",
            "parked_at": "2020-01-01T00:00:00.000Z",
        })
        with mock.patch.object(program_actions.time, "sleep"):
            program_actions.report_hunt_evidence(context, "run-1", ["sighting--2"], 1)
        self.assertEqual([call["input"]["result_ids"] for call in context.client.calls_of("SplunkHuntRunEvidence")],
                         [["sighting--2"]])
        self.assertTrue(context.logger.has("warning", "never ingested"))
        self.assertEqual(context.cache.items("hunt_evidence_pending|run-1|"), [])

    def test_hunt_targets_without_feature(self):
        context = FakeAlertContext(FakeAlertHelper(), detector=FakeDetector())
        self.assertEqual(program_actions.hunt_targets(context, "run-1"), ([], None))


if __name__ == "__main__":
    unittest.main()
