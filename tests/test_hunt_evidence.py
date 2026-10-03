"""Tests for the Report hunt evidence alert action (WS-D, #68)."""
import json
import unittest

from program_fakes import FakeAlertContext, FakeAlertHelper, FakeClient, FakeDetector, graphql_error

import alert_common
import alert_report_hunt_evidence_helper as action
import program_actions
from opencti_features import FEATURE_HUNT_EVIDENCE, FEATURE_HUNTS
from stix_converter import convert_to_hunt_evidence

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

    def test_same_run_and_objects_give_the_same_ids(self):
        first = convert_to_hunt_evidence(PARAMS, EVENT, "run-1", PLATFORM["standard_id"], [TECHNIQUE])[1]
        second = convert_to_hunt_evidence(PARAMS, EVENT, "run-1", PLATFORM["standard_id"], [TECHNIQUE])[1]
        self.assertEqual(first, second)
        other_run = convert_to_hunt_evidence(PARAMS, EVENT, "run-2", PLATFORM["standard_id"], [TECHNIQUE])[1]
        self.assertNotEqual(first[0], other_run[0])

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

    def test_link_failure_does_not_fail_the_result(self):
        client = FakeClient({
            "SplunkHuntRun": self._hunt_run([{"id": "t1", "standard_id": TECHNIQUE, "entity_type": "Attack-Pattern"}]),
            "SplunkHuntRunEvidence": graphql_error("run is archived"),
        })
        helper = FakeAlertHelper(params={"hunt_run_id": "run-1", "tlp": "tlp_green"}, events=[EVENT])
        context = FakeAlertContext(helper, client=client, detector=FakeDetector((FEATURE_HUNTS, FEATURE_HUNT_EVIDENCE)),
                                   platform=PLATFORM)
        code = alert_common.run_alert(helper, "report_hunt_evidence", action.report_hunt_evidence, context_factory=lambda h: context)
        self.assertEqual(code, 0)
        self.assertTrue(any("not attached" in m for level, m in helper.logs if level == "warning"))

    def test_hunt_targets_without_feature(self):
        context = FakeAlertContext(FakeAlertHelper(), detector=FakeDetector())
        self.assertEqual(program_actions.hunt_targets(context, "run-1"), ([], None))


if __name__ == "__main__":
    unittest.main()
