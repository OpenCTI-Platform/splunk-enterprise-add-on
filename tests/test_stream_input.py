"""Tests for the OpenCTI stream modular input: deployment write-back, #20 and knowledge fields (#68)."""
import json
import logging
import unittest
from types import SimpleNamespace
from unittest import mock

import program_fakes  # noqa: F401  (paths and Splunk-only module stubs)

import opencti_stream_helper as stream
from addon_config import AddonSettings
from deployment_reporter import STATUS_DEPLOYED, STATUS_EXPIRED, STATUS_FAILED, STATUS_REMOVED
from knowledge_fields import PROVENANCE_EXTENSION_ID

OCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
STIX_ID = "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
INTERNAL_ID = "2b0f6d1e-0c4a-4d2c-9a43-7a1f1c1e9d55"


def _indicator(**extra):
    payload = {
        "type": "indicator",
        "id": STIX_ID,
        "name": "evil.example",
        "pattern": "[domain-name:value = 'evil.example']",
        "pattern_type": "stix",
        "valid_until": "2099-01-01T00:00:00.000Z",
        "extensions": {
            OCTI_EXTENSION: {"id": INTERNAL_ID, "score": 80, "updated_at": "2026-10-01T10:00:00.000Z",
                             "main_observable_type": "Domain-Name"},
            PROVENANCE_EXTENSION_ID: {"corroboration_count": 2, "assertions_count": 3, "single_sourced": False,
                                      "has_conflicts": False, "freshness_stale": False,
                                      "sources_by_kind": {"connector": 2},
                                      "last_asserted": "2026-10-01T09:00:00.000Z"},
        },
    }
    payload.update(extra)
    return payload


def _message(event, data, number):
    return SimpleNamespace(event=event, id=f"1727000000{number:03d}-0", data=json.dumps({"data": data}))


class FakeKVData:
    def __init__(self, fail_saves=False):
        self.docs = {}
        self.deleted = []
        self.fail_saves = fail_saves

    def query_by_id(self, key):
        if key not in self.docs:
            raise Exception("HTTP 404 Not Found")
        return self.docs[key]

    def delete_by_id(self, key):
        self.deleted.append(key)
        self.docs.pop(key, None)

    def batch_save(self, *docs):
        if self.fail_saves:
            raise Exception("KV Store is not ready")
        for doc in docs:
            self.docs[doc["_key"]] = dict(doc)


class RecordingReporter:
    def __init__(self):
        self.reports = []
        self.flushes = 0
        self.stats = {}

    def report(self, indicator_id, status, external_id=None, error_message=None, removed_at=None, deployed_at=None):
        self.reports.append({"id": indicator_id, "status": status, "external_id": external_id,
                             "error": error_message, "removed_at": removed_at})
        return True

    def flush_if_due(self):
        pass

    def flush(self, force=False):
        self.flushes += 1


class StreamInputTest(unittest.TestCase):
    def _run(self, messages, input_type="kvstore", kv=None, enrichment=None):
        kv = kv or FakeKVData()
        service = SimpleNamespace(kvstore={"opencti_indicators": SimpleNamespace(data=kv)})
        reporter = RecordingReporter()
        settings = AddonSettings({"opencti_url": "https://opencti.example", "opencti_api_key": "key"})
        client = mock.Mock()
        client.get_indicator_enrichment.return_value = enrichment
        checkpoint = mock.Mock()
        checkpoint.get.return_value = json.dumps({"start_from": "0-0"})
        written = []
        writer = SimpleNamespace(write_event=written.append)
        inputs = SimpleNamespace(
            inputs={"opencti_stream://test": {"input_type": input_type, "stream_id": "live", "index": "opencti", "import_from": "30"}},
            metadata={"session_key": "session"},
        )
        with mock.patch.object(stream, "logger_for_input", return_value=logging.getLogger("stream-test")), \
                mock.patch.object(stream.conf_manager, "get_log_level", return_value="INFO"), \
                mock.patch.object(stream, "load_settings", return_value=settings), \
                mock.patch.object(AddonSettings, "build_client", return_value=client), \
                mock.patch.object(stream.log, "modular_input_start"), \
                mock.patch.object(stream.checkpointer, "KVStoreCheckpointer", return_value=checkpoint), \
                mock.patch.object(stream.client, "connect", return_value=service), \
                mock.patch.object(stream, "build_deployment_reporter", return_value=(None, reporter)), \
                mock.patch.object(stream, "SSEClient", return_value=iter(messages)), \
                mock.patch.object(stream.smi, "Event", side_effect=lambda **kwargs: kwargs):
            stream.stream_events(inputs, writer)
        return kv, reporter, written, client

    def test_kvstore_create_reports_deployed_with_the_kv_key(self):
        kv, reporter, _, _ = self._run([_message("create", _indicator(), 1)])
        self.assertIn(INTERNAL_ID, kv.docs)
        self.assertEqual(reporter.reports, [{"id": STIX_ID, "status": STATUS_DEPLOYED,
                                             "external_id": f"kvstore:opencti_indicators/{INTERNAL_ID}",
                                             "error": None, "removed_at": None}])
        self.assertEqual(reporter.flushes, 1, "pending reports are flushed when the stream ends")

    def test_knowledge_fields_are_stored(self):
        enrichment = {"attack_patterns": ["T1071"], "malware": [], "threat_actors": [], "vulnerabilities": [],
                      "indicator": {"pulse": {"prevalence": "common", "trend": "rising"}}}
        kv, _, _, _ = self._run([_message("create", _indicator(), 1)], enrichment=enrichment)
        doc = kv.docs[INTERNAL_ID]
        self.assertEqual(doc["corroboration_count"], 2)
        self.assertEqual(doc["sources_by_kind"], "connector=2")
        self.assertEqual(doc["last_asserted_at"], "2026-10-01T09:00:00.000Z")
        self.assertEqual((doc["pulse_prevalence"], doc["pulse_trend"]), ("common", "rising"))
        self.assertEqual(doc["attack_patterns"], ["T1071"])
        self.assertNotIn("extensions", doc)

    def test_delete_reports_removed_or_expired(self):
        kv = FakeKVData()
        expired = _indicator(valid_until="2020-01-01T00:00:00.000Z")
        _, reporter, _, client = self._run(
            [_message("create", _indicator(), 1), _message("delete", _indicator(), 2), _message("delete", expired, 3)], kv=kv)
        self.assertEqual([r["status"] for r in reporter.reports], [STATUS_DEPLOYED, STATUS_REMOVED, STATUS_EXPIRED])
        self.assertEqual(reporter.reports[2]["removed_at"], "2020-01-01T00:00:00.000Z")
        self.assertEqual(kv.deleted, [INTERNAL_ID])
        self.assertEqual(client.get_indicator_enrichment.call_count, 1, "deleted indicators are not enriched")

    def test_revoked_update_is_reported_removed(self):
        _, reporter, _, _ = self._run([_message("update", _indicator(revoked=True), 1)])
        self.assertEqual(reporter.reports[0]["status"], STATUS_REMOVED)

    def test_kv_failure_reports_failed(self):
        _, reporter, _, _ = self._run([_message("create", _indicator(), 1)], kv=FakeKVData(fail_saves=True))
        self.assertEqual(reporter.reports[0]["status"], STATUS_FAILED)
        self.assertIn("KV Store is not ready", reporter.reports[0]["error"])

    def test_index_mode_delete_uses_the_kv_key(self):
        """#20: index-mode deletes purge the KV entry keyed by _key, not by the STIX id."""
        kv = FakeKVData()
        kv.docs[INTERNAL_ID] = {"_key": INTERNAL_ID}
        _, reporter, written, _ = self._run([_message("delete", _indicator(), 1)], input_type="index", kv=kv)
        self.assertEqual(kv.deleted, [INTERNAL_ID])
        self.assertEqual(len(written), 1, "the delete event is still indexed")
        self.assertEqual(reporter.reports[0]["status"], STATUS_REMOVED)
        self.assertEqual(reporter.reports[0]["external_id"], f"index:opencti/{STIX_ID}")

    def test_index_mode_delete_purges_the_lookup_entry_keyed_by_stix_id(self):
        """The "Update OpenCTI Indicators Lookup" searches key entries by the STIX id (_key = id)."""
        kv = FakeKVData()
        kv.docs[STIX_ID] = {"_key": STIX_ID}
        _, reporter, _, _ = self._run([_message("delete", _indicator(), 1)], input_type="index", kv=kv)
        self.assertEqual(kv.deleted, [STIX_ID])
        self.assertEqual(kv.docs, {})
        self.assertEqual(reporter.reports[0]["status"], STATUS_REMOVED)

    def test_index_mode_delete_with_a_failed_purge_reports_failed(self):
        kv = FakeKVData()
        kv.docs[INTERNAL_ID] = {"_key": INTERNAL_ID}

        def failing_delete(key):
            raise Exception("KV Store is not ready")

        kv.delete_by_id = failing_delete
        _, reporter, written, _ = self._run([_message("delete", _indicator(), 1)], input_type="index", kv=kv)
        self.assertEqual(len(written), 1)
        self.assertEqual(reporter.reports[0]["status"], STATUS_FAILED)
        self.assertIn("KV Store is not ready", reporter.reports[0]["error"])

    def test_index_mode_external_id_is_stable_across_updates(self):
        _, reporter, written, _ = self._run(
            [_message("create", _indicator(), 7), _message("update", _indicator(), 8)], input_type="index")
        self.assertEqual(json.loads(written[0]["data"])["corroboration_count"], 2)
        self.assertEqual({r["external_id"] for r in reporter.reports}, {f"index:opencti/{STIX_ID}"})

    def test_non_indicator_entities_are_not_reported(self):
        identity = {"type": "identity", "id": "identity--1", "name": "ACME", "identity_class": "organization",
                    "x_opencti_type": "organization"}
        _, reporter, _, _ = self._run([_message("create", identity, 1)])
        self.assertEqual(reporter.reports, [])


class ReportIndicatorStateTest(unittest.TestCase):
    def test_no_reporter(self):
        self.assertIsNone(stream.report_indicator_state(None, "create", {"id": STIX_ID}, "x"))

    def test_external_ids(self):
        self.assertEqual(stream.kv_external_id("opencti_indicators", "k"), "kvstore:opencti_indicators/k")
        self.assertEqual(stream.index_external_id("", STIX_ID), f"index:default/{STIX_ID}")

    def test_indexed_indicator_kv_keys(self):
        self.assertEqual(stream.indexed_indicator_kv_keys({"id": STIX_ID, "_key": INTERNAL_ID}), [STIX_ID, INTERNAL_ID])
        self.assertEqual(stream.indexed_indicator_kv_keys({"id": STIX_ID, "_key": STIX_ID}), [STIX_ID])


if __name__ == "__main__":
    unittest.main()
