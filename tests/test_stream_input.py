"""Tests for the OpenCTI stream modular input: #20, deleted indicators and the proxy log line."""
import json
import logging
import unittest
from types import SimpleNamespace
from unittest import mock

import program_fakes  # noqa: F401  (paths and Splunk-only module stubs)

import opencti_stream_helper as stream
import utils
from addon_config import AddonSettings

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
        },
    }
    payload.update(extra)
    return payload


def _message(event, data, number):
    return SimpleNamespace(event=event, id=f"1727000000{number:03d}-0", data=json.dumps({"data": data}))


class FakeKVData:
    def __init__(self, fail_lookups=False):
        self.docs = {}
        self.deleted = []
        self.fail_lookups = fail_lookups

    def query_by_id(self, key):
        if self.fail_lookups:
            raise Exception("KV Store is not ready")
        if key not in self.docs:
            raise Exception("HTTP 404 Not Found")
        return self.docs[key]

    def delete_by_id(self, key):
        self.deleted.append(key)
        self.docs.pop(key, None)

    def batch_save(self, *docs):
        for doc in docs:
            self.docs[doc["_key"]] = dict(doc)


class StreamInputTest(unittest.TestCase):
    def _run(self, messages, input_type="kvstore", kv=None, enrichment=None, proxy_settings=None):
        kv = kv or FakeKVData()
        service = SimpleNamespace(kvstore={"opencti_indicators": SimpleNamespace(data=kv)})
        settings = AddonSettings({"opencti_url": "https://opencti.example", "opencti_api_key": "key"},
                                 proxy_settings=proxy_settings)
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
        logger = logging.getLogger("stream-test")
        with mock.patch.object(stream, "logger_for_input", return_value=logger), \
                mock.patch.object(stream.conf_manager, "get_log_level", return_value="INFO"), \
                mock.patch.object(stream, "load_settings", return_value=settings), \
                mock.patch.object(AddonSettings, "build_client", return_value=client), \
                mock.patch.object(stream.log, "modular_input_start"), \
                mock.patch.object(stream.checkpointer, "KVStoreCheckpointer", return_value=checkpoint), \
                mock.patch.object(stream.client, "connect", return_value=service), \
                mock.patch.object(stream, "SSEClient", return_value=iter(messages)), \
                mock.patch.object(stream.smi, "Event", side_effect=lambda **kwargs: kwargs), \
                self.assertLogs(logger, level="INFO") as logs:
            stream.stream_events(inputs, writer)
        return kv, written, client, logs.output

    def test_kvstore_create_writes_the_entry(self):
        kv, _, _, _ = self._run([_message("create", _indicator(), 1)])
        self.assertIn(INTERNAL_ID, kv.docs)
        self.assertNotIn("extensions", kv.docs[INTERNAL_ID])

    def test_delete_removes_the_entry_without_enrichment(self):
        kv = FakeKVData()
        _, _, client, _ = self._run([_message("create", _indicator(), 1), _message("delete", _indicator(), 2)], kv=kv)
        self.assertEqual(kv.deleted, [INTERNAL_ID])
        self.assertEqual(client.get_indicator_enrichment.call_count, 1, "deleted indicators are not enriched")

    def test_index_mode_delete_uses_the_kv_key(self):
        """#20: index-mode deletes purge the KV entry keyed by _key, not by the STIX id."""
        kv = FakeKVData()
        kv.docs[INTERNAL_ID] = {"_key": INTERNAL_ID}
        _, written, _, _ = self._run([_message("delete", _indicator(), 1)], input_type="index", kv=kv)
        self.assertEqual(kv.deleted, [INTERNAL_ID])
        self.assertEqual(len(written), 1, "the delete event is still indexed")

    def test_index_mode_delete_purges_the_lookup_entry_keyed_by_stix_id(self):
        """The "Update OpenCTI Indicators Lookup" searches key entries by the STIX id (_key = id)."""
        kv = FakeKVData()
        kv.docs[STIX_ID] = {"_key": STIX_ID}
        self._run([_message("delete", _indicator(), 1)], input_type="index", kv=kv)
        self.assertEqual(kv.deleted, [STIX_ID])
        self.assertEqual(kv.docs, {})

    def test_delete_with_a_failed_lookup_keeps_the_entry(self):
        """A KV Store failure is not an absent entry: nothing is deleted on its ground."""
        for input_type in ("kvstore", "index"):
            with self.subTest(input_type=input_type):
                kv = FakeKVData(fail_lookups=True)
                kv.docs[INTERNAL_ID] = {"_key": INTERNAL_ID}
                self._run([_message("delete", _indicator(), 1)], input_type=input_type, kv=kv)
                self.assertEqual(kv.deleted, [])
                self.assertIn(INTERNAL_ID, kv.docs)

    def test_proxy_password_is_not_logged(self):
        proxy = {"proxy_url": "proxy.example", "proxy_port": "3128", "proxy_username": "svc", "proxy_password": "s3cret"}
        _, _, _, output = self._run([], proxy_settings=proxy)
        proxy_lines = [line for line in output if "Proxy settings" in line]
        self.assertEqual(len(proxy_lines), 1)
        self.assertNotIn("s3cret", proxy_lines[0])
        self.assertIn("********", proxy_lines[0])


class StreamHelpersTest(unittest.TestCase):
    def test_indexed_indicator_kv_keys(self):
        self.assertEqual(stream.indexed_indicator_kv_keys({"id": STIX_ID, "_key": INTERNAL_ID}), [STIX_ID, INTERNAL_ID])
        self.assertEqual(stream.indexed_indicator_kv_keys({"id": STIX_ID, "_key": STIX_ID}), [STIX_ID])

    def test_redact_proxy_settings(self):
        self.assertEqual(utils.redact_proxy_settings({"password": "x", "user": "u"}), {"password": "********", "user": "u"})
        self.assertEqual(utils.redact_proxy_settings({"proxy_password": ""}), {"proxy_password": ""})
        self.assertEqual(utils.redact_proxy_settings(None), {})


if __name__ == "__main__":
    unittest.main()
