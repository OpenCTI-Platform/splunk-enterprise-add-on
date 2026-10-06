"""Tests for the KV Store wrapper (#68)."""
import json
import unittest

import program_fakes  # noqa: F401

import addon_state
from addon_state import KVCollection


class FakeData:
    """splunklib KVStoreCollectionData double."""

    def __init__(self, documents):
        self.documents = documents
        self.calls = []

    def query(self, **kwargs):
        self.calls.append(kwargs)
        documents = self.documents
        query = json.loads(kwargs.get("query") or "{}")
        if "$or" in query:
            keys = {branch["_key"] for branch in query["$or"]}
            documents = [d for d in documents if d["_key"] in keys]
        if kwargs.get("sort") == "_key:1":
            documents = sorted(documents, key=lambda d: d["_key"])
        skip = kwargs.get("skip", 0)
        limit = kwargs.get("limit") or len(documents)
        return documents[skip:skip + limit]

    def query_by_id(self, key):
        for document in self.documents:
            if document["_key"] == key:
                return dict(document)
        raise Exception("HTTP 404 Not Found")

    def insert(self, document):
        if any(d["_key"] == document["_key"] for d in self.documents):
            raise Exception("HTTP 409 Conflict -- A document with the same key already exists")
        self.documents.append(dict(document))
        return {"_key": document["_key"]}


class FakeService:
    def __init__(self, data):
        self.kvstore = {"c": type("Collection", (), {"data": data})()}


class KVCollectionTest(unittest.TestCase):
    def test_query_all_pages_sorted_by_key(self):
        data = FakeData([{"_key": f"{i:03d}"} for i in reversed(range(5))])
        records = list(KVCollection(FakeService(data), "c").query_all(page_size=2))
        self.assertEqual([r["_key"] for r in records], ["000", "001", "002", "003", "004"])
        self.assertTrue(all(call["sort"] == "_key:1" for call in data.calls))

    def test_get_many_is_chunked(self):
        data = FakeData([{"_key": f"{i:03d}", "v": i} for i in range(addon_state.GET_MANY_CHUNK + 3)])
        keys = [f"{i:03d}" for i in range(addon_state.GET_MANY_CHUNK + 3)] + ["missing"]
        documents = KVCollection(FakeService(data), "c").get_many(keys)
        self.assertEqual(len(documents), addon_state.GET_MANY_CHUNK + 3)
        self.assertEqual(len(data.calls), 2)

    def test_insert_reports_an_existing_key(self):
        collection = KVCollection(FakeService(FakeData([])), "c")
        self.assertTrue(collection.insert({"_key": "k"}))
        self.assertFalse(collection.insert({"_key": "k"}))

    def test_cache_reservation_is_exclusive(self):
        cache = addon_state.KVStoreCache(FakeService(FakeData([])), collection="c")
        self.assertTrue(cache.reserve("autopilot|x", {"status": "pending"}))
        self.assertFalse(cache.reserve("autopilot|x", {"status": "pending"}))
        self.assertEqual(cache.get("autopilot|x"), {"status": "pending"})

    def test_cache_items_query_the_escaped_key_prefix(self):
        data = FakeData([])
        addon_state.KVStoreCache(FakeService(data), collection="c").items("hunt_evidence_pending|run.1|")
        self.assertEqual(json.loads(data.calls[0]["query"]), {"name": {"$regex": "^hunt_evidence_pending\\|run\\.1\\|"}})

    def test_cache_items_skip_cleared_and_foreign_entries(self):
        data = FakeData([
            {"_key": "a", "name": "pending|run|a", "value": json.dumps({"result_ids": ["x"]})},
            {"_key": "b", "name": "pending|run|b", "value": json.dumps({})},
            {"_key": "c", "name": "pending|run|c", "value": "not json"},
            {"_key": "d", "name": "other|run|d", "value": json.dumps({"result_ids": ["y"]})},
        ])
        cache = addon_state.KVStoreCache(FakeService(data), collection="c")
        self.assertEqual(cache.items("pending|run|"), [("pending|run|a", {"result_ids": ["x"]})])

    def test_cache_items_come_least_recently_written_first(self):
        data = FakeData([])
        cache = addon_state.KVStoreCache(FakeService(data), collection="c")
        cache.items("alert_followup|")
        self.assertEqual(data.calls[0]["sort"], "updated_at:1")
        saved = []
        data.batch_save = lambda *documents: saved.append(documents)
        cache.touch([("alert_followup|a", {"entity_id": "a"}), ("alert_followup|b", {"entity_id": "b"})])
        self.assertEqual(len(saved), 1, "one batch for every entry")
        self.assertEqual([d["name"] for d in saved[0]], ["alert_followup|a", "alert_followup|b"])
        self.assertTrue(all(d["updated_at"] for d in saved[0]))


def _stale(value):
    return value.get("at") == "old"


class TakeOverTest(unittest.TestCase):
    def setUp(self):
        self.cache = addon_state.MemoryCache()

    def test_free_key_is_created(self):
        self.assertEqual(addon_state.take_over(self.cache, "k", {"at": "now"}, _stale), [])
        self.assertEqual(self.cache.get("k")["at"], "now")
        self.assertTrue(self.cache.get("k")["lease"])

    def test_live_holder_keeps_it(self):
        self.cache.set("k", {"at": "now"})
        self.assertIsNone(addon_state.take_over(self.cache, "k", {"at": "now"}, _stale))
        self.assertEqual(self.cache.get("k"), {"at": "now"})

    def test_stale_holder_is_taken_over_once(self):
        stale = {"at": "old", "lease": "a"}
        self.cache.set("k", stale)
        self.assertEqual(addon_state.take_over(self.cache, "k", {"at": "now"}, _stale), ["k|takeover|a"])
        self.assertEqual(self.cache.get("k")["at"], "now")
        # A process that read the same stale value meanwhile loses
        self.cache.get = lambda key, real=self.cache.get: stale if key == "k" else real(key)
        self.assertIsNone(addon_state.take_over(self.cache, "k", {"at": "now"}, _stale))

    def test_dead_takeover_is_taken_over_in_turn(self):
        self.cache.set("k", {"at": "old", "lease": "a"})
        self.cache.set("k|takeover|a", {"at": "old", "lease": "b"})
        chain = addon_state.take_over(self.cache, "k", {"at": "now"}, _stale)
        self.assertEqual(chain, ["k|takeover|a", "k|takeover|a|takeover|b"])
        self.assertEqual(self.cache.get("k")["at"], "now")

    def test_live_takeover_is_left_to_it(self):
        self.cache.set("k", {"at": "old", "lease": "a"})
        self.cache.set("k|takeover|a", {"at": "now", "lease": "b"})
        self.assertIsNone(addon_state.take_over(self.cache, "k", {"at": "now"}, _stale))
        self.assertEqual(self.cache.get("k")["at"], "old")

    def test_values_without_lease_get_a_stable_takeover_key(self):
        value = {"at": "old"}
        self.assertEqual(addon_state.takeover_key("k", value), addon_state.takeover_key("k", dict(value)))
        self.assertTrue(addon_state.takeover_key("k", value).startswith("k|takeover|"))


if __name__ == "__main__":
    unittest.main()
