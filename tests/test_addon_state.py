"""Tests for the KV Store wrapper (#68)."""
import json
import re
import unittest

import program_fakes  # noqa: F401

import addon_state
from addon_state import KVCollection


class FakeData:
    """splunklib KVStoreCollectionData double."""

    def __init__(self, documents):
        self.documents = documents
        self.calls = []

    @classmethod
    def _matches(cls, document, query):
        if "$and" in query:
            return all(cls._matches(document, branch) for branch in query["$and"])
        if "$or" in query:
            return any(cls._matches(document, branch) for branch in query["$or"])
        for field, expected in query.items():
            if isinstance(expected, dict):
                value = document.get(field, "")
                if "$gt" in expected and not value > expected["$gt"]:
                    return False
                if "$regex" in expected and not re.search(expected["$regex"], value):
                    return False
            elif document.get(field) != expected:
                return False
        return True

    def query(self, **kwargs):
        self.calls.append(kwargs)
        query = json.loads(kwargs.get("query") or "{}")
        documents = [d for d in self.documents if self._matches(d, query)]
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
        self.assertTrue(all("skip" not in call for call in data.calls))

    def test_query_all_keeps_every_document_when_one_is_deleted_mid_scan(self):
        data = FakeData([{"_key": f"{i:03d}", "status": "declared"} for i in range(6)])
        collection = KVCollection(FakeService(data), "c")
        seen = []
        for record in collection.query_all(query={"status": "declared"}, page_size=2):
            seen.append(record["_key"])
            if record["_key"] == "001":
                # Rewritten out of the query while the scan runs, as a withdrawal does
                data.documents[0]["status"] = "withdrawn"
        self.assertEqual(seen, ["000", "001", "002", "003", "004", "005"])
        self.assertFalse(collection.truncated)

    def test_query_all_reports_a_truncated_scan(self):
        data = FakeData([{"_key": f"{i:03d}"} for i in range(5)])
        collection = KVCollection(FakeService(data), "c")
        self.assertEqual(len(list(collection.query_all(page_size=2, max_records=4))), 4)
        self.assertTrue(collection.truncated)
        self.assertEqual(len(list(collection.query_all(page_size=2, max_records=5))), 5)
        self.assertFalse(collection.truncated)

    def test_query_all_always_reads_the_key(self):
        data = FakeData([{"_key": "000", "id": "a"}])
        list(KVCollection(FakeService(data), "c").query_all(fields=["id"]))
        self.assertEqual(data.calls[0]["fields"], "id,_key")

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


def _stale(value):
    return value.get("at") == "old"


if __name__ == "__main__":
    unittest.main()
