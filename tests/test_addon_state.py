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


if __name__ == "__main__":
    unittest.main()
