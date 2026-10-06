"""KV Store backed state of the alert actions.

Collections (declared in default/collections.conf):
- opencti_addon_state: caches (feature detection, resolved Security Platform)
"""

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone

STATE_COLLECTION = "opencti_addon_state"

# KV Store accepts at most 1000 documents per batch_save call.
KV_BATCH_MAX = 1000
GET_MANY_CHUNK = 50
# Each level is a process that died while taking the entry over.
TAKEOVER_MAX_DEPTH = 16


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def state_key(*parts):
    """
    :param parts: values identifying a record
    :return: stable, short KV Store _key
    """
    raw = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]


def takeover_key(key, existing):
    """
    :param key: cache entry held by a process that died
    :param existing: its current value
    :return: the key whose creation takes this very value over
    """
    token = existing.get("lease") or state_key(json.dumps(existing, sort_keys=True))
    return f"{key}|takeover|{token}"


def take_over(cache, key, record, is_stale):
    """
    Atomically create ``key``, or take it over when the process holding it
    died. Of the processes that see one stale value, the one creating its
    takeover key (takeover_key) wins. A winner that dies before rewriting
    ``key`` leaves a takeover entry that goes stale in turn and is taken over
    the same way, so a crash at any step never blocks ``key`` for good.

    :param cache: KVStoreCache-like (reserve is an atomic insert)
    :param record: value written to ``key``, with a fresh "lease" token
    :param is_stale: callable(value) -> True when its holder died
    :return: None when a live process holds ``key``, else the takeover keys
        on the way to it ([] when ``key`` was free)
    """
    record = dict(record, lease=uuid.uuid4().hex)
    current, chain = key, []
    for _ in range(TAKEOVER_MAX_DEPTH):
        if cache.reserve(current, record):
            if chain:
                cache.set(key, record)
            return chain
        existing = cache.get(current)
        if not existing or not is_stale(existing):
            return None
        current = takeover_key(current, existing)
        chain.append(current)
    return None


def connect_service(session_key, app, splunkd_uri=None):
    """
    :param session_key: Splunk session key
    :param app: app namespace
    :param splunkd_uri: e.g. https://127.0.0.1:8089 (search commands provide it)
    :return: splunklib Service bound to the app, owner nobody
    """
    import splunklib.client as client  # type: ignore

    kwargs = {"token": session_key, "app": app, "owner": "nobody"}
    if splunkd_uri:
        from urllib.parse import urlparse

        parsed = urlparse(splunkd_uri)
        kwargs.update({"scheme": parsed.scheme or "https", "host": parsed.hostname, "port": parsed.port or 8089})
    return client.connect(**kwargs)


class KVCollection:
    """Thin wrapper over a KV Store collection data endpoint."""

    def __init__(self, service, name):
        self.name = name
        self._data = service.kvstore[name].data

    def get(self, key):
        """
        :return: the document, or None when absent
        """
        try:
            return self._data.query_by_id(key)
        except Exception as ex:
            if getattr(ex, "status", None) == 404 or "404" in str(ex):
                return None
            raise

    def upsert(self, records):
        """
        :param records: documents carrying their _key
        :return: number of documents written
        """
        records = [record for record in records if record]
        for start in range(0, len(records), KV_BATCH_MAX):
            self._data.batch_save(*records[start:start + KV_BATCH_MAX])
        return len(records)

    def insert(self, record):
        """
        :param record: document carrying its _key
        :return: True when inserted, False when a document already has this key
            (the KV Store rejects it atomically, unlike upsert)
        """
        try:
            self._data.insert(record)
            return True
        except Exception as ex:
            if getattr(ex, "status", None) == 409 or "409" in str(ex):
                return False
            raise

    def query(self, query=None, limit=0, skip=0, fields=None, sort=None):
        kwargs = {}
        if query:
            kwargs["query"] = json.dumps(query)
        if limit:
            kwargs["limit"] = limit
        if skip:
            kwargs["skip"] = skip
        if fields:
            kwargs["fields"] = ",".join(fields)
        if sort:
            kwargs["sort"] = sort
        return self._data.query(**kwargs)

    def get_many(self, keys):
        """
        :param keys: document keys
        :return: dict _key -> document, for the documents that exist
        """
        keys = sorted(set(keys))
        documents = {}
        # The query travels in the URL: keep each one short.
        for start in range(0, len(keys), GET_MANY_CHUNK):
            chunk = keys[start:start + GET_MANY_CHUNK]
            for document in self.query(query={"$or": [{"_key": key} for key in chunk]}, limit=len(chunk)):
                if document.get("_key"):
                    documents[document["_key"]] = document
        return documents

    def query_all(self, query=None, page_size=KV_BATCH_MAX, fields=None, max_records=1000000, sort="_key:1"):
        """
        Iterate a whole collection by pages, sorted (ascending _key by default,
        KV Store "field:1" syntax) so that skip-based paging stays stable while
        documents are rewritten.
        """
        skip = 0
        while skip < max_records:
            page = self.query(query=query, limit=page_size, skip=skip, fields=fields, sort=sort)
            if not page:
                return
            for record in page:
                yield record
            if len(page) < page_size:
                return
            skip += page_size

    def delete(self, key):
        try:
            self._data.delete_by_id(key)
            return True
        except Exception as ex:
            if getattr(ex, "status", None) == 404 or "404" in str(ex):
                return False
            raise


class KVStoreCache:
    """Persistent cache for OpenCTIFeatureDetector and the Security Platform resolver."""

    persistent = True

    def __init__(self, service, collection=STATE_COLLECTION):
        self._collection = KVCollection(service, collection)

    def get(self, key):
        record = self._collection.get(state_key(key))
        if not record:
            return None
        try:
            value = json.loads(record.get("value") or "{}")
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _record(key, value):
        return {
            "_key": state_key(key),
            "name": key,
            "value": json.dumps(value),
            "updated_at": utc_now_iso(),
        }

    def set(self, key, value):
        self._collection.upsert([self._record(key, value)])

    def reserve(self, key, value):
        """:return: True when this caller created the entry, False when it already existed"""
        return self._collection.insert(self._record(key, value))

    def release(self, key):
        self._collection.delete(state_key(key))

    def items(self, prefix, limit=100):
        """:return: list of (key, value) of the entries whose key starts with prefix"""
        found = []
        query = {"name": {"$regex": "^" + re.escape(prefix)}}
        for record in self._collection.query(query=query, limit=limit) or []:
            try:
                value = json.loads(record.get("value") or "{}")
            except ValueError:
                continue
            if isinstance(value, dict) and value and str(record.get("name", "")).startswith(prefix):
                found.append((record["name"], value))
        return found


class MemoryCache:
    """Process-local cache with the KVStoreCache interface (tests, fallbacks)."""

    persistent = False

    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = value

    def reserve(self, key, value):
        if key in self.values:
            return False
        self.values[key] = value
        return True

    def release(self, key):
        self.values.pop(key, None)

    def items(self, prefix, limit=100):
        return [(key, value) for key, value in self.values.items() if key.startswith(prefix) and value][:limit]
