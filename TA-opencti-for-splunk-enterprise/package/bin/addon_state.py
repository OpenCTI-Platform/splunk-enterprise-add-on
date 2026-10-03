"""KV Store backed state shared by the modular input, alert actions and search commands.

Collections (declared in default/collections.conf):
- opencti_addon_state: caches (feature detection, resolved Security Platform)
- opencti_deployments: last deployment status written back per indicator
- opencti_indicator_hits: hit history reported per indicator
- opencti_validation_results: IOC validation outcomes decided by Splunk
- opencti_provides: telemetry inventory posted as provides relationships
"""

import hashlib
import json
from datetime import datetime, timezone

STATE_COLLECTION = "opencti_addon_state"
DEPLOYMENTS_COLLECTION = "opencti_deployments"
HITS_COLLECTION = "opencti_indicator_hits"
VALIDATION_COLLECTION = "opencti_validation_results"
PROVIDES_COLLECTION = "opencti_provides"

# KV Store accepts at most 1000 documents per batch_save call.
KV_BATCH_MAX = 1000
GET_MANY_CHUNK = 50


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def state_key(*parts):
    """
    :param parts: values identifying a record
    :return: stable, short KV Store _key
    """
    raw = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]


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

    def query_all(self, query=None, page_size=KV_BATCH_MAX, fields=None, max_records=1000000, sort="_key"):
        """
        Iterate a whole collection by pages, sorted (by _key by default) so
        that skip-based paging stays stable while documents are rewritten.
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

    def set(self, key, value):
        self._collection.upsert([{
            "_key": state_key(key),
            "name": key,
            "value": json.dumps(value),
            "updated_at": utc_now_iso(),
        }])


class MemoryCache:
    """Process-local cache with the KVStoreCache interface (tests, fallbacks)."""

    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = value
