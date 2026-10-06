"""OpenCTI calls made by the alert actions.

- Indicator resolution for sightings (#57, #67): by STIX id, or by value
  through the opencti_indicators KV Store and OpenCTI's exact pattern.
"""

from constants import INDICATORS_KVSTORE_NAME
from stix_converter import indicator_patterns, pattern_indicator

CASE_INSENSITIVE_KINDS = frozenset({"domain", "ipv4", "ipv6", "email_addr", "file_hash"})

INDICATOR_BY_ID_QUERY = """
query SplunkSightedIndicator($id: String!) {
  indicator(id: $id) { id standard_id pattern revoked }
}
"""

INDICATORS_BY_PATTERN_QUERY = """
query SplunkIndicatorsByPattern($filters: FilterGroup) {
  indicators(first: 10, filters: $filters, orderBy: created_at, orderMode: desc) {
    edges { node { id standard_id pattern revoked } }
  }
}
"""


# region indicator resolution for sightings
def _usable(node):
    return isinstance(node, dict) and node.get("standard_id") and not node.get("revoked")


def find_indicator_by_id(client, indicator_id):
    """
    :return: the indicator node (standard_id, revoked), or None when not readable
    """
    data = client.graphql_query(INDICATOR_BY_ID_QUERY, {"id": indicator_id})
    node = data.get("indicator")
    return node if isinstance(node, dict) and node.get("standard_id") else None


def find_indicator_in_kvstore(kv_collection, value, kind=None, main_type=None):
    """
    :param kv_collection: addon_state.KVCollection over opencti_indicators
    :param value: observable value
    :param kind: observable kind; only case-insensitive kinds also match the
        lower and upper case forms of the value
    :param main_type: OpenCTI main observable type the indicator must have
        (an entry that does not record it is accepted)
    :return: STIX id of a non-revoked indicator holding this value, or None
    """
    # KV Store queries are case sensitive; a URL path is too, unlike hosts and hashes
    candidates = [value]
    if kind in CASE_INSENSITIVE_KINDS:
        for candidate in (value.lower(), value.upper()):
            if candidate not in candidates:
                candidates.append(candidate)
    for candidate in candidates:
        records = kv_collection.query(query={"value": candidate}, limit=10, fields=["id", "revoked", "main_observable_type"])
        for record in records or []:
            if not record.get("id") or str(record.get("revoked", "false")).lower() in ("true", "1"):
                continue
            recorded_type = record.get("main_observable_type")
            if main_type and recorded_type and recorded_type.lower() != main_type.lower():
                continue
            return record["id"]
    return None


def find_indicator_by_pattern(client, patterns):
    """
    :param patterns: equivalent STIX patterns
    :return: STIX id of a non-revoked indicator with one of these patterns, or None
    """
    filters = {
        "mode": "and",
        "filters": [{"key": ["pattern"], "values": list(patterns), "operator": "eq", "mode": "or"}],
        "filterGroups": [],
    }
    data = client.graphql_query(INDICATORS_BY_PATTERN_QUERY, {"filters": filters})
    for edge in ((data.get("indicators") or {}).get("edges")) or []:
        node = (edge or {}).get("node") or {}
        if _usable(node):
            return node["standard_id"]
    return None


def resolve_sighted_indicator(context, sighting_of_type, value, kind):
    """
    :param context: alert_common.AlertContext
    :param sighting_of_type: "indicator_id" or "<kind>_indicator"
    :param value: Sighting of Value
    :param kind: observable kind for "<kind>_indicator" types
    :return: indicator dict for stix_converter.convert_to_sighting
    :raise ValueError: when the indicator cannot be used
    """
    value = (value or "").strip()
    if sighting_of_type == "indicator_id":
        if not value.startswith("indicator--"):
            raise ValueError(f"Sighting of Value must be an indicator STIX id (indicator--<uuid>), got {value!r}")
        found = find_indicator_by_id(context.client, value)
        if found is None:
            raise ValueError(f"Indicator {value} not found in OpenCTI or not readable by the add-on account")
        if not _usable(found):
            raise ValueError(f"Indicator {value} is revoked in OpenCTI: revoked indicators are not sighted")
        return {"id": found["standard_id"]}
    patterns, main_type = indicator_patterns(kind, value)
    case_insensitive = kind in CASE_INSENSITIVE_KINDS
    if case_insensitive:
        # OpenCTI pattern filters are case sensitive too
        for variant in (value.lower(), value.upper()):
            patterns += [p for p in indicator_patterns(kind, variant)[0] if p not in patterns]
    try:
        from addon_state import KVCollection

        found = find_indicator_in_kvstore(KVCollection(context.service, INDICATORS_KVSTORE_NAME), value, kind, main_type)
        if found:
            return {"id": found}
    except Exception as ex:
        context.logger.warning(f"opencti_indicators lookup failed, asking OpenCTI: {ex}")
    found = find_indicator_by_pattern(context.client, patterns)
    if found:
        return {"id": found}
    # Unknown to OpenCTI: create it from this single value (#57), one indicator whatever the case
    return pattern_indicator(kind, value.lower() if case_insensitive else value)
# endregion
