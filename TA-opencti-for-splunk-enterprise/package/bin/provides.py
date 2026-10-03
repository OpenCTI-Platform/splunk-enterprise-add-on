"""Telemetry inventory to the defense matrix (| openctiprovides).

The "OpenCTI - Telemetry inventory" search lists the CIM data models and the
sourcetypes holding data, maps them to MITRE Data Components through the
shipped, editable opencti_cim_data_components lookup, and pipes one row per
data component (data_component, sources, event_count) into the command,
which declares ``provides`` relationships Splunk Security Platform -> Data
Component in OpenCTI (innovation 09). With prune=t, data components the
add-on declared earlier and absent from the current inventory get their
provides relationship deleted, unless the inventory is empty or a
declaration of the run failed.
"""

import logging

from addon_state import state_key, utc_now_iso
from app_connector_helper import OpenCTIGraphQLError
from deployment_reporter import RateLimiter
from opencti_features import FEATURE_PROVIDES

MAX_SOURCES_IN_DESCRIPTION = 15

DATA_COMPONENTS_QUERY = """
query SplunkDataComponents($filters: FilterGroup, $first: Int) {
  dataComponents(first: $first, filters: $filters) {
    edges { node { id standard_id name } }
  }
}
"""

PROVIDES_ADD_MUTATION = """
mutation SplunkProvides($input: StixCoreRelationshipAddInput!) {
  stixCoreRelationshipAdd(input: $input) { id }
}
"""

PROVIDES_DELETE_MUTATION = """
mutation SplunkProvidesDelete($id: ID!) {
  stixCoreRelationshipEdit(id: $id) { delete }
}
"""

STATUS_DECLARED = "declared"
STATUS_UNMATCHED = "unmatched_data_component"
STATUS_PRUNED = "pruned"
STATUS_ERROR = "error"


def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v).strip()]
    return [v for v in (part.strip() for part in str(value).split("\n")) if v]


def aggregate_inventory(records):
    """
    :param records: rows with data_component, sources (multivalue), event_count
    :return: dict lower(name) -> {"name", "sources" (sorted), "event_count"}
    """
    inventory = {}
    for record in records:
        for name in _as_list(record.get("data_component")):
            entry = inventory.setdefault(name.lower(), {"name": name, "sources": set(), "event_count": 0})
            entry["sources"].update(_as_list(record.get("sources")))
            try:
                entry["event_count"] += int(float(str(record.get("event_count") or 0)))
            except ValueError:
                pass
    for entry in inventory.values():
        entry["sources"] = sorted(entry["sources"])
    return inventory


def provides_description(sources):
    shown = sources[:MAX_SOURCES_IN_DESCRIPTION]
    more = f" (+{len(sources) - len(shown)} more)" if len(sources) > len(shown) else ""
    return "Telemetry available in Splunk from: " + (", ".join(shown) or "unknown sources") + more


class ProvidesPublisher:
    def __init__(self, client, detector, platform, state, logger=None, rate_per_minute=120):
        """
        :param client: SplunkAppConnectorHelper
        :param detector: OpenCTIFeatureDetector
        :param platform: Splunk Security Platform node (id)
        :param state: KVCollection over opencti_provides
        """
        self.client = client
        self.detector = detector
        self.platform = platform or {}
        self.state = state
        self.logger = logger or logging.getLogger(__name__)
        self.limiter = RateLimiter(rate_per_minute)
        # A declaration error in any chunk of the search disables pruning:
        # the inventory of the run is then incomplete.
        self._had_error = False

    def resolve_data_components(self, names):
        """
        :return: dict lower(name) -> list of Data Component ids
        """
        resolved = {}
        names = sorted(set(names))
        for start in range(0, len(names), 100):
            chunk = names[start:start + 100]
            data = self.client.graphql_query(DATA_COMPONENTS_QUERY, {
                "first": len(chunk) * 4,
                "filters": {
                    "mode": "and",
                    "filters": [{"key": ["name"], "values": chunk, "operator": "eq", "mode": "or"}],
                    "filterGroups": [],
                },
            })
            for edge in ((data.get("dataComponents") or {}).get("edges")) or []:
                node = (edge or {}).get("node") or {}
                if node.get("name") and node.get("id"):
                    resolved.setdefault(node["name"].lower(), []).append(node["id"])
        return resolved

    def publish(self, records, prune=False, known_keys=None):
        """
        :param records: inventory rows
        :param prune: delete provides relationships declared earlier for data
            components absent from this inventory
        :param known_keys: lower-cased data component names seen in previous
            chunks of the same search (never pruned)
        :return: output rows, one per data component
        """
        if not self.platform.get("id"):
            return [{"data_component": "", "status": "skipped", "message": "No Splunk Security Platform"}]
        if not self.detector.require(FEATURE_PROVIDES, "Telemetry provides declaration"):
            return [{"data_component": "", "status": "skipped", "message": "The OpenCTI platform has no provides relationship"}]
        inventory = aggregate_inventory(records)
        resolved = self.resolve_data_components([entry["name"] for entry in inventory.values()])
        rows, states = [], []
        for key, entry in sorted(inventory.items()):
            row = {
                "data_component": entry["name"],
                "sources": entry["sources"],
                "event_count": entry["event_count"],
            }
            ids = resolved.get(key)
            if not ids:
                row.update({"status": STATUS_UNMATCHED, "message": "no Data Component with this name in OpenCTI"})
                rows.append(row)
                continue
            relationship_ids = []
            try:
                for data_component_id in ids:
                    self.limiter.acquire()
                    data = self.client.graphql_query(PROVIDES_ADD_MUTATION, {"input": {
                        "fromId": self.platform["id"],
                        "toId": data_component_id,
                        "relationship_type": "provides",
                        "description": provides_description(entry["sources"]),
                    }})
                    relationship_ids.append((data.get("stixCoreRelationshipAdd") or {}).get("id") or "")
                row.update({"status": STATUS_DECLARED, "message": ""})
            except OpenCTIGraphQLError as ex:
                self.logger.error(f"provides {entry['name']} failed: {ex}")
                row.update({"status": STATUS_ERROR, "message": str(ex)[:1000]})
            rows.append(row)
            if row["status"] == STATUS_DECLARED:
                states.append({
                    "_key": state_key(self.platform["id"], key),
                    "platform_id": self.platform["id"],
                    "data_component": entry["name"],
                    "data_component_ids": ",".join(ids),
                    "relationship_ids": ",".join(r for r in relationship_ids if r),
                    "sources": ", ".join(entry["sources"]),
                    "event_count": entry["event_count"],
                    "status": STATUS_DECLARED,
                    "reported_at": utc_now_iso(),
                })
        if any(row["status"] == STATUS_ERROR for row in rows):
            self._had_error = True
        if prune:
            current_keys = set(inventory) | set(known_keys or ())
            if not current_keys:
                self.logger.warning("Empty telemetry inventory: provides relationships are not pruned")
            elif self._had_error:
                self.logger.warning("Declaration errors in this run: provides relationships are not pruned")
            else:
                rows.extend(self._prune(current_keys, states))
        try:
            self.state.upsert(states)
        except Exception as ex:
            self.logger.warning(f"Unable to store the telemetry inventory in the KV Store: {ex}")
        return rows

    def _prune(self, current_keys, states):
        rows = []
        for record in self.state.query_all(query={"platform_id": self.platform["id"], "status": STATUS_DECLARED}):
            if (record.get("data_component") or "").lower() in current_keys:
                continue
            remaining, error = [], None
            for relationship_id in [r for r in (record.get("relationship_ids") or "").split(",") if r]:
                try:
                    self.limiter.acquire()
                    self.client.graphql_query(PROVIDES_DELETE_MUTATION, {"id": relationship_id})
                except OpenCTIGraphQLError as ex:
                    self.logger.warning(f"provides {relationship_id} not deleted: {ex}")
                    remaining.append(relationship_id)
                    error = ex
            if remaining:
                # Still declared: the next pruning run retries the relationships left.
                states.append(dict(
                    {k: v for k, v in record.items() if k == "_key" or not k.startswith("_")},
                    relationship_ids=",".join(remaining),
                ))
                rows.append({"data_component": record.get("data_component"), "status": STATUS_ERROR,
                             "message": f"not pruned: {str(error)[:1000]}"})
                continue
            states.append(dict(
                {k: v for k, v in record.items() if k == "_key" or not k.startswith("_")},
                status=STATUS_PRUNED, reported_at=utc_now_iso(),
            ))
            rows.append({"data_component": record.get("data_component"), "status": STATUS_PRUNED, "message": ""})
        return rows
