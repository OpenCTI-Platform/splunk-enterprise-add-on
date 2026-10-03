"""Reconciliation of Splunk with OpenCTI (| openctireconcile).

mode=deployments (default): compare the indicators held in opencti_indicators
with the deployed-on relationships OpenCTI knows for the Splunk Security
Platform, and repair the drift through the deployment write-back:
- in Splunk and usable, not live in OpenCTI      -> deployed
- in Splunk but revoked or expired, live in OpenCTI -> removed / expired
- live in OpenCTI, absent from Splunk             -> removed
With refresh=t, indicators already in sync are re-reported too, which
refreshes last_sync_at in OpenCTI.

mode=knowledge: refresh the provenance and Threat Pulse fields of the
indicators in opencti_indicators (OpenCTI updates them without stream events).
"""

import logging
from datetime import datetime, timezone

from deployment_reporter import STATUS_DEPLOYED, STATUS_EXPIRED, STATUS_REMOVED, removal_status
from knowledge_fields import KNOWLEDGE_FIELDS, enrichment_graphql_fields, refresh_knowledge_fields
from opencti_features import FEATURE_DEPLOYED_ON, FEATURE_PROVENANCE, FEATURE_PULSE
from utils import get_bool_val

LIVE_STATUSES = ("deployed", "active")
PAGE_SIZE = 500
MAX_DEPLOYMENTS = 500000
KNOWLEDGE_BATCH = 200

DEPLOYMENTS_QUERY = """
query SplunkPlatformDeployments($toId: StixRef, $first: Int, $after: ID) {
  stixCoreRelationships(relationship_type: "deployed-on", toId: $toId, first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        deployment_status
        external_id
        from { ... on Indicator { id standard_id } }
      }
    }
  }
}
"""

KNOWLEDGE_QUERY = """
query SplunkIndicatorsKnowledge($filters: FilterGroup, $first: Int) {
  indicators(first: $first, filters: $filters) {
    edges { node { id standard_id %s } }
  }
}
"""

ACTION_DEPLOY = "deploy"
ACTION_REMOVE = "remove"
ACTION_EXPIRE = "expire"
ACTION_REFRESH = "refresh"
ACTION_NONE = "none"


def splunk_state(record, now=None):
    """
    :param record: opencti_indicators record
    :return: "usable", or the removal status (removed / expired) for revoked
        or expired indicators
    """
    if get_bool_val(record.get("revoked")):
        return removal_status(record, now)
    if removal_status(record, now) == STATUS_EXPIRED:
        return STATUS_EXPIRED
    return "usable"


def plan_reconciliation(splunk_indicators, opencti_deployments, refresh=False, now=None):
    """
    Pure drift computation (unit tested).

    :param splunk_indicators: dict STIX id -> opencti_indicators record
    :param opencti_deployments: dict STIX id -> deployment_status in OpenCTI
    :param refresh: re-report indicators already in sync
    :return: list of (indicator STIX id, action, status to report or None, record or None)
    """
    plan = []
    for indicator_id, record in splunk_indicators.items():
        state = splunk_state(record, now)
        current = opencti_deployments.get(indicator_id)
        live = current in LIVE_STATUSES
        if state == "usable":
            if not live:
                plan.append((indicator_id, ACTION_DEPLOY, STATUS_DEPLOYED, record))
            elif refresh:
                plan.append((indicator_id, ACTION_REFRESH, STATUS_DEPLOYED, record))
            else:
                plan.append((indicator_id, ACTION_NONE, None, record))
        elif live:
            action = ACTION_EXPIRE if state == STATUS_EXPIRED else ACTION_REMOVE
            plan.append((indicator_id, action, state, record))
        else:
            plan.append((indicator_id, ACTION_NONE, None, record))
    # An empty collection is more likely unreadable or not synced yet than
    # emptied on purpose: never withdraw every deployment on that ground.
    if splunk_indicators:
        for indicator_id, current in opencti_deployments.items():
            if indicator_id not in splunk_indicators and current in LIVE_STATUSES:
                plan.append((indicator_id, ACTION_REMOVE, STATUS_REMOVED, None))
    return plan


class Reconciler:
    def __init__(self, client, detector, platform, indicators, reporter, logger=None, collection_name="opencti_indicators"):
        """
        :param client: SplunkAppConnectorHelper
        :param detector: OpenCTIFeatureDetector
        :param platform: Splunk Security Platform node
        :param indicators: KVCollection over opencti_indicators
        :param reporter: DeploymentReporter
        """
        self.client = client
        self.detector = detector
        self.platform = platform or {}
        self.indicators = indicators
        self.reporter = reporter
        self.logger = logger or logging.getLogger(__name__)
        self.collection_name = collection_name
        self.external_ids = {}

    def external_id(self, indicator_id, record):
        """
        :return: the external id OpenCTI already holds for this deployment (set
            by the stream input, KV Store or index mode), else the KV entry
        """
        if self.external_ids.get(indicator_id):
            return self.external_ids[indicator_id]
        return f"kvstore:{self.collection_name}/{record.get('_key')}" if record else None

    def splunk_indicators(self):
        indicators = {}
        for record in self.indicators.query_all(fields=["_key", "id", "revoked", "valid_until", "value", "type"]):
            if record.get("id"):
                indicators[record["id"]] = record
        return indicators

    def opencti_deployments(self):
        deployments = {}
        after = None
        while len(deployments) < MAX_DEPLOYMENTS:
            data = self.client.graphql_query(DEPLOYMENTS_QUERY, {
                "toId": self.platform["id"], "first": PAGE_SIZE, "after": after,
            })
            connection = data.get("stixCoreRelationships") or {}
            for edge in connection.get("edges") or []:
                node = (edge or {}).get("node") or {}
                source = node.get("from") or {}
                if source.get("standard_id"):
                    deployments[source["standard_id"]] = node.get("deployment_status")
                    if node.get("external_id"):
                        self.external_ids[source["standard_id"]] = node["external_id"]
            page = connection.get("pageInfo") or {}
            if not page.get("hasNextPage"):
                break
            after = page.get("endCursor")
        return deployments

    def reconcile(self, refresh=False):
        """
        :return: list of output rows (one per indicator with an action, plus a summary row)
        """
        if not self.platform.get("id"):
            return [{"action": "skipped", "message": "No Splunk Security Platform (Configuration > Security Platform)"}]
        if not self.detector.require(FEATURE_DEPLOYED_ON, "Deployment reconciliation"):
            return [{"action": "skipped", "message": "The OpenCTI platform has no deployed-on relationship"}]
        splunk = self.splunk_indicators()
        opencti = self.opencti_deployments()
        if not splunk and opencti:
            self.logger.warning(
                f"{self.collection_name} is empty: the {len(opencti)} deployments OpenCTI knows are left unchanged"
            )
        plan = plan_reconciliation(splunk, opencti, refresh=refresh, now=datetime.now(timezone.utc))
        rows = []
        counts = {}
        for indicator_id, action, status, record in plan:
            counts[action] = counts.get(action, 0) + 1
            if action == ACTION_NONE:
                continue
            external_id = self.external_id(indicator_id, record)
            removed_at = record.get("valid_until") if record and status == STATUS_EXPIRED else None
            queued = self.reporter.report(indicator_id, status, external_id, removed_at=removed_at)
            rows.append({
                "indicator_id": indicator_id,
                "value": (record or {}).get("value", ""),
                "opencti_status": opencti.get(indicator_id) or "unknown",
                "action": action,
                "reported_status": status,
                "queued": queued,
            })
        self.reporter.flush(force=True)
        summary = {"action": "summary", "splunk_indicators": len(splunk), "opencti_deployments": len(opencti)}
        summary.update({f"count_{key}": value for key, value in counts.items()})
        summary.update({f"writeback_{key}": value for key, value in self.reporter.stats.items()})
        rows.append(summary)
        self.logger.info(f"Deployment reconciliation: {summary}")
        return rows

    def refresh_knowledge(self):
        """
        :return: list of output rows (one summary row)
        """
        fields = enrichment_graphql_fields(self.detector)
        if not fields:
            self.detector.require(FEATURE_PROVENANCE, "Provenance fields refresh")
            self.detector.require(FEATURE_PULSE, "Threat Pulse fields refresh")
            return [{"action": "skipped", "message": "The OpenCTI platform has no provenance nor pulse fields"}]
        queried = {
            "provenance": self.detector.has(FEATURE_PROVENANCE),
            "pulse": self.detector.has(FEATURE_PULSE),
        }
        total = 0
        updated = 0
        page = {}
        # Only keys and ids are paged (sorted by _key, stable while documents
        # are rewritten); the full documents are re-read right before writing
        # since batch_save replaces whole documents.
        for record in self.indicators.query_all(fields=["_key", "id"]):
            if record.get("id") and record.get("_key"):
                page[record["id"]] = record["_key"]
            if len(page) >= KNOWLEDGE_BATCH:
                total += len(page)
                updated += self._refresh_page(page, fields, queried)
                page = {}
        if page:
            total += len(page)
            updated += self._refresh_page(page, fields, queried)
        summary = {"action": "knowledge_refresh", "splunk_indicators": total, "updated": updated}
        self.logger.info(f"Knowledge fields refresh: {summary}")
        return [summary]

    def _refresh_page(self, page, fields, queried):
        """
        :param page: dict indicator STIX id -> KV _key
        :return: number of documents updated
        """
        data = self.client.graphql_query(KNOWLEDGE_QUERY % fields, {
            "first": len(page) * 2,
            "filters": {"mode": "and", "filters": [{"key": ["ids"], "values": sorted(page)}], "filterGroups": []},
        })
        nodes = {}
        for edge in ((data.get("indicators") or {}).get("edges")) or []:
            node = (edge or {}).get("node") or {}
            if node.get("standard_id") in page:
                nodes[node["standard_id"]] = node
        if not nodes:
            return 0
        fresh = self.indicators.get_many([page[indicator_id] for indicator_id in nodes])
        changed = []
        for indicator_id, node in nodes.items():
            record = fresh.get(page[indicator_id])
            if record is None or record.get("id") != indicator_id:
                continue
            clean = {key: value for key, value in record.items() if key == "_key" or not key.startswith("_")}
            before = {key: clean.get(key) for key in KNOWLEDGE_FIELDS}
            refreshed = refresh_knowledge_fields(clean, node, **queried)
            if {key: refreshed.get(key) for key in KNOWLEDGE_FIELDS} != before:
                changed.append(refreshed)
        self.indicators.upsert(changed)
        return len(changed)
