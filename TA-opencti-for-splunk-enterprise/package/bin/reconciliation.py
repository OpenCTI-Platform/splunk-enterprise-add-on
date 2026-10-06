"""Reconciliation of Splunk with OpenCTI (| openctireconcile).

mode=deployments (default): compare the indicators held in opencti_indicators
with the deployed-on relationships OpenCTI knows for the Splunk Security
Platform, and repair the drift through the deployment write-back:
- in Splunk and usable, not live in OpenCTI      -> deployed
- in Splunk but revoked or expired, live in OpenCTI -> removed / expired
- live in OpenCTI, absent from Splunk             -> removed
With refresh=t, indicators already in sync are re-reported too, which
refreshes last_sync_at in OpenCTI.
"""

import logging
from datetime import datetime, timezone

from addon_state import state_key
from deployment_reporter import STATUS_DEPLOYED, STATUS_EXPIRED, STATUS_REMOVED, removal_status, reported_status
from opencti_features import FEATURE_DEPLOYED_ON
from utils import get_bool_val, to_epoch

LIVE_STATUSES = ("deployed", "active")
PAGE_SIZE = 500
MAX_DEPLOYMENTS = 500000
# A deployment Splunk confirmed this recently is not withdrawn for missing from
# opencti_indicators: in index mode the lookup follows the index every 5 minutes.
ORPHAN_GRACE_SECONDS = 3600
# Clock difference tolerated between Splunk and OpenCTI
CLOCK_SKEW_SECONDS = 300

DEPLOYMENTS_QUERY = """
query SplunkPlatformDeployments($toId: StixRef, $first: Int, $after: ID) {
  stixCoreRelationships(relationship_type: "deployed-on", toId: $toId, first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        deployment_status
        external_id
        last_sync_at
        from { ... on Indicator { id standard_id } }
      }
    }
  }
}
"""

ACTION_DEPLOY = "deploy"
ACTION_REMOVE = "remove"
ACTION_EXPIRE = "expire"
ACTION_REFRESH = "refresh"
ACTION_WAIT = "wait"
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


def recently_confirmed(confirmed_at, now):
    """
    :param confirmed_at: dict STIX id -> last_sync_at of the deployment in OpenCTI
    :param now: aware datetime
    :return: set of the STIX ids Splunk confirmed within ORPHAN_GRACE_SECONDS
        (a time further in the future than the clock skew is not recent)
    """
    recent = set()
    for indicator_id, value in confirmed_at.items():
        epoch = to_epoch(value)
        if epoch is not None and -CLOCK_SKEW_SECONDS <= now.timestamp() - epoch <= ORPHAN_GRACE_SECONDS:
            recent.add(indicator_id)
    return recent


def plan_reconciliation(splunk_indicators, opencti_deployments, refresh=False, now=None, recent=()):
    """
    Pure drift computation (unit tested).

    :param splunk_indicators: dict STIX id -> opencti_indicators record
    :param opencti_deployments: dict STIX id -> deployment_status in OpenCTI
    :param refresh: re-report indicators already in sync
    :param recent: STIX ids Splunk confirmed recently (see recently_confirmed):
        absent from opencti_indicators, they wait for the lookup instead of
        being withdrawn
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
                if indicator_id in recent:
                    plan.append((indicator_id, ACTION_WAIT, None, None))
                else:
                    plan.append((indicator_id, ACTION_REMOVE, STATUS_REMOVED, None))
    return plan


class Reconciler:
    def __init__(self, client, detector, platform, indicators, reporter, logger=None, collection_name="opencti_indicators",
                 deployments=None):
        """
        :param client: SplunkAppConnectorHelper
        :param detector: OpenCTIFeatureDetector
        :param platform: Splunk Security Platform node
        :param indicators: KVCollection over opencti_indicators
        :param reporter: DeploymentReporter
        :param deployments: optional KVCollection over opencti_deployments
            (external ids the stream input reported)
        """
        self.client = client
        self.detector = detector
        self.platform = platform or {}
        self.indicators = indicators
        self.reporter = reporter
        self.logger = logger or logging.getLogger(__name__)
        self.collection_name = collection_name
        self.deployments = deployments
        self.external_ids = {}
        self.reported_external_ids = {}
        self.confirmed_at = {}

    def external_id(self, indicator_id, record):
        """
        The identity the stream input gives the deployment, so both address one:
        the external id OpenCTI holds, else the one the stream input reported,
        else the index the lookup entry was built from (index mode), else the
        KV Store entry.
        """
        for known in (self.external_ids, self.reported_external_ids):
            if known.get(indicator_id):
                return known[indicator_id]
        if not record:
            return None
        if record.get("source_index"):
            return f"index:{record['source_index']}/{indicator_id}"
        return f"kvstore:{self.collection_name}/{record.get('_key')}"

    def load_reported_external_ids(self, indicator_ids):
        """Read the external ids the stream input reported for these indicators (opencti_deployments)."""
        ids = [indicator_id for indicator_id in indicator_ids if not self.external_ids.get(indicator_id)]
        if self.deployments is None or not ids:
            return
        try:
            documents = self.deployments.get_many([state_key(indicator_id) for indicator_id in ids])
        except Exception as ex:
            self.logger.warning(f"opencti_deployments unreadable, external ids derived from the lookup: {ex}")
            return
        for document in documents.values():
            if document.get("indicator_id") and document.get("external_id"):
                self.reported_external_ids[document["indicator_id"]] = document["external_id"]

    def splunk_indicators(self):
        indicators = {}
        fields = ["_key", "id", "revoked", "valid_until", "value", "type", "source_index"]
        for record in self.indicators.query_all(fields=fields):
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
                    if node.get("last_sync_at"):
                        self.confirmed_at[source["standard_id"]] = node["last_sync_at"]
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
        if not self.reporter.enabled:
            return [{"action": "skipped", "message": "The OpenCTI platform has no deployment write-back mutation"}]
        splunk = self.splunk_indicators()
        opencti = self.opencti_deployments()
        if not splunk and opencti:
            self.logger.warning(
                f"{self.collection_name} is empty: the {len(opencti)} deployments OpenCTI knows are left unchanged"
            )
        now = datetime.now(timezone.utc)
        plan = plan_reconciliation(splunk, opencti, refresh=refresh, now=now,
                                   recent=recently_confirmed(self.confirmed_at, now))
        idle = (ACTION_NONE, ACTION_WAIT)
        self.load_reported_external_ids([indicator_id for indicator_id, action, _, _ in plan if action not in idle])
        rows = []
        counts = {}
        for indicator_id, action, status, record in plan:
            counts[action] = counts.get(action, 0) + 1
            if action in idle:
                continue
            external_id = self.external_id(indicator_id, record)
            removed_at = record.get("valid_until") if record and status == STATUS_EXPIRED else None
            queued = self.reporter.report(indicator_id, status, external_id, removed_at=removed_at)
            rows.append({
                "indicator_id": indicator_id,
                "value": (record or {}).get("value", ""),
                "opencti_status": opencti.get(indicator_id) or "unknown",
                "action": action,
                "reported_status": reported_status(status),
                "queued": queued,
            })
        self.reporter.drain()
        summary = {"action": "summary", "splunk_indicators": len(splunk), "opencti_deployments": len(opencti)}
        summary.update({f"count_{key}": value for key, value in counts.items()})
        summary.update({f"writeback_{key}": value for key, value in self.reporter.stats.items()})
        rows.append(summary)
        self.logger.info(f"Deployment reconciliation: {summary}")
        return rows
