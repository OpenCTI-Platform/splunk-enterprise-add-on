"""OpenCTI program calls made by the alert actions, each feature detected.

- Hunt run targets for hunt evidence (innovation 01, huntRun) and the
  evidence write-back (huntRunEvidenceAdd, requested on #18671).
"""

import time
import uuid

from addon_state import take_over, utc_now_iso
from opencti_features import FEATURE_HUNT_EVIDENCE, FEATURE_HUNTS
from utils import parse_iso, to_iso

HUNT_RUN_QUERY = """
query SplunkHuntRun($id: String!) {
  huntRun(id: $id) {
    id
    hunt_id
    hunt { id name huntTargets { id standard_id entity_type } }
  }
}
"""

HUNT_EVIDENCE_MUTATION = """
mutation SplunkHuntRunEvidence($id: ID!, $input: HuntRunEvidenceAddInput!) {
  huntRunEvidenceAdd(id: $id, input: $input) { id }
}
"""

EVIDENCE_INGESTED_QUERY = """
query SplunkEvidenceIngested($id: String!) {
  stixObjectOrStixRelationship(id: $id) {
    ... on BasicObject { id }
    ... on BasicRelationship { id }
  }
}
"""

# The OpenCTI workers ingest a pushed bundle asynchronously: the evidence is
# attached to the run once it exists, after at most these waits.
EVIDENCE_INGESTION_DELAYS_SECONDS = (1, 2, 4, 8)
# Seconds of one alert run, over all its results, after which hunt evidence stops
# waiting. The waits for ingestion, the ingestion checks (one request per object:
# OpenCTI accepts a query field at most twice per request, so they cannot be
# batched) and the retries of parked reports all count. Once spent, the later
# results check their objects once and park them, and leave the parked reports
# to the next alert run.
EVIDENCE_WAIT_BUDGET_SECONDS = 60
# Evidence still not ingested is attached by a later report of the same run,
# within this delay.
EVIDENCE_PENDING_SECONDS = 86400
# Far above one attachment (ingestion wait included): an older claim is stale.
EVIDENCE_CLAIM_SECONDS = 600
PENDING_PREFIX = "hunt_evidence_pending|"
# Expired entries of other runs dropped by one report
EVIDENCE_SWEEP_LIMIT = 100

# Types a hunt evidence sighting can target (sighting_of_ref must be an SDO)
HUNT_SIGHTABLE_TYPES = {
    "Indicator", "Attack-Pattern", "Intrusion-Set", "Malware", "Campaign",
    "Threat-Actor-Group", "Threat-Actor-Individual", "Tool", "Infrastructure",
}


# region hunts
def hunt_targets(context, hunt_run_id):
    """
    :return: (targets STIX ids, hunt name) of the hunt behind the run; empty
        when the platform has no hunts or the run is unknown
    """
    if not context.detector.require(FEATURE_HUNTS, "Hunt run lookup"):
        return [], None
    data = context.client.graphql_query(HUNT_RUN_QUERY, {"id": hunt_run_id})
    run = data.get("huntRun")
    if not run:
        raise ValueError(f"Hunt run {hunt_run_id} not found in OpenCTI or not readable by the add-on account")
    hunt = run.get("hunt") or {}
    targets = [
        target.get("standard_id")
        for target in hunt.get("huntTargets") or []
        if isinstance(target, dict) and target.get("standard_id") and target.get("entity_type") in HUNT_SIGHTABLE_TYPES
    ]
    return targets, hunt.get("name")


def _start_budget(context):
    """The evidence budget of an alert run starts with its first evidence report."""
    if getattr(context, "evidence_deadline", None) is None:
        context.evidence_deadline = time.monotonic() + EVIDENCE_WAIT_BUDGET_SECONDS


def _budget_left(context):
    """:return: seconds left of the evidence budget of the alert run"""
    _start_budget(context)
    return context.evidence_deadline - time.monotonic()


def _ingested(context, object_ids):
    """
    :return: the ids among object_ids that OpenCTI already holds
    """
    present = []
    for object_id in object_ids:
        data = context.client.graphql_query(EVIDENCE_INGESTED_QUERY, {"id": object_id})
        if data.get("stixObjectOrStixRelationship"):
            present.append(object_id)
    return present


def wait_for_ingestion(context, object_ids, delays=EVIDENCE_INGESTION_DELAYS_SECONDS):
    """
    :return: (ids OpenCTI holds, ids still not ingested after the waits)
    """
    pending = list(object_ids)
    for delay in (0,) + tuple(delays):
        if delay:
            if delay > _budget_left(context):
                break
            time.sleep(delay)
        present = set(_ingested(context, pending))
        pending = [object_id for object_id in pending if object_id not in present]
        if not pending:
            break
    return [object_id for object_id in object_ids if object_id not in pending], pending


class HuntEvidenceDeferred(Exception):
    """No evidence object is ingested by OpenCTI yet: all are parked for a later report of the run."""


def _pending_prefix(hunt_run_id):
    return f"{PENDING_PREFIX}{hunt_run_id}|"


def _park(context, hunt_run_id, item):
    # One entry per parked report: concurrent reports never overwrite each other.
    context.cache.set(f"{_pending_prefix(hunt_run_id)}{uuid.uuid4().hex}", item)


def _stale_claim(value):
    """:return: True for a claim older than EVIDENCE_CLAIM_SECONDS (its holder died)"""
    claimed_at = parse_iso(value.get("claimed_at"))
    return claimed_at is None or time.time() - claimed_at.timestamp() > EVIDENCE_CLAIM_SECONDS


def _claim(cache, claim):
    """
    Atomic: of concurrent reports of the run, one only holds the claim; a stale
    claim is taken over (addon_state.take_over).

    :return: takeover keys to release with the claim once done, None when not claimed
    """
    return take_over(cache, claim, {"claimed_at": utc_now_iso()}, _stale_claim)


def _expired(item):
    parked_at = parse_iso(item.get("parked_at"))
    return parked_at is None or time.time() - parked_at.timestamp() > EVIDENCE_PENDING_SECONDS


def _drop(context, key, item, hunt_run_id):
    """Forget deferred evidence OpenCTI never ingested, with its claim and take-overs."""
    context.logger.warning(
        f"Hunt evidence {item.get('result_ids')} never ingested by OpenCTI: not attached to run {hunt_run_id}"
    )
    claim = f"{key}|claim"
    context.cache.release(key)
    context.cache.release(claim)
    for takeover, _ in context.cache.items(f"{claim}|takeover|"):
        context.cache.release(takeover)


def _drop_expired_pending(context):
    """Drop expired deferred evidence of every run: a run that never reports again would keep it for good."""
    for key, item in context.cache.items(PENDING_PREFIX, limit=EVIDENCE_SWEEP_LIMIT):
        run_and_entry = key[len(PENDING_PREFIX):].split("|")
        if len(run_and_entry) == 2 and _expired(item):
            _drop(context, key, item, run_and_entry[0])


def _move_behind(context, key, item, hunt_run_id):
    """
    items() returns the least recently written entries first: an entry still
    waiting goes behind the others, so a run with more parked reports than one
    listing holds gets all of them attached in turn.
    """
    try:
        context.cache.touch([(key, item)])
    except Exception as ex:
        context.logger.warning(f"Deferred hunt evidence {key} of run {hunt_run_id} not moved behind the rest: {ex}")


def _attach_pending(context, hunt_run_id):
    """Attach the evidence of earlier reports of this run that is now ingested."""
    prefix = _pending_prefix(hunt_run_id)
    for key, item in context.cache.items(prefix):
        if _budget_left(context) <= 0:
            # The entries not reached are the least recently written: the next run takes them first.
            break
        if "|" in key[len(prefix):]:
            continue
        claim = f"{key}|claim"
        if _expired(item):
            _drop(context, key, item, hunt_run_id)
            continue
        takeovers = _claim(context.cache, claim)
        if takeovers is None:
            continue
        try:
            # The listing may predate another report that attached this entry.
            item = context.cache.get(key)
            if not item:
                continue
            result_ids = item.get("result_ids")
            if not isinstance(result_ids, list) or not all(isinstance(object_id, str) for object_id in result_ids):
                context.logger.warning(f"Malformed deferred hunt evidence {key} of run {hunt_run_id} dropped")
                context.cache.release(key)
                continue
            present = _ingested(context, result_ids)
            if present:
                payload = {k: v for k, v in item.items() if k != "parked_at"}
                payload["result_ids"] = present
                context.client.graphql_query(HUNT_EVIDENCE_MUTATION, {"id": hunt_run_id, "input": payload})
            remaining = [object_id for object_id in result_ids if object_id not in present]
            if not remaining:
                context.cache.release(key)
            elif present:
                context.cache.set(key, dict(item, result_ids=remaining, hits_count=0))
            else:
                # Under the claim only: once it is released another report may attach and
                # release the entry, and a later rewrite would bring it back.
                _move_behind(context, key, item, hunt_run_id)
        except Exception as ex:
            # One entry failing never keeps the others of the run waiting
            context.logger.warning(f"Deferred hunt evidence {key} of run {hunt_run_id} not attached yet: {ex}")
        finally:
            context.cache.release(claim)
            for takeover in takeovers:
                context.cache.release(takeover)


def report_hunt_evidence(context, hunt_run_id, result_ids, hits_count, platform_id=None, observed_at=None):
    """
    Attach the evidence objects to the hunt run when the platform supports it,
    once OpenCTI ingested them. Objects still not ingested, and objects whose
    attachment failed, are attached by a later report of the same run.

    :return: True when attached, False when the mutation is absent
    :raise HuntEvidenceDeferred: no object ingested yet, all parked (not a failure)
    :raise Exception: the evidence, or part of it, cannot be attached (a failure)
    """
    if not context.detector.require(FEATURE_HUNT_EVIDENCE, "Hunt evidence attachment to the run"):
        return False
    _start_budget(context)
    try:
        _drop_expired_pending(context)
    except Exception as ex:
        context.logger.warning(f"Expired deferred hunt evidence not dropped yet: {ex}")
    try:
        _attach_pending(context, hunt_run_id)
    except Exception as ex:
        context.logger.warning(f"Deferred hunt evidence of run {hunt_run_id} not attached yet: {ex}")
    payload = {
        "hits_count": int(hits_count),
        "source": "splunk-alert-action",
    }
    if platform_id:
        payload["security_platform_id"] = platform_id
    if observed_at is not None:
        payload["observed_at"] = to_iso(observed_at)
    persistent = getattr(context.cache, "persistent", False)
    ingested, pending = wait_for_ingestion(context, list(result_ids))
    deferred = "they are attached by the next evidence report of the run"
    lost = "the KV Store is unavailable to defer them, so they are not attached"
    if pending and persistent:
        # The hits of this report are counted once, by its first attachment.
        parked = dict(payload, result_ids=pending, parked_at=utc_now_iso())
        if ingested:
            parked["hits_count"] = 0
        _park(context, hunt_run_id, parked)
    if not ingested:
        if persistent:
            raise HuntEvidenceDeferred(f"{len(pending)} evidence objects not ingested by OpenCTI yet: {deferred}")
        raise ValueError(f"{len(pending)} evidence objects not ingested by OpenCTI yet: {lost}")
    try:
        context.client.graphql_query(HUNT_EVIDENCE_MUTATION, {"id": hunt_run_id, "input": dict(payload, result_ids=ingested)})
    except Exception:
        if persistent:
            # A later report of the run retries the link, with the hits of this report
            try:
                _park(context, hunt_run_id, dict(payload, result_ids=ingested, parked_at=utc_now_iso()))
            except Exception as ex:
                context.logger.warning(f"Hunt evidence of run {hunt_run_id} not parked for a retry: {ex}")
        raise
    if pending and not persistent:
        raise ValueError(f"{len(pending)} of the evidence objects not ingested by OpenCTI yet: {lost}")
    if pending:
        context.logger.warning(f"{len(pending)} hunt evidence objects not ingested by OpenCTI yet: {deferred}")
    return True
# endregion
