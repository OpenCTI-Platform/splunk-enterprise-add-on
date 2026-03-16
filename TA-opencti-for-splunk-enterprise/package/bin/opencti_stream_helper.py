import json
import logging
import hashlib

import import_declare_test
import splunklib.client as client
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from splunklib import modularinput as smi
import utils

from app_connector_helper import SplunkAppConnectorHelper
from constants import (
    VERIFY_SSL,
    INDICATORS_KVSTORE_NAME,
    REPORTS_KVSTORE_NAME,
    MARKINGS_KVSTORE_NAME,
    IDENTITIES_KVSTORE_NAME,
    ADDON_NAME,
)
from filigran_sseclient import SSEClient
from stix2patterns.v21.pattern import Pattern
import six
from datetime import datetime, timedelta, timezone
import sys

MARKING_DEFs = {}
IDENTITY_DEFs = {}

SUPPORTED_TYPES = {
    "email-addr": {"value": "email-addr"},
    "email-message": {"value": "email-message"},
    "ipv4-addr": {"value": "ipv4-addr"},
    "ipv6-addr": {"value": "ipv6-addr"},
    "domain-name": {"value": "domain-name"},
    "hostname": {"value": "hostname"},
    "url": {"value": "url"},
    "user-agent": {"value": "user-agent"},
    "file": {
        "hashes.MD5": "md5",
        "hashes.SHA-1": "sha1",
        "hashes.SHA-256": "sha256",
        "name": "filename",
    },
}

# Identity subtypes (x_opencti_type or identity_class) -> KV store
IDENTITY_KVSTORE_MAP = {
    "organization": IDENTITIES_KVSTORE_NAME
}

# Map entity types -> KV store collections.
ENTITY_KVSTORE_MAP = {
    "indicator": INDICATORS_KVSTORE_NAME,
    "report": REPORTS_KVSTORE_NAME,
    "marking-definition": MARKINGS_KVSTORE_NAME,
}

# ---------------------------------------------------------------------------
# Splunk ES Threat Intel collections
# Maps OpenCTI main_observable_type -> (ES collection name, ES key field)
# ---------------------------------------------------------------------------
ES_INTEL_MAP = {
    "IPv4-Addr":   ("ip_intel",     "ip"),
    "IPv6-Addr":   ("ip_intel",     "ip"),
    "Domain-Name": ("domain_intel", "domain"),
    "Url":         ("http_intel",   "url"),
    "StixFile":    ("file_intel",   "file_hash"),
    "Email-Addr":  ("email_intel",  "src_user"),
}

ES_APP_NAME = "SplunkEnterpriseSecuritySuite"


def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")


def get_account_api_key(session_key: str, account_name: str):
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta-opencti-for-splunk-enterprise_account",
    )
    account_conf_file = cfm.get_conf("ta-opencti-for-splunk-enterprise_account")
    return account_conf_file.get(account_name).get("api_key")


def validate_input(definition: smi.ValidationDefinition):
    return


def exist_in_kvstore(kv_store, key_id):
    """
    Check whether a record exists in a KV store collection by _key.
    Only treats HTTP 404 as 'not found'; re-raises all other exceptions
    so genuine errors are not silently swallowed.
    """
    try:
        kv_store.query_by_id(key_id)
        return True
    except client.HTTPError as e:
        if e.status == 404:
            return False
        raise
    except Exception:
        raise


def parse_stix_pattern(stix_pattern):
    try:
        parsed_pattern = Pattern(stix_pattern)
        for observable_type, comparisons in six.iteritems(
                parsed_pattern.inspect().comparisons
        ):
            for data_path, data_operator, data_value in comparisons:
                if observable_type in SUPPORTED_TYPES:
                    data_path = ".".join(data_path)
                    if (
                            data_path in SUPPORTED_TYPES[observable_type]
                            and data_operator == "="
                    ):
                        return {
                            "type": SUPPORTED_TYPES[observable_type][data_path],
                            "value": data_value.strip("'"),
                        }
    except Exception as e:
        logging.getLogger(__name__).warning(
            f"STIX pattern parse error: {e} | pattern = {stix_pattern}"
        )
        return None


def enrich_payload(stream_id, input_name, payload, msg_event):
    payload["stream_id"] = stream_id
    payload["input_name"] = input_name
    payload["event"] = msg_event

    created_by_id = payload.get("created_by_ref")
    if created_by_id:
        payload["created_by"] = IDENTITY_DEFs.get(created_by_id)

    payload["markings"] = []
    for marking_ref_id in payload.get("object_marking_refs", []):
        marking_value = MARKING_DEFs.get(marking_ref_id)
        if marking_value:
            payload["markings"].append(marking_value)

    if "labels" in payload and payload["labels"] is not None:
        if not isinstance(payload["labels"], list):
            payload["labels"] = [payload["labels"]]
    else:
        extracted_labels = []
        if "extensions" in payload:
            for ext in payload["extensions"].values():
                if "labels" in ext and ext["labels"]:
                    if isinstance(ext["labels"], list):
                        extracted_labels.extend(ext["labels"])
                    else:
                        extracted_labels.append(ext["labels"])
                if "x_opencti_labels" in ext and ext["x_opencti_labels"]:
                    if isinstance(ext["x_opencti_labels"], list):
                        extracted_labels.extend(ext["x_opencti_labels"])
                    else:
                        extracted_labels.append(ext["x_opencti_labels"])
        payload["labels"] = list(set(extracted_labels)) if extracted_labels else []

    parsed_stix = parse_stix_pattern(payload["pattern"])
    if parsed_stix is None:
        logging.getLogger(__name__).warning(
            f"Unsupported or unparseable STIX pattern, skipping indicator "
            f"{payload.get('id')}: {payload.get('pattern')}"
        )
        return None

    payload["type"] = parsed_stix["type"]
    payload["value"] = parsed_stix["value"]

    if "extensions" in payload:
        for ext in payload["extensions"].values():
            for attr in [
                "id",
                "score",
                "created_at",
                "updated_at",
                "is_inferred",
                "detection",
                "main_observable_type",
            ]:
                if attr in ext:
                    payload["_key" if attr == "id" else attr] = ext[attr]
        del payload["extensions"]

    if "external_references" in payload:
        del payload["external_references"]

    if "_key" not in payload and "id" in payload:
        payload["_key"] = payload["id"]

    return payload


def enrich_generic_payload(stream_id, input_name, payload, msg_event):
    payload["stream_id"] = stream_id
    payload["input_name"] = input_name
    payload["event"] = msg_event

    created_by_id = payload.get("created_by_ref")
    if created_by_id:
        payload["created_by"] = IDENTITY_DEFs.get(created_by_id)

    payload["markings"] = []
    for marking_ref_id in payload.get("object_marking_refs", []):
        marking_value = MARKING_DEFs.get(marking_ref_id)
        if marking_value:
            payload["markings"].append(marking_value)

    if "labels" in payload and payload["labels"] is not None:
        if not isinstance(payload["labels"], list):
            payload["labels"] = [payload["labels"]]
    else:
        extracted_labels = []
        if "extensions" in payload:
            for ext in payload["extensions"].values():
                if "labels" in ext and ext["labels"]:
                    if isinstance(ext["labels"], list):
                        extracted_labels.extend(ext["labels"])
                    else:
                        extracted_labels.append(ext["labels"])
                if "x_opencti_labels" in ext and ext["x_opencti_labels"]:
                    if isinstance(ext["x_opencti_labels"], list):
                        extracted_labels.extend(ext["x_opencti_labels"])
                    else:
                        extracted_labels.append(ext["x_opencti_labels"])
        payload["labels"] = list(set(extracted_labels)) if extracted_labels else []

    if "extensions" in payload:
        for ext in payload["extensions"].values():
            for attr in [
                "id",
                "score",
                "created_at",
                "creator_ids",
                "updated_at",
                "is_inferred",
                "x_opencti_organization_type",
            ]:
                if attr in ext:
                    payload["_key" if attr == "id" else attr] = ext[attr]
        # Fix: delete extensions to avoid bloating the KV store record
        del payload["extensions"]

    if "external_references" in payload:
        del payload["external_references"]

    if "_key" not in payload and "id" in payload:
        payload["_key"] = payload["id"]

    return payload


def get_kvstore_name_for_entity(entity_type, data):
    """
    Decide which KV store collection to use based on STIX entity type
    and, for identities, x_opencti_type / identity_class.
    """
    if entity_type == "identity":
        x_type = data.get("x_opencti_type") or data.get("identity_class")
        if not x_type:
            return None
        return IDENTITY_KVSTORE_MAP.get(x_type)
    return ENTITY_KVSTORE_MAP.get(entity_type)


def map_score_to_weight(score):
    """Map OpenCTI score (0-100) to Splunk ES intel weight (1-3)."""
    try:
        score = int(score or 0)
    except (ValueError, TypeError):
        return 1
    if score >= 75:
        return 3
    if score >= 40:
        return 2
    return 1


def parse_event_timestamp(timestamp_str, logger):
    """
    Parse an OpenCTI ISO timestamp to a Unix float.
    Handles both microsecond and non-microsecond variants.
    Returns None if unparseable.
    """
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(timestamp_str, fmt).timestamp()
        except (ValueError, TypeError):
            continue
    logger.warning(f"Unable to parse timestamp: {timestamp_str}")
    return None


# ---------------------------------------------------------------------------
# ES Intel helpers
# ---------------------------------------------------------------------------

def _es_intel_key(value, source):
    """Stable, collision-resistant _key for ES intel records."""
    return hashlib.md5(f"{value}|{source}".encode()).hexdigest()


def write_to_es_intel(es_service, parsed_stix, es_kvstore_handles, logger):
    """
    Upsert a parsed indicator into the appropriate Splunk ES intel KV store.
    Only indicators with a recognised main_observable_type are written.
    """
    obs_type = parsed_stix.get("main_observable_type")
    if obs_type not in ES_INTEL_MAP:
        logger.debug(f"ES intel: no mapping for observable type '{obs_type}', skipping.")
        return

    collection_name, field = ES_INTEL_MAP[obs_type]
    value = parsed_stix.get("value")
    if not value:
        logger.warning("ES intel: indicator has no value, skipping.")
        return

    source = "opencti:{}".format(
        parsed_stix.get("input_name") or parsed_stix.get("stream_id") or "unknown"
    )
    record = {
        "_key":            _es_intel_key(value, source),
        field:             value,
        "description":     parsed_stix.get("name", ""),
        "source":          source,
        "weight":          map_score_to_weight(parsed_stix.get("score")),
        "expiration_date": parsed_stix.get("valid_until", ""),
    }

    try:
        if collection_name not in es_kvstore_handles:
            es_kvstore_handles[collection_name] = es_service.kvstore[collection_name].data
            logger.info(f"ES intel: initialised KV handle for '{collection_name}'")

        es_kvstore_handles[collection_name].batch_save(*[record])
        logger.info(f"ES intel [{collection_name}]: upserted {field}={value} source={source}")
    except Exception as e:
        logger.error(f"ES intel: failed to write to '{collection_name}': {e}")


def delete_from_es_intel(es_service, parsed_stix, es_kvstore_handles, logger):
    """
    Delete an indicator from the appropriate Splunk ES intel KV store.
    Scoped by both indicator value and source to avoid cross-feed deletions.
    """
    obs_type = parsed_stix.get("main_observable_type")
    if obs_type not in ES_INTEL_MAP:
        logger.debug(f"ES intel: no mapping for observable type '{obs_type}', skipping delete.")
        return

    collection_name, field = ES_INTEL_MAP[obs_type]
    value = parsed_stix.get("value")
    if not value:
        logger.warning("ES intel: delete called with no indicator value, skipping.")
        return

    source = "opencti:{}".format(
        parsed_stix.get("input_name") or parsed_stix.get("stream_id") or "unknown"
    )

    try:
        if collection_name not in es_kvstore_handles:
            es_kvstore_handles[collection_name] = es_service.kvstore[collection_name].data
            logger.info(f"ES intel: initialised KV handle for '{collection_name}'")

        es_kvstore_handles[collection_name].delete(
            query=json.dumps({
                "$and": [
                    {field:    {"$eq": value}},
                    {"source": {"$eq": source}},
                ]
            })
        )
        logger.info(f"ES intel [{collection_name}]: deleted {field}={value} source={source}")
    except Exception as e:
        logger.error(f"ES intel: failed to delete from '{collection_name}': {e}")


# ---------------------------------------------------------------------------
# Modular input entry points
# ---------------------------------------------------------------------------

def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    for input_name, input_item in inputs.inputs.items():

        normalized_input_name = input_name.split("/")[-1]
        logger = logger_for_input(normalized_input_name)
        try:
            session_key = inputs.metadata["session_key"]
            log_level = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name="ta-opencti-for-splunk-enterprise_settings",
            )
            logger.setLevel(log_level)

            cfm = conf_manager.ConfManager(
                session_key,
                ADDON_NAME,
                realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta-opencti-for-splunk-enterprise_settings",
            )
            conf = cfm.get_conf("ta-opencti-for-splunk-enterprise_settings")
            opencti_url = conf.get("account").get("opencti_url")
            opencti_api_key = conf.get("account").get("opencti_api_key")

            log.modular_input_start(logger, normalized_input_name)
            logger.info("OpenCTI data input module start")

            # ------------------------------------------------------------------
            # Read boolean flags from input config.
            # UCC checkboxes arrive as the strings "0" or "1".
            # ------------------------------------------------------------------
            index_output    = str(input_item.get("index_output", "0")).strip() == "1"
            es_intel_output = str(input_item.get("es_intel_output", "0")).strip() == "1"

            stream_id    = input_item.get("stream_id")
            target_index = input_item.get("index")
            import_from  = input_item.get("import_from")

            logger.info(f"OpenCTI URL: {opencti_url}")
            logger.info(f"Fetching data from OpenCTI stream.id: {stream_id}")
            logger.info(f"Index output enabled: {index_output}")
            logger.info(f"ES intel output enabled: {es_intel_output}")

            # resolve proxy configurations
            proxy_settings = conf_manager.get_proxy_dict(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name="ta-opencti-for-splunk-enterprise_settings",
            )
            logger.info(f"Proxy settings: {proxy_settings}")

            # Create Splunk App Connector Helper
            connector_helper = SplunkAppConnectorHelper(
                connector_id="splunk-stream-input",
                connector_name="Splunk Stream Input",
                opencti_url=opencti_url,
                opencti_api_key=opencti_api_key,
                proxy_settings=proxy_settings,
            )

            kvstore_checkpointer = checkpointer.KVStoreCheckpointer(
                ADDON_NAME + "_checkpoints",
                session_key,
                ADDON_NAME,
            )
            state = kvstore_checkpointer.get(input_name)
            logger.info(f"state: {state}")

            if state is None:
                recover_until = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                start_date = datetime.now(timezone.utc) - timedelta(days=int(import_from))
                start_timestamp = int(datetime.timestamp(start_date)) * 1000
                state = {
                    "start_from": str(start_timestamp) + "-0",
                    "recover_until": recover_until,
                }
                logger.info(f"Initialized checkpoint state: {state}")
            else:
                state = json.loads(state)

            live_stream_url = f"{opencti_url}/stream/{stream_id}"
            if "recover_until" in state:
                live_stream_url += f"?recover={state['recover_until']}"
            logger.debug(f"Live stream URL: {live_stream_url}")

            # ------------------------------------------------------------------
            # Primary Splunk service — scoped to this TA (always required)
            # ------------------------------------------------------------------
            service = None
            kvstore_handles = {}

            try:
                service = client.connect(token=session_key, app=ADDON_NAME)
                logger.info("Connected to Splunk service (TA context)")
            except Exception as e:
                logger.error(f"Failed to connect to Splunk service: {e}")
                return

            # ------------------------------------------------------------------
            # Secondary Splunk service — scoped to ES (only when es_intel enabled)
            # ------------------------------------------------------------------
            es_service = None
            es_kvstore_handles = {}

            if es_intel_output:
                try:
                    es_service = client.connect(
                        token=session_key,
                        app=ES_APP_NAME,
                    )
                    logger.info(f"Connected to Splunk service (ES context: {ES_APP_NAME})")
                except Exception as e:
                    logger.error(
                        f"Failed to connect to ES app context '{ES_APP_NAME}': {e}. "
                        f"ES intel output will be disabled for this run."
                    )
                    es_intel_output = False

            proxies = utils.get_proxy_config(proxy_settings=proxy_settings)
            try:
                messages = SSEClient(
                    live_stream_url,
                    state.get("start_from"),
                    headers={
                        "authorization": f"Bearer {opencti_api_key}",
                        "listen-delete": "true",
                        "no-dependencies": "true",
                        "with-inferences": "true",
                    },
                    verify=VERIFY_SSL,
                    proxies=proxies,
                )

                for msg in messages:
                    if msg.event not in ["create", "update", "delete"]:
                        continue

                    logger.debug(f"Received message ID: {msg.id} | Event: {msg.event}")
                    message_payload = json.loads(msg.data)
                    logger.debug(f"Message payload: {message_payload}")
                    data = message_payload.get("data", {})
                    entity_type = data.get("type")

                    # Keep in-memory caches warm for markings and identities
                    if entity_type == "identity":
                        IDENTITY_DEFs[data["id"]] = data.get("name", "Unknown")
                    elif entity_type == "marking-definition":
                        MARKING_DEFs[data["id"]] = data.get("name", "Unknown")

                    # ----------------------------------------------------------
                    # Enrich — one pipeline regardless of output destinations
                    # ----------------------------------------------------------
                    parsed_stix = None
                    if entity_type == "indicator" and data.get("pattern_type") == "stix":
                        parsed_stix = enrich_payload(stream_id, input_name, data, msg.event)
                        if parsed_stix is not None:
                            try:
                                enrich_row = connector_helper.get_indicator_enrichment(data["id"])
                                if enrich_row:
                                    parsed_stix["attack_patterns"]  = enrich_row["attack_patterns"]
                                    parsed_stix["malware"]           = enrich_row["malware"]
                                    parsed_stix["threat_actors"]     = enrich_row["threat_actors"]
                                    parsed_stix["vulnerabilities"]   = enrich_row["vulnerabilities"]
                            except Exception as e:
                                logger.warning(
                                    f"OpenCTI enrichment failed for {data['id']}: {e}"
                                )
                    else:
                        parsed_stix = enrich_generic_payload(stream_id, input_name, data, msg.event)

                    if parsed_stix is None:
                        logger.error(f"Could not enrich data for msg {msg.id}")
                        continue

                    key_id = parsed_stix.get("_key")
                    indicator_value = parsed_stix.get("value") or data.get("value")
                    logger.info(
                        f"[{entity_type} {key_id}] Processing value={indicator_value} event={msg.event}"
                    )

                    # ==========================================================
                    # 1. PRIMARY — Always write to TA KV Store
                    # ==========================================================
                    kvstore_name = get_kvstore_name_for_entity(entity_type, parsed_stix)

                    if not kvstore_name:
                        logger.debug(
                            f"No KV store mapping for entity_type={entity_type}, "
                            f"x_opencti_type={parsed_stix.get('x_opencti_type')}"
                        )
                    else:
                        try:
                            if kvstore_name not in kvstore_handles:
                                kvstore_handles[kvstore_name] = service.kvstore[kvstore_name].data
                                logger.info(f"Initialized KV handle for collection: {kvstore_name}")

                            kv = kvstore_handles[kvstore_name]

                            if msg.event == "delete":
                                if key_id and exist_in_kvstore(kv, key_id):
                                    kv.delete_by_id(key_id)
                                    logger.info(f"KV Store [{kvstore_name}]: Deleted {key_id}")
                            else:
                                parsed_stix["added_at"] = datetime.now(timezone.utc).strftime(
                                    "%Y-%m-%dT%H:%M:%SZ"
                                )
                                kv.batch_save(parsed_stix)
                                logger.info(f"KV Store [{kvstore_name}]: Inserted/Updated {key_id}")

                        except Exception as kv_ex:
                            logger.error(
                                f"KV Store operation failed for collection={kvstore_name}: {kv_ex}"
                            )
                            continue

                    # ==========================================================
                    # 2. CONDITIONAL — Write/delete in Splunk ES intel KV stores
                    # ==========================================================
                    if es_intel_output and es_service and entity_type == "indicator":
                        if msg.event == "delete":
                            delete_from_es_intel(es_service, parsed_stix, es_kvstore_handles, logger)
                        else:
                            write_to_es_intel(es_service, parsed_stix, es_kvstore_handles, logger)

                    # ==========================================================
                    # 3. CONDITIONAL — Write to Splunk index (audit / replay)
                    # ==========================================================
                    if index_output:
                        event_time = parse_event_timestamp(
                            parsed_stix.get("updated_at"), logger
                        )
                        event_writer.write_event(
                            smi.Event(
                                data=json.dumps(parsed_stix),
                                time=event_time,
                                host=None,
                                index=target_index,
                                source="opencti",
                                sourcetype=f"opencti:{entity_type}",
                                done=True,
                                unbroken=True,
                            )
                        )
                        # Write a tombstone event for deletes so the index has a full audit trail
                        if msg.event == "delete":
                            logger.debug(f"Index tombstone written for deleted {entity_type} {key_id}")

                    state["start_from"] = msg.id
                    kvstore_checkpointer.update(input_name, json.dumps(state))

            except Exception as ex:
                logger.error(f"Error in stream processing loop: {ex}")
                sys.excepthook(*sys.exc_info())

        except Exception as e:
            log.log_exception(
                logger, e, "opencti_stream_helper",
                msg_before="Exception raised while ingesting data"
            )
