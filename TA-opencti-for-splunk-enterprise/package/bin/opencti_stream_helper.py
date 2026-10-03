import json
import logging

import import_declare_test  # noqa: F401  # type: ignore
import splunklib.client as client  # type: ignore
import solnlib.conf_manager as conf_manager  # type: ignore
import solnlib.log as log  # type: ignore
import solnlib.modular_input.checkpointer as checkpointer  # type: ignore
import splunklib.modularinput as smi  # type: ignore

from addon_config import load_settings
from addon_state import DEPLOYMENTS_COLLECTION, KVCollection, KVStoreCache
from constants import (
    INDICATORS_KVSTORE_NAME,
    REPORTS_KVSTORE_NAME,
    MARKINGS_KVSTORE_NAME,
    IDENTITIES_KVSTORE_NAME,
    ADDON_NAME,
)
from deployment_reporter import (
    DeploymentReporter,
    STATUS_DEPLOYED,
    STATUS_EXPIRED,
    STATUS_FAILED,
    removal_status,
)
from filigran_sseclient import SSEClient  # type: ignore
from knowledge_fields import enrichment_graphql_fields, merge_knowledge_fields, provenance_from_extension, pulse_from_extension
from opencti_features import OpenCTIFeatureDetector
from security_platform import SecurityPlatformResolver
from stix2patterns.v21.pattern import Pattern  # type: ignore
import six  # type: ignore
from datetime import datetime, timedelta, timezone
import sys
import utils

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


# Identity subtypes (x_opencti_type or identity_class) → KV store
IDENTITY_KVSTORE_MAP = {
    "organization": IDENTITIES_KVSTORE_NAME
}

# Map entity types → KV store collections.
# For indicators we reuse INDICATORS_KVSTORE_NAME so you can point it at
# either `opencti_indicators` or `opencti_lookup` via constants.py.
ENTITY_KVSTORE_MAP = {
    "indicator": INDICATORS_KVSTORE_NAME,
    "report": REPORTS_KVSTORE_NAME,
    "marking-definition": MARKINGS_KVSTORE_NAME,
}


def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")


def get_account_api_key(session_key: str, account_name: str):
    account_realm = (
        f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/"
        "conf-ta-opencti-for-splunk-enterprise_account"
    )
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=account_realm,
    )

    account_conf_file = cfm.get_conf(
        "ta-opencti-for-splunk-enterprise_account"
    )
    return account_conf_file.get(account_name).get("api_key")


def validate_input(definition):
    return


def exist_in_kvstore(kv_store, key_id):
    try:
        kv_store.query_by_id(key_id)
        return True
    except Exception:
        return False


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
        print(f"[!] STIX pattern parse error: {e} | pattern = {stix_pattern}")
        return None

def enrich_payload(stream_id, input_name, payload, msg_event):
    """
    :param stream_id:
    :param input_name:
    :param payload:
    :param msg_event:
    :return:
    """
    payload["stream_id"] = stream_id
    payload["input_name"] = input_name
    payload["event"] = msg_event

    created_by_id = payload.get("created_by_ref")
    if created_by_id:
        payload["created_by"] = IDENTITY_DEFs.get(created_by_id)

    # Marking definitions -> human-readable markings
    payload["markings"] = []
    for marking_ref_id in payload.get("object_marking_refs", []):
        marking_value = MARKING_DEFs.get(marking_ref_id)
        if marking_value:
            payload["markings"].append(marking_value)

    # --- LABELS ---
    # If labels are already present at top level, keep them.
    # Otherwise, try to extract from extensions before we delete them.
    if "labels" in payload and payload["labels"] is not None:
        # Ensure it's always a list (Splunk MV friendly)
        if not isinstance(payload["labels"], list):
            payload["labels"] = [payload["labels"]]
    else:
        extracted_labels = []
        if "extensions" in payload:
            for ext in payload["extensions"].values():
                # Common patterns you might see from OpenCTI STIX
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
        if extracted_labels:
            payload["labels"] = list(set(extracted_labels))  # de-dup
        else:
            payload["labels"] = []

    parsed_stix = parse_stix_pattern(payload["pattern"])
    if parsed_stix is None:
        return None
    payload["type"] = parsed_stix["type"]
    payload["value"] = parsed_stix["value"]

    # Provenance (and, once carried, Threat Pulse) summaries travel as STIX
    # extensions; keep them before the extensions are dropped.
    knowledge = provenance_from_extension(payload.get("extensions"))
    knowledge.update(pulse_from_extension(payload.get("extensions")))
    payload.update(knowledge)

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
    # Ensure we always have a _key for KV store operations
    if "_key" not in payload and "id" in payload:
        payload["_key"] = payload["id"]
    return payload

def enrich_generic_payload(stream_id, input_name, payload, msg_event):
    """
    :param stream_id:
    :param input_name:
    :param payload:
    :param msg_event:
    :return:
    """
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

    # --- LABELS ---
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
        if extracted_labels:
            payload["labels"] = list(set(extracted_labels))
        else:
            payload["labels"] = []

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

    if "external_references" in payload:
        del payload["external_references"]
    # Ensure we always have a _key for KV store operations
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

def kv_external_id(collection, key):
    """External id of an indicator held in a KV Store collection (deployed-on)."""
    return f"kvstore:{collection}/{key}"


def index_external_id(index, indicator_id):
    """External id of an indicator written as events (deployed-on), stable across its updates."""
    return f"index:{index or 'default'}/{indicator_id}"


def indexed_indicator_kv_keys(indicator):
    """
    :return: the opencti_indicators keys an indicator streamed in index mode
        can have: its STIX id (the "Update OpenCTI Indicators Lookup" searches
        set _key = id) and its OpenCTI internal id (KV Store mode)
    """
    keys = []
    for key in (indicator.get("id"), indicator.get("_key")):
        if key and key not in keys:
            keys.append(key)
    return keys


def report_indicator_state(reporter, event, indicator, external_id, error=None):
    """
    Queue the deployment state of an indicator after a Splunk write.

    :param reporter: DeploymentReporter or None (write-back disabled)
    :param event: stream event (create, update, delete)
    :param indicator: enriched indicator payload
    :param external_id: kv_external_id() or index_external_id()
    :param error: write failure message, if any
    :return: the reported status, or None
    """
    if reporter is None or not indicator:
        return None
    indicator_id = indicator.get("id")
    if not indicator_id:
        return None
    if error:
        status = STATUS_FAILED
        reporter.report(indicator_id, status, external_id, error_message=error)
    elif event == "delete" or utils.get_bool_val(indicator.get("revoked")):
        # A revoked indicator stays as a record but no detection uses it.
        status = removal_status(indicator)
        removed_at = indicator.get("valid_until") if status == STATUS_EXPIRED else None
        reporter.report(indicator_id, status, external_id, removed_at=removed_at)
    else:
        status = STATUS_DEPLOYED
        reporter.report(indicator_id, status, external_id)
    return status


def build_deployment_reporter(settings, client_helper, service, logger):
    """
    :return: (detector, DeploymentReporter or None)
    """
    cache = None
    try:
        cache = KVStoreCache(service)
    except Exception as ex:
        logger.warning(f"Add-on state collection unavailable, caching in memory only: {ex}")
    detector = OpenCTIFeatureDetector(client_helper, logger=logger, cache=cache, ttl=settings.feature_cache_ttl)
    if not settings.deployment_writeback:
        logger.info("Indicator deployment write-back disabled in Configuration > Security Platform")
        return detector, None
    resolver = SecurityPlatformResolver(
        client_helper, detector, settings.platform, server_name=settings.server_name, cache=cache, logger=logger
    )

    def platform_id():
        platform = resolver.resolve()
        return platform.get("id") if platform else None

    def sink(records):
        KVCollection(service, DEPLOYMENTS_COLLECTION).upsert(records)

    reporter = DeploymentReporter(
        client_helper,
        detector,
        platform_id,
        batch_size=settings.writeback_batch_size,
        rate_per_minute=settings.writeback_rate_limit,
        logger=logger,
        state_sink=sink,
        on_platform_missing=resolver.invalidate,
    )
    return detector, reporter


def stream_events(inputs, event_writer):
    # inputs.inputs is a Python dictionary object like:
    # {
    #   "opencti_stream://<input_name>": {
    #     "account": "<account_name>",
    #     "disabled": "0",
    #     "host": "$decideOnStartup",
    #     "index": "<index_name>",
    #     "interval": "<interval_value>",
    #     "python.version": "python3",
    #   },
    # }
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

            settings = load_settings(session_key, logger)
            opencti_url = settings.opencti_url
            opencti_api_key = settings.opencti_api_key
            ssl_verify = settings.ssl_verify

            log.modular_input_start(logger, normalized_input_name)
            logger.info("OpenCTI data input module start")

            input_type = input_item.get("input_type").strip().lower()
            stream_id = input_item.get("stream_id")
            target_index = input_item.get("index")
            import_from = input_item.get("import_from")

            logger.info(f"OpenCTI URL: {opencti_url}")
            logger.info(f"Fetching data from OpenCTI stream.id: {stream_id}")
            logger.info(f"Selected input type: {input_type}")
            logger.info(f"Proxy settings: {utils.redact_proxy_settings(settings.proxy_settings)}")

            user_agent = settings.user_agent
            logger.debug(f"User-Agent: {user_agent}")

            # Create Splunk App Connector Helper
            connector_helper = settings.build_client(
                connector_id="splunk-stream-input",
                connector_name="Splunk Stream Input",
            )

            kvstore_checkpointer = checkpointer.KVStoreCheckpointer(
                ADDON_NAME+"_checkpoints",
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

            service = None
            kvstore_handles = {}

            logger.debug(f"Input Type: {input_type}")
            try:
                logger.debug("Initializing Splunk service for KV Store")

                service = client.connect(
                    token=session_key,
                    app=ADDON_NAME
                )
                logger.info("Connected to Splunk service for KV Store access")
            except Exception as e:
                logger.error(f"Failed to connect to Splunk service: {e}")
                return

            detector, reporter = build_deployment_reporter(settings, connector_helper, service, logger)

            proxies = utils.get_proxy_config(proxy_settings=settings.proxy_settings)
            try:
                messages = SSEClient(
                    live_stream_url,
                    state.get("start_from"),
                    headers={
                        "authorization": f"Bearer {opencti_api_key}",
                        "user-agent": user_agent,
                        "listen-delete": "true",
                        "no-dependencies": "true",
                        "with-inferences": "true",
                    },
                    verify=ssl_verify,
                    proxies=proxies,
                )
                for msg in messages:
                    if reporter is not None:
                        reporter.flush_if_due()
                    if msg.event not in ["create", "update", "delete"]:
                        continue
                    logger.debug(f"Received message ID: {msg.id} | Event: {msg.event}")
                    message_payload = json.loads(msg.data)
                    logger.debug(f"Message payload: {message_payload}")
                    data = message_payload.get("data", {})
                    entity_type = data.get("type")

                    if entity_type == "identity":
                        IDENTITY_DEFs[data["id"]] = data.get("name", "Unknown")
                    elif entity_type == "marking-definition":
                        MARKING_DEFs[data["id"]] = data.get("name", "Unknown")

                    parsed_stix = None
                    if entity_type == "indicator" and data.get("pattern_type") == "stix":
                        parsed_stix = enrich_payload(stream_id, input_name, data, msg.event)
                        if parsed_stix is not None and msg.event != "delete":
                            try:
                                enrich_row = connector_helper.get_indicator_enrichment(
                                    data["id"], extra_fields=enrichment_graphql_fields(detector)
                                )
                                if enrich_row:
                                    parsed_stix["attack_patterns"] = enrich_row.get(
                                        "attack_patterns", []
                                    )
                                    parsed_stix["malware"] = enrich_row.get(
                                        "malware", []
                                    )
                                    parsed_stix["threat_actors"] = enrich_row.get(
                                        "threat_actors", []
                                    )
                                    parsed_stix["vulnerabilities"] = enrich_row.get(
                                        "vulnerabilities", []
                                    )
                                    merge_knowledge_fields(parsed_stix, {}, enrich_row.get("indicator"))
                            except Exception as e:
                                logger.warning(
                                    f"OpenCTI enrichment failed for {data['id']}: {e}"
                                )
                    else:
                        parsed_stix = enrich_generic_payload(stream_id, input_name, data, msg.event)
                    if parsed_stix is None:
                        logger.error(f"Could not enrich data for msg {msg.id}")
                        continue

                    is_indicator = entity_type == "indicator"
                    indicator_value = parsed_stix.get("value") or data.get("value")
                    logger.info(
                        f"[Indicator {parsed_stix.get('_key')}] Processing value={indicator_value} event={msg.event}"
                    )
                    logger.debug(f"{data}")
                    if input_type == "kvstore":
                        # Decide which KV collection to use based on entity_type and x_opencti_type
                        kvstore_name = get_kvstore_name_for_entity(entity_type, parsed_stix)

                        if not kvstore_name:
                            logger.debug(
                                f"No KV store mapping for entity_type={entity_type}, "
                                f"x_opencti_type={parsed_stix.get('x_opencti_type')}"
                            )
                        else:
                            key_id = parsed_stix.get("_key")
                            external_id = kv_external_id(kvstore_name, key_id)
                            try:
                                # Lazily cache the kvstore.data handle per collection
                                if kvstore_name not in kvstore_handles:
                                    kvstore_handles[kvstore_name] = service.kvstore[
                                        kvstore_name
                                    ].data
                                    logger.info(
                                        f"Initialized KV handle for collection: {kvstore_name}"
                                    )

                                kv = kvstore_handles[kvstore_name]

                                if msg.event == "delete":
                                    if key_id and exist_in_kvstore(kv, key_id):
                                        kv.delete_by_id(key_id)
                                        logger.info(
                                            f"KV Store [{kvstore_name}]: Deleted {key_id}"
                                        )
                                else:
                                    parsed_stix["added_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                                    # Upsert into this KV collection
                                    kv.batch_save(*[parsed_stix])
                                    logger.info(
                                        f"KV Store [{kvstore_name}]: Inserted/Updated {key_id}"
                                    )
                                if is_indicator:
                                    report_indicator_state(reporter, msg.event, parsed_stix, external_id)
                            except Exception as kv_ex:
                                logger.error(
                                    f"KV Store operation failed for collection={kvstore_name}: {kv_ex}"
                                )
                                if is_indicator:
                                    report_indicator_state(
                                        reporter, msg.event, parsed_stix, external_id,
                                        error=f"KV Store {kvstore_name} write failed: {kv_ex}",
                                    )
                                continue

                    elif input_type == "index":
                        # If this is an indicator delete event, also purge it from the indicator KV
                        purge_error = None
                        if is_indicator and msg.event == "delete":
                            try:
                                # Lazily init the indicators KV handle via kvstore_handles
                                if INDICATORS_KVSTORE_NAME not in kvstore_handles:
                                    kvstore_handles[INDICATORS_KVSTORE_NAME] = service.kvstore[
                                        INDICATORS_KVSTORE_NAME
                                    ].data
                                    logger.info(
                                        f"Initialized KV handle for collection: {INDICATORS_KVSTORE_NAME}"
                                    )

                                kv_indicators = kvstore_handles[INDICATORS_KVSTORE_NAME]
                                for key_id in indexed_indicator_kv_keys(parsed_stix):
                                    if exist_in_kvstore(kv_indicators, key_id):
                                        kv_indicators.delete_by_id(key_id)
                                        logger.info(
                                            f"KV Store [{INDICATORS_KVSTORE_NAME}]: Deleted {key_id} on delete event"
                                        )
                                    else:
                                        logger.debug(
                                            f"No existing KV entry for {key_id} in [{INDICATORS_KVSTORE_NAME}]"
                                        )
                            except Exception as e:
                                logger.warning(
                                    f"Failed to delete indicator from KV store [{INDICATORS_KVSTORE_NAME}]: {e}"
                                )
                                # Detections still match the KV entry: not removed from Splunk.
                                purge_error = f"KV Store {INDICATORS_KVSTORE_NAME} delete failed: {e}"

                        # Always write the event to the index (create/update/delete)
                        event_time = parsed_stix.get("updated_at")
                        if event_time:
                            try:
                                event_time = datetime.strptime(
                                    event_time, "%Y-%m-%dT%H:%M:%S.%fZ"
                                ).timestamp()
                            except ValueError:
                                logger.warning(
                                    f"Unable to parse updated_at timestamp: {event_time}"
                                )
                                event_time = None

                        external_id = index_external_id(target_index, parsed_stix.get("id"))
                        try:
                            event_obj = smi.Event(  # type: ignore[attr-defined]
                                data=json.dumps(parsed_stix),
                                time=event_time,
                                host=None,
                                index=target_index,
                                source="opencti",
                                sourcetype=f"opencti:{entity_type}",
                                done=True,
                                unbroken=True,
                            )
                            event_writer.write_event(event_obj)
                        except Exception as write_ex:
                            logger.error(f"Index write failed for {parsed_stix.get('id')}: {write_ex}")
                            if is_indicator:
                                report_indicator_state(
                                    reporter, msg.event, parsed_stix, external_id,
                                    error=f"Index {target_index} write failed: {write_ex}",
                                )
                            raise
                        if is_indicator:
                            report_indicator_state(reporter, msg.event, parsed_stix, external_id, error=purge_error)

                    else:
                        logger.warning(f"Unknown input_type: {input_type}")
                        continue

                    state["start_from"] = msg.id
                    kvstore_checkpointer.update(input_name, json.dumps(state))

            except Exception as ex:
                logger.error(f"Error in stream processing loop: {ex}")
                exc_type, exc_value, exc_tb = sys.exc_info()
                if exc_type and exc_value and exc_tb:
                    sys.excepthook(exc_type, exc_value, exc_tb)
            finally:
                if reporter is not None:
                    reporter.flush(force=True)
                    logger.info(f"Deployment write-back statistics: {reporter.stats}")

        except Exception as e:
            log.log_exception(logger, e, "my custom error type", msg_before="Exception raised while ingesting data")
