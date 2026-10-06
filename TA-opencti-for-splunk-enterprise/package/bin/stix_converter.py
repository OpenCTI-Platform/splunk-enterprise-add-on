import re

import stix2
from datetime import datetime, timezone

from stix_constants import CustomObservableUserAgent, CustomObservableText, CustomObjectCaseIncident
from utils import get_hash_type, is_ipv6, is_ipv4, disambiguate_created, to_epoch
from utils import generate_incident_id, generate_identity_id, generate_relation_id, generate_case_incident_id, generate_sighting_id
from utils import generate_observed_data_id

FAKE_INDICATOR_ID = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac8"

# "query" is a generic field name outside the CIM: only a host name makes a Domain observable.
# Labels start and end with a letter or digit (a leading underscore is allowed, as in _dmarc);
# the top-level label has 2 to 63 characters and is not all digits.
DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?![0-9]+$)[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]$"
)

# TLP:AMBER+STRICT is not a stix2 built-in; the ID is OpenCTI's static one
# (pycti MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"))
TLP_AMBER_STRICT = stix2.MarkingDefinition(
    id="marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="TLP",
    x_opencti_definition="TLP:AMBER+STRICT",
)


def _get_stix_marking_id(value):
    if value == "tlp_clear":
        return stix2.TLP_WHITE
    if value == "tlp_green":
        return stix2.TLP_GREEN
    if value == "tlp_amber":
        return stix2.TLP_AMBER
    if value == "tlp_amber_strict":
        return TLP_AMBER_STRICT
    if value == "tlp_red":
        return stix2.TLP_RED
    raise ValueError(
        f"Invalid TLP value: {value!r} "
        "(expected tlp_clear, tlp_green, tlp_amber, tlp_amber_strict or tlp_red)"
    )


def _extract_observables_from_cim_model(event, marking, creator):
    """
    :param event:
    :param marking:
    :param creator:
    :return:
    """
    observables = []
    if "url" in event and event.get("url") != "":
        observables.append({"type": "url", "value": event.get("url")})
    if "url_domain" in event and event.get("url_domain") != "":
        observables.append({"type": "domain", "value": event.get("url_domain")})
    if "user" in event and event.get("user") != "unknown" and event.get("user") != "":
        observables.append({"type": "user_account", "value": event.get("user")})
    if "user_name" in event and event.get("user_name") != "unknown" and event.get("user_name") != "":
        observables.append({"type": "user_account", "value": event.get("user_name")})
    if "user_agent" in event and event.get("user_agent") != "":
        observables.append({"type": "user_agent", "value": event.get("user_agent")})
    if "http_user_agent" in event and event.get("http_user_agent") != "":
        observables.append({"type": "user_agent", "value": event.get("http_user_agent")})
    if "query" in event and event.get("query") != "":
        # Network_Resolution.DNS: the name or address looked up
        query = str(event.get("query")).strip().rstrip(".")
        if is_ipv4(query):
            observables.append({"type": "ipv4", "value": query})
        elif is_ipv6(query):
            observables.append({"type": "ipv6", "value": query})
        elif DNS_NAME.match(query):
            observables.append({"type": "domain", "value": query})
    if "dest" in event and event.get("dest") != "":
        if is_ipv4(event.get("dest")):
            observables.append({"type": "ipv4", "value": event.get("dest")})
        elif is_ipv6(event.get("dest")):
            observables.append({"type": "ipv6", "value": event.get("dest")})
        else:
            observables.append({"type": "hostname", "value": event.get("dest")})
    if "dest_ip" in event and event.get("dest_ip") != "":
        if is_ipv4(event.get("dest_ip")):
            observables.append({"type": "ipv4", "value": event.get("dest_ip")})
        if is_ipv6(event.get("dest_ip")):
            observables.append({"type": "ipv6", "value": event.get("dest_ip")})
    if "src" in event and event.get("src") != "":
        if is_ipv4(event.get("src")):
            observables.append({"type": "ipv4", "value": event.get("src")})
        elif is_ipv6(event.get("src")):
            observables.append({"type": "ipv6", "value": event.get("src")})
        else:
            observables.append({"type": "hostname", "value": event.get("src")})
    if "src_ip" in event and event.get("src_ip") != "":
        if is_ipv4(event.get("src_ip")):
            observables.append({"type": "ipv4", "value": event.get("src_ip")})
        if is_ipv6(event.get("src_ip")):
            observables.append({"type": "ipv6", "value": event.get("src_ip")})
    if "file_hash" in event and event.get("file_hash") != "":
        file_hash = event.get("file_hash").strip()
        hash_type = get_hash_type(file_hash)
        if hash_type:
            observables.append({"type": hash_type, "value": file_hash})
    if "file_name" in event and event.get("file_name") != "":
        observables.append({"type": "file_name", "value": event.get("file_name")})

    return _convert_observables_to_stix(observables, marking, creator)


def _extract_observables_from_key_model(event, marking, creator):
    """
    :param event:
    :param marking:
    :param creator:
    :return:
    """
    observables = []
    prefix = "octi"
    # print the keys and values
    for field in event:
        if field.startswith(prefix):
            for key in ["ip", "url", "domain", "hash", "email_addr",
                        "user_agent", "mutex", "text", "windows_registry_key",
                        "windows_registry_value_type", "directory", "email_message",
                        "file_name", "mac_addr", "user_account"]:
                if field == prefix + "_" + key:
                    if key == "hash":
                        hash_type = get_hash_type(event[field])
                        if hash_type:
                            observables.append({"type": hash_type, "value": event[field]})
                    elif key == "ip":
                        ipv4 = is_ipv4(event[field])
                        if ipv4:
                            observables.append({"type": "ipv4", "value": event[field]})
                        ipv6 = is_ipv6(event[field])
                        if ipv6:
                            observables.append({"type": "ipv6", "value": event[field]})
                    else:
                        observables.append({"type": key, "value": event[field]})
    return _convert_observables_to_stix(observables, marking, creator)


def _convert_observables_to_stix(observables, marking, creator):
    """
    :param observables:
    :param marking:
    :param creator:
    :return:
    """
    stix_observables = []
    customer_properties = {
        "created_by_ref": creator["id"]
    }

    for observable in observables:
        if observable.get("type") == "ipv4":
            stix_observable = stix2.IPv4Address(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "ipv6":
            stix_observable = stix2.IPv6Address(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "url":
            stix_observable = stix2.URL(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "domain":
            stix_observable = stix2.DomainName(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "md5":
            stix_observable = stix2.File(
                hashes={"MD5": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "sha1":
            stix_observable = stix2.File(
                hashes={"SHA-1": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "sha256":
            stix_observable = stix2.File(
                hashes={"SHA-256": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "sha512":
            stix_observable = stix2.File(
                hashes={"SHA-512": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "file_name":
            stix_observable = stix2.File(
                name=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "email_addr":
            stix_observable = stix2.EmailAddress(
                type="email-addr",
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "user_agent":
            stix_observable = CustomObservableUserAgent(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "mutex":
            stix_observable = stix2.Mutex(
                type="mutex",
                name=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "text":
            stix_observable = CustomObservableText(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "windows_registry_key":
            stix_observable = stix2.WindowsRegistryKey(
                key=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "windows_registry_value_type":
            stix_observable = stix2.WindowsRegistryValueType(
                data=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "directory":
            stix_observable = stix2.Directory(
                path=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "email_message":
            stix_observable = stix2.EmailMessage(
                subject=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "mac_addr":
            stix_observable = stix2.MACAddress(
                subject=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "user_account":
            stix_observable = stix2.UserAccount(
                account_login=observable.get("value"),
                display_name=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
    return stix_observables


def convert_to_incident_response(alert_params, event):
    """
    :param alert_params:
    :param event:
    :return:
    """
    bundle_objects = []

    # event date
    if "_time" in event and event.get("_time"):
        event_date = datetime.fromtimestamp(float(event.get("_time")), timezone.utc)
    else:
        event_date = datetime.now(timezone.utc)

    # created: disambiguated so same-second results don't share an ID (#50)
    created_date = disambiguate_created(event_date, event)

    # manage marking
    marking = alert_params.get("tlp")
    marking_id = _get_stix_marking_id(marking)
    bundle_objects.append(marking_id)

    # manage author
    stix_author = stix2.Identity(
        id=generate_identity_id(event.get("host", "Splunk"), "system"),
        name=event.get("host", "Splunk"),
        identity_class="system"
    )
    bundle_objects.append(stix_author)

    # observables extraction
    observable_ref_ids = []
    if alert_params.get("observables_extraction") == "cim_model":
        observables = _extract_observables_from_cim_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)
    if alert_params.get("observables_extraction") == "field_mapping":
        observables = _extract_observables_from_key_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)

    # create incident response case
    stix_case_incident = CustomObjectCaseIncident(
        id=generate_case_incident_id(alert_params.get("name"), created_date),
        name=alert_params.get("name"),
        description=alert_params.get("description"),
        severity=alert_params.get("severity"),
        priority=alert_params.get("priority"),
        labels=alert_params.get("labels"),
        created=created_date,
        external_references=[],
        created_by_ref=stix_author.id,
        object_marking_refs=[marking_id],
        object_refs=observable_ref_ids
    )
    bundle_objects.append(stix_case_incident)

    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize()


def convert_to_incident(alert_params, event):
    """
    :param alert_params:
    :param event:
    :return:
    """
    bundle_objects = []

    # event date
    if "_time" in event and event.get("_time"):
        event_date = datetime.fromtimestamp(float(event.get("_time")), timezone.utc)
    else:
        event_date = datetime.now(timezone.utc)

    # created: disambiguated so same-second results don't share an ID (#50)
    created_date = disambiguate_created(event_date, event)

    # manage marking
    marking = alert_params.get("tlp")
    marking_id = _get_stix_marking_id(marking)
    bundle_objects.append(marking_id)

    # manage author
    stix_author = stix2.Identity(
        id=generate_identity_id(event.get("host", "Splunk"), "system"),
        name=event.get("host", "Splunk"),
        identity_class="system"
    )
    bundle_objects.append(stix_author)

    # observables extraction
    observable_ref_ids = []
    if alert_params.get("observables_extraction") == "cim_model":
        observables = _extract_observables_from_cim_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)
    if alert_params.get("observables_extraction") == "field_mapping":
        observables = _extract_observables_from_key_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)

    # create incident
    stix_incident = stix2.Incident(
        id=generate_incident_id(alert_params.get("name"), created_date),
        name=alert_params.get("name"),
        created=created_date,
        description=alert_params.get("description"),
        object_marking_refs=[marking_id],
        created_by_ref=stix_author.id,
        external_references=[],
        labels=alert_params.get("labels"),
        allow_custom=True,
        custom_properties={
            "source": event.get("host", "Splunk"),
            "severity": alert_params.get("severity"),
            "incident_type": alert_params.get("type"),
            "first_seen": event_date
        }
    )
    bundle_objects.append(stix_incident)

    for observable_id in observable_ref_ids:
        stix_relation_account = stix2.Relationship(
            id=generate_relation_id(
                "related-to", observable_id, stix_incident.id),
            relationship_type="related-to",
            source_ref=observable_id,
            target_ref=stix_incident.id,
            created_by_ref=stix_author.id)
        bundle_objects.append(stix_relation_account)

    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize()


def _event_date(event):
    if "_time" in event and event.get("_time"):
        return datetime.fromtimestamp(float(event.get("_time")), timezone.utc)
    return datetime.now(timezone.utc)


def _optional_date(value):
    """
    :param value: epoch (number or numeric string) or ISO 8601 string
    :return: aware datetime, or None
    """
    epoch = to_epoch(value)
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc)


def _sighting_window(event):
    """first_seen / last_seen of a sighting: the result's first_seen / last_seen
    fields (for example from `stats min(_time) max(_time)`), else _time."""
    event_date = _event_date(event)
    first_seen = _optional_date(event.get("first_seen")) or event_date
    last_seen = _optional_date(event.get("last_seen")) or event_date
    if last_seen < first_seen:
        first_seen, last_seen = last_seen, first_seen
    return first_seen, last_seen


def sighting_count(value):
    try:
        return max(1, int(float(str(value).strip())))
    except (TypeError, ValueError):
        return 1


def _author(event):
    return stix2.Identity(
        id=generate_identity_id(event.get("host", "Splunk"), "system"),
        name=event.get("host", "Splunk"),
        identity_class="system"
    )


def convert_to_sighting(alert_params, event):
    """
    :param alert_params:
    :param event:
    :return:
    """
    bundle_objects = []

    # event date
    if "_time" in event and event.get("_time"):
        event_date = datetime.fromtimestamp(float(event.get("_time")), timezone.utc)
    else:
        event_date = datetime.now(timezone.utc)

    # manage marking
    marking = alert_params.get("tlp")
    marking_id = _get_stix_marking_id(marking)
    bundle_objects.append(marking_id)

    # manage author
    stix_author = stix2.Identity(
        id=generate_identity_id(event.get("host", "Splunk"), "system"),
        name=event.get("host", "Splunk"),
        identity_class="system"
    )
    bundle_objects.append(stix_author)

    sighting_of_value=alert_params.get("sighting_of_value")
    sighting_of_type=alert_params.get("sighting_of_type")
    where_sighted_value=alert_params.get("where_sighted_value")
    where_sighted_type=alert_params.get("where_sighted_type")

    if where_sighted_type.lower() == "organization":
        where_sighted = stix2.Identity(
            id=generate_identity_id(str(where_sighted_value), "organization"),
            name=str(where_sighted_value),
            identity_class="organization"
        )
    elif where_sighted_type.lower() == "system":
        where_sighted = stix2.Identity(
            id=generate_identity_id(str(where_sighted_value), "system"),
            name=str(where_sighted_value),
            identity_class="system"
        )
    else:
        raise Exception(f"Invalid where_sighted_type: {where_sighted_type}")

    bundle_objects.append(where_sighted)

    # sighting_of conversion
    if "_observable" in sighting_of_type:
        observable_type = sighting_of_type.split("_observable")[0]

        # file hash: algorithm is auto-detected from the digest length
        if observable_type == "file_hash":
            sighting_of_value = (sighting_of_value or "").strip()
            observable_type = get_hash_type(sighting_of_value)
            if observable_type is None:
                raise ValueError(
                    f"Unrecognized hash value: {sighting_of_value!r} "
                    "(expected an MD5, SHA-1, SHA-256 or SHA-512 hex digest)"
                )

        obs = {
            "type": observable_type,
            "value": sighting_of_value
        }

        stix_observables = _convert_observables_to_stix(
            observables=[obs],
            marking=marking_id,
            creator=stix_author
        )
        if not stix_observables:
            raise ValueError(f"Unsupported sighting_of_type: {sighting_of_type}")
        stix_observable = stix_observables[0]
        bundle_objects.append(stix_observable)

        sighting = stix2.Sighting(
            id=generate_sighting_id(
                stix_observable["id"],
                where_sighted["id"],
                #event_date,
                #event_date,
            ),
            created_by_ref=stix_author.id,
            description=None,
            sighting_of_ref=FAKE_INDICATOR_ID,
            first_seen=event_date,
            last_seen=event_date,
            where_sighted_refs=[where_sighted],
            #count=1,
            object_marking_refs=[marking_id],
            labels=alert_params.get("labels"),
            custom_properties={
                "x_opencti_sighting_of_ref": stix_observable["id"],
            },
        )

        bundle_objects.append(sighting)

    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize()


def _hunt_observables(alert_params, event, marking_id, author):
    extraction = alert_params.get("observables_extraction") or "cim_model"
    if extraction == "cim_model":
        return _extract_observables_from_cim_model(event=event, marking=marking_id, creator=author)
    if extraction == "field_mapping":
        return _extract_observables_from_key_model(event=event, marking=marking_id, creator=author)
    return []


def convert_to_hunt_evidence(alert_params, event, hunt_run_id, platform_ref=None, targets=None):
    """
    Evidence of a hunt run found by a Splunk search.

    - Observed-Data over the observables extracted from the result (CIM or
      field mapping), number_observed = count;
    - one sighting per hunt target (Indicators, Attack Patterns, threats of
      the hunt) on the Splunk Security Platform.
    Every object carries x_opencti_hunt_run_id.

    :param alert_params: action parameters (tlp, labels, observables_extraction, count)
    :param event: the Splunk result
    :param hunt_run_id: id of the OpenCTI hunt run
    :param platform_ref: STIX id of the Splunk Security Platform, or None
    :param targets: STIX ids of the hunt targets (may be empty)
    :return: (serialized bundle, list of STIX ids of the evidence objects)
    :raise ValueError: when the result holds no evidence at all
    """
    if not hunt_run_id or not str(hunt_run_id).strip():
        raise ValueError("Hunt run id is empty: pass it with the hunt_run_id token ($result.hunt_run_id$)")
    hunt_run_id = str(hunt_run_id).strip()
    first_seen, last_seen = _sighting_window(event)
    count = sighting_count(alert_params.get("count"))
    labels = alert_params.get("labels") or None
    search_name = alert_params.get("search_name") or "Splunk search"
    description = f"Evidence of OpenCTI hunt run {hunt_run_id} found by the Splunk search '{search_name}'"

    marking_id = _get_stix_marking_id(alert_params.get("tlp"))
    author = _author(event)
    bundle_objects = [marking_id, author]
    hunt_properties = {"x_opencti_hunt_run_id": hunt_run_id}
    result_ids = []

    observables = _hunt_observables(alert_params, event, marking_id, author)
    bundle_objects.extend(observables)
    if observables:
        object_ids = sorted({observable.id for observable in observables})
        observed_data = stix2.ObservedData(
            id=generate_observed_data_id(object_ids),
            created_by_ref=author.id,
            first_observed=first_seen,
            last_observed=last_seen,
            number_observed=count,
            object_refs=object_ids,
            object_marking_refs=[marking_id],
            labels=labels,
            allow_custom=True,
            custom_properties=dict(hunt_properties, x_opencti_description=description),
        )
        bundle_objects.append(observed_data)
        result_ids.append(observed_data.id)

    where_sighted_refs = [platform_ref] if platform_ref else [author.id]
    for target in sorted(set(targets or [])):
        sighting = stix2.Sighting(
            id=generate_sighting_id(target, sorted(where_sighted_refs), first_seen, last_seen),
            created_by_ref=author.id,
            description=description,
            sighting_of_ref=target,
            first_seen=first_seen,
            last_seen=last_seen,
            count=count,
            where_sighted_refs=where_sighted_refs,
            object_marking_refs=[marking_id],
            labels=labels,
            allow_custom=True,
            custom_properties=hunt_properties,
        )
        bundle_objects.append(sighting)
        result_ids.append(sighting.id)

    if not result_ids:
        raise ValueError(
            "No evidence in this result: no observable could be extracted and the hunt has no target"
        )
    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize(), result_ids
