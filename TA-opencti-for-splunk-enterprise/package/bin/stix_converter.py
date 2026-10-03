import re
import stix2
from datetime import datetime, timezone

from stix_constants import CustomObservableUserAgent, CustomObservableText, CustomObjectCaseIncident
from utils import get_hash_type, is_ipv6, is_ipv4, disambiguate_created, incident_event_key, to_epoch
from utils import generate_incident_id, generate_identity_id, generate_relation_id, generate_case_incident_id, generate_sighting_id
from utils import generate_indicator_id, generate_observed_data_id

# Dispatch time in a Splunk sid: scheduled ("scheduler__<owner>__<app>__<name>_at_<epoch>_<n>", plus
# "_<member GUID>" in a search head cluster; rt_ and ES variants) and ad hoc ("<epoch>.<n>") searches
SCHEDULED_SID_RE = re.compile(r"_at_(\d{9,11})_\d+")
ADHOC_SID_RE = re.compile(r"^(?:rt_)?(\d{9,11})\.\d+")

# Sighting of Type values targeting an Indicator (#57, #67)
SIGHTING_OF_INDICATOR_ID = "indicator_id"
INDICATOR_SIGHTING_TYPES = {
    "url_indicator": "url",
    "domain_indicator": "domain",
    "ipv4_indicator": "ipv4",
    "ipv6_indicator": "ipv6",
    "file_hash_indicator": "file_hash",
    "email_indicator": "email_addr",
}
# Historical "<type> Observable" values sight the matching Indicator: OpenCTI
# rejects a Sighting whose sighting_of_ref is not an SDO (#57)
LEGACY_OBSERVABLE_SIGHTING_TYPES = {
    "url_observable": "url_indicator",
    "domain_observable": "domain_indicator",
    "ipv4_observable": "ipv4_indicator",
    "ipv6_observable": "ipv6_indicator",
    "file_hash_observable": "file_hash_indicator",
}
# observable kind -> (STIX pattern object path, OpenCTI main observable type)
PATTERN_PATHS = {
    "url": ("url:value", "Url"),
    "domain": ("domain-name:value", "Domain-Name"),
    "ipv4": ("ipv4-addr:value", "IPv4-Addr"),
    "ipv6": ("ipv6-addr:value", "IPv6-Addr"),
    "email_addr": ("email-addr:value", "Email-Addr"),
}
HASH_PATTERN_NAMES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}

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
        observables.append({"type": "user_agent", "value": event.get("http_user_agent")})
    if "http_user_agent" in event and event.get("http_user_agent") != "":
        observables.append({"type": "user_agent", "value": event.get("http_user_agent")})
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


def container_id(generate, name, created, event, alert_params, used_ids=None):
    """
    Incident / Case-Incident id of a result (#47).

    Rows without an event identity (transforming searches without an
    incident key) keep the historical name + created id; when several of them
    share it in one alert run, the 2nd, 3rd... get an occurrence suffix so
    they are not merged. Row order of a transforming search is stable between
    runs, so each row keeps upserting onto its own container.

    :param generate: generate_incident_id or generate_case_incident_id
    :param used_ids: dict shared by the results of one alert run, or None
    """
    key = incident_event_key(event, alert_params.get("incident_key"))
    entity_id = generate(name, created, key)
    if key or used_ids is None:
        return entity_id
    occurrence = used_ids.get(entity_id, 0) + 1
    used_ids[entity_id] = occurrence
    if occurrence == 1:
        return entity_id
    return generate(name, created, f"occurrence|{occurrence}")


def convert_to_incident_response(alert_params, event, return_id=False, used_ids=None):
    """
    :param alert_params:
    :param event:
    :param return_id: also return the Case-Incident STIX id
    :param used_ids: see container_id
    :return: serialized bundle, or (bundle, case id) when return_id
    """
    bundle_objects = []

    event_date = _container_date(event, alert_params)

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
        id=container_id(
            generate_case_incident_id, alert_params.get("name"), created_date, event, alert_params, used_ids,
        ),
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
    if return_id:
        return bundle.serialize(), stix_case_incident.id
    return bundle.serialize()


def convert_to_incident(alert_params, event, return_id=False, used_ids=None):
    """
    :param alert_params:
    :param event:
    :param return_id: also return the Incident STIX id
    :param used_ids: see container_id
    :return: serialized bundle, or (bundle, incident id) when return_id
    """
    bundle_objects = []

    event_date = _container_date(event, alert_params)

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
        id=container_id(
            generate_incident_id, alert_params.get("name"), created_date, event, alert_params, used_ids,
        ),
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
    if return_id:
        return bundle.serialize(), stix_incident.id
    return bundle.serialize()


def _event_date(event):
    if "_time" in event and event.get("_time"):
        return datetime.fromtimestamp(float(event.get("_time")), timezone.utc)
    return datetime.now(timezone.utc)


def _container_date(event, alert_params):
    """
    created of an Incident / Case-Incident, which seeds its id: the result
    time, else the time the alert was dispatched read from its sid (the same
    for every retry of that alert run), else now.
    """
    if event.get("_time"):
        return datetime.fromtimestamp(float(event.get("_time")), timezone.utc)
    sid = str(alert_params.get("sid") or "")
    match = SCHEDULED_SID_RE.search(sid) or ADHOC_SID_RE.match(sid)
    if match:
        return datetime.fromtimestamp(int(match.group(1)), timezone.utc)
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


def _where_sighted_identity(where_sighted_type, where_sighted_value):
    """
    :return: the System / Organization identity selected in the action, or
        None when no value is given (the Security Platform alone is used)
    """
    if where_sighted_value is None or not str(where_sighted_value).strip():
        return None
    where_sighted_type = (where_sighted_type or "system").lower()
    if where_sighted_type == "organization":
        return stix2.Identity(
            id=generate_identity_id(str(where_sighted_value), "organization"),
            name=str(where_sighted_value),
            identity_class="organization"
        )
    if where_sighted_type == "system":
        return stix2.Identity(
            id=generate_identity_id(str(where_sighted_value), "system"),
            name=str(where_sighted_value),
            identity_class="system"
        )
    raise ValueError(f"Invalid where_sighted_type: {where_sighted_type}")


def _escape_pattern_value(value):
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def indicator_patterns(kind, value):
    """
    STIX patterns matching a single observable value, the canonical one first.

    :param kind: url, domain, ipv4, ipv6, email_addr or file_hash
    :param value: observable value
    :return: (list of equivalent patterns, OpenCTI main observable type)
    :raise ValueError: on an unsupported kind or unrecognized hash
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("Sighting of Value is empty")
    escaped = _escape_pattern_value(value)
    if kind == "file_hash":
        hash_type = get_hash_type(value)
        if hash_type is None:
            raise ValueError(
                f"Unrecognized hash value: {value!r} "
                "(expected an MD5, SHA-1, SHA-256 or SHA-512 hex digest)"
            )
        name = HASH_PATTERN_NAMES[hash_type]
        quoted = f"[file:hashes.'{name}' = '{escaped}']"
        bare = f"[file:hashes.{name} = '{escaped}']"
        # OpenCTI quotes hash names containing a dash; MD5 is written bare
        patterns = [quoted, bare] if "-" in name else [bare, quoted]
        return patterns, "StixFile"
    if kind not in PATTERN_PATHS:
        raise ValueError(f"Unsupported indicator kind: {kind}")
    path, main_type = PATTERN_PATHS[kind]
    return [f"[{path} = '{escaped}']", f"[{path}='{escaped}']"], main_type


def sighting_indicator_type(sighting_of_type):
    """
    :return: the Indicator Sighting of Type a legacy "<type>_observable"
        value maps to, other values unchanged
    """
    sighting_of_type = sighting_of_type or ""
    return LEGACY_OBSERVABLE_SIGHTING_TYPES.get(sighting_of_type, sighting_of_type)


def pattern_indicator(kind, value):
    """
    :return: indicator dict for convert_to_sighting creating the Indicator of
        this single value, under the id OpenCTI gives its pattern
    :raise ValueError: on an unsupported kind or unrecognized hash
    """
    patterns, main_type = indicator_patterns(kind, value)
    return {
        "id": generate_indicator_id(patterns[0]),
        "create": True,
        "pattern": patterns[0],
        "name": (value or "").strip(),
        "main_observable_type": main_type,
    }


def _legacy_sighted_observable(sighting_of_type, value, marking_id, author):
    """
    :return: the STIX observable a legacy "<type>_observable" mode names
    :raise ValueError: on an unrecognized hash or unsupported type
    """
    observable_type = sighting_of_type.split("_observable")[0]
    value = (value or "").strip()
    if observable_type == "file_hash":
        observable_type = get_hash_type(value)
        if observable_type is None:
            raise ValueError(
                f"Unrecognized hash value: {value!r} "
                "(expected an MD5, SHA-1, SHA-256 or SHA-512 hex digest)"
            )
    stix_observables = _convert_observables_to_stix(
        observables=[{"type": observable_type, "value": value}],
        marking=marking_id,
        creator=author,
    )
    if not stix_observables:
        raise ValueError(f"Unsupported sighting_of_type: {sighting_of_type}")
    return stix_observables[0]


def convert_to_sighting(alert_params, event, platform_ref=None, indicator=None):
    """
    Build a sighting bundle.

    The sighting always targets an Indicator (#57 / #67): the one the action
    resolved (``indicator``), else the Indicator of the value's pattern. A
    legacy "<type> Observable" type sights the Indicator of that value and
    also carries the observable, linked to the Indicator by ``based-on``.
    It is sighted on the Splunk Security Platform (``platform_ref``) and/or on
    the System / Organization selected in the action.

    :param alert_params: action parameters
    :param event: the Splunk result
    :param platform_ref: STIX id of the Splunk Security Platform, or None
    :param indicator: dict with "id" (STIX id of the Indicator), and for an
        indicator to create: "create": True, "pattern", "name", "main_observable_type"
    :return: serialized bundle
    """
    bundle_objects = []
    first_seen, last_seen = _sighting_window(event)
    count = sighting_count(alert_params.get("count"))

    # manage marking
    marking_id = _get_stix_marking_id(alert_params.get("tlp"))
    bundle_objects.append(marking_id)

    # manage author
    stix_author = _author(event)
    bundle_objects.append(stix_author)

    where_sighted_refs = []
    if platform_ref:
        where_sighted_refs.append(platform_ref)
    where_sighted = _where_sighted_identity(
        alert_params.get("where_sighted_type"), alert_params.get("where_sighted_value")
    )
    if where_sighted is not None:
        bundle_objects.append(where_sighted)
        where_sighted_refs.append(where_sighted.id)
    if not where_sighted_refs:
        raise ValueError(
            "Nothing to sight on: set Where Sighted, or configure the Splunk Security Platform "
            "(Configuration > Security Platform) on an OpenCTI platform that supports it"
        )

    requested_type = alert_params.get("sighting_of_type") or ""
    sighting_of_type = sighting_indicator_type(requested_type)
    sighting_of_value = alert_params.get("sighting_of_value")
    labels = alert_params.get("labels")

    legacy_observable = None
    if requested_type in LEGACY_OBSERVABLE_SIGHTING_TYPES:
        legacy_observable = _legacy_sighted_observable(requested_type, sighting_of_value, marking_id, stix_author)
    if indicator is None and sighting_of_type in INDICATOR_SIGHTING_TYPES:
        indicator = pattern_indicator(INDICATOR_SIGHTING_TYPES[sighting_of_type], sighting_of_value)

    if indicator is not None:
        indicator_id = indicator["id"]
        if indicator.get("create"):
            bundle_objects.append(stix2.Indicator(
                id=indicator_id,
                name=indicator.get("name") or str(sighting_of_value),
                pattern=indicator["pattern"],
                pattern_type="stix",
                valid_from=first_seen,
                created_by_ref=stix_author.id,
                object_marking_refs=[marking_id],
                labels=labels or None,
                allow_custom=True,
                custom_properties={
                    "x_opencti_main_observable_type": indicator.get("main_observable_type"),
                },
            ))
        sighting = stix2.Sighting(
            id=generate_sighting_id(indicator_id, sorted(where_sighted_refs), first_seen, last_seen),
            created_by_ref=stix_author.id,
            sighting_of_ref=indicator_id,
            first_seen=first_seen,
            last_seen=last_seen,
            count=count,
            where_sighted_refs=where_sighted_refs,
            object_marking_refs=[marking_id],
            labels=labels or None,
        )
        bundle_objects.append(sighting)
        if legacy_observable is not None:
            bundle_objects.append(legacy_observable)
            bundle_objects.append(stix2.Relationship(
                id=generate_relation_id("based-on", indicator_id, legacy_observable.id),
                relationship_type="based-on",
                source_ref=indicator_id,
                target_ref=legacy_observable.id,
                created_by_ref=stix_author.id,
                object_marking_refs=[marking_id],
            ))
    else:
        raise ValueError(f"Unsupported sighting_of_type: {sighting_of_type}")

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
