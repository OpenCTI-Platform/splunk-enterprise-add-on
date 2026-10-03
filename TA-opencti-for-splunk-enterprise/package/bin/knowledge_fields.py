"""Provenance and Threat Pulse fields stored with the indicators in Splunk.

Provenance (OpenCTI innovation 06) travels in the stream payload through the
``extension-definition--283daa2f-...`` extension (counts, dates and flags,
never source names) and is also readable through GraphQL, where the source
names the account may see are available. Threat Pulse (innovation 04) is
only readable through GraphQL today. Every field is optional: on platforms
without these features the fields are simply absent.

Threat Pulse has a preview mode (the default of a platform registered with
XTM Hub that does not contribute): only the coarse prevalence and trend are
set, flagged ``pulse_preview``, and the network fields stay absent.
"""

from opencti_features import FEATURE_PROVENANCE, FEATURE_PULSE
from utils import to_iso

PROVENANCE_EXTENSION_ID = "extension-definition--283daa2f-7739-5345-a110-19d73676f670"

PROVENANCE_FIELDS = (
    "corroboration_count",
    "assertions_count",
    "first_asserted_at",
    "last_asserted_at",
    "single_sourced",
    "has_conflicts",
    "freshness_stale",
    "sources",
    "sources_by_kind",
)
PULSE_FIELDS = (
    "pulse_prevalence",
    "pulse_trend",
    "pulse_first_seen_network",
    "pulse_platforms_bucket",
    "pulse_preview",
)
KNOWLEDGE_FIELDS = PROVENANCE_FIELDS + PULSE_FIELDS
# Provenance fields read from the Indicator itself, not from its assertions
PROVENANCE_GRAPHQL_OWNED = (
    "corroboration_count",
    "last_asserted_at",
    "single_sourced",
    "has_conflicts",
    "freshness_stale",
    "sources",
)

# Bounded: a sources summary is a label, not the assertion list.
MAX_SOURCE_NAMES = 20

PROVENANCE_GRAPHQL_FIELDS = (
    "corroboration_count last_asserted_at single_sourced has_conflicts freshness_stale "
    "x_opencti_assertions { source_name source_kind first_asserted_at }"
)
# PulseInformation fields the add-on reads, selected when the schema has them
PULSE_SELECTABLE = ("preview", "prevalence", "prevalence_bucket", "trend", "first_seen_network", "platforms_bucket")
# Selection used when the detection did not list the PulseInformation fields
PULSE_LEGACY_SELECTION = ("prevalence", "trend", "first_seen_network", "platforms_bucket")


def _kinds_summary(sources_by_kind):
    if not isinstance(sources_by_kind, dict):
        return ""
    parts = [f"{kind}={count}" for kind, count in sorted(sources_by_kind.items()) if count]
    return ",".join(parts)


def provenance_from_extension(extensions):
    """
    :param extensions: the "extensions" member of a STIX object
    :return: dict of provenance fields (empty when the extension is absent)
    """
    if not isinstance(extensions, dict):
        return {}
    extension = extensions.get(PROVENANCE_EXTENSION_ID)
    if not isinstance(extension, dict) or "corroboration_count" not in extension:
        return {}
    fields = {
        "corroboration_count": int(extension.get("corroboration_count") or 0),
        "assertions_count": int(extension.get("assertions_count") or 0),
        "single_sourced": bool(extension.get("single_sourced")),
        "has_conflicts": bool(extension.get("has_conflicts")),
        "freshness_stale": bool(extension.get("freshness_stale")),
        "sources_by_kind": _kinds_summary(extension.get("sources_by_kind")),
    }
    first = to_iso(extension.get("first_asserted"))
    last = to_iso(extension.get("last_asserted"))
    if first:
        fields["first_asserted_at"] = first
    if last:
        fields["last_asserted_at"] = last
    return fields


def pulse_from_extension(extensions):
    """
    Forward compatible reader of a Threat Pulse summary extension
    (requested on OpenCTI-Platform/opencti#18674): any property extension
    carrying ``prevalence`` and ``trend``.

    :return: dict of pulse fields (empty when absent)
    """
    if not isinstance(extensions, dict):
        return {}
    for extension in extensions.values():
        if not isinstance(extension, dict) or "trend" not in extension:
            continue
        if "prevalence" in extension or "prevalence_bucket" in extension:
            return pulse_from_graphql(extension)
    return {}


def provenance_from_graphql(indicator):
    """
    :param indicator: Indicator node selected with PROVENANCE_GRAPHQL_FIELDS
    :return: dict of provenance fields (empty when the platform has none)
    """
    if not isinstance(indicator, dict) or indicator.get("corroboration_count") is None:
        return {}
    fields = {
        "corroboration_count": int(indicator.get("corroboration_count") or 0),
        "single_sourced": bool(indicator.get("single_sourced")),
        "has_conflicts": bool(indicator.get("has_conflicts")),
        "freshness_stale": bool(indicator.get("freshness_stale")),
    }
    last = to_iso(indicator.get("last_asserted_at"))
    if last:
        fields["last_asserted_at"] = last
    assertions = [a for a in (indicator.get("x_opencti_assertions") or []) if isinstance(a, dict)]
    if assertions:
        fields["assertions_count"] = len(assertions)
        names = sorted({str(a.get("source_name")).strip() for a in assertions if a.get("source_name")})
        if names:
            fields["sources"] = ", ".join(names[:MAX_SOURCE_NAMES]) + (
                f" (+{len(names) - MAX_SOURCE_NAMES})" if len(names) > MAX_SOURCE_NAMES else ""
            )
        kinds = {}
        for assertion in assertions:
            kind = assertion.get("source_kind") or "unknown"
            kinds[kind] = kinds.get(kind, 0) + 1
        fields["sources_by_kind"] = _kinds_summary(kinds)
        firsts = [to_iso(a.get("first_asserted_at")) for a in assertions if a.get("first_asserted_at")]
        if firsts:
            fields["first_asserted_at"] = min(firsts)
    return fields


def pulse_from_graphql(pulse_or_indicator):
    """
    :param pulse_or_indicator: PulseInformation node, or an Indicator node
        selected with pulse_graphql_fields
    :return: dict of pulse fields (empty when the platform has none)
    """
    if not isinstance(pulse_or_indicator, dict):
        return {}
    pulse = pulse_or_indicator.get("pulse") if "pulse" in pulse_or_indicator else pulse_or_indicator
    if not isinstance(pulse, dict):
        return {}
    fields = {}
    prevalence = pulse.get("prevalence") or pulse.get("prevalence_bucket")
    if prevalence:
        fields["pulse_prevalence"] = str(prevalence)
    if pulse.get("trend"):
        fields["pulse_trend"] = str(pulse["trend"])
    first_seen = to_iso(pulse.get("first_seen_network"))
    if first_seen:
        fields["pulse_first_seen_network"] = first_seen
    if pulse.get("platforms_bucket"):
        fields["pulse_platforms_bucket"] = str(pulse["platforms_bucket"])
    if fields and pulse.get("preview") is not None:
        fields["pulse_preview"] = bool(pulse["preview"])
    return fields


def pulse_graphql_fields(detector):
    """
    :param detector: OpenCTIFeatureDetector of a platform with FEATURE_PULSE
    :return: the Indicator ``pulse`` selection for this platform ("" when it
        exposes none of the fields the add-on reads)
    """
    available = detector.pulse_fields()
    selected = PULSE_LEGACY_SELECTION if available is None else [f for f in PULSE_SELECTABLE if f in available]
    return f"pulse {{ {' '.join(selected)} }}" if selected else ""


def enrichment_graphql_fields(detector):
    """
    :param detector: OpenCTIFeatureDetector
    :return: Indicator fields to add to the enrichment query for this platform
    """
    fields = []
    if detector is not None and detector.has(FEATURE_PROVENANCE):
        fields.append(PROVENANCE_GRAPHQL_FIELDS)
    if detector is not None and detector.has(FEATURE_PULSE):
        fields.append(pulse_graphql_fields(detector))
    return " ".join(field for field in fields if field)


def merge_knowledge_fields(payload, extension_fields, indicator_node, overwrite=False):
    """
    Set the knowledge fields on ``payload``: the stream extension first,
    GraphQL values filling (and, for source names, refining) the rest.

    :param payload: KV / index record (mutated)
    :param extension_fields: dict from provenance_from_extension / pulse_from_extension
    :param indicator_node: enrichment Indicator node, or None
    :param overwrite: GraphQL values replace the existing ones (periodic refresh)
    :return: payload
    """
    for key, value in (extension_fields or {}).items():
        payload[key] = value
    for key, value in provenance_from_graphql(indicator_node).items():
        if overwrite or key == "sources" or key not in payload:
            payload[key] = value
    for key, value in pulse_from_graphql(indicator_node or {}).items():
        payload[key] = value
    return payload


def refresh_knowledge_fields(record, indicator_node, provenance=True, pulse=True):
    """
    Periodic refresh: GraphQL is authoritative for the features it was
    queried for, so values OpenCTI no longer holds are cleared. Fields only
    the assertion list can give are kept when the account sees no assertion.

    :param record: KV record (mutated)
    :param indicator_node: Indicator node selected with enrichment_graphql_fields
    :param provenance: the provenance fields were queried
    :param pulse: the pulse fields were queried
    :return: record
    """
    if provenance:
        fields = provenance_from_graphql(indicator_node)
        owned = PROVENANCE_FIELDS if not fields or "assertions_count" in fields else PROVENANCE_GRAPHQL_OWNED
        for key in owned:
            record.pop(key, None)
        record.update(fields)
    if pulse:
        for key in PULSE_FIELDS:
            record.pop(key, None)
        record.update(pulse_from_graphql(indicator_node or {}))
    return record
