"""Tests for the provenance and Threat Pulse fields (WS-E, #68)."""
import unittest

from program_fakes import FakeDetector

from knowledge_fields import (
    KNOWLEDGE_FIELDS,
    PROVENANCE_EXTENSION_ID,
    enrichment_graphql_fields,
    merge_knowledge_fields,
    provenance_from_extension,
    provenance_from_graphql,
    pulse_from_extension,
    pulse_from_graphql,
)
from opencti_features import FEATURE_PROVENANCE, FEATURE_PULSE

EXTENSION = {
    "extension_type": "property-extension",
    "corroboration_count": 3,
    "assertions_count": 7,
    "first_asserted": "2026-09-01T10:00:00.000Z",
    "last_asserted": "2026-10-02T08:30:00.000Z",
    "single_sourced": False,
    "has_conflicts": True,
    "conflicting_fields": ["description"],
    "freshness_stale": False,
    "sources_by_kind": {"connector": 2, "feed": 1, "user": 0},
}

NODE = {
    "corroboration_count": 2,
    "last_asserted_at": "2026-10-02T08:30:00.000Z",
    "single_sourced": False,
    "has_conflicts": False,
    "freshness_stale": True,
    "x_opencti_assertions": [
        {"source_name": "AlienVault", "source_kind": "feed", "first_asserted_at": "2026-09-03T00:00:00Z"},
        {"source_name": "MISP", "source_kind": "connector", "first_asserted_at": "2026-09-01T00:00:00Z"},
    ],
    "pulse": {"prevalence": "common", "trend": "rising", "first_seen_network": "2026-08-15T00:00:00Z", "platforms_bucket": "10-50"},
}


class ExtensionTest(unittest.TestCase):
    def test_provenance_extension(self):
        fields = provenance_from_extension({PROVENANCE_EXTENSION_ID: EXTENSION})
        self.assertEqual(fields["corroboration_count"], 3)
        self.assertEqual(fields["assertions_count"], 7)
        self.assertEqual(fields["last_asserted_at"], "2026-10-02T08:30:00.000Z")
        self.assertEqual(fields["first_asserted_at"], "2026-09-01T10:00:00.000Z")
        self.assertFalse(fields["single_sourced"])
        self.assertTrue(fields["has_conflicts"])
        self.assertEqual(fields["sources_by_kind"], "connector=2,feed=1")
        self.assertNotIn("sources", fields, "the stream extension never carries source names")

    def test_absent_on_older_platforms(self):
        self.assertEqual(provenance_from_extension({"extension-definition--ea279b3e": {"score": 50}}), {})
        self.assertEqual(provenance_from_extension(None), {})
        self.assertEqual(pulse_from_extension({}), {})

    def test_forward_compatible_pulse_extension(self):
        fields = pulse_from_extension({"extension-definition--opencti-pulse": {"prevalence": "rare", "trend": "stable"}})
        self.assertEqual(fields, {"pulse_prevalence": "rare", "pulse_trend": "stable"})


class GraphQLTest(unittest.TestCase):
    def test_provenance_with_source_names(self):
        fields = provenance_from_graphql(NODE)
        self.assertEqual(fields["sources"], "AlienVault, MISP")
        self.assertEqual(fields["sources_by_kind"], "connector=1,feed=1")
        self.assertEqual(fields["first_asserted_at"], "2026-09-01T00:00:00.000Z")
        self.assertTrue(fields["freshness_stale"])

    def test_pulse(self):
        self.assertEqual(pulse_from_graphql(NODE), {
            "pulse_prevalence": "common",
            "pulse_trend": "rising",
            "pulse_first_seen_network": "2026-08-15T00:00:00.000Z",
            "pulse_platforms_bucket": "10-50",
        })
        self.assertEqual(pulse_from_graphql({"pulse": None}), {})
        self.assertEqual(pulse_from_graphql({"id": "x"}), {})

    def test_enrichment_fields_follow_the_features(self):
        self.assertEqual(enrichment_graphql_fields(FakeDetector()), "")
        both = enrichment_graphql_fields(FakeDetector((FEATURE_PROVENANCE, FEATURE_PULSE)))
        self.assertIn("corroboration_count", both)
        self.assertIn("pulse {", both)

    def test_merge_keeps_the_stream_values_and_adds_names(self):
        payload = {"value": "1.2.3.4"}
        merge_knowledge_fields(payload, provenance_from_extension({PROVENANCE_EXTENSION_ID: EXTENSION}), NODE)
        self.assertEqual(payload["corroboration_count"], 3, "stream extension wins")
        self.assertEqual(payload["sources"], "AlienVault, MISP")
        self.assertEqual(payload["pulse_trend"], "rising")

    def test_merge_overwrite_for_refresh(self):
        payload = {"corroboration_count": 1}
        merge_knowledge_fields(payload, {}, NODE, overwrite=True)
        self.assertEqual(payload["corroboration_count"], 2)

    def test_every_field_is_declared(self):
        payload = merge_knowledge_fields({}, provenance_from_extension({PROVENANCE_EXTENSION_ID: EXTENSION}), NODE)
        self.assertTrue(set(payload) <= set(KNOWLEDGE_FIELDS))


if __name__ == "__main__":
    unittest.main()
