"""
Tests for sighting an existing OpenCTI indicator by its STIX ID in the Create
Sighting alert action (#67).

Requires the app's pinned runtime libraries (stix2 at minimum). From the
repository root:
    python3 -m venv .venv && .venv/bin/pip install -r TA-opencti-for-splunk-enterprise/package/lib/requirements.txt
    .venv/bin/python -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest

APP_BIN = os.path.join(os.path.dirname(__file__), "..", "TA-opencti-for-splunk-enterprise", "package", "bin")
sys.path.insert(0, os.path.abspath(APP_BIN))

from stix_converter import FAKE_INDICATOR_ID, convert_to_sighting  # noqa: E402
from utils import generate_identity_id, generate_sighting_id  # noqa: E402

INDICATOR_ID = "indicator--0d2b5b3e-3f5b-5d2e-9c1a-6f3e4a7b8c9d"
EVENT = {"_time": "1727000000", "host": "splunk01"}


def _params(value, sighting_of_type="indicator_stix_id"):
    return {
        "sighting_of_value": value,
        "sighting_of_type": sighting_of_type,
        "where_sighted_value": "edr01",
        "where_sighted_type": "system",
        "labels": [],
        "tlp": "tlp_clear",
    }


def _objects(bundle_json):
    return json.loads(bundle_json)["objects"]


class SightingIndicatorTest(unittest.TestCase):

    def test_sighting_references_indicator_directly(self):
        objects = _objects(convert_to_sighting(_params(INDICATOR_ID), EVENT))
        sightings = [o for o in objects if o["type"] == "sighting"]
        self.assertEqual(len(sightings), 1)
        self.assertEqual(sightings[0]["sighting_of_ref"], INDICATOR_ID)
        self.assertNotIn("x_opencti_sighting_of_ref", sightings[0])

    def test_bundle_has_no_indicator_nor_observable(self):
        objects = _objects(convert_to_sighting(_params(INDICATOR_ID), EVENT))
        self.assertEqual(
            sorted({o["type"] for o in objects}),
            ["identity", "marking-definition", "sighting"],
        )
        self.assertNotIn(FAKE_INDICATOR_ID, json.dumps(objects))

    def test_sighting_id_is_deterministic(self):
        sighting = [o for o in _objects(convert_to_sighting(_params(INDICATOR_ID), EVENT))
                    if o["type"] == "sighting"][0]
        where_sighted_id = generate_identity_id("edr01", "system")
        self.assertEqual(sighting["id"], generate_sighting_id(INDICATOR_ID, where_sighted_id))

    def test_value_is_stripped(self):
        sighting = [o for o in _objects(convert_to_sighting(_params(f"  {INDICATOR_ID}\n"), EVENT))
                    if o["type"] == "sighting"][0]
        self.assertEqual(sighting["sighting_of_ref"], INDICATOR_ID)

    def test_invalid_indicator_id_raises_clear_error(self):
        for value in [
            "",
            None,
            "example.com",
            "0d2b5b3e-3f5b-5d2e-9c1a-6f3e4a7b8c9d",               # internal ID, no prefix
            "domain-name--0d2b5b3e-3f5b-5d2e-9c1a-6f3e4a7b8c9d",  # not an indicator
            "indicator--not-a-uuid",
            f"{INDICATOR_ID} {INDICATOR_ID}",                     # multivalue token
        ]:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "Invalid indicator ID"):
                    convert_to_sighting(_params(value), EVENT)

    def test_unknown_type_raises_instead_of_sending_empty_bundle(self):
        with self.assertRaisesRegex(ValueError, "Unsupported sighting_of_type"):
            convert_to_sighting(_params(INDICATOR_ID, "unknown"), EVENT)


if __name__ == "__main__":
    unittest.main()
