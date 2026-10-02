"""
Tests for TLP marking selection in the alert actions (#62).

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

import stix2  # noqa: E402
from stix_converter import (  # noqa: E402
    _get_stix_marking_id,
    convert_to_incident,
    convert_to_incident_response,
    convert_to_sighting,
)

# OpenCTI static TLP IDs (pycti MarkingDefinition.generate_id)
TLP_IDS = {
    "tlp_clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "tlp_green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "tlp_amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "tlp_amber_strict": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "tlp_red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
EVENT = {"_time": "1727000000", "host": "splunk01"}
INCIDENT_PARAMS = {
    "name": "EDR hit",
    "description": "",
    "type": "alert",
    "severity": "high",
    "priority": "P2",
    "labels": [],
    "observables_extraction": "none",
}
SIGHTING_PARAMS = {
    "sighting_of_value": "1.2.3.4",
    "sighting_of_type": "ipv4_observable",
    "where_sighted_value": "edr01",
    "where_sighted_type": "system",
    "labels": [],
}
# converter, params, STIX type of the object carrying the marking
CONVERTERS = [
    (convert_to_incident, INCIDENT_PARAMS, "incident"),
    (convert_to_incident_response, INCIDENT_PARAMS, "case-incident"),
    (convert_to_sighting, SIGHTING_PARAMS, "sighting"),
]


def _objects(bundle_json, stix_type):
    return [o for o in json.loads(bundle_json)["objects"] if o["type"] == stix_type]


class GetStixMarkingTest(unittest.TestCase):

    def test_each_tlp_maps_to_opencti_static_id(self):
        for value, marking_id in TLP_IDS.items():
            with self.subTest(tlp=value):
                self.assertEqual(_get_stix_marking_id(value).id, marking_id)

    def test_amber_strict_is_an_opencti_tlp_marking(self):
        marking = _get_stix_marking_id("tlp_amber_strict")
        self.assertEqual(marking.x_opencti_definition_type, "TLP")
        self.assertEqual(marking.x_opencti_definition, "TLP:AMBER+STRICT")

    def test_invalid_tlp_raises_clear_error(self):
        for value in [None, "", "tlp_white", "amber", "TLP:AMBER+STRICT"]:
            with self.subTest(tlp=value):
                with self.assertRaisesRegex(ValueError, "Invalid TLP value"):
                    _get_stix_marking_id(value)


class BundleMarkingTest(unittest.TestCase):

    def test_amber_strict_marking_applied_and_shipped_in_bundle(self):
        marking_id = TLP_IDS["tlp_amber_strict"]
        for convert, params, stix_type in CONVERTERS:
            with self.subTest(converter=convert.__name__):
                bundle = convert(dict(params, tlp="tlp_amber_strict"), EVENT)
                self.assertEqual(_objects(bundle, stix_type)[0]["object_marking_refs"], [marking_id])
                markings = _objects(bundle, "marking-definition")
                self.assertEqual([m["id"] for m in markings], [marking_id])
                self.assertEqual(markings[0]["x_opencti_definition"], "TLP:AMBER+STRICT")

    def test_builtin_tlp_marking_shipped_in_bundle(self):
        for convert, params, stix_type in CONVERTERS:
            with self.subTest(converter=convert.__name__):
                bundle = convert(dict(params, tlp="tlp_green"), EVENT)
                markings = _objects(bundle, "marking-definition")
                self.assertEqual([m["id"] for m in markings], [stix2.TLP_GREEN.id])

    def test_invalid_tlp_fails_before_building_bundle(self):
        for convert, params, _ in CONVERTERS:
            with self.subTest(converter=convert.__name__):
                with self.assertRaisesRegex(ValueError, "Invalid TLP value"):
                    convert(dict(params, tlp=None), EVENT)


if __name__ == "__main__":
    unittest.main()
