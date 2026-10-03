"""
Tests for file hash support in the Create Sighting alert action, for
hash-only File observables shared with Incident / Incident Response, and for
CIM `file_hash` extraction (#56).

Requires the app's pinned runtime libraries (stix2 at minimum). From the
repository root:
    python3 -m venv .venv && .venv/bin/pip install -r TA-opencti-for-splunk-enterprise/package/lib/requirements.txt
    .venv/bin/python -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest
from unittest import mock

APP_BIN = os.path.join(os.path.dirname(__file__), "..", "TA-opencti-for-splunk-enterprise", "package", "bin")
sys.path.insert(0, os.path.abspath(APP_BIN))

import stix2  # noqa: E402
import stix_converter  # noqa: E402
from stix_converter import convert_to_incident, convert_to_sighting  # noqa: E402
from utils import get_hash_type  # noqa: E402

HASHES = {
    "md5": ("MD5", "d41d8cd98f00b204e9800998ecf8427e"),
    "sha1": ("SHA-1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    "sha256": ("SHA-256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    "sha512": ("SHA-512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                          "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
}
EVENT = {"_time": "1727000000", "host": "splunk01"}


def _params(value, sighting_of_type="file_hash_observable"):
    return {
        "sighting_of_value": value,
        "sighting_of_type": sighting_of_type,
        "where_sighted_value": "edr01",
        "where_sighted_type": "system",
        "labels": [],
        "tlp": "tlp_clear",
    }


def _incident_params(observables_extraction):
    return {
        "name": "EDR hit",
        "description": "",
        "type": "alert",
        "severity": "high",
        "priority": "P2",
        "labels": [],
        "tlp": "tlp_clear",
        "observables_extraction": observables_extraction,
    }


def _objects(bundle_json, stix_type):
    return [o for o in json.loads(bundle_json)["objects"] if o["type"] == stix_type]


class GetHashTypeTest(unittest.TestCase):

    def test_detects_each_algorithm(self):
        for hash_type, (_, value) in HASHES.items():
            with self.subTest(hash_type=hash_type):
                self.assertEqual(get_hash_type(value), hash_type)
                self.assertEqual(get_hash_type(value.upper()), hash_type)

    def test_rejects_non_hash_values(self):
        for value in [
            "a" * 50,                      # between SHA-1 and SHA-256 lengths
            "a" * 31,                      # too short for MD5
            "a" * 129,                     # too long for SHA-512
            HASHES["md5"][1] + "suffix",   # trailing garbage
            "z" * 32,                      # not hex
            " " + HASHES["md5"][1],        # whitespace is stripped by callers
            "",
            None,
        ]:
            with self.subTest(value=value):
                self.assertIsNone(get_hash_type(value))


class SightingFileHashTest(unittest.TestCase):

    def test_sighting_created_for_each_hash_type(self):
        for hash_type, (algorithm, value) in HASHES.items():
            with self.subTest(hash_type=hash_type):
                bundle = convert_to_sighting(_params(value), EVENT)
                files = _objects(bundle, "file")
                sightings = _objects(bundle, "sighting")
                self.assertEqual(len(files), 1)
                self.assertEqual(files[0]["hashes"], {algorithm: value})
                self.assertNotIn("name", files[0])
                self.assertEqual(len(sightings), 1)
                indicators = _objects(bundle, "indicator")
                self.assertEqual(len(indicators), 1)
                self.assertIn(value, indicators[0]["pattern"])
                self.assertEqual(sightings[0]["sighting_of_ref"], indicators[0]["id"])
                self.assertNotIn("x_opencti_sighting_of_ref", sightings[0])
                based_on = _objects(bundle, "relationship")
                self.assertEqual([(r["relationship_type"], r["source_ref"], r["target_ref"]) for r in based_on],
                                 [("based-on", indicators[0]["id"], files[0]["id"])])

    def test_value_is_stripped(self):
        algorithm, value = HASHES["sha256"]
        bundle = convert_to_sighting(_params(f"  {value}\n"), EVENT)
        self.assertEqual(_objects(bundle, "file")[0]["hashes"], {algorithm: value})

    def test_unrecognized_hash_raises_clear_error(self):
        with self.assertRaisesRegex(ValueError, "Unrecognized hash value"):
            convert_to_sighting(_params("a" * 50), EVENT)

    def test_unsupported_type_raises_clear_error(self):
        with self.assertRaisesRegex(ValueError, "Unsupported sighting_of_type"):
            convert_to_sighting(_params("foo", "unknown_observable"), EVENT)


class HashOnlyFileTest(unittest.TestCase):
    """Hash Files carry no name: shared by Sighting and Incident / Incident Response."""

    def _files(self, observables):
        author = stix2.Identity(name="splunk01", identity_class="system")
        return stix_converter._convert_observables_to_stix(observables, stix2.TLP_WHITE, author)

    def test_hash_file_has_no_name_and_hash_only_id(self):
        for hash_type, (algorithm, value) in HASHES.items():
            with self.subTest(hash_type=hash_type):
                stix_file = self._files([{"type": hash_type, "value": value}])[0]
                self.assertNotIn("name", stix_file)
                self.assertEqual(stix_file.id, stix2.File(hashes={algorithm: value}).id)

    def test_file_name_keeps_name(self):
        stix_file = self._files([{"type": "file_name", "value": "evil.exe"}])[0]
        self.assertEqual(stix_file.name, "evil.exe")

    def test_incident_field_mapping_hash_file_has_no_name(self):
        value = HASHES["sha256"][1]
        bundle = convert_to_incident(_incident_params("field_mapping"), dict(EVENT, octi_hash=value))
        files = _objects(bundle, "file")
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["hashes"], {"SHA-256": value})
        self.assertNotIn("name", files[0])


class KeyModelHashTest(unittest.TestCase):

    def _extracted(self, event):
        with mock.patch.object(stix_converter, "_convert_observables_to_stix",
                               side_effect=lambda observables, marking, creator: observables):
            return stix_converter._extract_observables_from_key_model(event, None, None)

    def test_hash_field_yields_single_typed_observable(self):
        value = HASHES["sha256"][1]
        self.assertEqual(self._extracted({"octi_hash": value}), [{"type": "sha256", "value": value}])

    def test_over_length_hash_is_dropped(self):
        self.assertEqual(self._extracted({"octi_hash": "a" * 50}), [])


class CimModelHashTest(unittest.TestCase):
    """CIM `file_hash` used to be emitted as type "hash" and silently dropped."""

    def _incident(self, **fields):
        event = dict(EVENT, file_name="evil.exe", **fields)
        return convert_to_incident(_incident_params("cim_model"), event)

    def test_file_hash_is_extracted_and_linked_to_incident(self):
        for hash_type, (algorithm, value) in HASHES.items():
            with self.subTest(hash_type=hash_type):
                bundle = self._incident(file_hash=f" {value} ")
                hash_files = [f for f in _objects(bundle, "file") if "hashes" in f]
                self.assertEqual(len(hash_files), 1)
                self.assertEqual(hash_files[0]["hashes"], {algorithm: value})
                self.assertNotIn("name", hash_files[0])

                incident_id = _objects(bundle, "incident")[0]["id"]
                links = {(r["source_ref"], r["target_ref"]) for r in _objects(bundle, "relationship")}
                self.assertIn((hash_files[0]["id"], incident_id), links)

    def test_unrecognized_file_hash_is_dropped(self):
        files = _objects(self._incident(file_hash="a" * 50), "file")
        self.assertEqual([f.get("name") for f in files], ["evil.exe"])
        self.assertFalse(any("hashes" in f for f in files))


if __name__ == "__main__":
    unittest.main()
