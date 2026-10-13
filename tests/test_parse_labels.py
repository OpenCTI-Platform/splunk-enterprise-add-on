"""
Tests for the Labels parameter of the alert actions (#77).

Requires the app's pinned runtime libraries (solnlib, stix2). From the
repository root:
    python3 -m venv .venv && .venv/bin/pip install -r TA-opencti-for-splunk-enterprise/package/lib/requirements.txt
    .venv/bin/python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

APP_BIN = os.path.join(os.path.dirname(__file__), "..", "TA-opencti-for-splunk-enterprise", "package", "bin")
sys.path.insert(0, os.path.abspath(APP_BIN))

from utils import parse_labels  # noqa: E402


class ParseLabelsTest(unittest.TestCase):

    def test_empty_value(self):
        for value in [None, "", " , ,\n"]:
            with self.subTest(value=value):
                self.assertEqual(parse_labels(value), [])

    def test_comma_separated(self):
        self.assertEqual(parse_labels(" splunk, proxy ,,detection "), ["splunk", "proxy", "detection"])

    def test_multivalue_token_is_split(self):
        # "splunk,$result.ioc_labels$" with ioc_labels = [apt28, c2], as rendered by Splunk
        self.assertEqual(parse_labels("splunk,apt28\nc2"), ["splunk", "apt28", "c2"])

    def test_windows_line_breaks(self):
        self.assertEqual(parse_labels("apt28\r\nc2"), ["apt28", "c2"])

    def test_spaces_inside_a_label_are_kept(self):
        self.assertEqual(parse_labels("threat actor,initial access"), ["threat actor", "initial access"])

    def test_duplicates_are_dropped_in_order(self):
        self.assertEqual(parse_labels("c2,apt28\nc2,splunk"), ["c2", "apt28", "splunk"])


if __name__ == "__main__":
    unittest.main()
