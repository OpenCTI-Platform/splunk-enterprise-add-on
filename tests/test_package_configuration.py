"""Static checks of the shipped Splunk configuration (hunting, #68)."""
import configparser
import json
import os
import re
import unittest

import program_fakes  # noqa: F401  (paths)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TA = os.path.join(ROOT, "TA-opencti-for-splunk-enterprise")
DEFAULT = os.path.join(TA, "package", "default")
BIN = os.path.join(TA, "package", "bin")


def _conf(name):
    parser = configparser.RawConfigParser(strict=False, interpolation=None, delimiters=("=",), comment_prefixes=("#",))
    parser.optionxform = str
    with open(os.path.join(DEFAULT, name), encoding="utf-8") as handle:
        # .conf line continuations
        parser.read_string(handle.read().replace("\\\n", " "))
    return parser


def _global_config():
    with open(os.path.join(TA, "globalConfig.json"), encoding="utf-8") as handle:
        return json.load(handle)


class ConfigurationTest(unittest.TestCase):
    def test_state_collection(self):
        from addon_state import STATE_COLLECTION

        self.assertIn(STATE_COLLECTION, _conf("collections.conf").sections())

    def test_hunt_scope_macro(self):
        macros = _conf("macros.conf")
        self.assertIn("opencti_hunt_scope", macros.sections())
        self.assertEqual(macros.get("opencti_hunt_scope", "iseval"), "0")

    def test_hunt_evidence_log_sourcetype(self):
        props = _conf("props.conf")
        stanza = "source::...opencti_report_hunt_evidence_modalert.log*"
        self.assertEqual(props.get(stanza, "sourcetype"), "taopenctiforsplunkenterprise:log")


class GlobalConfigTest(unittest.TestCase):
    def setUp(self):
        self.config = _global_config()
        self.alerts = {alert["name"]: alert for alert in self.config["alerts"]}

    def _fields(self, alert):
        return {entity["field"] for entity in self.alerts[alert]["entity"]}

    def test_alert_parameters_read_by_the_helpers_exist(self):
        alert = "opencti_report_hunt_evidence"
        self.assertTrue({"hunt_run_id", "count", "observables_extraction", "tlp", "labels"} <= self._fields(alert))
        helper = self.alerts[alert]["customScript"] + ".py"
        self.assertTrue(os.path.isfile(os.path.join(BIN, helper)), helper)
        with open(os.path.join(BIN, helper), encoding="utf-8") as handle:
            source = handle.read()
        for field in re.findall(r'get_param\("(\w+)"\)', source):
            self.assertIn(field, self._fields(alert), f"{helper} reads {field}")

    def test_hunt_run_id_defaults_to_the_result_token(self):
        entity = next(e for e in self.alerts["opencti_report_hunt_evidence"]["entity"] if e["field"] == "hunt_run_id")
        self.assertEqual(entity["defaultValue"], "$result.hunt_run_id$")
        self.assertTrue(entity["required"])

    def test_platform_tab_matches_the_settings_loader(self):
        from addon_config import DEFAULTS, PLATFORM_STANZA

        tab = next(t for t in self.config["pages"]["configuration"]["tabs"] if t.get("name") == PLATFORM_STANZA)
        self.assertEqual({e["field"] for e in tab["entity"]}, set(DEFAULTS))

    def test_versions_agree(self):
        version = self.config["meta"]["version"]
        with open(os.path.join(TA, "package", "app.manifest"), encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["info"]["id"]["version"], version)
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
            readme = handle.read()
        self.assertTrue(f"Version {version}" in readme, "README version line")
        self.assertTrue(f"TA-opencti-for-splunk-enterprise-{version}.tar.gz" in readme, "README download link")

    def test_no_secret_in_defaults(self):
        for name in os.listdir(DEFAULT):
            with open(os.path.join(DEFAULT, name), encoding="utf-8") as handle:
                content = handle.read().lower()
            self.assertNotIn("api_key =", content, name)
            self.assertNotIn("password =", content, name)


class DashboardTest(unittest.TestCase):
    def test_tabs_and_data_sources(self):
        with open(os.path.join(TA, "custom_dashboard.json"), encoding="utf-8") as handle:
            dashboard = json.load(handle)
        labels = [tab["label"] for tab in dashboard["layout"]["tabs"]["items"]]
        # Names of the OpenCTI features (innovation 13 naming directive)
        self.assertEqual(labels, ["Indicators", "Hunts"])
        for layout in dashboard["layout"]["layoutDefinitions"].values():
            for item in layout["structure"]:
                visualization = dashboard["visualizations"][item["item"]]
                self.assertIn(visualization["dataSources"]["primary"], dashboard["dataSources"])


if __name__ == "__main__":
    unittest.main()
