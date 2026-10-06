"""Static checks of the shipped Splunk configuration (Case Autopilot, #68)."""
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


class GlobalConfigTest(unittest.TestCase):
    def setUp(self):
        self.config = _global_config()
        self.alerts = {alert["name"]: alert for alert in self.config["alerts"]}

    def _fields(self, alert):
        return {entity["field"] for entity in self.alerts[alert]["entity"]}

    def test_alert_parameters_read_by_the_helpers_exist(self):
        for alert in ("opencti_create_incident", "opencti_create_incident_response"):
            self.assertTrue({"run_case_autopilot", "autopilot_policy_id"} <= self._fields(alert), alert)
            helper = self.alerts[alert]["customScript"] + ".py"
            self.assertTrue(os.path.isfile(os.path.join(BIN, helper)), helper)
            with open(os.path.join(BIN, helper), encoding="utf-8") as handle:
                source = handle.read()
            for field in re.findall(r'get_param\("(\w+)"\)', source):
                self.assertIn(field, self._fields(alert), f"{helper} reads {field}")
        for module in ("program_actions.py",):
            with open(os.path.join(BIN, module), encoding="utf-8") as handle:
                source = handle.read()
            for field in re.findall(r'context\.(?:flag|param)\("(\w+)"', source):
                for alert in ("opencti_create_incident", "opencti_create_incident_response"):
                    self.assertIn(field, self._fields(alert), f"{module} reads {field}")

    def test_no_settings_tab_and_default_feature_cache(self):
        from addon_config import DEFAULTS, PLATFORM_STANZA

        self.assertNotIn(PLATFORM_STANZA, [t.get("name") for t in self.config["pages"]["configuration"]["tabs"]])
        self.assertEqual(DEFAULTS, {"feature_cache_ttl": "60"})

    def test_case_autopilot_defaults_off(self):
        for alert in ("opencti_create_incident", "opencti_create_incident_response"):
            entity = next(e for e in self.alerts[alert]["entity"] if e["field"] == "run_case_autopilot")
            self.assertEqual(entity["defaultValue"], 0, alert)

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
        self.assertEqual(labels, ["Indicators", "Case Autopilot"])
        for layout in dashboard["layout"]["layoutDefinitions"].values():
            for item in layout["structure"]:
                visualization = dashboard["visualizations"][item["item"]]
                self.assertIn(visualization["dataSources"]["primary"], dashboard["dataSources"])

    def test_tables_show_human_headers(self):
        """Splunk shows the fields of the final table, renamed, as column headers: no raw names or IDs."""
        with open(os.path.join(TA, "custom_dashboard.json"), encoding="utf-8") as handle:
            dashboard = json.load(handle)
        checked = 0
        for name, source in dashboard["dataSources"].items():
            query = source.get("options", {}).get("query", "")
            tables = re.findall(r"\|\s*table\s+([^|]+)", query)
            if not tables:
                continue
            checked += 1
            renames = dict(re.findall(r'(\w+) AS "([^"]+)"', query.split("| table")[-1]))
            for field in tables[-1].split():
                shown = renames.get(field, field)
                if shown.startswith("_"):
                    continue  # hidden by Splunk tables
                with self.subTest(source=name, field=field):
                    self.assertIsNone(re.fullmatch(r"[a-z0-9_]+", shown), f"{shown} is a raw field name")
                    self.assertNotRegex(shown.lower(), r"\bids?\b")
        self.assertGreaterEqual(checked, 1)


if __name__ == "__main__":
    unittest.main()
