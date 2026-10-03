"""Static checks of the shipped Splunk configuration (WS-D, WS-E, WS-F, #68)."""
import configparser
import csv
import json
import os
import re
import unittest

import program_fakes  # noqa: F401  (paths)

from knowledge_fields import KNOWLEDGE_FIELDS

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TA = os.path.join(ROOT, "TA-opencti-for-splunk-enterprise")
DEFAULT = os.path.join(TA, "package", "default")
BIN = os.path.join(TA, "package", "bin")
VERSION = "1.2.0"
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
PROGRAM_SEARCHES = (
    "OpenCTI - Network traffic with an indicator IP",
    "OpenCTI - DNS resolution of an indicator domain",
    "OpenCTI - Web request to an indicator URL",
    "OpenCTI - File or process matching an indicator hash",
    "OpenCTI - Email from an indicator sender",
    "OpenCTI - Report indicator hits",
    "OpenCTI - IOC validation proof",
    "OpenCTI - Reconcile indicator deployments",
    "OpenCTI - Refresh indicator knowledge fields",
    "OpenCTI - Telemetry inventory",
)


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


class SavedSearchesTest(unittest.TestCase):
    def setUp(self):
        self.searches = _conf("savedsearches.conf")

    def test_every_search_ships_disabled(self):
        for stanza in self.searches.sections():
            self.assertEqual(self.searches.get(stanza, "disabled"), "1", stanza)

    def test_program_searches_exist(self):
        for name in PROGRAM_SEARCHES:
            self.assertIn(name, self.searches.sections())

    def test_detections_carry_attack_annotations(self):
        annotated = [s for s in self.searches.sections() if self.searches.has_option(s, "action.correlationsearch.annotations")]
        self.assertGreaterEqual(len(annotated), 6)
        for stanza in annotated:
            annotations = json.loads(self.searches.get(stanza, "action.correlationsearch.annotations"))
            self.assertTrue(annotations["mitre_attack"], stanza)
            for technique in annotations["mitre_attack"]:
                self.assertRegex(technique, TECHNIQUE_RE)

    def test_detections_are_alerts_for_the_saved_search_importer(self):
        for stanza in PROGRAM_SEARCHES[:5]:
            self.assertEqual(self.searches.get(stanza, "alert.track"), "1", stanza)
            self.assertEqual(self.searches.get(stanza, "action.correlationsearch.label"), stanza)

    def test_hit_windows_do_not_overlap(self):
        stanza = "OpenCTI - Report indicator hits"
        self.assertEqual(self.searches.get(stanza, "cron_schedule"), "*/15 * * * *")
        self.assertEqual((self.searches.get(stanza, "dispatch.earliest_time"), self.searches.get(stanza, "dispatch.latest_time")),
                         ("-20m@m", "-5m@m"))
        self.assertIn("| openctireporthits", self.searches.get(stanza, "search"))

    def test_hash_fields_are_reduced_to_the_digest(self):
        """CIM hash fields carry values such as sha256=<digest>; the indicators hold the raw digest."""
        for stanza in ("OpenCTI - File or process matching an indicator hash", "OpenCTI - Report indicator hits"):
            search = self.searches.get(stanza, "search")
            for field in ("Filesystem.file_hash", "Processes.process_hash"):
                with self.subTest(stanza=stanza, field=field):
                    self.assertIn(f"rex field={field} max_match=0", search)
                    self.assertNotIn(f'rename "{field}" AS value', search)

    def test_kv_sync_searches_never_restore_deleted_indicators(self):
        for stanza in ("Update OpenCTI Indicators Lookup", "Nightly Rebuild OpenCTI Indicators Lookup"):
            search = self.searches.get(stanza, "search")
            with self.subTest(stanza=stanza):
                self.assertIn('OR event="delete"', search)
                self.assertIn("sort 0 id -_time -is_delete", search)
        # The incremental upsert only touches the rows it outputs: a winning
        # delete overwrites the entry with a non-matchable revoked tombstone.
        incremental = self.searches.get("Update OpenCTI Indicators Lookup", "search")
        self.assertNotIn("where is_delete == 0", incremental)
        tombstone = incremental.index('revoked = if(is_delete == 1, "true", revoked)')
        self.assertLess(incremental.index("dedup id"), tombstone)
        self.assertIn("value = if(is_delete == 1, null(), value)", incremental)
        self.assertIn("pattern = if(is_delete == 1, null(), pattern)", incremental)
        self.assertLess(tombstone, incremental.index("outputlookup append=t"))
        # The nightly rebuild replaces the collection: delete winners are dropped.
        nightly = self.searches.get("Nightly Rebuild OpenCTI Indicators Lookup", "search")
        self.assertLess(nightly.index("dedup id"), nightly.index("where is_delete == 0"))
        self.assertLess(nightly.index("where is_delete == 0"), nightly.index("outputlookup opencti_indicators"))
        self.assertNotIn("append", nightly[nightly.index("outputlookup"):])

    def test_kv_sync_searches_keep_the_knowledge_fields(self):
        for stanza in ("Update OpenCTI Indicators Lookup", "Nightly Rebuild OpenCTI Indicators Lookup"):
            search = self.searches.get(stanza, "search")
            for field in KNOWLEDGE_FIELDS:
                self.assertIn(field, search, f"{stanza}: {field}")


class CollectionsTest(unittest.TestCase):
    def test_knowledge_fields_are_typed_and_looked_up(self):
        collections = _conf("collections.conf")
        transforms = _conf("transforms.conf")
        fields_list = [f.strip() for f in transforms.get("opencti_indicators", "fields_list").split(",")]
        for field in KNOWLEDGE_FIELDS:
            self.assertTrue(collections.has_option("opencti_indicators", f"field.{field}"), field)
            self.assertIn(field, fields_list)

    def test_state_collections_and_lookups(self):
        from addon_state import DEPLOYMENTS_COLLECTION, HITS_COLLECTION, PROVIDES_COLLECTION, STATE_COLLECTION, VALIDATION_COLLECTION

        collections = _conf("collections.conf")
        transforms = _conf("transforms.conf")
        for name in (STATE_COLLECTION, DEPLOYMENTS_COLLECTION, HITS_COLLECTION, VALIDATION_COLLECTION, PROVIDES_COLLECTION):
            self.assertIn(name, collections.sections())
        for name in (DEPLOYMENTS_COLLECTION, HITS_COLLECTION, VALIDATION_COLLECTION, PROVIDES_COLLECTION):
            self.assertEqual(transforms.get(name, "external_type"), "kvstore")

    def test_cim_mapping_lookup(self):
        transforms = _conf("transforms.conf")
        self.assertEqual(transforms.get("opencti_cim_data_components", "match_type"), "WILDCARD(source)")
        path = os.path.join(TA, "package", "lookups", transforms.get("opencti_cim_data_components", "filename"))
        with open(path, encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertGreater(len(rows), 50)
        for row in rows:
            self.assertRegex(row["source"], r"^(datamodel|sourcetype):\S")
            self.assertTrue(row["data_component"].strip())
        self.assertEqual(len({(r["source"], r["data_component"]) for r in rows}), len(rows), "no duplicate mapping")


class CommandsTest(unittest.TestCase):
    def test_commands_are_chunked_python3_and_documented(self):
        commands = _conf("commands.conf")
        searchbnf = _conf("searchbnf.conf")
        self.assertEqual(set(commands.sections()), {"openctireporthits", "openctivalidation", "openctireconcile", "openctiprovides"})
        for name in commands.sections():
            self.assertEqual(commands.get(name, "chunked"), "true")
            self.assertEqual(commands.get(name, "python.version"), "python3")
            self.assertEqual(commands.get(name, "python.required"), "3.13")
            self.assertTrue(os.path.isfile(os.path.join(BIN, commands.get(name, "filename"))))
            self.assertIn(f"{name}-command", searchbnf.sections())

    def test_macros(self):
        macros = _conf("macros.conf")
        for name in ("opencti_hunt_scope", "opencti_hits_scope", "opencti_hits_match", "opencti_corroborated_indicator(1)",
                     "opencti_prevalent_indicator", "opencti_inventory_scope"):
            self.assertIn(name, macros.sections())


class GlobalConfigTest(unittest.TestCase):
    def setUp(self):
        self.config = _global_config()
        self.alerts = {alert["name"]: alert for alert in self.config["alerts"]}

    def _fields(self, alert):
        return {entity["field"] for entity in self.alerts[alert]["entity"]}

    def test_alert_parameters_read_by_the_helpers_exist(self):
        expected = {
            "opencti_create_incident": {"incident_key", "timeline_milestone", "run_case_autopilot", "autopilot_policy_id"},
            "opencti_create_incident_response": {"incident_key", "timeline_milestone", "run_case_autopilot", "autopilot_policy_id"},
            "opencti_create_sighting": {"sighted_on_platform", "count", "sighting_of_type", "where_sighted_value"},
            "opencti_report_hunt_evidence": {"hunt_run_id", "count", "observables_extraction", "tlp", "labels"},
        }
        for alert, fields in expected.items():
            self.assertTrue(fields <= self._fields(alert), alert)
            helper = self.alerts[alert]["customScript"] + ".py"
            self.assertTrue(os.path.isfile(os.path.join(BIN, helper)), helper)
            with open(os.path.join(BIN, helper), encoding="utf-8") as handle:
                source = handle.read()
            for field in re.findall(r'get_param\("(\w+)"\)', source):
                self.assertIn(field, self._fields(alert), f"{helper} reads {field}")

    def test_sighting_types_match_the_converter(self):
        from stix_converter import INDICATOR_SIGHTING_TYPES, LEGACY_OBSERVABLE_SIGHTING_TYPES, SIGHTING_OF_INDICATOR_ID

        entity = next(e for e in self.alerts["opencti_create_sighting"]["entity"] if e["field"] == "sighting_of_type")
        values = {item["value"] for item in entity["options"]["items"]}
        indicator_modes = {SIGHTING_OF_INDICATOR_ID, *INDICATOR_SIGHTING_TYPES}
        self.assertEqual(values, indicator_modes | set(LEGACY_OBSERVABLE_SIGHTING_TYPES))
        self.assertTrue(set(LEGACY_OBSERVABLE_SIGHTING_TYPES.values()) <= set(INDICATOR_SIGHTING_TYPES))
        self.assertIn(entity["defaultValue"], indicator_modes, "#57: the default sights an indicator")

    def test_platform_tab_matches_the_settings_loader(self):
        from addon_config import DEFAULTS, PLATFORM_STANZA

        tab = next(t for t in self.config["pages"]["configuration"]["tabs"] if t.get("name") == PLATFORM_STANZA)
        self.assertEqual({e["field"] for e in tab["entity"]}, set(DEFAULTS))

    def test_versions(self):
        self.assertEqual(self.config["meta"]["version"], VERSION)
        with open(os.path.join(TA, "package", "app.manifest"), encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["info"]["id"]["version"], VERSION)
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
            readme = handle.read()
        self.assertTrue(f"Version {VERSION}" in readme, "README version line")
        self.assertTrue(f"TA-opencti-for-splunk-enterprise-{VERSION}.tar.gz" in readme, "README download link")
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as handle:
            self.assertTrue(f"## {VERSION}" in handle.read(), "CHANGELOG entry")

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
        self.assertEqual(labels, ["Indicators", "Dissemination assurance", "Sources", "Threat Pulse",
                                  "Defense matrix", "Hunts", "Timeline"])
        for layout in dashboard["layout"]["layoutDefinitions"].values():
            for item in layout["structure"]:
                visualization = dashboard["visualizations"][item["item"]]
                self.assertIn(visualization["dataSources"]["primary"], dashboard["dataSources"])


if __name__ == "__main__":
    unittest.main()
