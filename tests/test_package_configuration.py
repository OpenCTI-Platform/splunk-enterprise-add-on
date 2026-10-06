"""Static checks of the shipped Splunk configuration (defense matrix, #68)."""
import configparser
import csv
import json
import os
import re
import unittest

import program_fakes  # noqa: F401  (paths)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TA = os.path.join(ROOT, "TA-opencti-for-splunk-enterprise")
DEFAULT = os.path.join(TA, "package", "default")
BIN = os.path.join(TA, "package", "bin")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
DETECTIONS = (
    "OpenCTI - Network traffic with an indicator IP",
    "OpenCTI - DNS resolution of an indicator domain",
    "OpenCTI - Web request to an indicator URL",
    "OpenCTI - File or process matching an indicator hash",
    "OpenCTI - Email from an indicator sender",
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
        for name in DETECTIONS + ("OpenCTI - Telemetry inventory",):
            self.assertIn(name, self.searches.sections())

    def test_detections_carry_attack_annotations(self):
        annotated = [s for s in self.searches.sections() if self.searches.has_option(s, "action.correlationsearch.annotations")]
        self.assertEqual(set(annotated), set(DETECTIONS))
        for stanza in annotated:
            annotations = json.loads(self.searches.get(stanza, "action.correlationsearch.annotations"))
            self.assertTrue(annotations["mitre_attack"], stanza)
            for technique in annotations["mitre_attack"]:
                self.assertRegex(technique, TECHNIQUE_RE)

    def test_detections_are_alerts_for_the_saved_search_importer(self):
        for stanza in DETECTIONS:
            self.assertEqual(self.searches.get(stanza, "alert.track"), "1", stanza)
            self.assertEqual(self.searches.get(stanza, "action.correlationsearch.label"), stanza)

    def test_inventory_declares_no_technique_and_no_alert(self):
        stanza = "OpenCTI - Telemetry inventory"
        self.assertFalse(self.searches.has_option(stanza, "action.correlationsearch.annotations"))
        self.assertEqual(self.searches.get(stanza, "alert.track"), "0")
        self.assertIn("| openctiprovides", self.searches.get(stanza, "search"))

    def test_hash_fields_are_reduced_to_the_digest(self):
        """CIM hash fields carry values such as sha256=<digest>; the indicators hold the raw digest."""
        search = self.searches.get("OpenCTI - File or process matching an indicator hash", "search")
        for field in ("Filesystem.file_hash", "Processes.process_hash"):
            with self.subTest(field=field):
                self.assertIn(f"rex field={field} max_match=0", search)
                self.assertNotIn(f'rename "{field}" AS value', search)


class CollectionsTest(unittest.TestCase):
    def test_state_collections_and_lookups(self):
        from addon_state import PROVIDES_COLLECTION, STATE_COLLECTION

        collections = _conf("collections.conf")
        transforms = _conf("transforms.conf")
        for name in (STATE_COLLECTION, PROVIDES_COLLECTION):
            self.assertIn(name, collections.sections())
        self.assertEqual(transforms.get(PROVIDES_COLLECTION, "external_type"), "kvstore")

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
    def test_command_is_chunked_python3_and_documented(self):
        commands = _conf("commands.conf")
        searchbnf = _conf("searchbnf.conf")
        self.assertEqual(set(commands.sections()), {"openctiprovides"})
        for name in commands.sections():
            self.assertEqual(commands.get(name, "chunked"), "true")
            self.assertEqual(commands.get(name, "run_in_preview"), "false", f"{name} writes to OpenCTI")
            self.assertEqual(commands.get(name, "python.version"), "python3")
            self.assertEqual(commands.get(name, "python.required"), "3.13")
            self.assertTrue(os.path.isfile(os.path.join(BIN, commands.get(name, "filename"))))
            self.assertIn(f"{name}-command", searchbnf.sections())

    def test_macros(self):
        macros = _conf("macros.conf")
        for name in ("opencti_hits_scope", "opencti_hits_summariesonly", "opencti_usable_indicator", "opencti_hits_match",
                     "opencti_inventory_scope", "opencti_inventory_summariesonly"):
            self.assertIn(name, macros.sections())

    def test_hits_match_yields_one_row_per_indicator(self):
        steps = [step.strip() for step in _conf("macros.conf").get("opencti_hits_match", "definition").split("|")]
        self.assertEqual(steps[:3], ["eval value = mvdedup(value)", "mvexpand value",
                                     "lookup opencti_indicators value OUTPUT id AS indicator_id"],
                         "each digest of a hash field is matched on its own row, so an indicator keeps its own value")
        self.assertLess(steps.index("eval indicator_id = mvdedup(indicator_id)"), steps.index("mvexpand indicator_id"))
        self.assertLess(steps.index("mvexpand indicator_id"),
                        steps.index("lookup opencti_indicators id AS indicator_id OUTPUT revoked valid_until type AS indicator_type"))
        self.assertEqual(steps[-1], "where `opencti_usable_indicator` AND `opencti_kind_indicator`")
        usable = _conf("macros.conf").get("opencti_usable_indicator", "definition")
        self.assertIn("mvfind(revoked", usable)
        self.assertIn("isnull(valid_until) OR coalesce(", usable, "expired indicators never hit")
        self.assertIn("> now()", usable)

    def test_every_matched_value_declares_its_kind(self):
        """A value only hits the indicators of its observable type (a file name is not a domain)."""
        kinds = _conf("macros.conf").get("opencti_kind_indicator", "definition")
        for kind, types in (("ip", "ipv[46]-addr"), ("domain", "domain-name|hostname"), ("url", '"url"'),
                            ("hash", "md5|sha1|sha256"), ("email", '"email-addr"')):
            self.assertIn(f'opencti_value_kind == "{kind}"', kinds)
            self.assertIn(types, kinds)
        self.assertNotIn("filename", kinds)
        searches = _conf("savedsearches.conf")
        calls = 0
        for name in searches.sections():
            search = " ".join(searches.get(name, "search", fallback="").split())
            for match in re.finditer(r"\| `opencti_hits_match`", search):
                calls += 1
                self.assertRegex(search[:match.start()], r'eval opencti_value_kind="(ip|domain|url|hash|email)" $', name)
        self.assertGreaterEqual(calls, 7)

    def test_hits_match_applies_once_per_row(self):
        # The macro yields one row per matching indicator: a second pass squares the rows of shared values
        searches = _conf("savedsearches.conf")
        for name in searches.sections():
            search = " ".join(searches.get(name, "search", fallback="").replace("\\", " ").split())
            self.assertNotIn("`opencti_hits_match`] | `opencti_hits_match`", search, name)
            self.assertNotIn("`opencti_hits_match` | `opencti_hits_match`", search, name)
        # A hash string yields several digests (multivalue value): grouping by it would add rows for
        # the digests that matched nothing
        hashes = searches.get("OpenCTI - File or process matching an indicator hash", "search")
        self.assertTrue(" ".join(hashes.split()).endswith("values(value) AS value by indicator_id"))


class GlobalConfigTest(unittest.TestCase):
    def setUp(self):
        self.config = _global_config()

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
        self.assertEqual(labels, ["Indicators", "Defense matrix"])
        for layout in dashboard["layout"]["layoutDefinitions"].values():
            for item in layout["structure"]:
                visualization = dashboard["visualizations"][item["item"]]
                self.assertIn(visualization["dataSources"]["primary"], dashboard["dataSources"])


if __name__ == "__main__":
    unittest.main()
