"""Static checks of the shipped Splunk configuration (dissemination assurance, #68)."""
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
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
PROGRAM_SEARCHES = (
    "OpenCTI - Report indicator hits",
    "OpenCTI - IOC validation proof",
    "OpenCTI - Reconcile indicator deployments",
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

    def test_hits_search_carries_attack_annotations(self):
        annotations = json.loads(self.searches.get("OpenCTI - Report indicator hits", "action.correlationsearch.annotations"))
        self.assertTrue(annotations["mitre_attack"])
        for technique in annotations["mitre_attack"]:
            self.assertRegex(technique, TECHNIQUE_RE)

    def test_maintenance_searches_declare_no_technique(self):
        for stanza in ("OpenCTI - IOC validation proof", "OpenCTI - Reconcile indicator deployments"):
            self.assertFalse(self.searches.has_option(stanza, "action.correlationsearch.annotations"), stanza)
            self.assertEqual(self.searches.get(stanza, "alert.track"), "0", stanza)

    def test_hit_windows_do_not_overlap(self):
        stanza = "OpenCTI - Report indicator hits"
        self.assertEqual(self.searches.get(stanza, "cron_schedule"), "*/15 * * * *")
        self.assertEqual((self.searches.get(stanza, "dispatch.earliest_time"), self.searches.get(stanza, "dispatch.latest_time")),
                         ("-20m@m", "-5m@m"))
        self.assertIn("| openctireporthits", self.searches.get(stanza, "search"))

    def test_hash_fields_are_reduced_to_the_digest(self):
        """CIM hash fields carry values such as sha256=<digest>; the indicators hold the raw digest."""
        search = self.searches.get("OpenCTI - Report indicator hits", "search")
        for field in ("Filesystem.file_hash", "Processes.process_hash"):
            with self.subTest(field=field):
                self.assertIn(f"rex field={field} max_match=0", search)
                self.assertNotIn(f'rename "{field}" AS value', search)

    def test_kv_sync_searches_read_both_timestamp_precisions(self):
        """A whole-second update must never lose the delete tie-break to an older delete."""
        for stanza in ("Update OpenCTI Indicators Lookup", "Nightly Rebuild OpenCTI Indicators Lookup"):
            search = self.searches.get(stanza, "search")
            with self.subTest(stanza=stanza):
                for field in ("modified", "updated_at", "created_at"):
                    self.assertIn(f'strptime({field}, "%Y-%m-%dT%H:%M:%S.%3NZ"), strptime({field}, "%Y-%m-%dT%H:%M:%SZ")', search)
                self.assertNotIn("case( match(modified", " ".join(search.split()))

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

    def test_kv_sync_searches_keep_the_source_index(self):
        """The reconciliation gives index-mode lookup entries the identity of the stream input."""
        for stanza in ("Update OpenCTI Indicators Lookup", "Nightly Rebuild OpenCTI Indicators Lookup"):
            search = self.searches.get(stanza, "search")
            with self.subTest(stanza=stanza):
                self.assertIn("source_index = index", search)
                self.assertIn(" source_index ", search)

    def test_hits_search_ends_with_the_coverage_heartbeat(self):
        search = self.searches.get("OpenCTI - Report indicator hits", "search")
        heartbeat = search.index("eval opencti_hits_heartbeat = 1")
        self.assertLess(search.index("by indicator_id"), heartbeat)
        self.assertLess(heartbeat, search.index("| openctireporthits"))


class CollectionsTest(unittest.TestCase):
    def test_state_collections_and_lookups(self):
        from addon_state import DEPLOYMENTS_COLLECTION, HITS_COLLECTION, STATE_COLLECTION, VALIDATION_COLLECTION

        collections = _conf("collections.conf")
        transforms = _conf("transforms.conf")
        for name in (STATE_COLLECTION, DEPLOYMENTS_COLLECTION, HITS_COLLECTION, VALIDATION_COLLECTION):
            self.assertIn(name, collections.sections())
        for name in (DEPLOYMENTS_COLLECTION, HITS_COLLECTION, VALIDATION_COLLECTION):
            self.assertEqual(transforms.get(name, "external_type"), "kvstore")

    def test_source_index_is_typed_and_looked_up(self):
        self.assertTrue(_conf("collections.conf").has_option("opencti_indicators", "field.source_index"))
        fields_list = [f.strip() for f in _conf("transforms.conf").get("opencti_indicators", "fields_list").split(",")]
        self.assertIn("source_index", fields_list)


class CommandsTest(unittest.TestCase):
    def test_commands_are_chunked_python3_and_documented(self):
        commands = _conf("commands.conf")
        searchbnf = _conf("searchbnf.conf")
        self.assertEqual(set(commands.sections()), {"openctireporthits", "openctivalidation", "openctireconcile"})
        for name in commands.sections():
            self.assertEqual(commands.get(name, "chunked"), "true")
            self.assertEqual(commands.get(name, "run_in_preview"), "false", f"{name} writes to OpenCTI")
            self.assertEqual(commands.get(name, "python.version"), "python3")
            self.assertEqual(commands.get(name, "python.required"), "3.13")
            self.assertTrue(os.path.isfile(os.path.join(BIN, commands.get(name, "filename"))))
            self.assertIn(f"{name}-command", searchbnf.sections())

    def test_macros(self):
        macros = _conf("macros.conf")
        for name in ("opencti_hits_scope", "opencti_hits_summariesonly", "opencti_usable_indicator", "opencti_hits_match"):
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
    def setUp(self):
        with open(os.path.join(TA, "custom_dashboard.json"), encoding="utf-8") as handle:
            self.dashboard = json.load(handle)

    def test_tabs_and_data_sources(self):
        labels = [tab["label"] for tab in self.dashboard["layout"]["tabs"]["items"]]
        # Names of the OpenCTI features (innovation 13 naming directive)
        self.assertEqual(labels, ["Indicators", "Dissemination assurance"])
        for layout in self.dashboard["layout"]["layoutDefinitions"].values():
            for item in layout["structure"]:
                visualization = self.dashboard["visualizations"][item["item"]]
                self.assertIn(visualization["dataSources"]["primary"], self.dashboard["dataSources"])

    def test_iso_timestamps_parse_both_precisions(self):
        # KV Store rows hold second (utc_now_iso) and millisecond (to_iso) timestamps
        parsed = 0
        for name, source in self.dashboard["dataSources"].items():
            if not name.startswith(("ds_dep_", "ds_hits_", "ds_val_")):
                continue
            query = source.get("options", {}).get("query", "")
            for field in set(re.findall(r'strptime\((\w+), "%Y-%m-%dT', query)):
                parsed += 1
                self.assertIn(f'strptime({field}, "%Y-%m-%dT%H:%M:%S.%3NZ")', query, name)
                self.assertIn(f'strptime({field}, "%Y-%m-%dT%H:%M:%SZ")', query, name)
        self.assertGreaterEqual(parsed, 2)


if __name__ == "__main__":
    unittest.main()
