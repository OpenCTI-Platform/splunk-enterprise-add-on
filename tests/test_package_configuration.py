"""Static checks of the shipped Splunk configuration (#20, #47, #57, #67)."""
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


class SavedSearchesTest(unittest.TestCase):
    def setUp(self):
        self.searches = _conf("savedsearches.conf")

    def test_every_search_ships_disabled(self):
        for stanza in self.searches.sections():
            self.assertEqual(self.searches.get(stanza, "disabled"), "1", stanza)

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


class CollectionsTest(unittest.TestCase):
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
        expected = {
            "opencti_create_incident": {"incident_key"},
            "opencti_create_incident_response": {"incident_key"},
            "opencti_create_sighting": {"sighted_on_platform", "count", "sighting_of_type", "where_sighted_value"},
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
    def test_iso_timestamps_parse_both_precisions(self):
        # KV Store rows hold second (stream added_at) and millisecond (KV sync searches) timestamps
        with open(os.path.join(TA, "custom_dashboard.json"), encoding="utf-8") as handle:
            dashboard = json.load(handle)
        parsed = 0
        for name, source in dashboard["dataSources"].items():
            query = source.get("options", {}).get("query", "")
            for field in set(re.findall(r'strptime\((\w+), "%Y-%m-%dT', query)):
                parsed += 1
                self.assertIn(f'strptime({field}, "%Y-%m-%dT%H:%M:%S.%3NZ")', query, name)
                self.assertIn(f'strptime({field}, "%Y-%m-%dT%H:%M:%SZ")', query, name)
        self.assertGreaterEqual(parsed, 1)

    def test_existing_added_at_parses_both_precisions(self):
        search = _conf("savedsearches.conf").get("Update OpenCTI Indicators Lookup", "search")
        self.assertIn('strptime(existing_added_at, "%Y-%m-%dT%H:%M:%S.%3NZ")', search)
        self.assertIn('strptime(existing_added_at, "%Y-%m-%dT%H:%M:%SZ")', search)

    def test_kv_sync_searches_parse_every_iso_field_in_both_precisions(self):
        """A whole-second created_at must not give the rebuilt row a null added_at."""
        searches = _conf("savedsearches.conf")
        for stanza in ("Update OpenCTI Indicators Lookup", "Nightly Rebuild OpenCTI Indicators Lookup"):
            search = searches.get(stanza, "search")
            fields = set(re.findall(r'strptime\((\w+), "%Y-%m-%dT%H:%M:%S\.%3NZ"\)', search))
            self.assertIn("created_at", fields, stanza)
            for field in fields:
                with self.subTest(stanza=stanza, field=field):
                    self.assertEqual(
                        search.count(f'strptime({field}, "%Y-%m-%dT%H:%M:%S.%3NZ")'),
                        search.count(f'strptime({field}, "%Y-%m-%dT%H:%M:%SZ")'),
                    )
            self.assertNotIn('match(created_at, "^', search, stanza)


if __name__ == "__main__":
    unittest.main()
