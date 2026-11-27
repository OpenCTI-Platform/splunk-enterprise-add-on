"""
Tests for the "Revoked indicators" tile of the Monitoring Dashboard (#90).

From the repository root:
    python3 -m unittest discover -s tests -p "test_dashboard_revoked_tile.py" -v
"""
import json
import os
import unittest

DASHBOARD = os.path.join(
    os.path.dirname(__file__), "..", "TA-opencti-for-splunk-enterprise", "custom_dashboard.json"
)


class TestRevokedIndicatorsTile(unittest.TestCase):
    def test_query_counts_only_revoked_indicators(self):
        with open(DASHBOARD, encoding="utf-8") as handle:
            data_sources = json.load(handle)["dataSources"]
        query = data_sources["ds_z5ZhhLJx_ds_PYxsaacd"]["options"]["query"]
        self.assertEqual(
            query,
            "| inputlookup opencti_indicators | search revoked=1 OR revoked=true"
            " | stats count AS revoked",
        )


if __name__ == "__main__":
    unittest.main()
