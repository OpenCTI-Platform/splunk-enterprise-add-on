"""Tests for the alert action plumbing: exit codes (#18)."""
import unittest

from program_fakes import FakeAlertContext, FakeAlertHelper

import alert_common


def _run(handler, helper, context):
    return alert_common.run_alert(helper, "test", handler, context_factory=lambda _helper: context)


class ExitCodeTest(unittest.TestCase):
    """#18: process_event reports failures to Splunk."""

    def test_zero_when_every_result_succeeds(self):
        helper = FakeAlertHelper(events=[{}, {}])
        self.assertEqual(_run(lambda c, e: True, helper, FakeAlertContext(helper)), 0)

    def test_non_zero_when_a_result_fails(self):
        helper = FakeAlertHelper(events=[{}, {}, {}])
        results = iter([True, False, True])
        self.assertEqual(_run(lambda c, e: next(results), helper, FakeAlertContext(helper)), 2)
        self.assertIn("1 of 3 results failed", helper.errors()[-1])

    def test_exception_in_a_result_is_a_failure(self):
        helper = FakeAlertHelper(events=[{"rid": "0"}])

        def boom(context, event):
            raise ValueError("bad result")

        self.assertEqual(_run(boom, helper, FakeAlertContext(helper)), 2)

    def test_unusable_configuration_is_a_failure(self):
        helper = FakeAlertHelper(events=[{}])

        def factory(_helper):
            raise ValueError("OpenCTI URL and API key must be configured")

        self.assertEqual(alert_common.run_alert(helper, "test", lambda c, e: True, context_factory=factory), 2)


class HelperLoggerTest(unittest.TestCase):
    def test_maps_levels(self):
        helper = FakeAlertHelper()
        logger = alert_common.HelperLogger(helper)
        logger.info("i")
        logger.warning("w")
        logger.error("e")
        logger.debug("d")
        self.assertEqual([level for level, _ in helper.logs], ["info", "warning", "error", "debug"])

    def test_parse_labels(self):
        self.assertEqual(alert_common.parse_labels(" a, ,b ,"), ["a", "b"])
        self.assertEqual(alert_common.parse_labels(None), [])


if __name__ == "__main__":
    unittest.main()
