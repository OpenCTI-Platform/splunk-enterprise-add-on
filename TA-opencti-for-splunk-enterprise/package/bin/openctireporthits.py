#!/usr/bin/env python
# encoding = utf-8
"""| openctireporthits [id_field=<field>] [count_field=<field>] [first_field=<field>] [last_field=<field>]

Report indicator hits to OpenCTI on the Splunk Security Platform (see hits.py).
"""
import sys

import import_declare_test  # noqa: F401  # type: ignore
from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch  # type: ignore

from addon_state import HITS_COLLECTION
from command_common import CommandContext
from hits import HitReporter, STATUS_ERROR, STATUS_REPORTED_AS_SIGHTING


@Configuration()
class OpenCTIReportHitsCommand(EventingCommand):
    id_field = Option(require=False, default="indicator_id", doc="Field holding the indicator STIX id")
    count_field = Option(require=False, default="hit_count", doc="Field holding the number of hits")
    first_field = Option(require=False, default="first_hit", doc="Field holding the first hit time (epoch or ISO)")
    last_field = Option(require=False, default="last_hit", doc="Field holding the last hit time (epoch or ISO)")

    def __init__(self):
        super().__init__()
        self._context = None
        self._reporter = None

    def transform(self, records):
        if self._reporter is None:
            self._context = CommandContext(self, "openctireporthits")
            self._reporter = HitReporter(
                self._context.client,
                self._context.detector,
                self._context.platform,
                self._context.collection(HITS_COLLECTION),
                logger=self._context.logger,
                author_name=self._context.settings.server_name or "Splunk",
            )
        reporter = self._reporter
        fields = {
            "id_field": self.id_field or "indicator_id",
            "count_field": self.count_field or "hit_count",
            "first_field": self.first_field or "first_hit",
            "last_field": self.last_field or "last_hit",
        }
        # Buffer the chunk: fallback sightings are sent in one bundle at the
        # end, and their status depends on that call.
        output = []
        for record in records:
            record.update(reporter.report(record, **fields))
            output.append(record)
        failed = reporter.flush()
        if failed:
            id_field = fields["id_field"]
            for record in output:
                message = failed.get(str(record.get(id_field) or "").strip())
                if message is not None and record.get("opencti_hit_status") == STATUS_REPORTED_AS_SIGHTING:
                    record["opencti_hit_status"] = STATUS_ERROR
                    record["opencti_hit_message"] = message
        for record in output:
            yield record


dispatch(OpenCTIReportHitsCommand, sys.argv, sys.stdin, sys.stdout, __name__)
