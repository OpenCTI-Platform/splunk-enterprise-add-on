#!/usr/bin/env python
# encoding = utf-8
"""... | openctiprovides [prune=<bool>]

Declare the telemetry of Splunk to the OpenCTI defense matrix (see provides.py).
Input rows: data_component, sources, event_count.
"""
import sys

import import_declare_test  # noqa: F401  # type: ignore
from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch, validators  # type: ignore

from addon_state import PROVIDES_COLLECTION
from command_common import CommandContext
from provides import ProvidesPublisher


@Configuration()
class OpenCTIProvidesCommand(EventingCommand):
    prune = Option(
        require=False,
        default=False,
        validate=validators.Boolean(),
        doc="Delete the provides relationships declared earlier for data components absent from this inventory",
    )

    def __init__(self):
        super().__init__()
        self._seen = set()
        self._publisher = None

    def transform(self, records):
        if self._publisher is None:
            context = CommandContext(self, "openctiprovides")
            self._publisher = ProvidesPublisher(
                context.client,
                context.detector,
                context.platform,
                context.collection(PROVIDES_COLLECTION),
                logger=context.logger,
            )
        records = list(records)
        finished = bool(getattr(self, "_finished", True))
        rows = self._publisher.publish(records, prune=bool(self.prune) and finished, known_keys=self._seen)
        self._seen.update((row.get("data_component") or "").lower() for row in rows)
        for row in rows:
            yield row


dispatch(OpenCTIProvidesCommand, sys.argv, sys.stdin, sys.stdout, __name__)
