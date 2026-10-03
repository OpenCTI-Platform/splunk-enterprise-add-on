#!/usr/bin/env python
# encoding = utf-8
"""| openctivalidation [writeback=<bool>]

Prove the IOC validation requests of OpenCTI targeting the Splunk Security
Platform from the hits recorded by openctireporthits (see validation.py).
"""
import sys

import import_declare_test  # noqa: F401  # type: ignore
from splunklib.searchcommands import Configuration, GeneratingCommand, Option, dispatch, validators  # type: ignore

from addon_state import HITS_COLLECTION, VALIDATION_COLLECTION
from command_common import CommandContext
from validation import ValidationProver


@Configuration(type="reporting", distributed=False)
class OpenCTIValidationCommand(GeneratingCommand):
    writeback = Option(
        require=False,
        default=None,
        validate=validators.Boolean(),
        doc="Write the outcomes back to OpenCTI (default: Configuration > Security Platform setting)",
    )

    def generate(self):
        context = CommandContext(self, "openctivalidation")
        writeback = context.settings.validation_writeback if self.writeback is None else self.writeback
        prover = ValidationProver(
            context.client,
            context.detector,
            context.platform,
            context.collection(HITS_COLLECTION),
            context.collection(VALIDATION_COLLECTION),
            grace_minutes=context.settings.validation_grace_minutes,
            writeback=writeback,
            logger=context.logger,
            author_name=context.settings.server_name or "Splunk",
        )
        rows = prover.run()
        if not rows:
            yield {"message": "No IOC validation request targets this Security Platform"}
        for row in rows:
            yield row


dispatch(OpenCTIValidationCommand, sys.argv, sys.stdin, sys.stdout, __name__)
