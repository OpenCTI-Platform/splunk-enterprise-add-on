#!/usr/bin/env python
# encoding = utf-8
"""| openctireconcile [mode=deployments|knowledge] [refresh=<bool>]

Reconcile the opencti_indicators KV Store with OpenCTI (see reconciliation.py).
"""
import sys

import import_declare_test  # noqa: F401  # type: ignore
from splunklib.searchcommands import Configuration, GeneratingCommand, Option, dispatch, validators  # type: ignore

from addon_state import DEPLOYMENTS_COLLECTION
from command_common import CommandContext
from constants import INDICATORS_KVSTORE_NAME
from deployment_reporter import DeploymentReporter
from reconciliation import Reconciler


@Configuration(type="reporting", distributed=False)
class OpenCTIReconcileCommand(GeneratingCommand):
    mode = Option(
        require=False,
        default="deployments",
        validate=validators.Set("deployments", "knowledge"),
        doc="deployments: repair the deployment drift; knowledge: refresh provenance and pulse fields",
    )
    refresh = Option(
        require=False,
        default=False,
        validate=validators.Boolean(),
        doc="Re-report indicators already in sync (refreshes last_sync_at in OpenCTI)",
    )

    def generate(self):
        context = CommandContext(self, "openctireconcile")
        platform = context.platform
        deployments = context.collection(DEPLOYMENTS_COLLECTION)
        reporter = DeploymentReporter(
            context.client,
            context.detector,
            (platform or {}).get("id"),
            batch_size=context.settings.writeback_batch_size,
            rate_per_minute=context.settings.writeback_rate_limit,
            logger=context.logger,
            state_sink=deployments.upsert,
            on_platform_missing=context.invalidate_platform,
        )
        reconciler = Reconciler(
            context.client,
            context.detector,
            platform,
            context.collection(INDICATORS_KVSTORE_NAME),
            reporter,
            logger=context.logger,
            collection_name=INDICATORS_KVSTORE_NAME,
        )
        if (self.mode or "deployments") == "knowledge":
            rows = reconciler.refresh_knowledge()
        else:
            rows = reconciler.reconcile(refresh=bool(self.refresh))
        for row in rows:
            yield row


dispatch(OpenCTIReconcileCommand, sys.argv, sys.stdin, sys.stdout, __name__)
