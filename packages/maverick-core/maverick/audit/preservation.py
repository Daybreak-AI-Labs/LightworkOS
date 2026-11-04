"""Read-only preservation gates for broad retention, including disabled ledgers.

The retention stores cannot reliably map every record to a rights-case subject.
Any active case hold therefore blocks the entire workspace's broad purge.
External holds still require the records owner's independent confirmation.

Active eDiscovery matters are deliberately absent from this snapshot.  People
reviewing their own data can read it, and a matter's existence is visible only
to audit access.  Broad purges check matters themselves (see
``maverick.ediscovery.assert_no_active_matters``).
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3


def preservation_snapshot() -> dict:
    from ..paths import current_tenant_id, data_dir
    from ..privacy_rights_orchestration import PrivacyRightsOrchestrationStore

    tenant = current_tenant_id()
    path = data_dir("privacy_automation", "privacy-rights-orchestration.sqlite3")
    gates = []
    legal_holds = 0
    retention_blocks = 0
    if path.exists():
        # Do not initialize a ledger or require its optional feature/key merely
        # to respect a hold that was recorded before the feature was disabled.
        # The connection's own context manager only commits; close it explicitly so
        # the ledger is released when this check returns (Windows keeps it locked).
        with contextlib.closing(
            sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        ) as connection:
            connection.row_factory = sqlite3.Row
            for row in connection.execute("SELECT * FROM rights_cases ORDER BY case_id"):
                payload = PrivacyRightsOrchestrationStore._payload(row, "rights case")
                if payload.get("tenant_id") != tenant:
                    raise RuntimeError("Preservation ledger workspace binding is invalid")
                hold = payload.get("legal_hold")
                blocked = payload.get("retention_blocks_deletion")
                if not isinstance(hold, bool) or not isinstance(blocked, bool):
                    raise RuntimeError("Preservation ledger gates are invalid")
                legal_holds += int(hold)
                retention_blocks += int(blocked)
                if hold or blocked:
                    gates.append([row["case_id"], hold, blocked])
    return {
        "legal_holds": legal_holds, "retention_blocks": retention_blocks,
        "blocked": bool(legal_holds or retention_blocks),
        "revision": hashlib.sha256(json.dumps(gates, sort_keys=True).encode()).hexdigest(),
        "coverage": "All recorded privacy-rights cases in this workspace; external holds require separate confirmation.",
    }
