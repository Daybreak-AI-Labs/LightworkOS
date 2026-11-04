"""Isolated native signing-secret publication and interrupted-history journey."""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

import server
from fastapi import HTTPException, Request


class SyntheticProcessInterruption(BaseException):
    """Bypass native rollback, as process interruption does after publication."""


def main():
    server.exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.CONFIG = server.CONFIG.replace('[features]', '[features]\ncopilot_operations = true').replace(
        'operation_families = ["learning", "commitments"]', 'operation_families = ["learning", "commitments", "connections"]') + '\n[audit]\nsign = true\n'
    with tempfile.TemporaryDirectory(prefix="lightwork-webhook-recovery-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        os.environ["MAVERICK_INBOUND_WEBHOOK_SECRET"] = "synthetic-fixture-control-key"  # pragma: allowlist secret
        server.block_outbound()
        app = server.build_app(directory)
        from maverick import audit, config
        from maverick_dashboard import auth, settings_store, webhook_settings
        from maverick_dashboard import webhook_settings_recovery as recovery

        mode, writes = {"next": "", "refuse": False, "receipt": False}, []
        original_record, original_write = webhook_settings._record, settings_store._write
        original_completed = recovery.completed

        def write(data):
            writes.append("native settings publication")
            return original_write(data)

        def record(principal, action, before, after, identity, phase):
            if phase == "confirmed" and mode["next"]:
                failure, mode["next"] = mode["next"], ""
                if failure == "interrupt":
                    raise SyntheticProcessInterruption("Synthetic interrupted process after local publication")
                raise webhook_settings.WebhookSettingsUnavailable("Synthetic activity outage; publication rolled back")
            if phase.startswith("reconciled") and mode["refuse"]:
                mode["refuse"] = False
                raise webhook_settings.WebhookSettingsUnavailable("Synthetic refused recovery activity")
            return original_record(principal, action, before, after, identity, phase)

        settings_store._write, webhook_settings._record = write, record

        def completed(row, after, outcome):
            if mode["receipt"]:
                mode["receipt"] = False
                raise RuntimeError("Synthetic lost local receipt after accepted activity")
            return original_completed(row, after, outcome)

        recovery.completed = completed

        def owner(request):
            auth.require_global_permission(request, "admin")
            if auth.caller_principal(request) != "user:browser-reviewer":
                raise HTTPException(403, "Only the synthetic owner can control this fixture.")

        @app.post("/__browser_fixture/webhook-recovery/arm", include_in_schema=False)
        async def arm(request: Request):
            owner(request)
            body = await request.json()
            if body.get("mode") in {"interrupt", "rollback"}:
                mode["next"] = body["mode"]
            elif body.get("mode") == "refuse":
                mode["refuse"] = True
            elif body.get("mode") == "receipt":
                mode["receipt"] = True
            elif body.get("mode") == "external":
                os.environ["MAVERICK_WEBHOOK_SECRET"] = "synthetic-fixture-external-key"  # pragma: allowlist secret -- synthetic test value
                config.reset_config_cache()
            else:
                raise HTTPException(422, "Choose a synthetic fixture mode.")
            return {"synthetic": True}

        @app.get("/__browser_fixture/webhook-recovery/state", include_in_schema=False)
        def state(request: Request):
            owner(request)
            rows = [row for row in audit.global_audit_log().tail(1000) if row.get("section") == "webhooks" and row.get("key") == "secret"]
            journals = recovery._rows()
            return {"writes": len(writes), "events": rows, "signed": audit.global_audit_log().signing_enabled,
                "all_journals_encrypted": all(path.read_bytes().startswith(b"MVKBND1\n") for path in recovery._directory().glob("*.enc")),
                "completed_material_removed": all(not {"before", "target", "target_outbound", "publication"}.intersection(row) for row in journals if row["state"] == "completed"),
                "pending": sum(row["state"] != "completed" for row in journals)}

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="critical", timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
