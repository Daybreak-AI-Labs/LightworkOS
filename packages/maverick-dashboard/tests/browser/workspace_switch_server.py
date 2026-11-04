"""Two real workspace stores and one administrator account; synthetic, loopback only."""
from __future__ import annotations

import argparse
import os
import secrets
import tempfile
from pathlib import Path

from fastapi import HTTPException, Request
from server import KEEP_ALIVE_SECONDS, block_outbound, environment, exit_cleanly_on_sigterm


def build(directory: Path, *, fixed: bool = False):
    environment(directory)
    os.environ.pop("MAVERICK_TENANT", None)
    os.environ.pop("MAVERICK_CLIENT_ID", None)
    admin = "user:acceptance-admin@example.test"
    os.environ["MAVERICK_DASHBOARD_ADMINS"] = admin
    path = Path(os.environ["MAVERICK_CONFIG"])
    path.write_text(path.read_text(encoding="utf-8") + "\n[dashboard]\ninvites=true\ninvite_email=false\n", encoding="utf-8")
    block_outbound()
    from maverick import config
    from maverick.paths import tenant_scope
    from maverick.tenant.registry import create_tenant
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import (
        auth,
        local_passphrases,
        rbac,
        subject_directory,
        workspace_tenants,
    )

    config.reset_config_cache()
    rbac.set_role(admin, "admin")
    tasks, approvals = {}, {}
    for tenant, label in (("workspace-a", "Acceptance workspace A"), ("workspace-b", "Acceptance workspace B")):
        create_tenant(tenant, display_name=label)
        rbac.set_tenant_role(tenant, admin, "admin", actor=admin)
        with tenant_scope(tenant=tenant):
            world = dashboard._world()
            goal = world.create_goal(label + " task", owner=admin)
            world.set_goal_status(goal, "done", result=label + " captured result")
            tasks[tenant] = goal
            approvals[tenant] = world.create_approval("synthetic-review", risk="high", scope=label,
                                                      detail="Deny-only fixture; never dispatches an effect.",
                                                      requested_by=admin)
    workspace_tenants.set_selection(admin, "workspace-a")
    # An existing account is never invited (accepting would replace its
    # passphrase), so the administrator signs in with the passphrase they have.
    passphrase = secrets.token_urlsafe(24)
    local_passphrases.store(local_passphrases.prepare("acceptance-admin@example.test", passphrase), tenant="workspace-a")
    unassigned = "unassigned@example.test"
    subject_directory.record_login(unassigned, [unassigned])
    if fixed:
        os.environ["MAVERICK_TENANT"] = "workspace-a"
    print("FIXTURE_ADMIN_PASSPHRASE=" + passphrase, flush=True)

    @dashboard.app.get("/__workspace_acceptance", include_in_schema=False)
    def state(request: Request):
        if auth.caller_principal(request) != admin:
            raise HTTPException(403, "Synthetic fixture administrator required")
        states = {}
        for tenant, approval_id in approvals.items():
            with tenant_scope(tenant=tenant):
                states[tenant] = dashboard._world().get_approval(approval_id).status
        return {"synthetic": True, "outbound_calls": "blocked", "tasks": tasks, "approvals": approvals,
                "approval_states": states, "selected": workspace_tenants.get_selection(admin),
                "unassigned": "user:" + unassigned, "unassigned_role": rbac.list_users().get("user:" + unassigned),
                "fixed": fixed}

    return dashboard.app


if __name__ == "__main__":
    import uvicorn
    exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--fixed", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="lightwork-workspace-acceptance-") as temporary:
        uvicorn.run(build(Path(temporary), fixed=args.fixed), host="127.0.0.1", port=args.port, log_level="warning",
                    timeout_keep_alive=KEEP_ALIVE_SECONDS)
