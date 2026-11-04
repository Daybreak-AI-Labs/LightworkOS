"""Disposable local invitation/lifecycle qualification; never a product entry point.

The administrator already has a passphrase and signs in with it; the four new
colleagues join through real single-use invites. Everyone gets signed cookies.
Source evidence and the provider token exchange are synthetic; every outbound
socket is blocked.
"""
from __future__ import annotations

import argparse
import os
import secrets
import tempfile
from pathlib import Path

from fastapi import HTTPException, Request
from server import (
    KEEP_ALIVE_SECONDS,
    block_outbound,
    environment,
    exit_cleanly_on_sigterm,
    fake_connection_authorization,
)


def build(directory):
    environment(directory)
    path = Path(os.environ["MAVERICK_CONFIG"])
    settings = path.read_text(encoding="utf-8").replace(
        "[features]", "[features]\npersonal_data_controls=true\nemployee_departures=true",
    ).replace("[connections]\nenable = true", "[connections]\nenable = true"
              "\nallow_self_connect=true\nself_connect_profiles='google-drive'")
    # default_role keeps the global fallback view-only (deny by default).
    settings += "\n[dashboard]\ninvites=true\ninvite_email=false\ndefault_role=\"viewer\"\n[oauth]\nvault=true\n"
    path.write_text(settings, encoding="utf-8")
    os.environ["MAVERICK_TENANT"] = "browser-enterprise"
    os.environ["MAVERICK_DASHBOARD_ADMINS"] = "user:admin@browser.example.test"
    block_outbound()

    from maverick.tenant import registry

    # Provision before app imports initialize tenant-bound stores. Namespace
    # reservations are deliberately immutable, including in disposable homes.
    tenant, admin = "browser-enterprise", "user:admin@browser.example.test"
    registry.create_tenant(tenant, display_name="Synthetic enterprise workspace")

    from maverick import config, connection_oauth, world_model
    from maverick.paths import tenant_scope
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import auth, invites, local_passphrases, rbac, session_revocation

    config.reset_config_cache()
    employee, manager = "employee@browser.example.test", "manager@browser.example.test"
    auditor, tenant_admin = "auditor@browser.example.test", "workspace-admin@browser.example.test"
    rbac.set_role(admin, "admin")
    rbac.set_tenant_role(tenant, admin, "admin", actor=admin)
    # An existing account is never invited (accepting would replace its
    # passphrase), so the administrator signs in with the passphrase they have.
    administrator_passphrase = secrets.token_urlsafe(24)
    local_passphrases.store(local_passphrases.prepare("admin@browser.example.test", administrator_passphrase), tenant=tenant)
    print("FIXTURE_ADMIN_PASSPHRASE=" + administrator_passphrase, flush=True)
    links = {}
    for email, role in ((employee, "operator"), (manager, "operator"), (auditor, "auditor"), (tenant_admin, "admin")):
        # Each colleague is new here. With the view-only global fallback, an
        # accepted invite grants only its role in this exact workspace, never
        # installation controls.
        _, token = invites.create_invite(email, role, created_by=admin, tenant=tenant)
        links[email.split("@")[0]] = "/auth/invite/" + token
    _, expired = invites.create_invite("expired@browser.example.test", "viewer", created_by=admin, ttl_hours=-1, tenant=tenant)
    links["expired"] = "/auth/invite/" + expired
    world_model.DEFAULT_DB = directory / "tenants" / tenant / "world.db"
    world_model.DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
    dashboard._world_cache.clear()
    exchanges = fake_connection_authorization(connection_oauth)
    with tenant_scope(tenant=tenant):
        world = dashboard._world()
        project = world.create_project("Employee evidence review", owner="user:" + employee)
        goal = world.create_goal("Employee private evidence task", "Synthetic private brief; not model-generated.", owner="user:" + employee, project_id=project)
        world.set_goal_status(goal, "done", result="Synthetic captured artifact [1]. Fixture evidence only; AI quality and live retrieval are unqualified.")
        connection_oauth.save_workspace_application(admin, provider="google", client_id="synthetic-enterprise-client", client_secret="synthetic-enterprise-secret", expected_revision="")
    from fixture_knowledge_access import install
    install(dashboard.app, tenant, "user:" + employee)

    def require_fixture_admin(request):
        if auth.caller_principal(request) != admin:
            raise HTTPException(403, "Synthetic fixture administrator required")

    @dashboard.app.get("/__enterprise_fixture", include_in_schema=False)
    def state(request: Request):
        require_fixture_admin(request)
        return {"synthetic": True, "invites": links, "goal": goal, "project": project,
                "employee": "user:" + employee, "manager": "user:" + manager,
                "admin": admin, "connection_exchanges": len(exchanges), "outbound_calls": "blocked"}

    @dashboard.app.post("/__enterprise_fixture/revoke-session", include_in_schema=False)
    def revoke(request: Request):
        require_fixture_admin(request)
        session_revocation.revoke_principal(auditor)
        return {"synthetic": True, "revoked": auditor}

    return dashboard.app


def main():
    import uvicorn
    exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="lightwork-enterprise-browser-") as temporary:
        app = build(Path(temporary))
        print("Synthetic enterprise fixture ready on", args.port, flush=True)
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning", timeout_keep_alive=KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
