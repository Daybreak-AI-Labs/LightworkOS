"""Disposable native consent request and allowance journeys; synthetic records only."""
from __future__ import annotations

import argparse
import hashlib
import tempfile
import time
from pathlib import Path

import server
from fastapi import HTTPException, Request


def main():
    server.exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.CONFIG = server.CONFIG.replace('[features]', '[features]\ncopilot_operations = true').replace(
        'operation_families = ["learning", "commitments"]', 'operation_families = ["learning", "tasks"]')
    server.CONFIG += '\n[consent_preferences.bulk_jobs]\nenable = true\ninitial_credits = 100\n[consent_preferences.limits]\nprofile_page_size = 2\nreceipt_page_size = 2\n'
    with tempfile.TemporaryDirectory(prefix="lightwork-consent-creation-") as temporary:
        directory = Path(temporary)
        server.environment(directory)
        server.block_outbound()
        from maverick.paths import tenant_scope
        from maverick.tenant.registry import create_tenant

        create_tenant("browser-workspace", display_name="Synthetic consent workspace")
        app = server.build_app(directory)
        from maverick.consent_bulk_jobs import ConsentBulkJobStore
        from maverick.consent_preferences import ConsentContext, PreferenceChoice
        from maverick_dashboard import auth, consent_preferences_api
        from maverick_dashboard.consent_bulk_jobs_composition import _default_job_store_path

        tenant = "browser-workspace"
        with tenant_scope(tenant=tenant):
            store = consent_preferences_api._store(tenant)
            store.publish_policy(tenant,"customer-outreach",1,{"email-marketing":"consent"},
                hashlib.sha256(b"synthetic policy").hexdigest(),time.time()-100)
            for name in ("Customer-A","Customer-B","Customer-C","Customer-D"):
                store.create_profile(tenant,name,"known",hashlib.sha256(name.encode()).hexdigest(),"fixture-"+name)
            receipts = []
            for index in range(5):
                receipts.append(store.record_preferences(tenant,"Customer-A","customer-outreach",1,
                    ConsentContext(jurisdiction="us",country_code="US"),
                    [PreferenceChoice(purpose_id="email-marketing",action="grant",expires_at=time.time()+86400)],
                    expected_revision=index,idempotency_key="fixture-choice-"+str(index),actor_sha256="a"*64))

        def owner(request):
            if auth.caller_principal(request) != "user:browser-reviewer":
                raise HTTPException(403,"Synthetic owner required")

        @app.get("/__browser_fixture/consent-creation", include_in_schema=False)
        def state(request: Request):
            owner(request)
            jobs = ConsentBulkJobStore(_default_job_store_path(tenant_id=tenant,request=request))
            rows = jobs.list_jobs(tenant,limit=100)["jobs"]
            with store._connect() as connection:
                selected = [dict(row) for row in connection.execute(
                    "SELECT profile_id,revision FROM consent_profiles WHERE tenant=? ORDER BY profile_id",(tenant,)).fetchall()]
                lifecycle = [dict(row) for row in connection.execute(
                    "SELECT * FROM consent_receipt_lifecycle WHERE tenant=?",(tenant,)).fetchall()]
            return {"jobs":rows,"allowance":jobs.credit_detail(tenant),"profiles":selected,
                "choice_changes":len(lifecycle),"outbound_calls":0}

        @app.post("/__browser_fixture/consent-creation/change-profile", include_in_schema=False)
        def change(request: Request):
            owner(request)
            with store._connect() as connection:
                connection.execute("UPDATE consent_profiles SET revision=revision+1 WHERE tenant=? AND profile_id=?",(tenant,"Customer-A"))
            return {"changed":True}

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="critical", timeout_keep_alive=server.KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
