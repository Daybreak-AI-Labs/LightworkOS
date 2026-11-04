"""Run the complete synthetic workflow and optional loopback dashboard.

Run from an installed checkout: python3 scripts/demo_vendor_onboarding.py
  --state-dir <new-empty-directory> [--report report.json] [--serve --port 8766]
No model calls or provider connectivity. All effects go to local fake adapters.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import asdict
from pathlib import Path

CONFIG = '''[vendor_onboarding]
enable = true
resource_owner = "procurement"
document_connection = "gdrive"
ticket_connection = "jira"
[vendor_management]
enable = true
[ai_vendor_risk]
enable = true
[model_risk_assurance]
enable = true
[evidence_graph]
enable = true
[flows]
enable = true
[enterprise]
enable = false
'''
EVIDENCE = b'''INTERNALLY AUTHORED SYNTHETIC MATERIAL - Northstar Support AI
Version 1, security response for a restricted support-drafting pilot.
We do not train models on customer data. Customer data is not used for training.
Data is encrypted at rest and in transit. Records are deleted after 30 days.
An administrator can disable processing. Operators review all generated replies.
Training data provenance and the complete subprocessor list are not yet documented.
These statements are unverified vendor assertions for an offline test.
'''


def prepare_environment(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise ValueError("Use a new empty state directory; existing records are preserved")
    path.mkdir(parents=True, exist_ok=True)
    (path / "config.toml").write_text(CONFIG, encoding="utf-8")
    os.environ.update({
        "MAVERICK_HOME": str(path), "MAVERICK_CONFIG": str(path / "config.toml"),
        "MAVERICK_TENANT": "synthetic-demo", "MAVERICK_PROFILE": "standard",
        "MAVERICK_ENTERPRISE": "0", "MAVERICK_ENCRYPT_AT_REST": "1",
    })
    # This executable never imports or invokes a live provider adapter.


def complete_case(service, context, row):
    row = service.collect_evidence(context, row["id"], row["revision"])
    row = service.assess(context, row["id"], row["revision"])
    qid = next(iter(row["assessment"]["answers"]))
    row = service.review(context, row["id"], row["revision"], "approved",
        "Synthetic reviewer accepts the restricted pilot and documents unresolved gaps.",
        corrections={qid: {"answer": "unknown", "note": "Require independent verification."}})
    row = service.prepare_action(context, row["id"], row["revision"])
    row = service.approve_action(
        context,
        row["id"],
        row["revision"],
        row["operation"]["approval_card"]["binding_sha256"],
    )
    row = service.execute(context, row["id"])
    if row["stage"] == "reconciliation_required":
        row = service.reconcile(context, row["id"])
    return service.accept(context, row["id"], row["revision"], True,
                           "Synthetic customer acceptance for this bounded pilot.")


def evolution_example(context, service, case, policy, now):
    from maverick.vendor_evidence_evolution import (
        BINDINGS,
        EvidenceRenewalEvolution,
        RenewalInputs,
    )

    evolution = EvidenceRenewalEvolution(policy, clock=lambda: now[0])
    due = case["outcome"]["renewal_due_at"]
    training, observations = [], []
    for offset, label in [(-300, "fresh"), (-50, "fresh"), (100, "renewal_due")]:
        now[0] = due + offset
        record = evolution.observe_case(context, service, case["id"], label,
            rationale="Human-reviewed synthetic timestep from this accepted case and current fake provider evidence.")
        training.append(record["id"])
        observations.append(record)
    base = dict(asdict(RenewalInputs(**observations[0]["inputs"])), now=due - 100)
    candidate = evolution.propose(context, training, bindings=BINDINGS,
                                  rationale="Review exact due_at and now bindings; no external action.")
    cases = [
        ("held-fresh", "held_out", dict(base, now=due - 200), "fresh", BINDINGS),
        ("held-due", "held_out", dict(base, now=due + 200), "renewal_due", BINDINGS),
        ("changed", "changed_inputs", dict(base, now=due + 400), "renewal_due", BINDINGS),
        ("bad-binding", "invalid_bindings", dict(base, now=due - 10), "human_fallback", {"due_at": "now", "now": "due_at"}),
        ("downstream", "changed_downstream", dict(base, downstream_version="2"), "human_fallback", BINDINGS),
        ("bad-time", "invalid_inputs", dict(base, now="not-a-time"), "human_fallback", BINDINGS),
    ]
    evaluated = evolution.evaluate(context, candidate["id"], [
        {"id": key, "category": category, "inputs": values, "expected": label,
         "bindings": bindings, "material": "internally_authored_synthetic"}
        for key, category, values, label, bindings in cases
    ])
    before = evolution.run_for_case(context, service, case["id"])
    activation = evolution.promote(context, candidate["id"], evaluated["revision"],
                                    rationale="Synthetic human promotion after all held-out cases pass.")
    now[0] = due + 1
    after = evolution.run_for_case(context, service, case["id"])
    rolled_back = evolution.rollback(context, activation["revision"],
                                     rationale="Exercise definition rollback without reversing a ticket.")
    fallback = evolution.run_for_case(context, service, case["id"])
    assert before["classification"] == "human_fallback"
    assert after["classification"] == "renewal_due"
    assert fallback["classification"] == "human_fallback"
    return {"training_observations": len(training), "candidate_id": candidate["id"],
            "training_source_provenance": [
                {key: observation[key] for key in (
                    "id", "capture_origin", "source_case_id", "source_case_revision",
                    "source_workflow_version", "evidence_sha256", "assessment_id",
                    "assessment_revision", "assessment_sha256", "source_provenance_sha256",
                )} for observation in observations
            ],
            "evaluation": evaluated["evaluation"], "before_promotion": before,
            "after_promotion": after, "rollback_revision": rolled_back["revision"],
            "after_rollback": fallback}


def run_demo():
    from maverick.governed_operations import ServiceContext
    from maverick.vendor_onboarding import VendorOnboardingService
    from maverick.vendor_onboarding_adapters import (
        GOOGLE_DOC_MIME,
        EvidenceDocument,
        FakeGoogleDriveEvidence,
        FakeJiraTickets,
    )

    demo_started = time.perf_counter()
    now = [time.time()]
    ctx = ServiceContext("synthetic-demo", "user:synthetic-reviewer", "procurement",
                         "user:synthetic-reviewer", "jira", human=True)

    def policy(candidate, capability, resource):
        return candidate.binding() == ctx.binding() and resource != "forbidden"

    docs = FakeGoogleDriveEvidence({(ctx.tenant, "security-paper"): EvidenceDocument(
        "security-paper", "v1", now[0] - 86400, EVIDENCE,
    )})
    fixtures = Path(__file__).parent / "acceptance/fixtures/vendor-documents"
    docs.documents[(ctx.tenant, "native-policy")] = EvidenceDocument(
        "native-policy", "v1", now[0] - 86400,
        (fixtures / "conflicting-provenance.txt").read_bytes(), GOOGLE_DOC_MIME, "text/plain",
    )
    tickets = FakeJiraTickets()
    service = VendorOnboardingService(docs, tickets, policy, clock=lambda: now[0])
    initial = service.intake(ctx, "Synthetic Northstar Support AI",
        "security-paper", "VEND", "Draft support replies for human review", freshness_days=30,
        document_ids=["security-paper", "native-policy"])
    initial = service.upload_document(ctx, initial["id"], initial["revision"],
        content=(fixtures / "northstar-policy.pdf").read_bytes(), name="Synthetic Northstar policy.pdf",
        mime="application/pdf", document_date=now[0] - 86400)
    original = complete_case(service, ctx, initial)
    assert original["assessment"]["answers"]["aiv_training_data"]["answer"] == "unknown"
    improvement = evolution_example(ctx, service, original, policy, now)
    # New evidence, a separate assessment and a separate reviewed ticket.
    docs.documents[(ctx.tenant, "security-paper")] = EvidenceDocument(
        "security-paper", "v2", now[0] - 1,
        EVIDENCE.replace(b"Version 1", b"Version 2") + b"\nRenewal adds a current retention statement.\n",
    )
    docs.documents[(ctx.tenant, "native-policy")] = EvidenceDocument(
        "native-policy", "v2", now[0] - 1,
        b"Synthetic renewal. Model provenance is documented with provider and version.\n"
        b"Training data sources are documented and licensed.", GOOGLE_DOC_MIME, "text/plain",
    )
    renewal = service.intake(ctx, original["vendor_name"],
        "security-paper", "VEND", "Renew the restricted support-drafting pilot", freshness_days=30,
        renewal_of=original["id"], document_ids=["security-paper", "native-policy"])
    # The retained upload has its old asserted date. A new review explicitly
    # removes and replaces it; copying a case never refreshes a document's age.
    renewal = service.set_documents(ctx, renewal["id"], renewal["revision"], renewal["document_ids"], [])
    renewal = service.upload_document(ctx, renewal["id"], renewal["revision"],
        content=(fixtures / "northstar-policy.pdf").read_bytes(), name="Synthetic renewed policy.pdf",
        mime="application/pdf", document_date=now[0] - 1)
    renewal = complete_case(service, ctx, renewal)
    tickets.timeout_after_success = True
    ambiguous = complete_case(service, ctx, service.intake(ctx, "Synthetic Harbor Document AI",
        "security-paper", "VEND", "Demonstrate a lost provider response and read-only reconciliation"))
    assert tickets.creates == 3
    assert ambiguous["operation"]["external_confirmation"]["reconciled"] is True
    report = {"status": "passed_offline_synthetic", "provider_calls": "local fake adapters only",
        "live_acceptance": "unverified", "model_calls": 0, "execution_cost_usd": 0,
        "elapsed_wall_seconds": time.perf_counter() - demo_started,
        "case_clock": "simulated logical clock; case elapsed times are not customer labor measurements",
        "cases": [original, renewal, ambiguous], "ticket_creates": tickets.creates,
        "evolution": improvement,
        "document_intake": {"formats": ["UTF-8 text", "native Google Docs text export (fake provider)", "digital PDF"],
            "documents_in_initial_case": len(original["evidence"]["documents"]),
            "original_training_data_answer": original["assessment"]["answers"]["aiv_training_data"]["answer"],
            "renewal_training_data_answer": renewal["assessment"]["answers"]["aiv_training_data"]["answer"],
            "renewal_changes": renewal["evidence"]["changes"],
            "pdf_cited_pages": sorted({page for item in original["evidence"]["documents"]
                for answer in item["extracted"]["answers"].values()
                for citation in answer["citations"] for page in citation.get("pages", [])})},
        "limitations": ["No measured customer savings, live model quality, provider billing or live acceptance.",
                        "Review time is unmeasured in this scripted demonstration.",
                        "Definition rollback does not reverse external effects."]}
    return report, service, ctx


def serve(service, ctx, port):
    import uvicorn
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.staticfiles import StaticFiles
    from maverick.paths import tenant_scope
    from maverick_dashboard.app import _STATIC_DIR, templates
    from maverick_dashboard.vendor_onboarding_api import router
    from maverick_dashboard.vendor_onboarding_composition import WorkflowBinding
    from maverick_dashboard.vendor_onboarding_page import create_vendor_onboarding_page_router

    demo = FastAPI(title="Lightwork offline vendor demonstration")
    demo.state.vendor_onboarding_demo = True
    demo.state.vendor_onboarding_binding_factory = lambda request: WorkflowBinding(service, ctx)

    @demo.middleware("http")
    async def local_demo_boundary(request: Request, call_next):
        if request.method != "GET" and request.headers.get("origin") != f"http://127.0.0.1:{port}":
            return JSONResponse({"detail": "Same-origin local demonstration only"}, status_code=403)
        with tenant_scope(tenant=ctx.tenant):
            response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    demo.include_router(router, prefix="/api/v1")
    demo.include_router(create_vendor_onboarding_page_router(templates))
    demo.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
    print(f"Offline dashboard: http://127.0.0.1:{port}/third-party/vendor-onboarding", flush=True)
    uvicorn.run(demo, host="127.0.0.1", port=port, log_level="warning")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    prepare_environment(args.state_dir.resolve())
    report, service, ctx = run_demo()
    output = args.report or args.state_dir / "report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({"status": report["status"], "ticket_creates": report["ticket_creates"],
        "evaluation_cases": report["evolution"]["evaluation"]["n"], "report": str(output.resolve())}))
    if args.serve:
        serve(service, ctx, args.port)


if __name__ == "__main__":
    main()
