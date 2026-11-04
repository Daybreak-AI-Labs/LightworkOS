"""Request-bound starter-team controls shared by the page and Copilot."""
from __future__ import annotations

import csv
import io
import json
import math
import secrets
import time
from datetime import date
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest, shoring
from maverick.governed_operations import ServiceContext, digest
from maverick.paths import current_tenant_id_strict
from pydantic import ConfigDict, Field

from . import auth
from .product_operations import StrictInput

router = APIRouter(prefix="/api/v1/starter-teams", tags=["starter-teams"])
PURPOSE = "lightwork.starter-team-review.v1"
TTL = 600
NOTICE = ("Samples and record checks prepare findings without calling an AI service or opening sources. "
          "Specialist workflows have a separate review and budget. Provider access and business outcomes "
          "still require qualification. The setup cadence records a preference; it does not start recurring work.")
PUBLIC_INPUT_ERRORS = frozenset({
    "A selected specialist is unavailable; review its setup in Agent Factory",
    "A selected specialist needs setup in Agent Factory before it can run",
    "Configure an authorized AI provider before running specialists",
    "Complete the evidence preparation before reviewing specialist work",
    "This case uses an older team definition; prepare a new case",
    "Bundled samples do not start paid specialists; prepare a case from approved workspace evidence",
    "Resume this team before reviewing specialist work",
    "This case already has different reviewed runtime authority; prepare a new case",
    "The runtime review expired or the team is paused; no work was dispatched",
    "Specialist setup or capability changed after review",
    "This team is paused; subsequent specialists will not start",
    "The evidence handoff exceeds the specialist input limit",
})


class SetupInput(StrictInput):
    team_id: str = Field(min_length=1, max_length=80)
    owner_label: str = Field(min_length=1, max_length=120)
    scope: str = Field(min_length=1, max_length=1000)
    cadence: Literal["manual", "daily", "weekly", "monthly"] = "manual"
    max_rows: int = Field(default=250, ge=1, le=1000)


class SampleInput(StrictInput):
    setup_id: str = Field(min_length=1, max_length=80)


class RecordsInput(SampleInput):
    as_of: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    tables: dict[str, str] = Field(min_length=1, max_length=12)


class PauseInput(SampleInput):
    paused: bool


class RuntimeInput(StrictInput):
    case_id: str = Field(min_length=1, max_length=80)
    max_dollars: float = Field(gt=0, le=100)
    max_wall_seconds: int = Field(ge=30, le=3600)


class ReviewInput(StrictInput):
    action: Literal["setup", "sample", "inputs", "pause", "runtime"]
    arguments: dict = Field(max_length=12)
    expected_context: str = Field(pattern=r"^[a-f0-9]{64}$")


class TokenInput(StrictInput):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2_000_000)
    confirmed: bool = False


INPUTS = {"setup": SetupInput, "sample": SampleInput, "inputs": RecordsInput, "pause": PauseInput, "runtime": RuntimeInput}


def context(request: Request) -> ServiceContext:
    """Resolve identity, current workspace, role and budget on every boundary."""
    from maverick import config
    from maverick.tenant.registry import TenantSuspended, assert_tenant_active

    from . import workspace_tenants
    from .vendor_onboarding_composition import (
        _budget_authority,
        _role_authority,
        _workspace_authority,
    )

    auth.require_permission(request, "operate")
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Workspace settings are unavailable. Restore access and reload.")
    if not shoring.enabled():
        raise HTTPException(409, "Autonomous shoring is turned off. Open its settings to continue.")
    tenant = current_tenant_id_strict()
    actor = auth.caller_principal(request)
    role = auth.caller_role(request)
    if not tenant:
        raise HTTPException(409, "Choose a workspace before opening starter teams.")
    if not actor or not role:
        raise HTTPException(403, "Sign in with permission to operate this workspace.")
    try:
        assert_tenant_active(tenant)
        source = getattr(request.state, "workspace_tenant_source", "")
        if source == "principal_selection" and not workspace_tenants.principal_can_select(actor, tenant):
            raise HTTPException(403, "Your workspace membership changed. Choose an available workspace.")
    except TenantSuspended as exc:
        raise HTTPException(403, "This workspace is no longer active.") from exc
    key_id = getattr(request.state, "api_key_id", None)
    key_scopes = auth.api_key_scopes(request)
    role_authority = _role_authority(role)
    if key_id or key_scopes is not None:
        role_authority = "sha256:" + digest({"role": role_authority, "key": key_id,
                                            "scopes": sorted(key_scopes or ())})
    return ServiceContext(
        tenant=tenant, actor=actor, resource_owner=actor,
        credential_authority=actor, credential_ref="starter-teams-structured-inputs",
        document_credential_ref="starter-teams-structured-inputs",
        human=not (key_id or key_scopes is not None),
        authorization_role=role, authorization_policy=role_authority,
        budget_authority=_budget_authority(tenant),
        workspace_authority=_workspace_authority(request, actor, tenant),
    )


def require_team(request, team):
    from maverick.domain import suites_for_domain

    from . import api

    for suite in {suite for name in team["specialists"] for suite in suites_for_domain(name)}:
        auth.require_suite(request, suite)
        if not api._department_entitled_for_request(suite):
            raise HTTPException(403, "This team needs department access. Ask your administrator to review your plan.")


def service(request):
    from maverick.starter_teams import StarterTeamService, get_team

    from .starter_team_scheduler import register_runtime_authorizer

    register_runtime_authorizer()
    bound = context(request)

    def authorize(candidate, operation, team):
        current = context(request)
        if candidate.binding() != current.binding() or candidate.human != current.human:
            return False
        if team:
            try:
                require_team(request, get_team(team) if isinstance(team, str) else team)
            except HTTPException as exc:
                if exc.status_code in {402, 403, 404}:
                    return False
                raise
        return operation in {"read", "setup", "run", "pause", "runtime_review", "runtime_approve", "runtime_start", "runtime_read"}

    return StarterTeamService(bound, authorize=authorize, workspace_id="tenant:" + bound.tenant)


def available_catalog(request):
    from maverick.starter_teams import catalog

    context(request)
    visible = []
    for team in catalog():
        try:
            require_team(request, team)
        except HTTPException as exc:
            if exc.status_code in {402, 403, 404}:
                continue
            raise
        visible.append(team)
    return visible


def csv_tables(team, supplied):
    """Parse ordinary CSV exports; never fetch source identifiers."""
    definitions = {table["key"]: table for table in team["inputs"]}
    if set(supplied) != set(definitions):
        raise ValueError("Supply every listed input table.")
    numeric = {}
    for rule in team["rules"]:
        if rule["kind"] == "compare":
            numeric.setdefault(rule["table"], set()).update((rule["field"], rule["other_field"]))
    parsed = {}
    for key, value in supplied.items():
        if not isinstance(value, str) or len(value.encode("utf-8")) > 200_000:
            raise ValueError("Each input table must be a CSV export under 200 KB.")
        reader = csv.DictReader(io.StringIO(value.lstrip("\ufeff")))
        columns = definitions[key]["columns"]
        if reader.fieldnames is None or len(set(reader.fieldnames)) != len(reader.fieldnames) or set(reader.fieldnames) != set(columns):
            raise ValueError("Keep the exact column names shown in the input template.")
        rows = []
        for row in reader:
            if None in row or any(item is None for item in row.values()):
                raise ValueError("Every row must have the same columns as the header.")
            if len(rows) >= 1000:
                raise ValueError("Each input table is limited to 1,000 records.")
            for field in numeric.get(key, ()):
                if row[field].strip():
                    try:
                        number = float(row[field])
                    except ValueError as exc:
                        raise ValueError("Use ordinary numbers in amount and quantity columns.") from exc
                    if not math.isfinite(number):
                        raise ValueError("Amounts and quantities must be finite numbers.")
                    row[field] = number
            rows.append(row)
        parsed[key] = rows
    return parsed


def prepare_operation(request, action, arguments):
    from maverick.starter_teams import get_team
    from maverick.tenant.registry import get_tenant

    args = INPUTS[action].model_validate(arguments).model_dump()
    workflow = service(request)
    if action == "runtime":
        native, public = prepare_runtime(workflow, args)
    elif action == "setup":
        native = workflow.preview_setup(**args)
        team = get_team(args["team_id"])
        public = {"Team": team["title"], "Responsible person": args["owner_label"],
                  "Scope": args["scope"], "Record limit": args["max_rows"],
                  "Cadence preference": args["cadence"], "Meaning": NOTICE}
    else:
        setup = workflow.get_setup(args["setup_id"])
        team = get_team(setup["team_id"])
        native = {"setup_id": setup["id"], "expected_revision": setup["revision"]}
        public = {"Team": team["title"], "Scope": setup["scope"], "Meaning": NOTICE}
        if action == "inputs":
            native.update(tables=csv_tables(team, args["tables"]), as_of=args["as_of"])
            from maverick.starter_team_checks import validate_tables
            date.fromisoformat(args["as_of"])
            validate_tables(team, native["tables"], max_rows=setup["max_rows"])
            public.update({"Input records": {key: len(rows) for key, rows in native["tables"].items()}, "Review date": args["as_of"]})
        elif action == "pause":
            native["paused"] = args["paused"]
            public["New state"] = "Paused" if args["paused"] else "Ready for manual runs"
        else:
            public["Data"] = "Bundled synthetic example"
    current = context(request)
    workspace = get_tenant(current.tenant)
    public["Workspace"] = workspace.display_name if workspace and workspace.display_name else "Current selected workspace"
    return {"action": action, "native": native, "context": current.binding()}, public


def prepare_runtime(workflow, arguments):
    from maverick.starter_team_runtime import StarterTeamRuntime
    from maverick.starter_teams import get_team

    from .plain_labels import pack_display_name

    case = workflow.get_case(arguments["case_id"])
    review = StarterTeamRuntime(workflow).review_runtime(**arguments)
    return review, {"Team": get_team(case["team_id"])["title"],
                    "Progress": "After starting, Lightwork continues through this exact approved roster while the application is running. Pause the team to hold later stages.",
                    "Scope": review["scope"], "Review date": case["as_of"],
                    "Evidence shared with the AI service": ["Record " + row["row_id"] + " from " + row["source"] + ": "
                        + "; ".join(str(key).replace("_", " ") + " = " + str(value) for key, value in row["record"].items())
                        for row in review["source_scope"]],
                    "Specialists": [pack_display_name(name) for name in review["specialists"]],
                    "Maximum total cost (USD)": arguments["max_dollars"],
                    "Maximum total time (seconds)": arguments["max_wall_seconds"],
                    "Authority": "Prepare review deliverables under the displayed limits. Outside actions remain blocked.",
                    "Meaning": "This starts actual specialist work using the configured AI service. A sample pass does not prove provider readiness or business acceptance."}


def _current_setup(workflow, native):
    setup = workflow.get_setup(native["setup_id"])
    if setup["revision"] != native["expected_revision"]:
        raise HTTPException(409, "The saved team changed. Review the current team before continuing.")
    return setup


def execute_operation(request, material, operation_id):
    workflow = service(request)
    if material["context"] != context(request).binding():
        raise HTTPException(409, "Your account, workspace or access changed. Prepare a new review.")
    if material["action"] == "runtime":
        from maverick.starter_team_runtime import StarterTeamRuntime
        return {"runtime": StarterTeamRuntime(workflow).start_runtime(material["native"], confirmed=True)}
    previous = recover_operation(request, material, operation_id)
    if previous is not None:
        return previous
    action, native = material["action"], material["native"]
    if action == "setup":
        return {"setup": workflow.save_setup(native, confirmed=True)}
    _current_setup(workflow, native)
    if action == "sample":
        return {"case": workflow.run_sample(native["setup_id"], idempotency_key=operation_id)}
    if action == "inputs":
        return {"case": workflow.run_inputs(native["setup_id"], native["tables"], as_of=native["as_of"], idempotency_key=operation_id)}
    return {"setup": workflow.set_paused(native["setup_id"], paused=native["paused"], expected_revision=native["expected_revision"], idempotency_key=operation_id)}


def recover_operation(request, material, operation_id):
    workflow = service(request)
    if material["context"] != context(request).binding():
        raise HTTPException(409, "Return to the original account and workspace to check this result.")
    native = material["native"]
    if material["action"] == "runtime":
        from maverick.starter_team_runtime import StarterTeamRuntime
        found = StarterTeamRuntime(workflow).get_runtime(native["case_id"])
        approval = (found or {}).get("approval") or {}
        return {"runtime": found} if (found and found["id"] == native["runtime_id"]
            and approval.get("binding_sha256") == native["binding_sha256"]) else None
    if material["action"] == "setup":
        found = workflow.setup_for_review(native)
        return {"setup": found} if found else None
    if material["action"] in {"sample", "inputs"}:
        found = workflow.get_case_for_key(native["setup_id"], operation_id)
        return {"case": found} if found and found.get("status") == "awaiting_review" else None
    found = workflow.get_pause_for_key(native["setup_id"], operation_id)
    return {"setup": workflow.get_setup(native["setup_id"]), "pause_receipt": found} if found else None


def public_outcome(value):
    if "runtime" in value:
        row = value["runtime"]
        return {"State": str(row["status"]).replace("_", " "),
                "Specialists completed": sum(stage.get("state") == "done" for stage in row.get("stages", [])),
                "Review needed": row.get("reason") or "Review the saved evidence and specialist results.",
                "Next step": {"label": "Open specialist progress", "href": "/starter-teams#case-" + row["case_id"]},
                "Meaning": "Recorded workflow state. Review the final deliverable before accepting the business result."}
    if "case" in value:
        row = value["case"]
        output = row.get("output") or {}
        return {"Result": "Structured checks completed", "Findings": len(output.get("findings", [])),
                "Next step": {"label": "Open the saved result", "href": "/starter-teams#case-" + row["id"]}, "Meaning": NOTICE}
    row = value["setup"]
    return {"State": "Paused" if row.get("paused") else "Ready for manual runs",
            "Next step": {"label": "Open the saved team", "href": "/starter-teams#setup-" + row["id"]}, "Meaning": NOTICE}


def call(operation):
    from maverick.governed_records import RecordConflict
    from pydantic import ValidationError

    try:
        return operation()
    except HTTPException:
        raise
    except RecordConflict as exc:
        raise HTTPException(409, "This work changed. Reload and review its current state.") from exc
    except PermissionError as exc:
        raise HTTPException(403, "Your current permissions do not allow this operation.") from exc
    except (ValueError, KeyError, ValidationError) as exc:
        detail = str(exc) if str(exc) in PUBLIC_INPUT_ERRORS else "Check the selected team, required fields and input columns, then review again."
        raise HTTPException(422, detail) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(503, "The work store is unavailable. Check the original result before retrying.") from exc


def _response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


def _origin(request):
    from .app import _require_same_origin
    _require_same_origin(request)


@router.get("")
def read_catalog(request: Request):
    return _response(call(lambda: {"teams": available_catalog(request), "setups": service(request).list_setups(),
                                  "context": digest(context(request).binding()), "notice": NOTICE}))


@router.get("/setups/{setup_id}/cases")
def read_cases(request: Request, setup_id: str):
    return _response(call(lambda: {"cases": service(request).list_cases(setup_id)}))


@router.get("/cases/{case_id}")
def read_case(request: Request, case_id: str):
    return _response(call(lambda: {"case": service(request).get_case(case_id)}))


@router.get("/cases/{case_id}/runtime")
def runtime_status(request: Request, case_id: str):
    from maverick.starter_team_runtime import StarterTeamRuntime
    return _response(call(lambda: {"runtime": StarterTeamRuntime(service(request)).reconcile(case_id)}))


@router.post("/review")
def review(request: Request, body: ReviewInput):
    _origin(request)
    if body.expected_context != digest(context(request).binding()):
        raise HTTPException(409, "Your account, workspace or access changed. Reload before reviewing this work.")
    material, public = call(lambda: prepare_operation(request, body.action, body.arguments))
    material.update(purpose=PURPOSE, expires_at=time.time() + TTL, operation_id=secrets.token_hex(16))
    serialized = json.dumps(material, sort_keys=True, allow_nan=False)
    if len(serialized.encode("utf-8")) > 1_000_000:
        raise HTTPException(422, "This review is too large. Use a smaller set of records and review again.")
    token = crypto_at_rest.seal_to_str(serialized)
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "The review could not be secured. Nothing was changed.")
    return _response({"token": token, "preview": public})


def open_token(token, *, recovery=False):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if value["purpose"] != PURPOSE or value["action"] not in INPUTS:
            raise ValueError
        if not recovery and not time.time() < value["expires_at"] <= time.time() + TTL:
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This review expired or could not be verified. Prepare a new review.") from exc


@router.post("/confirm")
def confirm(request: Request, body: TokenInput):
    _origin(request)
    if body.confirmed is not True:
        raise HTTPException(422, "Review the planned work, then confirm it.")
    material = open_token(body.token)
    return _response(call(lambda: execute_operation(request, material, material["operation_id"])))


@router.post("/original")
def original(request: Request, body: TokenInput):
    _origin(request)
    material = open_token(body.token, recovery=True)
    result = call(lambda: recover_operation(request, material, material["operation_id"]))
    return _response(result or {"status": "unconfirmed", "message": "The original action is not confirmed. No action was repeated. Reload current work before another review."})


def create_page_router(templates):
    pages = APIRouter()

    @pages.get("/starter-teams", include_in_schema=False)
    def starter_teams_page(request: Request):
        auth.require_permission(request, "view")
        return templates.TemplateResponse(request, "starter_teams.html", {"notice": NOTICE})

    return pages
