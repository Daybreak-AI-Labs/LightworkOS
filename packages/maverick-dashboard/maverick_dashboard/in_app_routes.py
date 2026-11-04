"""Small, permission-checked actions behind end-user setup and library forms."""
from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .api_schemas import GOAL_DESCRIPTION_MAX_LENGTH, GOAL_TITLE_MAX_LENGTH
from .auth import (
    assert_template_access,
    caller_principal,
    require_global_permission,
    require_permission,
)

router = APIRouter(prefix="/api/v1", tags=["v1"])

# These initial defaults grant no host mutation authority. Existing deployment
# policy and Settings overlays retain precedence through the normal loader.
INITIAL_SETTINGS = '''# Initial Lightwork settings. Manage these in the app.
[budget]
strict_pricing = true
[safety]
profile = "strict"
block_threshold = "medium"
scan_input = true
scan_tool_calls = true
scan_output = true
[sandbox]
backend = "local"
timeout = 60
[capabilities]
computer_use = false
browser = false
mobile_tools = false
ros = false
code_exec = false
[security]
denied_tools = ["computer", "browser", "shell", "write_file", "apply_patch", "str_replace_editor"]
'''


class InitializeSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: bool = Field(strict=True)


@router.post("/setup/initialize", status_code=201)
def initialize_settings(request: Request, payload: InitializeSettingsIn) -> dict:
    require_global_permission(request, "admin")
    if payload.confirm is not True:
        raise HTTPException(400, "Review and confirm the initial settings first.")
    from maverick.config import config_path, config_source_errors, load_config
    from maverick.file_lock import atomic_create_text

    # Invalid overlay/policy sources cannot become a successful fresh setup.
    load_config()
    if config_source_errors(include_tenant=True):
        raise HTTPException(409, "Existing settings need repair before initial setup.")
    try:
        atomic_create_text(config_path(), INITIAL_SETTINGS)
    except FileExistsError as exc:
        raise HTTPException(409, "Settings already exist. Open Settings to review them.") from exc
    except OSError as exc:
        raise HTTPException(503, "Lightwork could not save initial settings. Check installation access and retry.") from exc
    return {"initialized": True, "live_provider_verified": False}


@router.get("/setup/checks")
def setup_checks(request: Request) -> dict:
    require_global_permission(request, "admin")
    from .onboarding_state import _preflight_state

    return {
        "runtime": _preflight_state("run"),
        "assurance": _preflight_state("cockpit"),
        "live_provider_verified": False,
    }


class TemplateRatingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stars: int = Field(strict=True, ge=1, le=5)


class TemplatePrepareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    params: dict[str, str] = Field(default_factory=dict, max_length=100)


def _draft_context(request: Request) -> str:
    from maverick.paths import current_tenant_id

    return hashlib.sha256(
        json.dumps([current_tenant_id() or "", caller_principal(request) or ""]).encode()
    ).hexdigest()


@router.get("/templates/draft-context")
def template_draft_context(request: Request) -> dict:
    require_permission(request, "view")
    return {"context": _draft_context(request)}


@router.get("/templates/connection-choices")
def template_connection_choices(request: Request) -> dict:
    require_permission(request, "operate")
    from maverick.template_connections import SelectionUnavailable, choices
    try:
        return {"choices": choices(caller_principal(request) or ""), "context": _draft_context(request)}
    except SelectionUnavailable as exc:
        raise HTTPException(403, str(exc)) from exc


@router.post("/templates/{name}/prepare")
def prepare_template(request: Request, name: str, payload: TemplatePrepareIn) -> dict:
    require_permission(request, "operate")
    from maverick.templates import list_templates, load_template

    if name not in list_templates():
        raise HTTPException(404, "This template is no longer available.")
    try:
        template = load_template(name)
        assert_template_access(request, template)
        if set(payload.params) - set(template.params):
            raise ValueError("Complete the template's listed inputs.")
        if any(len(value) > 10000 or (not value.strip() and name not in template.parameter_schema.get("fields", {})) for name, value in payload.params.items()):
            raise ValueError("Each input needs a value of at most 10,000 characters.")
        from maverick.template_connections import parameters
        _, references = parameters(template, caller_principal(request) or "", payload.params)
        title, description = template.render_for(caller_principal(request) or "", **payload.params)
        if not title.strip() or len(title) > GOAL_TITLE_MAX_LENGTH or len(description) > GOAL_DESCRIPTION_MAX_LENGTH:
            raise ValueError("Chat accepts a title up to 200 characters and details up to 16,000 characters. Shorten this template in the workflow builder.")
    except (OSError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return {
        "title": title, "description": description, "started": False,
        "context": _draft_context(request), "connection_references": references,
    }


@router.post("/templates/{name}/rating")
def rate_template(request: Request, name: str, payload: TemplateRatingIn) -> dict:
    require_permission(request, "operate")
    from maverick.marketplace.ratings import RatingsLedger
    from maverick.templates import list_templates

    if name not in list_templates():
        raise HTTPException(404, "This template is no longer available.")
    rating = RatingsLedger().rate("templates", name, payload.stars)
    return {"name": name, "stars": rating["stars"], "saved": True}
