"""Explicit reviewed migration of installation first-login fallback policy."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy

from fastapi import HTTPException


def preview():
    from maverick import config

    from . import rbac
    cfg = config.load_global_config()
    if config.config_source_errors():
        raise HTTPException(503, "First-login policy is unavailable. Restore configuration before changing it.")
    section = cfg.get("dashboard") or {}
    if not isinstance(section, dict):
        raise HTTPException(503, "First-login policy is invalid. Restore configuration before changing it.")
    role = section.get("default_role", "viewer")
    suites = section.get("default_suites")
    if not isinstance(role, str) or not rbac.is_known_role(role) or (suites is not None and (not isinstance(suites, list) or any(not isinstance(s, str) for s in suites))):
        raise HTTPException(503, "First-login policy is invalid. Restore configuration before changing it.")
    result = {"role": role, "permissions": sorted(rbac.permissions_for(role)),
              "departments": sorted(suites) if suites is not None else None,
              "conservative": role == "viewer" and suites == []}
    result["revision"] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


def apply_conservative(request, expected_revision):
    from maverick import config
    from maverick.audit import audit_event

    from . import auth, settings_store
    with settings_store._locked(strict=True):
        auth.require_global_permission(request, "admin")
        current = preview()
        if current["revision"] != expected_revision:
            raise HTTPException(409, "The first-login baseline changed. Reload and review its current powers.")
        before = settings_store._load_overlay_for_update()
        updated = deepcopy(before)
        updated.setdefault("dashboard", {}).update(default_role="viewer", default_suites=[])
        settings_store._write(updated)
        config.reset_config_cache()
        try:
            effective = preview()
            if not effective["conservative"]:
                raise HTTPException(409, "An installation policy overrides this choice. Nothing was saved; ask the installation owner to change that policy.")
            recorded = audit_event("first_login_baseline_changed", agent="dashboard", _global=True,
                actor=auth.caller_principal(request) or "local", previous=current,
                effective=effective, includes_existing_unassigned=True)
            if recorded is not True:
                raise HTTPException(503, "The policy change could not be recorded. Nothing was saved.")
        except Exception:
            settings_store._write(before)
            config.reset_config_cache()
            raise
        return effective
