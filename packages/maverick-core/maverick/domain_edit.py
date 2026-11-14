"""Per-client pack customization -- the data layer behind the dashboard editor.

A built-in pack ships read-only inside the package; a client tailors it by
writing a *tenant override* (a partial TOML pack in the workspace domains dir).
:func:`maverick.domain.available_domains` overlays that override onto the
built-in base field-by-field, so the client inherits everything it didn't
change. This module is the editing surface over that mechanism:

  * :func:`resolved_view` -- the merged pack plus *provenance* (which fields are
    overridden vs inherited) and lint findings, for the editor UI.
  * :func:`write_override` -- validate then persist an override patch.
  * :func:`remove_override` -- remove the exact tenant override.
  * :func:`list_agents` -- the roster, flagged by override/workflow status.

Overrides serialize as JSON literals (``json.dumps`` with ``ensure_ascii=False``
and DEL escaped), which TOML also accepts; :func:`write_override` parses the
exact text and validates that parsed form before it publishes the file.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

from .authority_effects import authority_effect_fence
from .domain import (
    _MAX_DOMAIN_FILE_BYTES,
    _OVERLAYABLE,
    DomainProfile,
    _coerce,
    _disabled_suites,
    _envelope_errors,
    _load_raw_domains,
    _profile_field_type_errors,
    _unsafe_domain_alias,
    available_domains,
    builtin_dir,
    builtin_domains,
    declared_prompt_gate,
    enforced_gate,
    extends_errors,
    lint_profile,
    load_domain,
    load_domains,
    overlay_profile,
    overridden_fields,
    rejected_workspace_domains,
    suite_for,
    suites_for_domain,
    user_dir,
)
from .file_lock import (
    atomic_read_bytes,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)

# Scalars vs arrays serialize the same way (json.dumps), but we emit them in a
# stable, readable order; ``models`` and ``workflow`` become TOML tables.
_SCALAR_KEYS = ("name", "extends", "compartment", "description", "persona",
                "max_risk", "effort", "authoring")
_ARRAY_KEYS = ("allow_tools", "deny_tools", "allow_paths", "allow_hosts",
               "mcp_servers", "knowledge_sources", "refuse")

# Override names become filenames. Keep this deliberately narrower than a
# platform path component so the same identifier is safe on POSIX and Windows
# (where a backslash is a separator) and cannot address a sibling file.
_OVERRIDE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_MAX_OVERRIDE_BYTES = 256 * 1024
_TOOL_NAMES_UNSET = object()


def _action_label(name: str) -> str:
    """A short customer-facing action name, without registry identifiers."""
    familiar = {
        "web_search": "Search the web",
        "knowledge_search": "Search company knowledge",
        "code_exec": "Run calculations",
        "ledger_read": "Read financial records",
    }
    if name in familiar:
        return familiar[name]
    words = name.replace("_", " ").replace("-", " ").replace(".", " ").split()
    verbs = {"read": "Read", "write": "Update", "create": "Create",
             "search": "Search", "list": "List", "send": "Send"}
    if words and words[-1] in verbs:
        return verbs[words[-1]] + " " + " ".join(words[:-1])
    return " ".join(words).capitalize() or "An action"


@lru_cache(maxsize=8)
def _registered_tool_names(config_digest: str) -> frozenset[str] | None:
    """One built-in action inventory per effective installation configuration.

    The digest is a cache key only; no configuration values or credentials are
    retained. Settings changes invalidate the snapshot on the next request.
    """
    from .tools import base_tool_names

    names = base_tool_names(configured_optional=True)
    if names is None:
        return None
    names.update({"send_to_agent", "recv_from_agent"})
    # The agent adds these after base_registry, subject to the same feature
    # switches. Omitting knowledge_search would falsely block most built-ins.
    from .config import get_capabilities, knowledge_access_enabled

    if knowledge_access_enabled():
        names.add("knowledge_search")
    if (get_capabilities().get("code_exec", False)
            or os.environ.get("MAVERICK_CODE_EXEC", "").strip().lower()
            in {"1", "true", "yes", "on"}):
        names.add("code_exec")
    return frozenset(names)


def _configured_tool_names() -> frozenset[str] | None:
    try:
        from .config import config_path, load_config

        digest = hashlib.sha256(
            json.dumps({"config": load_config(), "config_path": str(config_path()),
                        "code_exec": os.environ.get("MAVERICK_CODE_EXEC"),
                        "knowledge_access": os.environ.get("MAVERICK_KNOWLEDGE_ACCESS")},
                       sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        names = _registered_tool_names(digest)
        if names is None:
            _registered_tool_names.cache_clear()
        return names
    except Exception:
        # A failed inventory is not a positive readiness verdict.
        return None


def workflow_readiness(
    profile: DomainProfile, known_tools: frozenset[str] | None | object = _TOOL_NAMES_UNSET,
    *, disabled_suites: frozenset[str] | None = None,
) -> dict:
    """Explain whether a pack's department and required actions can run.

    This is deliberately narrower than live readiness: credentials, permissions,
    remote service health and provider availability are checked when work runs.
    The run-time factory still makes the final admission decision.
    """
    if disabled_suites is None:
        disabled_suites = frozenset(_disabled_suites())
    if suites_for_domain(profile.name, profile) & disabled_suites:
        return {
            "state": "needs_setup", "missing_tools": [], "missing_labels": [],
            "missing_optional_tools": [],
            "fix_url": "/settings/all?group=people-access&id=suites.%2A#sa-suites-all-label",
            "label": "Department turned off",
        }
    if known_tools is _TOOL_NAMES_UNSET:
        known_tools = _configured_tool_names()
    required = {tool for step in profile.workflow for tool in step.tools}
    if known_tools is None:
        return {"state": "unknown", "missing_tools": [], "missing_optional_tools": [],
                "fix_url": "/settings", "label": "Setup check unavailable"}
    missing = sorted(required - known_tools)
    optional = sorted(set(profile.allow_tools) - required - known_tools)
    if missing:
        return {
            "state": "needs_setup", "missing_tools": missing,
            "missing_labels": [_action_label(name) for name in missing],
            "missing_optional_tools": optional,
            "fix_url": ("/settings/all?id=capabilities.web_search"
                        if "web_search" in missing else "/connections"),
            "label": ("Needs Web search" if set(missing) == {"web_search"}
                      else f"Needs {len(missing)} workflow action{'s' if len(missing) != 1 else ''}"),
        }
    return {
        "state": "action_ready", "missing_tools": [],
        "missing_optional_tools": optional,
        "fix_url": None,
        "label": ("Can start; some optional actions need setup" if optional
                  else "Can start"),
    }


def _validated_override_name(name: str) -> str:
    name = str(name or "")
    if not _OVERRIDE_NAME_RE.fullmatch(name):
        raise ValueError(
            "agent name must be 1-128 letters, numbers, underscores, or hyphens"
        )
    return name


def _toml_value(value) -> str:
    """A JSON literal TOML also accepts: characters outside the BMP stay
    literal (JSON would write a surrogate pair TOML rejects) and DEL, which
    TOML requires escaped, is escaped."""
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def overlay_toml(patch: dict) -> str:
    """Serialize an override patch dict to TOML that round-trips through the
    loader. Only the keys present in ``patch`` are written (it stays a thin
    overlay); empty scalars are skipped."""
    lines: list[str] = []
    for k in _SCALAR_KEYS:
        if k in patch and patch[k] not in (None, ""):
            lines.append(f"{k} = {_toml_value(patch[k])}")
    for k in _ARRAY_KEYS:
        if k in patch:
            lines.append(f"{k} = {_toml_value(list(patch[k]))}")
    if "models" in patch:
        lines.append("")
        lines.append("[models]")
        for role, model in dict(patch["models"]).items():
            lines.append(f"{_toml_value(role)} = {_toml_value(model)}")
    if patch.get("autonomy"):
        lines.append("")
        lines.append("[autonomy]")
        for key in ("default", "low", "medium", "high", "onboarding"):
            value = patch["autonomy"].get(key)
            if value is not None:
                lines.append(f"{key} = {_toml_value(value)}")
    out = patch.get("output")
    if out:
        lines.append("")
        lines.append("[output]")
        for key in ("shape", "deliverable", "cadence", "gate"):
            if out.get(key):
                lines.append(f"{key} = {_toml_value(out[key])}")
        if out.get("consumers"):
            lines.append(f"consumers = {_toml_value(list(out['consumers']))}")
    for step in patch.get("workflow") or []:
        if not str(step.get("name") or "").strip():
            continue
        lines.append("")
        lines.append("[[workflow]]")
        lines.append(f"name = {_toml_value(step['name'])}")
        if step.get("instruction"):
            lines.append(f"instruction = {_toml_value(step['instruction'])}")
        if step.get("tools"):
            lines.append(f"tools = {_toml_value(list(step['tools']))}")
        if step.get("gate"):
            lines.append(f"gate = {_toml_value(step['gate'])}")
    return "\n".join(lines) + "\n"


def _builtin_layout() -> tuple:
    directory = builtin_dir()
    files = []
    # One scan of the directory: Path objects per pack made this the slowest step of each base lookup.
    with os.scandir(directory) as entries:
        packs = sorted((entry for entry in entries if entry.name.endswith(".toml")), key=lambda entry: entry.name)
    for entry in packs:
        info = entry.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or _unsafe_domain_alias(info):
            return ()
        files.append((entry.name, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
    return (str(directory.resolve()), tuple(files))


@lru_cache(maxsize=4)
def _canonical_builtin_layout(signature: tuple) -> bool:
    """Cache only layout evidence; every selected base is still read afresh."""
    directory, files = signature
    try:
        return all(load_domain(Path(directory) / item[0]).name == Path(item[0]).stem for item in files)
    except Exception:
        # Discovery's permissive handling of malformed/noncanonical legacy packs
        # remains authoritative for layouts that do not satisfy this invariant.
        return False


def _fresh_builtin_base(name: str) -> DomainProfile | None:
    try:
        signature = _builtin_layout()
        if signature and _canonical_builtin_layout(signature) and _builtin_layout() == signature:
            # Every built-in pack is named by its file, so a name with no file has no
            # built-in base. Answer from the listing instead of parsing the catalogue.
            if f"{name}.toml" not in {item[0] for item in signature[1]}:
                return None
            profile = load_domain(Path(signature[0]) / f"{name}.toml")
            if profile.name == name:
                return profile
    except Exception:
        pass
    return load_domains(builtin_dir()).get(name)


def _resolve(name: str, patch: dict) -> DomainProfile:
    """The profile a ``name``/``patch`` override resolves to (base overlaid, or
    a standalone pack when there is no base to inherit)."""
    base_name = str(patch.get("extends") or name)
    base = available_domains().get(base_name) if base_name != name else None
    if base is None:
        base = _fresh_builtin_base(base_name)
    return overlay_profile(base, patch) if base else _coerce(name, patch)


def _base_profile(name: str, patch: dict) -> DomainProfile | None:
    """Active profile an override inherits from, if one exists."""
    base_name = str(patch.get("extends") or name)
    if base_name != name:
        base = available_domains().get(base_name)
        if base is not None:
            return base
    return _fresh_builtin_base(base_name)


def _extends_errors(name: str, patch: dict, base: DomainProfile | None) -> list[str]:
    builtin = (name,) if _fresh_builtin_base(name) is not None else ()
    return extends_errors(name, patch, base, builtin)


def validate_override(name: str, patch: dict) -> tuple[list[str], list[str]]:
    """Lint the *merged* result of applying ``patch`` to its base. Returns
    ``(errors, warnings)`` -- the editor blocks a save on any error."""
    try:
        name = _validated_override_name(name)
    except ValueError as exc:
        return [str(exc)], []
    patch = dict(patch)
    merged = _resolve(name, patch)
    base = _base_profile(name, patch)
    errors = _extends_errors(name, patch, base)
    lint_errors, warnings = lint_profile(merged)
    errors.extend(lint_errors)
    if not _profile_field_type_errors(merged):
        errors.extend(_envelope_errors(base, merged))
    return errors, warnings


def preview_override(name: str, patch: dict) -> DomainProfile:
    """Resolve the exact bounded draft without writing or changing active work."""
    name = _validated_override_name(name)
    if not isinstance(patch, dict) or not set(patch) <= _OVERLAYABLE | {"name", "extends"}:
        raise ValueError("This draft contains an unsupported specialist setting.")
    value = dict(patch)
    value["name"] = name
    content = overlay_toml(value)
    if len(content.encode("utf-8")) > _MAX_OVERRIDE_BYTES:
        raise ValueError("The complete specialist draft is too large. Nothing was shortened.")
    # Resolve what the existing native serializer would actually publish.
    from .domain import tomllib

    parsed = tomllib.loads(content)
    # One fresh base read per invocation. Apply exactly the same native lint
    # and envelope checks without resolving that complete catalog three times.
    base = _base_profile(name, parsed)
    merged = overlay_profile(base, parsed) if base else _coerce(name, parsed)
    errors = _extends_errors(name, parsed, base)
    errors.extend(lint_profile(merged)[0])
    if not _profile_field_type_errors(merged):
        errors.extend(_envelope_errors(base, merged))
    if errors:
        raise ValueError("; ".join(errors))
    return merged


class OverrideConflict(ValueError):
    """The agent changed after the editor loaded it."""


def _override_generation(name: str, path: Path) -> str:
    content = atomic_read_bytes(path) if path.exists() else b""
    return hashlib.sha256(name.encode() + b"\0" + content).hexdigest()


def write_override(name: str, patch: dict, directory: str | Path | None = None, *,
                   expected_generation: str | None = None, return_view: bool = False,
                   effect_guard: Callable[[], None] | None = None) -> str | dict:
    """Validate then persist a tenant override for ``name``. Raises
    ``ValueError`` (with the lint errors) rather than writing an override that
    would weaken the safety envelope. Returns the path written."""
    name = _validated_override_name(name)
    patch = {k: v for k, v in dict(patch).items() if k in _OVERLAYABLE or k in ("name", "extends")}
    # The route/argument identifier is authoritative; a caller-supplied payload
    # name must not create an identity mismatch inside a differently named file.
    patch["name"] = name
    content = overlay_toml(patch)
    if len(content.encode("utf-8")) > _MAX_OVERRIDE_BYTES:
        raise ValueError("agent override is too large")
    from .domain import tomllib

    # Validate exactly what will be persisted: the serialiser drops empty
    # tables and must never publish text the loader cannot read back.
    try:
        persisted = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError("This agent setup cannot be saved as written.") from exc
    errors, _ = validate_override(name, persisted)
    if errors:
        raise ValueError("; ".join(errors))
    d = ensure_private_directory(Path(directory) if directory else user_dir())
    path = d / f"{name}.toml"
    # Lock a stable sidecar, then publish a complete private file. Atomic
    # replacement also replaces a planted final-component symlink rather than
    # following it to an attacker-selected target.
    with authority_effect_fence(), cross_process_lock(path, strict=True):
        if expected_generation == "new":
            if path.exists() or name in available_domains():
                raise OverrideConflict("An agent with this name already exists. Open its latest version or choose a new name.")
        elif expected_generation is not None and not hmac.compare_digest(expected_generation, _override_generation(name, path)):
            raise OverrideConflict("This agent changed after you opened it. Reload the latest version before applying your edits.")
        if effect_guard is not None:
            effect_guard()
        atomic_write_text(path, content, mode=0o600, effect_guard=effect_guard)
        view = _resolved_view(name, directory) if return_view else None
    # The pack's capability surface may have changed. If it already has a
    # governance assessment, re-draft it so drift flips an accepted review back
    # to needs-review (best-effort; only touches the default user dir).
    if directory is None:
        try:
            from . import assessments
            assessments.refresh_on_change("agent", name)
        except Exception:  # pragma: no cover -- never let assessment break a save
            pass
    return view if return_view else str(path)


def read_override(name: str, directory: str | Path | None = None) -> dict:
    """The raw override patch for ``name`` (``{}`` if the client hasn't
    customized this pack)."""
    name = _validated_override_name(name)
    d = Path(directory) if directory else user_dir()
    return _load_raw_domains(d).get(name, {})


def remove_override(name: str, directory: str | Path | None = None, *, expected_generation: str | None = None,
                    effect_guard: Callable[[], None] | None = None) -> bool:
    """Remove a tenant override. Built-in agents resume their built-in definition;
    custom-only agents disappear. Returns whether a file was removed."""
    name = _validated_override_name(name)
    d = Path(directory) if directory else user_dir()
    path = d / f"{name}.toml"
    with authority_effect_fence(), cross_process_lock(path, strict=True):
        if expected_generation is not None and not hmac.compare_digest(expected_generation, _override_generation(name, path)):
            raise OverrideConflict("This agent changed after you opened it. Reload its latest version before changing it.")
        if path.is_file():
            if effect_guard is not None:
                effect_guard()
            path.unlink()
            return True
    return False


def _step_dict(step) -> dict:
    return {"name": step.name, "instruction": step.instruction,
            "tools": list(step.tools), "gate": step.gate}


def _output_dict(out) -> dict:
    """A pack's output contract as a plain dict for the editor/API payload."""
    return {"shape": out.shape, "deliverable": out.deliverable,
            "consumers": list(out.consumers), "cadence": out.cadence,
            "gate": out.gate}


def resolved_view(name: str, directory: str | Path | None = None) -> dict | None:
    try:
        name = _validated_override_name(name)
    except ValueError:
        return None
    d = ensure_private_directory(Path(directory) if directory else user_dir())
    with cross_process_lock(d / f"{name}.toml", strict=True):
        return _resolved_view(name, directory)


def _resolved_view(name: str, directory: str | Path | None = None) -> dict | None:
    """The merged pack the agent actually runs, plus provenance and lint -- the
    payload the editor renders. ``None`` if no such pack exists.

    ``overridden`` lists the fields the client has customized; everything else
    is inherited from the built-in base."""
    prof = available_domains().get(name)
    if prof is None:
        return None
    raw = read_override(name, directory)
    base = _base_profile(name, raw)
    errors, warnings = lint_profile(prof)
    readiness = workflow_readiness(prof)
    from .agent_autonomy import default_profile_for, effective_profile, levels_enabled, resolve
    from .config import get_workforce

    pack_autonomy = prof.autonomy or default_profile_for(name)
    current_autonomy = effective_profile(name, prof.autonomy)
    config_override = bool(get_workforce().get("agents", {}).get(name))
    autonomy_enabled = levels_enabled()
    return {
        "name": name,
        "generation": _override_generation(name, (Path(directory) if directory else user_dir()) / f"{name}.toml"),
        "is_builtin": name in builtin_domains(),
        "suite": suite_for(prof.name) or suite_for(name),
        "suites": sorted(suites_for_domain(name, prof)),
        "description": prof.description,
        "persona": prof.persona,
        "allow_tools": list(prof.allow_tools),
        "base_allow_tools": list(base.allow_tools) if base else None,
        "deny_tools": list(prof.deny_tools),
        "max_risk": prof.max_risk,
        "base_max_risk": base.max_risk if base else None,
        "knowledge_sources": list(prof.knowledge_sources),
        "mcp_servers": list(prof.mcp_servers),
        "models": dict(prof.models),
        "workflow": [_step_dict(s) for s in prof.workflow],
        "output": _output_dict(prof.output),
        # Keep prompt declarations separate from controls the release layer
        # actually enforces.  Consumers must never infer enforcement merely
        # because a gate-shaped string appeared in the LLM's instructions.
        "declared_prompt_gate": declared_prompt_gate(prof),
        "enforced_gate": enforced_gate(prof),
        "is_override": bool(raw),
        "overridden": sorted(overridden_fields(raw)),
        "errors": errors,
        "warnings": warnings,
        "readiness": readiness,
        "autonomy": {
            "default": current_autonomy.default.value,
            "low": current_autonomy.low.value if current_autonomy.low else None,
            "medium": current_autonomy.medium.value if current_autonomy.medium else None,
            "high": current_autonomy.high.value if current_autonomy.high else None,
            "onboarding": current_autonomy.onboarding,
            "levels_enabled": autonomy_enabled,
            "config_override": config_override,
            "pack_default": pack_autonomy.default.value,
            "pack": {
                "default": pack_autonomy.default.value,
                "low": pack_autonomy.low.value if pack_autonomy.low else None,
                "medium": pack_autonomy.medium.value if pack_autonomy.medium else None,
                "high": pack_autonomy.high.value if pack_autonomy.high else None,
                "onboarding": pack_autonomy.onboarding,
            },
            "effective": {
                risk: resolve(current_autonomy, risk=risk, levels_enabled=autonomy_enabled).level.value
                for risk in ("low", "medium", "high")
            },
        },
    }


def rejected_override_view(name: str) -> dict | None:
    """Minimal admin recovery state for an unavailable workspace pack."""
    try:
        name = _validated_override_name(name)
    except ValueError:
        return None
    if name not in rejected_workspace_domains():
        return None
    path = user_dir() / f"{name}.toml"
    generation = None
    try:
        info = path.lstat()
        if (stat.S_ISREG(info.st_mode) and not _unsafe_domain_alias(info)
                and info.st_nlink == 1 and info.st_size <= _MAX_DOMAIN_FILE_BYTES):
            generation = _override_generation(name, path)
    except (OSError, ValueError):
        pass
    return {
        "name": name,
        "generation": generation,
        "is_builtin": name in builtin_domains(),
    }


def list_agents(directory: str | Path | None = None) -> list[dict]:
    """Roster for the editor: every available pack, flagged by whether the
    client has overridden it and whether it carries a workflow."""
    overrides = _load_raw_domains(Path(directory) if directory else user_dir())
    known_tools = _configured_tool_names()
    disabled_suites = frozenset(_disabled_suites())
    out: list[dict] = []
    for name, prof in sorted(available_domains().items()):
        out.append({
            "name": name,
            "suite": suite_for(prof.name) or suite_for(name),
            "suites": sorted(suites_for_domain(name, prof)),
            "description": prof.description,
            "is_override": name in overrides,
            "has_workflow": bool(prof.workflow),
            "readiness": workflow_readiness(prof, known_tools, disabled_suites=disabled_suites),
        })
    return out


__all__ = [
    "overlay_toml", "validate_override", "write_override", "read_override",
    "remove_override", "resolved_view", "list_agents", "rejected_override_view",
    "workflow_readiness",
]
