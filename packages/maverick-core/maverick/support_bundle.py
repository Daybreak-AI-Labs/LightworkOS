"""``maverick support`` — a redacted diagnostics bundle for a support ticket.

Filing a ticket previously meant hand-running ``version`` + ``doctor`` + ``diag``
+ ``logs`` and manually redacting config. This assembles one structured,
**secret-redacted** snapshot (versions, runtime, client binding, readiness, a
redacted config, and a recent-failures summary) so an operator can attach a
single file. Best-effort: every section is independently guarded, so a failure
in one never blocks the rest.
"""
from __future__ import annotations

import hashlib
import platform
import sys
import time
from pathlib import Path
from typing import Any

# Config keys whose VALUE is a credential — redacted by name regardless of the
# value-level secret scrubber (which only catches recognised secret shapes).
_SECRET_KEY_HINTS = (
    "key", "token", "secret", "password", "passwd", "credential", "dsn",
)


def _redact(obj: Any) -> Any:
    """Recursively redact a config tree: drop values under secret-named keys,
    and run the value-level secret scrubber over every remaining string."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and any(h in k.lower() for h in _SECRET_KEY_HINTS):
                out[k] = "[REDACTED]" if v not in (None, "", {}, []) else v
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    if isinstance(obj, str):
        try:
            from .secrets import scrub
            return scrub(obj)
        except Exception:  # pragma: no cover - never let scrubbing block the bundle
            return "[unscrubbable]"
    return obj


def _config_topology(obj: Any) -> Any:
    """Describe configuration presence without exporting customer-authored text.

    Config is a general extension surface: harmless-looking fields can contain
    prompts, document excerpts, URLs, account names, or local paths. Pattern
    scrubbing cannot establish that the remainder is authorized for support.
    Preserve only keyed commitments, boolean/numeric controls, and collection
    sizes. Configuration keys are an extension surface too, so their literal
    text must never enter a support artifact.
    """
    if isinstance(obj, dict):
        entries = []
        for raw_key, value in obj.items():
            name = str(raw_key)
            key_sha256 = hashlib.sha256(name.encode("utf-8")).hexdigest()
            if any(hint in name.casefold() for hint in _SECRET_KEY_HINTS):
                topology = "[REDACTED]" if value not in (None, "", {}, []) else value
            else:
                topology = _config_topology(value)
            entries.append({"key_sha256": key_sha256, "value": topology})
        entries.sort(key=lambda row: row["key_sha256"])
        return {"type": "object", "configured_items": len(entries), "entries": entries}
    if isinstance(obj, list):
        return {"type": "list", "configured_items": len(obj)}
    if isinstance(obj, str):
        return "" if not obj else "[SET]"
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    return f"[{type(obj).__name__.upper()}]"


def _paths() -> dict[str, Any]:
    """Return bounded installation-path diagnostics without reading contents."""
    result: dict[str, Any] = {
        "python_executable": str(Path(sys.executable).resolve()),
    }
    try:
        from .paths import data_dir

        root = Path(data_dir()).resolve()
        result["data_root"] = str(root)
        result["data_root_exists"] = root.exists()
        result["data_root_is_directory"] = root.is_dir()
    except Exception:
        result["data_root"] = "unavailable"
        result["data_root_exists"] = None
        result["data_root_is_directory"] = None
    # The general scrubber catches credentials embedded in a configured path.
    # These are application/runtime roots only; no directory enumeration or
    # document filename enters the report.
    return _redact(result)


def _versions() -> dict:
    import importlib.metadata as md
    pkgs = {
        "maverick-agent": ("maverick-agent", "maverick"),
        "maverick-shield": ("maverick-shield",),
        "maverick-channels": ("maverick-channels",),
        "maverick-evolve": ("maverick-evolve",),
        "maverick-dashboard": ("maverick-dashboard",),
        "maverick-mcp-server": ("maverick-mcp-server",),
        "maverick-knowledge": ("maverick-knowledge",),
        "maverick-installer": ("maverick-installer",),
    }
    out: dict[str, str] = {}
    for display, candidates in pkgs.items():
        for c in candidates:
            try:
                out[display] = md.version(c)
                break
            except md.PackageNotFoundError:
                continue
        else:
            out[display] = "not installed"
    return out


def _runtime() -> dict:
    info: dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "machine": platform.machine(),
    }
    try:
        from .world_model import SCHEMA_VERSION
        info["world_schema_version"] = SCHEMA_VERSION
    except Exception:
        pass
    try:
        from maverick_shield import Shield
        info["shield_backend"] = Shield.from_config(warn_if_missing=False).backend
    except Exception:
        info["shield_backend"] = "not installed"
    return info


def _readiness() -> dict:
    """The same deep checks /readyz and doctor run (client binding, shield,
    agent-trust), as pass/fail strings."""
    checks: dict[str, str] = {}
    try:
        from .client import client_binding_enforced, client_id
        checks["client_binding"] = (
            "fail: enforced but no valid client id"
            if client_binding_enforced() and not client_id() else "ok")
    except Exception as e:  # pragma: no cover
        checks["client_binding"] = f"unknown: {type(e).__name__}"
    try:
        from .shield_policy import shield_available, shield_required
        checks["shield"] = (
            "fail: required but unavailable"
            if shield_required() and not shield_available() else "ok")
    except Exception as e:  # pragma: no cover
        checks["shield"] = f"unknown: {type(e).__name__}"
    try:
        from .agent_trust import load_trust_state
        enforced, registry = load_trust_state()
        checks["agent_trust"] = (
            "fail: engaged but registry empty"
            if enforced and not registry else "ok")
    except Exception as e:  # pragma: no cover
        checks["agent_trust"] = f"unknown: {type(e).__name__}"
    return checks


def _providers() -> dict:
    out: dict[str, Any] = {}
    try:
        from .config import any_provider_configured
        out["any_configured"] = any_provider_configured()
    except Exception:
        out["any_configured"] = None
    try:
        from .providers import KNOWN_PROVIDERS
        out["known"] = list(KNOWN_PROVIDERS)
    except Exception:
        pass
    return out


def _failure_category(value: object) -> str:
    """Reduce an untrusted job error to a small support-safe category.

    Worker exception text may contain customer document excerpts, prompts,
    provider responses, paths, or identifiers. Credential scrubbing cannot
    establish authorization for the remaining prose, so none is exported.
    """

    text = str(value or "").lower()
    categories = (
        ("cancelled", ("cancel",)),
        (
            "permission_denied",
            ("permission", "forbidden", "authorization", "unauthor", "denied"),
        ),
        ("rate_limited", ("rate limit", "ratelimit", "too many requests")),
        ("timeout", ("timeout", "timed out", "deadline")),
        ("connection", ("connection", "network", "dns", "socket")),
        ("validation", ("validation", "invalid", "malformed", "schema")),
        ("unavailable", ("unavailable", "not configured", "missing")),
    )
    for category, markers in categories:
        if any(marker in text for marker in markers):
            return category
    return "other"


def _recent_failures() -> dict:
    out: dict[str, Any] = {}
    try:
        from .failure_telemetry import summarize
        out["failure_modes"] = summarize()
    except Exception:
        out["failure_modes"] = "unavailable"
    try:
        from .job_queue import JobQueue
        failed = JobQueue().list(status="failed", limit=20)
        categories: dict[str, int] = {}
        errors_recorded = 0
        for job in failed:
            error = getattr(job, "last_error", "")
            category = _failure_category(error)
            categories[category] = categories.get(category, 0) + 1
            errors_recorded += bool(error)
        # Job ids and kinds are customer/plugin-controlled namespaces. Even a
        # syntactically tame value may identify a customer, document or custom
        # workflow, so support receives counts and closed categories only.
        out["failed_jobs"] = {
            "count": len(failed),
            "errors_recorded": errors_recorded,
            "categories": dict(sorted(categories.items())),
        }
    except Exception:
        out["failed_jobs"] = "unavailable"
    return out


def collect() -> dict:
    """Assemble the full redacted diagnostics bundle."""
    import secrets
    bundle: dict[str, Any] = {
        # A ticket key: correlate the bundle a customer sends to their ticket
        # and the exact build — without any customer data.
        "correlation_id": "sup_" + secrets.token_hex(6),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "versions": _versions(),
        "runtime": _runtime(),
        "paths": _paths(),
        "readiness": _readiness(),
        "providers": _providers(),
        "recent_failures": _recent_failures(),
    }
    try:
        from .client import status as client_status
        bundle["client"] = client_status()
    except Exception:
        bundle["client"] = "unavailable"
    try:
        from .config import load_config
        bundle["config_redacted"] = _config_topology(load_config() or {})
    except Exception:
        bundle["config_redacted"] = "unavailable"
    return bundle


def ticket_summary(bundle: dict | None = None) -> dict:
    """A compact, ticket-system-ready view of a bundle — the fields an intake
    queue routes on, keyed by ``correlation_id``: which build, which readiness
    checks are failing, and the recent failure modes. Derived purely from an
    already-redacted :func:`collect` bundle, so it carries no secrets and is
    safe to POST to a portal/email→ticket bridge. Pass a bundle to summarise,
    or omit to collect a fresh one."""
    b = bundle if bundle is not None else collect()
    readiness = b.get("readiness", {}) or {}
    failing = sorted(k for k, v in readiness.items() if str(v).startswith("fail"))
    recent = b.get("recent_failures", {}) or {}
    versions = b.get("versions", {}) or {}
    return {
        "correlation_id": b.get("correlation_id"),
        "generated_at": b.get("generated_at"),
        "agent_version": versions.get("maverick-agent"),
        "readiness_failing": failing,
        "healthy": not failing,
        "failure_modes": recent.get("failure_modes"),
        "failed_job_count": (
            recent["failed_jobs"].get("count")
            if isinstance(recent.get("failed_jobs"), dict)
            else len(recent["failed_jobs"])
            if isinstance(recent.get("failed_jobs"), list)
            else None
        ),
    }


def export(path: str | None = None) -> tuple:
    """Assemble the redacted bundle and write it to ``path`` (default
    ``support-<correlation_id>.json`` in the cwd). Returns ``(Path, bundle)``.

    The customer controls and can inspect the file before sending it — the
    air-gap-safe, regulator-safe support channel (no silent telemetry). Wiring
    an audit-trail record of the export belongs in the CLI wrapper so ``collect``
    stays side-effect free (see docs/enterprise/product-operations.md)."""
    import json
    from pathlib import Path

    from .file_lock import atomic_write_text

    bundle = collect()
    out = Path(path) if path else Path.cwd() / f"support-{bundle['correlation_id']}.json"
    atomic_write_text(out, json.dumps(bundle, indent=2, default=str))
    return out, bundle


__all__ = ["collect", "export", "ticket_summary"]
