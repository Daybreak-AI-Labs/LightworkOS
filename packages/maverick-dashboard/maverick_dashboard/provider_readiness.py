"""One truth about whether an AI service is connected.

Every page that says anything about AI services (the Settings header, the
Providers page, the Chat readiness card, Get started, the installation checks,
``/healthz`` and the provider API) reads :func:`workspace_readiness` so they
can never disagree.

Per provider, "set up" means a real key, server address, login or sign-in is
present after ``${VAR}`` interpolation -- a placeholder that resolves to an
unset variable never counts. "Connected" means the most recent connection test
(``integration_readiness.test_provider``) passed; a saved key that was never
tested is "not tested yet", never "connected".

The workspace verdict looks only at the providers the configured role models
actually use (``get_role_model`` / ``ROLE_MODELS``), for every provider the
registry knows, not just Anthropic:

``ready``
    every provider the models use is set up and its last test passed;
``needs_test``
    every one is set up and none failed, but at least one was never tested;
``not_ready``
    one is missing, blocked, or its last test failed.

Provider test receipts are saved with the current configuration fingerprint
(see ``integration_readiness``). After a restart, a matching receipt retains
the last test result; changing the configuration returns it to "not tested yet".
"""
from __future__ import annotations

import os
import re
from typing import Any

VERDICT_LABELS = {
    "ready": "Connected",
    "needs_test": "Set up, not tested yet",
    "not_ready": "Not connected",
}
VERDICT_BADGE_CLASS = {"ready": "ok", "needs_test": "warn", "not_ready": "blocked"}

ADD_KEY = {"label": "Add an AI provider key", "href": "/settings#settings-integrations"}
TEST_CONNECTION = {"label": "Test the connection", "href": "/providers"}
CHECK_AND_RETEST = {"label": "Check the key and test again", "href": "/providers"}
CHOOSE_MODELS = {"label": "Choose models", "href": "/settings#settings-models"}
HEALTH_CHECK = {"label": "Run the health check", "href": "/settings#settings-maintenance"}
OPEN_SETTINGS = {"label": "Open Settings", "href": "/settings#settings-maintenance"}

# Labels for providers the Settings key form does not list yet.
_EXTRA_LABELS = {
    "tgi": "Hugging Face TGI (self-hosted)",
    "azure": "Azure OpenAI",
    "bedrock": "Amazon Bedrock",
    "vertex": "Google Cloud Vertex AI",
    "openai_compatible": "OpenAI-compatible server",
    "codex_cli": "Codex CLI",
}

_HTTP_STATUS = re.compile(r"HTTP (\d{3})")

# Hosted services that cannot run on a server address alone: a proxy or
# gateway URL without a key is not "set up" (mirrors operator preflight).
_KEY_REQUIRED = frozenset({"anthropic", "openai", "openrouter", "gemini", "moonshot", "deepseek", "xai"})


def provider_labels() -> dict[str, str]:
    from .settings_store import PROVIDERS

    labels = {p["name"]: p["label"] for p in PROVIDERS}
    labels.update(_EXTRA_LABELS)
    return labels


def plain_reason(detail: str) -> str:
    """Turn a probe/dependency/policy detail into one plain sentence."""
    text = str(detail or "").strip()
    lower = text.lower()
    match = _HTTP_STATUS.search(text)
    if match:
        code = int(match.group(1))
        if 300 <= code < 400:
            return "The service redirected the test. Save its final model service address, then test again."
        if code in (401, 403):
            return "The service did not accept the key. Check the key and save it again."
        if code == 429:
            return "The service is busy or the account has reached its limit. Try again in a few minutes."
        if code >= 500:
            return "The service reported a problem on its side. Try again later."
        return f"The service answered with an error (HTTP {code}). Check the key and the server address."
    if "egress policy" in lower or "policy" in lower:
        return "Blocked by your outbound-connection rules. Ask an administrator to allow this address, then test again."
    if "probe failed" in lower:
        return "Lightwork could not reach the service. Check the internet connection or the server address, then test again."
    if "not found" in lower and "codex" in lower:
        return "The Codex tool is not installed on the computer running Lightwork."
    if "sdk" in lower or "not installed" in lower or "dependency" in lower:
        return "Software this service needs is missing on the computer running Lightwork."
    if "no effective" in lower:
        return "The key or server address is missing. Add it and test again."
    if "non-zero" in lower:
        return "The Codex tool is installed but did not start correctly."
    return "The last test did not work. Check the details and test again."


def _roles_by_provider(cfg: dict[str, Any]) -> dict[str, list[str]]:
    """Which roles route to each provider, from the deterministic resolver."""
    from maverick.llm import ROLE_MODELS, _parse_spec, offline_model_for_role

    models = cfg.get("models")
    models = models if isinstance(models, dict) else {}
    roles = set(ROLE_MODELS) | {
        str(role) for role, value in models.items()
        if isinstance(value, str) and value.strip()
    }
    out: dict[str, list[str]] = {}
    for role in sorted(roles):
        provider, _model = _parse_spec(offline_model_for_role(role, config=cfg))
        out.setdefault(provider, []).append(role)
    return out


def _configured(name: str, state: dict[str, Any], table: dict[str, Any]) -> tuple[bool, str]:
    """(set up?, what is saved) for one provider. Placeholders never count:
    ``provider_configuration_state`` reads config AFTER ``${VAR}``
    interpolation, so an unset variable resolves to "" and is not present."""
    if name == "azure":
        # A key alone is not a runnable Azure route: endpoint and deployment
        # (and an unambiguous sign-in) are required, exactly as preflight says.
        from maverick.config import azure_provider_configuration_missing

        return (not azure_provider_configuration_missing(table)), "sign-in"
    if name == "vertex":
        # Google sign-in needs no key: the project, region and model the operator
        # names are the set-up; the live connection test proves the sign-in.
        project = (str(table.get("project_id") or "").strip()
                   or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "").strip()
                   or os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip())
        region = (str(table.get("region") or "").strip()
                  or os.environ.get("CLOUD_ML_REGION", "").strip())
        model = (str(table.get("model_id") or "").strip()
                 or os.environ.get("VERTEX_MODEL_ID", "").strip())
        if not (project and region and model):
            return False, ""
        return True, "Google sign-in"
    if name == "bedrock":
        region = (str(table.get("region") or "").strip()
                  or os.environ.get("AWS_REGION", "").strip()
                  or os.environ.get("AWS_DEFAULT_REGION", "").strip())
        mode = str(table.get("auth_mode") or os.environ.get("BEDROCK_AUTH_MODE") or "").strip().lower()
        if not region:
            return False, ""
        if mode == "iam":
            return True, "AWS sign-in"
        key_ready = bool(state.get("api_key_configured") or os.environ.get("AWS_BEARER_TOKEN_BEDROCK"))
        if mode == "api_key" or key_ready:
            return key_ready, "key"
        return False, ""
    if state.get("api_key_configured"):
        if name == "openai_compatible" and not state.get("base_url_configured"):
            return False, ""
        return True, "key"
    if name in _KEY_REQUIRED or name == "openai_compatible":
        return False, ""
    if name == "codex_cli":
        try:
            from maverick.providers.codex_cli_provider import _auth_file_present

            if _auth_file_present():
                return True, "login"
        except Exception:  # optional provider must not break readiness
            pass
    if state.get("base_url_configured"):
        return True, "server address"
    return False, ""


def _saved_word(saved: str) -> str:
    return {"key": "Key", "server address": "Server address", "login": "Login",
            "sign-in": "Sign-in", "AWS sign-in": "AWS sign-in",
            "Google sign-in": "Google sign-in"}.get(saved, "Key")


def _provider_row(name: str, label: str, cfg: dict[str, Any], roles: list[str]) -> dict[str, Any]:
    from maverick.config import provider_configuration_state

    from .integration_readiness import provider_readiness

    state = provider_configuration_state(name)
    providers = cfg.get("providers")
    table = (providers.get(name) if isinstance(providers, dict) else None) or {}
    configured, saved = _configured(name, state, table if isinstance(table, dict) else {})
    readiness = provider_readiness(name, configured=configured)
    live = readiness["live"]
    runtime = readiness["runtime"]
    row: dict[str, Any] = {
        "name": name,
        "label": label,
        "configured": configured,
        "saved": saved,
        "via": state.get("via"),
        "used_by_roles": list(roles),
        "routed": bool(roles),
        "readiness": readiness,
        "last_test": {
            "status": "never",
            "tested_at": live.get("tested_at"),
            "reason": "",
            "detail": str(live.get("detail") or ""),
        },
    }
    if not configured:
        row.update(status="not_set_up", status_label="Not set up",
                   reason="Add the details to set up this service.")
    elif readiness["policy_allowed"] is False:
        reason = plain_reason(readiness["policy_detail"])
        row.update(status="blocked", status_label="Needs attention: " + reason, reason=reason)
    elif readiness["dependency"]["status"] == "failed":
        reason = plain_reason(readiness["dependency"]["detail"])
        row.update(status="blocked", status_label="Needs attention: " + reason, reason=reason)
    elif runtime["status"] == "passed":
        row["last_test"].update(status="passed", reason="The last connection test worked.")
        row.update(status="connected", status_label="Connected",
                   reason="The last connection test worked.")
    elif runtime["status"] == "failed":
        reason = plain_reason(live.get("detail") or runtime.get("detail") or "")
        if name in {"azure", "bedrock", "vertex"} and _HTTP_STATUS.search(str(live.get("detail") or "")):
            code = int(_HTTP_STATUS.search(str(live.get("detail") or "")).group(1))
            if code in (401, 403):
                reason = "The service did not accept this sign-in. Check the account's model access and try again."
        row["last_test"].update(status="failed", reason=reason)
        if (live.get("evidence", {}).get("blocked_by_egress_policy")
                or "egress policy" in str(live.get("detail") or "").lower()):
            row.update(status="blocked", status_label="Blocked by outbound-connection rules", reason=reason)
        else:
            row.update(status="failed", status_label="Connection failed: " + reason, reason=reason)
    elif name in {"azure", "bedrock", "vertex"} and live.get("status") == "unknown" and live.get("tested_at"):
        kind = live.get("evidence", {}).get("kind")
        reason = {
            "price_preflight": "Add this model's spending ceiling under Models, then test again.",
            "model_mismatch": "The default task model differs from the saved connection. Choose the saved model under Models, then test again.",
            "setup_incomplete": "Enter the model ID shown in your Vertex AI Model Garden, then test again.",
            "budget_limit": "The connection check reached its spending or token limit. Review the model's ceiling, then test again.",
        }.get(kind, "The connection check could not confirm a usable model response. Review its details and test again.")
        row["last_test"].update(status="unknown", reason=reason)
        row.update(status="blocked", status_label="Needs attention: " + reason, reason=reason)
    elif live.get("stale"):
        word = _saved_word(saved)
        row.update(status="untested", status_label=f"{word} saved, not tested yet",
                   reason=f"{live['detail']} Test it again to make sure it still works.")
    else:
        word = _saved_word(saved)
        row.update(status="untested", status_label=f"{word} saved, not tested yet",
                   reason=f"{word} saved, not tested yet. Test it to make sure it works.")
    return row


def _verdict(rows: list[dict[str, Any]]) -> tuple[str, str, dict[str, str] | None]:
    routed = [row for row in rows if row["routed"]]
    if not routed:
        return "not_ready", "No AI models are chosen yet.", dict(CHOOSE_MODELS)
    by_status = {status: [r for r in routed if r["status"] == status]
                 for status in ("not_set_up", "blocked", "failed", "untested", "connected")}
    if by_status["not_set_up"]:
        row = by_status["not_set_up"][0]
        reason = f"{row['label']} is not set up, and your models use it."
        # A different service that already passed its test is the quicker fix:
        # point the models at it. A merely saved one (the installer's default
        # Ollama address, say) is not proof of anything, so add the key.
        connected = [r for r in rows if r["status"] == "connected" and not r["routed"]]
        if connected:
            reason += f" {connected[0]['label']} is connected but no model uses it."
            return "not_ready", reason, dict(CHOOSE_MODELS)
        return "not_ready", reason, dict(ADD_KEY)
    if by_status["blocked"]:
        row = by_status["blocked"][0]
        action = HEALTH_CHECK if row["readiness"]["dependency"]["status"] == "failed" else TEST_CONNECTION
        return "not_ready", f"{row['label']}: {row['reason']}", dict(action)
    if by_status["failed"]:
        row = by_status["failed"][0]
        return "not_ready", f"{row['label']} connection failed: {row['reason']}", dict(CHECK_AND_RETEST)
    if by_status["untested"]:
        row = by_status["untested"][0]
        if row["readiness"]["live"].get("stale"):
            return "needs_test", f"{row['label']}: {row['readiness']['live']['detail']}", dict(TEST_CONNECTION)
        return "needs_test", f"{row['label']}: {_saved_word(row['saved']).lower()} saved, not tested yet.", dict(TEST_CONNECTION)
    names = ", ".join(r["label"] for r in by_status["connected"])
    return "ready", f"{names} connected: the last connection test worked.", None


def _unavailable(reason: str) -> dict[str, Any]:
    return {
        "providers": [],
        "verdict": "not_ready",
        "verdict_label": VERDICT_LABELS["not_ready"],
        "badge_class": VERDICT_BADGE_CLASS["not_ready"],
        "reason": reason,
        "next_action": dict(OPEN_SETTINGS),
        "summary": "AI settings could not be read",
        "configured_count": 0,
        "connected_count": 0,
        "total": 0,
    }


def workspace_readiness() -> dict[str, Any]:
    """Per-provider state for every known provider plus the workspace verdict.

    Never raises: an unreadable configuration is itself a ``not_ready``
    verdict with a plain reason, so no page can crash on it or invent a
    different answer."""
    try:
        from maverick.config import config_source_errors, load_config
        from maverick.providers import KNOWN_PROVIDERS

        cfg = load_config() or {}
        if not isinstance(cfg, dict) or config_source_errors(include_tenant=True):
            return _unavailable("Lightwork's settings could not be read. Open Settings to repair them.")
        roles = _roles_by_provider(cfg)
        labels = provider_labels()
        rows = [
            _provider_row(name, labels.get(name, name.replace("_", " ").title()), cfg, roles.get(name, []))
            for name in KNOWN_PROVIDERS
        ]
    except Exception:  # noqa: BLE001 -- a readiness read never takes a page down
        return _unavailable("Lightwork could not check its AI services. Open Settings and run the health check.")
    verdict, reason, next_action = _verdict(rows)
    configured_count = sum(1 for r in rows if r["configured"])
    connected_count = sum(1 for r in rows if r["status"] == "connected")
    return {
        "providers": rows,
        "verdict": verdict,
        "verdict_label": VERDICT_LABELS[verdict],
        "badge_class": VERDICT_BADGE_CLASS[verdict],
        "reason": reason,
        "next_action": next_action,
        "summary": f"{configured_count} set up · {connected_count} connected",
        "configured_count": configured_count,
        "connected_count": connected_count,
        "total": len(rows),
    }


def public_verdict(readiness: dict[str, Any]) -> dict[str, Any]:
    """The verdict without per-provider rows, for JSON responses."""
    return {key: readiness[key] for key in
            ("verdict", "verdict_label", "reason", "next_action", "summary",
             "configured_count", "connected_count", "total")}


def attention_provider(readiness: dict[str, Any]) -> str | None:
    """The provider row a person should look at first.

    The routed provider the workspace verdict is about (missing, then blocked,
    failed, untested -- the order :func:`_verdict` reports them), else the
    first provider the models use. ``None`` when no model is chosen yet. The
    "Open AI provider keys" link on a stopped task lands on this row."""
    routed = [row for row in readiness.get("providers") or [] if row.get("routed")]
    for status in ("not_set_up", "blocked", "failed", "untested"):
        for row in routed:
            if row.get("status") == status:
                return row["name"]
    return routed[0]["name"] if routed else None


def apply_to_rows(rows: list[dict[str, Any]], readiness: dict[str, Any]) -> list[dict[str, Any]]:
    """Copy the one truth onto Settings/Providers inventory rows (in place)."""
    by_name = {row["name"]: row for row in readiness["providers"]}
    for row in rows:
        truth = by_name.get(row["name"])
        if truth is None:
            continue
        for key in ("configured", "readiness", "status", "status_label", "reason",
                    "last_test", "used_by_roles", "routed"):
            row[key] = truth[key]
    return rows


__all__ = [
    "VERDICT_LABELS", "apply_to_rows", "attention_provider", "plain_reason", "provider_labels",
    "public_verdict", "workspace_readiness",
]
