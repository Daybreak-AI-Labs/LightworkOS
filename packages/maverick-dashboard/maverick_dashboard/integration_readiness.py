"""Bounded readiness receipts for dashboard-managed integrations.

Configuration and readiness are deliberately separate states.  Saving a key,
server, or channel proves only that Lightwork retained the operator's input; it
does not prove that the remote system accepted it.  This module keeps short
receipts tied to an exact configuration fingerprint.  A configuration change
therefore falls back to ``untested`` rather than carrying a stale green badge
forward.

Receipts contain no response bodies, headers, credentials, or URLs.  Channel
and MCP receipts are process-local.  Provider receipts are also written to
``<MAVERICK_HOME>/provider_test_receipts.json`` (atomic write with POSIX mode
0600 or a restricted Windows ACL) so
a working service stays "Connected" across a dashboard restart: the file holds
only the provider name, the outcome, the timestamp, the plain reason and the
SHA-256 fingerprint of the credential material -- a hash that stays on this
machine, never the key.  A stored receipt is used only while its fingerprint
still matches the current credential and it is younger than
``[providers] test_receipt_max_age_days`` (default 30); after that the
provider reads "not tested yet" again with the age of the last test.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_LOCK = threading.RLock()
_RECEIPTS: dict[tuple[str, str], dict[str, Any]] = {}
_RECEIPTS_BASENAME = "provider_test_receipts.json"
_PERSISTED_KINDS = frozenset({"provider"})


class IntegrationConfigurationUnavailable(RuntimeError):
    """An active integration configuration source cannot be trusted."""


def require_readable_config() -> dict[str, Any]:
    """Load the effective config and reject any fail-soft source error.

    ``maverick.config.load_config`` deliberately returns defaults for malformed
    TOML so ordinary model selection can remain available.  An integration
    inventory must not turn that fallback into a false "nothing configured"
    result, so inventory surfaces admit the snapshot only after the canonical
    source-error check passes.
    """
    from maverick.config import config_source_errors, load_config

    config = load_config() or {}
    if not isinstance(config, dict) or config_source_errors():
        raise IntegrationConfigurationUnavailable(
            "active integration configuration is unreadable"
        )
    return config


def fingerprint(material: object) -> str:
    """Return an internal identity for an exact effective configuration."""
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def record(
    kind: str,
    name: str,
    material: object,
    *,
    verified: bool | None,
    detail: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record one bounded result for exactly ``material``.

    ``detail`` and ``evidence`` are caller-authored summaries.  Callers must not
    pass provider or server response bodies because those can echo secrets.
    """
    receipt = {
        "status": "verified" if verified is True else "failed" if verified is False else "unknown",
        "checked": True,
        "verified": verified,
        "detail": str(detail)[:240],
        "tested_at": time.time(),
        "evidence": dict(evidence or {}),
        "fingerprint": fingerprint(material),
    }
    with _LOCK:
        _RECEIPTS[(str(kind), str(name))] = receipt
        if str(kind) in _PERSISTED_KINDS:
            _persist(str(name), receipt)
    return public_receipt(receipt)


def _receipts_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / _RECEIPTS_BASENAME


def _load_persisted() -> dict[str, dict[str, Any]]:
    """Stored provider receipts; an unreadable or malformed file is simply
    "never tested" (readiness must not crash on a bad file)."""
    try:
        from maverick.file_lock import atomic_read_bytes

        raw = json.loads(atomic_read_bytes(_receipts_path()).decode("utf-8"))
    except Exception:  # noqa: BLE001 -- missing, unreadable or corrupt: no receipts
        return {}
    rows = raw.get("providers") if isinstance(raw, dict) else None
    return {
        str(name): row for name, row in (rows or {}).items()
        if isinstance(row, dict) and isinstance(row.get("fingerprint"), str)
    }


def _persist(name: str, receipt: dict[str, Any]) -> None:
    """Write one provider receipt (fingerprint hash + outcome only) to disk."""
    try:
        from maverick.file_lock import atomic_write_text, cross_process_lock

        from .provider_readiness import plain_reason

        # Another dashboard worker may save a receipt for a different provider
        # at the same moment; hold the file lock across read and write so
        # neither erases the other's.
        with cross_process_lock(_receipts_path()):
            rows = _load_persisted()
            rows[name] = {
                "status": receipt["status"],
                "verified": receipt["verified"],
                "detail": receipt["detail"],
                "reason": plain_reason(receipt["detail"]) if receipt["verified"] is False else "",
                "tested_at": receipt["tested_at"],
                "evidence": receipt.get("evidence") or {},
                "fingerprint": receipt["fingerprint"],
            }
            atomic_write_text(
                _receipts_path(),
                json.dumps({"schema": 1, "providers": rows}, sort_keys=True, indent=1),
                mode=0o600,
            )
    except Exception:  # noqa: BLE001 -- a receipt that cannot be saved is still valid in-process
        return


def _stored_receipt(name: str, expected: str) -> dict[str, Any] | None:
    """A persisted provider receipt for the current credential, or None.

    Expired receipts come back with ``status`` ``unknown`` and a plain
    ``detail`` naming the age of the last test."""
    row = _load_persisted().get(name)
    if row is None or row.get("fingerprint") != expected:
        return None
    try:
        tested_at = float(row.get("tested_at") or 0)
    except (TypeError, ValueError):
        return None
    if tested_at <= 0:
        return None
    from maverick.config import provider_test_receipt_max_age_days

    age_days = int((time.time() - tested_at) // 86400)
    if age_days >= provider_test_receipt_max_age_days():
        passed = row.get("verified") is True
        return {
            "status": "unknown",
            "checked": False,
            "verified": None,
            "detail": (f"Last successful test was {age_days} days ago." if passed
                       else f"Last test was {age_days} days ago and did not pass."),
            "tested_at": tested_at,
            "evidence": {"stale": True, "last_verified": row.get("verified")},
            "stale": True,
        }
    return {
        "status": "verified" if row.get("verified") is True else "failed" if row.get("verified") is False else "unknown",
        "checked": True,
        "verified": row.get("verified"),
        "detail": str(row.get("detail") or "")[:240],
        "tested_at": tested_at,
        "evidence": dict(row.get("evidence") or {}),
    }


_UNTESTED: dict[str, Any] = {
    "status": "unknown",
    "checked": False,
    "verified": None,
    "detail": "saved configuration has not passed a readiness check",
    "tested_at": None,
    "evidence": {},
}


def get(kind: str, name: str, material: object) -> dict[str, Any]:
    """Return a receipt only when it still matches the effective config."""
    expected = fingerprint(material)
    with _LOCK:
        receipt = _RECEIPTS.get((str(kind), str(name)))
        if receipt is not None and receipt.get("fingerprint") == expected:
            return public_receipt(receipt)
    if str(kind) in _PERSISTED_KINDS:
        stored = _stored_receipt(str(name), expected)
        if stored is not None:
            return stored
    return dict(_UNTESTED)


def public_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key != "fingerprint"
    }


def clear(kind: str, name: str) -> None:
    with _LOCK:
        _RECEIPTS.pop((str(kind), str(name)), None)


def check(
    status: str,
    detail: str,
    *,
    kind: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one closed dependency/runtime check result."""
    if status not in {"passed", "failed", "unknown", "not_applicable"}:
        raise ValueError(f"invalid readiness check status {status!r}")
    passed = True if status == "passed" else False if status == "failed" else None
    return {
        "status": status,
        "checked": status in {"passed", "failed"},
        "passed": passed,
        "detail": str(detail)[:240],
        "evidence": {"kind": kind, **dict(evidence or {})},
    }


def contract(
    *,
    configured: bool,
    policy_allowed: bool | None,
    policy_detail: str,
    dependency: dict[str, Any],
    runtime: dict[str, Any],
    live: dict[str, Any],
) -> dict[str, Any]:
    """Return the common typed readiness contract used by every inventory."""
    if not configured:
        state = "not_configured"
    elif policy_allowed is False:
        state = "policy_denied"
    elif dependency.get("status") == "failed":
        state = "dependency_failed"
    elif runtime.get("status") == "failed":
        state = "runtime_failed"
    elif live.get("status") == "verified":
        state = "live_verified"
    elif live.get("status") == "failed":
        state = "live_failed"
    elif policy_allowed is None:
        state = "policy_unknown"
    elif runtime.get("status") == "passed":
        state = "runtime_passed_live_unknown"
    elif dependency.get("status") == "passed":
        state = "dependency_passed_runtime_unknown"
    else:
        state = "unverified"
    return {
        "configured": bool(configured),
        "policy_allowed": policy_allowed,
        "policy_detail": str(policy_detail)[:240],
        "dependency": dependency,
        "runtime": runtime,
        "live": live,
        "state": state,
    }


def _provider_key(provider: str, provider_config: dict[str, Any]) -> str:
    value = provider_config.get("api_key")
    if isinstance(value, str) and value.strip():
        return value.strip()
    from maverick.config import PROVIDER_KEY_ENV_MAP

    for env_name in PROVIDER_KEY_ENV_MAP.get(provider, ()):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    return ""


_PROVIDER_DEFAULT_ENDPOINTS = {
    "anthropic": "https://api.anthropic.com/v1/models",
    "openai": "https://api.openai.com/v1/models",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/models",
    "openrouter": "https://openrouter.ai/api/v1/models",
    "moonshot": "https://api.moonshot.ai/v1/models",
    "deepseek": "https://api.deepseek.com/v1/models",
    "xai": "https://api.x.ai/v1/models",
}
_SELF_HOSTED_PROVIDERS = frozenset({"ollama", "vllm", "tgi", "openai_compatible"})


def _cloud_receipt_material(name: str, material: dict[str, Any]) -> object:
    """Bind cloud receipts to the actual routed identity, including env inputs."""
    if name not in {"azure", "bedrock", "vertex"}:
        return material
    try:
        from maverick.llm import LLM

        return {"config": material, "route": LLM()._provider_client_config(name).fingerprint}
    except Exception:
        return {"config": material, "route": "unavailable"}


def _probe_native_cloud(name: str) -> dict[str, Any]:
    """One small model request through the same native client used by tasks.

    SDK response bodies are discarded. A successful constructor or IAM token
    lookup alone is never enough to label the provider connected.
    """
    from maverick.budget import Budget, BudgetExceeded, UnpricedModelError, _lookup_price_quote
    from maverick.llm import LLM, _enforce_provider_cap, model_for_role
    from maverick.provider_cost_cap import ProviderCapExceeded
    from maverick.providers import get_provider_client

    client = None
    held = 0.0
    budget = Budget(max_input_tokens=512, max_output_tokens=16,
                    max_dollars=0.05, max_wall_seconds=15)
    try:
        route = LLM()._provider_client_config(name)
        client = get_provider_client(
            name, api_key=route.api_key, base_url=route.base_url,
            default_headers=route.headers_dict(), environment=route.environment_dict(),
        )
        model_id = client.deployment if name == "azure" else client.DEFAULT_MODEL
        if name == "vertex":
            from maverick.providers.vertex_provider import valid_model_id

            if not valid_model_id(model_id):
                return {
                    "verified": None,
                    "detail": "enter the model ID exactly as shown in your Vertex AI Model Garden",
                    "evidence": {"kind": "setup_incomplete", "external_live_verified": False},
                }
        chosen = model_for_role("default")
        if chosen.startswith(f"{name}:") and chosen.partition(":")[2] != model_id:
            return {
                "verified": None,
                "detail": "the default task model differs from the model saved in this connection",
                "evidence": {"kind": "model_mismatch", "external_live_verified": False},
            }
        spec = f"{name}:{model_id}"
        quote = _lookup_price_quote(spec)
        projected = (256 * quote.input_per_mtok + 16 * quote.output_per_mtok) / 1_000_000
        _enforce_provider_cap(name, projected)
        budget.check()
        held = budget.reserve(projected)
        if name == "azure":
            args = client._build_kwargs(
                "Connection check.", [{"role": "user", "content": "Reply OK."}],
                None, 16, model_id,
            )
            response = client._sync.with_options(timeout=8.0, max_retries=0).chat.completions.create(**args)
        else:
            response = client.client.with_options(timeout=8.0, max_retries=0).messages.create(
                model=model_id, max_tokens=16,
                messages=[{"role": "user", "content": "Reply OK."}],
            )
        usage = getattr(response, "usage", None)
        if usage is None:
            budget.record_tokens(256, 16, model=spec)
            return {
                "verified": None,
                "detail": "the service answered but did not report usage for the connection check",
                "evidence": {"kind": "live_model_probe", "external_live_verified": False},
            }
        input_tokens = getattr(usage, "prompt_tokens" if name == "azure" else "input_tokens", None)
        output_tokens = getattr(usage, "completion_tokens" if name == "azure" else "output_tokens", None)
        if input_tokens is None or output_tokens is None:
            raise ValueError("usage missing")
        budget.record_tokens(input_tokens, output_tokens, model=spec)
        return {
            "verified": True, "detail": "provider accepted the bounded model request",
            "evidence": {"kind": "live_model_probe", "external_live_verified": True},
        }
    except UnpricedModelError:
        return {
            "verified": None,
            "detail": "set a current spending ceiling for this model before testing its connection",
            "evidence": {"kind": "price_preflight", "external_live_verified": False},
        }
    except BudgetExceeded:
        return {
            "verified": None,
            "detail": "the connection check exceeded its small spending or token limit",
            "evidence": {"kind": "budget_limit", "external_live_verified": False},
        }
    except ProviderCapExceeded:
        # The cap is checked here, before anything is sent: the provider was
        # never contacted, so this is not a failed test.
        return {
            "verified": None,
            "detail": "this provider has reached its spending ceiling for the period, so its connection was not checked",
            "evidence": {"kind": "budget_limit", "external_live_verified": False},
        }
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        detail = (f"provider readiness request returned HTTP {status}"
                  if isinstance(status, int) and 100 <= status <= 599 else
                  f"provider probe failed ({type(exc).__name__})")
        return {
            "verified": False, "detail": detail,
            "evidence": {"kind": "live_model_probe", "external_live_verified": False},
        }
    finally:
        if held:
            budget.release(held)
        if client is not None:
            sync = getattr(client, "_sync", None) or getattr(client, "client", None)
            close = getattr(sync, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass


def _append_endpoint(base_url: str, suffix: str) -> str:
    parsed = urlsplit(base_url.strip())
    path = parsed.path.rstrip("/") + "/" + suffix.lstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _valid_self_hosted_address(base_url: str) -> bool:
    try:
        parsed = urlsplit(base_url)
        _ = parsed.port  # reject malformed ports before making a request
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"} and bool(parsed.hostname)
        and parsed.username is None and parsed.password is None
        and not parsed.query and not parsed.fragment
        and not any(char.isspace() for char in base_url)
    )


def _self_hosted_probe_address(name: str, base_url: str) -> str:
    """Use the same server path as the provider's runtime client."""
    if name == "ollama":
        return base_url.rstrip("/").removesuffix("/v1")
    if name in {"vllm", "tgi"}:
        return base_url.rstrip("/").removesuffix("/v1") + "/v1"
    return base_url


def probe_provider(provider: str, provider_config: dict[str, Any]) -> dict[str, Any]:
    """Perform a bounded live authentication/readiness probe.

    Only status code evidence is retained.  Provider bodies and headers are
    intentionally discarded because they can contain account metadata or echo
    request material.
    """
    from maverick.tools import _ssrf

    name = str(provider).strip().lower()
    if name in {"azure", "bedrock", "vertex"}:
        return _probe_native_cloud(name)
    key = _provider_key(name, provider_config)
    base_url = str(provider_config.get("base_url") or "").strip()
    if name == "codex_cli":
        binary = str(provider_config.get("binary") or "codex").strip()
        resolved = shutil.which(binary)
        if not resolved:
            return {
                "verified": False,
                "detail": "configured Codex CLI binary was not found",
                "evidence": {"kind": "local_runtime_probe"},
            }
        try:
            result = subprocess.run(
                [resolved, "--version"],
                capture_output=True,
                check=False,
                timeout=8.0,
            )
        except Exception as exc:
            return {
                "verified": False,
                "detail": f"Codex CLI runtime probe failed ({type(exc).__name__})",
                "evidence": {"kind": "local_runtime_probe"},
            }
        passed = result.returncode == 0
        return {
            # Local process availability is runtime evidence, not external-live
            # provider acceptance, so live verification deliberately stays unknown.
            "verified": None if passed else False,
            "detail": (
                "Codex CLI binary passed a bounded local version probe"
                if passed
                else "Codex CLI binary returned a non-zero version result"
            ),
            "evidence": {
                "kind": "local_runtime_probe",
                "runtime_verified": passed,
                "external_live_verified": False,
            },
        }
    headers: dict[str, str] = {"Authorization": f"Bearer {key}"} if key else {}
    if name == "ollama":
        base_url = base_url or "http://127.0.0.1:11434"
        suffix = "api/tags"
    elif name in {"vllm", "tgi", "openai_compatible"}:
        if not base_url:
            env_names = {
                "vllm": ("VLLM_BASE_URL", "OPENAI_COMPATIBLE_BASE_URL"),
                "tgi": ("TGI_BASE_URL",),
                "openai_compatible": ("OPENAI_COMPATIBLE_BASE_URL",),
            }[name]
            for env_name in env_names:
                base_url = os.environ.get(env_name, "").strip()
                if base_url:
                    break
        if not base_url:
            return {
                "verified": False,
                "detail": f"no effective {name} base URL is configured",
                "evidence": {"kind": "live_status_probe"},
            }
        suffix = "models"
    else:
        endpoint = (
            _append_endpoint(base_url, "models")
            if base_url
            else _PROVIDER_DEFAULT_ENDPOINTS.get(name, "")
        )
        if not endpoint:
            return {
                "verified": None,
                "detail": "this provider has no bounded dashboard probe",
                "evidence": {
                    "kind": "unsupported",
                    "external_live_verified": False,
                },
            }
        if not key:
            return {
                "verified": False,
                "detail": "no effective provider key is configured",
                "evidence": {"kind": "live_status_probe"},
            }
        if name == "anthropic":
            headers = {
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
            }
        elif name == "gemini":
            headers = {"x-goog-api-key": key}
        else:
            headers = {"Authorization": f"Bearer {key}"}
    if name in _SELF_HOSTED_PROVIDERS:
        if not _valid_self_hosted_address(base_url):
            return {
                "verified": False,
                "detail": "provider address must be an HTTP or HTTPS URL without sign-in details",
                "evidence": {"kind": "live_status_probe"},
            }
        base_url = _self_hosted_probe_address(name, base_url)
        endpoint = _append_endpoint(base_url, suffix)
    try:
        if name in _SELF_HOSTED_PROVIDERS:
            import httpx

            # This address is the effective operator-configured model endpoint
            # (or Ollama's built-in loopback default), as with runtime clients.
            # Never follow a response to a different, unconfigured host.
            response = httpx.get(
                endpoint, headers=headers, timeout=8.0,
                follow_redirects=False, trust_env=False,
            )
        else:
            response = _ssrf.safe_get(endpoint, headers=headers, timeout=8.0)
    except _ssrf.BlockedHost:
        return {
            "verified": False,
            "detail": "provider endpoint is blocked by the egress policy",
            "evidence": {"kind": "live_status_probe", "blocked_by_egress_policy": True},
        }
    except Exception as exc:
        return {
            "verified": False,
            "detail": f"provider probe failed ({type(exc).__name__})",
            "evidence": {"kind": "live_status_probe"},
        }
    status = int(response.status_code)
    verified = 200 <= status < 300
    return {
        "verified": verified,
        "detail": (
            "provider accepted the bounded models request"
            if verified
            else f"provider readiness request returned HTTP {status}"
        ),
        "evidence": {"kind": "live_status_probe", "http_status": status},
    }


def provider_readiness(provider: str, *, configured: bool) -> dict[str, Any]:
    """Typed provider state without performing network I/O."""
    from maverick.config import get_provider_config

    name = str(provider).strip().lower()
    try:
        material = get_provider_config(name) or {}
    except Exception as exc:
        unavailable = check(
            "failed",
            f"provider configuration is unavailable ({type(exc).__name__})",
            kind="provider_configuration",
        )
        return contract(
            configured=configured,
            policy_allowed=None,
            policy_detail="provider policy could not be evaluated",
            dependency=unavailable,
            runtime=check(
                "unknown",
                "runtime probe cannot run without readable configuration",
                kind="provider_runtime_probe",
            ),
            live=get("provider", name, {"configuration_unavailable": True}),
        )
    policy_allowed: bool | None = None
    policy_detail = "provider policy is not evaluated until it is configured"
    if configured:
        try:
            from maverick.enterprise import enterprise_enabled, is_local_provider

            policy_allowed = not enterprise_enabled() or is_local_provider(name)
            policy_detail = (
                "provider is admitted by the effective egress policy"
                if policy_allowed
                else "provider is blocked by the enterprise egress policy"
            )
        except Exception as exc:
            policy_allowed = None
            policy_detail = f"provider policy is unavailable ({type(exc).__name__})"
    if not configured:
        dependency = check(
            "unknown",
            "dependency check is deferred until configuration exists",
            kind="provider_sdk",
        )
    else:
        from maverick.providers import missing_sdks

        missing = missing_sdks((f"{name}:readiness-probe",))
        dependency = check(
            "failed" if missing else "passed",
            missing[0] if missing else "provider SDK dependency is importable",
            kind="provider_sdk",
        )
    live = get("provider", name, _cloud_receipt_material(name, material))
    runtime_verified = live.get("evidence", {}).get("runtime_verified") is True
    runtime = check(
        (
            "passed"
            if live["status"] == "verified" or runtime_verified
            else "failed"
            if live["status"] == "failed"
            else "unknown"
        ),
        live["detail"],
        kind="provider_runtime_probe",
        evidence=live.get("evidence"),
    )
    return contract(
        configured=configured,
        policy_allowed=policy_allowed,
        policy_detail=policy_detail,
        dependency=dependency,
        runtime=runtime,
        live=live,
    )


def test_provider(provider: str) -> dict[str, Any]:
    """Run and retain a fingerprint-bound bounded provider probe."""
    from maverick.config import get_provider_config

    name = str(provider).strip().lower()
    material = get_provider_config(name) or {}
    readiness = provider_readiness(name, configured=True)
    if readiness["policy_allowed"] is not True:
        result = {
            "verified": False,
            "detail": readiness["policy_detail"],
            "evidence": {"kind": "policy_preflight"},
        }
    elif readiness["dependency"]["status"] != "passed":
        result = {
            "verified": False,
            "detail": readiness["dependency"]["detail"],
            "evidence": {"kind": "dependency_preflight"},
        }
    else:
        result = probe_provider(name, material)
    return record(
        "provider",
        name,
        _cloud_receipt_material(name, material),
        verified=result["verified"],
        detail=result["detail"],
        evidence=result.get("evidence"),
    )


_CHANNEL_REQUIRED_FIELDS = {
    "telegram": ("bot_token",),
    "discord": ("bot_token",),
    "slack": ("app_token", "bot_token"),
    "whatsapp_cloud": (
        "access_token",
        "phone_number_id",
        "verify_token",
        "app_secret",
    ),
    "sms": ("account_sid", "auth_token", "from_number"),
    "email": (
        "imap_host",
        "imap_user",
        "imap_password",
        "smtp_host",
        "smtp_user",
        "smtp_password",
    ),
    "mattermost": ("url",),
    "teams": ("app_id", "app_password", "tenant_id"),
}

_CHANNEL_MODULES = {
    "telegram": "maverick_channels.telegram",
    "discord": "maverick_channels.discord",
    "slack": "maverick_channels.slack",
    "matrix": "maverick_channels.matrix",
    "bluesky": "maverick_channels.bluesky",
    "mastodon": "maverick_channels.mastodon",
    "whatsapp": "maverick_channels.whatsapp",
    "whatsapp_cloud": "maverick_channels.whatsapp_cloud",
    "threads": "maverick_channels.threads",
    "rcs": "maverick_channels.rcs",
    "sms": "maverick_channels.sms",
    "email": "maverick_channels.email",
    "voice": "maverick_channels.voice",
    "mattermost": "maverick_channels.mattermost",
    "teams": "maverick_channels.teams",
    "irc": "maverick_channels.irc",
}

# Adapter modules deliberately defer optional imports so the dashboard itself
# can start without every chat integration.  Check what an enabled adapter
# actually needs before saying its required software is present.
_CHANNEL_SDKS = {
    "telegram": ("telegram",),
    "discord": ("discord", "aiohttp"),
    "slack": ("slack_sdk", "aiohttp"),
    "matrix": ("nio", "aiohttp"),
    "bluesky": ("httpx",),
    "mastodon": ("httpx",),
    "whatsapp": ("fastapi", "twilio", "multipart"),
    "whatsapp_cloud": ("fastapi", "httpx"),
    "threads": ("httpx",),
    "rcs": ("fastapi", "httpx", "google.auth"),
    "sms": ("fastapi", "twilio", "multipart"),
    "email": (),
    "voice": ("fastapi", "httpx"),
    "mattermost": ("httpx",),
    "teams": ("fastapi", "httpx", "jwt"),
    "irc": (),
}

_CHANNEL_NAMES = {
    "sms": "Text messaging",
    "rcs": "RCS",
    "whatsapp_cloud": "WhatsApp Business",
    "teams": "Microsoft Teams",
    "irc": "IRC",
}


def _channel_dependency(channel: str) -> dict[str, Any]:
    module = _CHANNEL_MODULES.get(channel)
    if not module:
        return check("unknown", "this channel has no bounded software check", kind="channel_adapter")
    label = _CHANNEL_NAMES.get(channel, channel.replace("_", " ").title())
    try:
        missing = []
        for sdk in _CHANNEL_SDKS[channel]:
            try:
                present = importlib.util.find_spec(sdk) is not None
            except (ImportError, ValueError):
                present = False
            if not present:
                missing.append(sdk)
        if missing:
            return check(
                "failed",
                f"{label} support is missing from this Lightwork installation. "
                "Ask your installation administrator to add it, then restart "
                "the chat service in Settings.",
                kind="channel_adapter", evidence={"missing_modules": missing},
            )
        adapter = importlib.import_module(module)
        # A cached adapter can still be unusable if its optional import failed
        # before the software was installed. Restarting reloads that adapter.
        flag = {"telegram": "_HAVE_TELEGRAM", "discord": "_HAVE_DISCORD",
                "slack": "_HAVE_SLACK", "matrix": "_HAVE_MATRIX"}.get(channel, "_HAVE_DEPS")
        if hasattr(adapter, flag) and getattr(adapter, flag) is not True:
            return check(
                "failed",
                f"{label} support did not load. Ask your installation "
                "administrator to repair it, then restart the chat service in Settings.",
                kind="channel_adapter",
            )
    except Exception as exc:
        return check(
            "failed",
            f"{label} support could not load "
            f"({type(exc).__name__}). Ask your installation administrator to repair it, "
            "then restart the chat service in Settings.",
            kind="channel_adapter",
        )
    return check("passed", "required chat support is installed and loads locally",
                 kind="channel_adapter")


def _voice_configuration_problem(channel_config: dict[str, Any]) -> str:
    """A local voice preflight must reflect the inbound caller gate."""
    try:
        from maverick_channels.voice import (
            _HAVE_DEPS,
            INBOUND_PROVIDERS,
            PROVIDER_KEY_ENV,
            configured_callers,
        )
    except ImportError:
        return "The phone call adapter is unavailable."
    if not _HAVE_DEPS:
        return "Phone call support is not installed on this server."

    try:
        callers = configured_callers(channel_config.get("allowed_callers"))
    except ValueError:
        return "Caller numbers must use +countrycode format in Settings > All settings > Chat channels > Phone calls."
    if not callers:
        return "Add permitted caller numbers in Settings > All settings > Chat channels > Phone calls before calls can start work."
    provider = str(channel_config.get("provider") or "vapi")
    if provider not in INBOUND_PROVIDERS:
        return "This phone service supports outgoing calls only. Choose Vapi or Retell for incoming conversations."
    if not channel_config.get("assistant_id"):
        return "Choose the saved assistant from your phone service in All settings before receiving calls."
    key_env = PROVIDER_KEY_ENV.get(provider, "VAPI_API_KEY")
    if not (channel_config.get("api_key") or os.environ.get(key_env)):
        return "The phone call service key is missing."
    if not (channel_config.get("webhook_token") or os.environ.get("VAPI_WEBHOOK_TOKEN")):
        return "The incoming call check key is missing."
    return ""


def _email_configuration_problem(channel_config: dict[str, Any]) -> str:
    from maverick.mail_auth import valid_trusted_mail_server
    from maverick.microsoft_mail import configuration_problem
    from maverick_channels.base import normalize_allowlist

    problem = configuration_problem(channel_config)
    if problem:
        return problem
    # Same fallback as the email channel: an unsaved setting uses the variable.
    if not valid_trusted_mail_server(channel_config.get("trusted_authserv_id")
                                     or os.environ.get("EMAIL_TRUSTED_AUTHSERV_ID")):
        return ("Set the server that checks incoming mail on the Channels page. "
                "Until then, email cannot start work.")
    senders = normalize_allowlist(channel_config.get("allowed_user_ids"),
                                  "EMAIL_ALLOWED_USER_IDS")
    if not senders or any(
        re.fullmatch(r"[^@\s,]+@[A-Za-z0-9.-]+", sender) is None or ".." in sender
        for sender in senders
    ):
        return "Add full permitted email addresses on the Channels page before email can start work."
    return ""


def _channel_allowlist_problem(channel: str, channel_config: dict[str, Any]) -> str:
    from maverick_channels.base import normalize_allowlist

    from .settings_catalog import CHANNEL_ALLOWLISTS

    access = CHANNEL_ALLOWLISTS.get(channel)
    if not access or not access[1] or channel == "email":
        return ""
    key, pattern, error = access[2], access[5], access[6]
    supplied = channel_config.get(key)
    if supplied is not None and not isinstance(supplied, list):
        return "The permitted-people list needs attention on the Channels page."
    people = normalize_allowlist(supplied, f"{channel.upper()}_{key.upper()}")
    if not people:
        return "Add permitted people on the Channels page before this chat app can start work."
    if any(re.fullmatch(pattern, person) is None for person in people):
        return f"The permitted-people list needs {error} on the Channels page."
    return ""


def probe_channel(name: str, channel_config: dict[str, Any]) -> dict[str, Any]:
    """Verify local adapter/config readiness without sending a message.

    A green result proves that the configured adapter can be imported and its
    required fields are present.  It is not presented as external delivery or
    webhook acceptance.
    """
    channel = str(name).strip().lower()
    if channel == "voice":
        problem = _voice_configuration_problem(channel_config)
        if problem:
            return {"verified": False, "detail": problem,
                    "evidence": {"kind": "local_adapter_preflight"}}
    if channel == "email":
        problem = _email_configuration_problem(channel_config)
        if problem:
            return {"verified": False, "detail": problem,
                    "evidence": {"kind": "local_adapter_preflight"}}
    problem = _channel_allowlist_problem(channel, channel_config)
    if problem:
        return {"verified": False, "detail": problem,
                "evidence": {"kind": "local_adapter_preflight"}}
    required = _CHANNEL_REQUIRED_FIELDS.get(channel, ())
    if channel == "email" and channel_config.get("email_auth") == "microsoft":
        required = tuple(field for field in required if not field.endswith("_password"))
    missing = [
        field
        for field in required
        if not str(channel_config.get(field) or "").strip()
    ]
    if missing:
        return {
            "verified": False,
            "detail": "missing required field(s): " + ", ".join(missing),
            "evidence": {"kind": "local_adapter_preflight"},
        }
    dependency = _channel_dependency(channel)
    if dependency["status"] != "passed":
        return {
            "verified": False,
            "detail": dependency["detail"],
            "evidence": {"kind": "local_adapter_preflight", "dependency": dependency["evidence"]},
        }
    return {
        "verified": True,
        "detail": "local adapter and required configuration passed preflight",
        "evidence": {
            "kind": "local_adapter_preflight",
            "external_delivery_verified": False,
        },
    }


def channel_readiness(name: str, channel_config: dict[str, Any]) -> dict[str, Any]:
    """Local channel preflight; external delivery remains explicitly unknown."""
    channel = str(name).strip().lower()
    configured = bool(channel_config.get("enabled", False))
    if not configured:
        dependency = check(
            "unknown",
            "adapter dependency is not checked for a disabled channel",
            kind="channel_adapter",
        )
        runtime = check(
            "unknown",
            "channel runtime preflight has not run",
            kind="channel_local_preflight",
        )
    else:
        dependency = _channel_dependency(channel)
        required = _CHANNEL_REQUIRED_FIELDS.get(channel, ())
        if channel == "email" and channel_config.get("email_auth") == "microsoft":
            required = tuple(field for field in required if not field.endswith("_password"))
        missing = [
            field
            for field in required
            if not str(channel_config.get(field) or "").strip()
        ]
        voice_problem = _voice_configuration_problem(channel_config) if channel == "voice" else ""
        email_problem = _email_configuration_problem(channel_config) if channel == "email" else ""
        allowlist_problem = _channel_allowlist_problem(channel, channel_config)
        runtime = check(
            "failed" if missing or voice_problem or email_problem or allowlist_problem else "passed",
            (
                voice_problem or email_problem or allowlist_problem or "missing required field(s): " + ", ".join(missing)
                if voice_problem or email_problem or allowlist_problem or missing
                else "required channel configuration passed local preflight"
            ),
            kind="channel_local_preflight",
        )
    live = get("channel", channel, channel_config)
    return contract(
        configured=configured,
        policy_allowed=True if configured else None,
        policy_detail=(
            "no separate channel policy denied this configuration"
            if configured
            else "channel policy is not evaluated until it is configured"
        ),
        dependency=dependency,
        runtime=runtime,
        live=live,
    )


def mcp_readiness(name: str, server_config: dict[str, Any]) -> dict[str, Any]:
    """Validate an MCP spec/dependency without starting it on inventory reads."""
    server = str(name).strip()
    material = dict(server_config)
    policy_allowed: bool | None = None
    policy_detail = "MCP policy could not be evaluated"
    try:
        from maverick.mcp_client import MCPServerSpec

        spec = MCPServerSpec.from_config(server, material)
    except Exception as exc:
        dependency = check(
            "failed",
            f"MCP configuration is invalid ({type(exc).__name__})",
            kind="mcp_dependency",
        )
    else:
        policy_allowed = True
        policy_detail = "MCP server is admitted by the effective runtime policy"
        if spec.is_http:
            from maverick.enterprise import enterprise_egress_denial

            denial = enterprise_egress_denial(spec.url or "", tool=f"mcp:{server}")
            if denial:
                policy_allowed = False
                policy_detail = denial
            try:
                http_dependency = importlib.util.find_spec("httpx") is not None
            except Exception:
                http_dependency = False
            dependency = check(
                "passed" if http_dependency else "failed",
                "HTTP MCP client dependency is importable"
                if http_dependency
                else "HTTP MCP client dependency is missing",
                kind="mcp_http_client",
            )
        else:
            command = spec.command
            resolved = (
                str(Path(command).resolve())
                if Path(command).is_absolute() and Path(command).is_file()
                else shutil.which(command)
            )
            dependency = check(
                "passed" if resolved else "failed",
                "MCP command dependency is resolvable"
                if resolved
                else "MCP command dependency was not found",
                kind="mcp_stdio_command",
            )
    live = get("mcp", server, material)
    runtime = check(
        "passed" if live["status"] == "verified" else (
            "failed" if live["status"] == "failed" else "unknown"
        ),
        live["detail"],
        kind="mcp_handshake",
        evidence=live.get("evidence"),
    )
    return contract(
        configured=True,
        policy_allowed=policy_allowed,
        policy_detail=policy_detail,
        dependency=dependency,
        runtime=runtime,
        live=live,
    )


def mcp_inventory() -> list[dict[str, Any]]:
    """Effective MCP inventory with secrets retained only in fingerprints."""
    from maverick.runtime_overrides import mcp_overlay

    configured = require_readable_config().get("mcp_servers") or {}
    overlay = mcp_overlay()
    rows: list[dict[str, Any]] = []
    for name, spec in configured.items():
        if isinstance(spec, dict):
            rows.append(_mcp_row(name, spec, "config"))
    for name, spec in overlay.items():
        if name not in configured and isinstance(spec, dict):
            rows.append(_mcp_row(name, spec, "dashboard"))
    return rows


def mcp_server_config(name: str) -> dict[str, Any] | None:
    """Return one effective raw MCP spec for an authorized readiness action."""
    from maverick.runtime_overrides import mcp_overlay

    configured = require_readable_config().get("mcp_servers") or {}
    value = configured.get(name)
    if isinstance(value, dict):
        return dict(value)
    value = mcp_overlay().get(name)
    return dict(value) if isinstance(value, dict) else None


def _mcp_row(name: str, spec: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "name": name,
        "transport": "http" if spec.get("url") else "stdio",
        "command": spec.get("command") or "",
        "args": spec.get("args") or [],
        "url": spec.get("url") or "",
        "source": source,
        "removable": source == "dashboard",
        "configured": True,
        "readiness": mcp_readiness(name, spec),
    }


async def test_mcp(name: str, server_config: dict[str, Any]) -> dict[str, Any]:
    """Start, initialize, list tools, and stop one MCP server within a bound."""
    from maverick.mcp_client import MCPClient, MCPServerSpec, StreamableHttpMCPClient

    server = str(name).strip()
    material = dict(server_config)
    client: Any = None
    try:
        spec = MCPServerSpec.from_config(server, material)
        client = StreamableHttpMCPClient(spec, timeout=8.0) if spec.is_http else MCPClient(
            spec, timeout=8.0
        )
        await asyncio.wait_for(client.start(), timeout=12.0)
        result = {
            "verified": True,
            "detail": f"MCP initialize and tools/list passed ({len(client.tools)} tool(s))",
            "evidence": {"kind": "mcp_handshake", "tool_count": len(client.tools)},
        }
    except Exception as exc:
        result = {
            "verified": False,
            "detail": f"MCP readiness handshake failed ({type(exc).__name__})",
            "evidence": {"kind": "mcp_handshake"},
        }
    finally:
        if client is not None:
            try:
                await client.stop()
            except Exception:
                pass
    return record(
        "mcp",
        server,
        material,
        verified=result["verified"],
        detail=result["detail"],
        evidence=result["evidence"],
    )


def plugin_readiness(row: dict[str, Any]) -> dict[str, Any]:
    """Map the plugin import check (policy admission plus a real import) into the
    common integration contract."""
    configured = bool(row.get("configured"))
    allowed = bool(row.get("allowed")) if configured else None
    state = str(row.get("state") or "")
    if not configured or allowed is False:
        dependency = check(
            "unknown",
            "plugin dependencies were not imported",
            kind="plugin_import",
        )
        runtime = check(
            "unknown",
            "plugin registration was not attempted",
            kind="plugin_registration",
        )
    elif row.get("loaded"):
        dependency = check(
            "passed",
            "plugin entry-point dependency imported",
            kind="plugin_import",
        )
        runtime = check(
            "passed",
            "plugin entry point passed its registration contract",
            kind="plugin_registration",
        )
    else:
        dependency = check(
            "failed" if state == "import_failed" else "passed",
            str(row.get("load_error") or "plugin import state is unavailable"),
            kind="plugin_import",
        )
        runtime = check(
            "failed",
            str(row.get("load_error") or "plugin registration failed"),
            kind="plugin_registration",
        )
    live = {
        "status": "unknown",
        "checked": False,
        "verified": None,
        "detail": "plugin import does not verify an external integration",
        "tested_at": None,
        "evidence": {"kind": "not_available"},
    }
    return contract(
        configured=configured,
        policy_allowed=allowed,
        policy_detail=(
            "plugin passed the effective trust policy"
            if allowed
            else str(row.get("load_error") or "plugin policy was not evaluated")
        ),
        dependency=dependency,
        runtime=runtime,
        live=live,
    )


def _clear_for_testing() -> None:
    with _LOCK:
        _RECEIPTS.clear()


__all__ = [
    "IntegrationConfigurationUnavailable",
    "channel_readiness",
    "check",
    "clear",
    "contract",
    "fingerprint",
    "get",
    "mcp_readiness",
    "mcp_inventory",
    "mcp_server_config",
    "plugin_readiness",
    "probe_channel",
    "probe_provider",
    "provider_readiness",
    "record",
    "require_readable_config",
    "test_mcp",
    "test_provider",
]
