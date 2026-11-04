"""One reviewed synthetic model call, with durable no-replay receipts."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import re
import struct
import time
import uuid
import zlib
from dataclasses import replace

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from .governed_operations import digest
from .llm import LLM
from .paths import current_tenant_id_strict, data_dir

CAPS = {"max_dollars": .05, "max_input_tokens": 2048, "max_output_tokens": 64,
        "max_wall_seconds": 30, "max_tool_calls": 0}
KINDS = {"generation": "Short text generation", "vision": "Synthetic image recognition"}
PROVIDERS = frozenset({"anthropic", "openai", "openrouter", "ollama", "gemini", "moonshot",
                      "deepseek", "xai", "tgi", "vllm", "azure", "bedrock", "vertex",
                      "openai_compatible"})


def policy():
    from . import config
    if config.config_source_errors(include_tenant=True):
        raise PermissionError("Model test settings are unavailable. Repair Settings before testing.")
    if (config.load_config().get("models") or {}).get("capability_tests", False) is not True:
        raise PermissionError("Enable bounded model tests in All settings before testing.")


def limits():
    from .budget import resolve_budget_caps
    configured = resolve_budget_caps()
    return {key: value if configured.get(key) is None else min(value, configured[key]) for key, value in CAPS.items()}


def route(model):
    from .enterprise import assert_provider_allowed
    from .llm import require_model_allowed
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9_.:/@-]{1,200}", model):
        raise ValueError("Choose an exact model name from your provider.")
    canonical = require_model_allowed(model)
    provider = canonical.split(":", 1)[0]
    if provider not in PROVIDERS:
        raise ValueError("This test requires a configured API provider; host command adapters cannot be tested here.")
    assert_provider_allowed(provider)
    admitted = LLM(canonical)._provider_client_config(provider)
    return {"model": canonical, "provider": provider, "fingerprint": admitted.fingerprint,
            "tenant": current_tenant_id_strict()}


def _path(context):
    if not re.fullmatch(r"[a-f0-9]{64}", context):
        raise ValueError("Invalid account context")
    return data_dir() / "model-tests" / (context + ".json")


def _read(path):
    if not path.exists():
        return {"schema": 1, "checks": {}}
    value = json.loads(atomic_read_text(path, encoding="utf-8"))
    if value.get("schema") != 1 or not isinstance(value.get("checks"), dict):
        raise ValueError("Model test history is unavailable. Nothing was replayed.")
    return value


def _edit(context, mutate):
    path = _path(context)
    ensure_private_directory(path.parent)
    from .authority_effects import authority_effect_fence
    with authority_effect_fence(), cross_process_lock(path.with_suffix(".lock"), strict=True):
        value = _read(path)
        result = mutate(value["checks"])
        atomic_write_text(path, json.dumps(value, allow_nan=False), encoding="utf-8")
        return result


def history(context):
    path = _path(context)
    if not path.exists():
        return []
    with cross_process_lock(path.with_suffix(".lock"), strict=True):
        return list(_read(path)["checks"].values())


def get(context, identity):
    return next((row for row in history(context) if row["id"] == identity), None)


def public(row):
    value = {key: value for key, value in row.items() if key not in {"route", "binding"}}
    if (row["state"] in {"queued", "executing"} and time.time() > row.get("started_at", row["created_at"]) + row["limits"]["max_wall_seconds"] + 10):
        value.update(state="unknown", may_still_be_running=True,
                     message="No terminal receipt arrived within the test window. The original request was not replayed. Request stop and check original accounting receipts.")
    return value


def prepare(context, model, kind, guard):
    guard()
    policy()
    if kind not in KINDS:
        raise ValueError("Choose text generation or synthetic image recognition.")
    selected, caps = route(model), limits()
    if caps["max_input_tokens"] <= 0 or caps["max_output_tokens"] <= 0 or caps["max_wall_seconds"] <= 0:
        raise ValueError("Current token or time policy does not permit a model test.")
    row = {"id": uuid.uuid4().hex, "model": selected["model"], "kind": kind,
           "state": "prepared", "created_at": time.time(), "expires_at": time.time() + 600,
           "route": selected, "limits": caps, "cancel_requested": False,
           "scope": "One synthetic sample only; tool use, quality, context size and live task suitability remain untested.",
           "notice": "One potentially paid request. No retry or model failover. A cancellation or timeout after dispatch can still be billed; check the original accounting receipt before deciding to run another test."}
    row["binding"] = digest({"route": selected, "limits": caps, "kind": kind})
    def insert(checks):
        guard()
        if len(checks) >= 1000:
            raise ValueError("Model test receipt storage reached its limit. Existing operation references are retained; ask support to archive the workspace before further tests.")
        checks[row["id"]] = row
        return row
    return _edit(context, insert)


def claim(context, identity, guard):
    def update(checks):
        guard()
        row = checks.get(identity)
        if row is None:
            raise ValueError("This model test is not available in this account and workspace.")
        if row["state"] != "prepared":
            return row, False
        policy()
        if time.time() >= row["expires_at"]:
            raise ValueError("This model test review expired. Prepare a new review.")
        current = {"route": route(row["model"]), "limits": limits(), "kind": row["kind"]}
        if digest(current) != row["binding"]:
            raise ValueError("Model configuration, approval policy or limits changed. Review again before spending.")
        row.update(state="queued", started_at=time.time())
        return dict(row), True
    return _edit(context, update)


def cancel(context, identity, guard):
    def update(checks):
        guard()
        row = checks.get(identity)
        if row is None:
            raise ValueError("This model test is not available in this account and workspace.")
        if row["state"] in {"prepared", "queued"}:
            row.update(state="cancelled", cancel_requested=True, message="Cancelled before dispatch.")
        elif row["state"] == "executing":
            row.update(cancel_requested=True, message="Stop requested. The original request may already be billable; no retry will be sent.")
        return dict(row)
    return _edit(context, update)


class PinnedTestLLM(LLM):
    def __init__(self, selected):
        super().__init__(selected["model"])
        self.selected = selected

    def _provider_client_config(self, provider):
        selected = self.selected
        raw = super()._provider_client_config(provider)
        if (provider != selected["provider"] or current_tenant_id_strict() != selected["tenant"]
                or raw.fingerprint != selected["fingerprint"]):
            raise PermissionError("The provider route changed before dispatch.")
        # Narrow only this test's immutable client snapshot; saved deployment
        # configuration and credentials are unchanged.
        env = raw.environment_dict()
        for key, maximum in (("MAVERICK_LLM_READ_TIMEOUT", 15), ("MAVERICK_LLM_CONNECT_TIMEOUT", 5)):
            value = float(env.get(key, maximum))
            if not math.isfinite(value) or value <= 0:
                raise ValueError("Provider timeout configuration is unavailable.")
            env[key] = str(min(value, maximum))
        return replace(raw, provider_environment=tuple(sorted(env.items())),
                       fingerprint=digest([raw.fingerprint, "model-test-v1", env.get("MAVERICK_LLM_READ_TIMEOUT"), env.get("MAVERICK_LLM_CONNECT_TIMEOUT")]))


def sample(row):
    if row["kind"] == "generation":
        return [{"role": "user", "content": "Reply with exactly LIGHTWORK_TEST_READY and nothing else."}], "LIGHTWORK_TEST_READY"
    colors = (("RED", (255, 0, 0)), ("GREEN", (0, 255, 0)), ("BLUE", (0, 0, 255)))
    expected, color = colors[int(row["id"][:8], 16) % len(colors)]
    def chunk(kind, payload):
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress((b"\x00" + bytes(color) * 16) * 16)) + chunk(b"IEND", b"")
    return [{"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": base64.b64encode(png).decode()}},
        {"type": "text", "text": "What is the single color in this synthetic image? Reply with exactly RED, GREEN, or BLUE and nothing else."}]}], expected


def _admission(actor, tenant):
    from . import killswitch, quotas, spending_limits
    from .tenant.registry import assert_tenant_active
    killswitch.check()
    if tenant:
        assert_tenant_active(tenant)
    if quotas.quotas_enforced() and (not actor or quotas.over_quota(actor)):
        raise PermissionError("A named account with an available AI allowance is required.")
    if spending_limits.start_refusal(actor):
        raise PermissionError("AI work is paused by a spending limit.")


async def run(context, identity, actor, tenant, guard):
    """Run a claimed review once. A crash leaves an ambiguous receipt, never a retry."""
    from .budget import budget_from_config
    from .connections import bind_principal
    from .orchestrator import _QuotaUsageSettlement
    from .paths import tenant_scope
    from .tenant.provider_admission import run_scope

    with tenant_scope(tenant=tenant), bind_principal(actor):
        row = get(context, identity)
        if row is None or row["state"] != "queued":
            return
        budget = settlement = task = None
        outcome = {"state": "unknown", "message": "The test result is unconfirmed. The original call was not replayed."}
        begun = time.monotonic()
        try:
            def current():
                guard()
                policy()
                if route(row["model"]) != row["route"] or limits() != row["limits"]:
                    raise PermissionError("Model policy or limits changed.")
                live = get(context, identity)
                if live is None or live.get("cancel_requested"):
                    raise PermissionError("Model test stopped.")
                _admission(actor, tenant)
                if budget is not None:
                    budget.check()
            current()
            budget = budget_from_config(**row["limits"])
            if getattr(budget, "_tenant_refusal", None):
                raise PermissionError("Workspace allowance is unavailable.")
            budget.check()
            settlement = _QuotaUsageSettlement(principal=actor, budget=budget, domain=None)
            messages, expected = sample(row)
            current()
            def mark_only(checks):
                guard()
                live = checks[identity]
                if live["state"] != "queued" or live.get("cancel_requested"):
                    raise PermissionError("This test is no longer queued.")
                live.update(state="executing", message="One bounded request is in progress; an interrupted result is never retried.")
            _edit(context, mark_only)
            with run_scope(budget, actor):
                task = asyncio.create_task(PinnedTestLLM(row["route"]).complete_async(
                    system="Perform only the requested synthetic capability sample. Do not use tools.",
                    messages=messages, tools=None, budget=budget, max_tokens=min(64, int(budget.max_output_tokens)),
                    _no_failover=True, dispatch_guard=current, max_physical_attempts=1))
                while not task.done():
                    await asyncio.wait({task}, timeout=.1)
                    current()
                    if time.monotonic() - begun >= row["limits"]["max_wall_seconds"]:
                        raise TimeoutError("Model test deadline elapsed")
                reply = await task
                current()
                text = getattr(reply, "text", None)
                passed = isinstance(text, str) and text.strip() == expected and not getattr(reply, "tool_calls", None)
                outcome = {"state": "passed" if passed else "not_matched", "sample_matched": passed,
                           "latency_seconds": round(time.monotonic() - begun, 3),
                           "message": "The single synthetic sample matched." if passed else "A response arrived but did not match this sample. This does not prove that the model lacks the capability.",
                           "response_sha256": hashlib.sha256(str(text).encode()).hexdigest(),
                           "recorded_dollars": budget.dollars}
        except (Exception, asyncio.CancelledError):
            live = get(context, identity)
            before = live is not None and live["state"] in {"queued", "cancelled"}
            outcome = {"state": "cancelled" if before and live.get("cancel_requested") else "refused" if before else "unknown",
                       "message": "No request was started." if before else "The request may have been billed. Its result is unconfirmed; it was not retried. Check Budget and the provider receipt before starting another test."}
        finally:
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except (Exception, asyncio.CancelledError):
                    pass
            if settlement is not None:
                settlement.record()
            outcome["finished_at"] = time.time()
            def finish(checks):
                if outcome["state"] in {"passed", "not_matched"}:
                    try:
                        current()
                    except Exception:
                        outcome.clear()
                        outcome.update(state="unknown", finished_at=time.time(),
                                       message="Policy or access changed before publication. Check the original accounting receipt; this request was not repeated.")
                checks[identity].update(outcome)
            _edit(context, finish)
