"""Source-owned, digest-only evidence from actual guarded connector attempts."""
from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Callable

from . import ai_runtime_guardrails as runtime
from . import crypto_at_rest
from .governed_records import GovernedRecordStore
from .paths import current_tenant_id_strict

MAX_RECORDS = 10_000
SCHEMA = "lightwork.runtime-enforcement.v1"
STATES = frozenset({"prepared", "refused", "executed", "failed", "accepted", "indeterminate"})
STORE = GovernedRecordStore("runtime-enforcement", "RTE", "runtime_enforcement")


class EnforcementUnavailable(RuntimeError):
    """Exact local enforcement evidence could not be retained or verified."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _tenant():
    tenant = current_tenant_id_strict()
    if tenant is None:
        raise EnforcementUnavailable("Select a workspace before reading safeguard activity.")
    return tenant


def _decode(row):
    if not crypto_at_rest.is_sealed_str(row.get("body")):
        raise EnforcementUnavailable("Protected safeguard activity is unavailable.")
    try:
        body = json.loads(crypto_at_rest.unseal_from_str(row["body"]))
        if (set(body) != {"schema", "tenant", "actor_sha256", "request_sha256", "receipt", "status"}
                or body["schema"] != SCHEMA or body["tenant"] != _tenant()
                or body["status"] not in STATES or digest(body) != row.get("body_sha256")):
            raise ValueError("binding")
        if any(not isinstance(body[name], str) or runtime._DIGEST_RE.fullmatch(body[name]) is None
                for name in ("actor_sha256", "request_sha256")):
            raise ValueError("identity")
        receipt = runtime._validated_result_receipt(runtime.RuntimeGuardrailResult(
            decision=body["receipt"]["decision"], receipt=body["receipt"]))
        if receipt["asset_binding"]["tenant_ref"] != runtime._tenant_ref():
            raise ValueError("tenant")
    except Exception as exc:
        raise EnforcementUnavailable("Saved safeguard activity could not be verified.") from exc
    return {**body, "id": row["id"], "revision": row["revision"], "created_at": row["created_at"],
        "updated_at": row["updated_at"], "confirmed": not bool(row.get("_audit_pending"))}


def records():
    """Read complete bounded native custody; never infer an effect from absence."""
    _tenant()
    rows = STORE.list(limit=MAX_RECORDS + 1)
    if len(rows) > MAX_RECORDS:
        raise EnforcementUnavailable("Safeguard activity exceeds its supported inventory. Nothing was silently omitted.")
    return [_decode(row) for row in rows]


def original(identifier):
    _tenant()
    row = STORE.get(identifier)
    return None if row is None else _decode(row)


def capture(result, *, actor, request_sha256, status, effect_guard: Callable[[], None]):
    """A caller's guard runs again under the physical native receipt writer."""
    if status not in STATES or not isinstance(actor, str) or not actor:
        raise EnforcementUnavailable("The safeguard activity identity is unavailable.")
    runtime.require_enabled()
    receipt = dict(runtime._validated_result_receipt(result))
    tenant = _tenant()
    if receipt["asset_binding"]["tenant_ref"] != runtime._tenant_ref():
        raise EnforcementUnavailable("The safeguard workspace changed.")
    if not isinstance(request_sha256, str) or runtime._DIGEST_RE.fullmatch(request_sha256) is None:
        raise EnforcementUnavailable("The safeguard request identity is unavailable.")
    body = {"schema": SCHEMA, "tenant": tenant, "actor_sha256": digest(actor),
        "request_sha256": request_sha256, "receipt": receipt, "status": status}

    def guard():
        effect_guard()
        runtime.require_enabled()
        if _tenant() != tenant:
            raise EnforcementUnavailable("The safeguard workspace changed before saving activity.")

    guard()
    sealed = crypto_at_rest.seal_to_str(json.dumps(body, sort_keys=True, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(sealed):
        raise EnforcementUnavailable("Protected safeguard activity could not be saved.")
    row = STORE.create({"id": "RTE-" + secrets.token_hex(16), "body": sealed,
        "body_sha256": digest(body)}, action="enforcement_prepared" if status == "prepared" else "enforcement_refused",
        actor=actor, max_records=MAX_RECORDS, effect_guard=guard)
    if row.get("_audit_pending"):
        raise EnforcementUnavailable("Safeguard activity is retained but its activity record is unconfirmed. No action was admitted.")
    return row["id"]


def finish(identifier, *, status, actor, effect_guard: Callable[[], None]):
    """Retain an observed outcome; a failed finish leaves prepared/unknown custody."""
    if status not in STATES - {"prepared"}:
        raise EnforcementUnavailable("The safeguard outcome is unavailable.")
    row = STORE.get(identifier)
    if row is None:
        raise EnforcementUnavailable("The original safeguard activity is unavailable.")
    body = _decode(row)
    if body["actor_sha256"] != digest(actor) or body["status"] != "prepared":
        raise EnforcementUnavailable("The safeguard activity belongs to another or completed attempt.")
    exact = {key: body[key] for key in ("schema", "tenant", "actor_sha256", "request_sha256", "receipt")}
    exact["status"] = status
    sealed = crypto_at_rest.seal_to_str(json.dumps(exact, sort_keys=True, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(sealed):
        raise EnforcementUnavailable("Protected safeguard outcome could not be saved.")

    def guard():
        effect_guard()
        if _tenant() != exact["tenant"]:
            raise EnforcementUnavailable("The safeguard workspace changed before recording the result.")

    def mutate(current):
        if current.get("body_sha256") != row["body_sha256"]:
            raise EnforcementUnavailable("The original safeguard activity changed.")
        current.update(body=sealed, body_sha256=digest(exact))

    saved = STORE.update(identifier, mutate, expected_revision=row["revision"],
        action="enforcement_outcome", actor=actor, effect_guard=guard)
    if saved is None or saved.get("_audit_pending"):
        raise EnforcementUnavailable("The action result has not been confirmed in safeguard activity. Read the original; do not send again.")
    return _decode(saved)


def observed_decision(row, *, asset, policy_sha256):
    binding = row["receipt"]["asset_binding"]
    if (not row["confirmed"] or row["status"] in {"prepared", "accepted", "indeterminate"}
            or binding["asset_revision"] != asset["revision"]
            or binding["asset_version_digest"] != asset["version_digest"]
            or row["receipt"]["policy_sha256"] != policy_sha256):
        return "unknown"
    decision = row["receipt"]["decision"]
    if row["status"] == "refused":
        return {"block": "block", "restrict": "restrict", "review": "review"}.get(decision, "unknown")
    return "allow" if decision == "allow" else "unknown"
