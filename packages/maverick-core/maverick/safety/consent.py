"""Consent prompts for destructive actions.

Tools that mutate user state (rm, force-push, mass-send, dd, mkfs)
call ``require_consent(action, risk_level)`` which:

  1. Checks the consent ledger -- a previously-granted consent for the
     same (action, scope) returns immediately.
  2. Checks ``MAVERICK_CONSENT_MODE`` env var:
        - "auto-approve" (default) -> grant + log (no friction out of the box)
        - "auto-deny"              -> deny + log
        - "ask"                    -> ask a person: prompt at a terminal; for a
                                      task someone started in Lightwork's chat,
                                      park it on the Approvals page and deny if
                                      nobody decides in time; otherwise (a
                                      headless run) deny at once
        - "dashboard"              -> park in the approvals queue + poll
  3. Logs an audit event for prompt + result.

Threading: prompts serialize through a lock so two parallel agents
don't both pop a prompt simultaneously on the same TTY.

Note: this is the *primitive*. Tools wire it in themselves (the ``shell``
tool does). The base mode is ``auto-approve``, but under **secure-by-default**
**high-** and **critical-risk** actions fail closed to ``ask`` (routing to the
approvals queue / dashboard) instead of auto-approving; low/medium stay
non-interactive out of the box. An operator can widen or narrow this via
``MAVERICK_CONSENT_MODE`` (or per-action config), and ``[security]
secure_defaults = false`` / ``MAVERICK_SECURE_DEFAULT=0`` restores the old
fully-opt-in behavior.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Any

from ..config_contracts import BOOLEAN_SETTINGS, INTEGER_SETTINGS
from ..constant_time import text_equals
from ..file_lock import (
    atomic_create_bytes,
    atomic_read_bytes,
    atomic_read_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
    open_private_append,
    require_private_directory,
)
from ..paths import TenantPolicyError, current_tenant_id_strict, data_dir

log = logging.getLogger(__name__)

# Legacy single-user override.  Keep this as a real attribute so test/integration
# patching restores ``None`` instead of materialising a tenant path returned by
# module ``__getattr__`` and pinning later calls to that stale location.
CONSENT_LEDGER_PATH: Path | None = None


def _same_ledger_path(left: Path, right: Path) -> bool:
    """Compare canonical paths, failing closed on resolution errors."""
    try:
        return left.expanduser().resolve(strict=False) == right.expanduser().resolve(
            strict=False
        )
    except (OSError, RuntimeError):
        return False


def _resolve_ledger_path(path: Path | None = None) -> Path:
    """Resolve a consent ledger without crossing a tenant boundary.

    ``CONSENT_LEDGER_PATH`` and the explicit ``path=`` argument predate tenant
    isolation.  They remain available to unscoped, single-user deployments,
    but a named tenant must always use its own data directory.  In particular,
    a stale process-wide override must never turn into a shared-grant fallback
    in a long-lived multi-tenant worker.
    """
    # Standing consent is an authorization boundary, so diagnostic identity
    # resolution is not sufficient here: corrupt client configuration must not
    # become indistinguishable from legitimate legacy/unbound mode. Resolve the
    # strict identity once and thread that exact value into path construction to
    # avoid a second lookup disagreeing with the admission decision.
    tenant = current_tenant_id_strict()
    if tenant is not None:
        active = data_dir("consent.ledger", tenant=tenant)
        if path is not None and not _same_ledger_path(Path(path), active):
            raise TenantPolicyError(
                "explicit consent ledger path does not match the active tenant"
            )
        return active
    if path is not None:
        return Path(path)
    override = CONSENT_LEDGER_PATH
    return Path(override) if override is not None else data_dir("consent.ledger")


def consent_ledger_path() -> Path:
    """The active tenant's consent ledger.

    A module-level path is unsafe in long-lived multi-tenant workers because it
    freezes whichever tenant imported this module first. An explicitly assigned
    legacy attribute remains an override for unscoped integrations/tests; it is
    deliberately ignored once a tenant or client floor is active.
    """
    return _resolve_ledger_path()


class ConsentDenied(Exception):
    """Raised when ``require_consent(..., raise_on_deny=True)`` is denied."""

    def __init__(self, action: str):
        super().__init__(f"consent denied for action: {action}")
        self.action = action


@dataclass(frozen=True)
class ConsentDecision:
    granted: bool
    source: str           # "ledger" | "auto" | "prompt" | "non-tty-deny"
    risk: str             # "low" | "medium" | "high" | "critical"
    ts: float
    actor: str = ""        # authenticated dashboard approver when available


@dataclass
class ConsentPermit:
    """One-use proof for one exact operation, rechecked at its effect boundary.

    Raw targets and parameters stay in memory behind providers.  Only their
    canonical digests are written to an approval card.  A failed validation
    burns the permit so a caller must obtain a fresh human review.
    """

    card: dict[str, Any]
    decision: ConsentDecision
    target_provider: Callable[[], object]
    parameters_provider: Callable[[], object]
    input_versions_provider: Callable[[], Mapping[str, Any]] | None
    credential_versions_provider: Callable[[], Mapping[str, Any]] | None
    budget_provider: Callable[[], Mapping[str, Any]] | None
    actor_hint: str | None = None
    principal_bound_at_issue: bool = False
    _lock: threading.Lock = dataclass_field(default_factory=threading.Lock, repr=False)
    _consumed: bool = dataclass_field(default=False, repr=False)

    def claim(self) -> bool:
        with self._lock:
            if self._consumed:
                return False
            self._consumed = True
            return True


_prompt_lock = threading.Lock()
_ledger_lock = threading.RLock()

_LEDGER_VERSION = 2
_MAX_LEDGER_BYTES = 4 * 1024 * 1024
_MAX_LEDGER_RECORDS = 10_000
_MAX_ACTION_CHARS = 256
_MAX_SCOPE_CHARS = 4096


class ConsentLedgerError(RuntimeError):
    """The standing-consent authority could not be verified safely."""


_CONSENT_MODES = frozenset({"auto-approve", "auto-deny", "ask", "dashboard"})


def _configured_mode() -> str:
    """``[safety] consent_mode`` from config, ``""`` when unset or unreadable."""
    try:
        from ..config import load_config

        raw = ((load_config() or {}).get("safety") or {}).get("consent_mode")
    except Exception:
        return ""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return ""
    mode = str(raw).strip().lower()
    return mode if mode in _CONSENT_MODES else "ask"


# Consent modes from the strictest to the loosest. "ask" outranks "dashboard":
# outside a terminal it refuses every headless run at once and withdraws an
# unanswered request, while "dashboard" parks any run's request on the
# Approvals page.
_STRICTNESS = ("auto-deny", "ask", "dashboard", "auto-approve")

# A per-task consent mode (director mode's autonomy level for one task). It is
# only ever applied when it is at least as strict as the installation's mode.
_TASK_MODE: ContextVar[str | None] = ContextVar("maverick_task_consent_mode", default=None)


def _strictness(mode: str) -> int:
    """Position in :data:`_STRICTNESS`; a mode this module does not know ranks
    strictest (-1), so nothing can be chosen over it."""
    try:
        return _STRICTNESS.index(mode)
    except ValueError:
        return -1


@contextmanager
def task_consent_mode(mode: str | None) -> Iterator[None]:
    """Run the enclosed task under ``mode`` where that tightens consent.

    The installation's mode (``MAVERICK_CONSENT_MODE``, ``[safety]
    consent_mode``, enterprise and secure-by-default rules) stays the ceiling:
    a task may ask for a stricter mode, never a looser one. A mode this module
    does not know is treated as "ask". ``None`` or ``""`` leaves consent as it
    is. Bound through a ContextVar, so concurrent tasks never see each other's
    mode.
    """
    value = str(mode or "").strip().lower() or None
    if value is not None and value not in _CONSENT_MODES:
        value = "ask"
    token = _TASK_MODE.set(value)
    try:
        yield
    finally:
        _TASK_MODE.reset(token)


def _resolve_mode(risk: str | None = None) -> str:
    """The consent mode for an action: the installation's, or the task's own
    when that is stricter (see :func:`task_consent_mode`)."""
    installation = _installation_mode(risk)
    task = _TASK_MODE.get()
    if task and _strictness(task) < _strictness(installation):
        return task
    return installation


def _installation_mode(risk: str | None = None) -> str:
    # Explicit operator setting always wins (any risk level).
    env = os.environ.get("MAVERICK_CONSENT_MODE")
    if env:
        return env.strip().lower()
    return installation_mode_for(_configured_mode(), risk)


def installation_mode_for(configured: str, risk: str | None = None) -> str:
    """The mode an action at ``risk`` gets when ``[safety] consent_mode`` is
    ``configured`` ("" when unset) and no environment variable overrides it.
    The approval-threshold preview asks this for a choice not yet saved; the
    gate asks it for the saved one, so both always agree."""
    # The same choice made in the dashboard (``[safety] consent_mode``); the
    # environment variable still wins. A value this module does not know
    # fails closed to asking a person.
    configured = str(configured or "").strip().lower()
    if configured:
        return configured if configured in _CONSENT_MODES else "ask"
    # Enterprise mode flips the default to 'ask' so destructive actions are gated
    # (a person decides; headless runs are denied) when handling sensitive data.
    try:
        from ..enterprise import enterprise_enabled
        if enterprise_enabled():
            return "ask"
    except Exception:
        pass
    # Secure-by-default: gate HIGH/CRITICAL-risk actions (an autonomous run can't
    # take a destructive action without an explicit decision -> 'ask', which
    # asks the person behind a chat task on the Approvals page and denies a
    # headless run). Low/medium stay frictionless so normal goals are
    # unaffected. An explicit MAVERICK_CONSENT_MODE opts out.
    if str(risk or "").strip().lower() in ("high", "critical"):
        try:
            from ..security_defaults import secure_by_default
            if secure_by_default():
                return "ask"
        except Exception:
            pass
    return "auto-approve"


def _validate_ledger_field(value: str, *, name: str, limit: int, empty: bool) -> str:
    if not isinstance(value, str):
        raise ValueError(f"consent {name} must be a string")
    if (not empty and not value) or len(value) > limit:
        qualifier = f"1..{limit}" if not empty else f"0..{limit}"
        raise ValueError(f"consent {name} must contain {qualifier} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"consent {name} cannot contain control characters")
    return value


def _validated_key(action: str, scope: str | None) -> tuple[str, str]:
    return (
        _validate_ledger_field(
            action, name="action", limit=_MAX_ACTION_CHARS, empty=False,
        ),
        _validate_ledger_field(
            scope or "", name="scope", limit=_MAX_SCOPE_CHARS, empty=True,
        ),
    )


def _principal_binding() -> str:
    try:
        from ..connections import current_principal

        principal = str(current_principal() or "local")
    except Exception:  # pragma: no cover - context lookup cannot widen authority
        principal = "local"
    return hashlib.sha256(principal.encode("utf-8")).hexdigest()


def _policy_binding() -> str:
    try:
        from ..enterprise import enterprise_enabled

        enterprise = bool(enterprise_enabled())
    except Exception:
        enterprise = False
    try:
        from ..security_defaults import secure_by_default

        secure = bool(secure_by_default())
    except Exception:
        secure = True
    policy = {
        "enterprise": enterprise,
        "secure_defaults": secure,
        "version": _LEDGER_VERSION,
    }
    raw = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _unscoped_policy_binding(policy: str) -> str:
    """Separate newly authorized unscoped grants from ambiguous old grants.

    Older rows do not record whether an operator or earned autonomy created
    them. They remain in the signed history but cannot authorize new effects.
    Scoped rows retain their original binding.
    """
    return hashlib.sha256(("explicit-unscoped-v2:" + policy).encode("ascii")).hexdigest()


def _authority_binding() -> tuple[str, str, str]:
    return (
        str(current_tenant_id_strict() or "shared"),
        _principal_binding(),
        _policy_binding(),
    )


def _is_default_ledger_path(path: Path) -> bool:
    return _same_ledger_path(path, data_dir("consent.ledger"))


def _prepare_ledger_parent(path: Path) -> None:
    if _is_default_ledger_path(path) or not path.parent.exists():
        ensure_private_directory(path.parent)
    else:
        # A caller-selected standing-authorization store is an integrity
        # boundary. Never claim a shared directory by changing its ACL.
        require_private_directory(path.parent)


@contextmanager
def _locked_ledger(path: Path | None = None) -> Iterator[Path]:
    resolved = _resolve_ledger_path(path)
    _prepare_ledger_parent(resolved)
    with _ledger_lock:
        with cross_process_lock(resolved, strict=True):
            yield resolved


def _key_path(path: Path) -> Path:
    return path.with_name(path.name + ".key")


def _ledger_key(path: Path, *, create: bool) -> bytes | None:
    key_path = _key_path(path)
    if key_path.exists():
        ensure_private_file(key_path)
        key = atomic_read_bytes(key_path)
        if len(key) != 32:
            raise ConsentLedgerError("consent ledger signing key is malformed")
        return key
    if not create:
        return None
    if path.exists() and path.stat().st_size:
        raise ConsentLedgerError(
            "unsigned or legacy consent ledger cannot authorize actions; "
            "move it aside and re-authorize standing grants"
        )
    key = secrets.token_bytes(32)
    try:
        atomic_create_bytes(key_path, key)
    except FileExistsError:
        ensure_private_file(key_path)
        key = atomic_read_bytes(key_path)
        if len(key) != 32:
            raise ConsentLedgerError("consent ledger signing key is malformed") from None
    return key


def _canonical_record(record: dict) -> bytes:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _record_mac(key: bytes, unsigned: dict) -> str:
    return hmac.new(key, _canonical_record(unsigned), hashlib.sha256).hexdigest()


def _load_records_unlocked(path: Path, key: bytes | None) -> list[dict]:
    if not path.exists():
        return []
    ensure_private_file(path)
    size = path.stat().st_size
    if size > _MAX_LEDGER_BYTES:
        raise ConsentLedgerError("consent ledger exceeds its bounded size")
    if size == 0:
        return []
    if key is None:
        raise ConsentLedgerError("consent ledger has no signing key")
    text = atomic_read_text(path, encoding="utf-8")
    if not text.endswith("\n"):
        raise ConsentLedgerError("consent ledger contains a partial record")
    # Records are written one per "\n". splitlines() would also split inside a
    # record at U+2028, U+2029 or U+0085, which a scope may contain.
    lines = text[:-1].split("\n")
    if len(lines) > _MAX_LEDGER_RECORDS:
        raise ConsentLedgerError("consent ledger contains too many records")
    records: list[dict] = []
    previous = "0" * 64
    expected_fields = {
        "action", "mac", "op", "policy", "prev", "principal", "scope",
        "seq", "tenant", "ts", "v",
    }
    for expected_seq, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ConsentLedgerError("consent ledger contains invalid JSON") from exc
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise ConsentLedgerError("consent ledger record shape is invalid")
        if record["v"] != _LEDGER_VERSION or record["seq"] != expected_seq:
            raise ConsentLedgerError("consent ledger sequence is invalid")
        if record["op"] not in {"grant", "revoke"} or record["prev"] != previous:
            raise ConsentLedgerError("consent ledger chain is invalid")
        _validate_ledger_field(
            record["action"], name="action", limit=_MAX_ACTION_CHARS, empty=False,
        )
        _validate_ledger_field(
            record["scope"], name="scope", limit=_MAX_SCOPE_CHARS, empty=True,
        )
        if not all(
            isinstance(record[field], str)
            and 0 < len(record[field]) <= 256
            for field in ("tenant", "principal", "policy", "prev", "mac")
        ):
            raise ConsentLedgerError("consent ledger authority binding is invalid")
        if (
            isinstance(record["ts"], bool)
            or not isinstance(record["ts"], (int, float))
            or not math.isfinite(record["ts"])
            or record["ts"] < 0
        ):
            raise ConsentLedgerError("consent ledger timestamp is invalid")
        unsigned = {name: value for name, value in record.items() if name != "mac"}
        if not text_equals(record["mac"], _record_mac(key, unsigned)):
            raise ConsentLedgerError("consent ledger signature is invalid")
        previous = record["mac"]
        records.append(record)
    return records


def _active_grants(records: list[dict]) -> dict[tuple[str, str], None]:
    tenant, principal, policy = _authority_binding()
    active: dict[tuple[str, str], None] = {}
    for record in records:
        if (
            record["tenant"] != tenant
            or record["principal"] != principal
            or record["policy"] != (
                _unscoped_policy_binding(policy) if not record["scope"] else policy
            )
        ):
            continue
        key = (record["action"], record["scope"])
        if record["op"] == "grant":
            active[key] = None
        else:
            active.pop(key, None)
    return active


def _append_record_unlocked(
    path: Path, key: bytes, records: list[dict], *, op: str,
    action: str, scope: str, effect_guard: Callable[[], None] | None = None,
    authority_binding: tuple[str, str, str] | None = None,
) -> None:
    if len(records) >= _MAX_LEDGER_RECORDS:
        raise ConsentLedgerError("consent ledger contains too many records")
    current_binding = _authority_binding()
    tenant, principal, policy = current_binding if authority_binding is None else authority_binding
    if authority_binding is not None and (tenant != current_binding[0] or not re.fullmatch(r"[a-f0-9]{64}", principal) or not re.fullmatch(r"[a-f0-9]{64}", policy)):
        raise ConsentLedgerError("consent revocation binding is invalid")
    if not scope and authority_binding is None:
        policy = _unscoped_policy_binding(policy)
    unsigned = {
        "action": action,
        "op": op,
        "policy": policy,
        "prev": records[-1]["mac"] if records else "0" * 64,
        "principal": principal,
        "scope": scope,
        "seq": len(records) + 1,
        "tenant": tenant,
        "ts": time.time(),
        "v": _LEDGER_VERSION,
    }
    record = {**unsigned, "mac": _record_mac(key, unsigned)}
    encoded = _canonical_record(record) + b"\n"
    current_size = path.stat().st_size if path.exists() else 0
    if current_size + len(encoded) > _MAX_LEDGER_BYTES:
        raise ConsentLedgerError("consent ledger exceeds its bounded size")
    fd = open_private_append(path, require_private_parent=True)
    try:
        with os.fdopen(fd, "ab") as stream:
            fd = -1
            if effect_guard is not None:
                effect_guard()
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def _check_ledger(action: str, scope: str | None, path: Path | None = None) -> bool:
    """True only for an intact grant bound to this tenant/principal/policy."""
    try:
        key_tuple = _validated_key(action, scope)
        with _locked_ledger(path) as resolved:
            key = _ledger_key(resolved, create=False)
            return key_tuple in _active_grants(_load_records_unlocked(resolved, key))
    except (ConsentLedgerError, OSError, PermissionError, ValueError) as exc:
        log.warning("consent: standing grants unavailable: %s", exc)
        return False


def grant_persistent(
    action: str, scope: str | None = None, *, path: Path | None = None,
) -> None:
    """Record a forever-grant; subsequent require_consent() returns immediately.

    Use sparingly; the more we ledger, the less the prompts matter.
    """
    action, normalized_scope = _validated_key(action, scope)
    with _locked_ledger(path) as resolved:
        key = _ledger_key(resolved, create=True)
        assert key is not None
        records = _load_records_unlocked(resolved, key)
        if (action, normalized_scope) not in _active_grants(records):
            _append_record_unlocked(
                resolved, key, records, op="grant",
                action=action, scope=normalized_scope,
            )


def revoke(
    action: str,
    scope: str | None = None,
    *,
    path: Path | None = None,
    strict: bool = False,
    write_tombstone: bool = False,
    effect_guard: Callable[[], None] | None = None,
    all_matching_bindings: bool = False,
) -> bool:
    """Remove all matching grants. Returns True if anything was removed.

    The default preserves the consent primitive's historical fail-soft
    administrative behavior. Security lifecycle transitions that must prove
    authority was revoked before proceeding (for example generated-tool
    deletion) pass ``strict=True`` so an unreadable or unwritable ledger aborts
    the mutation instead of looking identical to "there was no grant".
    ``write_tombstone=True`` appends a signed revocation even when no active
    grant exists, preserving durable evidence that the exact authority was
    invalidated. Repeating an already-current tombstone is idempotent.
    """
    action, normalized_scope = _validated_key(action, scope)
    try:
        with _locked_ledger(path) as resolved:
            if effect_guard is not None:
                effect_guard()
            key = _ledger_key(resolved, create=write_tombstone)
            records = _load_records_unlocked(resolved, key)
            if all_matching_bindings and key is not None and _revoke_generated_bindings(
                resolved, key, records, action, normalized_scope, effect_guard,
            ):
                return True
            was_active = (action, normalized_scope) in _active_grants(records)
            if key is None or (not was_active and not write_tombstone):
                return False
            if write_tombstone and not was_active:
                tenant, principal, policy = _authority_binding()
                if not normalized_scope:
                    policy = _unscoped_policy_binding(policy)
                last_matching = next(
                    (
                        record
                        for record in reversed(records)
                        if record["tenant"] == tenant
                        and record["principal"] == principal
                        and record["policy"] == policy
                        and record["action"] == action
                        and record["scope"] == normalized_scope
                    ),
                    None,
                )
                if last_matching is not None and last_matching["op"] == "revoke":
                    return False
            _append_record_unlocked(
                resolved, key, records, op="revoke",
                action=action, scope=normalized_scope, effect_guard=effect_guard,
            )
            return was_active
    except (ConsentLedgerError, OSError, PermissionError) as exc:
        if strict:
            raise
        log.warning("consent: cannot revoke standing grant: %s", exc)
        return False


def _generated_bindings(records, action, scope):
    tenant = _authority_binding()[0]
    if action != "register-generated-tool" or not re.fullmatch(re.escape(tenant) + r":[a-z][a-z0-9_]{1,40}:[a-f0-9]{64}", scope):
        raise ValueError("cross-binding revocation is limited to this tenant's exact generated source")
    latest = {}
    for record in records:
        if (record["tenant"], record["action"], record["scope"]) == (tenant, action, scope):
            latest[(record["principal"], record["policy"])] = record["op"]
    return [(tenant, principal, policy) for (principal, policy), op in latest.items() if op == "grant"]


def _revoke_generated_bindings(path, key, records, action, scope, effect_guard):
    bindings = _generated_bindings(records, action, scope)
    if not bindings:
        return False
    if len(bindings) > 128:
        raise ConsentLedgerError("the complete generated-source authority exceeds 128 active bindings")
    for binding in bindings:
        _append_record_unlocked(path, key, records, op="revoke", action=action, scope=scope,
                                effect_guard=effect_guard, authority_binding=binding)
        # Every append changes seq/prev. Re-verify the complete native signed
        # ledger before constructing the next row, retaining all prior bytes.
        records = _load_records_unlocked(path, key)
    return True


def list_grants(*, path: Path | None = None) -> list[tuple[str, str]]:
    """Return [(action, scope), ...] of all current grants."""
    try:
        with _locked_ledger(path) as resolved:
            key = _ledger_key(resolved, create=False)
            return list(_active_grants(_load_records_unlocked(resolved, key)))
    except (ConsentLedgerError, OSError, PermissionError) as exc:
        log.warning("consent: cannot list standing grants: %s", exc)
        return []


def require_consent(
    action: str,
    *,
    risk: str = "medium",
    scope: str | None = None,
    detail: str | None = None,
    provenance: str | None = None,
    raise_on_deny: bool = False,
    allow_auto_approve: bool = True,
    consult_ledger: bool = True,
    approval_card: Mapping[str, object] | None = None,
) -> ConsentDecision:
    """Gate a destructive action through user (or env) approval.

    ``action`` is a short identifier (e.g. "rm-rf", "force-push",
    "mass-dm"). ``scope`` is the resource being acted on (e.g.
    "/tmp/build", "main", "channel:#general"). ``detail`` is a
    human-readable description shown in the prompt. ``provenance`` is trusted
    caller-supplied metadata for dashboard labels; never derive it from
    user/model-controlled ``detail`` text.

    Returns a ConsentDecision. If ``raise_on_deny``, denials raise
    ConsentDenied instead.

    ``allow_auto_approve=False`` is for high-trust paths that require an
    explicit operator decision even though the consent primitive defaults to
    ``auto-approve`` for backwards compatibility. Ledger grants, dashboard
    approvals, and TTY prompts still work; silent auto-approval is treated as
    a denial.

    ``consult_ledger=False`` additionally disables the prior-grant fast-path, so
    a *fresh* decision is required even when a persistent grant for this
    ``(action, scope)`` exists. Used by the governance EU AI Act Art-14 gate
    when an operator opts into per-action human oversight
    (``[governance] require_fresh_human_approval``).

    ``approval_card`` is a pre-built, integrity-bound description of one exact
    operation.  Dashboard mode persists it in the encrypted detail column;
    other consent modes continue to receive the ordinary safe ``detail`` label.
    """
    ts = time.time()
    # 1) Ledger fast-path (skipped when a fresh decision is demanded).
    if consult_ledger and _check_ledger(action, scope):
        return _emit(ConsentDecision(True, "ledger", risk, ts), action, scope, detail)
    # 2) Mode override (risk-aware: secure-by-default gates high/critical risk).
    mode = _resolve_mode(risk)
    if mode == "auto-approve":
        d = _emit(
            ConsentDecision(allow_auto_approve, "auto", risk, ts),
            action, scope, detail,
        )
        if not d.granted and raise_on_deny:
            raise ConsentDenied(action)
        return d
    if mode == "auto-deny":
        d = _emit(ConsentDecision(False, "auto", risk, ts), action, scope, detail)
        if raise_on_deny:
            raise ConsentDenied(action)
        return d
    if mode == "dashboard":
        d = _decide_via_dashboard(
            action, risk, scope, detail, provenance, approval_card,
        )
        if d is not None:
            d = _emit(d, action, scope, detail)
            if not d.granted and raise_on_deny:
                raise ConsentDenied(action)
            return d
        # Dashboard unavailable -> fall through to the interactive/non-tty
        # path below (fail-open: the kernel never *requires* the dashboard).
    # 3) Interactive prompt (or non-tty deny).
    if not sys.stdin.isatty():
        if mode == "ask":
            # "Ask a person": a task someone started in Lightwork's chat sends
            # the step to the Approvals page and waits for them. Nobody deciding
            # in time is still the refusal below, and the request is withdrawn.
            asked = _decide_via_dashboard(
                action, risk, scope, detail, provenance, approval_card,
                withdraw_on_timeout=True, chat_tasks_only=True,
            )
            if asked is not None:
                return _decided(asked, action, scope, detail, raise_on_deny)
        d = _emit(ConsentDecision(False, "non-tty-deny", risk, ts), action, scope, detail)
        if raise_on_deny:
            raise ConsentDenied(action)
        return d
    with _prompt_lock:
        try:
            msg = _format_prompt(
                action, risk, scope, detail, approval_card=approval_card,
            )
        except Exception as exc:
            # A malformed exact card must not collapse into a broader prompt.
            log.warning("consent: exact approval card is invalid: %s", exc)
            d = _emit(
                ConsentDecision(False, "approval-card-invalid", risk, ts),
                action,
                scope,
                detail,
            )
            if raise_on_deny:
                raise ConsentDenied(action) from exc
            return d
        sys.stderr.write(msg)
        sys.stderr.flush()
        try:
            reply = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            reply = ""
    granted = reply in {"y", "yes"}
    d = _emit(ConsentDecision(granted, "prompt", risk, ts), action, scope, detail)
    if not granted and raise_on_deny:
        raise ConsentDenied(action)
    return d


def _decided(
    decision: ConsentDecision,
    action: str,
    scope: str | None,
    detail: str | None,
    raise_on_deny: bool,
) -> ConsentDecision:
    decision = _emit(decision, action, scope, detail)
    if not decision.granted and raise_on_deny:
        raise ConsentDenied(action)
    return decision


def require_person(
    action: str,
    *,
    risk: str,
    scope: str | None = None,
    detail: str | None = None,
    provenance: str | None = None,
    approval_card: Mapping[str, object] | None = None,
) -> ConsentDecision:
    """A decision made by a person, for a gate an administrator turned on.

    Unlike :func:`require_consent`, the deployment's automatic consent mode
    never answers: the request goes to the dashboard's Approvals page (or, in
    ``ask`` mode at an interactive terminal, to the terminal prompt). No
    decision within the dashboard wait is a refusal, and the unanswered
    request is withdrawn. ``auto-deny`` refuses at once; nothing grants
    silently. A supplied exact-operation card is checked with the decision.
    """
    ts = time.time()
    mode = _resolve_mode(risk)
    if mode == "auto-deny":
        return _emit(ConsentDecision(False, "auto", risk, ts), action, scope, detail)
    if mode == "ask" and sys.stdin.isatty():
        return require_consent(action, risk=risk, scope=scope, detail=detail,
                               provenance=provenance, allow_auto_approve=False,
                               consult_ledger=False, approval_card=approval_card)
    decided = _decide_via_dashboard(action, risk, scope, detail, provenance,
                                    approval_card,
                                    withdraw_on_timeout=True)
    if decided is not None:
        return _emit(decided, action, scope, detail)
    return _emit(ConsentDecision(False, "no-decision", risk, ts), action, scope, detail)


# A risky step waits this long (seconds) for a decision on the Approvals page
# unless [approval] dashboard_wait_seconds says otherwise: 30 minutes, with
# one in-app reminder to the people who can decide after 10 (see the
# dashboard's approval_reminders).
DEFAULT_DASHBOARD_WAIT_SECONDS = 1800.0
# A parked request's card never stays approvable longer than this.
_CARD_LIFETIME_CAP_SECONDS = 3600.0


def _dashboard_timeout() -> float:
    """How long (seconds) to wait for a dashboard approval before giving up.

    A timeout falls through to the interactive/non-tty path (fail-open),
    so a dashboard that's never opened doesn't wedge the agent forever.
    ``MAVERICK_CONSENT_DASHBOARD_TIMEOUT`` wins; otherwise ``[approval]
    dashboard_wait_seconds`` (set on Settings > All settings) applies;
    default 1800 (30 minutes).
    """
    raw = os.environ.get("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "")
    if not raw.strip():
        try:
            from ..config import load_config

            value = ((load_config() or {}).get("approval") or {}).get("dashboard_wait_seconds")
        except Exception:  # config never blocks the approval wait
            value = None
        if isinstance(value, (int, float)) and not isinstance(value, bool) \
                and math.isfinite(value):
            return max(0.0, float(value))
        return DEFAULT_DASHBOARD_WAIT_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_DASHBOARD_WAIT_SECONDS


def _approval_card_ttl() -> float:
    """How long a parked request's card stays approvable (seconds): the
    dashboard wait plus the undo grace (a decision made at the end of the wait
    only settles after the grace, and the card is re-checked then), at least a
    minute and never more than an hour."""
    return max(60.0, min(_dashboard_timeout() + approval_undo_grace_seconds(),
                         _CARD_LIFETIME_CAP_SECONDS))


def dashboard_wait_seconds() -> float:
    """How long a task waits for a decision on the Approvals page (seconds)."""
    return _dashboard_timeout()


def _consent_requester(wm) -> str | None:
    """The principal on whose behalf consent is being requested.

    This is the owner of the goal currently executing (bound in the goal trace
    context and copied across ``asyncio.to_thread`` into the tool/consent
    worker). The goal owner shares the dashboard's approver namespace
    (``caller_principal``), so recording it as ``requested_by`` lets the
    dual-control self-approval bar in ``world_model.decide_approval`` fire:
    under N-of-M dual control the requester cannot count as one of the distinct
    approvers (segregation of duties).

    Returns None when consent runs outside a goal, or for an unowned goal
    (single-user / no-auth) -- the bar then stays inactive, which is the
    unchanged single-approver behaviour."""
    try:
        from ..logging_config import current_goal_id
        gid = current_goal_id()
        if gid is None:
            return None
        goal = wm.get_goal(gid)
        owner = (getattr(goal, "owner", "") or "").strip()
        return owner or None
    except Exception:  # pragma: no cover -- requester resolution never blocks consent
        return None


def _runtime_approval_authority(
    *, actor_hint: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Resolve the live actor, workspace, role policy, and budget authority.

    Core remains usable without the dashboard package.  When dashboard RBAC is
    installed and enabled, an unresolved role is an authorization failure, not
    a reason to fall back to a synthetic role.
    """

    from ..approval_cards import ApprovalCardError, digest

    try:
        from ..connections import current_principal

        current_actor = str(current_principal() or "").strip()
    except Exception as exc:
        raise ApprovalCardError("current consent actor is unavailable") from exc
    principal_is_current = bool(current_actor)
    actor = current_actor or str(actor_hint or "local:operator").strip()
    if not actor:
        raise ApprovalCardError("current consent actor is unavailable")
    try:
        workspace = str(current_tenant_id_strict() or "local")
    except Exception as exc:
        raise ApprovalCardError("current consent workspace is unavailable") from exc

    role = "local-operator"
    permissions: list[str] = []
    try:
        from maverick_dashboard.auth import auth_genuinely_off, role_for_principal
        from maverick_dashboard.rbac import permissions_for

        resolved = role_for_principal(None if actor == "local:operator" else actor)
        if resolved:
            role = str(resolved)
            permissions = sorted(str(item) for item in permissions_for(resolved))
        elif not auth_genuinely_off():
            raise ApprovalCardError("current dashboard role authority is unavailable")
    except ImportError:
        pass
    except ApprovalCardError:
        raise
    except Exception as exc:
        try:
            from maverick_dashboard.auth import auth_genuinely_off

            auth_off = auth_genuinely_off()
        except Exception:
            auth_off = False
        if not auth_off:
            raise ApprovalCardError(
                "current dashboard role authority is unavailable"
            ) from exc

    budget_material: dict[str, Any] = {
        "schema": "lightwork.runtime-budget-authority.v1",
        "configured": {},
        "dashboard_dollar_cap": None,
        "environment_dollar_cap": os.environ.get("MAVERICK_BUDGET_DOLLARS"),
    }
    try:
        from ..config import get_budget_overrides

        configured = get_budget_overrides()
        if not isinstance(configured, dict):
            raise TypeError("budget overrides are not an object")
        budget_material["configured"] = configured
    except Exception as exc:
        raise ApprovalCardError("current consent budget is unavailable") from exc
    try:
        from ..runtime_overrides import budget_override

        budget_material["dashboard_dollar_cap"] = budget_override()
    except Exception as exc:
        raise ApprovalCardError("current consent budget is unavailable") from exc

    budget_digest = digest(budget_material)
    authority = {
        "actor": actor,
        "workspace": workspace,
        "role": role,
        "versions": {
            "principal_sha256": digest(actor),
            "role_permissions_sha256": digest(
                {"role": role, "permissions": permissions}
            ),
            "budget_authority_sha256": budget_digest,
        },
    }
    budget = {
        "currency": "USD",
        "external_effect_cost": "unmeasured",
        "authority_sha256": budget_digest,
    }
    return authority, budget, principal_is_current


def _constant_provider(value: object) -> Callable[[], object]:
    frozen = copy.deepcopy(value)
    return lambda: copy.deepcopy(frozen)


def _provider_value(
    provider: Callable[[], object], *, name: str,
) -> object:
    from ..approval_cards import ApprovalCardError, digest

    try:
        value = provider()
        digest(value)
        return value
    except ApprovalCardError:
        raise
    except Exception as exc:
        raise ApprovalCardError(f"current consent {name} is unavailable") from exc


def _provider_mapping(
    provider: Callable[[], Mapping[str, Any]] | None,
    *,
    name: str,
    default: Mapping[str, Any],
) -> dict[str, Any]:
    from ..approval_cards import ApprovalCardError, digest

    if provider is None:
        value: object = dict(default)
    else:
        try:
            value = provider()
        except Exception as exc:
            raise ApprovalCardError(
                f"current consent {name} is unavailable"
            ) from exc
    if not isinstance(value, Mapping):
        raise ApprovalCardError(f"current consent {name} must be an object")
    result = dict(value)
    digest(result)
    return result


def _operation_budget(
    runtime_budget: Mapping[str, Any],
    provider: Callable[[], Mapping[str, Any]] | None,
) -> dict[str, Any]:
    return {
        "runtime": dict(runtime_budget),
        "operation": _provider_mapping(
            provider,
            name="operation budget",
            default={"state": "not_applicable"},
        ),
    }


def _card_label(value: object, fallback: str) -> str:
    text = " ".join(str(value or "").split())
    try:
        from .secret_detector import redact

        text, _matches = redact(text)
    except Exception as exc:
        from ..approval_cards import ApprovalCardError

        raise ApprovalCardError("approval label redaction is unavailable") from exc
    return (text or fallback)[:500]


def _validate_operation_permit(permit: ConsentPermit) -> dict[str, Any]:
    """Rebuild every current commitment and compare it with the reviewed card."""

    from ..approval_cards import ApprovalCardError, digest, require_current_approval_card

    if not isinstance(permit, ConsentPermit):
        raise ApprovalCardError("an exact consent permit is required")
    card = require_current_approval_card(permit.card)
    target = _provider_value(permit.target_provider, name="target")
    parameters = _provider_value(permit.parameters_provider, name="parameters")
    inputs = _provider_mapping(
        permit.input_versions_provider,
        name="input versions",
        default={"parameters_sha256": digest(parameters)},
    )
    credentials = _provider_mapping(
        permit.credential_versions_provider,
        name="credential versions",
        default={"state": "not_applicable"},
    )
    authority, runtime_budget, principal_is_current = _runtime_approval_authority(
        actor_hint=permit.actor_hint,
    )
    if permit.principal_bound_at_issue and not principal_is_current:
        # A bound principal disappearing must never be repaired from the
        # issuance-time actor hint.  The hint exists solely for legacy,
        # deliberately unbound local execution.
        raise ApprovalCardError("current consent actor is unavailable")
    budget = _operation_budget(runtime_budget, permit.budget_provider)
    if (
        not hmac.compare_digest(card["target"]["sha256"], digest(target))
        or not hmac.compare_digest(
            card["parameters"]["sha256"], digest(parameters)
        )
        or card["inputs"] != inputs
        or card["credentials"] != credentials
        or card["authority"] != authority
        or card["budget"] != budget
    ):
        raise ApprovalCardError(
            "the operation or its current authority changed after approval"
        )
    return card


def require_operation_consent(
    action: str,
    *,
    risk: str,
    scope: str | None,
    detail: str,
    provenance: str,
    target: object,
    parameters: object,
    parameter_summary: list[str],
    known_effects: list[str],
    unresolved_assumptions: list[str],
    before: str,
    after: str,
    irreversible: bool,
    target_provider: Callable[[], object] | None = None,
    parameters_provider: Callable[[], object] | None = None,
    input_versions_provider: Callable[[], Mapping[str, Any]] | None = None,
    credential_versions_provider: Callable[[], Mapping[str, Any]] | None = None,
    budget_provider: Callable[[], Mapping[str, Any]] | None = None,
    allow_auto_approve: bool = False,
    consult_ledger: bool = False,
    require_fresh_person: bool = False,
    ttl_seconds: float | None = None,
    display_command: str | None = None,
) -> ConsentPermit:
    """Obtain a one-use exact-operation permit for a mutating boundary.

    ``require_fresh_person`` sends the committed card to an explicit reviewer
    regardless of silent consent or standing grants. ``display_command`` is
    the exact command shown to whoever may read the card. ``ttl_seconds``
    defaults to the dashboard wait (capped at an hour), so a person deciding
    late in the wait is not refused as expired.
    """

    from ..approval_cards import ApprovalCardError, build_approval_card, digest

    target_fn = target_provider or _constant_provider(target)
    parameters_fn = parameters_provider or _constant_provider(parameters)
    current_target = _provider_value(target_fn, name="target")
    current_parameters = _provider_value(parameters_fn, name="parameters")
    if (
        not hmac.compare_digest(digest(target), digest(current_target))
        or not hmac.compare_digest(
            digest(parameters), digest(current_parameters),
        )
    ):
        raise ApprovalCardError(
            "the declared operation already differs from its live boundary"
        )
    current_inputs = _provider_mapping(
        input_versions_provider,
        name="input versions",
        default={"parameters_sha256": digest(current_parameters)},
    )
    current_credentials = _provider_mapping(
        credential_versions_provider,
        name="credential versions",
        default={"state": "not_applicable"},
    )
    actor_hint: str | None = None
    try:
        authority, runtime_budget, principal_bound_at_issue = (
            _runtime_approval_authority()
        )
        actor_hint = str(authority["actor"])
        display_action = _card_label(action, "reviewed operation")
        display_scope = (
            _card_label(scope, "reviewed target") if scope is not None else None
        )
        display_detail = _card_label(detail, "Review this exact operation.")
        display_provenance = _card_label(provenance, "operation-consent")
        ttl = _approval_card_ttl() if ttl_seconds is None else float(ttl_seconds)
        if not math.isfinite(ttl) or ttl <= 0:
            raise ApprovalCardError("consent permit ttl must be positive and finite")
        card = build_approval_card(
            action=display_action,
            summary=display_detail,
            target_label=display_scope or display_action,
            target=current_target,
            parameters=current_parameters,
            parameter_summary=parameter_summary,
            actor=str(authority["actor"]),
            workspace=str(authority["workspace"]),
            role=str(authority["role"]),
            authority_versions=dict(authority["versions"]),
            input_versions=current_inputs,
            credential_versions=current_credentials,
            budget=_operation_budget(runtime_budget, budget_provider),
            expires_at=time.time() + min(ttl, 24 * 3600.0),
            known_effects=known_effects,
            unresolved_assumptions=unresolved_assumptions,
            before=before,
            after=after,
            irreversible=irreversible,
            display_command=display_command,
        )
        if require_fresh_person:
            decision = require_person(
                display_action, risk=risk, scope=display_scope,
                detail=display_detail, provenance=display_provenance,
                approval_card=card,
            )
        else:
            decision = require_consent(
                display_action,
                risk=risk,
                scope=display_scope,
                detail=display_detail,
                provenance=display_provenance,
                raise_on_deny=True,
                allow_auto_approve=allow_auto_approve,
                consult_ledger=consult_ledger,
                approval_card=card,
            )
        if not decision.granted:
            raise ConsentDenied(display_action)
        permit = ConsentPermit(
            card=card,
            decision=decision,
            target_provider=target_fn,
            parameters_provider=parameters_fn,
            input_versions_provider=input_versions_provider,
            credential_versions_provider=credential_versions_provider,
            budget_provider=budget_provider,
            actor_hint=actor_hint,
            principal_bound_at_issue=principal_bound_at_issue,
        )
        _validate_operation_permit(permit)
        return permit
    except ConsentDenied:
        raise
    except ApprovalCardError:
        raise


@contextmanager
def consume_operation_consent(
    permit: ConsentPermit,
) -> Iterator[dict[str, Any]]:
    """Spend and revalidate a permit while excluding local authority changes."""

    from ..approval_cards import ApprovalCardError
    from ..authority_effects import authority_effect_fence

    with authority_effect_fence():
        if not isinstance(permit, ConsentPermit) or not permit.claim():
            raise ApprovalCardError(
                "the operation consent was already consumed; request a fresh review"
            )
        card = _validate_operation_permit(permit)
        yield card


def described_approval_card(
    action: str,
    *,
    scope: str | None,
    summary: str,
    target_label: str,
    request: Mapping[str, object],
    what_it_will_do: Sequence[str],
    known_effects: Sequence[str],
    open_questions: Sequence[str] = (),
    before: str,
    after: str,
    irreversible: bool,
    requester: str | None = None,
) -> dict[str, object]:
    """An exact-request card whose plain words the caller writes.

    The authority, budget and expiry come from the same live sources as every
    other card, so a caller only describes the request; it cannot widen it."""
    from ..approval_cards import build_approval_card, digest

    authority, runtime_budget, _principal_is_current = _runtime_approval_authority(
        actor_hint=requester,
    )
    return build_approval_card(
        action=action,
        summary=summary,
        target_label=target_label,
        target={"scope": scope},
        parameters=dict(request),
        parameter_summary=list(what_it_will_do),
        actor=str(authority["actor"]),
        workspace=str(authority["workspace"]),
        role=str(authority["role"]),
        authority_versions=dict(authority["versions"]),
        input_versions={"request_sha256": digest(dict(request))},
        credential_versions={"state": "not_applicable"},
        budget=_operation_budget(runtime_budget, None),
        expires_at=time.time() + _approval_card_ttl(),
        known_effects=list(known_effects),
        unresolved_assumptions=list(open_questions),
        before=before,
        after=after,
        irreversible=irreversible,
    )


def _dashboard_approval_card(
    action: str,
    risk: str,
    scope: str | None,
    detail: str | None,
    provenance: str | None,
    requester: str | None,
) -> dict[str, object]:
    """Build a conservative exact-request card for unadapted consent callers."""

    def label(value: object, fallback: str) -> str:
        text = " ".join(str(value or "").split())
        return (text or fallback)[:500]

    action_label = label(action, "requested operation")
    effect = label(detail, f"Run {action_label} once for the reviewed scope.")
    return described_approval_card(
        action_label,
        scope=scope,
        summary=effect,
        target_label=label(scope, "the exact committed request scope"),
        request={"action": action, "risk": risk, "scope": scope, "detail": detail,
                 "provenance": provenance},
        what_it_will_do=["Authorize this exact committed action, scope, detail, and provenance once."],
        known_effects=[effect],
        open_questions=["This compatibility caller supplied no operation-specific credential metadata."],
        before="The requested operation has not been authorized.",
        after="The exact committed request may execute once after this decision.",
        irreversible=risk in {"high", "critical"},
        requester=requester,
    )


def approval_undo_grace_seconds() -> float:
    """How long (seconds) a dashboard decision can still be undone.

    The Approvals page offers "Undo" for this long after approve/reject, so
    the agent-side consumer must not act on a decision until the window has
    passed. ``MAVERICK_APPROVAL_UNDO_GRACE_SECONDS`` wins; otherwise
    ``[approval] undo_grace_seconds`` (Settings > All settings) applies;
    default 30. ``0`` disables undo and restores immediate consumption.
    """
    contract = INTEGER_SETTINGS["approval.undo_grace_seconds"]
    raw = os.environ.get(contract.dashboard_env[0], "")
    if not raw.strip():
        try:
            from ..config import load_config

            value = ((load_config() or {}).get("approval") or {}).get("undo_grace_seconds")
        except Exception:  # config never blocks the approval wait
            value = None
        if isinstance(value, (int, float)) and not isinstance(value, bool) \
                and math.isfinite(value):
            return max(float(contract.minimum), min(float(value), float(contract.maximum)))
        raw = str(contract.default)
    try:
        return max(float(contract.minimum), min(float(raw), float(contract.maximum)))
    except ValueError:
        return float(contract.default)


def approval_requires_acknowledgement() -> bool:
    """Whether approving a high or critical risk request must carry an explicit
    acknowledgement (the Approvals page confirmation; the API's
    ``acknowledged`` field, plus a typed ``confirmation`` for critical risk).

    ``MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT`` wins; otherwise ``[approval]
    require_acknowledgement`` applies; default on.
    """
    contract = BOOLEAN_SETTINGS["approval.require_acknowledgement"]
    raw = os.environ.get(contract.dashboard_env[0], "").strip().lower()
    if raw:
        return raw not in ("0", "false", "no", "off")
    try:
        from ..config import load_config

        value = ((load_config() or {}).get("approval") or {}).get("require_acknowledgement")
    except Exception:  # config never weakens the confirmation
        value = None
    return value if isinstance(value, bool) else contract.default


def approval_decision_settles_at(row: object, *, grace: float | None = None) -> float:
    """Wall-clock time when a decided approval stops being undoable.

    Until then the decision is recorded but not yet in effect: a consumer
    keeps waiting and an undo returns the request to pending.
    """
    if grace is None:
        grace = approval_undo_grace_seconds()
    decided_at = getattr(row, "decided_at", None)
    if not isinstance(decided_at, (int, float)) or isinstance(decided_at, bool):
        decided_at = time.time()
    return float(decided_at) + grace


# Task states after which a waiting request can no longer be acted on: the
# person pressed Stop, or the run finished or paused for good. A decision made
# later must not start the step in a run nobody is following any more.
_TASK_OVER = frozenset({"cancelled", "done", "completed", "failed", "error", "blocked"})


def _web_chat_goal(wm) -> int | None:
    """The running task when a person started it in Lightwork's chat, else None.

    That person follows the task on its chat page and can open the Approvals
    page, so "ask" sends the decision there. A headless run (the command line,
    a webhook, a schedule, an API script) has no chat behind it.
    """
    try:
        from ..chat_threads import ChatThreads
        from ..logging_config import current_goal_id

        goal_id = current_goal_id()
        if goal_id is None:
            return None
        return goal_id if ChatThreads(wm).binding(goal_id) is not None else None
    except Exception:  # an unreadable binding never widens who is asked
        return None


def _task_over(wm, goal_id: int | None) -> bool:
    if goal_id is None:
        return False
    try:
        goal = wm.get_goal(goal_id)
    except Exception:  # a failed read keeps waiting; the approval poll fails closed
        return False
    return goal is None or str(getattr(goal, "status", "") or "") in _TASK_OVER


def _withdraw_approval(wm, approval_id: int, by: str) -> None:
    """Take a request nobody can act on any more off the Approvals page."""
    try:
        if wm.decide_approval(approval_id, "denied", decided_by=by):
            return
        # The immediate path refuses an approval that already carries audited
        # votes or an undo marker: deny it through the signed-audit path.
        event = wm.decide_approval_audited(approval_id, "denied", decided_by=by)
        if event is not None:
            from ..channel_approvals import audit_approval_decision

            audit_approval_decision(wm, event)
    except Exception:  # pragma: no cover -- the refusal stands either way
        pass


def _park_approval(
    wm,
    action: str,
    risk: str,
    scope: str | None,
    detail: str | None,
    provenance: str | None,
    approval_card: Mapping[str, object] | None,
) -> tuple[int, Mapping[str, object]]:
    """Queue the exact request on the Approvals page; raise when it can't be."""
    # Optional [approval] delegation rules suggest a reviewer for this risk
    # and tool. The suggestion may appear in detail; it does not constrain
    # decision authority and a prebuilt card may omit it altogether.
    try:
        from ..approval_delegation import route as _delegate_route
        delegate = _delegate_route({"risk": risk, "tool": action})
        if delegate:
            detail = f"{detail or ''}\n[delegated to: {delegate}]".strip()
    except Exception:  # pragma: no cover -- delegation never blocks consent
        pass
    try:
        # N-of-M dual control: a risk band may require multiple distinct approvers
        # before the action is granted (segregation of duties). Default 1 ->
        # unchanged single-approver behaviour.
        from .dual_control import required_approvals
        required = required_approvals(risk)
    except Exception:  # pragma: no cover -- config never blocks consent
        required = 1
    requester = _consent_requester(wm)
    from ..approval_cards import encode_approval_detail

    if approval_card is None:
        approval_card = _dashboard_approval_card(
            action, risk, scope, detail, provenance, requester,
        )
    stored = encode_approval_detail(approval_card)
    # This wait holds each decision for the undo window before acting on it,
    # so its requests are the ones a person can undo.
    approval_id = wm.create_approval(
        action, risk=risk, scope=scope, detail=stored, provenance=provenance,
        approvals_required=required, requested_by=requester, undoable=True,
    )
    # Chat channels get the same card with decision buttons: the world model
    # announces it (maverick.approval_notify) right after the row commits.
    return approval_id, approval_card


def _settled_decision(row, approval_card: Mapping[str, object], risk: str) -> ConsentDecision:
    """The final answer for a decision whose undo window has passed."""
    granted = row.status == "approved"
    source = "dashboard"
    if granted:
        try:
            from ..approval_cards import (
                decode_approval_detail,
                require_current_approval_card,
            )

            stored = decode_approval_detail(row.detail)
            if stored is None:
                raise ValueError("legacy approval detail")
            expected_binding = str(approval_card["binding_sha256"])
            require_current_approval_card(
                stored, expected_binding=expected_binding,
            )
        except Exception:
            # A decision can become stale between the API vote and this
            # poll. Return a denial; operation-permit consumers also
            # rebuild all live authority immediately before the effect.
            granted = False
            source = "dashboard-stale"
    return ConsentDecision(
        granted,
        source,
        risk,
        time.time(),
        actor=str(getattr(row, "decided_by", "") or ""),
    )


# How long the wait keeps trying to settle a decision the database will not
# take (a write lock held elsewhere) before it falls back as for any other
# unreadable approval store.
_SETTLE_RETRY_SECONDS = 60.0


def _await_dashboard_decision(
    wm,
    approval_id: int,
    approval_card: Mapping[str, object],
    risk: str,
    *,
    goal_id: int | None,
    withdraw_on_timeout: bool,
) -> ConsentDecision | None:
    """Poll the parked request until a person decides, the task stops, or time runs out."""
    # monotonic for the elapsed-time window: a wall-clock jump must not collapse
    # the human-approval window (timing out a risky-action prompt early) or
    # extend it (stalling the agent). The decision record below keeps wall time.
    deadline = time.monotonic() + _dashboard_timeout()
    from ..world_model import approval_held_open

    grace = approval_undo_grace_seconds()
    settle_failing_since = None
    while True:
        try:
            row = wm.get_approval(approval_id)
        except Exception:
            return None
        if _task_over(wm, goal_id):
            # Stop (or the end of the run) withdraws the request, so a later
            # approval can never start the step after the person pressed Stop.
            _withdraw_approval(wm, approval_id, "system:task-stopped")
            return ConsentDecision(False, "task-stopped", risk, time.time())
        if row is not None and row.status != "pending":
            # The person can still undo for the grace window: keep polling
            # (a decision seen near the deadline still gets its full window;
            # an undo flips the row back to pending and the wait resumes).
            remaining = approval_decision_settles_at(row, grace=grace) - time.time()
            if remaining > 0:
                settle_failing_since = None   # a new decision gets its own retry time
                time.sleep(min(1.0, remaining))
                continue
            # Make the decision final before acting on it: an undo that reads
            # a longer window (another process, a changed setting) is refused
            # from here on, and one that got in first leaves it pending. Only a
            # decision whose own window has passed is settled: one made again
            # after an undo just now waits out its full window.
            try:
                row = wm.settle_approval_decision(approval_id, decided_before=time.time() - grace)
            except Exception:
                # A busy database: the decision stands and stays undoable until
                # it is settled, so try again rather than refuse what was approved.
                settle_failing_since = settle_failing_since or time.monotonic()
                if time.monotonic() - settle_failing_since >= _SETTLE_RETRY_SECONDS:
                    return None
                time.sleep(1.0)
                continue
            settle_failing_since = None
            if row is None or row.status == "pending" or approval_held_open(row):
                continue
            return _settled_decision(row, approval_card, risk)
        settle_failing_since = None   # undone: the next decision gets its own retry time
        if time.monotonic() >= deadline:
            break
        time.sleep(1.0)
    if withdraw_on_timeout:
        # Nobody decided in time and the caller will not act on a later vote:
        # take the request off the Approvals page instead of leaving it there.
        _withdraw_approval(wm, approval_id, "system:no-decision")
    return None  # timed out: caller falls back


def _decide_via_dashboard(
    action: str,
    risk: str,
    scope: str | None,
    detail: str | None,
    provenance: str | None,
    approval_card: Mapping[str, object] | None = None,
    *,
    withdraw_on_timeout: bool = False,
    chat_tasks_only: bool = False,
) -> ConsentDecision | None:
    """Park the action in the world model and poll for a dashboard decision.

    Returns a ConsentDecision once the operator approves/denies via the
    dashboard /approvals page (or a refusal when the task is stopped while it
    waits), or ``None`` if the world model is unavailable or the wait times
    out -- the caller then falls back to the interactive/non-tty path
    (fail-open per the kernel contract). ``chat_tasks_only`` parks the request
    only for a task a person started in Lightwork's chat and returns ``None``
    at once for anything else.
    """
    try:
        from ..world_model import close_world_if_owned, open_world
        wm = open_world()  # client/tenant-floored: the same DB the dashboard reads
    except Exception as e:  # world model missing/unwritable -> fail-open
        log.warning("consent: dashboard mode unavailable, falling back: %s", e)
        return None
    try:
        if chat_tasks_only:
            goal_id = _web_chat_goal(wm)
            if goal_id is None:
                return None
        else:
            from ..logging_config import current_goal_id

            goal_id = current_goal_id()
        try:
            approval_id, approval_card = _park_approval(
                wm, action, risk, scope, detail, provenance, approval_card,
            )
        except Exception as e:
            log.warning("consent: cannot queue approval, falling back: %s", e)
            return None
        return _await_dashboard_decision(
            wm, approval_id, approval_card, risk,
            goal_id=goal_id, withdraw_on_timeout=withdraw_on_timeout,
        )
    finally:
        close_world_if_owned(wm)


def _format_prompt(
    action: str,
    risk: str,
    scope: str | None,
    detail: str | None,
    *,
    approval_card: Mapping[str, object] | None = None,
) -> str:
    risk_tag = {"low": "?", "medium": "!", "high": "!!", "critical": "!!!"}.get(risk, "?")
    if approval_card is not None:
        from ..approval_cards import validate_approval_card

        card = validate_approval_card(approval_card)
        rendered = json.dumps(card, indent=2, sort_keys=True, ensure_ascii=False)
        return (
            f"\n[CONSENT {risk_tag}] Exact operation approval card\n"
            f"{rendered}\nAllow this exact binding? [y/N]: "
        )
    parts = [
        f"\n[CONSENT {risk_tag}] {action}",
    ]
    if scope:
        parts.append(f"  scope: {scope}")
    if detail:
        parts.append(f"  detail: {detail}")
    parts.append("Allow? [y/N]: ")
    return "\n".join(parts)


def _emit(
    decision: ConsentDecision,
    action: str,
    scope: str | None,
    detail: str | None,
) -> ConsentDecision:
    """Record consent; a required audit refusal must not release approval."""
    from ..audit import EventKind, audit_event

    audit_event(
        EventKind.CONSENT_PROMPT,
        action=action, risk=decision.risk,
        scope=scope, detail=detail,
    )
    audit_event(
        EventKind.CONSENT_RESULT,
        action=action,
        decision="approve" if decision.granted else "deny",
        source=decision.source,
        decided_by=decision.actor,
    )
    # One content-free row per decision, for previewing a threshold change.
    from ..approval_checks import record_decision

    record_decision(risk=decision.risk, action=action, granted=decision.granted,
                    source=decision.source)
    return decision


__all__ = [
    "ConsentPermit",
    "ConsentDecision",
    "ConsentDenied",
    "ConsentLedgerError",
    "described_approval_card",
    "consume_operation_consent",
    "require_consent",
    "require_operation_consent",
    "require_person",
    "grant_persistent",
    "installation_mode_for",
    "revoke",
    "list_grants",
]
