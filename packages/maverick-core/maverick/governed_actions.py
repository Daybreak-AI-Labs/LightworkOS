"""Governed Actions -- typed, simulatable, lineage-tracked operations.

Borrowed from Palantir's ontology *Actions*, at agent scale: instead of an agent
running a free-form effect, a consequential operation is a declared ``Action``
with TYPED parameters and a risk class. Before it commits it is SIMULATED (a
preview of its effect with no side effects), gated by risk/approval, then
applied -- and every commit appends a tamper-evident LINEAGE link (hash-chained
exactly like :mod:`maverick.tools.provenance_chain`) so any outcome can be traced
back to the action, its inputs, and the skills/sources behind it.

Three Palantir borrows in one place:
  * **typed Actions** -- a registry of declared operations, not arbitrary calls;
  * **simulate-before-commit** -- preview the effect, gate the commit on risk;
  * **decision lineage** -- a verifiable chain from outcome to inputs.

Opt-in and fail-open per kernel rule 1: shipping this module changes nothing
(the kernel does not route through it by default); an operator/integration uses
it explicitly. Approval gating is enforced whenever ``commit`` is called;
``[actions] require_approval_at`` (default ``high``) sets the floor.
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import time

from .config import env_flag
from .safety.tool_risk import RISK_LEVELS, risk_rank

log = logging.getLogger(__name__)

_GENESIS = "0" * 64


class ActionError(Exception):
    """A governed action was refused (bad params, risk gate, unknown action)."""


def _require_approval_at() -> str:
    """Risk floor at/above which ``commit`` requires an approver. Reads
    ``[actions] require_approval_at`` (default ``high``); an unreadable config
    source gives ``low``, so a lost policy never lowers the floor. Never
    raises."""
    try:
        from .config import config_source_errors, load_config
        v = str((load_config() or {}).get("actions", {}).get("require_approval_at", "high")).strip().lower()
        if config_source_errors(include_tenant=True):
            return RISK_LEVELS[0]
        return v if v in RISK_LEVELS else "high"
    except Exception:  # pragma: no cover -- config must never block
        return "high"


def _safe_lineage_text(value: object, *, max_len: int = 4000) -> str:
    """Return bounded, redacted audit text without a raw-data fallback.

    Connector responses, effect previews, source labels, and even exception
    strings may contain credentials. If the redactor is unavailable, retain a
    content digest for correlation instead of writing the original value into
    the durable lineage ledger.
    """
    raw = str(value)
    try:
        from .safety.secret_detector import redact

        raw, _ = redact(raw)
    except Exception:  # pragma: no cover -- safe fallback is tested explicitly
        digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
        raw = f"<redaction unavailable; sha256={digest}>"
    return raw if len(raw) <= max_len else raw[:max_len] + "...(truncated)"


def _canonical(params: dict, *, max_len: int = 4000) -> str:
    """Stable redacted JSON for hashing/lineage, bounded before persistence."""
    try:
        raw = json.dumps(params, sort_keys=True, default=str)
    except Exception:  # pragma: no cover -- unserializable -> repr
        raw = repr(params)
    return _safe_lineage_text(raw, max_len=max_len)


def _link_hash(fields: dict, prev_hash: str) -> str:
    """Hash all lineage fields that consumers treat as verified audit data."""
    payload = dict(fields)
    payload["prev_hash"] = prev_hash
    payload.pop("hash", None)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


@dataclass(frozen=True)
class ActionSpec:
    """A declared, typed operation. ``simulate`` previews the effect WITHOUT
    side effects; ``apply`` performs it. ``risk`` is a :data:`RISK_LEVELS` tier."""
    name: str
    params: dict[str, type]
    risk: str = "medium"
    simulate: Callable[[dict], str] | None = None
    apply: Callable[[dict], str] | None = None

    def __post_init__(self) -> None:
        if self.risk not in RISK_LEVELS:
            raise ValueError(f"risk {self.risk!r} must be one of {RISK_LEVELS}")


@dataclass(frozen=True)
class Preview:
    """The simulated effect of an action -- what WOULD happen on commit."""
    action: str
    params: dict
    effect: str
    risk: str
    requires_approval: bool


@dataclass(frozen=True)
class LineageLink:
    """One tamper-evident step: outcome <- action <- inputs/sources/skills."""
    ts: float
    action: str
    params_json: str   # canonical, secret-redacted
    effect: str
    result: str
    sources: tuple[str, ...]
    skills: tuple[str, ...]
    approver: str
    prev_hash: str
    hash: str


class GovernedActions:
    """A registry + executor for typed governed actions, with an append-only,
    hash-chained lineage ledger."""

    def __init__(self) -> None:
        self._specs: dict[str, ActionSpec] = {}
        self.lineage: list[LineageLink] = []

    # -- registry -----------------------------------------------------------
    def register(self, spec: ActionSpec) -> None:
        self._specs[spec.name] = spec

    def get(self, name: str) -> ActionSpec:
        try:
            return self._specs[name]
        except KeyError:
            raise ActionError(f"unknown action {name!r}") from None

    # -- typing -------------------------------------------------------------
    def _validate(self, spec: ActionSpec, params: dict) -> None:
        missing = [k for k in spec.params if k not in params]
        if missing:
            raise ActionError(f"{spec.name}: missing param(s) {missing}")
        for k, typ in spec.params.items():
            if not isinstance(params[k], typ):
                raise ActionError(
                    f"{spec.name}: param {k!r} must be {typ.__name__}, "
                    f"got {type(params[k]).__name__}")

    def _requires_approval(self, spec: ActionSpec) -> bool:
        return risk_rank(spec.risk) >= risk_rank(_require_approval_at())

    # -- simulate-before-commit --------------------------------------------
    def simulate(self, name: str, params: dict) -> Preview:
        """Preview an action's effect WITHOUT performing it (typed-checked)."""
        spec = self.get(name)
        self._validate(spec, params)
        effect = spec.simulate(params) if spec.simulate else f"(no simulator for {name})"
        return Preview(action=name, params=dict(params), effect=str(effect),
                       risk=spec.risk, requires_approval=self._requires_approval(spec))

    def commit(self, name: str, params: dict, *, approver: str = "",
               sources: tuple[str, ...] = (), skills: tuple[str, ...] = ()) -> str:
        """Type-check, gate on risk/approval, apply, and append a lineage link.
        Raises :class:`ActionError` if the risk gate is unmet -- governance is
        enforced here, not optional."""
        spec = self.get(name)
        self._validate(spec, params)
        preview = self.simulate(name, params)
        if preview.requires_approval and not approver:
            raise ActionError(
                f"{name}: {spec.risk!r}-risk action requires an approver "
                f"(>= [actions] require_approval_at={_require_approval_at()!r})")
        result = spec.apply(params) if spec.apply else f"(no apply for {name})"
        self._append_lineage(spec, params, preview.effect, str(result),
                             sources, skills, approver)
        return str(result)

    # -- lineage ------------------------------------------------------------
    def _append_lineage(self, spec: ActionSpec, params: dict, effect: str,
                        result: str, sources, skills, approver: str) -> None:
        prev = self.lineage[-1].hash if self.lineage else _GENESIS
        pj = _canonical(params)
        ts = time()
        fields = {"ts": ts, "action": spec.name, "params_json": pj,
                  "effect": effect, "result": result,
                  "sources": list(sources), "skills": list(skills),
                  "approver": approver}
        h = _link_hash(fields, prev)
        self.lineage.append(LineageLink(
            ts=ts, action=spec.name, params_json=pj, effect=effect,
            result=result, sources=tuple(sources), skills=tuple(skills),
            approver=approver, prev_hash=prev, hash=h))

    def verify_lineage(self) -> str:
        """Recompute the hash chain; ``VALID`` or ``BROKEN`` at the first bad
        link (reordering, edits, forged links). Deterministic, offline."""
        expected = _GENESIS
        for i, link in enumerate(self.lineage):
            if link.prev_hash != expected:
                return f"BROKEN: link {i} ({link.action}) prev_hash mismatch"
            fields = {"ts": link.ts, "action": link.action, "params_json": link.params_json,
                      "effect": link.effect, "result": link.result,
                      "sources": list(link.sources), "skills": list(link.skills),
                      "approver": link.approver}
            if link.hash != _link_hash(fields, link.prev_hash):
                return f"BROKEN: link {i} ({link.action}) content hash mismatch"
            expected = link.hash
        return f"VALID: {len(self.lineage)} link(s), head {expected[:12]}..."

    def trace(self, index: int = -1) -> dict:
        """The decision lineage of one outcome: what action ran, on what inputs,
        from which sources/skills, approved by whom (the Palantir 'trace this
        number to source' artifact, for an agent decision)."""
        if not self.lineage:
            raise ActionError("no lineage recorded")
        link = self.lineage[index]
        return {"action": link.action, "params": link.params_json,
                "effect": link.effect, "result": link.result,
                "sources": list(link.sources), "skills": list(link.skills),
                "approver": link.approver, "hash": link.hash[:12]}


def impact_of(identifier: str, *, kind: str = "any",
              store_dir: str | Path | None = None) -> list[dict]:
    """Impact analysis: every recorded consequential action that depended on a
    given skill or source. Use when a skill/source is revoked or found bad --
    "what did it touch?" -- the inverse of lineage. Scans all per-goal ledgers;
    ``kind`` is ``skill`` | ``source`` | ``any``. Read-only, fail-open."""
    out: list[dict] = []
    try:
        d = _lineage_dir(store_dir)
        if not d.exists():
            return out
        want_skill = kind in ("skill", "any")
        want_source = kind in ("source", "any")
        for f in sorted(d.glob("*.ndjson")):
            try:
                goal_id: object = int(f.stem)
            except ValueError:
                goal_id = f.stem
            links = [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines()
                     if line.strip()]
            if _verify_links(links).startswith("BROKEN"):
                continue
            for link in links:
                skills = link.get("skills") or []
                sources = link.get("sources") or []
                via = ("skill" if (want_skill and identifier in skills)
                       else "source" if (want_source and identifier in sources)
                       else None)
                if via:
                    out.append({"goal_id": goal_id, "action": link.get("action"),
                                "ts": link.get("ts"), "via": via,
                                "hash": str(link.get("hash", ""))[:12]})
    except Exception:  # pragma: no cover -- impact analysis never raises
        return out
    return out


__all__ = ["ActionSpec", "Preview", "LineageLink", "GovernedActions", "ActionError",
           "enabled", "record_tool_lineage", "load_lineage", "verify_lineage_file",
           "impact_of"]


# --------------------------------------------------------------------------
# Run-path wiring: persistent, per-goal lineage of consequential tool calls.
# Off by default (kernel rule 1); fail-open (lineage never breaks a run).
# --------------------------------------------------------------------------
def enabled() -> bool:
    """Whether the run path records governed-action lineage. Off by default;
    ``[actions] enable`` / ``MAVERICK_GOVERNED_ACTIONS`` turns it on. An
    unreadable config source keeps it on, since the setting may have been
    lost. Never raises."""
    _v = env_flag("MAVERICK_GOVERNED_ACTIONS")
    if _v is not None:
        return _v
    try:
        from .config import config_source_errors, load_config
        on = bool((load_config() or {}).get("actions", {}).get("enable", False))
        return on or bool(config_source_errors(include_tenant=True))
    except Exception:  # pragma: no cover -- config must never block a run
        return False


def _lineage_dir(store_dir: str | Path | None = None) -> Path:
    """Where per-goal lineage lives: ``data_dir("lineage")``, so an ACTIVE
    tenant's audit trail never mixes with another's and ``MAVERICK_HOME`` is
    honoured. A tenant binding that cannot be resolved raises rather than
    falling back to the shared directory."""
    if store_dir is not None:
        return Path(store_dir).expanduser()
    from .paths import data_dir
    return data_dir("lineage")


def _lineage_file_for_read(goal_id: int, store_dir: str | Path | None) -> Path:
    """The ledger file to READ for ``goal_id``. Before lineage honoured
    ``MAVERICK_HOME`` it was written under ``~/.maverick/lineage`` when no
    tenant was active; a goal whose file is only there is still read from
    there. Nothing is ever written to that location."""
    path = _lineage_dir(store_dir) / f"{int(goal_id)}.ndjson"
    if store_dir is None and not path.exists():
        from .paths import current_tenant
        if not current_tenant():
            legacy = Path("~/.maverick/lineage").expanduser() / path.name
            if legacy.exists():
                return legacy
    return path


def record_tool_lineage(goal_id: int | None, action: str, params: object, *,
                        skills: tuple[str, ...] = (), sources: tuple[str, ...] = (),
                        actor: str = "", effect: str = "", result: str = "",
                        approver: str = "", transaction_id: str = "",
                        phase: str = "", force: bool = False,
                        strict: bool = False,
                        store_dir: str | Path | None = None) -> bool:
    """Append a tamper-evident lineage link for a CONSEQUENTIAL tool call
    (risk >= medium) to ``<store>/<goal_id>.ndjson``. Governed write callers can
    set ``force`` and ``strict`` so a PREPARE receipt is durable before an
    external effect occurs. Ordinary observability callers retain fail-soft
    behavior. Returns whether a receipt was persisted (or intentionally skipped
    because the action was low risk)."""
    try:
        from .safety.tool_risk import risk_rank, tool_risk
        if not force and risk_rank(tool_risk(str(action))) < risk_rank("medium"):
            return True  # only consequential actions are traced
        if goal_id is None:
            from .logging_config import current_goal_id
            goal_id = current_goal_id()
        f = _lineage_dir(store_dir)
        from .file_lock import (
            atomic_read_text,
            atomic_write_text,
            cross_process_lock,
            ensure_private_directory,
            ensure_private_file,
        )

        ensure_private_directory(f)
        basename = f"{int(goal_id)}.ndjson" if goal_id is not None else "standalone.ndjson"
        f = f / basename
        with cross_process_lock(f, strict=strict):
            prev = _GENESIS
            links: list[dict] = []
            if f.exists():
                ensure_private_file(f)
                for line in atomic_read_text(f, encoding="utf-8").splitlines():
                    if line.strip():
                        link = json.loads(line)
                        links.append(link)
                        prev = link.get("hash", prev)
            if strict and links and not _verify_links(links).startswith("VALID"):
                raise RuntimeError(
                    "existing governed-action lineage is not trustworthy"
                )
            pj = _canonical(params if isinstance(params, dict) else {"input": params})
            rec = {
                "ts": time(),
                "actor": _safe_lineage_text(actor, max_len=512),
                "action": _safe_lineage_text(action, max_len=512),
                "params_json": pj,
                "skills": [_safe_lineage_text(v, max_len=512) for v in skills],
                "sources": [_safe_lineage_text(v, max_len=1000) for v in sources],
                "effect": _safe_lineage_text(effect),
                "result": _safe_lineage_text(result),
                "approver": _safe_lineage_text(approver, max_len=512),
                "transaction_id": _safe_lineage_text(transaction_id, max_len=256),
                "phase": _safe_lineage_text(phase, max_len=128),
                "prev_hash": prev,
            }
            rec["hash"] = _link_hash(rec, prev)
            body = "".join(json.dumps(link) + "\n" for link in (*links, rec))
            atomic_write_text(f, body, mode=0o600, encoding="utf-8")
        return True
    except Exception:  # pragma: no cover -- strict callers exercise propagation
        if strict:
            raise
        return False


def load_lineage(goal_id: int, store_dir: str | Path | None = None) -> list[dict]:
    """Best-effort display adapter; use verification for evidence decisions."""
    try:
        f = _lineage_file_for_read(goal_id, store_dir)
        if not f.exists():
            return []
        links = [json.loads(ln) for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()]
        return links if all(isinstance(link, dict) for link in links) else []
    except Exception:  # pragma: no cover
        return []


def _verify_links(links: list[dict]) -> str:
    expected = _GENESIS
    for i, link in enumerate(links):
        if not isinstance(link, dict):
            return f"BROKEN: link {i} is not an object"
        if link.get("prev_hash") != expected:
            return f"BROKEN: link {i} ({link.get('action')}) prev_hash mismatch"
        if link.get("hash") != _link_hash(link, expected):
            return f"BROKEN: link {i} ({link.get('action')}) content hash mismatch"
        expected = str(link.get("hash"))
    return f"VALID: {len(links)} link(s)" + (f", head {expected[:12]}..." if links else " (empty)")


def verify_lineage_file(goal_id: int, store_dir: str | Path | None = None) -> str:
    """Report ``VALID``, ``BROKEN``, ``MISSING`` or ``UNAVAILABLE`` evidence.

    An existing empty file is a valid empty chain. A missing file supplies no
    chain to verify; read/parse failures must never become an empty chain.
    """
    try:
        path = _lineage_file_for_read(goal_id, store_dir)
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "MISSING: no persisted lineage file"
    except UnicodeError:
        return "BROKEN: lineage is not UTF-8 text"
    except (OSError, ValueError, TypeError, RuntimeError):
        return "UNAVAILABLE: lineage file could not be read"
    try:
        links = [json.loads(line) for line in body.splitlines() if line.strip()]
    except (ValueError, RecursionError):
        return "BROKEN: malformed lineage JSON"
    return _verify_links(links)
