"""Security remediation -- assess the deployment's posture and (bounded) fix it.

The security assessor's engine. It reads the live security posture (control gaps
from :func:`maverick.compliance.compliance_report`, active breach signals from
:func:`maverick.threat_hunt.hunt`) and maps each gap to the remediation that
closes it. Some remediations are **auto-fixable** -- a reversible, in-boundary
flip of *Lightwork's own* config (enable audit signing, set retention) -- and the
rest are **gated**: behaviour-changing (enterprise mode, at-rest encryption) or
outward-facing, so they are *proposed* for a human, never auto-applied.

Two hard guards on every auto-fix, both off by default:
  1. it runs only under **enterprise mode + an explicit opt-in**
     (``[security] auto_fix = true`` / ``MAVERICK_SECURITY_AUTOFIX=1``);
  2. it only ever **appends** a config block when that section is absent (the
     least-destructive write -- it never edits or clobbers a hand-edited section).
Every applied fix is recorded as a ``config_remediated`` audit event and reports
how to undo it. ``apply`` defaults to a dry run.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Remediation:
    control: str                     # the compliance control it closes
    title: str
    section: str                     # the config.toml table it writes
    changes: dict[str, Any]
    auto: bool                       # True = low-risk reversible auto-fix; False = gated
    rationale: str


# Each action-needed control -> its remediation. ``auto`` is reserved for
# reversible, in-boundary flips that cannot break a running workflow; anything
# that changes LLM routing, data handling, or consent behaviour is gated.
_REMEDIATIONS: tuple[Remediation, ...] = (
    Remediation(
        "Tamper-evident audit", "Enable Ed25519 audit signing",
        "audit", {"sign": True}, auto=True,
        rationale="reversible flag; makes the audit log tamper-evident "
                  "(EU AI Act Art. 12 / SOC 2)"),
    Remediation(
        "Storage limitation (retention)", "Set data-retention windows",
        "retention", {"audit_days": 365, "episodes_days": 90, "events_days": 365},
        auto=True,
        rationale="reversible; bounds retention (GDPR Art. 5(1)(e)) without "
                  "changing agent behaviour"),
    Remediation(
        "Data-egress control", "Enable enterprise mode (egress lock)",
        "enterprise", {"mode": True}, auto=False,
        rationale="pins LLM calls to local models -- can break a cloud workflow, "
                  "so propose for human review, do not auto-apply"),
    Remediation(
        "Encryption at rest", "Enable at-rest encryption",
        "encryption", {"at_rest": True}, auto=False,
        rationale="changes data handling (new writes sealed); propose for review"),
    Remediation(
        "Human oversight (consent gating)", "Gate destructive actions (consent ask)",
        "enterprise", {"mode": True}, auto=False,
        rationale="gates destructive actions -- can block non-interactive runs; "
                  "propose for review"),
)
_BY_CONTROL = {r.control: r for r in _REMEDIATIONS}


@dataclass
class RemediationItem:
    control: str
    title: str
    auto: bool
    section: str
    changes: dict[str, Any]
    rationale: str
    detail: str


@dataclass
class RemediationPlan:
    gaps: list[RemediationItem]
    breaches: list[dict]              # active attack signals from the threat hunt
    auto_fix_enabled: bool


@dataclass
class ApplyResult:
    control: str
    applied: bool
    dry_run: bool = False
    reason: str = ""
    block: str = ""                  # the config block added / that would be added
    undo: str = ""


def _truthy(v: object) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def auto_fix_enabled() -> bool:
    """Off by default. Auto-fix requires enterprise mode AND an explicit opt-in
    (``MAVERICK_SECURITY_AUTOFIX`` env wins over ``[security] auto_fix``)."""
    try:
        from .enterprise import enterprise_enabled
        if not enterprise_enabled():
            return False
    except Exception:
        return False
    env = os.environ.get("MAVERICK_SECURITY_AUTOFIX")
    if env is not None and env.strip() != "":
        return _truthy(env)
    try:
        from .config import load_config
        return _truthy(((load_config() or {}).get("security") or {}).get("auto_fix"))
    except Exception:
        return False


def plan(*, include_breaches: bool = True) -> RemediationPlan:
    """Assess the security posture: control gaps (each mapped to its remediation)
    plus active breach signals. Read-only; never raises."""
    gaps: list[RemediationItem] = []
    try:
        from .compliance import compliance_report
        for c in compliance_report():
            rem = _BY_CONTROL.get(c.control)
            if c.status == "action_needed" and rem is not None:
                gaps.append(RemediationItem(
                    control=c.control, title=rem.title, auto=rem.auto,
                    section=rem.section, changes=dict(rem.changes),
                    rationale=rem.rationale, detail=c.detail,
                ))
    except Exception:
        pass
    breaches: list[dict] = []
    if include_breaches:
        try:
            from .threat_hunt import hunt
            breaches = [
                {"kind": f.kind, "title": f.title, "severity": f.severity,
                 "count": f.count}
                for f in hunt().findings
            ]
        except Exception:
            pass
    return RemediationPlan(gaps=gaps, breaches=breaches,
                           auto_fix_enabled=auto_fix_enabled())


def _toml_scalar(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    s = (str(v).replace("\\", "\\\\").replace('"', '\\"')
         .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))
    return f'"{s}"'


def _emit_block(section: str, changes: dict[str, Any]) -> str:
    lines = [f"[{section}]"]
    lines += [f"{k} = {_toml_scalar(v)}" for k, v in changes.items()]
    return "\n".join(lines) + "\n"


def _parses_ok(text: str) -> bool:
    """True if ``text`` is valid TOML -- the last gate before committing a write,
    so an append that would corrupt config (duplicate table, scalar/table name
    collision, or an already-malformed file) is refused, not written."""
    try:
        import tomllib  # 3.11+
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    try:
        tomllib.loads(text)
        return True
    except Exception:
        return False


def _record_remediation(item: RemediationItem, block: str) -> bool:
    """Record the ``config_remediated`` audit event. Returns False if it could not
    be written -- the caller then refuses to leave config mutated unlogged (audit
    is load-bearing for a self-modifying-config change)."""
    try:
        from .audit import AuditRefused, EventKind, record
        return bool(record(
            EventKind.CONFIG_REMEDIATED, agent="security_assessor",
            section=item.section, control=item.control, applied=block.strip()))
    except AuditRefused:
        raise
    except Exception:
        return False


def _write_config_atomic(path, text: str, *, prior: str) -> str:
    """Write ``text`` to ``path`` atomically and privately (0600), backing the
    prior contents up to ``<name>.bak`` first. Returns the backup path (or "").

    A temp file in the same dir is written + fsync'd then ``os.replace``-d, so a
    crash / full disk can never truncate the live config; ``0600`` keeps the
    secret-bearing file off other users (mirrors the wizard / audit signer)."""
    from .file_lock import atomic_write_text, ensure_private_directory

    ensure_private_directory(path.parent)
    backup = ""
    if prior.strip():
        bak = path.with_name(path.name + ".bak")
        atomic_write_text(bak, prior, mode=0o600)
        backup = str(bak)
    atomic_write_text(path, text, mode=0o600)
    return backup


def apply_remediation(item: RemediationItem, *, dry_run: bool = True) -> ApplyResult:
    """Apply one auto-fix (append its config block), or report why it was refused.

    Refuses -- never writes -- unless the item is ``auto``, auto-fix is enabled
    (enterprise + opt-in), and the target section is **absent** from config (so the
    append cannot clobber an existing hand-edited table). ``dry_run`` reports the
    block without writing. A real apply records a ``config_remediated`` audit event.
    """
    if not item.auto:
        return ApplyResult(item.control, False,
                           reason="gated -- propose for human review, not auto-applied")
    if not auto_fix_enabled():
        return ApplyResult(
            item.control, False,
            reason="auto-fix disabled (needs enterprise mode + "
                   "[security] auto_fix = true)")
    block = _emit_block(item.section, item.changes)
    try:
        from .config import config_path, load_config
        cfg = load_config() or {}
        if item.section in cfg:
            return ApplyResult(
                item.control, False, block=block,
                reason=f"[{item.section}] already present -- apply by hand to avoid "
                       "clobbering existing keys")
        path = config_path()
    except Exception as e:
        return ApplyResult(item.control, False, reason=f"could not read config: {e}")

    if dry_run:
        return ApplyResult(item.control, False, dry_run=True, block=block,
                           undo=f"remove the appended [{item.section}] block")
    # Serialize the read-modify-write of config.toml across processes: the
    # section-absent check + read + append + write must be atomic w.r.t. another
    # config writer (a second remediation, self_learning, the wizard), or the
    # append is built on stale text and a concurrent edit is clobbered. Re-read
    # and re-check the section INSIDE the lock so a writer that landed between
    # the pre-filter above and here is not overwritten.
    from .file_lock import cross_process_lock
    with cross_process_lock(path):
        try:
            cfg_now = load_config() or {}
        except Exception as e:
            return ApplyResult(item.control, False, reason=f"could not read config: {e}")
        if item.section in cfg_now:
            return ApplyResult(
                item.control, False, block=block,
                reason=f"[{item.section}] already present -- apply by hand to avoid "
                       "clobbering existing keys")
        existed_before = path.exists()
        try:
            existing = path.read_text(encoding="utf-8") if existed_before else ""
        except OSError as e:
            return ApplyResult(item.control, False, reason=f"could not read config: {e}")
        new_text = (existing.rstrip() + "\n\n" + block) if existing.strip() else block
        # Last gate: never write something that doesn't parse -- a duplicate table, a
        # scalar/table name clash, or an already-malformed config the section check
        # couldn't see. Refuse rather than corrupt the file.
        if not _parses_ok(new_text):
            return ApplyResult(
                item.control, False, block=block,
                reason=f"appending [{item.section}] would make config.toml invalid "
                       "(it may already be malformed); fix it by hand")
        try:
            backup = _write_config_atomic(path, new_text, prior=existing)
        except OSError as e:
            return ApplyResult(item.control, False, reason=f"could not write config: {e}")
        # Audit is load-bearing here: record only after the config commit succeeds,
        # and roll the commit back if the audit writer reports failure. This avoids
        # both unlogged config mutation and false-positive remediation audit rows.
        # Kept inside the lock so the rollback write can't race another writer.
        from .audit import AuditRefused

        try:
            recorded = _record_remediation(item, block)
        except AuditRefused:
            try:
                if existed_before:
                    _write_config_atomic(path, existing, prior=new_text)
                else:
                    path.unlink(missing_ok=True)
            except OSError as rollback_exc:
                raise RuntimeError(
                    "audit refused the remediation record and rollback failed"
                ) from rollback_exc
            raise
        if not recorded:
            try:
                if existed_before:
                    _write_config_atomic(path, existing, prior=new_text)
                else:
                    path.unlink(missing_ok=True)
            except OSError as e:
                return ApplyResult(
                    item.control, False,
                    reason="could not write the audit record; rollback failed: "
                           f"{e}")
            return ApplyResult(
                item.control, False,
                reason="could not write the audit record; rolled back config change "
                       "rather than leave it unlogged")
    return ApplyResult(
        item.control, True, block=block,
        undo=f"restore {backup}" if backup
        else f"remove the appended [{item.section}] block from {path}")


def render_plan_text(plan_: RemediationPlan) -> str:
    lines = ["Security remediation plan", "=" * 25, ""]
    if plan_.breaches:
        lines.append("Active breach signals (from the threat hunt):")
        for b in plan_.breaches:
            lines.append(f"  [{b['severity'].upper()}] {b['title']} (x{b['count']})")
        lines.append("")
    auto = [g for g in plan_.gaps if g.auto]
    gated = [g for g in plan_.gaps if not g.auto]
    if not plan_.gaps:
        lines.append("No control gaps -- posture is clean.")
    if auto:
        state = "ENABLED" if plan_.auto_fix_enabled else "disabled"
        lines.append(f"Auto-fixable (low-risk, reversible; auto-fix is {state}):")
        for g in auto:
            mark = "will apply" if plan_.auto_fix_enabled else "run with auto-fix on"
            lines.append(f"  [{mark}] {g.title}  ->  [{g.section}] {g.changes}")
    if gated:
        lines.append("")
        lines.append("Proposed (gated -- needs human approval):")
        for g in gated:
            lines.append(f"  - {g.title}  ({g.rationale})")
    return "\n".join(lines)


def render_plan_json(plan_: RemediationPlan) -> str:
    import json
    from dataclasses import asdict
    return json.dumps(asdict(plan_), indent=2, default=str)


__all__ = [
    "Remediation",
    "RemediationItem",
    "RemediationPlan",
    "ApplyResult",
    "auto_fix_enabled",
    "plan",
    "apply_remediation",
    "render_plan_text",
    "render_plan_json",
]
