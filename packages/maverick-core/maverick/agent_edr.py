"""The Agent Security Plane: detect, respond, prove.

Lightwork already carries most of an agent-runtime defense stack -- the shield's
chokepoints, capability attenuation and revocation, honeytokens and canaries,
compartment seals, the SSRF guards, `threat_hunt` over the audit trail.
What it does not carry is a *plane*: one surface where a security operator sees
every detection in one shape, contains a compromised agent in one act, and gets
a forensic record they can hand to an insurer. Today those live in six modules
with six vocabularies, which is fine for the kernel and useless for an analyst.

This module is that surface, and it is deliberately thin -- it composes the
existing enforcement rather than re-implementing any of it. Detection reads the
audit chain and reports signed versus unsigned evidence explicitly, so a row is
never called tamper-evident merely because the signing library is installed.

Three rules, all the same rule from a different angle:

*A plane that cannot see is not a plane that found nothing.* :func:`posture`
reports which defenses are actually switched on, and :func:`detections` carries
that posture with it. "No detections" from a deployment with the shield off is
not a clean bill of health, and reporting it as one would be the single most
dangerous thing this module could do -- the analyst stops looking.

*Containment is reported at the strength it actually achieved.* Compartment
seals are **run-scoped and in-memory** (``QuarantineRegistry`` holds them in a
dict); revocations are **durable** (``RevocationRegistry`` writes to disk under
a cross-process lock). Those are very different guarantees, and a `contain()`
that blurred them would tell an operator an agent is locked out when the seal
evaporates at process exit. :class:`Containment` records each action separately
and is ``contained`` only when every requested action actually succeeded.

*Severity is derived from the event, never self-declared.* A compromised agent
gets no say in how loudly its own detection rings.

Exposure note: this plane is CLI-facing. Detail text is bounded, stripped of
terminal control bytes, and already secret-redacted by the audit writer before
signing, which is enough for a terminal. It is NOT enough to feed an LLM -- if
these detections are ever wrapped as an agent tool, use the stricter allowlist
form (:func:`maverick.threat_hunt._sanitize_audit_value`), which exists because
audit prose returned to a model is an injection surface, not just a display one.
"""
from __future__ import annotations

import json
import logging
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

# Normalized detection classes. The audit chain speaks in enforcement terms
# ("governance_denied"); an analyst thinks in attack terms.
INJECTION = "injection"
EXFILTRATION = "exfiltration"
CAPABILITY_BREACH = "capability_breach"
POLICY_BREACH = "policy_breach"
TRUST_BREACH = "trust_breach"
EGRESS_BREACH = "egress_breach"
CONTROL_EVENT = "control_event"

LOW, MEDIUM, HIGH, CRITICAL = "low", "medium", "high", "critical"
_SEVERITY_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

#: audit ``kind`` -> (detection class, severity). Every entry names a row the
#: enforcement path already writes; this table adds no new instrumentation, it
#: only translates. A kind absent here is not a detection -- silence beats
#: inventing a threat class for a row we do not understand.
#: The attack class each audit kind maps to. SEVERITY IS NOT SET HERE -- it
#: comes from ``threat_hunt._INDICATORS`` so `maverick hunt` and `maverick
#: security detections` cannot rate the same signed row differently. Two
#: security surfaces disagreeing about one event is the "six modules, six
#: vocabularies" problem this plane exists to end.
_KIND_CLASS: dict[str, str] = {
    "shield_block": INJECTION,
    "capability_denied": CAPABILITY_BREACH,
    "governance_denied": POLICY_BREACH,
    "egress_blocked": EGRESS_BREACH,
    "agent_trust_denied": TRUST_BREACH,
    "secret_redacted": EXFILTRATION,
    # Present in threat_hunt too, so a kill switch engagement and a refused
    # destructive action are reportable by the single security view.
    "halt": CONTROL_EVENT,
    "consent_result": CONTROL_EVENT,
}

#: Fallback severities for kinds threat_hunt does not rate.
_LOCAL_SEVERITY: dict[str, str] = {"agent_trust_denied": HIGH}


def _severity_for(kind: str) -> str:
    """The severity `maverick hunt` would give this row."""
    try:
        from .threat_hunt import _INDICATORS
        rated = _INDICATORS.get(kind)
        if rated and str(rated[1]).lower() in _SEVERITY_RANK:
            return str(rated[1]).lower()
    except Exception:  # pragma: no cover -- threat_hunt unavailable
        pass
    return _LOCAL_SEVERITY.get(kind, MEDIUM)

#: Fields that may carry the implicated principal, most specific first.
_SUBJECT_FIELDS = ("agent", "peer", "principal", "actor", "tool")

_MAX_DETECTIONS = 5000
_MAX_DETAIL = 300


@dataclass(frozen=True)
class Detection:
    """One normalized security event backed by an audit row.

    Signature completeness belongs to :class:`Scan`; an individual detection
    does not imply that its source row was signed.
    """

    ts: float
    kind: str
    severity: str
    subject: str
    detail: str
    source_event: str
    day: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ts": self.ts, "kind": self.kind, "severity": self.severity,
            "subject": self.subject, "detail": self.detail,
            "source_event": self.source_event, "day": self.day,
            "evidence": dict(self.evidence),
        }


@dataclass
class Posture:
    """Which defenses are actually on. The context every detection needs."""

    shield: bool = False
    capabilities: bool = False
    audit_signing: bool = False
    agent_trust: bool = False
    egress_control: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def blind_spots(self) -> list[str]:
        return sorted(n for n, on in (
            ("shield", self.shield), ("capabilities", self.capabilities),
            ("audit_signing", self.audit_signing),
            ("agent_trust", self.agent_trust),
            ("egress_control", self.egress_control),
        ) if not on)

    def to_dict(self) -> dict:
        return {
            "shield": self.shield, "capabilities": self.capabilities,
            "audit_signing": self.audit_signing, "agent_trust": self.agent_trust,
            "egress_control": self.egress_control,
            "blind_spots": self.blind_spots, "notes": list(self.notes),
        }


@dataclass
class Containment:
    """What a containment attempt actually achieved, per action.

    ``contained`` is the AND of everything that was asked for. A partial
    containment reported as success is worse than a failed one: the operator
    stops watching an agent that is still live.
    """

    subject: str
    reason: str
    sealed: bool = False
    seal_is_durable: bool = False
    revoked: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    audit_written: bool | None = None
    superseded: bool = False

    @property
    def contained(self) -> bool:
        return not self.failed

    def to_dict(self) -> dict:
        return {
            "subject": self.subject, "reason": self.reason,
            "contained": self.contained, "sealed": self.sealed,
            "seal_is_durable": self.seal_is_durable,
            "revoked": list(self.revoked), "failed": list(self.failed),
            "notes": list(self.notes), "audit_written": self.audit_written,
            "superseded": self.superseded,
        }


# ---- posture ----------------------------------------------------------------

def posture() -> Posture:
    """Report which defenses are live, so a quiet chain can be read correctly."""
    p = Posture()
    # Each of these asks the same authority the enforcement path asks, rather
    # than re-reading config keys here. A posture that disagreed with what is
    # actually enforced would be worse than none.
    try:
        from .shield_policy import shield_available
        p.shield = bool(shield_available())
    except Exception as e:  # pragma: no cover -- shield package absent
        p.notes.append(f"shield state unknown: {e}")
    try:
        from .capability import capability_enforced
        p.capabilities = bool(capability_enforced())
    except Exception as e:  # pragma: no cover
        p.notes.append(f"capability state unknown: {e}")
    try:
        from .agent_trust import load_trust_state
        p.agent_trust = bool(load_trust_state()[0])
    except Exception as e:  # pragma: no cover
        p.notes.append(f"agent-trust state unknown: {e}")
    try:
        # `[egress] deny` is the key air_gap.py actually enforces. The previous
        # probe read `allow_hosts`/`enable`, which no module writes or reads, so
        # egress_control was reported off on every deployment -- including
        # air-gapped ones -- and a blind-spot warning that always fires is the
        # fastest way to train an operator to ignore the list.
        from .config import load_config
        p.egress_control = bool((load_config().get("egress") or {}).get("deny"))
    except Exception as e:  # pragma: no cover
        p.notes.append(f"egress state unknown: {e}")
    try:
        # Whether signing is SWITCHED ON, not whether `cryptography` imports.
        # The library being installed says nothing about `[audit] sign`, and
        # answering the wrong question here told an analyst the chain was
        # tamper-evident on a deployment writing bare rows.
        from .audit.writer import _resolve_signing
        p.audit_signing = bool(_resolve_signing(None))
    except Exception as e:  # pragma: no cover
        p.notes.append(f"audit signing state unknown: {e}")
    if p.blind_spots:
        p.notes.append(
            "a defense that is off records nothing, so an empty detection list "
            "over these controls means 'not watched', not 'not attacked'")
    return p


# ---- detect -----------------------------------------------------------------

def _subject_of(row: dict) -> str:
    for key in _SUBJECT_FIELDS:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return _flatten(value, 120)
    return "(unattributed)"


#: Anything a terminal would act on rather than print. Attacker-influenced
#: detail text reaches an analyst's terminal verbatim, and `\x1b[1A\x1b[2K`
#: erases the real detection line printed above it.
_CONTROL_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b.|[\x00-\x1f\x7f-\x9f]")

#: `time.gmtime` accepts roughly +/- 1e17 on a 64-bit platform; stay well inside.
_MAX_TS = 1e12


def _finite_ts(value: object) -> float:
    """A timestamp safe to format, or 0.0. Never raises."""
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(ts) or abs(ts) > _MAX_TS:
        return 0.0
    return ts


def _flatten(text: str, limit: int) -> str:
    """Collapse whitespace and bound the length.

    Detail text is attacker-influenced (a tool name, a shield rule, a blocked
    URL). Left with its newlines it renders as extra lines in the incident
    report, so a hostile ``reason`` can paint a convincing fake detection row --
    ``[low] FAKE CLEARED  nothing to see`` -- straight into the analyst's
    output. One line in, one line out.
    """
    return " ".join(_CONTROL_RE.sub(" ", str(text)).split())[:limit]


def _detail_of(row: dict) -> str:
    for key in ("reason", "rule", "detail", "message", "tool"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return _flatten(value, _MAX_DETAIL)
    return ""


def _detection_from(row: dict, day: str) -> Detection | None:
    kind = row.get("kind")
    if not isinstance(kind, str):
        return None
    cls = _KIND_CLASS.get(kind)
    if cls is None:
        return None
    severity = _severity_for(kind)
    # A non-finite or out-of-range timestamp is not a detection we can place in
    # a timeline: `time.gmtime` raises on inf/NaN/1e18, so one poisoned row
    # would take down the whole incident report -- exactly when a hostile row is
    # present. NaN also silently scrambles the sort. Fall back to 0.0.
    when = _finite_ts(row.get("ts"))
    return Detection(
        ts=when, kind=cls, severity=severity, subject=_subject_of(row),
        detail=_detail_of(row), source_event=kind, day=day,
        evidence={k: v for k, v in row.items()
                  if k in ("goal_id", "rule", "direction", "correlation_id")},
    )


@dataclass
class Scan:
    """A detection sweep and what it had to leave out."""

    found: list[Detection] = field(default_factory=list)
    truncated: bool = False
    signed_rows: int = 0
    unsigned_rows: int = 0
    unreadable_days: list[str] = field(default_factory=list)
    root_missing: bool = False

    @property
    def evidence_is_signed(self) -> bool:
        """True only if every security row read carried a signature.

        Derived from the rows themselves, never from "is the crypto library
        importable" -- a deployment with `cryptography` installed but signing
        switched off writes bare rows, and calling those tamper-evident would
        put an analyst's weight on a timeline that anyone could have edited.
        """
        if self.root_missing or self.unreadable_days or self.unsigned_rows:
            return False
        # Zero rows read is zero evidence. Without this an analyst pointed at
        # the wrong MAVERICK_HOME, or at a host whose audit dir was deleted,
        # reads a signed-looking all-clear with no warning on it at all.
        return self.signed_rows > 0


def scan(*, since: float | None = None, subject: str = "",
         min_severity: str = LOW, limit: int = _MAX_DETECTIONS,
         audit_dir: Path | str | None = None) -> Scan:
    """Sweep the audit chain for security detections, newest first.

    Reads only; this never re-runs enforcement. A row that cannot be parsed is
    skipped rather than guessed at -- an unreadable row is not evidence of an
    attack, and a plane that invents detections trains its operator to ignore it.

    Day-files are walked **newest first** and the bound stops the sweep, so a
    busy deployment keeps its most recent detections. Oldest-first would have
    filled the bound with history and silently dropped the incident actually in
    progress -- and :attr:`Scan.truncated` says when anything was left out,
    because a capped list that looks complete is how an analyst concludes they
    have seen everything.
    """
    from .audit.sealing import segment_text
    from .audit.signing import day_files
    from .paths import data_dir

    root = Path(audit_dir) if audit_dir is not None else data_dir("audit")
    result = Scan()
    if not root.is_dir():
        result.root_missing = True
        return result
    floor = _SEVERITY_RANK.get(min_severity, 0)
    for path in reversed(day_files(root)):
        if len(result.found) >= limit:
            result.truncated = True
            break
        try:
            text = segment_text(path, fail_soft=False)
        except Exception as e:
            # A day we cannot read is a hole in the evidence, not an absence of
            # detections. Recorded so the report can say the timeline is partial.
            log.debug("agent_edr: cannot read %s: %s", path.name, e)
            result.unreadable_days.append(path.stem)
            continue
        # Reversed, because rows within a day-file are append order. Walking a
        # busy day oldest-first filled the bound with that morning and dropped
        # the incident in progress -- the same defect the newest-first day walk
        # above was added to fix, one level down, and the report then told the
        # analyst the opposite ("OLDER detections exist").
        for line in reversed(text.splitlines()):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict):
                continue
            det = _detection_from(row, path.stem)
            if det is None:
                continue
            if row.get("sig") and row.get("hash") and row.get("key_id"):
                result.signed_rows += 1
            else:
                result.unsigned_rows += 1
            if since is not None and det.ts < since:
                continue
            if subject and det.subject != subject:
                continue
            if _SEVERITY_RANK.get(det.severity, 0) < floor:
                continue
            result.found.append(det)
            if len(result.found) >= limit:
                result.truncated = True
                break
    result.found.sort(key=lambda d: d.ts, reverse=True)
    return result


def detections(*, since: float | None = None, subject: str = "",
               min_severity: str = LOW,
               audit_dir: Path | str | None = None) -> list[Detection]:
    """Detections only. Use :func:`scan` when completeness matters."""
    return scan(since=since, subject=subject, min_severity=min_severity,
                audit_dir=audit_dir).found


def timeline(subject: str, *, since: float | None = None,
             audit_dir: Path | str | None = None) -> list[Detection]:
    """The forensic record for one principal, oldest first (incident order)."""
    found = detections(since=since, subject=subject, audit_dir=audit_dir)
    return sorted(found, key=lambda d: d.ts)


def summary(found: list[Detection]) -> dict:
    """Counts by class and severity -- the fleet console's top line."""
    by_kind: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    subjects: dict[str, int] = {}
    for d in found:
        by_kind[d.kind] = by_kind.get(d.kind, 0) + 1
        by_severity[d.severity] = by_severity.get(d.severity, 0) + 1
        subjects[d.subject] = subjects.get(d.subject, 0) + 1
    return {
        "total": len(found), "by_kind": by_kind, "by_severity": by_severity,
        "top_subjects": sorted(subjects.items(), key=lambda kv: -kv[1])[:10],
    }


# ---- respond ----------------------------------------------------------------

def contain(
    subject: str,
    *,
    reason: str,
    registry: Any | None = None,
    edges: dict[str, Any] | None = None,
    seal: bool = True,
    revoke: bool = True,
    now: float | None = None,
    durable_apply: Callable[[], bool | None] | None = None,
) -> Containment:
    """Contain ``subject``: seal it mid-run and revoke its capability subtree.

    ``registry`` is a :class:`maverick.quarantine.QuarantineRegistry` -- the
    live swarm's, when there is one. Passing none is normal for an out-of-band
    operator action and is recorded as such: **there is no durable seal to
    apply**, because compartment seals live in a running swarm's memory. The
    revocation is the part that survives, which is exactly why it is reported
    separately rather than folded into one "contained" boolean.

    Idempotent by construction: sealing an already-sealed agent and revoking an
    already-revoked principal are both no-ops in the underlying registries, so a
    second containment during an incident cannot make things worse.
    """
    result = Containment(subject=subject, reason=reason)
    if not isinstance(subject, str) or not subject.strip():
        result.failed.append("invalid subject")
        return result
    if not seal and not revoke:
        # Nothing was asked for, so nothing was contained. Without this the
        # result is vacuously `contained` -- an empty failure list reading as
        # success is the same laundering the rest of this module refuses.
        result.failed.append("no containment action requested")
        return result

    registry_r = None
    expected_revocations: list[str] = []
    dependents_applied = False

    def _apply_dependents() -> None:
        nonlocal dependents_applied
        if dependents_applied:
            return
        dependents_applied = True
        if seal:
            if registry is None:
                # Not a failure of containment, but not containment either. Said
                # plainly so nobody reads "revoked" as "this agent stopped running".
                result.notes.append(
                    "no live quarantine registry supplied: the running swarm was "
                    "not sealed, only future authority was revoked")
            else:
                try:
                    registry.seal(subject, reason)
                    result.sealed = bool(registry.is_sealed(subject))
                    if not result.sealed:
                        result.failed.append("seal did not take effect")
                    # Run-scoped by design: QuarantineRegistry keeps seals in
                    # memory for the swarm that owns it.
                    result.seal_is_durable = False
                    result.notes.append(
                        "the compartment seal is run-scoped and ends with the "
                        "process; the durable revocation remains the enforcement floor")
                except Exception as e:
                    result.failed.append(f"seal failed: {e}")
        # Each restrictive arm is independent. A failed live seal must not
        # prevent trust-registry or external-gateway containment from being
        # attempted; accumulate every failure and leave all successful arms in
        # their restrictive state.
        if durable_apply is not None:
            try:
                if durable_apply() is False:
                    result.failed.append("dependent containment did not take effect")
            except Exception as e:
                result.failed.append(f"dependent containment failed: {e}")
        if registry_r is not None:
            # ``RevocationRegistry`` invokes this callback while its
            # per-principal containment authority and writer lock are still
            # held. Confirm the durable mutation here, where a legitimate
            # concurrent release cannot linearize between publication and the
            # observation. The former post-return check raced with exactly
            # such a release and falsely reported a successful containment as
            # failed after it had already been cleanly released.
            try:
                revoked_snapshot = registry_r.revoked()
            except Exception as e:
                result.failed.append(f"revocation confirmation failed: {e}")
                return
            missed = [
                principal
                for principal in expected_revocations
                if principal not in revoked_snapshot
            ]
            if missed:
                result.failed.append(
                    f"revocation did not take effect for {', '.join(missed)}"
                )

    # Publish the durable generation before touching dependent run-scoped
    # state, then apply every dependent projection before releasing the same
    # strict writer authority. Release therefore cannot delete the generation
    # between publication and the live/trust/gateway containment writes.
    if revoke:
        try:
            from .revocation import _bfs, shared

            registry_r = shared()
            expected_revocations = _bfs(subject, edges) if edges else [subject]
            if edges:
                order = registry_r.revoke_subtree(
                    subject, edges, reason=reason, now=now, protected=True,
                    durable_apply=_apply_dependents,
                )
                result.revoked = list(order)
            else:
                registry_r.revoke(
                    subject, reason=reason, now=now, protected=True,
                    durable_apply=_apply_dependents,
                )
                result.revoked = [subject]
        except Exception as e:
            result.failed.append(f"revoke failed: {e}")
            # Revocation persistence is one restrictive authority, not a
            # prerequisite for the others. If it failed before invoking its
            # under-lock callback, still attempt the live seal and external
            # containment rather than abandoning every available control.
            _apply_dependents()
    else:
        _apply_dependents()

    _audit_containment(result, now=now)
    return result


def _audit_containment(result: Containment, *, now: float | None = None) -> None:
    """Attempt an audit row and report whether it was written.

    Audit signing depends on deployment policy; this helper deliberately makes
    no claim that a successful write was signed.
    """
    from .audit.errors import AuditRefused

    try:
        from .audit import audit_event
        result.audit_written = audit_event(
            "agent_edr_containment", agent="agent_edr",
            subject=result.subject, reason=result.reason[:200],
            contained=result.contained, sealed=result.sealed,
            seal_is_durable=result.seal_is_durable,
            revoked=len(result.revoked), failed=len(result.failed),
        )
        if not result.audit_written:
            result.notes.append("containment audit row was not written")
    except AuditRefused:
        result.audit_written = False
        raise
    except Exception:  # pragma: no cover -- defensive helper boundary
        result.audit_written = False
        log.debug("agent_edr: containment audit failed", exc_info=True)


def release(
    subject: str,
    *,
    registry: Any | None = None,
    unrevoke: bool = True,
    durable_clear: Callable[[], None] | None = None,
) -> Containment:
    """Undo one observed containment generation.

    The live seal and any caller-supplied dependent-store clear run while the
    durable revocation authority still holds its strict writer lock. A newer
    containment generation therefore wins without any stale release callback
    reopening its dependent authority.
    """
    result = Containment(subject=subject, reason="released")
    if registry is None and durable_clear is None and not unrevoke:
        result.failed.append("no release action requested")
        return result

    def _clear_dependents() -> None:
        was_sealed = False
        if registry is not None:
            was_sealed = bool(registry.is_sealed(subject))
            registry.unseal_agent(subject)
        try:
            if durable_clear is not None:
                durable_clear()
        except Exception:
            # The durable generation will be retained by ``unrevoke``. Restore
            # a live seal that this callback removed so a dependent trust or
            # gateway failure cannot reopen the running compartment.
            if registry is not None and was_sealed:
                try:
                    registry.seal(
                        subject,
                        "release failed; durable security containment retained",
                    )
                    if not registry.is_sealed(subject):
                        result.notes.append(
                            "failed to restore the restrictive live compartment seal"
                        )
                except Exception:
                    result.notes.append(
                        "live compartment seal restoration was unavailable; durable "
                        "capability containment remains in place"
                    )
            raise

    if unrevoke:
        try:
            from .revocation import RevocationGenerationMismatch, shared

            registry_r = shared()
            observed = registry_r.revoked().get(subject)
            if observed is None:
                result.notes.append("principal was not revoked")
                if registry is not None or durable_clear is not None:
                    result.failed.append(
                        "no protected containment generation; dependent authorities retained"
                    )
            else:
                # This function is the explicit security release authority.
                # Ordinary resume/capability-unrevoke calls do not receive this
                # override or the observed generation.
                registry_r.unrevoke(
                    subject,
                    allow_protected=True,
                    expected_generation=observed.generation,
                    durable_clear=_clear_dependents,
                )
        except RevocationGenerationMismatch:
            result.superseded = True
            result.failed.append(
                "a newer security containment superseded this release and was retained"
            )
        except Exception as e:
            result.failed.append(f"unrevoke failed: {e}")
    else:
        try:
            _clear_dependents()
        except Exception as e:
            result.failed.append(f"dependent release failed: {e}")
    _audit_containment(result)
    return result


# ---- prove ------------------------------------------------------------------

def incident_report(subject: str, *, since: float | None = None,
                    audit_dir: Path | str | None = None,
                    now: float | None = None) -> dict:
    """The analyst's artifact: posture, timeline, and what was contained.

    Deliberately reports the posture alongside the timeline. A timeline drawn
    from a chain that nobody was signing is a story, not evidence, and the
    report says which it is holding.
    """
    swept = scan(subject=subject, since=since, audit_dir=audit_dir)
    events = sorted(swept.found, key=lambda d: d.ts)
    p = posture()
    # None, not False: a failed lookup means we do not know, and False renders
    # as a definite "this agent still has its authority".
    contained: bool | None = None
    try:
        from .revocation import is_revoked
        contained = bool(is_revoked(subject))
    except Exception as e:
        p.notes.append(f"revocation state unknown: {e}")
    if swept.unsigned_rows:
        p.notes.append(
            f"{swept.unsigned_rows} security row(s) carry no signature: this "
            "timeline is not tamper-evident")
    if swept.unreadable_days:
        p.notes.append(
            f"{len(swept.unreadable_days)} day-file(s) could not be read; the "
            "timeline is partial")
    return {
        "schema_version": SCHEMA_VERSION,
        "subject": subject,
        "generated_at": float(now if now is not None else time.time()),
        "posture": p.to_dict(),
        "currently_revoked": contained,
        "detections": [d.to_dict() for d in events],
        "summary": summary(events),
        "truncated": swept.truncated,
        # From the rows actually read, not from "is the crypto library here".
        "evidence_is_signed": swept.evidence_is_signed,
    }


def render_report(report: dict) -> str:
    """Human-readable incident report."""
    width = 74
    lines = ["=" * width,
             f"  AGENT-EDR INCIDENT REPORT -- {report.get('subject', '?')}",
             "=" * width]
    s = report.get("summary", {})
    revoked = report.get("currently_revoked")
    revoked_text = "unknown" if revoked is None else str(revoked)
    lines.append(f"  detections: {s.get('total', 0)}   "
                 f"currently revoked: {revoked_text}")
    if not report.get("evidence_is_signed"):
        lines.append("  ! the security rows read are UNSIGNED or unreadable: "
                     "this timeline is not tamper-evident")
    if report.get("truncated"):
        lines.append("  ! the sweep hit its bound: OLDER detections exist that "
                     "are not shown")
    posture_block = report.get("posture") or {}
    blind = posture_block.get("blind_spots") or []
    if blind:
        lines.append(f"  ! defenses OFF: {', '.join(blind)} "
                     "-- absence of detections here proves nothing")
    # The notes carry "the timeline is partial" and "revocation state unknown".
    # Printing only blind_spots left those in --json alone, so the artifact the
    # module says you hand to an insurer omitted that days of the chain were
    # unreadable.
    for note in posture_block.get("notes") or []:
        lines.append(f"  ! {note}")
    lines.append("-" * width)
    for d in report.get("detections", []):
        when = time.strftime("%Y-%m-%d %H:%M:%S",
                             time.gmtime(d.get("ts", 0) or 0))
        lines.append(f"  {when}  [{d.get('severity', '?'):8}] "
                     f"{d.get('kind', '?'):18} {d.get('detail', '')}")
    if not report.get("detections"):
        lines.append("  (no detections in the reviewed window)")
    lines.append("=" * width)
    return "\n".join(lines)


__all__ = [
    "CAPABILITY_BREACH", "CRITICAL", "Containment", "Detection", "EGRESS_BREACH",
    "EXFILTRATION", "HIGH", "INJECTION", "LOW", "MEDIUM", "POLICY_BREACH",
    "Posture", "SCHEMA_VERSION", "Scan", "TRUST_BREACH", "contain",
    "detections",
    "incident_report", "posture", "release", "render_report", "scan",
    "summary", "timeline",
]
