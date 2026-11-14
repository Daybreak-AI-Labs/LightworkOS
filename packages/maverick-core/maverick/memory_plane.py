"""The Institutional Memory plane: attest what the fleet actually learned.

The fleet's accumulated operational judgment is held in a governed,
vendor-neutral plane. :mod:`maverick.fleet_memory` implements the ingest/recall
half: external agents from any vendor deposit and retrieve department-scoped
lessons through a fail-closed governed surface, every read audited with the
reader's identity.

This module is the **attest** half. A memory plane whose value is "it
compounds, and it is yours, and it never leaked across tenants" is making three
claims that should be checkable rather than taken on trust.

The attestation deliberately uses the **same signed bundle spine as the
attestation bundle** (:mod:`maverick.attestation`;
:mod:`maverick.attestation_verify` supplies the crypto, the trust-anchor rule,
and the HOLDS/FAILS/INDETERMINATE/NOT_APPLICABLE vocabulary). There is one
implementation of "verify a signature against a key the verifier already
trusted", not two.

The gradings carry the same discipline, which matters most in two places:

*One vendor is not cross-vendor.* The cross-vendor claim is that a lesson
crosses a vendor boundary: a Copilot agent benefiting from a lesson a Claude
agent learned last week. A plane with a single vendor connected has nothing to
demonstrate, so the claim is ``NOT_APPLICABLE`` rather than a pass. Grading it
HOLDS because nothing went wrong would claim the property on the strength of
an empty room.

*Isolation cannot be proven from inside.* "One customer's memory never reaches
another's" is not checkable within a single tenant's bundle -- every record is
under this tenant's root because that is the only place we looked. So the tenant
binding is published as *evidence*, and the claim says plainly that it is
established by comparing two tenants' bundles, not by reading one. A tautology
dressed as a proof is worse than an admitted gap.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .attestation_verify import (
    FAILS,
    HOLDS,
    INDETERMINATE,
    NOT_APPLICABLE,
    ClaimResult,
    VerifyResult,
    _have_crypto,
    canonical_bundle_bytes,
    format_report,
    verify_ed25519,
)

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
BUNDLE_KIND = "maverick-memory-plane"

#: Below this many runs a compounding curve is noise, not evidence.
_MIN_RUNS_FOR_CLAIM = 4


@dataclass
class DepartmentCurve:
    """Cold-vs-warm cost and reliability for one department."""

    department: str
    runs: int
    cold_cost: float
    warm_cost: float
    cold_success: float
    warm_success: float
    improving: bool

    def to_dict(self) -> dict:
        return {
            "department": self.department, "runs": self.runs,
            "cold_cost": round(self.cold_cost, 4),
            "warm_cost": round(self.warm_cost, 4),
            "cold_success": round(self.cold_success, 3),
            "warm_success": round(self.warm_success, 3),
            "improving": self.improving,
        }


def compounding_by_department(world: Any, *, window: int = 5,
                              min_runs: int = _MIN_RUNS_FOR_CLAIM,
                              ) -> list[DepartmentCurve]:
    """The cold->warm curve per department.

    Reuses :mod:`maverick.compounding_metric` and only changes how a run is
    classified: by department rather than by task verb, because a
    per-department result ("the finance swarm got 40% cheaper") is the one an
    operator can act on. Read-only.
    """
    from . import compounding_metric as cm

    def _by_department(goal: Any) -> str:
        return str(getattr(goal, "domain", "") or "unassigned").strip().lower()

    try:
        reports = cm.report_from_world(
            world, classify=_by_department, window=window, min_runs=min_runs)
    except Exception as e:  # pragma: no cover -- read-only, never block
        log.debug("memory_plane: compounding read failed: %s", e)
        return []
    return [
        DepartmentCurve(
            department=r.task_class, runs=r.runs, cold_cost=r.cold_cost,
            warm_cost=r.warm_cost, cold_success=r.cold_success,
            warm_success=r.warm_success,
            improving=bool(r.improving) and _is_real_cost_pair(
                r.cold_cost, r.warm_cost),
        )
        for r in reports
    ]


def _is_real_cost_pair(cold: float, warm: float) -> bool:
    """Are these costs capable of evidencing anything?

    ``CompoundingReport.improving`` is a bare ``warm < cold`` comparison, which
    a negative or non-finite cost satisfies trivially: episodes logged at
    -$1e9 and -$1e12 "improve" beautifully. The claim is only worth making if
    it cannot be faked, so a cost that is not a finite positive number
    disqualifies the curve rather than powering it.
    """
    return all(
        isinstance(v, (int, float)) and not isinstance(v, bool)
        and math.isfinite(v) and v > 0
        for v in (cold, warm)
    )


def _fleet_evidence(audit_dir: Path | str | None = None,
                    ) -> tuple[dict, list[str]]:
    """Roster, per-source counts and provenance integrity from the plane."""
    warnings: list[str] = []
    try:
        from . import fleet_memory
    except Exception as e:  # pragma: no cover
        return {"available": False, "error": str(e)[:200]}, [
            f"fleet memory unavailable: {e}"]
    try:
        status = fleet_memory.status()
    except Exception as e:
        # An unreadable plane is not an empty plane. Saying so keeps a read
        # failure from being graded as "no cross-vendor activity".
        log.warning("memory_plane: fleet status unavailable: %s", e)
        return {"available": False, "error": str(e)[:200]}, [
            f"fleet memory status unreadable: {e}"]

    roster = status.get("agents") or []
    vendors: set[str] = set()
    for entry in roster:
        vendor = str((entry or {}).get("vendor", "") or "").strip()
        if vendor:
            vendors.add(vendor)

    # Ingestion counts come from the SIGNED AUDIT CHAIN, not from the inbox
    # directory `status()` globs. Two reasons, and the first is disqualifying:
    # `ingest` routes a "lesson" into the reflexion store and only
    # success/failure records into the inbox, so an inbox count misses the
    # cross-vendor lessons that are the entire point of the plane -- a Copilot
    # agent could deposit 500 of them and the attestation would report "no
    # records deposited". Second, an audit row is signed and hash-chained,
    # which is the standard of evidence an attestation should be built on.
    ingests, recalls, unprovenanced, audit_warnings = _audited_fleet_activity(
        audit_dir)
    warnings.extend(audit_warnings)
    # A vendor counts only if it is on the roster. `fleet_memory.ingest` is
    # fail-closed on registration, so an ingest naming a vendor nobody
    # registered should not exist -- and treating one as evidence would let a
    # forged or stale source string manufacture the cross-vendor property out
    # of a single contributor. Counted as an anomaly instead.
    off_roster = sorted({
        source.split(":", 1)[0] for source in ingests
        if ":" in source and source.split(":", 1)[0] not in vendors
    })
    if off_roster:
        warnings.append(
            f"{len(off_roster)} vendor(s) appear in ingest events but not on "
            f"the roster ({', '.join(off_roster[:5])}); not counted")
    total = sum(n for source, n in ingests.items()
                if ":" in source and source.split(":", 1)[0] in vendors)
    if unprovenanced:
        warnings.append(
            f"{unprovenanced} ingest event(s) carry no vendor:agent_id "
            "provenance and cannot be attributed")
    return {
        "available": True,
        "enabled": bool(getattr(fleet_memory, "enabled", lambda: False)()),
        "agents": len(roster),
        "vendors": sorted(vendors),
        "records": total,
        "recalls": sum(recalls.values()),
        "unprovenanced_records": unprovenanced,
        "by_source": {str(k): int(v) for k, v in sorted(ingests.items())},
        "recalls_by_source": {str(k): int(v) for k, v in sorted(recalls.items())},
    }, warnings


#: Bound on day-files read per export. The whole audit history could be years
#: deep, and unsealing every file to count fleet rows is not something an
#: attestation should do unbounded.
_MAX_ACTIVITY_DAYS = 400


def _audited_fleet_activity(audit_dir: Path | str | None = None,
                            ) -> tuple[dict[str, int], dict[str, int], int,
                                       list[str]]:
    """Per-source ingest and recall counts, read off the signed audit chain.

    Only rows whose signature and hash chain verify are counted. The bundle's whole
    justification for preferring this source over the inbox is that an audit row
    is signed and hash-chained; counting bare rows from a deployment with
    signing switched off would assert cross-vendor totals over evidence nobody
    signed.
    """
    from .audit.sealing import segment_text
    from .audit.signing import day_files
    from .paths import data_dir

    ingests: dict[str, int] = {}
    recalls: dict[str, int] = {}
    unprovenanced = 0
    warnings: list[str] = []
    root = Path(audit_dir) if audit_dir is not None else data_dir("audit")
    if not root.is_dir():
        return ingests, recalls, unprovenanced, [
            "no audit directory: fleet activity cannot be evidenced"]
    sealed_days = 0
    unverified_days = 0
    unsigned_rows = 0
    days = day_files(root)
    if len(days) > _MAX_ACTIVITY_DAYS:
        warnings.append(
            f"only the most recent {_MAX_ACTIVITY_DAYS} of {len(days)} audit "
            "day-file(s) were read; counts are a lower bound")
        days = days[-_MAX_ACTIVITY_DAYS:]
    for path in days:
        try:
            text = segment_text(path, fail_soft=False)
        except Exception:
            # A sealed or unreadable day hides activity from the count. Said
            # out loud, because a silently short total would understate the
            # very claim this bundle exists to make.
            sealed_days += 1
            continue
        if not _day_chain_verified(path, text):
            unverified_days += 1
            continue
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict) or row.get("agent") != "fleet_memory":
                continue
            event = row.get("fleet")
            if event not in ("ingest", "recall"):
                continue
            if not (row.get("sig") and row.get("hash") and row.get("key_id")):
                unsigned_rows += 1
                continue
            source = str(row.get("source", "") or "")
            bucket = ingests if event == "ingest" else recalls
            if not source or ":" not in source:
                if event == "ingest":
                    unprovenanced += 1
                continue
            bucket[source] = bucket.get(source, 0) + 1
    if sealed_days:
        warnings.append(
            f"{sealed_days} audit day-file(s) could not be read; fleet activity "
            "counts are a lower bound, not a total")
    if unverified_days:
        warnings.append(
            f"{unverified_days} audit day-file(s) failed signature or hash-chain "
            "verification; their fleet rows were not counted")
    if unsigned_rows:
        warnings.append(
            f"{unsigned_rows} fleet row(s) carry no signature and were not "
            "counted; audit signing appears to be off")
    return ingests, recalls, unprovenanced, warnings


def _day_chain_verified(path: Path, text: str) -> bool:
    """Whether a day's signed rows verify (signature and hash chain).

    Rows written with signing off are reported as ``unsigned`` and are
    skipped by the caller anyway; any other break means a row's signature or
    chain cannot be trusted, so none of that day's rows count as evidence.
    """
    from .audit.signing import verify_chain
    try:
        breaks = verify_chain(path, segment=text)
    except Exception:
        return False
    return all(b.reason == "unsigned" for b in breaks)


def _tenant_binding() -> dict:
    """Which tenant's data root this plane resolves under.

    Published as evidence, not as a claim: see the module docstring. The path is
    hashed rather than emitted, because a filesystem layout is not something an
    attestation should leak, and a digest is enough to compare two bundles.
    """
    out: dict[str, Any] = {}
    try:
        from .client import client_id
        out["tenant"] = str(client_id() or "(default)")
    except Exception as e:  # pragma: no cover
        out["tenant_error"] = str(e)[:200]
    try:
        from . import fleet_memory
        root = Path(fleet_memory.inbox_dir()).resolve()
        out["root_sha256"] = hashlib.sha256(
            str(root).encode("utf-8")).hexdigest()
    except Exception as e:  # pragma: no cover
        out["root_error"] = str(e)[:200]
    return out


def build(world: Any = None, *, now: float | None = None,
          window: int = 5,
          audit_dir: Path | str | None = None) -> dict:
    """Assemble the (unsigned) memory-plane attestation from live evidence."""
    fleet, warnings = _fleet_evidence(audit_dir)
    curves: list[dict] = []
    if world is not None:
        curves = [c.to_dict() for c in
                  compounding_by_department(world, window=window)]
    elif fleet.get("available"):
        warnings.append(
            "no world model supplied: the compounding claim has no runs to "
            "read and is reported as unproven, not as absent improvement")
    return {
        "kind": BUNDLE_KIND,
        "schema_version": SCHEMA_VERSION,
        "issued_at": float(now if now is not None else time.time()),
        "tenant_binding": _tenant_binding(),
        "claims": {
            # Raw observations. The verifier grades; a self-graded claim is the
            # thing a third party cannot use.
            "cross_vendor": fleet,
            "compounding": {"departments": curves},
            "tenant_isolation": {},
        },
        "warnings": warnings,
    }


def sign(bundle: dict) -> dict:
    """Sign with the instance's Ed25519 audit key. Raises without crypto."""
    from .audit.signing import _have_crypto, _load_or_create_keypair
    if not _have_crypto():
        raise RuntimeError(
            "memory-plane attestation requires 'cryptography' "
            "(install 'maverick-agent[audit-signing]'): bundles are always signed.")
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv, pub, key_id = _load_or_create_keypair()
    sig = ed25519.Ed25519PrivateKey.from_private_bytes(priv).sign(
        canonical_bundle_bytes(bundle))
    return {**bundle, "signature": {
        "pubkey": pub.hex(), "key_id": key_id, "sig": sig.hex()}}


def export(out_path: Path | str, world: Any = None, *,
           now: float | None = None) -> Path:
    """Build, sign and atomically write a memory-plane attestation."""
    bundle = sign(build(world, now=now))
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    from .audit import EventKind, audit_event

    # Do not publish a governed export after the configured audit guarantee
    # explicitly refuses to record it.
    audit_event(
        EventKind.LEARNING_UPDATE, agent="memory_plane",
        attestation="export",
        vendors=len(bundle["claims"]["cross_vendor"].get("vendors") or []),
        key_id=bundle["signature"]["key_id"],
    )
    from .file_lock import atomic_write_text
    atomic_write_text(out, json.dumps(bundle, indent=2, default=str), mode=0o600)
    return out


# ---- claim grading ----------------------------------------------------------

def _check_cross_vendor(bundle: dict) -> ClaimResult:
    """Did agents from more than one vendor actually share this plane?"""
    ev = bundle.get("claims", {}).get("cross_vendor")
    notes: list[str] = []
    if not isinstance(ev, dict) or not ev.get("available"):
        return ClaimResult("cross_vendor", INDETERMINATE,
                           "the fleet-memory plane could not be read")
    by_source = ev.get("by_source")
    if not isinstance(by_source, dict):
        return ClaimResult("cross_vendor", INDETERMINATE,
                           "the bundle records no per-source activity")
    roster = {str(v) for v in (ev.get("vendors") or [])}
    # A vendor counts only if it BOTH contributed and is on the roster, and the
    # verifier derives both from the bundle rather than taking the publisher's
    # summary. Either half alone is gameable: roster-only is the empty room (one
    # contributor plus an agent that never ingests), contributor-only lets a
    # forged source string invent a second vendor.
    contributors = {
        str(src).split(":", 1)[0] for src, n in by_source.items()
        if ":" in str(src) and int(n or 0) > 0
    }
    vendors = sorted(contributors & roster)
    off_roster = sorted(contributors - roster)
    if off_roster:
        notes.append(
            f"{len(off_roster)} contributing vendor(s) are not on the roster "
            f"({', '.join(off_roster[:5])}); not counted")
    unprovenanced = ev.get("unprovenanced_records") or 0
    if unprovenanced:
        # Records nobody can attribute undermine the whole claim: a lesson of
        # unknown origin is exactly what the governed plane exists to prevent.
        return ClaimResult(
            "cross_vendor", FAILS,
            f"{unprovenanced} record(s) carry no vendor:agent_id provenance",
            notes)
    if not ev.get("enabled"):
        notes.append("the fleet-memory plane is switched off; these totals are "
                     "historical, not live")
    if len(vendors) < 2:
        # The claim is a lesson crossing a vendor boundary. One vendor cannot
        # demonstrate that, and a pass here would claim the property on the
        # strength of an empty room.
        return ClaimResult(
            "cross_vendor", NOT_APPLICABLE,
            f"{len(vendors)} contributing vendor(s): nothing crossed a vendor "
            "boundary, so there is no cross-vendor property to attest", notes)
    # No `records == 0` branch: `vendors` only holds contributors whose count
    # is above zero, so reaching here with nothing counted is impossible.
    records = sum(
        int(n or 0) for src, n in by_source.items()
        if ":" in str(src) and str(src).split(":", 1)[0] in set(vendors))
    return ClaimResult(
        "cross_vendor", HOLDS,
        f"{records} record(s) from {len(vendors)} contributing vendors "
        f"({', '.join(vendors[:6])}), all attributable", notes)


def _check_compounding(bundle: dict) -> ClaimResult:
    """Is the plane measurably making the fleet cheaper and no less reliable?"""
    ev = bundle.get("claims", {}).get("compounding")
    if not isinstance(ev, dict):
        return ClaimResult("compounding", INDETERMINATE,
                           "the bundle records no compounding evidence")
    departments = ev.get("departments")
    if not isinstance(departments, list) or not departments:
        return ClaimResult(
            "compounding", INDETERMINATE,
            "no department reached the minimum run count, so the curve is "
            "noise rather than evidence")
    notes: list[str] = []
    improving = stagnant = 0
    for row in departments:
        if not isinstance(row, dict):
            return ClaimResult("compounding", FAILS,
                               "a department curve is not an object")
        runs = row.get("runs")
        if not isinstance(runs, int) or isinstance(runs, bool) or runs < _MIN_RUNS_FOR_CLAIM:
            notes.append(f"{row.get('department', '?')}: only {runs} run(s), "
                         "below the evidence floor")
            continue
        # Recomputed from the numbers in the same row. Trusting the published
        # `improving` boolean made the verifier grade the issuer's own verdict
        # -- a bundle claiming improving=True over cold 1.0 -> warm 9.0 with
        # reliability falling 0.9 -> 0.1 graded HOLDS. `_is_real_cost_pair` ran
        # only at build time, so a negative-cost curve passed here too. The
        # module's own rule is that the verifier grades; anything else is a
        # self-graded claim, which is the thing a third party cannot use.
        if _curve_improves(row):
            improving += 1
        else:
            stagnant += 1
            notes.append(
                f"{row.get('department', '?')}: warm cost "
                f"{row.get('warm_cost')} vs cold {row.get('cold_cost')} "
                "— not yet compounding")
    if not improving and not stagnant:
        return ClaimResult("compounding", INDETERMINATE,
                           "no department cleared the evidence floor", notes)
    if not improving:
        # Not a failure of integrity -- an honest negative result. The plane is
        # running and has not yet paid off, which a customer should be told.
        return ClaimResult(
            "compounding", FAILS,
            f"0 of {stagnant} department(s) are compounding", notes)
    return ClaimResult(
        "compounding", HOLDS,
        f"{improving} of {improving + stagnant} department(s) got cheaper "
        "without getting less reliable", notes)


def _curve_improves(row: dict) -> bool:
    """Did this department get cheaper without getting less reliable?"""
    try:
        cold, warm = float(row["cold_cost"]), float(row["warm_cost"])
        cold_ok, warm_ok = float(row["cold_success"]), float(row["warm_success"])
    except (KeyError, TypeError, ValueError):
        return False
    if not _is_real_cost_pair(cold, warm):
        return False
    if not all(math.isfinite(v) for v in (cold_ok, warm_ok)):
        return False
    return warm < cold and warm_ok >= cold_ok - 1e-9


def _check_isolation(bundle: dict) -> ClaimResult:
    """Tenant isolation -- honestly ungradable from a single bundle."""
    binding = bundle.get("tenant_binding")
    if not isinstance(binding, dict) or not binding.get("root_sha256"):
        return ClaimResult("tenant_isolation", INDETERMINATE,
                           "the bundle publishes no tenant binding")
    return ClaimResult(
        "tenant_isolation", NOT_APPLICABLE,
        f"bound to tenant {binding.get('tenant', '?')!r}; isolation is "
        "established by comparing two tenants' bundles, not by reading one",
        ["every record in this bundle is under this tenant's root because that "
         "is the only place it looked — within one bundle that is a tautology, "
         "not a proof",
         f"root digest {str(binding.get('root_sha256'))[:16]}… — two tenants' "
         "bundles must not share it"])


def verify(bundle: dict, *, trusted_key_hex: str) -> VerifyResult:
    """Check a memory-plane attestation against an out-of-band key.

    Same trust model as the attestation bundle: without an anchor obtained
    outside the artifact, verification fails closed, because a key carried
    inside a signed file identifies nobody.
    """
    if not isinstance(bundle, dict):
        return VerifyResult(False, "unverified", "bundle is not a JSON object")
    if bundle.get("kind") != BUNDLE_KIND:
        return VerifyResult(False, "unverified",
                            f"not a {BUNDLE_KIND} bundle "
                            f"(kind={bundle.get('kind')!r})")
    if bundle.get("schema_version") != SCHEMA_VERSION:
        return VerifyResult(
            False, "unverified",
            f"bundle schema version {bundle.get('schema_version')!r} is not "
            f"{SCHEMA_VERSION}")
    if not _have_crypto():
        # Without this the signature check below fails and the customer is told
        # the publisher's signature is BAD -- a tamper accusation for a missing
        # optional extra. The attestation verifier already distinguishes the two.
        return VerifyResult(False, "unverified",
                            "the 'cryptography' package is required to verify")
    sig = bundle.get("signature")
    if not isinstance(sig, dict) or not sig.get("sig"):
        return VerifyResult(False, "unverified", "bundle is unsigned")
    anchor = (trusted_key_hex or "").strip().lower()
    if not anchor:
        return VerifyResult(
            False, "unverified",
            "a trusted public key is required: a key read out of the bundle "
            "proves only that somebody signed it, not who")
    embedded = str(sig.get("pubkey") or "").strip().lower()
    if embedded and embedded != anchor:
        return VerifyResult(
            False, "unverified",
            "the bundle's signing key is not the trusted key (provenance fail)")
    if not verify_ed25519(anchor, str(sig.get("sig")),
                          canonical_bundle_bytes(bundle)):
        return VerifyResult(False, "unverified",
                            "signature does not verify over the bundle contents")

    claims = [_check_cross_vendor(bundle), _check_compounding(bundle),
              _check_isolation(bundle)]
    failed = [c.name for c in claims if c.status == FAILS]
    findings = list(bundle.get("warnings") or [])
    if failed:
        return VerifyResult(False, "signed",
                            f"claim(s) FAILED: {', '.join(failed)}",
                            claims, findings)
    held = sum(1 for c in claims if c.status == HOLDS)
    return VerifyResult(
        True, "signed",
        f"signature verified against the trusted key; {held} of {len(claims)} "
        "claim(s) affirmatively hold", claims, findings)


def verify_file(path: Path | str, *, trusted_key_hex: str) -> VerifyResult:
    """Verify a memory-plane attestation on disk."""
    try:
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return VerifyResult(False, "unverified", f"unreadable bundle: {e}")
    return verify(bundle, trusted_key_hex=trusted_key_hex)


__all__ = [
    "BUNDLE_KIND", "SCHEMA_VERSION", "DepartmentCurve", "build",
    "compounding_by_department", "export", "format_report", "sign", "verify",
    "verify_file",
]
