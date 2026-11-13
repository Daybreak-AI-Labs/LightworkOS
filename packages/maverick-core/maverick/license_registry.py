"""Regulatory license & renewals register — the state-by-state patchwork.

The inventory a licensed business actually runs on: every license
(jurisdiction, authority, license number, holder, status) with its renewal
clock on the SAME semantics the assessment lifecycle already uses
(``renewal_at`` + cadence). Renewing is an auditable act: it advances the
clock by the cadence, files the evidence note, and appends to the record's
history — nothing is overwritten, and the register never files anything
with a regulator itself (evidence in, humans file).

Storage is one JSON file under the tenant data dir, guarded by the
cross-process lock like every other register. These are the client's
REGULATORY licenses.
"""
from __future__ import annotations

import copy
import json
import time
import uuid

_STATUSES = ("active", "pending", "lapsed", "surrendered")
# Renewal-runway bands, keyed the way the DSAR aging bands are.
_BANDS = ("overdue", "d0_30", "d31_60", "d61_90", "d90_plus")


class LicenseRegistryError(RuntimeError):
    """The regulatory-license register could not complete a safe mutation."""


def _store_path():
    from .paths import data_dir
    return data_dir("registers") / "licenses.json"


def _load(*, strict: bool = False) -> list[dict]:
    """The register rows. Mutations pass ``strict``: a register that exists but
    cannot be read is refused, because saving over it would drop its rows."""
    p = _store_path()
    if not p.exists():
        return []
    try:
        rows = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        if strict:
            raise LicenseRegistryError(
                "the license register could not be read; refusing to overwrite it"
            ) from exc
        return []
    if strict and not isinstance(rows, list):
        raise LicenseRegistryError(
            "the license register could not be read; refusing to overwrite it"
        )
    return rows


def _save(rows: list[dict]) -> None:
    p = _store_path()
    from .file_lock import atomic_write_text

    atomic_write_text(p, json.dumps(rows, indent=1))


def _locked():
    from .file_lock import cross_process_lock
    return cross_process_lock(_store_path().with_suffix(".lock"))


def _audit(kind: str, **payload) -> bool:
    from .audit import audit_event

    return audit_event(kind, agent="license-register", **payload)


def _save_with_audit(
    rows: list[dict],
    prior: list[dict],
    *,
    existed_before: bool,
    kind: str,
    payload: dict,
) -> None:
    """Publish a mutation, restoring the exact prior store on audit refusal."""
    _save(rows)
    from .audit import AuditRefused

    try:
        _audit(kind, **payload)
    except AuditRefused:
        try:
            if existed_before:
                _save(prior)
            else:
                _store_path().unlink(missing_ok=True)
        except Exception as rollback_exc:
            raise LicenseRegistryError(
                "audit refused license-register mutation and rollback failed"
            ) from rollback_exc
        raise


def add_license(*, name: str, jurisdiction: str, authority: str,
                license_number: str, holder: str = "",
                status: str = "active", renewal_at: float | None = None,
                cadence_days: int = 365, added_by: str = "local") -> dict:
    """Register a license. ``renewal_at`` defaults to one cadence out."""
    if status not in _STATUSES:
        raise ValueError(f"status must be one of {_STATUSES}")
    cadence_days = max(1, int(cadence_days))
    now = time.time()
    rec = {
        "id": f"lic-{uuid.uuid4().hex[:10]}",
        "name": name.strip()[:200],
        "jurisdiction": jurisdiction.strip()[:120],
        "authority": authority.strip()[:200],
        "license_number": license_number.strip()[:120],
        "holder": holder.strip()[:200],
        "status": status,
        "renewal_at": float(renewal_at or now + cadence_days * 86400),
        "cadence_days": cadence_days,
        "created_at": now,
        "evidence": [],
        "history": [{"at": now, "event": "registered", "by": added_by}],
    }
    with _locked():
        rows = _load(strict=True)
        prior = copy.deepcopy(rows)
        existed_before = _store_path().exists()
        rows.append(rec)
        _save_with_audit(
            rows,
            prior,
            existed_before=existed_before,
            kind="LICENSE_REGISTERED",
            payload={
                "license": rec["id"],
                "name": rec["name"],
                "jurisdiction": rec["jurisdiction"],
                "by": added_by,
            },
        )
    return rec


def list_licenses() -> list[dict]:
    """Every license with its computed runway: days to renewal, overdue
    flag, and the runway band -- soonest deadline first."""
    now = time.time()
    out = []
    for rec in _load():
        days = int((float(rec.get("renewal_at", 0)) - now) // 86400)
        band = ("overdue" if days < 0 else "d0_30" if days <= 30
                else "d31_60" if days <= 60 else "d61_90" if days <= 90
                else "d90_plus")
        out.append({**rec, "days_left": days, "overdue": days < 0,
                    "band": band})
    return sorted(out, key=lambda r: r["renewal_at"])


def runway() -> dict:
    """The renewal-runway rollup for boards and binders."""
    rows = [r for r in list_licenses()
            if r.get("status") in ("active", "pending")]
    bands = dict.fromkeys(_BANDS, 0)
    for r in rows:
        bands[r["band"]] += 1
    juris = sorted({r["jurisdiction"] for r in rows if r["jurisdiction"]})
    return {"total": len(rows), "bands": bands,
            "overdue": bands["overdue"],
            "due_90d": bands["overdue"] + bands["d0_30"] + bands["d31_60"]
                       + bands["d61_90"],
            "jurisdictions": len(juris), "lapsed": sum(
                1 for r in list_licenses() if r.get("status") == "lapsed")}


def attach_evidence(license_id: str, *, note: str, filename: str = "",
                    by: str = "local") -> dict | None:
    """File an evidence note (renewal confirmation, filing receipt name)
    against the license. Returns the updated record or None."""
    with _locked():
        rows = _load(strict=True)
        prior = copy.deepcopy(rows)
        existed_before = _store_path().exists()
        for rec in rows:
            if rec.get("id") == license_id:
                rec["evidence"].append({"at": time.time(),
                                        "note": note.strip()[:2000],
                                        "filename": filename.strip()[:300],
                                        "by": by})
                rec["history"].append({"at": time.time(),
                                       "event": "evidence", "by": by})
                _save_with_audit(
                    rows,
                    prior,
                    existed_before=existed_before,
                    kind="LICENSE_EVIDENCE",
                    payload={"license": license_id, "by": by},
                )
                return rec
    return None


def renew(license_id: str, *, note: str = "", by: str = "local") -> dict | None:
    """Record a completed renewal: advance the clock one cadence FROM THE
    DEADLINE (not from today -- regulators don't reset calendars to your
    filing date), set status active, and keep the history. The register
    records that a human renewed; it never files with the authority."""
    with _locked():
        rows = _load(strict=True)
        prior = copy.deepcopy(rows)
        existed_before = _store_path().exists()
        for rec in rows:
            if rec.get("id") == license_id:
                base = float(rec.get("renewal_at", time.time()))
                rec["renewal_at"] = base + int(rec.get("cadence_days", 365)) * 86400
                rec["status"] = "active"
                if note:
                    rec["evidence"].append({"at": time.time(),
                                            "note": note.strip()[:2000],
                                            "filename": "", "by": by})
                rec["history"].append({"at": time.time(),
                                       "event": "renewed", "by": by})
                _save_with_audit(
                    rows,
                    prior,
                    existed_before=existed_before,
                    kind="LICENSE_RENEWED",
                    payload={
                        "license": license_id,
                        "by": by,
                        "next_renewal": rec["renewal_at"],
                    },
                )
                return rec
    return None


def set_status(license_id: str, status: str, *, by: str = "local") -> dict | None:
    if status not in _STATUSES:
        raise ValueError(f"status must be one of {_STATUSES}")
    with _locked():
        rows = _load(strict=True)
        prior = copy.deepcopy(rows)
        existed_before = _store_path().exists()
        for rec in rows:
            if rec.get("id") == license_id:
                rec["status"] = status
                rec["history"].append({"at": time.time(),
                                       "event": f"status:{status}",
                                       "by": by})
                _save_with_audit(
                    rows,
                    prior,
                    existed_before=existed_before,
                    kind="LICENSE_STATUS",
                    payload={
                        "license": license_id,
                        "status": status,
                        "by": by,
                    },
                )
                return rec
    return None


__all__ = [
    "LicenseRegistryError",
    "add_license",
    "list_licenses",
    "runway",
    "attach_evidence",
    "renew",
    "set_status",
]
