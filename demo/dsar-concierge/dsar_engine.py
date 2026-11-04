"""Vendored DSAR engine — the standalone agent's record store and clocks.

Zero platform imports (stdlib only): subject requests as JSON records under
``DSAR_DATA_DIR``, the statutory clock (``DSAR_SLA_DAYS``, default 30), a
deterministic message detector (kind + subject + the matched phrases kept as
provenance), an identity-verification token loop, SLA aging bands, package
assembly for access/portability, and the deliberately non-destructive
erasure handoff — the agent NEVER deletes anything itself; it prepares a
structured instruction set for an authenticated operator workflow.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from pathlib import Path

_LOCK = threading.RLock()
_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")
KINDS = ("access", "portability", "erasure")

# Open-ish statuses the clock keeps running on.
OPEN_STATUSES = ("awaiting_verification", "open", "awaiting_erasure")

_KIND_MARKERS = {
    "erasure": ("delete my", "erase my", "forget me", "right to be forgotten",
                "art. 17", "article 17", "remove my data", "erasure"),
    "portability": ("portability", "machine-readable", "art. 20",
                    "article 20", "transfer my data", "export my data"),
    "access": ("access to my", "copy of my data", "what data do you",
               "art. 15", "article 15", "access request", "my personal data"),
}
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def sla_days() -> int:
    try:
        return max(1, int(os.environ.get("DSAR_SLA_DAYS", "30")))
    except ValueError:
        return 30


def _dir() -> Path:
    d = Path(os.environ.get("DSAR_DATA_DIR", ".dsar-data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(rid: str) -> Path:
    if not _ID_RE.fullmatch(rid or ""):
        raise ValueError(f"bad request id {rid!r}")
    return _dir() / f"{rid}.json"


def _now() -> float:
    return time.time()


def _save(rec: dict) -> dict:
    with _LOCK:
        p = _path(rec["id"])
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        tmp.replace(p)
    return rec


def get(rid: str) -> dict | None:
    try:
        p = _path(rid)
    except ValueError:
        return None
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _event(rec: dict, text: str) -> None:
    rec.setdefault("events", []).append({"at": _now(), "text": text})


def open_request(subject_id: str, kind: str, *, channel: str = "web",
                 note: str = "", intake: dict | None = None) -> dict:
    """Open a request awaiting identity verification. The statutory clock
    starts NOW (verification never pauses it — the regulator's clock
    doesn't wait for your inbox)."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    subject = (subject_id or "").strip()
    if not subject:
        raise ValueError("subject_id is required")
    now = _now()
    rec = {
        "id": f"DSR-{uuid.uuid4().hex[:8].upper()}",
        "subject_id": subject[:200],
        "kind": kind,
        "channel": channel[:40],
        "note": note[:2000],
        "intake": intake,
        "status": "awaiting_verification",
        "opened_at": now,
        "due_at": now + sla_days() * 86400,
        "verify_token": uuid.uuid4().hex,
        "verified_at": None,
        "package": None,
        "erasure": None,
        "closed_at": None,
        "events": [],
    }
    _event(rec, f"Request opened via {channel}; the {sla_days()}-day "
                f"statutory clock started. Verification email issued.")
    return _save(rec)


def from_message(text: str, *, sender: str = "", before_open=None) -> dict | None:
    """Deterministic triage of an inbound message. Returns the opened
    record, or None when no request kind or no subject address is
    detectable — the caller refuses honestly instead of guessing."""
    low = f" {(text or '').lower()} "
    matched_kind = None
    signals: list[str] = []
    for kind in ("erasure", "portability", "access"):
        hits = [m for m in _KIND_MARKERS[kind] if m in low]
        if hits and matched_kind is None:
            matched_kind = kind
            signals = hits
    subject = (sender or "").strip()
    if not subject:
        m = _EMAIL_RE.search(text or "")
        subject = m.group(0) if m else ""
    if matched_kind is None or not subject:
        return None
    if before_open is not None:
        subject = before_open(subject)
    return open_request(
        subject, matched_kind, channel="message",
        note=(text or "")[:2000],
        intake={"signals": signals, "excerpt": (text or "")[:300]})


def verify(token: str) -> dict | None:
    """Identity confirmed by the emailed token link: the request becomes
    workable. Unknown/reused tokens return None."""
    token = (token or "").strip()
    if not token:
        return None
    with _LOCK:
        for p in _dir().glob("DSR-*.json"):
            rec = get(p.stem)
            if rec and rec.get("verify_token") == token \
                    and rec["status"] == "awaiting_verification":
                rec["verified_at"] = _now()
                rec["status"] = "open"
                rec["verify_token"] = ""      # single-use
                _event(rec, "Identity verified via emailed token link.")
                return _save(rec)
    return None


def list_requests() -> list[dict]:
    """Summaries, newest first, with the live clock fields."""
    now = _now()
    out = []
    for p in _dir().glob("DSR-*.json"):
        rec = get(p.stem)
        if rec is None:
            continue
        days_left = int((float(rec["due_at"]) - now) // 86400)
        out.append({
            "id": rec["id"], "subject_id": rec["subject_id"],
            "kind": rec["kind"], "channel": rec["channel"],
            "status": rec["status"], "opened_at": rec["opened_at"],
            "due_at": rec["due_at"], "days_left": days_left,
            "overdue": (rec["status"] in OPEN_STATUSES and days_left < 0),
            "verified": bool(rec.get("verified_at")),
        })
    return sorted(out, key=lambda r: r["opened_at"], reverse=True)


def aging() -> dict:
    """SLA aging bands over the open clocks — the same band vocabulary the
    Lightwork privacy workspace uses, so the numbers line up on the platform."""
    bands = {"overdue": 0, "d0_7": 0, "d8_14": 0, "d15_30": 0, "d30_plus": 0}
    open_rows = [r for r in list_requests() if r["status"] in OPEN_STATUSES]
    for r in open_rows:
        dl = r["days_left"]
        band = ("overdue" if dl < 0 else "d0_7" if dl <= 7
                else "d8_14" if dl <= 14 else "d15_30" if dl <= 30
                else "d30_plus")
        bands[band] += 1
    return {"open": len(open_rows), "bands": bands,
            "overdue": bands["overdue"],
            "closing_soon": bands["overdue"] + bands["d0_7"]}


def fulfill_access(rid: str, extracts: dict[str, str],
                   *, by: str = "operator") -> dict | None:
    """Assemble the access/portability response package from the system
    extracts the operator provides. The package is a machine-readable JSON
    document plus a plain cover note — nothing is fabricated: only the
    provided extracts go in."""
    rec = get(rid)
    if rec is None or rec["status"] != "open" \
            or rec["kind"] not in ("access", "portability"):
        return None
    clean = {str(k)[:100]: str(v)[:20_000]
             for k, v in (extracts or {}).items() if str(v).strip()}
    rec["package"] = {
        "created_at": _now(), "created_by": by[:100],
        "subject_id": rec["subject_id"], "kind": rec["kind"],
        "systems": sorted(clean),
        "data": clean,
        "cover_note": (
            f"Response to your {rec['kind']} request {rec['id']}. "
            f"The attached data covers {len(clean)} system(s): "
            f"{', '.join(sorted(clean)) or 'none'}. If anything looks "
            f"incomplete, reply and the request reopens."),
    }
    rec["status"] = "fulfilled"
    _event(rec, f"{rec['kind'].capitalize()} package assembled from "
                f"{len(clean)} system extract(s) by {by}.")
    return _save(rec)


def erasure_handoff(rid: str, systems: list[str],
                    *, by: str = "operator") -> dict | None:
    """Erasure is NEVER destructive from here: produce the structured
    operator handoff (per-system instruction rows, no shell commands) and
    park the request awaiting confirmation."""
    rec = get(rid)
    if rec is None or rec["status"] != "open" or rec["kind"] != "erasure":
        return None
    rows = [{"system": s.strip()[:100],
             "action": "erase-subject-records",
             "subject_id": rec["subject_id"],
             "operator_instruction":
                 f"In {s.strip()}, locate records for "
                 f"{rec['subject_id']} and run your authenticated "
                 f"deletion workflow. Record the ticket/confirmation id."}
            for s in systems if s.strip()]
    if not rows:
        return None
    rec["erasure"] = {"created_at": _now(), "created_by": by[:100],
                      "systems": rows, "confirmations": []}
    rec["status"] = "awaiting_erasure"
    _event(rec, f"Erasure handoff prepared for {len(rows)} system(s) — "
                f"deliberately non-destructive; a human runs each "
                f"deletion and confirms.")
    return _save(rec)


def close(rid: str, *, by: str = "operator", reason: str = "") -> dict | None:
    rec = get(rid)
    if rec is None or rec["status"] == "closed":
        return None
    rec["status"] = "closed"
    rec["closed_at"] = _now()
    _event(rec, f"Closed by {by}" + (f": {reason[:300]}" if reason else "."))
    return _save(rec)
