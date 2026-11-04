"""Self-contained deterministic engine for the standalone GRC Concierge.

This module intentionally imports nothing from ``maverick``. It is a reduced,
unsigned SKU: three starter frameworks and a local JSON record store. Framework
text is original paraphrase, not reproduced licensed standards text.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from local_store_lock import cross_process_lock as _cross_process_lock


@dataclass(frozen=True)
class Control:
    id: str
    family: str
    requirement: str
    severity: str
    evidence_terms: tuple[str, ...]
    remediation: str


def _c(cid, family, requirement, severity, terms, remediation):
    return Control(cid, family, requirement, severity, tuple(terms), remediation)


CATALOG: dict[str, dict] = {
    "soc2": {
        "name": "SOC 2 starter screen",
        "version": "TSC starter",
        "controls": (
            _c("CC1", "Control environment", "Leadership assigns security accountability and oversight.", "high", ("accountability", "oversight", "security owner"), "Assign accountable control owners and record oversight."),
            _c("CC2", "Communication", "Security duties and material issues are communicated to relevant people.", "medium", ("security awareness", "communication", "reporting"), "Publish and attest security responsibilities."),
            _c("CC6", "Logical access", "Access is authorized, least-privileged, and removed when no longer needed.", "high", ("least privilege", "access review", "deprovision"), "Enforce least privilege and periodic access review."),
            _c("CC7", "Operations", "Security events are detected, investigated, and resolved.", "high", ("monitoring", "incident", "alert"), "Implement monitored detection and incident response."),
            _c("CC8", "Change management", "Changes are authorized, tested, and traceable.", "medium", ("change approval", "code review", "testing"), "Require review, testing, and approval for changes."),
        ),
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022 starter screen",
        "version": "Annex A starter",
        "controls": (
            _c("A.5.1", "Organizational", "Information-security policies are approved, communicated, and reviewed.", "high", ("security policy", "annual review", "approved"), "Approve a policy set with owners and review dates."),
            _c("A.5.15", "Organizational", "Access control rules reflect business and security needs.", "high", ("access control", "least privilege", "role based"), "Document and enforce access-control rules."),
            _c("A.6.3", "People", "Personnel receive relevant security awareness and training.", "medium", ("security training", "awareness", "phishing"), "Deliver and track role-appropriate training."),
            _c("A.8.15", "Technological", "Security-relevant activity is logged and protected.", "high", ("audit log", "logging", "retention"), "Centralize, retain, and protect security logs."),
            _c("A.8.16", "Technological", "Networks, systems, and applications are monitored for anomalies.", "high", ("monitoring", "anomaly", "siem"), "Define monitored signals and response ownership."),
        ),
    },
    "nist-csf": {
        "name": "NIST CSF 2.0 starter screen",
        "version": "2.0 starter",
        "controls": (
            _c("GV.OC", "Govern", "Organizational context and stakeholder expectations inform cybersecurity risk decisions.", "high", ("risk appetite", "stakeholder", "business context"), "Document context, stakeholders, and risk appetite."),
            _c("ID.AM", "Identify", "Assets and services are inventoried and prioritized.", "high", ("asset inventory", "service inventory", "owner"), "Maintain an owned and prioritized asset inventory."),
            _c("PR.AA", "Protect", "Identities and access are managed according to risk.", "high", ("mfa", "identity", "access review"), "Require MFA and lifecycle access reviews."),
            _c("DE.CM", "Detect", "Assets and services are monitored for adverse events.", "high", ("continuous monitoring", "alert", "detection"), "Establish monitored detections with accountable responders."),
            _c("RS.MA", "Respond", "Incidents are managed, contained, and communicated.", "high", ("incident response", "containment", "tabletop"), "Test an incident response plan and communication tree."),
            _c("RC.RP", "Recover", "Recovery plans restore operations and incorporate lessons learned.", "medium", ("recovery plan", "restore test", "lessons learned"), "Test recovery and track lessons to closure."),
        ),
    },
}

MOCK_HANDOFF_DESTINATIONS = {
    "grc_platform_a": "GRC platform A",
    "grc_platform_b": "GRC platform B",
    "grc_platform_c": "GRC platform C",
}

VENDOR_POSTURE_FIELDS = (
    "data_encryption",
    "mfa",
    "incident_response",
    "vulnerability_management",
    "business_continuity",
)


def list_frameworks() -> list[dict]:
    return [{"id": key, "name": value["name"], "version": value["version"], "controls": len(value["controls"])} for key, value in CATALOG.items()]


def get_framework(framework: str) -> dict:
    if not isinstance(framework, str):
        raise ValueError("framework must be a string")
    item = CATALOG.get(framework)
    if item is None:
        raise ValueError(f"unknown framework: {framework}")
    return {**item, "id": framework}


def score_questionnaire(framework: str, answers: dict[str, str], subject: str = "") -> dict:
    if not isinstance(answers, dict):
        raise ValueError("answers must be an object keyed by control id")
    controls = get_framework(framework)["controls"]
    unexpected = set(answers).difference(control.id for control in controls)
    if unexpected:
        raise ValueError(f"unknown control answers: {sorted(unexpected)}")
    findings = []
    weights = {"high": 3, "medium": 2, "low": 1}
    possible = sum(weights[c.severity] for c in controls)
    gap_score = 0
    for control in controls:
        answer = str(answers.get(control.id, "unknown")).lower()
        if answer not in {"yes", "no", "na", "unknown"}:
            raise ValueError(f"invalid answer for {control.id}")
        if answer in {"no", "unknown"}:
            gap_score += weights[control.severity]
            findings.append({"control_id": control.id, "severity": control.severity, "answer": answer, "requirement": control.requirement, "remediation": control.remediation})
    ratio = gap_score / possible if possible else 0
    posture = "high risk" if ratio >= 0.55 else "moderate risk" if ratio >= 0.25 else "low risk"
    bounded_subject = str(subject or "").strip()
    if len(bounded_subject) > 300:
        raise ValueError("subject must not exceed 300 characters")
    answered = sum(
        str(answers.get(control.id, "unknown")).lower() in {"yes", "no", "na"}
        for control in controls
    )
    return {"id": uuid.uuid4().hex, "type": "assessment", "framework": framework, "subject": bounded_subject or "Untitled scope", "posture": posture, "score": round((1 - ratio) * 100), "answered": answered, "total": len(controls), "findings": findings}


def evaluate_controls(
    controls: tuple[Control, ...] | list[Control] | list[dict],
    text: str,
    source: str = "pasted evidence",
) -> list[dict]:
    """Return explainable verdicts for either local or adapted controls."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text must be a non-empty string")
    if not isinstance(source, str) or not source.strip() or len(source) > 200:
        raise ValueError("source must contain 1 to 200 characters")
    if len(text) > 20000:
        raise ValueError("text must not exceed 20000 characters")
    normalized = " ".join(text.split())
    sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", normalized) if part.strip()]
    verdicts = []
    for control in controls:
        cid = control.id if isinstance(control, Control) else str(control["id"])
        requirement = (
            control.requirement
            if isinstance(control, Control)
            else str(control["requirement"])
        )
        terms = (
            control.evidence_terms
            if isinstance(control, Control)
            else tuple(str(term) for term in control.get("evidence_terms", ()))
        )
        matched = [
            sentence
            for sentence in sentences
            if any(term in sentence.lower() for term in terms)
        ]
        hits = sum(
            any(term in sentence.lower() for sentence in sentences) for term in terms
        )
        status = "present" if hits >= 2 else "partial" if hits == 1 else "missing"
        verdicts.append(
            {
                "control_id": cid,
                "status": status,
                "source": source,
                "quote": matched[0][:500] if matched else "",
                "requirement": requirement,
            }
        )
    return verdicts


def evaluate_evidence(framework: str, text: str, source: str = "pasted evidence") -> list[dict]:
    """Return explainable control verdicts; each positive verdict quotes text."""
    return evaluate_controls(get_framework(framework)["controls"], text, source)


class RevisionConflict(ValueError):
    pass


def _checked_revision(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("expected_revision must be a non-negative integer")
    return value


class LocalStore:
    """Atomic local JSON store with revision CAS; records are unsigned."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or os.environ.get("GRC_STORE", ".grc-standalone/records.json"))
        self._lock = threading.RLock()

    def _read(self) -> dict:
        if not self.path.exists():
            return {"revision": 0, "records": []}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def list_records(self, kind: str | None = None) -> list[dict]:
        rows = self._read()["records"]
        return [row for row in rows if kind is None or row.get("type") == kind]

    def get_record(self, record_id: str) -> dict | None:
        for row in reversed(self.list_records()):
            if row.get("id") == record_id:
                return row
        return None

    def current_revision(self) -> int:
        return int(self._read()["revision"])

    def save(self, record: dict, expected_revision: int) -> dict:
        revision = _checked_revision(expected_revision)
        with self._lock:
            with _cross_process_lock(self.path):
                return self._save(record, revision)

    def _save(self, record: dict, expected_revision: int) -> dict:
        state = self._read()
        if state["revision"] != expected_revision:
            raise RevisionConflict(f"revision changed: expected {expected_revision}, found {state['revision']}")
        row = dict(record)
        row.setdefault("id", uuid.uuid4().hex)
        row.setdefault("created_at", time.time())
        row["revision"] = state["revision"] + 1
        state["revision"] += 1
        state["records"].append(row)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent, delete=False) as tmp:
            json.dump(state, tmp, indent=2, sort_keys=True)
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, self.path)
        return row

    def replace(self, record_id: str, record: dict, expected_revision: int) -> dict:
        """CAS-replace one record while preserving its stable identity."""
        revision = _checked_revision(expected_revision)
        with self._lock:
            with _cross_process_lock(self.path):
                state = self._read()
                if state["revision"] != revision:
                    raise RevisionConflict(
                        f"revision changed: expected {revision}, found {state['revision']}"
                    )
                index = next(
                    (
                        index
                        for index in range(len(state["records"]) - 1, -1, -1)
                        if state["records"][index].get("id") == record_id
                    ),
                    None,
                )
                if index is None:
                    raise ValueError("stored record not found")
                previous = state["records"][index]
                row = dict(record)
                row["id"] = record_id
                row.setdefault("created_at", previous.get("created_at", time.time()))
                state["revision"] += 1
                row["revision"] = state["revision"]
                state["records"][index] = row
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    "w", encoding="utf-8", dir=self.path.parent, delete=False
                ) as tmp:
                    json.dump(state, tmp, indent=2, sort_keys=True)
                    tmp_path = Path(tmp.name)
                os.replace(tmp_path, self.path)
                return row


def create_risk(title: str, likelihood: int, impact: int, owner: str, treatment: str) -> dict:
    if (
        not isinstance(likelihood, int)
        or isinstance(likelihood, bool)
        or not isinstance(impact, int)
        or isinstance(impact, bool)
    ):
        raise ValueError("likelihood and impact must be integers")
    if not 1 <= likelihood <= 5 or not 1 <= impact <= 5:
        raise ValueError("likelihood and impact must be between 1 and 5")
    if treatment not in {"accept", "mitigate", "transfer", "avoid"}:
        raise ValueError("invalid treatment")
    if not isinstance(title, str) or not isinstance(owner, str):
        raise ValueError("title and owner must be strings")
    risk_title = title.strip()
    risk_owner = owner.strip()
    if not risk_title or len(risk_title) > 300:
        raise ValueError("title must contain 1 to 300 characters")
    if not risk_owner or len(risk_owner) > 160:
        raise ValueError("owner must contain 1 to 160 characters")
    return {"type": "risk", "title": risk_title, "owner": risk_owner, "likelihood": likelihood, "impact": impact, "risk_score": likelihood * impact, "treatment": treatment}


def create_poam(finding: str, owner: str, due_date: str, milestone: str) -> dict:
    if not all(isinstance(value, str) for value in (finding, owner, due_date, milestone)):
        raise ValueError("finding, owner, due_date, and milestone must be strings")
    gap = finding.strip()
    accountable_owner = owner.strip()
    next_milestone = milestone.strip()
    due = due_date.strip()
    if not gap or len(gap) > 2000:
        raise ValueError("finding must contain 1 to 2000 characters")
    if not accountable_owner or len(accountable_owner) > 160:
        raise ValueError("owner must contain 1 to 160 characters")
    if not next_milestone or len(next_milestone) > 300:
        raise ValueError("milestone must contain 1 to 300 characters")
    try:
        date.fromisoformat(due)
    except ValueError as exc:
        raise ValueError("due_date must use YYYY-MM-DD") from exc
    return {"type": "poam", "finding": gap, "owner": accountable_owner, "due_date": due, "milestone": next_milestone, "status": "open"}


def create_vendor_assessment(
    vendor: str,
    owner: str,
    answers: dict[str, str],
    previous: dict | None = None,
) -> dict:
    """Create a bounded local vendor snapshot with explicit carry-forward provenance."""
    if not isinstance(vendor, str) or not vendor.strip() or len(vendor.strip()) > 200:
        raise ValueError("vendor must contain 1 to 200 characters")
    if not isinstance(owner, str) or not owner.strip() or len(owner.strip()) > 160:
        raise ValueError("owner must contain 1 to 160 characters")
    if not isinstance(answers, dict):
        raise ValueError("answers must be an object")
    unexpected = set(answers).difference(VENDOR_POSTURE_FIELDS)
    if unexpected:
        raise ValueError(f"unsupported vendor posture fields: {sorted(unexpected)}")
    if previous is not None:
        if previous.get("type") != "vendor_assessment":
            raise ValueError("carry-forward source must be a vendor assessment")
        if str(previous.get("vendor", "")).casefold() != vendor.strip().casefold():
            raise ValueError("carry-forward source must belong to the same vendor")
    previous_answers = previous.get("answers", {}) if previous else {}
    merged: dict[str, str] = {}
    provenance: dict[str, str] = {}
    for field in VENDOR_POSTURE_FIELDS:
        if field in answers:
            value = answers[field]
            provenance[field] = "new"
        elif field in previous_answers:
            value = previous_answers[field]
            provenance[field] = "carried_forward"
        else:
            value = "unknown"
            provenance[field] = "default_unknown"
        if not isinstance(value, str) or value.lower() not in {
            "yes",
            "no",
            "unknown",
            "na",
        }:
            raise ValueError(f"invalid vendor posture answer for {field}")
        merged[field] = value.lower()
    gap_count = sum(value in {"no", "unknown"} for value in merged.values())
    posture = "high risk" if gap_count >= 4 else "moderate risk" if gap_count >= 2 else "low risk"
    return {
        "type": "vendor_assessment",
        "vendor": vendor.strip(),
        "subject": vendor.strip(),
        "owner": owner.strip(),
        "answers": merged,
        "answer_provenance": provenance,
        "carry_forward_from": previous.get("id") if previous else None,
        "carried_field_count": sum(
            source == "carried_forward" for source in provenance.values()
        ),
        "posture": posture,
        "gap_count": gap_count,
        "status": "ready_for_mock_handoff",
    }


def create_mock_handoff(
    record: dict,
    destination: str,
    prepared_by: str,
    note: str = "",
) -> dict:
    """Create a local receipt without contacting or approving in a GRC system."""
    if not isinstance(destination, str):
        raise ValueError("destination must be a string")
    label = MOCK_HANDOFF_DESTINATIONS.get(destination)
    if label is None:
        raise ValueError("unsupported mock handoff destination")
    record_id = str(record.get("id") or "").strip()
    if not record_id:
        raise ValueError("source record requires an id")
    if record.get("type") == "mock_handoff_receipt":
        raise ValueError("a mock handoff receipt cannot hand off another receipt")
    if not isinstance(prepared_by, str):
        raise ValueError("prepared_by must be a string")
    actor = prepared_by.strip()
    if not actor or len(actor) > 160:
        raise ValueError("prepared_by must contain 1 to 160 characters")
    if not isinstance(note, str):
        raise ValueError("note must be a string")
    bounded_note = note.strip()
    if len(bounded_note) > 1000:
        raise ValueError("note must not exceed 1000 characters")
    source_digest = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    prepared_at = time.time()
    return {
        "type": "mock_handoff_receipt",
        "source_record_id": record_id,
        "source_record_type": str(record.get("type") or "record")[:80],
        "source_record_sha256": source_digest,
        "destination": destination,
        "destination_label": label,
        "prepared_by": actor,
        "note": bounded_note,
        "status": "pending_human_review",
        "delivery_status": "not_sent_mock_only",
        "review_queue": "local_mock_tenant",
        "approval_authority": "local_mock_reviewer_only",
        "manual_approval_required": True,
        "network_call_made": False,
        "source_created_at": float(record.get("created_at") or prepared_at),
        "prepared_at": prepared_at,
        "created_at": prepared_at,
    }


def decide_mock_handoff(
    receipt: dict,
    decision: str,
    reviewer: str,
    rationale: str = "",
) -> dict:
    """Record a local mock-tenant review decision; never deliver externally."""
    if receipt.get("type") != "mock_handoff_receipt":
        raise ValueError("review target must be a mock handoff receipt")
    if receipt.get("status") != "pending_human_review":
        raise ValueError("mock handoff has already been reviewed")
    if decision not in {"approve", "reject"}:
        raise ValueError("decision must be approve or reject")
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer.strip()) > 160:
        raise ValueError("reviewer must contain 1 to 160 characters")
    if not isinstance(rationale, str) or len(rationale.strip()) > 1000:
        raise ValueError("rationale must not exceed 1000 characters")
    reviewed_at = time.time()
    row = dict(receipt)
    row.update(
        {
            "status": f"mock_{decision}d" if decision == "approve" else "mock_rejected",
            "decision": decision,
            "reviewer": reviewer.strip(),
            "rationale": rationale.strip(),
            "reviewed_at": reviewed_at,
            "review_seconds": max(
                0.0, reviewed_at - float(receipt.get("prepared_at") or reviewed_at)
            ),
            "manual_approval_required": False,
            "network_call_made": False,
            "delivery_status": "not_sent_mock_only",
        }
    )
    return row


def speed_story(records: list[dict]) -> dict:
    """Aggregate measured local preparation/review timing without estimates."""
    receipts = [row for row in records if row.get("type") == "mock_handoff_receipt"]
    reviewed = [row for row in receipts if isinstance(row.get("reviewed_at"), (int, float))]
    preparation_seconds = [
        max(0.0, float(row["prepared_at"]) - float(row["source_created_at"]))
        for row in receipts
        if isinstance(row.get("prepared_at"), (int, float))
        and isinstance(row.get("source_created_at"), (int, float))
    ]
    review_seconds = [max(0.0, float(row.get("review_seconds", 0.0))) for row in reviewed]

    def average(values: list[float]) -> float | None:
        return round(sum(values) / len(values), 3) if values else None

    return {
        "receipts_prepared": len(receipts),
        "receipts_reviewed": len(reviewed),
        "pending_reviews": sum(
            row.get("status") == "pending_human_review" for row in receipts
        ),
        "average_prepare_seconds": average(preparation_seconds),
        "average_review_seconds": average(review_seconds),
        "measurement": "local observed elapsed time",
    }
