"""Deterministic Security & GRC operating registers.

This module is the security counterpart to :mod:`maverick.privacy_ops`.  It
keeps governance records in private, tenant-scoped JSON stores with monotonic
revision compare-and-swap (CAS) and a durable at-least-once audit outbox.

The engines here deliberately do not make compliance, materiality, control,
or notification decisions.  They map evidence and compute arithmetic posture;
named people approve evidence, accept risk, determine notification duties, and
close findings.  Document extraction is always marked ``untrusted`` and kept
behind a review gate.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import math
import re
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone

from .privacy_ops import (
    AuditOutboxError as SecurityAuditOutboxError,
)
from .privacy_ops import (
    PrivacyStateError as SecurityStateError,
)
from .privacy_ops import (
    RecordConflict,
    _actor_label,
    _build_document_evidence,
    _document_text,
    _queue_audit,
    _RecordStore,
    _validated_audit_queue,
)

_SECURITY_EVENT_KIND = "security_record_changed"
_MAX_TEXT = 2_000_000
_VALID_CONTROL_STATUS = (
    "not_started",
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "not_applicable",
)
_EVIDENCE_REQUIRED_CONTROL_STATUS = frozenset({"partial", "implemented"})
_RISK_TREATMENTS = ("accept", "mitigate", "transfer", "avoid")
_POAM_STATUS = ("open", "in_progress", "blocked", "complete", "closed", "accepted")
_POLICY_STATUS = ("draft", "review", "approved", "attested", "retired")
_INCIDENT_PHASES = ("containment", "eradication", "recovery")
_RESOLVED_INCIDENT_CLOCK_STATES = frozenset({"documented_not_notifiable", "notify"})
_AUDIT_STATUS = ("planning", "planned", "fieldwork", "review", "complete", "closed")
_AUDIT_TERMINAL_STATUS = frozenset({"complete", "closed"})
_AUDIT_TERMINAL_TRANSITIONS = {
    "complete": frozenset({"review", "closed"}),
    "closed": frozenset({"review"}),
}
_SEVERITIES = ("low", "medium", "high", "critical")


class SecurityTransitionError(SecurityStateError):
    """A requested human-governed lifecycle transition is invalid."""


def enabled() -> bool:
    """Whether deployment-global Security/GRC operations are enabled.

    The suite remains default-on when the section/key is absent for backwards
    compatibility.  A present malformed value fails closed, and tenant overlays
    cannot change this deployment authority bit.
    """
    try:
        from .config import config_source_errors, load_global_config

        config = load_global_config()
        if config_source_errors(include_tenant=False):
            return False
        if "security_ops" not in config:
            return True
        section = config.get("security_ops")
        return (
            isinstance(section, dict)
            and section.get("enable", True) is True
        )
    except Exception:  # pragma: no cover - authority reads fail closed
        return False


_CONTROLS = _RecordStore("security_controls", "CTL")
_EVIDENCE = _RecordStore("security_evidence", "EVD")
_RISKS = _RecordStore("security_risks", "RSK")
_POAMS = _RecordStore("security_poam", "POAM")
_VENDORS = _RecordStore("security_vendors", "VEN")
_POLICIES = _RecordStore("security_policies", "POL")
_INCIDENTS = _RecordStore("security_incidents", "SINC")
_ENGAGEMENTS = _RecordStore("security_audits", "AUD")
_CLOCKS = _RecordStore("security_clock_packs", "CLK")

_STORES = (
    ("control", _CONTROLS),
    ("evidence", _EVIDENCE),
    ("risk", _RISKS),
    ("poam", _POAMS),
    ("vendor", _VENDORS),
    ("policy", _POLICIES),
    ("incident", _INCIDENTS),
    ("audit_engagement", _ENGAGEMENTS),
    ("regulatory_clock", _CLOCKS),
)


def _evidence_integrity_lock():
    """Serialize evidence decisions with every evidence-backed mutation.

    Evidence, controls, risks, and audit workpapers intentionally live in
    separate CAS stores.  Their individual record locks cannot prevent an
    approval from being revoked between a support check and the dependent
    write, so cross-store evidence bindings share one strict tenant-local
    lock.
    """
    from .file_lock import cross_process_lock, ensure_private_directory
    from .paths import data_dir

    target = data_dir("security_integrity", "evidence-bindings")
    ensure_private_directory(target.parent)
    return cross_process_lock(target, strict=True)


def _required(value: object, label: str, limit: int = 4000) -> str:
    out = str(value or "").strip()
    if not out:
        raise ValueError(f"{label} is required")
    return out[:limit]


def _human(value: object, label: str = "human actor") -> str:
    return _actor_label(_required(value, label, 4096))


def _bounded_list(values, *, limit: int = 128, item_limit: int = 200) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, (list, tuple, set, frozenset)):
        raise ValueError("value must be a list")
    return [str(value).strip()[:item_limit] for value in list(values)[:limit] if str(value).strip()]


def _validate_expected_revision(value: int | None, *, updating: bool) -> None:
    if updating and value is None:
        raise ValueError("expected_revision is required when updating a record")
    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
        raise ValueError("expected_revision must be a non-negative integer")


def _audit_mutation(store: _RecordStore, record_type: str, record: dict) -> dict:
    """Flush one record's durable outbox without changing its CAS revision."""
    record_id = str(record.get("id") or "")
    outcome: dict | None = None

    def _flush(current: dict) -> None:
        nonlocal outcome
        queue = _validated_audit_queue(current)
        if not queue:
            outcome = current
            return
        remaining = list(queue)
        for pending in queue[:16]:
            try:
                from .audit import record as audit_record
                from .paths import current_tenant_id

                ok = audit_record(
                    _SECURITY_EVENT_KIND,
                    agent=str(pending.get("actor") or "system"),
                    event_id=str(pending.get("event_id") or ""),
                    occurred_at=float(pending.get("prepared_at") or 0.0),
                    actor=str(pending.get("actor") or "system"),
                    tenant=current_tenant_id() or "",
                    record_type=record_type,
                    action=str(pending.get("action") or ""),
                    record_id=record_id,
                    revision=int(pending.get("revision") or current.get("revision") or 0),
                    status=str(pending.get("status") or current.get("status") or ""),
                    record_sha256=str(pending.get("record_sha256") or ""),
                )
                if not ok:
                    raise RuntimeError("audit writer refused security event")
            except Exception:  # noqa: BLE001 - durable receipt remains for retry
                break
            remaining.pop(0)
        if remaining:
            current["_audit_pending"] = remaining
        else:
            current.pop("_audit_pending", None)
        outcome = current

    saved = store.update(record_id, _flush, metadata_only=True)
    if saved is None:
        raise SecurityStateError("security record disappeared during audit commit")
    return saved if outcome is None else outcome


_AUDIT_RETRY_LOCK = threading.Lock()
_AUDIT_RETRY_OFFSET = 0


def retry_pending_audits(*, limit: int = 100) -> int:
    """Retry a bounded, rotating set of durable security audit receipts."""
    global _AUDIT_RETRY_OFFSET

    cleared = 0
    visited = 0
    budget = max(1, int(limit))
    with _AUDIT_RETRY_LOCK:
        start = _AUDIT_RETRY_OFFSET % len(_STORES)
        indexes = tuple(range(start, len(_STORES))) + tuple(range(start))
        for index in indexes:
            record_type, store = _STORES[index]
            for _, record_id in store.iter_record_ids(limit=budget - visited):
                if visited >= budget:
                    break
                visited += 1
                before = store.load(record_id)
                had_pending = bool(before and before.get("_audit_pending"))
                if not before:
                    continue
                after = _audit_mutation(store, record_type, before)
                if had_pending and not after.get("_audit_pending"):
                    cleared += 1
            _AUDIT_RETRY_OFFSET = (index + 1) % len(_STORES)
            if visited >= budget:
                break
    return cleared


def _list(store: _RecordStore) -> list[dict]:
    retry_pending_audits(limit=16)
    return store.list()


def _create(store: _RecordStore, record_type: str, record: dict, action: str, actor: str) -> dict:
    _queue_audit(record, action, actor)
    return _audit_mutation(
        store,
        record_type,
        store.save(record, expected_revision=0),
    )


def _update(
    store: _RecordStore,
    record_type: str,
    record_id: str,
    mutate,
    *,
    expected_revision: int,
    action: str,
    actor: str,
) -> dict | None:
    _validate_expected_revision(expected_revision, updating=True)

    def _mutate(record: dict) -> None:
        mutate(record)
        _queue_audit(record, action, actor)

    saved = store.update(
        record_id,
        _mutate,
        expected_revision=expected_revision,
    )
    return _audit_mutation(store, record_type, saved) if saved is not None else None


# ---------------------------------------------------------------------------
# Canonical control register and cross-framework crosswalk
# ---------------------------------------------------------------------------

# These are original, compact control objectives. Framework identifiers are
# references, not reproductions of restricted standards text.
CONTROL_CATALOG: tuple[dict, ...] = (
    {
        "id": "GOV-01",
        "title": "Security governance and risk ownership",
        "patterns": (r"security (?:governance|program)", r"risk (?:committee|owner|register)"),
        "mappings": {
            "soc2": ["CC1", "CC3"],
            "iso27001": ["A.5.1", "A.5.2"],
            "nist_csf": ["GV.OC", "GV.RM", "GV.RR"],
            "nist_800_53": ["PM", "RA"],
            "cis_v8": ["1-18 Governance"],
            "pci_dss": ["12"],
            "hipaa": ["164.308(a)(1)"],
            "cmmc_l2": ["CA", "RA"],
            "fedramp_moderate": ["PM", "RA"],
        },
    },
    {
        "id": "POL-01",
        "title": "Approved security policies",
        "patterns": (
            r"information security polic",
            r"approved.{0,60}polic",
            r"annual.{0,30}review",
        ),
        "mappings": {
            "soc2": ["CC1.1", "CC2.2"],
            "iso27001": ["A.5.1"],
            "nist_csf": ["GV.PO"],
            "nist_800_53": ["PL-1"],
            "cis_v8": ["14.1"],
            "pci_dss": ["12.1"],
            "hipaa": ["164.316"],
            "fedramp_moderate": ["PL-1"],
        },
    },
    {
        "id": "AST-01",
        "title": "Hardware and software asset inventory",
        "patterns": (
            r"asset inventor",
            r"software inventor",
            r"configuration management database|cmdb",
        ),
        "mappings": {
            "soc2": ["CC6.1"],
            "iso27001": ["A.5.9"],
            "nist_csf": ["ID.AM"],
            "nist_800_53": ["CM-8"],
            "cis_v8": ["1", "2"],
            "pci_dss": ["2.4", "12.5"],
            "hipaa": ["164.308(a)(1)"],
            "cmmc_l2": ["CM"],
            "fedramp_moderate": ["CM-8"],
        },
    },
    {
        "id": "DAT-01",
        "title": "Information classification and handling",
        "patterns": (r"data classification", r"information classification", r"handling standard"),
        "mappings": {
            "soc2": ["C1.1"],
            "iso27001": ["A.5.12", "A.5.13"],
            "nist_csf": ["ID.AM-07", "PR.DS"],
            "nist_800_53": ["MP", "SC"],
            "cis_v8": ["3"],
            "pci_dss": ["3"],
            "hipaa": ["164.312"],
            "cmmc_l2": ["MP"],
            "fedramp_moderate": ["MP"],
        },
    },
    {
        "id": "IAM-01",
        "title": "Identity lifecycle and least privilege",
        "patterns": (r"least privilege", r"access review", r"deprovision", r"identity lifecycle"),
        "mappings": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "iso27001": ["A.5.15", "A.5.16", "A.5.18"],
            "nist_csf": ["PR.AA"],
            "nist_800_53": ["AC", "IA"],
            "cis_v8": ["5", "6"],
            "pci_dss": ["7", "8"],
            "hipaa": ["164.312(a)"],
            "cmmc_l2": ["AC", "IA"],
            "fedramp_moderate": ["AC", "IA"],
        },
    },
    {
        "id": "IAM-02",
        "title": "Strong authentication for sensitive access",
        "patterns": (
            r"multi-factor|multifactor|\bmfa\b",
            r"phishing-resistant",
            r"unique (?:user )?id",
        ),
        "mappings": {
            "soc2": ["CC6.1"],
            "iso27001": ["A.5.17", "A.8.5"],
            "nist_csf": ["PR.AA-03"],
            "nist_800_53": ["IA-2"],
            "cis_v8": ["6.3", "6.4", "6.5"],
            "pci_dss": ["8.4"],
            "hipaa": ["164.312(a)(2)(i)"],
            "cmmc_l2": ["IA"],
            "fedramp_moderate": ["IA-2"],
        },
    },
    {
        "id": "CFG-01",
        "title": "Secure configuration baselines",
        "patterns": (r"secure configuration", r"configuration baseline", r"hardening standard"),
        "mappings": {
            "soc2": ["CC6.6", "CC8.1"],
            "iso27001": ["A.8.9"],
            "nist_csf": ["PR.PS"],
            "nist_800_53": ["CM"],
            "cis_v8": ["4"],
            "pci_dss": ["2"],
            "hipaa": ["164.308(a)(1)"],
            "cmmc_l2": ["CM"],
            "fedramp_moderate": ["CM"],
        },
    },
    {
        "id": "VUL-01",
        "title": "Continuous vulnerability remediation",
        "patterns": (r"vulnerability (?:management|scan)", r"patch management", r"remediation sla"),
        "mappings": {
            "soc2": ["CC7.1"],
            "iso27001": ["A.8.8"],
            "nist_csf": ["ID.RA", "PR.PS"],
            "nist_800_53": ["RA-5", "SI-2"],
            "cis_v8": ["7"],
            "pci_dss": ["6", "11.3"],
            "hipaa": ["164.308(a)(8)"],
            "cmmc_l2": ["RA", "SI"],
            "fedramp_moderate": ["RA-5", "SI-2"],
        },
    },
    {
        "id": "LOG-01",
        "title": "Security audit logging",
        "patterns": (r"audit log", r"security log", r"log retention", r"tamper-evident"),
        "mappings": {
            "soc2": ["CC7.2"],
            "iso27001": ["A.8.15"],
            "nist_csf": ["DE.CM"],
            "nist_800_53": ["AU"],
            "cis_v8": ["8"],
            "pci_dss": ["10"],
            "hipaa": ["164.312(b)"],
            "cmmc_l2": ["AU"],
            "fedramp_moderate": ["AU"],
        },
    },
    {
        "id": "MON-01",
        "title": "Detection and event analysis",
        "patterns": (r"security monitoring", r"alert triage", r"siem", r"detection rule"),
        "mappings": {
            "soc2": ["CC7.2", "CC7.3"],
            "iso27001": ["A.8.16"],
            "nist_csf": ["DE.CM", "DE.AE"],
            "nist_800_53": ["SI-4"],
            "cis_v8": ["8", "13"],
            "pci_dss": ["10", "11"],
            "hipaa": ["164.308(a)(1)(ii)(D)"],
            "cmmc_l2": ["SI"],
            "fedramp_moderate": ["SI-4"],
        },
    },
    {
        "id": "ENC-01",
        "title": "Cryptographic protection and key custody",
        "patterns": (r"encrypt(?:ed|ion)", r"key management", r"cryptographic"),
        "mappings": {
            "soc2": ["CC6.7", "C1.2"],
            "iso27001": ["A.8.24"],
            "nist_csf": ["PR.DS"],
            "nist_800_53": ["SC-12", "SC-13", "SC-28"],
            "cis_v8": ["3.10", "3.11"],
            "pci_dss": ["3", "4"],
            "hipaa": ["164.312(a)(2)(iv)", "164.312(e)"],
            "cmmc_l2": ["SC"],
            "fedramp_moderate": ["SC-12", "SC-13", "SC-28"],
        },
    },
    {
        "id": "NET-01",
        "title": "Network protection and segmentation",
        "patterns": (r"network segmentation", r"firewall", r"network security", r"zero trust"),
        "mappings": {
            "soc2": ["CC6.6"],
            "iso27001": ["A.8.20", "A.8.22"],
            "nist_csf": ["PR.IR"],
            "nist_800_53": ["SC-7"],
            "cis_v8": ["12", "13"],
            "pci_dss": ["1"],
            "hipaa": ["164.312(e)"],
            "cmmc_l2": ["SC"],
            "fedramp_moderate": ["SC-7"],
        },
    },
    {
        "id": "MAL-01",
        "title": "Malware and unsafe-content defenses",
        "patterns": (
            r"anti-malware|antimalware",
            r"malware defense",
            r"endpoint detection|\bedr\b",
        ),
        "mappings": {
            "soc2": ["CC6.8"],
            "iso27001": ["A.8.7"],
            "nist_csf": ["PR.PS", "DE.CM"],
            "nist_800_53": ["SI-3"],
            "cis_v8": ["10"],
            "pci_dss": ["5"],
            "hipaa": ["164.308(a)(5)"],
            "cmmc_l2": ["SI"],
            "fedramp_moderate": ["SI-3"],
        },
    },
    {
        "id": "BAK-01",
        "title": "Recoverable backups and resilience tests",
        "patterns": (
            r"backup",
            r"restore test",
            r"recovery point|\brpo\b",
            r"recovery time|\brto\b",
        ),
        "mappings": {
            "soc2": ["A1.2", "A1.3"],
            "iso27001": ["A.8.13", "A.8.14"],
            "nist_csf": ["PR.IR", "RC.RP"],
            "nist_800_53": ["CP"],
            "cis_v8": ["11"],
            "pci_dss": ["12.10"],
            "hipaa": ["164.308(a)(7)"],
            "fedramp_moderate": ["CP"],
        },
    },
    {
        "id": "IR-01",
        "title": "Incident response and lessons learned",
        "patterns": (r"incident response", r"containment", r"lessons learned", r"tabletop"),
        "mappings": {
            "soc2": ["CC7.4", "CC7.5"],
            "iso27001": ["A.5.24", "A.5.26", "A.5.27"],
            "nist_csf": ["RS.MA", "RS.AN", "RS.MI"],
            "nist_800_53": ["IR"],
            "cis_v8": ["17"],
            "pci_dss": ["12.10"],
            "hipaa": ["164.308(a)(6)"],
            "cmmc_l2": ["IR"],
            "fedramp_moderate": ["IR"],
        },
    },
    {
        "id": "BCP-01",
        "title": "Business continuity and ICT readiness",
        "patterns": (r"business continuity", r"disaster recovery", r"continuity plan"),
        "mappings": {
            "soc2": ["A1.1", "A1.2"],
            "iso27001": ["A.5.29", "A.5.30"],
            "nist_csf": ["RC.RP"],
            "nist_800_53": ["CP"],
            "cis_v8": ["11"],
            "pci_dss": ["12.10"],
            "hipaa": ["164.308(a)(7)"],
            "fedramp_moderate": ["CP"],
        },
    },
    {
        "id": "SUP-01",
        "title": "Third-party and supply-chain assurance",
        "patterns": (
            r"vendor risk",
            r"supplier (?:risk|security)",
            r"third-party (?:risk|security)",
            r"supply chain",
        ),
        "mappings": {
            "soc2": ["CC9.2"],
            "iso27001": ["A.5.19", "A.5.21", "A.5.22"],
            "nist_csf": ["GV.SC"],
            "nist_800_53": ["SR"],
            "cis_v8": ["15"],
            "pci_dss": ["12.8"],
            "hipaa": ["164.308(b)"],
            "fedramp_moderate": ["SA", "SR"],
        },
    },
    {
        "id": "SDLC-01",
        "title": "Secure software lifecycle",
        "patterns": (
            r"secure (?:software )?development",
            r"secure sdlc",
            r"code review",
            r"application security test",
        ),
        "mappings": {
            "soc2": ["CC8.1"],
            "iso27001": ["A.8.25", "A.8.28", "A.8.29"],
            "nist_csf": ["PR.PS"],
            "nist_800_53": ["SA"],
            "cis_v8": ["16"],
            "pci_dss": ["6"],
            "hipaa": ["164.308(a)(8)"],
            "fedramp_moderate": ["SA"],
        },
    },
    {
        "id": "CHG-01",
        "title": "Controlled production change",
        "patterns": (r"change management", r"change approval", r"production change"),
        "mappings": {
            "soc2": ["CC8.1"],
            "iso27001": ["A.8.32"],
            "nist_csf": ["PR.PS"],
            "nist_800_53": ["CM-3"],
            "cis_v8": ["4", "16"],
            "pci_dss": ["6.5"],
            "hipaa": ["164.308(a)(8)"],
            "cmmc_l2": ["CM"],
            "fedramp_moderate": ["CM-3"],
        },
    },
    {
        "id": "AWR-01",
        "title": "Security awareness and role training",
        "patterns": (r"security awareness", r"security training", r"phishing simulation"),
        "mappings": {
            "soc2": ["CC1.4", "CC2.2"],
            "iso27001": ["A.6.3"],
            "nist_csf": ["PR.AT"],
            "nist_800_53": ["AT"],
            "cis_v8": ["14"],
            "pci_dss": ["12.6"],
            "hipaa": ["164.308(a)(5)"],
            "cmmc_l2": ["AT"],
            "fedramp_moderate": ["AT"],
        },
    },
    {
        "id": "PHY-01",
        "title": "Physical access and equipment protection",
        "patterns": (r"physical access", r"facility access", r"badge access", r"secure area"),
        "mappings": {
            "soc2": ["CC6.4"],
            "iso27001": ["A.7"],
            "nist_csf": ["PR.AA"],
            "nist_800_53": ["PE"],
            "cis_v8": ["1"],
            "pci_dss": ["9"],
            "hipaa": ["164.310"],
            "cmmc_l2": ["PE"],
            "fedramp_moderate": ["PE"],
        },
    },
    {
        "id": "HRA-01",
        "title": "Personnel screening and offboarding",
        "patterns": (
            r"background (?:check|screen)",
            r"personnel screening",
            r"termination checklist",
            r"offboarding",
        ),
        "mappings": {
            "soc2": ["CC1.4", "CC6.2"],
            "iso27001": ["A.6.1", "A.6.5"],
            "nist_csf": ["GV.RR", "PR.AA"],
            "nist_800_53": ["PS"],
            "cis_v8": ["5", "6"],
            "pci_dss": ["12.7"],
            "hipaa": ["164.308(a)(3)"],
            "cmmc_l2": ["PS"],
            "fedramp_moderate": ["PS"],
        },
    },
    {
        "id": "EVD-01",
        "title": "Independent control assurance",
        "patterns": (
            r"control test",
            r"independent review",
            r"internal audit",
            r"operating effectiveness",
        ),
        "mappings": {
            "soc2": ["CC4.1", "CC4.2"],
            "iso27001": ["A.5.35", "A.5.36"],
            "nist_csf": ["GV.OV", "ID.IM"],
            "nist_800_53": ["CA"],
            "cis_v8": ["18"],
            "pci_dss": ["11", "12.4"],
            "hipaa": ["164.308(a)(8)"],
            "cmmc_l2": ["CA"],
            "fedramp_moderate": ["CA"],
        },
    },
    {
        "id": "PRV-01",
        "title": "Privacy and regulated-data safeguards",
        "patterns": (
            r"privacy program",
            r"personal data",
            r"protected health information|\bephi\b",
            r"data subject",
        ),
        "mappings": {
            "soc2": ["P1-P8"],
            "iso27001": ["A.5.34"],
            "nist_csf": ["GV.OC", "PR.DS"],
            "nist_800_53": ["PT"],
            "cis_v8": ["3"],
            "pci_dss": ["3"],
            "hipaa": ["164.308", "164.312"],
            "cmmc_l2": ["MP", "SC"],
            "fedramp_moderate": ["PT"],
        },
    },
)

_CONTROL_BY_ID = {control["id"]: control for control in CONTROL_CATALOG}


def _control_record(canonical_id: str, *, owner: str, actor: str) -> dict:
    control = _CONTROL_BY_ID[canonical_id]
    now = time.time()
    mappings = {key: list(value) for key, value in control["mappings"].items()}
    return {
        "id": f"CTL-{canonical_id}",
        "canonical_id": canonical_id,
        "framework": "canonical",
        "control_id": canonical_id,
        "title": control["title"],
        "implementation_status": "not_started",
        "applicable": True,
        "applicability_rationale": "Pending human applicability review",
        "owner": _human(owner, "control owner"),
        "mappings": mappings,
        "crosswalk": [
            f"{framework}:{reference}"
            for framework, references in mappings.items()
            for reference in references
        ],
        "evidence_ids": [],
        "created_at": now,
        "updated_at": now,
        "updated_by": _actor_label(actor),
        "status": "active",
    }


def initialize_control_register(owner: str = "", created_by: str = "") -> list[dict]:
    """Idempotently seed one Statement-of-Applicability row per canonical control."""
    owner = _required(owner, "control owner", 200)
    created = []
    for control in CONTROL_CATALOG:
        record = _control_record(control["id"], owner=owner, actor=created_by)
        try:
            created.append(_create(_CONTROLS, "control", record, "create", created_by))
        except RecordConflict:
            existing = _CONTROLS.load(record["id"])
            if existing is not None:
                created.append(existing)
    return created


def _apply_control_update(record: dict, payload: dict, status: str, updated_by: str) -> None:
    if "title" in payload:
        record["title"] = _required(payload["title"], "title", 500)
    if "implementation_status" in payload:
        record["implementation_status"] = status
        if status not in _EVIDENCE_REQUIRED_CONTROL_STATUS:
            # A human downgrade is the explicit way to detach posture support.
            # This keeps stale citations from silently surviving a control
            # reset and lets a reviewer subsequently revoke their approval.
            record["evidence_ids"] = []
    if "applicable" in payload:
        if not isinstance(payload["applicable"], bool):
            raise ValueError("applicable must be a boolean")
        record["applicable"] = payload["applicable"]
    if "applicability_rationale" in payload:
        record["applicability_rationale"] = _required(
            payload["applicability_rationale"], "applicability rationale", 2000
        )
    if (
        record.get("implementation_status") == "not_applicable"
        and record.get("applicable") is not False
    ):
        raise SecurityTransitionError(
            "not_applicable status requires applicable=false and a human rationale"
        )
    if "owner" in payload:
        record["owner"] = _human(payload.get("owner"), "control owner")
    if "mappings" in payload:
        if not isinstance(payload["mappings"], dict):
            raise ValueError("mappings must be an object")
        record["mappings"] = {
            str(key)[:40]: _bounded_list(value, limit=64, item_limit=80)
            for key, value in payload["mappings"].items()
        }
    if "crosswalk" in payload:
        record["crosswalk"] = _bounded_list(payload["crosswalk"], limit=256, item_limit=240)
    if "framework" in payload:
        record["framework"] = _required(payload["framework"], "framework", 120)
    if "control_id" in payload:
        record["control_id"] = _required(payload["control_id"], "control_id", 160)
    record["updated_at"] = time.time()
    record["updated_by"] = _actor_label(updated_by)


def _upsert_control_unlocked(
    payload: dict,
    *,
    control_id: str = "",
    expected_revision: int | None = None,
    updated_by: str = "",
) -> dict | None:
    """Create/update a control row; update is always revision-CAS guarded."""
    if not isinstance(payload, dict):
        raise ValueError("control payload must be an object")
    if payload.get("evidence_ids"):
        raise ValueError("evidence_ids may only be changed through reviewed evidence application")
    record_id = str(control_id or "").strip()
    _validate_expected_revision(expected_revision, updating=bool(record_id))
    status = str(payload.get("implementation_status", "not_started")).lower()
    if status not in _VALID_CONTROL_STATUS:
        raise ValueError(f"implementation_status must be one of {_VALID_CONTROL_STATUS}")
    if (
        "implementation_status" in payload
        and status in _EVIDENCE_REQUIRED_CONTROL_STATUS
    ):
        raise SecurityTransitionError(
            "partial or implemented status requires human-approved cited evidence"
        )
    canonical = str(payload.get("canonical_id") or "").strip().upper()
    if record_id:

        def _mutate(record: dict) -> None:
            _apply_control_update(record, payload, status, updated_by)

        return _update(
            _CONTROLS,
            "control",
            record_id,
            _mutate,
            expected_revision=int(expected_revision),
            action="update",
            actor=updated_by,
        )
    if canonical and canonical in _CONTROL_BY_ID:
        record = _control_record(canonical, owner=str(payload.get("owner") or ""), actor=updated_by)
        record["implementation_status"] = status
        record["applicable"] = bool(payload.get("applicable", True))
        if payload.get("applicability_rationale"):
            record["applicability_rationale"] = str(payload["applicability_rationale"])[:2000]
    else:
        title = _required(payload.get("title"), "title", 500)
        now = time.time()
        record = {
            "id": _CONTROLS.new_id(),
            "canonical_id": canonical,
            "framework": _required(payload.get("framework") or "custom", "framework", 120),
            "control_id": _required(
                payload.get("control_id") or canonical or uuid.uuid4().hex[:12],
                "control_id",
                160,
            ),
            "title": title,
            "implementation_status": status,
            "applicable": bool(payload.get("applicable", True)),
            "applicability_rationale": _required(
                payload.get("applicability_rationale") or "Pending human applicability review",
                "applicability rationale",
                2000,
            ),
            "owner": _human(payload.get("owner"), "control owner"),
            "mappings": {
                str(key)[:40]: _bounded_list(value, limit=64, item_limit=80)
                for key, value in dict(payload.get("mappings") or {}).items()
            },
            "crosswalk": _bounded_list(payload.get("crosswalk"), limit=256, item_limit=240),
            "evidence_ids": [],
            "created_at": now,
            "updated_at": now,
            "updated_by": _actor_label(updated_by),
            "status": "active",
        }
    if record["implementation_status"] == "not_applicable":
        if record.get("applicable") is not False or not str(
            payload.get("applicability_rationale") or ""
        ).strip():
            raise SecurityTransitionError(
                "not_applicable status requires applicable=false and a human rationale"
            )
    return _create(_CONTROLS, "control", record, "create", updated_by)


def upsert_control(
    payload: dict,
    *,
    control_id: str = "",
    expected_revision: int | None = None,
    updated_by: str = "",
) -> dict | None:
    """Create/update a control under the cross-store evidence lock."""
    with _evidence_integrity_lock():
        return _upsert_control_unlocked(
            payload,
            control_id=control_id,
            expected_revision=expected_revision,
            updated_by=updated_by,
        )


def list_controls() -> list[dict]:
    return _list(_CONTROLS)


def get_control(control_id: str) -> dict | None:
    retry_pending_audits(limit=8)
    return _CONTROLS.load(control_id)


def control_crosswalk(control_id: str = "", framework: str = "") -> list[dict]:
    """Return canonical mappings, optionally filtered by control/framework."""
    canonical = str(control_id or "").strip().upper()
    fw = str(framework or "").strip().lower()
    out = []
    for control in CONTROL_CATALOG:
        if canonical and canonical not in (control["id"], f"CTL-{control['id']}"):
            continue
        mappings = {
            key: list(value) for key, value in control["mappings"].items() if not fw or key == fw
        }
        if fw and not mappings:
            continue
        out.append({"control_id": control["id"], "title": control["title"], "mappings": mappings})
    for row in list_controls():
        if row.get("canonical_id") in _CONTROL_BY_ID:
            continue
        aliases = {
            str(row.get("id") or "").upper(),
            str(row.get("control_id") or "").upper(),
            str(row.get("canonical_id") or "").upper(),
        }
        if canonical and canonical not in aliases:
            continue
        mappings = {
            str(key).lower(): list(value) for key, value in dict(row.get("mappings") or {}).items()
        }
        for item in row.get("crosswalk") or []:
            mapped_framework, separator, reference = str(item).partition(":")
            if separator and mapped_framework and reference:
                mappings.setdefault(mapped_framework.lower(), []).append(reference)
        row_framework = str(row.get("framework") or "").lower()
        if fw:
            mappings = {key: value for key, value in mappings.items() if key == fw}
            if not mappings and fw != row_framework:
                continue
        out.append(
            {
                "control_id": row.get("control_id") or row["id"],
                "record_id": row["id"],
                "title": row["title"],
                "mappings": mappings,
            }
        )
    return out


def statement_of_applicability(framework: str = "") -> list[dict]:
    fw = str(framework or "").strip().lower()
    rows = list_controls()
    return [
        row
        for row in rows
        if not fw
        or fw == str(row.get("framework") or "").lower()
        or fw in (row.get("mappings") or {})
    ]


# ---------------------------------------------------------------------------
# Deterministic, quoted evidence mapping
# ---------------------------------------------------------------------------


def _quote_for_span(text: str, start: int, end: int) -> str:
    start = max(0, start - 90)
    end = min(len(text), end + 150)
    quote = " ".join(text[start:end].split())
    return quote[:500]


_CLAIM_CONTEXT_CHARS = 180
_CLAIM_SIGNAL_WINDOW_CHARS = 120
_CLAIM_BOUNDARY_RE = re.compile(
    r"[.!?;\r\n]+|\b(?:although|but|however|though|whereas)\b",
    flags=re.IGNORECASE,
)
_NON_CURRENT_CLAIM_RE = re.compile(
    r"\b(?:"
    r"no|not|never|without|missing|absent|lacks?|disabled|unsupported|unavailable|"
    r"cannot|can't|doesn't|does\s+not|do\s+not|did\s+not|isn't|is\s+not|"
    r"aren't|are\s+not|hasn't|has\s+not|haven't|have\s+not|fails?\s+to|"
    r"planned|planning\s+to|plans?\s+to|will|shall|intends?\s+to|intended\s+to|"
    r"scheduled\s+to|roadmapped|proposed|pending|future|targeted\s+for|"
    r"to\s+be\s+(?:implemented|deployed|enabled|enforced|adopted)"
    r")\b",
    flags=re.IGNORECASE,
)
_AFFIRMATIVE_NEGATION_IDIOM_RE = re.compile(
    r"\b(?:not\s+only|not\s+(?:absent|disabled|missing|unavailable|unsupported)|"
    r"no\s+(?:known\s+)?exceptions?|without\s+(?:exception|interruption))\b",
    flags=re.IGNORECASE,
)


def _claim_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """Return a bounded sentence/contrast-clause around one matched signal."""
    lower = max(0, start - _CLAIM_CONTEXT_CHARS)
    upper = min(len(text), end + _CLAIM_CONTEXT_CHARS)
    before = text[lower:start]
    after = text[end:upper]
    prior_boundaries = list(_CLAIM_BOUNDARY_RE.finditer(before))
    claim_start = lower + prior_boundaries[-1].end() if prior_boundaries else lower
    next_boundary = _CLAIM_BOUNDARY_RE.search(after)
    claim_end = end + next_boundary.start() if next_boundary else upper
    return claim_start, claim_end


def _non_current_claim(text: str, start: int, end: int) -> bool:
    """Detect bounded negation or future language on either side of a signal."""
    claim_start, claim_end = _claim_bounds(text, start, end)
    window_start = max(claim_start, start - _CLAIM_SIGNAL_WINDOW_CHARS)
    window_end = min(claim_end, end + _CLAIM_SIGNAL_WINDOW_CHARS)
    window = text[window_start:window_end]
    # Avoid demoting affirmative idioms such as "MFA has no exceptions" while
    # keeping genuinely negative/future language available to the matcher.
    window = _AFFIRMATIVE_NEGATION_IDIOM_RE.sub(" ", window)
    return _NON_CURRENT_CLAIM_RE.search(window) is not None


def _map_one_control(text: str, control: dict) -> dict:
    hits = []
    quotes = []
    current_hits = 0
    non_current_language = False
    for pattern in control["patterns"]:
        matches = list(re.finditer(pattern, text, flags=re.IGNORECASE))
        if not matches:
            continue
        evaluated = [
            (match, _non_current_claim(text, match.start(), match.end()))
            for match in matches
        ]
        non_current_language = non_current_language or any(
            is_non_current for _match, is_non_current in evaluated
        )
        current_match = next(
            (match for match, is_non_current in evaluated if not is_non_current),
            None,
        )
        selected = current_match or evaluated[0][0]
        hits.append(selected.group(0))
        quotes.append(_quote_for_span(text, selected.start(), selected.end()))
        if current_match is not None:
            current_hits += 1
    quote = quotes[0] if quotes else ""
    if current_hits >= 2:
        verdict = "present"
    elif hits:
        verdict = "partial"
    else:
        verdict = "missing"
    verdict = {
        "control_id": control["id"],
        "control_title": control["title"],
        "status": verdict,
        "evidence_quote": quote,
        "matched_signals": hits[:8],
        "negation_or_future_language": non_current_language,
    }
    if control.get("record_id"):
        verdict["register_control_id"] = control["record_id"]
    if control.get("external_control_id"):
        verdict["external_control_id"] = control["external_control_id"]
    return verdict


_EVIDENCE_PATTERN_STOP_WORDS = frozenset(
    {
        "about",
        "against",
        "control",
        "from",
        "have",
        "into",
        "review",
        "security",
        "that",
        "their",
        "this",
        "with",
    }
)


def _evidence_control_definitions() -> list[dict]:
    definitions = [dict(control) for control in CONTROL_CATALOG]
    for row in list_controls():
        canonical = str(row.get("canonical_id") or "").upper()
        if canonical in _CONTROL_BY_ID:
            definition = next(item for item in definitions if item["id"] == canonical)
            definition["record_id"] = row["id"]
            definition["external_control_id"] = row.get("control_id") or canonical
            continue
        words = [
            word
            for word in re.findall(r"[a-z0-9][a-z0-9_-]{3,}", str(row.get("title") or "").lower())
            if word not in _EVIDENCE_PATTERN_STOP_WORDS
        ]
        external = str(row.get("control_id") or "").strip()
        patterns = [rf"\b{re.escape(word)}\b" for word in dict.fromkeys(words)][:12]
        if external:
            patterns.insert(0, rf"\b{re.escape(external)}\b")
        definitions.append(
            {
                "id": row["id"],
                "record_id": row["id"],
                "external_control_id": external,
                "title": row["title"],
                "patterns": tuple(patterns),
            }
        )
    return definitions


def _control_aliases(control: dict) -> set[str]:
    """Return every canonical, register, external, and crosswalk reference."""
    aliases = {
        str(control.get("id") or "").upper(),
        str(control.get("record_id") or "").upper(),
        str(control.get("external_control_id") or "").upper(),
    }
    mappings = control.get("mappings") or {}
    if isinstance(mappings, dict):
        for references in mappings.values():
            values = references if isinstance(references, (list, tuple, set)) else [references]
            aliases.update(str(value or "").upper() for value in values)
    return {alias for alias in aliases if alias}


def map_evidence(
    title: str,
    text: str,
    *,
    source: str = "paste",
    control_ids=None,
    submitted_by: str = "",
    document_evidence: dict | None = None,
) -> dict:
    """Map source text to controls with exact quotes; always review-gated."""
    body = str(text or "")[:_MAX_TEXT]
    if not body.strip():
        raise ValueError("evidence text is required")
    requested = {item.upper() for item in _bounded_list(control_ids)}
    definitions = _evidence_control_definitions()
    controls = []
    matched = set()
    for control in definitions:
        aliases = _control_aliases(control)
        selected = requested & aliases
        if not requested or selected:
            controls.append(control)
            matched.update(selected)
    unknown = requested - matched
    if unknown:
        raise ValueError(f"unknown control ids: {sorted(unknown)}")
    verdicts = [_map_one_control(body, control) for control in controls]
    counts = Counter(item["status"] for item in verdicts)
    record = {
        "id": _EVIDENCE.new_id(),
        "title": _required(title, "title", 300),
        "source": str(source or "paste").strip()[:80],
        "source_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "chars_reviewed": len(body),
        "created_at": time.time(),
        "submitted_by": _actor_label(submitted_by),
        "status": "pending_review",
        "extraction_confidence": "untrusted",
        "review_required": True,
        "mapping_method": "deterministic_pattern_v1",
        "verdicts": verdicts,
        "counts": dict(counts),
        "decision": None,
    }
    if document_evidence:
        evidence = dict(document_evidence)
        evidence["confidence"] = "untrusted"
        evidence["review_required"] = True
        without_binding = {key: value for key, value in evidence.items() if key != "binding_sha256"}
        evidence["binding_sha256"] = hashlib.sha256(
            json.dumps(
                without_binding,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        record["document_evidence"] = evidence
    return _create(_EVIDENCE, "evidence", record, "map", submitted_by)


def map_evidence_from_document(
    title: str,
    source: str,
    doc_id: str,
    *,
    ref: dict | None = None,
    control_ids=None,
    submitted_by: str = "",
    principal: str | None = None,
    allow_ambient_credentials: bool = False,
) -> dict:
    """Fetch through a configured connector and map bounded extracted text."""
    from . import doc_discovery

    data, mime = doc_discovery.fetch(
        source,
        doc_id,
        ref,
        max_bytes=16 * 1024 * 1024,
        principal=principal,
        allow_ambient_credentials=allow_ambient_credentials,
    )
    mime = doc_discovery.resolve_mime(title or doc_id, mime)
    extraction: dict = {}
    text = _document_text(data, mime, _metadata=extraction)
    if not text.strip():
        raise ValueError("document yielded no supported text; paste verified text instead")
    evidence = _build_document_evidence(
        data=data,
        text=text,
        mime=mime,
        source=source,
        doc_id=doc_id,
        ref=ref,
        extraction=extraction,
    )
    return map_evidence(
        title,
        text,
        source=source,
        control_ids=control_ids,
        submitted_by=submitted_by,
        document_evidence=evidence,
    )


def list_evidence() -> list[dict]:
    return _list(_EVIDENCE)


def get_evidence(evidence_id: str) -> dict | None:
    retry_pending_audits(limit=8)
    return _EVIDENCE.load(evidence_id)


def _evidence_verdict_for_control(evidence: dict, control: dict) -> dict | None:
    verdict_ids = {
        str(control.get("canonical_id") or ""),
        str(control.get("id") or ""),
        str(control.get("control_id") or ""),
    }
    return next(
        (
            item
            for item in evidence.get("verdicts", [])
            if {
                str(item.get("control_id") or ""),
                str(item.get("register_control_id") or ""),
                str(item.get("external_control_id") or ""),
            }
            & verdict_ids
        ),
        None,
    )


def _evidence_supports_control(evidence: dict, control: dict, status: str) -> bool:
    if evidence.get("status") != "approved":
        return False
    verdict = _evidence_verdict_for_control(evidence, control)
    if verdict is None or verdict.get("status") == "missing":
        return False
    return status != "implemented" or verdict.get("status") == "present"


def _evidence_dependencies(evidence_id: str) -> list[str]:
    """Return bounded dependency labels that make approval revocation unsafe."""
    dependencies: list[str] = []
    for control in _CONTROLS.list():
        if (
            evidence_id in control.get("evidence_ids", [])
            and control.get("implementation_status") in _EVIDENCE_REQUIRED_CONTROL_STATUS
        ):
            dependencies.append(f"control:{control.get('id', '')}")
    for risk in _RISKS.list():
        if evidence_id in risk.get("evidence_ids", []):
            dependencies.append(f"risk:{risk.get('id', '')}")
    for engagement in _ENGAGEMENTS.list():
        for request in engagement.get("evidence_requests", []):
            if (
                request.get("status") in {"accepted", "closed"}
                and evidence_id in request.get("evidence_ids", [])
            ):
                dependencies.append(
                    f"audit_request:{engagement.get('id', '')}:{request.get('id', '')}"
                )
        for test in engagement.get("control_tests", []):
            if (
                test.get("result") in {"pass", "fail"}
                and evidence_id in test.get("evidence_ids", [])
            ):
                dependencies.append(
                    f"control_test:{engagement.get('id', '')}:{test.get('id', '')}"
                )
    return dependencies[:20]


def decide_evidence(
    evidence_id: str, decision: str, rationale: str, decided_by: str, expected_revision: int
) -> dict | None:
    choice = str(decision or "").lower()
    if choice not in ("approved", "rejected"):
        raise ValueError("decision must be approved or rejected")
    actor = _human(decided_by, "decided_by")
    why = _required(rationale, "rationale")

    with _evidence_integrity_lock():

        def _mutate(record: dict) -> None:
            if record.get("status") not in ("pending_review", "approved", "rejected"):
                raise SecurityTransitionError("evidence is not reviewable")
            if record.get("status") == "approved" and choice == "rejected":
                dependencies = _evidence_dependencies(evidence_id)
                if dependencies:
                    raise SecurityTransitionError(
                        "approved evidence cannot be rejected while it supports "
                        f"governance records: {dependencies}"
                    )
            record["status"] = choice
            record["decision"] = {
                "decision": choice,
                "rationale": why,
                "decided_by": actor,
                "decided_at": time.time(),
            }

        return _update(
            _EVIDENCE,
            "evidence",
            evidence_id,
            _mutate,
            expected_revision=expected_revision,
            action="decision",
            actor=decided_by,
        )


def apply_evidence_to_control(
    control_id: str,
    evidence_id: str,
    implementation_status: str,
    applied_by: str,
    expected_revision: int,
) -> dict | None:
    actor = _human(applied_by, "applied_by")
    status = str(implementation_status or "").lower()
    if status not in _EVIDENCE_REQUIRED_CONTROL_STATUS:
        raise ValueError("reviewed evidence may set control status to partial or implemented")
    with _evidence_integrity_lock():
        evidence = _EVIDENCE.load(evidence_id)
        if evidence is None or evidence.get("status") != "approved":
            raise SecurityTransitionError("only human-approved evidence may support a control")
        control = _CONTROLS.load(control_id) or {}
        verdict = _evidence_verdict_for_control(evidence, control)
        if verdict is None or verdict.get("status") == "missing":
            raise SecurityTransitionError("evidence does not support this control")
        if verdict.get("status") != "present" and status == "implemented":
            raise SecurityTransitionError(
                "partial evidence cannot mark a control implemented"
            )

        def _mutate(record: dict) -> None:
            ids = list(record.get("evidence_ids") or [])
            if evidence_id not in ids:
                ids.append(evidence_id)
            record["evidence_ids"] = ids[:256]
            record["implementation_status"] = status
            record["updated_at"] = time.time()
            record["updated_by"] = actor

        return _update(
            _CONTROLS,
            "control",
            control_id,
            _mutate,
            expected_revision=expected_revision,
            action="evidence_applied",
            actor=applied_by,
        )


# ---------------------------------------------------------------------------
# Risk register, treatments, exceptions, and POA&M
# ---------------------------------------------------------------------------


def _score_value(value: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 5:
        raise ValueError(f"{label} must be an integer from 1 to 5")
    return value


def _risk_band(score: int) -> str:
    if score >= 17:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


def _risk_evidence_ids(values) -> list[str]:
    evidence_ids = _bounded_list(values, limit=256, item_limit=80)
    if not evidence_ids:
        raise ValueError("risk scoring requires at least one cited evidence record")
    records = {evidence_id: _EVIDENCE.load(evidence_id) for evidence_id in evidence_ids}
    missing = [evidence_id for evidence_id, record in records.items() if record is None]
    if missing:
        raise ValueError(f"unknown risk evidence ids: {missing}")
    unapproved = [
        evidence_id
        for evidence_id, record in records.items()
        if record is not None and record.get("status") != "approved"
    ]
    if unapproved:
        raise SecurityTransitionError(
            f"risk scoring requires human-approved evidence: {unapproved}"
        )
    return evidence_ids


def _register_risk_unlocked(
    title: str,
    likelihood: int,
    impact: int,
    owner: str,
    *,
    description: str = "",
    control_ids=None,
    likelihood_rationale: str = "",
    impact_rationale: str = "",
    evidence_ids=None,
    created_by: str = "",
) -> dict:
    like = _score_value(likelihood, "likelihood")
    imp = _score_value(impact, "impact")
    like_why = _required(likelihood_rationale, "likelihood rationale", 4000)
    impact_why = _required(impact_rationale, "impact rationale", 4000)
    cited_evidence = _risk_evidence_ids(evidence_ids)
    score = like * imp
    now = time.time()
    record = {
        "id": _RISKS.new_id(),
        "title": _required(title, "title", 300),
        "description": str(description or "")[:4000],
        "owner": _human(owner, "owner"),
        "control_ids": _bounded_list(control_ids),
        "evidence_ids": cited_evidence,
        "likelihood": like,
        "impact": imp,
        "inherent_score": score,
        "inherent_rating": _risk_band(score),
        "residual_likelihood": like,
        "residual_impact": imp,
        "residual_score": score,
        "residual_rating": _risk_band(score),
        "inherent_score_basis": {
            "likelihood_rationale": like_why,
            "impact_rationale": impact_why,
            "evidence_ids": cited_evidence,
        },
        "residual_score_basis": {
            "likelihood_rationale": like_why,
            "impact_rationale": impact_why,
            "evidence_ids": cited_evidence,
        },
        "treatment": None,
        "exception": None,
        "status": "open",
        "created_at": now,
        "updated_at": now,
        "created_by": _actor_label(created_by),
    }
    return _create(_RISKS, "risk", record, "create", created_by)


def register_risk(
    title: str,
    likelihood: int,
    impact: int,
    owner: str,
    *,
    description: str = "",
    control_ids=None,
    likelihood_rationale: str = "",
    impact_rationale: str = "",
    evidence_ids=None,
    created_by: str = "",
) -> dict:
    with _evidence_integrity_lock():
        return _register_risk_unlocked(
            title,
            likelihood,
            impact,
            owner,
            description=description,
            control_ids=control_ids,
            likelihood_rationale=likelihood_rationale,
            impact_rationale=impact_rationale,
            evidence_ids=evidence_ids,
            created_by=created_by,
        )


def _set_risk_treatment_unlocked(
    risk_id: str,
    treatment: str,
    plan: str,
    residual_likelihood: int,
    residual_impact: int,
    owner: str,
    updated_by: str,
    expected_revision: int,
    *,
    residual_likelihood_rationale: str = "",
    residual_impact_rationale: str = "",
    evidence_ids=None,
) -> dict | None:
    choice = str(treatment or "").lower()
    if choice not in _RISK_TREATMENTS:
        raise ValueError(f"treatment must be one of {_RISK_TREATMENTS}")
    actor = _human(updated_by, "updated_by")
    risk_owner = _human(owner, "owner")
    why = _required(plan, "treatment plan")
    like = _score_value(residual_likelihood, "residual_likelihood")
    imp = _score_value(residual_impact, "residual_impact")
    like_why = _required(
        residual_likelihood_rationale, "residual likelihood rationale", 4000
    )
    impact_why = _required(
        residual_impact_rationale, "residual impact rationale", 4000
    )
    cited_evidence = _risk_evidence_ids(evidence_ids)

    def _mutate(record: dict) -> None:
        if record.get("status") == "closed":
            raise SecurityTransitionError("closed risk cannot be treated")
        score = like * imp
        record["treatment"] = {
            "strategy": choice,
            "plan": why,
            "owner": risk_owner,
            "decided_by": actor,
            "decided_at": time.time(),
        }
        record["owner"] = risk_owner
        record["residual_likelihood"] = like
        record["residual_impact"] = imp
        record["residual_score"] = score
        record["residual_rating"] = _risk_band(score)
        record["residual_score_basis"] = {
            "likelihood_rationale": like_why,
            "impact_rationale": impact_why,
            "evidence_ids": cited_evidence,
        }
        record["evidence_ids"] = list(dict.fromkeys([
            *record.get("evidence_ids", []),
            *cited_evidence,
        ]))[:256]
        record["updated_at"] = time.time()

    return _update(
        _RISKS,
        "risk",
        risk_id,
        _mutate,
        expected_revision=expected_revision,
        action="treatment",
        actor=updated_by,
    )


def set_risk_treatment(
    risk_id: str,
    treatment: str,
    plan: str,
    residual_likelihood: int,
    residual_impact: int,
    owner: str,
    updated_by: str,
    expected_revision: int,
    *,
    residual_likelihood_rationale: str = "",
    residual_impact_rationale: str = "",
    evidence_ids=None,
) -> dict | None:
    with _evidence_integrity_lock():
        return _set_risk_treatment_unlocked(
            risk_id,
            treatment,
            plan,
            residual_likelihood,
            residual_impact,
            owner,
            updated_by,
            expected_revision,
            residual_likelihood_rationale=residual_likelihood_rationale,
            residual_impact_rationale=residual_impact_rationale,
            evidence_ids=evidence_ids,
        )


def grant_risk_exception(
    risk_id: str,
    owner: str,
    rationale: str,
    expires_at: float,
    granted_by: str,
    expected_revision: int,
) -> dict | None:
    risk_owner = _human(owner, "owner")
    actor = _human(granted_by, "granted_by")
    why = _required(rationale, "rationale")
    expiry = float(expires_at)
    if not math.isfinite(expiry) or expiry <= time.time():
        raise ValueError("expires_at must be a future timestamp")

    def _mutate(record: dict) -> None:
        if record.get("status") == "closed":
            raise SecurityTransitionError("closed risk cannot receive an exception")
        record["exception"] = {
            "owner": risk_owner,
            "rationale": why,
            "expires_at": expiry,
            "granted_by": actor,
            "granted_at": time.time(),
        }
        record["updated_at"] = time.time()

    return _update(
        _RISKS,
        "risk",
        risk_id,
        _mutate,
        expected_revision=expected_revision,
        action="exception",
        actor=granted_by,
    )


def close_risk(risk_id: str, rationale: str, closed_by: str, expected_revision: int) -> dict | None:
    actor = _human(closed_by, "closed_by")
    why = _required(rationale, "rationale")

    def _mutate(record: dict) -> None:
        if not record.get("treatment"):
            raise SecurityTransitionError("risk needs a documented treatment before closure")
        record["status"] = "closed"
        record["closed_at"] = time.time()
        record["closed_by"] = actor
        record["closure_rationale"] = why

    return _update(
        _RISKS,
        "risk",
        risk_id,
        _mutate,
        expected_revision=expected_revision,
        action="close",
        actor=closed_by,
    )


def list_risks() -> list[dict]:
    now = time.time()
    out = []
    for stored in _list(_RISKS):
        row = dict(stored)
        expiry = (row.get("exception") or {}).get("expires_at")
        row["exception_expired"] = bool(expiry and now >= float(expiry))
        row["exception_due"] = bool(expiry and now < float(expiry) <= now + 30 * 86400)
        out.append(row)
    return out


def get_risk(risk_id: str) -> dict | None:
    retry_pending_audits(limit=8)
    return _RISKS.load(risk_id)


def create_poam(
    finding: str,
    owner: str,
    due_at: float,
    *,
    control_ids=None,
    milestones=None,
    created_by: str = "",
) -> dict:
    due = float(due_at)
    if not math.isfinite(due) or due <= 0:
        raise ValueError("due_at must be a positive timestamp")
    now = time.time()
    items = []
    for item in list(milestones or [])[:128]:
        if not isinstance(item, dict):
            raise ValueError("each milestone must be an object")
        items.append(
            {
                "id": str(item.get("id") or uuid.uuid4().hex[:12]),
                "title": _required(item.get("title"), "milestone title", 300),
                "due_at": float(item.get("due_at") or due),
                "status": str(item.get("status") or "open")[:40],
            }
        )
    record = {
        "id": _POAMS.new_id(),
        "finding": _required(finding, "finding", 2000),
        "owner": _human(owner, "owner"),
        "due_at": due,
        "control_ids": _bounded_list(control_ids),
        "milestones": items,
        "status": "open",
        "created_at": now,
        "updated_at": now,
        "created_by": _actor_label(created_by),
        "review_trigger": None,
    }
    return _create(_POAMS, "poam", record, "create", created_by)


def update_poam(
    poam_id: str,
    status: str,
    *,
    owner: str | None = None,
    due_at: float | None = None,
    milestones=None,
    note: str = "",
    updated_by: str = "",
    expected_revision: int,
) -> dict | None:
    state = str(status or "").lower()
    if state not in _POAM_STATUS:
        raise ValueError(f"status must be one of {_POAM_STATUS}")
    actor = _human(updated_by, "updated_by")

    def _mutate(record: dict) -> None:
        record["status"] = state
        if owner is not None:
            record["owner"] = _human(owner, "owner")
        if due_at is not None:
            due = float(due_at)
            if not math.isfinite(due) or due <= 0:
                raise ValueError("due_at must be a positive timestamp")
            record["due_at"] = due
        if milestones is not None:
            items = []
            for item in list(milestones)[:128]:
                if not isinstance(item, dict):
                    raise ValueError("each milestone must be an object")
                items.append(
                    {
                        "id": str(item.get("id") or uuid.uuid4().hex[:12]),
                        "title": _required(item.get("title"), "milestone title", 300),
                        "due_at": float(item.get("due_at") or record["due_at"]),
                        "status": str(item.get("status") or "open")[:40],
                    }
                )
            record["milestones"] = items
        if note:
            record.setdefault("history", []).append(
                {
                    "at": time.time(),
                    "by": actor,
                    "note": str(note)[:2000],
                    "status": state,
                }
            )
        record["updated_at"] = time.time()
        if state in ("complete", "closed", "accepted"):
            record["closed_at"] = time.time()
            record["closed_by"] = actor

    return _update(
        _POAMS,
        "poam",
        poam_id,
        _mutate,
        expected_revision=expected_revision,
        action="update",
        actor=updated_by,
    )


def trigger_poam_review(
    poam_id: str, reason: str, triggered_by: str, expected_revision: int
) -> dict | None:
    actor = _human(triggered_by, "triggered_by")
    why = _required(reason, "reason")

    def _mutate(record: dict) -> None:
        record["review_trigger"] = {
            "reason": why,
            "triggered_by": actor,
            "triggered_at": time.time(),
        }
        if record.get("status") in ("complete", "closed", "accepted"):
            record["status"] = "open"
        record["updated_at"] = time.time()

    return _update(
        _POAMS,
        "poam",
        poam_id,
        _mutate,
        expected_revision=expected_revision,
        action="review_triggered",
        actor=triggered_by,
    )


def list_poams() -> list[dict]:
    now = time.time()
    out = []
    for stored in _list(_POAMS):
        row = dict(stored)
        row["overdue"] = bool(
            row.get("status") not in ("complete", "closed", "accepted")
            and float(row.get("due_at") or now) < now
        )
        out.append(row)
    return out


def get_poam(poam_id: str) -> dict | None:
    retry_pending_audits(limit=8)
    return _POAMS.load(poam_id)


# ---------------------------------------------------------------------------
# Vendor/TPRM memory and policy lifecycle
# ---------------------------------------------------------------------------

VENDOR_CHECKS: tuple[tuple[str, str, str], ...] = (
    ("independent_assurance", "Current independent security assurance", "high"),
    ("encryption", "Encryption for regulated data in transit and at rest", "high"),
    ("mfa", "Strong authentication and least privilege", "high"),
    ("incident_sla", "Contractual security-incident notification timeline", "medium"),
    ("subprocessors", "Disclosed and governed subprocessors", "medium"),
    ("vulnerability_management", "Documented vulnerability remediation", "high"),
    ("business_continuity", "Tested continuity and recovery", "medium"),
    ("data_deletion", "Verified return/deletion at offboarding", "medium"),
)


def assess_vendor(
    name: str,
    posture: dict,
    *,
    criticality: str = "medium",
    owner: str = "",
    services: str = "",
    assessment_id: str = "",
    carry_forward_from: str = "",
    assessed_by: str = "",
) -> dict:
    if not isinstance(posture, dict):
        raise ValueError("posture must be an object")
    critical = str(criticality or "medium").lower()
    if critical not in _SEVERITIES:
        raise ValueError(f"criticality must be one of {_SEVERITIES}")
    inherited: dict = {}
    prior = None
    if carry_forward_from:
        prior = _VENDORS.load(carry_forward_from)
        if prior is None:
            raise ValueError("carry_forward_from vendor assessment was not found")
        inherited = {item["key"]: item.get("answer") for item in prior.get("checks", [])}
    checks = []
    severities = []
    for key, requirement, severity in VENDOR_CHECKS:
        carried = key not in posture and key in inherited
        answer = posture.get(key, inherited.get(key))
        if answer not in (True, False, None):
            raise ValueError(f"vendor posture {key} must be true, false, or null")
        status = "present" if answer is True else "missing" if answer is False else "unverified"
        if answer is not True:
            severities.append(severity)
        checks.append(
            {
                "key": key,
                "requirement": requirement,
                "severity": severity,
                "answer": answer,
                "status": status,
                "carried_forward": carried,
                "requires_revalidation": carried or answer is None,
            }
        )
    ranking = {"minimal": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    risk = max(severities, key=lambda item: ranking[item], default="minimal")
    now = time.time()
    record = {
        "id": _VENDORS.new_id(),
        "name": _required(name, "name", 300),
        "criticality": critical,
        "owner": _actor_label(owner),
        "services": str(services or "")[:2000],
        "assessment_id": str(assessment_id or "")[:128],
        "carry_forward_from": str(carry_forward_from or "")[:80],
        "checks": checks,
        "residual_risk": risk,
        "status": "pending_review",
        "review_required": True,
        "decision": None,
        "created_at": now,
        "assessed_by": _actor_label(assessed_by),
    }
    return _create(_VENDORS, "vendor", record, "assess", assessed_by)


def decide_vendor_assessment(
    vendor_id: str, decision: str, rationale: str, decided_by: str, expected_revision: int
) -> dict | None:
    choice = str(decision or "").lower()
    if choice not in ("approved", "needs_work", "rejected"):
        raise ValueError("decision must be approved, needs_work, or rejected")
    actor = _human(decided_by, "decided_by")
    why = _required(rationale, "rationale")

    def _mutate(record: dict) -> None:
        record["status"] = choice
        record["decision"] = {
            "decision": choice,
            "rationale": why,
            "decided_by": actor,
            "decided_at": time.time(),
        }

    return _update(
        _VENDORS,
        "vendor",
        vendor_id,
        _mutate,
        expected_revision=expected_revision,
        action="decision",
        actor=decided_by,
    )


def list_vendor_assessments() -> list[dict]:
    return _list(_VENDORS)


def get_vendor_assessment(vendor_id: str) -> dict | None:
    retry_pending_audits(limit=8)
    return _VENDORS.load(vendor_id)


def latest_vendor_assessment(name: str) -> dict | None:
    target = str(name or "").strip().lower()
    return next(
        (row for row in list_vendor_assessments() if str(row.get("name") or "").lower() == target),
        None,
    )


def create_policy(
    title: str,
    owner: str,
    *,
    content_ref: str = "",
    review_cadence_days: int = 365,
    created_by: str = "",
) -> dict:
    days = int(review_cadence_days)
    if not 1 <= days <= 3650:
        raise ValueError("review_cadence_days must be 1-3650")
    now = time.time()
    record = {
        "id": _POLICIES.new_id(),
        "title": _required(title, "title", 300),
        "owner": _human(owner, "owner"),
        "content_ref": str(content_ref or "")[:2000],
        "review_cadence_days": days,
        "next_review_at": None,
        "status": "draft",
        "attestations": [],
        "history": [],
        "created_at": now,
        "updated_at": now,
        "created_by": _actor_label(created_by),
    }
    return _create(_POLICIES, "policy", record, "create", created_by)


def transition_policy(
    policy_id: str, target_status: str, actor: str, *, note: str = "", expected_revision: int
) -> dict | None:
    target = str(target_status or "").lower()
    if target not in _POLICY_STATUS:
        raise ValueError(f"target_status must be one of {_POLICY_STATUS}")
    human = _human(actor, "actor")
    allowed = {
        "draft": {"review", "retired"},
        "review": {"draft", "approved", "retired"},
        "approved": {"review", "retired"},
        "attested": {"review", "retired"},
        "retired": set(),
    }

    def _mutate(record: dict) -> None:
        current = str(record.get("status") or "draft")
        if target not in allowed.get(current, set()):
            raise SecurityTransitionError(f"policy cannot move from {current} to {target}")
        if target == "approved" and not str(note or "").strip():
            raise ValueError("approval note is required")
        record["status"] = target
        now = time.time()
        record["updated_at"] = now
        record["history"] = list(record.get("history") or []) + [
            {
                "from": current,
                "to": target,
                "at": now,
                "by": human,
                "note": str(note or "")[:2000],
            }
        ]
        if target == "approved":
            record["approved_at"] = now
            record["approved_by"] = human
            record["next_review_at"] = now + int(record["review_cadence_days"]) * 86400

    return _update(
        _POLICIES,
        "policy",
        policy_id,
        _mutate,
        expected_revision=expected_revision,
        action=f"transition_{target}",
        actor=actor,
    )


def attest_policy(
    policy_id: str, subject: str, statement: str, attested_by: str, expected_revision: int
) -> dict | None:
    human = _human(attested_by, "attested_by")
    attesting_subject = _human(subject, "subject")
    text = _required(statement, "statement", 2000)

    def _mutate(record: dict) -> None:
        if record.get("status") not in ("approved", "attested"):
            raise SecurityTransitionError("only an approved policy can be attested")
        attestations = list(record.get("attestations") or [])
        attestations.append(
            {
                "id": uuid.uuid4().hex[:12],
                "subject": attesting_subject,
                "statement": text,
                "attested_by": human,
                "attested_at": time.time(),
            }
        )
        record["attestations"] = attestations[:10000]
        record["status"] = "attested"
        record["updated_at"] = time.time()

    return _update(
        _POLICIES,
        "policy",
        policy_id,
        _mutate,
        expected_revision=expected_revision,
        action="attestation",
        actor=attested_by,
    )


def trigger_policy_review(
    policy_id: str, reason: str, triggered_by: str, expected_revision: int
) -> dict | None:
    human = _human(triggered_by, "triggered_by")
    why = _required(reason, "reason")

    def _mutate(record: dict) -> None:
        if record.get("status") == "retired":
            raise SecurityTransitionError("retired policy cannot be reviewed")
        before = str(record.get("status") or "draft")
        record["status"] = "review"
        record["review_trigger"] = {"reason": why, "at": time.time(), "by": human}
        record["history"] = list(record.get("history") or []) + [
            {
                "from": before,
                "to": "review",
                "at": time.time(),
                "by": human,
                "note": why,
            }
        ]
        record["updated_at"] = time.time()

    return _update(
        _POLICIES,
        "policy",
        policy_id,
        _mutate,
        expected_revision=expected_revision,
        action="review_triggered",
        actor=triggered_by,
    )


def list_policies() -> list[dict]:
    now = time.time()
    out = []
    for stored in _list(_POLICIES):
        row = dict(stored)
        due = row.get("next_review_at")
        row["review_due"] = bool(due and now >= float(due))
        out.append(row)
    return out


def get_policy(policy_id: str) -> dict | None:
    retry_pending_audits(limit=8)
    return _POLICIES.load(policy_id)


# ---------------------------------------------------------------------------
# Global regulatory clock packs and human-governed incident response
# ---------------------------------------------------------------------------

REGULATORY_CLOCKS: tuple[dict, ...] = (
    {
        "key": "gdpr_eu_72h",
        "title": "EU GDPR supervisory-authority notice",
        "jurisdiction": "European Union / EEA",
        "status": "current",
        "effective": "2018-05-25",
        "anchor": "awareness",
        "deadline": {"amount": 72, "unit": "hours"},
        "source_url": "https://eur-lex.europa.eu/eli/reg/2016/679/art_33/oj",
        "source_title": "GDPR Article 33",
        "applicability": "Human legal determination required",
    },
    {
        "key": "uk_gdpr_72h",
        "title": "UK GDPR ICO notice",
        "jurisdiction": "United Kingdom",
        "status": "current",
        "effective": "2021-01-01",
        "anchor": "awareness",
        "deadline": {"amount": 72, "unit": "hours"},
        "source_url": "https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/",
        "source_title": "ICO personal data breach guidance",
        "applicability": "Human legal determination required",
    },
    {
        "key": "nis2_early_24h",
        "title": "NIS2 early warning",
        "jurisdiction": "European Union",
        "status": "current",
        "effective": "2024-10-18",
        "anchor": "awareness",
        "deadline": {"amount": 24, "unit": "hours"},
        "source_url": "https://eur-lex.europa.eu/eli/dir/2022/2555/art_23/oj",
        "source_title": "Directive (EU) 2022/2555 Article 23",
        "applicability": "Human determination of significant incident and national transposition required",
    },
    {
        "key": "nis2_notification_72h",
        "title": "NIS2 incident notification",
        "jurisdiction": "European Union",
        "status": "current",
        "effective": "2024-10-18",
        "anchor": "awareness",
        "deadline": {"amount": 72, "unit": "hours"},
        "source_url": "https://eur-lex.europa.eu/eli/dir/2022/2555/art_23/oj",
        "source_title": "Directive (EU) 2022/2555 Article 23",
        "applicability": "Human determination of significant incident and national transposition required",
    },
    {
        "key": "nis2_final_1mo",
        "title": "NIS2 final report",
        "jurisdiction": "European Union",
        "status": "current",
        "effective": "2024-10-18",
        "anchor": "incident_notification",
        "deadline": {"amount": 1, "unit": "calendar_months"},
        "source_url": "https://eur-lex.europa.eu/eli/dir/2022/2555/art_23/oj",
        "source_title": "Directive (EU) 2022/2555 Article 23",
        "applicability": "Human determination of significant incident and national transposition required",
    },
    {
        "key": "singapore_pdpa_3d",
        "title": "Singapore PDPC breach notification",
        "jurisdiction": "Singapore",
        "status": "current",
        "effective": "2021-02-01",
        "anchor": "notifiable_determination",
        "deadline": {"amount": 3, "unit": "calendar_days"},
        "source_url": "https://www.pdpc.gov.sg/report-data-breach/before-you-report-a-data-breach-3/info",
        "source_title": "PDPC Before You Report a Data Breach",
        "applicability": "Human determination after breach assessment required",
    },
    {
        "key": "australia_ndb_assess_30d",
        "title": "Australia NDB assessment period",
        "jurisdiction": "Australia",
        "status": "current",
        "effective": "2018-02-22",
        "anchor": "reasonable_suspicion",
        "deadline": {"amount": 30, "unit": "calendar_days"},
        "source_url": "https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches",
        "source_title": "OAIC NDB quick reference guide",
        "applicability": "Human assessment of suspected eligible data breach required",
    },
    {
        "key": "australia_ndb_notice_asap",
        "title": "Australia NDB notice",
        "jurisdiction": "Australia",
        "status": "current",
        "effective": "2018-02-22",
        "anchor": "eligible_breach_determination",
        "deadline": None,
        "timing_text": "As soon as practicable after determination",
        "source_url": "https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches",
        "source_title": "OAIC NDB quick reference guide",
        "applicability": "Human eligible-data-breach determination required",
    },
    {
        "key": "canada_pipeda_asap",
        "title": "Canada PIPEDA breach report",
        "jurisdiction": "Canada",
        "status": "current",
        "effective": "2018-11-01",
        "anchor": "reportable_breach_determination",
        "deadline": None,
        "timing_text": "As soon as feasible after determination",
        "source_url": "https://www.priv.gc.ca/media/4844/pipeda_pb_form_e.pdf",
        "source_title": "PIPEDA breach report form and guidance",
        "applicability": "Human real-risk-of-significant-harm determination required",
    },
    {
        "key": "sec_8k_4bd",
        "title": "SEC Form 8-K Item 1.05 filing",
        "jurisdiction": "United States (SEC registrants)",
        "status": "current",
        "effective": "2023-12-18",
        "anchor": "materiality_determination",
        "deadline": {"amount": 4, "unit": "business_days"},
        "source_url": "https://www.sec.gov/newsroom/press-releases/2023-139",
        "source_title": "SEC cybersecurity incident disclosure rule release",
        "applicability": "Human materiality and registrant-status determination required; holiday calendar review required",
    },
    {
        "key": "hipaa_60d",
        "title": "HIPAA individual breach notice outer limit",
        "jurisdiction": "United States (HIPAA)",
        "status": "current",
        "effective": "2009-09-23",
        "anchor": "discovery",
        "deadline": {"amount": 60, "unit": "calendar_days"},
        "source_url": "https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html",
        "source_title": "HHS Breach Notification Rule guidance",
        "applicability": "Human covered-entity/business-associate and breach determination required",
    },
)

_CLOCK_KEY_RE = re.compile(r"[a-z][a-z0-9_]{2,63}\Z")


def _normalise_clock(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("regulatory clock must be an object")
    key = str(payload.get("key") or "").strip().lower()
    if not key:
        title_slug = re.sub(r"[^a-z0-9]+", "_", str(payload.get("title") or "").lower()).strip("_")
        key = f"custom_{title_slug}"[:64].rstrip("_")
    if not _CLOCK_KEY_RE.fullmatch(key):
        raise ValueError("clock key must be a lowercase slug")
    deadline = payload.get("deadline")
    deadline_kind = str(payload.get("deadline_kind") or "").strip().lower()
    deadline_seconds = payload.get("deadline_seconds")
    if "deadline" not in payload and (deadline_seconds is not None or deadline_kind == "asap"):
        if deadline_kind not in ("elapsed", "calendar", "business", "asap"):
            raise ValueError("deadline_kind is invalid")
        if deadline_kind == "asap":
            deadline = None
        else:
            if (
                not isinstance(deadline_seconds, int)
                or isinstance(deadline_seconds, bool)
                or deadline_seconds <= 0
            ):
                raise ValueError("deadline_seconds must be a positive integer")
            if deadline_kind == "elapsed":
                deadline = {"amount": deadline_seconds, "unit": "seconds"}
            else:
                if deadline_seconds % 86400:
                    raise ValueError(
                        "calendar and business deadlines must be whole multiples of 86400 seconds"
                    )
                deadline = {
                    "amount": deadline_seconds // 86400,
                    "unit": "calendar_days" if deadline_kind == "calendar" else "business_days",
                }
    if deadline is not None:
        if not isinstance(deadline, dict):
            raise ValueError("deadline must be an object or null")
        amount = deadline.get("amount")
        unit = str(deadline.get("unit") or "")
        if (
            not isinstance(amount, int)
            or isinstance(amount, bool)
            or amount <= 0
            or unit not in ("seconds", "hours", "calendar_days", "business_days", "calendar_months")
        ):
            raise ValueError("deadline amount/unit is invalid")
        deadline = {"amount": amount, "unit": unit}
    if not deadline_kind:
        if deadline is None:
            deadline_kind = "asap"
        elif deadline["unit"] == "business_days":
            deadline_kind = "business"
        elif deadline["unit"] in ("calendar_days", "calendar_months"):
            deadline_kind = "calendar"
        else:
            deadline_kind = "elapsed"
    if deadline_seconds is None and deadline is not None:
        multipliers = {"seconds": 1, "hours": 3600, "calendar_days": 86400, "business_days": 86400}
        if deadline["unit"] in multipliers:
            deadline_seconds = deadline["amount"] * multipliers[deadline["unit"]]
    return {
        "key": key,
        "title": _required(payload.get("title"), "title", 300),
        "jurisdiction": _required(payload.get("jurisdiction"), "jurisdiction", 300),
        "status": _required(payload.get("status") or "current", "status", 40),
        "effective": str(payload.get("effective") or "")[:40],
        "anchor": _required(payload.get("anchor"), "anchor", 80),
        "deadline": deadline,
        "deadline_seconds": deadline_seconds,
        "deadline_kind": deadline_kind,
        "timing_text": str(
            payload.get("timing_text")
            or (
                "As soon as required after the human anchor determination."
                if deadline is None
                else "Computed from the recorded human anchor determination."
            )
        )[:500],
        "source_url": _required(payload.get("source_url"), "source_url", 1000),
        "source_title": _required(payload.get("source_title"), "source_title", 500),
        "applicability": _required(
            payload.get("applicability")
            or "Human applicability and notification determination required",
            "applicability",
            1000,
        ),
    }


def list_regulatory_clock_packs() -> list[dict]:
    merged = {clock["key"]: dict(clock) for clock in REGULATORY_CLOCKS}
    for record in _list(_CLOCKS):
        merged[str(record["key"])] = {
            key: value for key, value in record.items() if key not in ("_audit_pending",)
        }
    return [merged[key] for key in sorted(merged)]


def upsert_regulatory_clock(
    payload: dict, *, clock_id: str = "", updated_by: str = "", expected_revision: int | None = None
) -> dict | None:
    policy = _normalise_clock(payload)
    record_id = str(clock_id or "")
    _validate_expected_revision(expected_revision, updating=bool(record_id))
    duplicate = next(
        (
            row
            for row in list_regulatory_clock_packs()
            if row.get("key") == policy["key"] and row.get("id") != record_id
        ),
        None,
    )
    if duplicate is not None:
        raise ValueError(f"regulatory clock key {policy['key']!r} already exists")
    if record_id:

        def _mutate(record: dict) -> None:
            record.update(policy)
            record["updated_at"] = time.time()
            record["updated_by"] = _actor_label(updated_by)

        return _update(
            _CLOCKS,
            "regulatory_clock",
            record_id,
            _mutate,
            expected_revision=int(expected_revision),
            action="update",
            actor=updated_by,
        )
    now = time.time()
    record = {
        "id": _CLOCKS.new_id(),
        **policy,
        "created_at": now,
        "updated_at": now,
        "updated_by": _actor_label(updated_by),
    }
    return _create(_CLOCKS, "regulatory_clock", record, "create", updated_by)


def _deadline_at(anchor_at: float, deadline: dict | None) -> float | None:
    if not deadline:
        return None
    amount = int(deadline["amount"])
    unit = deadline["unit"]
    if unit == "seconds":
        return anchor_at + amount
    if unit == "hours":
        return anchor_at + amount * 3600
    if unit == "calendar_days":
        return anchor_at + amount * 86400
    if unit == "business_days":
        current = datetime.fromtimestamp(anchor_at, tz=timezone.utc)
        remaining = amount
        while remaining:
            current = current.fromtimestamp(current.timestamp() + 86400, tz=timezone.utc)
            if current.weekday() < 5:
                remaining -= 1
        return current.timestamp()
    current = datetime.fromtimestamp(anchor_at, tz=timezone.utc)
    month_index = current.month - 1 + amount
    year = current.year + month_index // 12
    month = month_index % 12 + 1
    day = min(current.day, calendar.monthrange(year, month)[1])
    return current.replace(year=year, month=month, day=day).timestamp()


def _clock_instance(clock: dict, *, discovered_at: float) -> dict:
    return {
        **{key: value for key, value in clock.items() if key not in ("id", "revision")},
        "state": "awaiting_human_applicability",
        "anchor_at": None,
        "deadline_at": None,
        "decision": None,
        "incident_discovered_at": discovered_at,
    }


def open_incident(
    title: str,
    *,
    severity: str = "medium",
    description: str = "",
    mitre_techniques=None,
    clock_ids=None,
    custom_clocks=None,
    reported_by: str = "",
    discovered_at: float | None = None,
) -> dict:
    sev = str(severity or "medium").lower()
    if sev not in _SEVERITIES:
        raise ValueError(f"severity must be one of {_SEVERITIES}")
    discovered = float(discovered_at or time.time())
    if not math.isfinite(discovered) or discovered <= 0:
        raise ValueError("discovered_at must be a positive timestamp")
    available = {clock["key"]: clock for clock in list_regulatory_clock_packs()}
    selected = []
    for key in _bounded_list(clock_ids, limit=64, item_limit=64):
        if key not in available:
            raise ValueError(f"unknown regulatory clock {key!r}")
        selected.append(_clock_instance(available[key], discovered_at=discovered))
    for custom in list(custom_clocks or [])[:32]:
        selected.append(_clock_instance(_normalise_clock(custom), discovered_at=discovered))
    techniques = _bounded_list(mitre_techniques, limit=128, item_limit=32)
    for technique in techniques:
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique) is None:
            raise ValueError(f"invalid MITRE ATT&CK technique {technique!r}")
    now = time.time()
    record = {
        "id": _INCIDENTS.new_id(),
        "title": _required(title, "title", 300),
        "severity": sev,
        "description": str(description or "")[:8000],
        "mitre_techniques": techniques,
        "regulatory_clocks": selected,
        "timeline": [],
        "status": "open",
        "created_at": now,
        "discovered_at": discovered,
        "reported_by": _actor_label(reported_by),
        "notification_note": "Applicability and notification are human decisions; no notice is sent automatically.",
    }
    return _create(_INCIDENTS, "incident", record, "open", reported_by)


def start_incident_clock(
    incident_id: str, clock_id: str, anchor_at: float, started_by: str, expected_revision: int
) -> dict | None:
    actor = _human(started_by, "started_by")
    anchor = float(anchor_at)
    if not math.isfinite(anchor) or anchor <= 0:
        raise ValueError("anchor_at must be a positive timestamp")
    key = _required(clock_id, "clock_id", 64)

    def _mutate(record: dict) -> None:
        if record.get("status") == "closed":
            raise SecurityTransitionError("closed incident cannot start regulatory clocks")
        clock = next(
            (item for item in record.get("regulatory_clocks", []) if item.get("key") == key), None
        )
        if clock is None:
            raise ValueError("incident does not contain that regulatory clock")
        if clock.get("state") == "running":
            raise SecurityTransitionError(
                "a running regulatory clock cannot be started again; its human "
                "anchor and deadline are already recorded"
            )
        # A clock documented as not notifiable before it was ever started has
        # no anchor to overwrite; starting it is the only way a later
        # notifiable determination can be recorded.
        if (
            clock.get("state") in _RESOLVED_INCIDENT_CLOCK_STATES
            and clock.get("anchor_at") is not None
        ):
            raise SecurityTransitionError(
                "a resolved regulatory clock cannot be restarted; record a new "
                "human notification decision if the determination changes"
            )
        clock["state"] = "running"
        clock["anchor_at"] = anchor
        clock["deadline_at"] = _deadline_at(anchor, clock.get("deadline"))
        clock["started_by"] = actor
        clock["started_at"] = time.time()

    return _update(
        _INCIDENTS,
        "incident",
        incident_id,
        _mutate,
        expected_revision=expected_revision,
        action="clock_started",
        actor=started_by,
    )


def record_incident_phase(
    incident_id: str,
    phase: str,
    note: str,
    recorded_by: str,
    expected_revision: int,
    occurred_at: float | None = None,
) -> dict | None:
    step = str(phase or "").lower()
    if step not in _INCIDENT_PHASES:
        raise ValueError(f"phase must be one of {_INCIDENT_PHASES}")
    actor = _human(recorded_by, "recorded_by")
    detail = _required(note, "note", 4000)
    occurred = float(occurred_at or time.time())
    if not math.isfinite(occurred) or occurred <= 0:
        raise ValueError("occurred_at must be a positive timestamp")

    def _mutate(record: dict) -> None:
        if record.get("status") == "closed":
            raise SecurityTransitionError("closed incident cannot receive timeline events")
        timeline = list(record.get("timeline") or [])
        timeline.append(
            {
                "id": uuid.uuid4().hex[:12],
                "phase": step,
                "note": detail,
                "occurred_at": occurred,
                "recorded_by": actor,
            }
        )
        record["timeline"] = timeline[:10000]

    return _update(
        _INCIDENTS,
        "incident",
        incident_id,
        _mutate,
        expected_revision=expected_revision,
        action=f"phase_{step}",
        actor=recorded_by,
    )


def _has_ordered_incident_response(timeline: list[dict]) -> bool:
    """Return whether the timeline proves containment, eradication, then recovery."""

    phase_times: dict[str, list[float]] = {phase: [] for phase in _INCIDENT_PHASES}
    for event in timeline:
        phase = str(event.get("phase") or "")
        if phase not in phase_times:
            continue
        try:
            occurred_at = float(event.get("occurred_at"))
        except (TypeError, ValueError):
            continue
        if math.isfinite(occurred_at) and occurred_at > 0:
            phase_times[phase].append(occurred_at)

    for recovery_at in sorted(phase_times["recovery"]):
        eligible_eradications = [
            value for value in phase_times["eradication"] if value <= recovery_at
        ]
        for eradication_at in sorted(eligible_eradications, reverse=True):
            if any(value <= eradication_at for value in phase_times["containment"]):
                return True
    return False


def decide_incident_notification(
    incident_id: str,
    clock_id: str,
    notifiable: bool,
    rationale: str,
    decided_by: str,
    expected_revision: int,
) -> dict | None:
    if not isinstance(notifiable, bool):
        raise ValueError("notifiable must be a boolean")
    actor = _human(decided_by, "decided_by")
    why = _required(rationale, "rationale")
    key = _required(clock_id, "clock_id", 64)

    def _mutate(record: dict) -> None:
        if record.get("status") == "closed":
            raise SecurityTransitionError("closed incident cannot change notification decisions")
        clock = next(
            (item for item in record.get("regulatory_clocks", []) if item.get("key") == key), None
        )
        if clock is None:
            raise ValueError("incident does not contain that regulatory clock")
        if notifiable and clock.get("anchor_at") is None:
            raise SecurityTransitionError(
                "notifiable decision requires a started regulatory clock and human anchor"
            )
        clock["decision"] = {
            "notifiable": notifiable,
            "rationale": why,
            "decided_by": actor,
            "decided_at": time.time(),
        }
        clock["state"] = "notify" if notifiable else "documented_not_notifiable"

    return _update(
        _INCIDENTS,
        "incident",
        incident_id,
        _mutate,
        expected_revision=expected_revision,
        action="notification_decision",
        actor=decided_by,
    )


def close_incident(
    incident_id: str, summary: str, closed_by: str, expected_revision: int
) -> dict | None:
    actor = _human(closed_by, "closed_by")
    text = _required(summary, "summary", 4000)

    def _mutate(record: dict) -> None:
        if record.get("status") == "closed":
            raise SecurityTransitionError("closed incident cannot be closed again")
        if not _has_ordered_incident_response(list(record.get("timeline") or [])):
            raise SecurityTransitionError(
                "incident needs chronologically ordered containment, eradication, and recovery "
                "timeline entries before closure"
            )
        unresolved_clocks = [
            str(clock.get("key") or "unknown")
            for clock in record.get("regulatory_clocks", [])
            if clock.get("state") not in _RESOLVED_INCIDENT_CLOCK_STATES
        ]
        if unresolved_clocks:
            raise SecurityTransitionError(
                "regulatory clocks need a documented human notification decision "
                f"before closure: {', '.join(unresolved_clocks)}"
            )
        record["status"] = "closed"
        record["closure_summary"] = text
        record["closed_by"] = actor
        record["closed_at"] = time.time()

    return _update(
        _INCIDENTS,
        "incident",
        incident_id,
        _mutate,
        expected_revision=expected_revision,
        action="close",
        actor=closed_by,
    )


def list_incidents() -> list[dict]:
    now = time.time()
    out = []
    for stored in _list(_INCIDENTS):
        row = dict(stored)
        clocks = []
        for item in row.get("regulatory_clocks", []):
            clock = dict(item)
            deadline = clock.get("deadline_at")
            state = clock.get("state")
            if state == "running":
                measured_at = now
            elif state == "notify":
                # Nothing records when a notice was sent, so a notifiable
                # clock stays breached when the decision came after the deadline.
                measured_at = (clock.get("decision") or {}).get("decided_at")
            else:
                measured_at = None
            clock["clock_breached"] = bool(
                deadline and measured_at is not None and float(deadline) < float(measured_at)
            )
            clock["hours_left"] = int((float(deadline) - now) // 3600) if deadline else None
            clocks.append(clock)
        row["regulatory_clocks"] = clocks
        row["clock_breached"] = any(item["clock_breached"] for item in clocks)
        out.append(row)
    return out


def get_incident(incident_id: str) -> dict | None:
    return next((row for row in list_incidents() if row.get("id") == incident_id), None)


# ---------------------------------------------------------------------------
# Audit engagements, requests, tests, and findings
# ---------------------------------------------------------------------------


def _require_mutable_audit_workpapers(record: dict) -> None:
    state = str(record.get("status") or "planned")
    if state in _AUDIT_TERMINAL_STATUS:
        raise SecurityTransitionError(
            f"{state} audit engagement is read-only; move it to review before changing workpapers"
        )


def create_audit_engagement(
    name: str,
    framework: str,
    scope: str,
    owner: str,
    *,
    due_at: float | None = None,
    created_by: str = "",
    engagement_id: str = "",
) -> dict:
    due = float(due_at) if due_at is not None else None
    if due is not None and (not math.isfinite(due) or due <= 0):
        raise ValueError("due_at must be a positive timestamp")
    identifier = str(engagement_id or "").strip() or _ENGAGEMENTS.new_id()
    if re.fullmatch(r"AUD-[A-Za-z0-9_-]{1,60}", identifier) is None:
        raise ValueError("engagement_id must be a valid AUD identifier")
    now = time.time()
    record = {
        "id": identifier,
        "name": _required(name, "name", 300),
        "framework": _required(framework, "framework", 200),
        "scope": _required(scope, "scope", 4000),
        "owner": _human(owner, "owner"),
        "due_at": due,
        "status": "planned",
        "evidence_requests": [],
        "control_tests": [],
        "findings": [],
        "created_at": now,
        "updated_at": now,
        "created_by": _actor_label(created_by),
    }
    return _create(_ENGAGEMENTS, "audit_engagement", record, "create", created_by)


def add_evidence_request(
    engagement_id: str,
    description: str,
    owner: str,
    due_at: float,
    *,
    control_ids=None,
    requested_by: str = "",
    expected_revision: int,
) -> dict | None:
    request_owner = _human(owner, "owner")
    due = float(due_at)
    if not math.isfinite(due) or due <= 0:
        raise ValueError("due_at must be a positive timestamp")

    def _mutate(record: dict) -> None:
        _require_mutable_audit_workpapers(record)
        requests = list(record.get("evidence_requests") or [])
        requests.append(
            {
                "id": f"REQ-{uuid.uuid4().hex[:10]}",
                "description": _required(description, "description", 2000),
                "owner": request_owner,
                "due_at": due,
                "control_ids": _bounded_list(control_ids),
                "status": "open",
                "evidence_ids": [],
                "requested_at": time.time(),
                "requested_by": _actor_label(requested_by),
            }
        )
        record["evidence_requests"] = requests[:5000]
        record["updated_at"] = time.time()

    return _update(
        _ENGAGEMENTS,
        "audit_engagement",
        engagement_id,
        _mutate,
        expected_revision=expected_revision,
        action="evidence_request",
        actor=requested_by,
    )


def _validated_evidence_records(
    values,
    *,
    context: str,
    required: bool,
    approved: bool,
) -> tuple[list[str], dict[str, dict]]:
    evidence_ids = _bounded_list(values, limit=256, item_limit=80)
    if required and not evidence_ids:
        raise ValueError(f"{context} requires at least one cited evidence record")
    records = {evidence_id: _EVIDENCE.load(evidence_id) for evidence_id in evidence_ids}
    missing = [evidence_id for evidence_id, record in records.items() if record is None]
    if missing:
        raise ValueError(f"unknown {context} evidence ids: {missing}")
    if approved:
        unapproved = [
            evidence_id
            for evidence_id, record in records.items()
            if record is not None and record.get("status") != "approved"
        ]
        if unapproved:
            raise SecurityTransitionError(
                f"{context} requires human-approved evidence: {unapproved}"
            )
    return evidence_ids, {key: value for key, value in records.items() if value is not None}


def _update_evidence_request_unlocked(
    engagement_id: str,
    request_id: str,
    status: str,
    *,
    evidence_ids=None,
    updated_by: str = "",
    expected_revision: int,
) -> dict | None:
    state = str(status or "").lower()
    if state not in ("open", "submitted", "accepted", "rejected", "closed"):
        raise ValueError("request status is invalid")
    actor = _human(updated_by, "updated_by")

    def _mutate(record: dict) -> None:
        _require_mutable_audit_workpapers(record)
        request = next(
            (item for item in record.get("evidence_requests", []) if item.get("id") == request_id),
            None,
        )
        if request is None:
            raise ValueError("evidence request not found")
        cited, _records = _validated_evidence_records(
            evidence_ids,
            context="audit evidence request",
            required=state in {"submitted", "accepted", "closed"},
            approved=state in {"accepted", "closed"},
        )
        request["status"] = state
        request["evidence_ids"] = cited
        request["updated_at"] = time.time()
        request["updated_by"] = actor
        record["updated_at"] = time.time()

    return _update(
        _ENGAGEMENTS,
        "audit_engagement",
        engagement_id,
        _mutate,
        expected_revision=expected_revision,
        action="evidence_request_update",
        actor=updated_by,
    )


def update_evidence_request(
    engagement_id: str,
    request_id: str,
    status: str,
    *,
    evidence_ids=None,
    updated_by: str = "",
    expected_revision: int,
) -> dict | None:
    with _evidence_integrity_lock():
        return _update_evidence_request_unlocked(
            engagement_id,
            request_id,
            status,
            evidence_ids=evidence_ids,
            updated_by=updated_by,
            expected_revision=expected_revision,
        )


def _record_control_test_unlocked(
    engagement_id: str,
    control_id: str,
    procedure: str,
    result: str,
    *,
    evidence_ids=None,
    tested_by: str,
    expected_revision: int,
) -> dict | None:
    outcome = str(result or "").lower()
    if outcome not in ("pass", "fail", "needs_review"):
        raise ValueError("result must be pass, fail, or needs_review")
    tester = _human(tested_by, "tested_by")
    process = _required(procedure, "procedure", 4000)

    def _mutate(record: dict) -> None:
        _require_mutable_audit_workpapers(record)
        cited_evidence, _records = _validated_evidence_records(
            evidence_ids,
            context="control-test verdict",
            required=outcome in {"pass", "fail"},
            approved=outcome in {"pass", "fail"},
        )
        tests = list(record.get("control_tests") or [])
        tests.append(
            {
                "id": f"TST-{uuid.uuid4().hex[:10]}",
                "control_id": control_id,
                "procedure": process,
                "result": outcome,
                "evidence_ids": cited_evidence,
                "tested_by": tester,
                "tested_at": time.time(),
            }
        )
        record["control_tests"] = tests[:10000]
        record["updated_at"] = time.time()

    return _update(
        _ENGAGEMENTS,
        "audit_engagement",
        engagement_id,
        _mutate,
        expected_revision=expected_revision,
        action="control_test",
        actor=tested_by,
    )


def record_control_test(
    engagement_id: str,
    control_id: str,
    procedure: str,
    result: str,
    *,
    evidence_ids=None,
    tested_by: str,
    expected_revision: int,
) -> dict | None:
    with _evidence_integrity_lock():
        return _record_control_test_unlocked(
            engagement_id,
            control_id,
            procedure,
            result,
            evidence_ids=evidence_ids,
            tested_by=tested_by,
            expected_revision=expected_revision,
        )


def add_audit_finding(
    engagement_id: str,
    title: str,
    severity: str,
    *,
    control_ids=None,
    owner: str = "",
    due_at: float | None = None,
    created_by: str = "",
    expected_revision: int,
) -> dict | None:
    sev = str(severity or "").lower()
    if sev not in _SEVERITIES:
        raise ValueError(f"severity must be one of {_SEVERITIES}")
    due = float(due_at) if due_at is not None else None

    def _mutate(record: dict) -> None:
        _require_mutable_audit_workpapers(record)
        findings = list(record.get("findings") or [])
        findings.append(
            {
                "id": f"FND-{uuid.uuid4().hex[:10]}",
                "title": _required(title, "title", 500),
                "severity": sev,
                "control_ids": _bounded_list(control_ids),
                "owner": _actor_label(owner),
                "due_at": due,
                "status": "open",
                "created_at": time.time(),
                "created_by": _actor_label(created_by),
            }
        )
        record["findings"] = findings[:10000]
        record["updated_at"] = time.time()

    return _update(
        _ENGAGEMENTS,
        "audit_engagement",
        engagement_id,
        _mutate,
        expected_revision=expected_revision,
        action="finding",
        actor=created_by,
    )


def update_audit_finding(
    engagement_id: str, finding_id: str, status: str, updated_by: str, expected_revision: int
) -> dict | None:
    state = str(status or "").lower()
    if state not in ("open", "in_progress", "resolved", "remediated", "accepted", "closed"):
        raise ValueError("finding status is invalid")
    actor = _human(updated_by, "updated_by")

    def _mutate(record: dict) -> None:
        _require_mutable_audit_workpapers(record)
        finding = next(
            (item for item in record.get("findings", []) if item.get("id") == finding_id), None
        )
        if finding is None:
            raise ValueError("audit finding not found")
        finding["status"] = state
        finding["updated_at"] = time.time()
        finding["updated_by"] = actor
        record["updated_at"] = time.time()

    return _update(
        _ENGAGEMENTS,
        "audit_engagement",
        engagement_id,
        _mutate,
        expected_revision=expected_revision,
        action="finding_update",
        actor=updated_by,
    )


def _update_audit_engagement_status_unlocked(
    engagement_id: str, status: str, updated_by: str, expected_revision: int
) -> dict | None:
    state = str(status or "").lower()
    if state not in _AUDIT_STATUS:
        raise ValueError("engagement status is invalid")
    actor = _human(updated_by, "updated_by")

    def _mutate(record: dict) -> None:
        current = str(record.get("status") or "planned")
        if (
            current in _AUDIT_TERMINAL_STATUS
            and state not in _AUDIT_TERMINAL_TRANSITIONS[current]
        ):
            raise SecurityTransitionError(
                f"{current} audit engagement may only move to "
                f"{', '.join(sorted(_AUDIT_TERMINAL_TRANSITIONS[current]))}"
            )
        unresolved_requests = []
        for request in record.get("evidence_requests", []):
            request_state = str(request.get("status") or "open")
            if request_state not in {"accepted", "closed"}:
                unresolved_requests.append(str(request.get("id") or ""))
                continue
            try:
                _validated_evidence_records(
                    request.get("evidence_ids"),
                    context="completed audit evidence request",
                    required=True,
                    approved=True,
                )
            except (ValueError, SecurityTransitionError):
                unresolved_requests.append(str(request.get("id") or ""))
        if state in _AUDIT_TERMINAL_STATUS and unresolved_requests:
            raise SecurityTransitionError(
                "unresolved or unsupported evidence requests prevent engagement "
                f"completion or closure: {unresolved_requests[:20]}"
            )
        if state in ("complete", "closed") and any(
            finding.get("status", "open") in ("open", "in_progress")
            for finding in record.get("findings", [])
        ):
            raise SecurityTransitionError(
                "open or in-progress findings prevent engagement completion or closure"
            )
        record["status"] = state
        record["updated_at"] = time.time()
        record["updated_by"] = actor

    return _update(
        _ENGAGEMENTS,
        "audit_engagement",
        engagement_id,
        _mutate,
        expected_revision=expected_revision,
        action="status",
        actor=updated_by,
    )


def update_audit_engagement_status(
    engagement_id: str,
    status: str,
    updated_by: str,
    expected_revision: int,
) -> dict | None:
    with _evidence_integrity_lock():
        return _update_audit_engagement_status_unlocked(
            engagement_id,
            status,
            updated_by,
            expected_revision,
        )


def list_audit_engagements() -> list[dict]:
    return _list(_ENGAGEMENTS)


def get_audit_engagement(engagement_id: str) -> dict | None:
    retry_pending_audits(limit=8)
    return _ENGAGEMENTS.load(engagement_id)


# ---------------------------------------------------------------------------
# Readiness and board reporting
# ---------------------------------------------------------------------------

SECURITY_ASSESSMENT_TYPES = frozenset(
    {
        "soc2",
        "iso27001",
        "nist_csf",
        "nist_800_53",
        "cis_v8",
        "pci_dss",
        "hipaa",
        "cmmc_l2",
        "fedramp_moderate",
        "iso42001",
    }
)


def _readiness_report_unlocked(framework: str = "") -> dict:
    fw = str(framework or "").strip().lower()
    controls = statement_of_applicability(fw)
    applicable = [row for row in controls if row.get("applicable", True)]
    evidence = list_evidence()
    approved_evidence = [row for row in evidence if row.get("status") == "approved"]
    evidence_by_id = {str(row.get("id") or ""): row for row in evidence}

    def _support_intact(control: dict) -> bool:
        status = str(control.get("implementation_status") or "")
        if status not in _EVIDENCE_REQUIRED_CONTROL_STATUS:
            return True
        evidence_ids = [str(item) for item in control.get("evidence_ids", []) if str(item)]
        records = [evidence_by_id.get(evidence_id) for evidence_id in evidence_ids]
        return bool(records) and all(
            record is not None and record.get("status") == "approved"
            for record in records
        ) and any(
            record is not None and _evidence_supports_control(record, control, status)
            for record in records
        )

    support = {str(row.get("id") or ""): _support_intact(row) for row in applicable}
    implemented = [
        row
        for row in applicable
        if row.get("implementation_status") == "implemented"
        and support.get(str(row.get("id") or ""), False)
    ]
    partial = [
        row
        for row in applicable
        if row.get("implementation_status") == "partial"
        and support.get(str(row.get("id") or ""), False)
    ]
    integrity_gaps = [
        row
        for row in applicable
        if row.get("implementation_status") in _EVIDENCE_REQUIRED_CONTROL_STATUS
        and not support.get(str(row.get("id") or ""), False)
    ]
    denominator = len(applicable)
    coverage = round(100.0 * len(implemented) / denominator, 1) if denominator else 0.0
    return {
        "framework": fw or "all",
        "controls_total": len(controls),
        "controls_applicable": denominator,
        "controls_implemented": len(implemented),
        "controls_partial": len(partial),
        "coverage_percent": coverage,
        "approved_evidence": len(approved_evidence),
        "evidence_integrity_gaps": len(integrity_gaps),
        "review_gated_evidence": sum(1 for row in evidence if row.get("review_required")),
        "top_control_gaps": [
            {
                "id": row["id"],
                "canonical_id": row.get("canonical_id"),
                "title": row.get("title"),
                "status": (
                    "evidence_invalid"
                    if row in integrity_gaps
                    else row.get("implementation_status")
                ),
                "declared_status": row.get("implementation_status"),
                "owner": row.get("owner", ""),
            }
            for row in applicable
            if row not in implemented
        ][:10],
        "note": "Readiness is deterministic posture, not certification or legal advice.",
    }


def readiness_report(framework: str = "") -> dict:
    with _evidence_integrity_lock():
        return _readiness_report_unlocked(framework)


def program_report(assessment_types: set | None = None) -> dict:
    from .assessment import list_saved

    now = time.time()
    types = set(assessment_types or SECURITY_ASSESSMENT_TYPES)
    assessments = [row for row in list_saved() if row.get("type") in types]
    controls = list_controls()
    evidence = list_evidence()
    risks = list_risks()
    poams = list_poams()
    vendors = list_vendor_assessments()
    policies = list_policies()
    incidents = list_incidents()
    audits = list_audit_engagements()
    readiness = readiness_report()
    return {
        "generated_at": now,
        "assessments": {
            "total": len(assessments),
            "by_status": dict(Counter(row.get("status") for row in assessments)),
            "by_residual": dict(Counter(row.get("residual_risk") for row in assessments)),
            "review_due": sum(1 for row in assessments if row.get("review_due")),
        },
        "controls": {
            "total": len(controls),
            "by_status": dict(Counter(row.get("implementation_status") for row in controls)),
            "applicable": sum(1 for row in controls if row.get("applicable", True)),
        },
        "evidence": {
            "total": len(evidence),
            "pending_review": sum(1 for row in evidence if row.get("status") == "pending_review"),
            "approved": sum(1 for row in evidence if row.get("status") == "approved"),
        },
        "risks": {
            "total": len(risks),
            "open": sum(1 for row in risks if row.get("status") == "open"),
            "critical_high": sum(
                1
                for row in risks
                if row.get("status") == "open"
                and row.get("residual_rating") in ("critical", "high")
            ),
            "expired_exceptions": sum(1 for row in risks if row.get("exception_expired")),
        },
        "poam": {
            "total": len(poams),
            "open": sum(
                1 for row in poams if row.get("status") not in ("complete", "closed", "accepted")
            ),
            "overdue": sum(1 for row in poams if row.get("overdue")),
        },
        "vendors": {
            "total": len(vendors),
            "pending_review": sum(1 for row in vendors if row.get("status") == "pending_review"),
            "high_risk": sum(
                1 for row in vendors if row.get("residual_risk") in ("critical", "high")
            ),
        },
        "policies": {
            "total": len(policies),
            "review_due": sum(1 for row in policies if row.get("review_due")),
            "approved_or_attested": sum(
                1 for row in policies if row.get("status") in ("approved", "attested")
            ),
        },
        "incidents": {
            "total": len(incidents),
            "open": sum(1 for row in incidents if row.get("status") == "open"),
            "clock_breached": sum(1 for row in incidents if row.get("clock_breached")),
        },
        "audits": {
            "total": len(audits),
            "active": sum(1 for row in audits if row.get("status") not in ("complete", "closed")),
            "open_findings": sum(
                1
                for row in audits
                for finding in row.get("findings", [])
                if finding.get("status") in ("open", "in_progress")
            ),
        },
        "readiness": readiness,
        "top_gaps": readiness["top_control_gaps"],
    }


def render_board_report(report: dict | None = None) -> str:
    data = report or program_report()
    readiness = data["readiness"]
    lines = [
        "Security & GRC Board Readiness Report",
        "=====================================",
        f"Generated: {datetime.fromtimestamp(data['generated_at'], tz=timezone.utc).isoformat()}",
        "",
        f"Control readiness: {readiness['coverage_percent']:.1f}% "
        f"({readiness['controls_implemented']}/{readiness['controls_applicable']} applicable controls)",
        f"Open high/critical risks: {data['risks']['critical_high']}",
        f"Open / overdue POA&M: {data['poam']['open']} / {data['poam']['overdue']}",
        f"Pending evidence reviews: {data['evidence']['pending_review']}",
        f"Open incidents / breached clocks: {data['incidents']['open']} / {data['incidents']['clock_breached']}",
        "",
        "Top control gaps:",
    ]
    if not data["top_gaps"]:
        lines.append("  None recorded.")
    else:
        for item in data["top_gaps"]:
            lines.append(
                f"  - {item.get('canonical_id') or item['id']}: {item['title']} [{item['status']}]"
            )
    lines.extend(
        [
            "",
            "Readiness is a deterministic management view; it is not certification or legal advice.",
        ]
    )
    return "\n".join(lines)


__all__ = [
    "CONTROL_CATALOG",
    "REGULATORY_CLOCKS",
    "SECURITY_ASSESSMENT_TYPES",
    "RecordConflict",
    "SecurityAuditOutboxError",
    "SecurityStateError",
    "SecurityTransitionError",
    "add_audit_finding",
    "add_evidence_request",
    "apply_evidence_to_control",
    "assess_vendor",
    "attest_policy",
    "close_incident",
    "close_risk",
    "control_crosswalk",
    "create_audit_engagement",
    "create_poam",
    "create_policy",
    "decide_evidence",
    "decide_incident_notification",
    "decide_vendor_assessment",
    "enabled",
    "get_audit_engagement",
    "get_control",
    "get_evidence",
    "get_incident",
    "get_poam",
    "get_policy",
    "get_risk",
    "get_vendor_assessment",
    "grant_risk_exception",
    "initialize_control_register",
    "latest_vendor_assessment",
    "list_audit_engagements",
    "list_controls",
    "list_evidence",
    "list_incidents",
    "list_poams",
    "list_policies",
    "list_regulatory_clock_packs",
    "list_risks",
    "list_vendor_assessments",
    "map_evidence",
    "map_evidence_from_document",
    "open_incident",
    "program_report",
    "readiness_report",
    "record_control_test",
    "record_incident_phase",
    "register_risk",
    "render_board_report",
    "retry_pending_audits",
    "set_risk_treatment",
    "start_incident_clock",
    "statement_of_applicability",
    "transition_policy",
    "trigger_poam_review",
    "trigger_policy_review",
    "update_audit_engagement_status",
    "update_audit_finding",
    "update_evidence_request",
    "update_poam",
    "upsert_control",
    "upsert_regulatory_clock",
]
