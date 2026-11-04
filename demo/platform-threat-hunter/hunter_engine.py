"""Vendored defensive detector; imports nothing from Maverick.

Raw events are processed in memory and discarded. Only minimized, derived
finding evidence is eligible for the unsigned local store.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from pathlib import Path

from local_store_lock import cross_process_lock as _cross_process_lock
from request_limits import reject_raw_fields

RULES = (
    {"id": "shield-bypass", "title": "Shield bypass attempt", "technique": "T1562.001", "severity": "high", "terms": ("disable shield", "bypass shield", "ignore policy")},
    {"id": "prompt-injection", "title": "Prompt-injection marker", "technique": "T1059", "severity": "high", "terms": ("ignore previous instructions", "reveal system prompt", "developer message")},
    {"id": "unsanctioned-self-modification", "title": "Self-modification outside learning", "technique": "T1546", "severity": "critical", "terms": ("self_modify", "rewrite_agent", "mutation outside promotion")},
    {"id": "budget-anomaly", "title": "Budget or rate anomaly", "technique": "T1496", "severity": "medium", "numeric": "budget_spend", "threshold": 100.0},
)


def _excerpt(event: dict) -> str:
    text = str(event.get("message") or event.get("content") or event.get("action") or "")
    return " ".join(text.split())[:320]


def _finding(rule: dict, event: dict, reason: str) -> dict:
    source_id = str(event.get("id") or event.get("event_id") or "unknown")
    fid = hashlib.sha256(f"{rule['id']}:{source_id}:{reason}".encode()).hexdigest()[:20]
    return {"id": fid, "type": "finding", "rule_id": rule["id"], "title": rule["title"], "severity": rule["severity"], "technique": rule["technique"], "status": "open", "evidence": {"source_event_id": source_id, "kind": str(event.get("kind", "event"))[:80], "excerpt": _excerpt(event), "reason": reason}}


def detect(events: list[dict]) -> list[dict]:
    """Run deterministic rules against ephemeral platform events."""
    findings = []
    for event in events:
        haystack = json.dumps(event, sort_keys=True).lower()
        for rule in RULES:
            if "terms" in rule:
                matched = next((term for term in rule["terms"] if term in haystack), None)
                if matched:
                    findings.append(_finding(rule, event, f"matched marker: {matched}"))
            elif float(event.get(rule["numeric"], 0) or 0) >= rule["threshold"]:
                findings.append(_finding(rule, event, f"{rule['numeric']} >= {rule['threshold']:g}"))
        if event.get("kind") == "approval" and event.get("requester") == event.get("approver"):
            rule = {"id": "self-approval", "title": "Segregation-of-duties break", "technique": "T1078", "severity": "critical"}
            findings.append(_finding(rule, event, "requester and approver are identical"))
        if event.get("kind") == "tool_call" and event.get("tool_novelty", 0) >= 0.9:
            rule = {"id": "novel-tool", "title": "Novel tool use", "technique": "T1059", "severity": "medium"}
            findings.append(_finding(rule, event, "tool_novelty >= 0.9"))
        if event.get("chain_valid") is False:
            rule = {"id": "chain-integrity", "title": "Audit-chain integrity failure", "technique": "T1565.001", "severity": "critical"}
            findings.append(_finding(rule, event, "input reports chain_valid=false"))
    # Exfiltration-shaped sequence: data read followed by outbound send by actor.
    by_actor: dict[str, list[dict]] = {}
    for event in events:
        by_actor.setdefault(str(event.get("actor", "unknown")), []).append(event)
    for actor, actor_events in by_actor.items():
        read = next((e for e in actor_events if e.get("action") in {"bulk_read", "export", "secret_read"}), None)
        send = next((e for e in actor_events if e.get("action") in {"http_post", "external_email", "upload"}), None)
        if read and send:
            combined = {"id": f"{read.get('id','?')}->{send.get('id','?')}", "kind": "correlation", "message": f"{read.get('action')} followed by {send.get('action')}", "actor": actor}
            rule = {"id": "exfil-sequence", "title": "Data-exfiltration-shaped sequence", "technique": "T1041", "severity": "critical"}
            findings.append(_finding(rule, combined, "sensitive read followed by outbound transfer"))
    return list({item["id"]: item for item in findings}.values())


def open_investigation(finding: dict, analyst: str = "unassigned") -> dict:
    return {"id": f"inv-{finding['id']}", "type": "investigation", "finding_id": finding["id"], "title": finding["title"], "severity": finding["severity"], "technique": finding["technique"], "analyst": analyst, "status": "open", "suggested_response": "Review cited evidence, scope affected goals, and propose containment for human approval.", "evidence": finding["evidence"]}


def _minimized_evidence(value) -> dict:
    item = value if isinstance(value, dict) else {}
    return {
        "source_event_id": str(item.get("source_event_id", "unknown"))[:160],
        "kind": str(item.get("kind", "event"))[:80],
        "excerpt": str(item.get("excerpt", ""))[:320],
        "sha256": str(item.get("sha256", ""))[:64],
        "reason": str(item.get("reason", ""))[:500],
    }


def _minimized_record(record: dict) -> dict:
    reject_raw_fields(record)
    record_type = record.get("type")
    if record_type == "finding":
        return {
            "id": str(record.get("id", ""))[:160],
            "type": "finding",
            "rule_id": str(record.get("rule_id", ""))[:160],
            "title": str(record.get("title", ""))[:300],
            "severity": str(record.get("severity", "unknown"))[:40],
            "technique": str(record.get("technique", "unmapped"))[:80],
            "mitre_techniques": [
                str(item)[:80] for item in list(record.get("mitre_techniques") or [])[:32]
            ],
            "status": str(record.get("status", "open"))[:40],
            "score": max(0, min(100, int(record.get("score", 0) or 0))),
            "evidence": _minimized_evidence(record.get("evidence")),
            "suggested_containment": str(record.get("suggested_containment", ""))[:1000],
        }
    if record_type == "investigation":
        return {
            "id": str(record.get("id", ""))[:160],
            "type": "investigation",
            "finding_id": str(record.get("finding_id", ""))[:160],
            "title": str(record.get("title", ""))[:300],
            "severity": str(record.get("severity", "unknown"))[:40],
            "technique": str(record.get("technique", "unmapped"))[:80],
            "analyst": str(record.get("analyst", "unassigned"))[:160],
            "status": str(record.get("status", "open"))[:40],
            "suggested_response": str(record.get("suggested_response", ""))[:1000],
            "evidence": _minimized_evidence(record.get("evidence")),
        }
    raise ValueError("only derived findings and investigations may be persisted")


def _checked_revision(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("expected_revision must be a non-negative integer")
    return value


class LocalFindingStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or os.environ.get("PLATFORM_HUNTER_STORE", ".platform-hunter/findings.json"))
        self._lock = threading.RLock()

    def _read(self):
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {"revision": 0, "records": []}

    def list_records(self):
        return self._read()["records"]

    def get_finding(self, finding_id: str):
        for record in reversed(self.list_records()):
            if record.get("type") == "finding" and record.get("id") == finding_id:
                return _minimized_record(record)
        return None

    def save_derived(self, records: list[dict], expected_revision: int):
        revision = _checked_revision(expected_revision)
        with self._lock:
            with _cross_process_lock(self.path):
                return self._save_derived(records, revision)

    def _save_derived(self, records: list[dict], expected_revision: int):
        state = self._read()
        if state["revision"] != expected_revision:
            raise ValueError(f"revision changed: expected {expected_revision}, found {state['revision']}")
        for record in records:
            record = _minimized_record(record)
            if not record["id"]:
                raise ValueError("derived records require an id")
            state["revision"] += 1
            state["records"].append({**record, "revision": state["revision"]})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent, delete=False) as tmp:
            json.dump(state, tmp, indent=2, sort_keys=True)
            temp = Path(tmp.name)
        os.replace(temp, self.path)
        return state["records"][-len(records):] if records else []
