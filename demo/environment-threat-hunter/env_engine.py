"""Vendored environment detector with ephemeral raw-event handling.

The engine is defensive and imports nothing from Maverick. Persistence accepts
only derived findings, investigations, and response proposals.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from pathlib import Path

from local_store_lock import cross_process_lock as _cross_process_lock
from request_limits import reject_raw_fields, validate_sigma_rules


def ingest(source_type: str, payload) -> list[dict]:
    """Normalize common customer exports without persisting the payload."""
    if not isinstance(source_type, str) or not source_type.strip():
        raise ValueError("source_type must be a non-empty string")
    source = source_type.lower().replace("_", "-")
    if source in {"json", "sigma"}:
        value = json.loads(payload) if isinstance(payload, str) else payload
        return value if isinstance(value, list) else [value]
    if source == "cloudtrail":
        value = json.loads(payload) if isinstance(payload, str) else payload
        if isinstance(value, dict):
            records = value.get("Records", [])
            if not isinstance(records, list):
                raise ValueError("CloudTrail Records must be a list")
            return records
        if isinstance(value, list):
            return value
        raise ValueError("CloudTrail payload must be an object or list")
    if source in {"k8s", "kubernetes"}:
        value = json.loads(payload) if isinstance(payload, str) else payload
        if isinstance(value, dict) and "items" in value:
            items = value["items"]
            if not isinstance(items, list):
                raise ValueError("Kubernetes items must be a list")
            return items
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
        raise ValueError("Kubernetes payload must be an object or list")
    if source == "syslog":
        if isinstance(payload, str):
            lines = payload.splitlines()
        elif isinstance(payload, list) and all(isinstance(item, str) for item in payload):
            lines = payload
        else:
            raise ValueError("syslog payload must be text or a list of strings")
        return [{"id": hashlib.sha256(line.encode()).hexdigest()[:16], "kind": "syslog", "message": line} for line in lines if line.strip()]
    raise ValueError(f"unsupported source_type: {source_type}")


def _actor(event: dict) -> str:
    identity = event.get("userIdentity") or {}
    source_ips = event.get("sourceIPs") or []
    if not isinstance(identity, dict):
        identity = {}
    if not isinstance(source_ips, list):
        source_ips = []
    return str(
        event.get("actor")
        or event.get("user")
        or identity.get("arn")
        or (source_ips[0] if source_ips else "unknown")
    )


def _evidence(event: dict, reason: str) -> dict:
    event_id = str(event.get("eventID") or event.get("auditID") or event.get("id") or "unknown")
    message = str(event.get("message") or event.get("eventName") or event.get("verb") or "")
    return {"source_event_id": event_id[:160], "source_kind": str(event.get("kind") or event.get("eventSource") or "event")[:80], "excerpt": " ".join(message.split())[:400], "reason": reason}


def _finding(rule_id: str, title: str, severity: str, technique: str, event: dict, reason: str) -> dict:
    evidence = _evidence(event, reason)
    fid = hashlib.sha256(f"{rule_id}:{evidence['source_event_id']}:{reason}".encode()).hexdigest()[:20]
    return {"id": fid, "type": "finding", "rule_id": rule_id, "title": title, "severity": severity, "technique": technique, "actor": _actor(event), "status": "open", "confidence": 0.9, "evidence": evidence}


def _sigma_matches(event: dict, rule: dict) -> bool:
    """Safe deterministic subset: detection.selection exact/contains matches."""
    selection = (rule.get("detection") or {}).get("selection") or {}
    for raw_key, expected in selection.items():
        key, _, modifier = raw_key.partition("|")
        actual = event.get(key)
        candidates = expected if isinstance(expected, list) else [expected]
        if modifier == "contains":
            if not any(str(item).lower() in str(actual).lower() for item in candidates):
                return False
        elif actual not in candidates:
            return False
    return bool(selection)


def detect(events: list[dict], sigma_rules: list[dict] | None = None) -> list[dict]:
    sigma_rules = validate_sigma_rules(sigma_rules)
    findings = []
    for event in events:
        haystack = json.dumps(event, sort_keys=True).lower()
        event_name = str(event.get("eventName", ""))
        if event_name == "ConsoleLogin" and "failure" in haystack:
            findings.append(_finding("aws-console-failure", "Failed cloud console login", "medium", "T1078", event, "ConsoleLogin reports failure"))
        object_ref = event.get("objectRef") or {}
        if not isinstance(object_ref, dict):
            object_ref = {}
        request_uri = str(event.get("requestURI") or object_ref.get("subresource") or "")
        if event.get("verb") in {"create", "connect"} and ("exec" in request_uri or "portforward" in request_uri):
            findings.append(_finding("k8s-interactive-access", "Interactive Kubernetes workload access", "high", "T1609", event, f"{event.get('verb')} on {request_uri}"))
        if event.get("kind") == "syslog" and re.search(r"authentication failure|failed password|sudo:.*incorrect", haystack):
            findings.append(_finding("linux-auth-failure", "Host authentication failure", "medium", "T1110", event, "syslog authentication-failure marker"))
        bytes_out = event.get("bytes_out", 0) or 0
        if not isinstance(bytes_out, (int, float)) or isinstance(bytes_out, bool):
            raise ValueError("bytes_out must be a finite JSON number")
        if float(bytes_out) >= 100_000_000:
            findings.append(_finding("large-egress", "Large outbound transfer", "high", "T1048", event, "bytes_out >= 100000000"))
        for rule in sigma_rules or []:
            if _sigma_matches(event, rule):
                technique = str((rule.get("tags") or ["attack.unknown"])[0]).replace("attack.", "").upper()
                findings.append(_finding(f"sigma:{rule.get('id','custom')}", str(rule.get("title", "Customer Sigma match")), str(rule.get("level", "medium")), technique, event, "matched customer Sigma selection"))
    # Correlate an actor's initial-access -> persistence -> exfiltration chain.
    by_actor: dict[str, list[dict]] = {}
    for finding in findings:
        by_actor.setdefault(finding["actor"], []).append(finding)
    for actor, actor_findings in by_actor.items():
        techniques = {finding["technique"] for finding in actor_findings}
        if "T1078" in techniques and ("T1609" in techniques or "T1543" in techniques) and ({"T1048", "T1041"} & techniques):
            first = actor_findings[0]
            synthetic = {"id": "+".join(f["id"] for f in actor_findings), "kind": "correlation", "actor": actor, "message": "initial access, persistence/activity, and exfiltration signals correlated"}
            findings.append(_finding("attack-chain", "Multi-stage attack chain", "critical", "TA0042→TA0010", synthetic, f"correlated {len(actor_findings)} findings for actor; first={first['id']}"))
    return list({item["id"]: item for item in findings}.values())


def investigate(finding: dict, related_findings: list[dict] | None = None) -> dict:
    related = related_findings or []
    confidence = min(0.99, float(finding.get("confidence", 0.5)) + min(len(related), 4) * 0.02)
    return {"id": f"inv-{finding['id']}", "type": "investigation", "finding_id": finding["id"], "title": finding["title"], "status": "open", "techniques": sorted({finding.get("technique", "unknown"), *(item.get("technique", "unknown") for item in related)}), "confidence": round(confidence, 2), "timeline": [finding["evidence"], *(item["evidence"] for item in related)], "raw_events_persisted": False}


def propose_response(investigation: dict, action: str, target: str) -> dict:
    allowed = {"isolate_host", "disable_identity", "rotate_credential", "block_indicator"}
    if action not in allowed:
        raise ValueError("unsupported defensive response")
    proposal_id = f"response-{investigation['id']}-{action}"
    commitment = {
        "proposal_id": proposal_id,
        "investigation_id": investigation["id"],
        "action": action,
        "target": target,
    }
    digest = hashlib.sha256(
        json.dumps(commitment, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "id": proposal_id,
        "type": "response_proposal",
        "investigation_id": investigation["id"],
        "action": action,
        "target": target,
        "status": "proposed",
        "digest": digest,
        "warning": (
            "Proposal only. This standalone app has no response execution or "
            "approval endpoint; use Lightwork /security/soc for governed execution."
        ),
    }


def _minimized_evidence(value) -> dict:
    item = value if isinstance(value, dict) else {}
    return {
        "source_event_id": str(item.get("source_event_id", "unknown"))[:160],
        "source_kind": str(item.get("source_kind", "event"))[:80],
        "excerpt": str(item.get("excerpt", ""))[:400],
        "sha256": str(item.get("sha256", ""))[:64],
        "observed_at": float(item.get("observed_at", 0) or 0),
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
            "actor": str(record.get("actor", "unknown"))[:200],
            "status": str(record.get("status", "open"))[:40],
            "confidence": max(0.0, min(1.0, float(record.get("confidence", 0) or 0))),
            "evidence": _minimized_evidence(record.get("evidence")),
        }
    if record_type == "investigation":
        timeline = [
            _minimized_evidence(item)
            for item in list(record.get("timeline") or [])[:128]
        ]
        return {
            "id": str(record.get("id", ""))[:160],
            "type": "investigation",
            "finding_id": str(record.get("finding_id", ""))[:160],
            "title": str(record.get("title", ""))[:300],
            "status": str(record.get("status", "open"))[:40],
            "techniques": [str(item)[:80] for item in list(record.get("techniques") or [])[:64]],
            "confidence": max(0.0, min(1.0, float(record.get("confidence", 0) or 0))),
            "timeline": timeline,
            "raw_events_persisted": False,
        }
    if record_type == "response_proposal":
        return {
            "id": str(record.get("id", ""))[:200],
            "type": "response_proposal",
            "investigation_id": str(record.get("investigation_id", ""))[:160],
            "action": str(record.get("action", ""))[:80],
            "target": str(record.get("target", ""))[:500],
            "status": "proposed",
            "digest": str(record.get("digest", ""))[:64],
            "warning": str(record.get("warning", ""))[:1000],
        }
    raise ValueError("only derived findings, investigations, and response proposals may be persisted")


def _checked_revision(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("expected_revision must be a non-negative integer")
    return value


class DerivedStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or os.environ.get("ENV_HUNTER_STORE", ".environment-hunter/derived.json"))
        self._lock = threading.RLock()

    def _read(self):
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {"revision": 0, "records": []}

    def list_records(self):
        return self._read()["records"]

    def get_record(self, record_id: str, record_type: str):
        for record in reversed(self.list_records()):
            if record.get("type") == record_type and record.get("id") == record_id:
                return _minimized_record(record)
        return None

    def save(self, records: list[dict], expected_revision: int):
        revision = _checked_revision(expected_revision)
        with self._lock:
            with _cross_process_lock(self.path):
                return self._save(records, revision)

    def _save(self, records: list[dict], expected_revision: int):
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
