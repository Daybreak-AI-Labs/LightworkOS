"""Idempotent outbound sync of governance records into a customer GRC system.

Model-risk findings, accepted risks, and incidents become records in the
customer's system of record (ServiceNow IRM tables, Archer applications, or
any REST GRC) through the same SSRF-safe, enterprise-egress-guarded request
path every governed connector uses. The mapper is deliberately narrow:

* **Idempotent by construction.** Each (kind, source record, connector, path)
  pair owns exactly one outbound record with a stable ``GRC-`` id; a re-run
  with an unchanged source is a no-op, and a changed source becomes an update
  (PATCH) to the already-created remote record, never a duplicate create.
* **Round-trip linked.** The outbound payload carries the Lightwork record id
  as the remote ``correlation_id`` (plus an optional backlink URL), and the
  outbound ledger stores the remote id the target returned — navigable in
  both directions.
* **Fail-closed on ambiguity.** Every write is claimed before dispatch.
  Interrupted or uncertain writes stay held instead of being blindly retried
  into duplicates. A successful create without a parseable remote id lands in
  ``delivered_unconfirmed``; explicit rejections stay retryable.
* **Bounded content.** Only the source record's id, type, severity, summary,
  and content digest leave the platform. Evidence bodies, citations, and
  detail payloads never do.

The operator-invoked ``maverick grc-sync run`` (or the admin API caller) is
the human authorization boundary for a batch; every delivery is a governed
outbound record in the tenant-scoped ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

OUTBOUND_SCHEMA = "lightwork.grc-outbound-record.v1"

_STORE = GovernedRecordStore("grc_sync_outbound", "GRC", "grc_outbound_record")
_KINDS = ("finding", "risk_acceptance", "incident")
_PATH_KEYS = {
    "finding": "findings_path",
    "risk_acceptance": "acceptances_path",
    "incident": "incidents_path",
}
_REMOTE_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{4,128}\Z")
_MAX_ERROR = 500
_MAX_BATCH = 200
_HELD_STATUSES = frozenset({
    "dispatching",
    "dispatch_unconfirmed",
    "bootstrap_reauthorization_required",
})
_HELD_REASON = (
    "Delivery is in progress or its outcome is unconfirmed; review the outbound "
    "record and external system before any retry."
)


class GRCSyncError(RuntimeError):
    """Base error for the outbound GRC sync."""


class GRCSyncConfigError(GRCSyncError):
    """The [grc_sync] configuration is missing, malformed, or disabled."""


class GRCSyncStateError(GRCSyncError):
    """A sync invariant does not hold."""


def _sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _text(value: Any, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GRCSyncConfigError(f"{label} must be a non-empty string")
    out = value.strip()
    if len(out) > limit:
        raise GRCSyncConfigError(f"{label} exceeds {limit} characters")
    return out


def _bounded(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def get_grc_sync_config() -> dict[str, Any]:
    """Return the validated ``[grc_sync]`` policy, fail-closed."""

    try:
        from .config import config_source_errors, load_global_config

        errors = config_source_errors(include_tenant=False)
        root = load_global_config()
    except Exception as exc:
        raise GRCSyncConfigError("GRC sync configuration is unavailable") from exc
    if errors or not isinstance(root, Mapping):
        raise GRCSyncConfigError("GRC sync configuration is unreadable")
    raw = root.get("grc_sync") or {}
    if not isinstance(raw, Mapping):
        raise GRCSyncConfigError("grc_sync must be a table")
    known = {
        "enable",
        "connector",
        "findings_path",
        "acceptances_path",
        "incidents_path",
        "backlink_base",
        "response_field_params",
    }
    unknown = sorted(set(raw) - known)
    if unknown:
        raise GRCSyncConfigError(f"unknown grc_sync keys: {', '.join(unknown)}")
    flag = raw.get("enable", False)
    if not isinstance(flag, bool):
        raise GRCSyncConfigError("grc_sync.enable must be a boolean")
    connector = raw.get("connector", "servicenow")
    connector = _text(connector, "grc_sync.connector", 64).lower()
    if not re.fullmatch(r"[a-z0-9_]{1,64}", connector):
        raise GRCSyncConfigError("grc_sync.connector must be a lowercase token")
    paths: dict[str, str] = {}
    for kind, key in _PATH_KEYS.items():
        value = raw.get(key, "")
        if value in ("", None):
            paths[kind] = ""
            continue
        path = _text(value, f"grc_sync.{key}", 512)
        if not path.startswith("/") or ".." in path or "?" in path or "#" in path:
            raise GRCSyncConfigError(
                f"grc_sync.{key} must be an absolute, query-free path"
            )
        paths[kind] = path
    backlink = raw.get("backlink_base", "")
    if backlink not in ("", None):
        backlink = _text(backlink, "grc_sync.backlink_base", 512)
        if not backlink.lower().startswith("https://"):
            raise GRCSyncConfigError("grc_sync.backlink_base must be HTTPS")
        backlink = backlink.rstrip("/")
    else:
        backlink = ""
    response_params = raw.get("response_field_params", {})
    if not isinstance(response_params, Mapping):
        raise GRCSyncConfigError("grc_sync.response_field_params must be a table")
    bounded_params: dict[str, str] = {}
    for key, value in response_params.items():
        bounded_params[_text(key, "response field param name", 64)] = _text(
            value, "response field param value", 128,
        )
    if len(bounded_params) > 8:
        raise GRCSyncConfigError("grc_sync.response_field_params is oversized")
    return {
        "enable": flag,
        "connector": connector,
        "paths": paths,
        "backlink_base": backlink,
        "response_field_params": bounded_params,
    }


def enabled() -> bool:
    try:
        config = get_grc_sync_config()
    except Exception:
        return False
    return bool(config["enable"]) and any(config["paths"].values())


def _require_config() -> dict[str, Any]:
    config = get_grc_sync_config()
    if not config["enable"]:
        raise GRCSyncConfigError("GRC sync requires [grc_sync] enable = true")
    if not any(config["paths"].values()):
        raise GRCSyncConfigError(
            "GRC sync requires at least one of findings_path, acceptances_path, "
            "or incidents_path"
        )
    return config


def _outbound_id(kind: str, source_id: str, connector: str, path: str) -> str:
    return "GRC-" + _sha256([kind, source_id, connector, path])[:24]


def _source_rows(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Bounded projections of every source record with an enabled path."""

    from . import model_risk_assurance as mra

    rows: list[dict[str, Any]] = []
    paths = config["paths"]
    if paths["finding"] or paths["risk_acceptance"]:
        for finding in mra.findings():
            accepted = mra.current_risk_acceptance(finding) is not None
            kind = "risk_acceptance" if accepted else "finding"
            if not paths[kind]:
                continue
            rows.append(
                {
                    "kind": kind,
                    "source_id": str(finding.get("id") or ""),
                    "asset_id": str(finding.get("asset_id") or ""),
                    "severity": str(finding.get("severity") or "unknown"),
                    "summary": _bounded(finding.get("summary"), 1000),
                    "content_sha256": str(
                        finding.get("finding_sha256") or _sha256(finding)
                    ),
                }
            )
    if paths["incident"]:
        for incident in mra.list_incidents():
            rows.append(
                {
                    "kind": "incident",
                    "source_id": str(incident.get("id") or ""),
                    "asset_id": str(incident.get("asset_id") or ""),
                    "severity": str(incident.get("severity") or "unknown"),
                    "summary": _bounded(incident.get("summary"), 1000),
                    "content_sha256": str(
                        incident.get("payload_sha256") or _sha256(incident)
                    ),
                }
            )
    rows = [row for row in rows if row["source_id"]]
    if len(rows) > _MAX_BATCH * 25:
        raise GRCSyncStateError("GRC sync source volume exceeds its bound")
    rows.sort(key=lambda row: (row["kind"], row["source_id"]))
    return rows


def outbound_payload(row: Mapping[str, Any], *, backlink_base: str) -> dict[str, Any]:
    """The exact bounded body sent to the GRC system. Nothing else leaves."""

    kind = str(row["kind"]).replace("_", " ")
    payload = {
        "short_description": _bounded(
            f"[Lightwork] {str(row['severity']).upper()} {kind}: {row['summary']}",
            160,
        ),
        "description": _bounded(
            (
                f"Lightwork governed {kind} {row['source_id']} for asset "
                f"{row['asset_id']}.\nSeverity: {row['severity']}\n"
                f"Summary: {row['summary']}\n"
                f"Content digest (sha256): {row['content_sha256']}\n"
                "Evidence and detail payloads remain in Lightwork; this record "
                "is a governed pointer, not the record of truth."
            ),
            4000,
        ),
        "correlation_id": row["source_id"],
        "correlation_display": "Lightwork",
        "severity": row["severity"],
    }
    if backlink_base:
        payload["u_lightwork_url"] = f"{backlink_base}/security/assurance"
    return payload


def _default_writer(config: Mapping[str, Any]) -> Callable[..., str]:
    """A writer over the SSRF-safe, egress-guarded governed request path."""

    from .governed_rest import GOVERNED_REST_FACTORIES, RestConnector

    factory = GOVERNED_REST_FACTORIES.get(config["connector"])
    if factory is not None:
        connector = factory()
    else:
        name = config["connector"]
        connector = RestConnector(
            name=name,
            base_url_env=f"{name.upper()}_INSTANCE_URL",
            token_env=f"{name.upper()}_TOKEN",
        )
    base_url, token = connector._config()
    request_headers = connector._headers(token)

    def write(op: str, path: str, body: Mapping[str, Any]) -> str:
        from .tools._rest_connector import _rest_execute

        args: dict[str, Any] = {"body": dict(body)}
        if config["response_field_params"]:
            args["params"] = dict(config["response_field_params"])
        return _rest_execute(
            op,
            path,
            args,
            name=connector.name,
            config=lambda: (base_url, token),
            headers=lambda _token: request_headers,
            norm=connector._norm,  # noqa: SLF001
        )

    write.target_sha256 = _sha256([config, base_url])
    return write


def _default_reader(config: Mapping[str, Any]) -> Callable[..., str]:
    """Read only through the same configured, guarded connector."""
    from .governed_rest import GOVERNED_REST_FACTORIES, RestConnector

    name = config["connector"]
    factory = GOVERNED_REST_FACTORIES.get(name)
    connector = factory() if factory else RestConnector(
        name=name, base_url_env=f"{name.upper()}_INSTANCE_URL", token_env=f"{name.upper()}_TOKEN",
    )
    base_url, token = connector._config()
    request_headers = connector._headers(token)

    def read(path: str, params: dict) -> str:
        from .tools._rest_connector import _rest_execute

        return _rest_execute("get", path, {"params": params}, name=connector.name,
                             config=lambda: (base_url, token), headers=lambda _token: request_headers,
                             norm=connector._norm)

    read.target_sha256 = _sha256([config, base_url])
    return read


def _confirmed_response_text(response: object) -> str | None:
    """Unwrap explicitly successful responses without reinterpreting content.

    Legacy strings retain their original `ERROR:` convention. Explicit
    failure/unknown states never become successful merely because their
    display text looks ordinary.
    """
    from .connector_attempts import ConnectorResult
    from .tool_results import ToolOutcome, ToolResultText, tool_result_failed

    if isinstance(response, (ConnectorResult, ToolOutcome, ToolResultText)):
        if tool_result_failed(response):
            return None
        return response.content if isinstance(response, ToolOutcome) else str(response)
    if not isinstance(response, str) or response.startswith("ERROR:"):
        return None
    return response


def _remote_id_from(response: object) -> str | None:
    """Extract the created/updated remote record id, or None if unparseable."""

    response_text = _confirmed_response_text(response)
    if response_text is None:
        return None
    try:
        data = json.loads(response_text)
    except ValueError:
        return None
    if not isinstance(data, Mapping):
        return None
    result = data.get("result")
    candidates = []
    if isinstance(result, Mapping):
        candidates.extend([result.get("sys_id"), result.get("id")])
    candidates.extend([data.get("sys_id"), data.get("id")])
    for candidate in candidates:
        if isinstance(candidate, str) and _REMOTE_ID_RE.fullmatch(candidate):
            return candidate
    return None


def _response_is_uncertain(response: Any, *, op: str) -> bool:
    from .connector_attempts import ConnectorResult
    from .tool_results import ToolOutcome, ToolResultText, tool_result_failed

    if isinstance(response, ConnectorResult):
        return response.attempt.outcome_unknown
    if isinstance(response, (ToolOutcome, ToolResultText)):
        # A failed/denied mutation may still need reconciliation; explicit
        # successful data can safely contain reserved legacy text prefixes.
        return tool_result_failed(response)
    if not isinstance(response, str):
        return True
    if response.startswith("INDETERMINATE:"):
        return True
    # The shared REST adapter deliberately renders errors without upstream
    # bodies or secrets. Its transport-error strings do not prove that the
    # remote mutation failed; the response may have been lost after commit.
    if re.fullmatch(r"ERROR: [a-z0-9_]+ request failed \([^\r\n]+\)", response):
        return True
    if response == "ERROR: connector configuration or request failed (RuntimeError)":
        return True
    # A server failure after POST may still have created the record. A PATCH
    # retry targets the existing remote id, so it cannot create another one.
    return op == "post" and bool(re.match(r"ERROR: post \(5\d\d\):", response))


def _deliver_one(
    row: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    writer: Callable[..., str],
    actor: str,
) -> dict[str, Any]:
    path = config["paths"][row["kind"]]
    outbound_id = _outbound_id(
        row["kind"], row["source_id"], config["connector"], path,
    )
    payload = outbound_payload(row, backlink_base=config["backlink_base"])
    payload_sha = _sha256(payload)
    current = _STORE.get(outbound_id)
    if current is None:
        record = {
            "id": outbound_id,
            "schema": OUTBOUND_SCHEMA,
            "kind": row["kind"],
            "source_id": row["source_id"],
            "source_sha256": row["content_sha256"],
            "connector": config["connector"],
            "path": path,
            "payload_sha256": payload_sha,
            "status": "pending",
            "remote_id": None,
            "attempts": 0,
            "last_error": None,
        }
        try:
            current = _STORE.create(record, action="stage_grc_outbound", actor=actor)
        except RecordConflict:
            current = _STORE.get(outbound_id)
            if current is None:
                raise
    status = str(current.get("status"))
    unchanged = current.get("source_sha256") == row["content_sha256"]
    if status in _HELD_STATUSES:
        return dict(current)
    if status == "delivered_unconfirmed":
        return dict(current)
    if status == "delivered" and unchanged:
        return dict(current)

    if status == "delivered":
        op = "patch"
        remote = str(current.get("remote_id") or "")
        target_path = f"{path}/{remote}"
    else:
        op = "post"
        target_path = path

    def claim(value: dict[str, Any]) -> None:
        value["status"] = "dispatching"
        value["attempts"] = int(value.get("attempts") or 0) + 1
        value["last_error"] = _HELD_REASON
        # Persist the exact attempted content before the remote effect. The
        # source may change while an uncertain delivery awaits human review.
        value["dispatch"] = {
            "operation": op, "path": target_path, "payload": payload,
            "payload_sha256": payload_sha, "source_sha256": row["content_sha256"],
            "target_sha256": getattr(writer, "target_sha256", None),
        }
        value.pop("inspection", None)

    # Claim in the authoritative record *before* the remote side effect. This
    # CAS works for local and shared backends; a process-local lock would not.
    # A crashed sender remains held, without an expiring lease that could
    # recreate an already-delivered remote record after a lost response.
    current = _STORE.update(
        outbound_id, claim, expected_revision=int(current.get("revision") or 0),
        action="claim_grc_outbound", actor=actor,
    )
    if current is None:
        raise GRCSyncStateError("GRC outbound record disappeared before delivery")
    uncertain = False
    try:
        response = writer(op, target_path, payload)
        uncertain = _response_is_uncertain(response, op=op)
    except Exception as exc:  # noqa: BLE001 - every failure is recorded, bounded
        response = f"ERROR: writer failed ({type(exc).__name__})"
        uncertain = True
    response_text = _confirmed_response_text(response)
    succeeded = response_text is not None
    remote_id = _remote_id_from(response_text) if succeeded else None

    def mutate(value: dict[str, Any]) -> None:
        value["payload_sha256"] = payload_sha
        if uncertain:
            value["status"] = "dispatch_unconfirmed"
            value["last_error"] = _HELD_REASON
            return
        if not succeeded:
            value["status"] = "failed" if value.get("remote_id") is None else "delivered"
            value["last_error"] = _bounded(response, _MAX_ERROR)
            return
        value["source_sha256"] = row["content_sha256"]
        value["last_error"] = None
        if op == "patch":
            value["status"] = "delivered"
            return
        if remote_id is None:
            # The create write went through but the response gave no id:
            # terminal, never blindly re-created into a duplicate.
            value["status"] = "delivered_unconfirmed"
            return
        value["status"] = "delivered"
        value["remote_id"] = remote_id

    saved = _STORE.update(
        outbound_id,
        mutate,
        expected_revision=int(current.get("revision") or 0),
        action="deliver_grc_outbound",
        actor=actor,
    )
    if saved is None:
        raise GRCSyncStateError("GRC outbound record disappeared during delivery")
    return dict(saved)


def run_sync(
    *,
    actor: str,
    writer: Callable[..., str] | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Deliver up to ``limit`` pending/changed records; per-record isolation."""

    config = _require_config()
    operator = _text(actor, "actor", 256)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_BATCH:
        raise ValueError(f"limit must be between 1 and {_MAX_BATCH}")
    send = writer or _default_writer(config)
    delivered: list[dict[str, Any]] = []
    unchanged = 0
    failures: list[dict[str, str]] = []
    blocked: list[dict[str, str]] = []
    processed = 0
    for row in _source_rows(config):
        if processed >= limit:
            break
        before = _STORE.get(
            _outbound_id(
                row["kind"], row["source_id"], config["connector"],
                config["paths"][row["kind"]],
            )
        )
        status_before = "" if before is None else str(before.get("status"))
        same_source = (
            before is not None
            and before.get("source_sha256") == row["content_sha256"]
        )
        if status_before in _HELD_STATUSES:
            blocked.append({"source_id": row["source_id"], "reason": _HELD_REASON})
            continue
        if status_before in {"delivered", "delivered_unconfirmed"} and same_source:
            unchanged += 1
            continue
        if status_before == "delivered_unconfirmed":
            # The create went through but the remote id is unknown; an update
            # is impossible and a re-create would duplicate. Surface it.
            blocked.append(
                {
                    "source_id": row["source_id"],
                    "reason": (
                        "source changed but the remote record id is "
                        "unconfirmed; resolve the outbound record manually"
                    ),
                }
            )
            continue
        processed += 1
        try:
            outcome = _deliver_one(row, config=config, writer=send, actor=operator)
        except (GRCSyncError, RecordConflict, ValueError) as exc:
            failures.append({"source_id": row["source_id"], "reason": _bounded(exc, 256)})
            continue
        if outcome.get("status") in _HELD_STATUSES:
            blocked.append({"source_id": row["source_id"], "reason": _HELD_REASON})
        elif str(outcome.get("status")).startswith("delivered") and not outcome.get("last_error"):
            delivered.append(outcome)
        else:
            failures.append(
                {
                    "source_id": row["source_id"],
                    "reason": _bounded(outcome.get("last_error"), 256),
                }
            )
    return {
        "delivered": delivered,
        "delivered_count": len(delivered),
        "unchanged_count": unchanged,
        "blocked": blocked,
        "blocked_count": len(blocked),
        "failures": failures,
        "failure_count": len(failures),
        "limit": limit,
        "connector": config["connector"],
    }


def list_outbound(*, limit: int = 100) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    # Sort the whole store before applying the limit: a limited read returns
    # an arbitrary window, so sorting it afterwards would not give the first
    # ``limit`` rows of the promised (kind, id) order.
    rows = _STORE.list()
    rows.sort(key=lambda row: (str(row.get("kind")), str(row.get("id"))))
    rows = rows[:limit]
    return [
        {
            "id": row.get("id"),
            "kind": row.get("kind"),
            "source_id": row.get("source_id"),
            "connector": row.get("connector"),
            "path": row.get("path"),
            "status": row.get("status"),
            "remote_id": row.get("remote_id"),
            "attempts": row.get("attempts"),
            "last_error": row.get("last_error"),
            "revision": row.get("revision"),
            "reconciliation": row.get("reconciliation"),
        }
        for row in rows
    ]


def _held_delivery(record_id: str, revision: int) -> tuple[dict, dict]:
    config = _require_config()
    record = _STORE.get(record_id)
    if record is None:
        raise GRCSyncStateError("Outbound delivery was not found in this workspace.")
    if record.get("revision") != revision:
        raise RecordConflict("Delivery changed; reload it before reviewing.")
    if record.get("status") not in {*_HELD_STATUSES, "delivered_unconfirmed"}:
        raise GRCSyncStateError("Only an uncertain delivery requires reconciliation.")
    if (record.get("connector") != config["connector"]
            or record.get("path") != config["paths"].get(record.get("kind"))):
        raise GRCSyncStateError("The delivery target configuration changed; restore it before review.")
    return record, config


def _attempted_payload(record: dict, config: dict) -> tuple[dict, str]:
    dispatch = record.get("dispatch")
    if isinstance(dispatch, dict):
        payload = dispatch.get("payload")
        if not isinstance(payload, dict) or _sha256(payload) != dispatch.get("payload_sha256"):
            raise GRCSyncStateError("The recorded delivery content is unavailable or corrupt.")
        return payload, dispatch["source_sha256"]
    # Old records can be reconstructed only if the source and exact content
    # still match their original digests. A guess must never confirm a write.
    for row in _source_rows(config):
        if row["source_id"] == record["source_id"] and row["kind"] == record["kind"]:
            payload = outbound_payload(row, backlink_base=config["backlink_base"])
            if (row["content_sha256"] == record["source_sha256"]
                    and _sha256(payload) == record["payload_sha256"]):
                return payload, row["content_sha256"]
    raise GRCSyncStateError("Original delivery content is unavailable; keep the delivery held for review.")


def _remote_rows(response: object) -> list[dict]:
    response_text = _confirmed_response_text(response)
    if response_text is None:
        raise GRCSyncStateError("The external system could not verify the delivery.")
    try:
        value = json.loads(response_text)
    except (TypeError, ValueError) as exc:
        raise GRCSyncStateError("The external system returned an unreadable record.") from exc
    if isinstance(value, dict) and "result" in value:
        value = value["result"]
    rows = value if isinstance(value, list) else [value]
    if len(rows) > 2 or any(not isinstance(row, dict) for row in rows):
        raise GRCSyncStateError("The external system returned an unsupported result.")
    return rows


def _inspect_remote(record: dict, config: dict, remote_id: str | None, reader) -> dict:
    payload, source_sha = _attempted_payload(record, config)
    binding = getattr(reader, "target_sha256", _sha256(config))
    original_binding = (record.get("dispatch") or {}).get("target_sha256")
    if original_binding is not None and binding != original_binding:
        raise GRCSyncStateError("The external destination changed; restore the recorded target before review.")
    params: dict[str, Any] = {}
    path = record["path"]
    if remote_id:
        if not _REMOTE_ID_RE.fullmatch(remote_id):
            raise ValueError("Enter a valid external record ID.")
        path += "/" + remote_id
    elif config["connector"] == "servicenow":
        source_id = record["source_id"]
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", source_id):
            raise GRCSyncStateError("This record requires an explicit external record ID.")
        params = {"sysparm_query": "correlation_id=" + source_id, "sysparm_limit": "2",
                  "sysparm_display_value": "false"}
    else:
        raise ValueError("Enter the external record ID for this connector.")
    rows = _remote_rows(reader(path, params))
    matched = len(rows) == 1
    found = rows[0] if matched else {}
    actual_id = found.get("sys_id", found.get("id"))
    matched = (matched and isinstance(actual_id, str)
               and bool(_REMOTE_ID_RE.fullmatch(actual_id))
               and (not remote_id or actual_id == remote_id))
    fields = [{"name": key, "expected": value, "actual": found.get(key),
               "matches": found.get(key) == value} for key, value in payload.items()]
    matched = bool(matched and all(field["matches"] for field in fields))
    # Retain only bounded expected fields and equality flags from the external
    # response; unrelated provider fields and secrets never enter the record/UI.
    fields = [{**field, "actual": _bounded(field["actual"], 2000)} for field in fields]
    result = {
        "matched": matched, "match_count": len(rows), "remote_id": actual_id if matched else None,
        "fields": fields, "source_sha256": source_sha, "payload_sha256": _sha256(payload),
        "remote_version": _bounded(found.get("sys_updated_on", found.get("updated_at", "")), 200),
        "checked_at": time.time(), "target_sha256": binding,
        "detail": ("Exactly one external record matches the attempted delivery." if matched else
                   "No unique exact match was verified. The delivery remains held; nothing was resent."),
    }
    result["evidence_sha256"] = _sha256({key: value for key, value in result.items()
                                         if key not in {"checked_at", "detail"}})
    return result


def inspect_delivery(record_id: str, *, expected_revision: int, actor: str,
                     remote_id: str | None = None, reader=None) -> dict:
    record, config = _held_delivery(record_id, expected_revision)
    operator = _text(actor, "reviewer", 256)
    inspection = _inspect_remote(record, config, remote_id, reader or _default_reader(config))
    inspection["reviewer"] = operator

    def save(value):
        value["inspection"] = inspection

    updated = _STORE.update(record_id, save, expected_revision=expected_revision,
                            action="inspect_grc_delivery", actor=operator)
    if updated is None:
        raise GRCSyncStateError("Delivery disappeared during review; reload the workspace.")
    return {"id": record_id, "revision": updated["revision"], "inspection": inspection}


def resolve_delivery(record_id: str, *, expected_revision: int, actor: str, note: str,
                     evidence_sha256: str | None = None, reader=None) -> dict:
    record, config = _held_delivery(record_id, expected_revision)
    operator = _text(actor, "reviewer", 256)
    rationale = _text(note, "review note", 2000)
    checked = None
    if evidence_sha256 is not None:
        prior = record.get("inspection") or {}
        if (not prior.get("matched") or prior.get("evidence_sha256") != evidence_sha256
                or prior.get("reviewer") != operator
                or not 0 <= time.time() - prior.get("checked_at", 0) <= 300):
            raise GRCSyncStateError("Inspect the exact delivery again before confirming it.")
        checked = _inspect_remote(record, config, prior["remote_id"], reader or _default_reader(config))
        if not checked["matched"] or checked["evidence_sha256"] != evidence_sha256:
            raise GRCSyncStateError("The external record changed; inspect it again. Delivery remains held.")

    def resolve(value):
        value["reconciliation"] = {"reviewer": operator, "note": rationale, "at": time.time(),
                                    "decision": "verified" if checked else "kept_held",
                                    "evidence_sha256": evidence_sha256}
        if checked:
            value.update(status="delivered", remote_id=checked["remote_id"], last_error=None,
                         source_sha256=checked["source_sha256"], payload_sha256=checked["payload_sha256"])
        value.pop("inspection", None)

    updated = _STORE.update(record_id, resolve, expected_revision=expected_revision,
                            action="resolve_grc_delivery", actor=operator)
    if updated is None:
        raise GRCSyncStateError("Delivery disappeared during review; reload the workspace.")
    return {key: updated.get(key) for key in ("id", "revision", "status", "remote_id", "reconciliation")}


def sync_status() -> dict[str, Any]:
    counts = {
        "pending": 0, "delivered": 0, "delivered_unconfirmed": 0, "failed": 0,
        "dispatching": 0, "dispatch_unconfirmed": 0,
    }
    for row in _STORE.list():
        status = str(row.get("status") or "")
        if status in counts:
            counts[status] += 1
    return {"outbound": counts, "enabled": enabled()}


__all__ = [
    "GRCSyncConfigError",
    "GRCSyncError",
    "GRCSyncStateError",
    "OUTBOUND_SCHEMA",
    "enabled",
    "get_grc_sync_config",
    "list_outbound",
    "inspect_delivery",
    "resolve_delivery",
    "outbound_payload",
    "run_sync",
    "sync_status",
]
