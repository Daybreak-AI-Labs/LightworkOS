"""Transport-injected, read-only connectors for customer security telemetry."""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Protocol, runtime_checkable

from ..audit.errors import AuditRefused
from .models import IngestionBatch, QueryRequest, TelemetryEvent, parse_timestamp

RawRow = Mapping[str, Any] | str
ReadTransport = Callable[[QueryRequest], Iterable[RawRow]]
Parser = Callable[[RawRow], TelemetryEvent]
AuditRecorder = Callable[[str, dict[str, Any]], bool]


@runtime_checkable
class Connector(Protocol):
    """The complete connector contract: one bounded, read-only fetch method."""

    name: str

    def fetch(self, request: QueryRequest) -> Iterable[TelemetryEvent]: ...


def _get(row: Mapping[str, Any], *paths: str, default: Any = "") -> Any:
    for path in paths:
        current: Any = row
        for part in path.split("."):
            if isinstance(current, Mapping) and part in current:
                current = current[part]
            elif isinstance(current, (list, tuple)) and part.isdigit() and int(part) < len(current):
                current = current[int(part)]
            else:
                current = None
                break
        if current is not None and current != "":
            return current
    return default


def _event_id(source: str, row: RawRow) -> str:
    from ..platform_hunt.models import canonical_digest

    return f"env_{canonical_digest([source, row])[:24]}"


def parse_cloudtrail(row: RawRow) -> TelemetryEvent:
    if not isinstance(row, Mapping):
        raise ValueError("CloudTrail row must be an object")
    source = "aws.cloudtrail"
    action = str(_get(row, "eventName", default="unknown"))
    return TelemetryEvent(
        event_id=str(_get(row, "eventID", "id", default=_event_id(source, row))),
        source=source,
        observed_at=parse_timestamp(_get(row, "eventTime", "timestamp", default=0)),
        category="cloud",
        action=action,
        principal=str(_get(row, "userIdentity.arn", "userIdentity.principalId", default="")),
        target=str(_get(row, "requestParameters.resource", "resources.0.ARN", default="")),
        outcome="failure" if _get(row, "errorCode", default="") else "success",
        attributes={
            "source_ip": str(_get(row, "sourceIPAddress", default="")),
            "region": str(_get(row, "awsRegion", default="")),
            "mfa": str(_get(row, "additionalEventData.MFAUsed", default="")),
            "user_agent": str(_get(row, "userAgent", default=""))[:256],
        },
    )


def parse_guardduty(row: RawRow) -> TelemetryEvent:
    if not isinstance(row, Mapping):
        raise ValueError("GuardDuty row must be an object")
    source = "aws.guardduty"
    service = _get(row, "service", default={})
    action_data = service.get("action", {}) if isinstance(service, Mapping) else {}
    return TelemetryEvent(
        event_id=str(_get(row, "id", default=_event_id(source, row))),
        source=source,
        observed_at=parse_timestamp(_get(row, "updatedAt", "createdAt", default=0)),
        category="alert",
        action=str(_get(row, "type", default="guardduty_finding")),
        principal=str(_get(row, "resource.accessKeyDetails.userName", default="")),
        target=str(_get(row, "resource.instanceDetails.instanceId", "resource.resourceType")),
        outcome="detected",
        attributes={
            "severity": _get(row, "severity", default=0),
            "action_type": str(action_data.get("actionType", "")),
        },
    )


_SYSLOG_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<program>[A-Za-z0-9_.@/-]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)


def parse_syslog(row: RawRow) -> TelemetryEvent:
    if isinstance(row, str):
        match = _SYSLOG_RE.match(row.strip())
        if not match:
            raise ValueError("syslog line has an unsupported shape")
        values = match.groupdict()
        mapping: Mapping[str, Any] = values
    elif isinstance(row, Mapping):
        mapping = row
    else:
        raise ValueError("syslog row must be text or an object")
    source = "host.syslog"
    message = str(_get(mapping, "message", "MESSAGE", default=""))
    timestamp_value = _get(mapping, "timestamp", "ts", "__REALTIME_TIMESTAMP")
    if "__REALTIME_TIMESTAMP" in mapping:
        try:
            timestamp_value = float(timestamp_value) / 1_000_000
        except (TypeError, ValueError):
            pass
    return TelemetryEvent(
        event_id=str(_get(mapping, "event_id", "__CURSOR", default=_event_id(source, row))),
        source=source,
        observed_at=parse_timestamp(timestamp_value),
        category="host",
        action=str(_get(mapping, "program", "SYSLOG_IDENTIFIER", default="syslog")),
        principal=str(_get(mapping, "user", "_UID", default="")),
        target=str(_get(mapping, "host", "_HOSTNAME", default="")),
        outcome=str(_get(mapping, "outcome", default="observed")),
        attributes={"message": message[:1024]},
    )


def parse_edr(row: RawRow) -> TelemetryEvent:
    if not isinstance(row, Mapping):
        raise ValueError("EDR/XDR row must be an object")
    source = f"edr.{str(_get(row, 'vendor', default='generic')).lower()}"
    return TelemetryEvent(
        event_id=str(_get(row, "event_id", "id", "alert_id", default=_event_id(source, row))),
        source=source,
        observed_at=parse_timestamp(_get(row, "timestamp", "observed_at", "created_at")),
        category=str(_get(row, "category", "type", default="endpoint")),
        action=str(_get(row, "action", "event_type", "name", default="endpoint_event")),
        principal=str(_get(row, "user", "principal", "username", default="")),
        target=str(_get(row, "host", "device_name", "hostname", default="")),
        outcome=str(_get(row, "outcome", "status", default="observed")),
        attributes={
            "process": str(_get(row, "process", "process_name", default="")),
            "parent_process": str(_get(row, "parent_process", default="")),
            "command_line": str(_get(row, "command_line", default=""))[:1024],
            "destination_ip": str(_get(row, "destination_ip", default="")),
            "bytes_out": _get(row, "bytes_out", default=0),
        },
    )


def parse_siem(row: RawRow) -> TelemetryEvent:
    if not isinstance(row, Mapping):
        raise ValueError("SIEM row must be an object")
    vendor = str(_get(row, "siem", "vendor", default="generic")).lower()
    source = f"siem.{vendor}"
    return TelemetryEvent(
        event_id=str(_get(row, "event_id", "_id", "id", default=_event_id(source, row))),
        source=source,
        observed_at=parse_timestamp(_get(row, "@timestamp", "TimeGenerated", "_time", "timestamp")),
        category=str(_get(row, "event.category", "category", "Type", default="siem")),
        action=str(_get(row, "event.action", "action", "OperationName", default="event")),
        principal=str(_get(row, "user.name", "principal", "UserPrincipalName", default="")),
        target=str(_get(row, "host.name", "target", "Computer", default="")),
        outcome=str(_get(row, "event.outcome", "outcome", "ResultType", default="observed")),
        attributes={
            "source_ip": str(_get(row, "source.ip", "src_ip", "IPAddress", default="")),
            "destination_ip": str(_get(row, "destination.ip", "dest_ip", default="")),
            "bytes_out": _get(row, "network.bytes_out", "bytes_out", default=0),
        },
    )


def parse_kubernetes_audit(row: RawRow) -> TelemetryEvent:
    if not isinstance(row, Mapping):
        raise ValueError("Kubernetes audit row must be an object")
    source = "kubernetes.audit"
    object_ref = _get(row, "objectRef", default={})
    if not isinstance(object_ref, Mapping):
        object_ref = {}
    target = "/".join(str(object_ref.get(key, "")) for key in ("resource", "namespace", "name"))
    return TelemetryEvent(
        event_id=str(_get(row, "auditID", default=_event_id(source, row))),
        source=source,
        observed_at=parse_timestamp(_get(row, "stageTimestamp", "requestReceivedTimestamp")),
        category="kubernetes",
        action=str(_get(row, "verb", default="unknown")),
        principal=str(_get(row, "user.username", default="")),
        target=target.strip("/"),
        outcome=str(_get(row, "responseStatus.code", "stage", default="observed")),
        attributes={
            "groups": _get(row, "user.groups", default=[]),
            "source_ip": str((_get(row, "sourceIPs", default=[""]) or [""])[0]),
        },
    )


def parse_okta(row: RawRow) -> TelemetryEvent:
    if not isinstance(row, Mapping):
        raise ValueError("Okta row must be an object")
    source = "identity.okta"
    return TelemetryEvent(
        event_id=str(_get(row, "uuid", default=_event_id(source, row))),
        source=source,
        observed_at=parse_timestamp(_get(row, "published")),
        category="identity",
        action=str(_get(row, "eventType", default="identity_event")),
        principal=str(_get(row, "actor.alternateId", "actor.id", default="")),
        target=str(_get(row, "target.0.alternateId", "target.0.id", default="")),
        outcome=str(_get(row, "outcome.result", default="observed")).lower(),
        attributes={
            "source_ip": str(_get(row, "client.ipAddress", default="")),
            "country": str(_get(row, "client.geographicalContext.country", default="")),
            "reason": str(_get(row, "outcome.reason", default=""))[:256],
        },
    )


def parse_entra(row: RawRow) -> TelemetryEvent:
    if not isinstance(row, Mapping):
        raise ValueError("Entra row must be an object")
    source = "identity.entra"
    return TelemetryEvent(
        event_id=str(_get(row, "id", default=_event_id(source, row))),
        source=source,
        observed_at=parse_timestamp(_get(row, "createdDateTime", "activityDateTime")),
        category="identity",
        action=str(_get(row, "activityDisplayName", "operationName", default="identity_event")),
        principal=str(_get(row, "initiatedBy.user.userPrincipalName", "userPrincipalName")),
        target=str(_get(row, "targetResources.0.displayName", "resourceDisplayName")),
        outcome=str(_get(row, "result", "status.errorCode", default="observed")).lower(),
        attributes={
            "source_ip": str(_get(row, "ipAddress", default="")),
            "country": str(_get(row, "location.countryOrRegion", default="")),
            "risk_level": str(_get(row, "riskLevelDuringSignIn", default="")),
        },
    )


class ReadOnlyConnector:
    name = "generic"
    parser: Parser

    def __init__(self, transport: ReadTransport, parser: Parser | None = None):
        self._transport = transport
        if parser is not None:
            self.parser = parser

    def fetch(self, request: QueryRequest) -> Iterable[TelemetryEvent]:
        if request.read_only is not True:
            raise ValueError("connector request is not read-only")
        count = 0
        for row in self._transport(request):
            if count >= request.limit:
                break
            yield self.parser(row)
            count += 1


class CloudTrailConnector(ReadOnlyConnector):
    name = "cloudtrail"
    parser = staticmethod(parse_cloudtrail)


class GuardDutyConnector(ReadOnlyConnector):
    name = "guardduty"
    parser = staticmethod(parse_guardduty)


class SyslogConnector(ReadOnlyConnector):
    name = "syslog"
    parser = staticmethod(parse_syslog)


class EDRConnector(ReadOnlyConnector):
    name = "edr"
    parser = staticmethod(parse_edr)


class SplunkConnector(ReadOnlyConnector):
    name = "splunk"
    parser = staticmethod(parse_siem)


class ElasticConnector(ReadOnlyConnector):
    name = "elastic"
    parser = staticmethod(parse_siem)


class SentinelConnector(ReadOnlyConnector):
    name = "sentinel"
    parser = staticmethod(parse_siem)


class KubernetesAuditConnector(ReadOnlyConnector):
    name = "kubernetes_audit"
    parser = staticmethod(parse_kubernetes_audit)


class OktaConnector(ReadOnlyConnector):
    name = "okta"
    parser = staticmethod(parse_okta)


class EntraConnector(ReadOnlyConnector):
    name = "entra"
    parser = staticmethod(parse_entra)


class ConnectorRegistry:
    def __init__(self, audit_recorder: AuditRecorder | None = None):
        self._connectors: dict[str, Connector] = {}
        self._audit_recorder = audit_recorder

    def register(self, connector: Connector) -> None:
        name = str(connector.name).strip().lower()
        if not name or not isinstance(connector, Connector):
            raise TypeError("connector does not implement the read-only contract")
        if name in self._connectors:
            raise ValueError(f"connector {name} is already registered")
        self._connectors[name] = connector

    def get(self, name: str) -> Connector:
        try:
            return self._connectors[name.strip().lower()]
        except KeyError as exc:
            raise KeyError(f"unknown connector {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._connectors))

    def _audit(self, payload: dict[str, Any]) -> bool:
        if self._audit_recorder is not None:
            try:
                return bool(self._audit_recorder("env_hunt_ingestion", payload))
            except AuditRefused:
                raise
            except Exception:  # failure-policy: visible_degradation
                return False
        try:
            from ..audit import record

            return bool(record("env_hunt_ingestion", **payload))
        except AuditRefused:
            raise
        except Exception:  # failure-policy: visible_degradation
            return False

    def ingest(self, name: str, request: QueryRequest) -> IngestionBatch:
        connector = self.get(name)
        events: dict[str, TelemetryEvent] = {}
        received = discarded = 0
        try:
            iterator = connector.fetch(request)
            for event in iterator:
                received += 1
                if event.observed_at < request.start or event.observed_at > request.end:
                    discarded += 1
                    continue
                if event.event_id in events:
                    discarded += 1
                    continue
                events[event.event_id] = event
        except (TypeError, ValueError):
            raise
        ordered = tuple(sorted(events.values(), key=lambda item: (item.observed_at, item.event_id)))
        audit_payload = {
            "connector": connector.name,
            "query_sha256": request.digest,
            "events_received": received,
            "events_accepted": len(ordered),
            "events_discarded": discarded,
            "raw_persisted": False,
        }
        audited = self._audit(audit_payload)
        return IngestionBatch(
            connector=connector.name,
            query_sha256=request.digest,
            events=ordered,
            received=received,
            discarded=discarded,
            audited=audited,
            raw_persisted=False,
        )


def credential_fingerprint(value: str) -> str:
    """Opaque fingerprint for operator diagnostics; never returns the credential."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


__all__ = [
    "CloudTrailConnector",
    "Connector",
    "ConnectorRegistry",
    "EDRConnector",
    "ElasticConnector",
    "EntraConnector",
    "GuardDutyConnector",
    "KubernetesAuditConnector",
    "OktaConnector",
    "ReadOnlyConnector",
    "SentinelConnector",
    "SplunkConnector",
    "SyslogConnector",
    "credential_fingerprint",
    "parse_cloudtrail",
    "parse_edr",
    "parse_entra",
    "parse_guardduty",
    "parse_kubernetes_audit",
    "parse_okta",
    "parse_siem",
    "parse_syslog",
]
