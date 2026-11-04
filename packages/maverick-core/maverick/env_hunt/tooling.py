"""Off-by-default connector factories and Maverick read-only hunt tools.

Trusted client startup code injects a transport callable after it has resolved
credentials in its own secret boundary. This module never accepts, stores, or
serializes credentials. A connector becomes available only when all three
conditions hold: the environment hunter is enabled, its explicit per-connector
knob is enabled, and a transport was registered for that connector.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from .connectors import (
    AuditRecorder,
    CloudTrailConnector,
    Connector,
    ConnectorRegistry,
    EDRConnector,
    ElasticConnector,
    EntraConnector,
    GuardDutyConnector,
    KubernetesAuditConnector,
    OktaConnector,
    ReadTransport,
    SentinelConnector,
    SplunkConnector,
    SyslogConnector,
)
from .models import QueryRequest

ConnectorFactory = Callable[[ReadTransport], Connector]

CONNECTOR_NAMES = (
    "cloudtrail",
    "guardduty",
    "syslog",
    "edr",
    "splunk",
    "elastic",
    "sentinel",
    "kubernetes_audit",
    "okta",
    "entra",
)

_BUILTIN_FACTORIES: dict[str, ConnectorFactory] = {
    "cloudtrail": CloudTrailConnector,
    "guardduty": GuardDutyConnector,
    "syslog": SyslogConnector,
    "edr": EDRConnector,
    "splunk": SplunkConnector,
    "elastic": ElasticConnector,
    "sentinel": SentinelConnector,
    "kubernetes_audit": KubernetesAuditConnector,
    "okta": OktaConnector,
    "entra": EntraConnector,
}
_CONNECTOR_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class ConnectorDisabled(PermissionError):
    pass


class ConnectorUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolQueryPolicy:
    max_limit: int = 1000
    max_window_seconds: float = 7 * 24 * 3600
    max_query_chars: int = 4096
    max_filters: int = 32

    def __post_init__(self) -> None:
        if not 1 <= self.max_limit <= 10_000:
            raise ValueError("tool query max_limit must be between 1 and 10000")
        if self.max_window_seconds <= 0 or self.max_query_chars < 1 or self.max_filters < 0:
            raise ValueError("tool query bounds must be positive")


def _root_config(config: dict[str, Any] | None) -> dict[str, Any]:
    if config is not None:
        return config if isinstance(config, dict) else {}
    try:
        from ..config import config_source_errors, load_config

        loaded = load_config()
        if config_source_errors():
            return {}
        return loaded if isinstance(loaded, dict) else {}
    except Exception:  # failure-policy: fail_closed
        return {}


def connector_enablement(
    config: dict[str, Any] | None = None,
    *,
    connector_names: tuple[str, ...] = CONNECTOR_NAMES,
) -> dict[str, bool]:
    """Resolve explicit connector knobs; absent/malformed always means off."""
    root = _root_config(config)
    section = root.get("env_hunt")
    suite_enabled = isinstance(section, dict) and section.get("enable") is True
    configured = section.get("connectors") if isinstance(section, dict) else None
    configured = configured if isinstance(configured, dict) else {}
    return {
        name: bool(
            suite_enabled
            and isinstance(configured.get(name), dict)
            and configured[name].get("enable") is True
        )
        for name in connector_names
    }


def connector_push_enablement(
    config: dict[str, Any] | None = None,
    *,
    connector_names: tuple[str, ...] = CONNECTOR_NAMES,
) -> dict[str, bool]:
    """Resolve the stronger web-push gate independently from pull access.

    Enabling a credential-owning read transport must not silently authorize an
    API caller to submit telemetry under that connector's trusted identity.
    """
    root = _root_config(config)
    section = root.get("env_hunt")
    suite_enabled = isinstance(section, dict) and section.get("enable") is True
    configured = section.get("connectors") if isinstance(section, dict) else None
    configured = configured if isinstance(configured, dict) else {}
    return {
        name: bool(
            suite_enabled
            and isinstance(configured.get(name), dict)
            and configured[name].get("enable") is True
            and configured[name].get("push_enable") is True
        )
        for name in connector_names
    }


def connector_pivot_enablement(
    config: dict[str, Any] | None = None,
    *,
    connector_names: tuple[str, ...] = CONNECTOR_NAMES,
) -> dict[str, bool]:
    """Resolve opt-in related-event pivots for registered pull transports."""
    root = _root_config(config)
    section = root.get("env_hunt")
    suite_enabled = isinstance(section, dict) and section.get("enable") is True
    configured = section.get("connectors") if isinstance(section, dict) else None
    configured = configured if isinstance(configured, dict) else {}
    return {
        name: bool(
            suite_enabled
            and isinstance(configured.get(name), dict)
            and configured[name].get("enable") is True
            and configured[name].get("pivot_enable") is True
        )
        for name in connector_names
    }


def connector_config_template() -> dict[str, Any]:
    """Installer/config-authoring shape with every named connector explicit."""
    return {
        "enable": False,
        "response_execution": False,
        "connectors": {
            name: {
                "enable": False,
                "push_enable": False,
                "pivot_enable": False,
            }
            for name in CONNECTOR_NAMES
        },
    }


class ConnectorFactoryRegistry:
    """Trusted-startup transport registry and read-only Tool factory."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        audit_recorder: AuditRecorder | None = None,
        query_policy: ToolQueryPolicy | None = None,
    ):
        self._config = _root_config(config)
        self._audit_recorder = audit_recorder
        self._query_policy = query_policy or ToolQueryPolicy()
        self._factories = dict(_BUILTIN_FACTORIES)
        self._transports: dict[str, ReadTransport] = {}

    @staticmethod
    def _name(value: str) -> str:
        name = str(value).strip().lower()
        if not _CONNECTOR_NAME_RE.fullmatch(name):
            raise ValueError("connector name must be a lowercase identifier")
        return name

    def register_factory(self, name: str, factory: ConnectorFactory) -> None:
        """Add a client-specific connector type without changing hunt engines."""
        normalized = self._name(name)
        if normalized in self._factories:
            raise ValueError(f"connector factory {normalized} is already registered")
        if not callable(factory):
            raise TypeError("connector factory must be callable")
        self._factories[normalized] = factory

    def register_transport(self, name: str, transport: ReadTransport) -> None:
        """Register a credential-owning transport closure, never credential data."""
        normalized = self._name(name)
        if normalized not in self._factories:
            raise KeyError(f"unknown connector factory {normalized}")
        if normalized in self._transports:
            raise ValueError(f"connector transport {normalized} is already registered")
        if not callable(transport):
            raise TypeError("connector transport must be callable")
        self._transports[normalized] = transport

    def enabled_names(self) -> tuple[str, ...]:
        names = tuple(sorted(self._factories))
        enablement = connector_enablement(self._config, connector_names=names)
        return tuple(name for name in names if enablement[name])

    def available_names(self) -> tuple[str, ...]:
        return tuple(name for name in self.enabled_names() if name in self._transports)

    def statuses(self) -> dict[str, dict[str, bool]]:
        names = tuple(sorted(self._factories))
        enablement = connector_enablement(self._config, connector_names=names)
        return {
            name: {
                "enabled": enablement[name],
                "registered": name in self._transports,
                "available": enablement[name] and name in self._transports,
            }
            for name in names
        }

    def build_connector(self, name: str) -> Connector:
        normalized = self._name(name)
        if normalized not in self._factories:
            raise KeyError(f"unknown connector factory {normalized}")
        if normalized not in self.enabled_names():
            raise ConnectorDisabled(f"connector {normalized} is disabled")
        transport = self._transports.get(normalized)
        if transport is None:
            raise ConnectorUnavailable(f"connector {normalized} has no registered transport")
        connector = self._factories[normalized](transport)
        if not isinstance(connector, Connector):
            raise TypeError("connector factory returned an incompatible connector")
        if connector.name.strip().lower() != normalized:
            raise ValueError("connector factory returned a mismatched name")
        return connector

    def build_connector_registry(self) -> ConnectorRegistry:
        registry = ConnectorRegistry(audit_recorder=self._audit_recorder)
        for name in self.available_names():
            registry.register(self.build_connector(name))
        return registry

    def _run_query(self, name: str, args: dict[str, Any]) -> str:
        if not isinstance(args, dict):
            raise TypeError("connector query arguments must be an object")
        allowed = {"start", "end", "query", "filters", "limit"}
        unexpected = sorted(str(key) for key in args if key not in allowed)
        if unexpected:
            raise ValueError(f"unsupported connector query fields: {', '.join(unexpected)}")
        query = str(args.get("query", "*"))
        if len(query) > self._query_policy.max_query_chars:
            raise ValueError("connector query exceeds its character limit")
        filters = args.get("filters") or {}
        if not isinstance(filters, dict):
            raise ValueError("connector query filters must be an object")
        if len(filters) > self._query_policy.max_filters:
            raise ValueError("connector query has too many filters")
        limit = args.get("limit", self._query_policy.max_limit)
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("connector query limit must be an integer")
        if not 1 <= limit <= self._query_policy.max_limit:
            raise ValueError(
                f"connector tool limit must be between 1 and {self._query_policy.max_limit}"
            )
        request = QueryRequest(
            start=args.get("start"),
            end=args.get("end"),
            query=query,
            filters=filters,
            limit=limit,
            read_only=True,
        )
        if request.end - request.start > self._query_policy.max_window_seconds:
            raise ValueError("connector query window exceeds the configured maximum")
        registry = ConnectorRegistry(audit_recorder=self._audit_recorder)
        registry.register(self.build_connector(name))
        batch = registry.ingest(name, request)
        if not batch.audited:
            raise RuntimeError("connector ingestion audit was not accepted")
        return json.dumps({
            "connector": batch.connector,
            "query_sha256": batch.query_sha256,
            "received": batch.received,
            "discarded": batch.discarded,
            "raw_persisted": batch.raw_persisted,
            "events": [asdict(event) for event in batch.events],
        }, sort_keys=True, separators=(",", ":"), default=str)

    def tools(self) -> tuple[Any, ...]:
        """Return Tool definitions only for enabled, transport-backed sources."""
        from ..tools import Tool

        properties = {
            "start": {"type": "number", "description": "Inclusive Unix timestamp"},
            "end": {"type": "number", "description": "Inclusive Unix timestamp"},
            "query": {
                "type": "string",
                "maxLength": self._query_policy.max_query_chars,
                "description": "Vendor query text; credentials are forbidden",
            },
            "filters": {
                "type": "object",
                "maxProperties": self._query_policy.max_filters,
                "description": "Non-secret equality filters",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": self._query_policy.max_limit,
            },
        }

        def build(name: str):
            def run(args: dict[str, Any]) -> str:
                return self._run_query(name, args)

            return Tool(
                name=f"env_hunt_query_{name}",
                description=(
                    f"Read bounded defensive telemetry from the registered {name} "
                    "transport. Read-only; raw telemetry is not persisted."
                ),
                input_schema={
                    "type": "object",
                    "properties": properties,
                    "required": ["start", "end"],
                    "additionalProperties": False,
                },
                fn=run,
                # A remote read may consume a client-side rate limit. Keep it
                # serial even though it has no state-changing authority.
                parallel_safe=False,
            )

        return tuple(build(name) for name in self.available_names())

    def tool_registry(self):
        from ..tools import ToolRegistry

        registry = ToolRegistry()
        for tool in self.tools():
            registry.register(tool)
        return registry


__all__ = [
    "CONNECTOR_NAMES",
    "ConnectorDisabled",
    "ConnectorFactory",
    "ConnectorFactoryRegistry",
    "ConnectorUnavailable",
    "ToolQueryPolicy",
    "connector_config_template",
    "connector_enablement",
    "connector_pivot_enablement",
    "connector_push_enablement",
]
