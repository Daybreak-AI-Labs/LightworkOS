"""Authorized MCP resource projection, independent of transport routing."""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

from .protocol import ProtocolError as _ProtocolError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResourceDependencies:
    """Authorization, data and output-policy boundaries supplied by the host."""

    world_factory: Callable[[], AbstractContextManager]
    read_tools: Mapping[str, str]
    access_permits: Callable[..., bool]
    record_denial: Callable[..., None]
    connector_principal: Callable[..., str | None]
    shield_required: Callable[[], bool]
    shield_scan_reason: Callable[..., Any]


class ResourceService:
    """Project resources through explicit caller, storage and safety contracts."""

    def __init__(self, dependencies: ResourceDependencies):
        self.dependencies = dependencies

    def list(
        self,
        params: dict,
        *,
        caller_trust_principal: str | None = None,
        capability=None,
    ) -> dict:
        """Expose Lightwork state as MCP Resources.

        - maverick://goals          — list of active/recent goals
        - maverick://skills         — installed skills
        """
        resources = [
            {
                "uri": "maverick://goals",
                "name": "All recent goals",
                "mimeType": "application/json",
            },
            {
                "uri": "maverick://skills",
                "name": "Installed skills",
                "mimeType": "application/json",
            },
        ]
        return {
            "resources": [
                resource for resource in resources
                if self.dependencies.access_permits(
                    capability,
                    caller_trust_principal,
                    self.dependencies.read_tools[resource["uri"]],
                )
            ]
        }

    def read(
        self,
        params: dict,
        *,
        caller_identity: str | None = None,
        caller_trust_principal: str | None = None,
        capability=None,
    ) -> dict:
        uri = params.get("uri", "")
        # A client can send a non-string `uri` (number/list, or `null` which
        # overrides the "" default); `.startswith` then raises and escapes as a
        # scrubbed -32603 instead of the correct -32602 invalid-params -- mirror
        # the non-dict `arguments` guard in handle_tools_call.
        if not isinstance(uri, str) or not uri.startswith("maverick://"):
            raise _ProtocolError(-32602, f"unsupported uri scheme: {uri!r}")
        read_tool = self.dependencies.read_tools.get(uri)
        if read_tool is None:
            raise _ProtocolError(-32602, f"unknown resource path: {uri}")
        if not self.dependencies.access_permits(
            capability,
            caller_trust_principal,
            read_tool,
        ):
            self.dependencies.record_denial(
                capability,
                caller_identity,
                read_tool,
            )
            # Match the unknown-resource response so the hidden resource is not
            # an authorization oracle for a scoped caller.
            raise _ProtocolError(-32602, f"unknown resource path: {uri}")
        path = uri[len("maverick://"):]

        if path == "goals":
            owner = self.dependencies.connector_principal(
                caller_identity,
                caller_trust_principal,
                capability,
            )
            with self.dependencies.world_factory() as wm:
                goals = (
                    wm.list_goals(owner=owner)
                    if owner is not None else wm.list_goals()
                )
            data = [
                {"id": g.id, "status": g.status, "title": g.title}
                for g in goals[-20:]
            ]
        elif path == "skills":
            try:
                from maverick.skills import load_skills
                data = [
                    {"name": s.name, "triggers": s.triggers,
                     "tools_needed": s.tools_needed}
                    for s in load_skills()
                ]
            except Exception:
                data = []
        else:
            raise _ProtocolError(-32602, f"unknown resource path: {uri}")

        # ensure_ascii=False so the Shield scan sees the real characters, not
        # \uXXXX escapes that defeat its normalization.
        text = json.dumps(data, separators=(",", ":"), default=str, ensure_ascii=False)
        required = self.dependencies.shield_required()
        try:
            from maverick.secrets import scrub

            text = scrub(text)
        except Exception as e:
            log.error("MCP resource output scrubbing failed: %s", e)
            if required:
                raise _ProtocolError(
                    -32603,
                    "resource output blocked by safety policy",
                ) from None
        if self.dependencies.shield_scan_reason(
            text,
            output=True,
            required=required,
        ) is not None:
            # Never echo scanner reasons here: a detector may include the
            # sensitive span that caused the block, turning its denial into the
            # very resource-data leak it was meant to prevent.
            raise _ProtocolError(
                -32603,
                "resource output blocked by safety policy",
            )
        return {
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                # compact: this JSON re-enters a client LLM's context
                "text": text,
            }],
        }
