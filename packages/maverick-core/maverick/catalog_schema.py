"""Validate and index declarative product catalogs at their boundaries."""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Any

_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
_ENVIRONMENT_NAME = re.compile(r"[A-Z_][A-Z0-9_]*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEVERITIES = frozenset({"low", "medium", "high"})


def index_security_practices(entries: Iterable[tuple]) -> Mapping[str, tuple]:
    """Validate practice rows and return an immutable reference index."""
    index: dict[str, tuple] = {}
    for entry in entries:
        if not isinstance(entry, tuple) or len(entry) != 5:
            raise ValueError("security practice must contain five fields")
        reference, section, objective, severity, minimum_group = entry
        if any(not isinstance(value, str) or not value.strip()
               for value in (reference, section, objective)):
            raise ValueError("security practice reference, section and objective are required")
        if not isinstance(severity, str) or severity not in _SEVERITIES:
            raise ValueError(f"invalid security practice severity: {severity!r}")
        if minimum_group is not None and (
            isinstance(minimum_group, bool) or not isinstance(minimum_group, int)
            or minimum_group not in (1, 2, 3)
        ):
            raise ValueError(f"invalid security practice implementation group: {minimum_group!r}")
        if reference in index:
            raise ValueError(f"duplicate security practice reference: {reference}")
        index[reference] = entry
    return MappingProxyType(index)


def index_security_catalogs(catalogs: Mapping[str, tuple], provenance: Mapping[str, dict]) -> Mapping[str, Mapping[str, tuple]]:
    """Validate provenance and index the exact published catalog rows."""
    if set(catalogs) != set(provenance):
        raise ValueError("security catalogs and provenance must name the same frameworks")
    index: dict[str, Mapping[str, tuple]] = {}
    for name, rows in catalogs.items():
        source = provenance[name]
        if not isinstance(source, dict):
            raise ValueError(f"security catalog {name} has invalid source provenance")
        for field in ("title", "version", "source_url", "source_artifact", "source_sha256", "selection", "license"):
            if not isinstance(source.get(field), str) or not source[field].strip():
                raise ValueError(f"security catalog {name} is missing {field}")
        if not source["source_url"].startswith("https://") or not _SHA256.fullmatch(source["source_sha256"]):
            raise ValueError(f"security catalog {name} has invalid source provenance")
        index[name] = index_security_practices(rows)
    return MappingProxyType(index)


def index_connector_specs(specs: Iterable[dict[str, Any]]) -> Mapping[str, dict[str, Any]]:
    """Validate connector identity and credentials, then index by tool name."""
    index: dict[str, dict[str, Any]] = {}
    for spec in specs:
        if not isinstance(spec, dict):
            raise ValueError("connector spec must be a mapping")
        name = spec.get("name")
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError(f"invalid connector name: {name!r}")
        if name in index:
            raise ValueError(f"duplicate connector name: {name}")
        if not isinstance(spec.get("description"), str) or not spec["description"].strip():
            raise ValueError(f"connector {name} requires a description")
        for key in ("base_url_env", "token_env"):
            value = spec.get(key)
            if not isinstance(value, str) or not _ENVIRONMENT_NAME.fullmatch(value):
                raise ValueError(f"connector {name} has invalid {key}")
        if "basic" in spec and not isinstance(spec["basic"], bool):
            raise ValueError(f"connector {name} has invalid basic authentication flag")
        for key in ("scheme", "token_header"):
            if key in spec and not isinstance(spec[key], str):
                raise ValueError(f"connector {name} has invalid {key}")
        extra = spec.get("extra_headers_env", {})
        if not isinstance(extra, dict) or any(
            not isinstance(header, str) or not header.strip()
            or not isinstance(env, str) or not _ENVIRONMENT_NAME.fullmatch(env)
            for header, env in extra.items()
        ):
            raise ValueError(f"connector {name} has invalid additional credential headers")
        index[name] = spec
    return MappingProxyType(index)
