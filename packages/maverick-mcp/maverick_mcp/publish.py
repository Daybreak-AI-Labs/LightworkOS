"""MCP server publishing manifest.

Generate the ``server.json`` an operator submits to publish this server to an
MCP registry (the modelcontextprotocol/registry format): the reverse-DNS
namespaced name, version, source repository, and the installable package +
transport. Tools are deliberately NOT embedded — a client discovers them at
runtime via ``tools/list`` — so the manifest stays small and never drifts from
the live tool set.

Deterministic and offline: built from the server's own ``SERVER_NAME`` /
``SERVER_VERSION`` and the package metadata, no network. ``validate`` lints a
manifest before submission; ``python -m maverick_mcp.publish`` prints it
(``--validate`` to check instead).
"""
from __future__ import annotations

import json

# Pinned to the registry schema this manifest targets; bump when adopting a
# newer registry schema revision.
SCHEMA_URL = ("https://static.modelcontextprotocol.io/schemas/"
              "2025-09-29/server.schema.json")
DEFAULT_REPO_URL = "https://github.com/Daybreak-AI-Labs/LightworkOS"
DEFAULT_MANIFEST_OWNER = "daybreak-ai-labs"
PACKAGE_NAME = "maverick-mcp-server"


def _metadata_summary() -> str:
    try:
        from importlib.metadata import metadata
        return metadata(PACKAGE_NAME).get("Summary") or _FALLBACK_DESC
    except Exception:
        return _FALLBACK_DESC


_FALLBACK_DESC = ("Model Context Protocol server for Lightwork "
                  "(exposes the swarm to MCP clients)")


def manifest_name(
    server: str,
    *,
    owner: str = DEFAULT_MANIFEST_OWNER,
) -> str:
    """Build ``io.github.<owner>/<server>`` without changing the server slug."""
    return f"io.github.{owner.strip().lower()}/{server.strip().lower()}"


def build_manifest(
    *,
    version: str | None = None,
    owner: str = DEFAULT_MANIFEST_OWNER,
    repo_url: str = DEFAULT_REPO_URL,
    description: str | None = None,
) -> dict:
    """Build the registry ``server.json`` for this MCP server."""
    from .protocol import SERVER_NAME, SERVER_VERSION
    ver = (version or SERVER_VERSION).strip()
    return {
        "$schema": SCHEMA_URL,
        "name": manifest_name(SERVER_NAME, owner=owner),
        "description": description or _metadata_summary(),
        "version": ver,
        "repository": {"url": repo_url, "source": "github"},
        "packages": [
            {
                "registryType": "pypi",
                "identifier": PACKAGE_NAME,
                "version": ver,
                "transport": {"type": "stdio"},
            }
        ],
    }


def validate(manifest: dict) -> list[str]:
    """Lint a manifest for registry submission. Returns problems ([] == OK)."""
    problems: list[str] = []
    name = manifest.get("name", "")
    if not isinstance(name, str) or "/" not in name or not name.startswith("io."):
        problems.append("name must be reverse-DNS namespaced, e.g. io.github.owner/server")
    if not (manifest.get("version") or "").strip():
        problems.append("version is required and must be non-empty")
    if not (manifest.get("description") or "").strip():
        problems.append("description is required")
    repo = manifest.get("repository") or {}
    if not (isinstance(repo, dict) and (repo.get("url") or "").strip()):
        problems.append("repository.url is required")
    packages = manifest.get("packages") or []
    if not packages:
        problems.append("at least one package (or remote) is required")
    for i, pkg in enumerate(packages):
        if not isinstance(pkg, dict):
            problems.append(f"packages[{i}] must be an object")
            continue
        if not (pkg.get("identifier") or "").strip():
            problems.append(f"packages[{i}].identifier is required")
        transport = pkg.get("transport")
        if not (isinstance(transport, dict) and transport.get("type")):
            problems.append(f"packages[{i}].transport.type is required")
    return problems


def tools_summary() -> list[str]:
    """The tool names this server publishes (informational; not in the manifest)."""
    from .catalog import TOOLS
    return sorted(t["name"] for t in TOOLS
                  if isinstance(t, dict) and t.get("name"))


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(
        prog="maverick_mcp.publish",
        description="Emit (or validate) the MCP registry server.json manifest.")
    p.add_argument("--validate", action="store_true",
                   help="validate the manifest and exit non-zero on problems")
    p.add_argument("--owner", default=DEFAULT_MANIFEST_OWNER,
                   help="GitHub owner for the reverse-DNS name")
    args = p.parse_args(argv)
    manifest = build_manifest(owner=args.owner)
    problems = validate(manifest)
    if args.validate:
        if problems:
            for prob in problems:
                print(f"INVALID: {prob}")
            return 1
        print("manifest OK")
        return 0
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


__all__ = [
    "build_manifest",
    "validate",
    "manifest_name",
    "tools_summary",
    "SCHEMA_URL",
    "DEFAULT_MANIFEST_OWNER",
    "PACKAGE_NAME",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
