"""MCP server publishing manifest: build + validate + tools summary."""
from __future__ import annotations

from maverick_mcp import publish
from maverick_mcp.server import SERVER_VERSION


def test_manifest_name_is_reverse_dns():
    assert (
        publish.manifest_name("maverick")
        == "io.github.daybreak-ai-labs/maverick"
    )
    assert publish.manifest_name("Maverick", owner="Example-Org") == \
        "io.github.example-org/maverick"


def test_build_manifest_shape():
    m = publish.build_manifest()
    assert m["name"] == "io.github.daybreak-ai-labs/maverick"
    assert m["name"].rsplit("/", 1)[1] == "maverick"
    assert m["version"] == SERVER_VERSION
    assert m["$schema"] == publish.SCHEMA_URL
    assert m["repository"]["source"] == "github"
    pkg = m["packages"][0]
    assert pkg["identifier"] == "maverick-mcp-server"
    assert pkg["registryType"] == "pypi"
    assert pkg["transport"]["type"] == "stdio"
    assert pkg["version"] == m["version"]
    # tools are discovered at runtime, never embedded in the manifest
    assert "tools" not in m


def test_build_manifest_version_override():
    m = publish.build_manifest(version="9.9.9")
    assert m["version"] == "9.9.9" and m["packages"][0]["version"] == "9.9.9"


def test_valid_manifest_passes_validation():
    assert publish.validate(publish.build_manifest()) == []


def test_validate_flags_missing_namespace():
    m = publish.build_manifest()
    m["name"] = "maverick"  # not reverse-DNS namespaced
    problems = publish.validate(m)
    assert any("reverse-DNS" in p for p in problems)


def test_validate_flags_empty_version_and_repo_and_packages():
    bad = {"name": "io.github.x/y", "description": "d", "version": "",
           "repository": {}, "packages": []}
    problems = publish.validate(bad)
    assert any("version" in p for p in problems)
    assert any("repository.url" in p for p in problems)
    assert any("package" in p for p in problems)


def test_validate_flags_package_missing_transport():
    m = publish.build_manifest()
    m["packages"][0].pop("transport")
    assert any("transport.type" in p for p in publish.validate(m))


def test_tools_summary_lists_known_tools():
    tools = publish.tools_summary()
    assert "maverick_start" in tools
    assert tools == sorted(tools)


def test_main_emits_valid_json(capsys):
    rc = publish.main([])
    assert rc == 0
    import json
    out = json.loads(capsys.readouterr().out)
    assert out["name"] == "io.github.daybreak-ai-labs/maverick"


def test_main_validate_ok(capsys):
    rc = publish.main(["--validate"])
    assert rc == 0
    assert "manifest OK" in capsys.readouterr().out
