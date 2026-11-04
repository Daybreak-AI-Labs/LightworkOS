"""`maverick plugin new` cookiecutter."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from maverick.plugin_scaffold import (
    VALID_KINDS,
    ScaffoldError,
    scaffold,
    validate_kind,
    validate_name,
)

# ---------- validation ----------

@pytest.mark.parametrize("name", ["my-tool", "abc", "weather-2", "a1b"])
def test_validate_name_ok(name):
    validate_name(name)  # no raise


@pytest.mark.parametrize("name", [
    "", "x",                # too short
    "Foo", "MY_TOOL",       # uppercase / underscore
    "-leading", "trailing-",
    "x" * 50,               # too long
    "has space",
])
def test_validate_name_rejects(name):
    with pytest.raises(ScaffoldError):
        validate_name(name)


def test_validate_kind_rejects_unknown():
    with pytest.raises(ScaffoldError, match="not supported"):
        validate_kind("mcp")  # MCP isn't a plugin kind here


@pytest.mark.parametrize("kind", VALID_KINDS)
def test_validate_kind_accepts(kind):
    validate_kind(kind)


# ---------- scaffold (tool) ----------

def test_scaffold_tool_writes_expected_files(tmp_path: Path):
    files = scaffold("my-weather", "tool", dest=tmp_path)
    base = tmp_path / "my-weather"
    expected = {
        base / "pyproject.toml",
        base / "maverick-plugin.toml",
        base / "src" / "my_weather" / "__init__.py",
        base / "src" / "my_weather" / "test_plugin.py",
        base / "README.md",
    }
    assert set(files) == expected
    for f in expected:
        assert f.exists()


def test_scaffold_tool_pyproject_wires_entry_point(tmp_path: Path):
    scaffold("my-weather", "tool", dest=tmp_path)
    pyproject = (tmp_path / "my-weather" / "pyproject.toml").read_text()
    assert 'maverick.tools' in pyproject
    assert 'my-weather = "my_weather:my_weather_tool"' in pyproject


def test_scaffold_tool_factory_returns_tool(tmp_path: Path):
    """End-to-end: the emitted code imports + the factory builds a real Tool."""
    scaffold("my-weather", "tool", dest=tmp_path)
    src = tmp_path / "my-weather" / "src"
    sys.path.insert(0, str(src))
    try:
        # Clear any previous import.
        sys.modules.pop("my_weather", None)
        import importlib
        mod = importlib.import_module("my_weather")
        from maverick.tools import Tool
        tool = mod.my_weather_tool()
        assert isinstance(tool, Tool)
        assert tool.name == "my_weather"
        # The default body is a STUB: it fails visibly (raises) rather than
        # returning placeholder output, so an un-edited generated tool can't
        # silently ship as if it works.
        with pytest.raises(NotImplementedError):
            tool.fn({"name": "Alice"})
    finally:
        sys.path.remove(str(src))
        sys.modules.pop("my_weather", None)


def test_scaffold_manifest_permissions_parse_correctly(tmp_path: Path):
    scaffold("net-tool", "tool", dest=tmp_path)
    from maverick.plugin_manifest import parse

    mf = parse(tmp_path / "net-tool" / "maverick-plugin.toml")
    assert mf is not None
    assert mf.permissions.network is True
    assert mf.permissions.fs_write is False
    assert mf.permissions.subprocess is False


# ---------- scaffold (channel + persona) ----------

def test_scaffold_channel(tmp_path: Path):
    scaffold("chat-thing", "channel", dest=tmp_path)
    body = (tmp_path / "chat-thing" / "src" / "chat_thing" / "__init__.py").read_text()
    # Must subclass the documented Channel base, not an ad-hoc class.
    assert "class ChatThingChannel(Channel)" in body
    assert "from maverick_channels import Channel" in body
    assert "async def start" in body
    assert "async def send" in body
    assert "async def stop" in body
    pyproject = (tmp_path / "chat-thing" / "pyproject.toml").read_text()
    assert 'maverick.channels' in pyproject


def test_scaffold_persona(tmp_path: Path):
    scaffold("snarky", "persona", dest=tmp_path)
    body = (tmp_path / "snarky" / "src" / "snarky" / "__init__.py").read_text()
    assert "def snarky_persona() -> str:" in body
    pyproject = (tmp_path / "snarky" / "pyproject.toml").read_text()
    assert 'maverick.personas' in pyproject


# ---------- overwrite protection ----------

def test_scaffold_refuses_to_overwrite(tmp_path: Path):
    scaffold("dup", "tool", dest=tmp_path)
    with pytest.raises(ScaffoldError, match="already exists"):
        scaffold("dup", "tool", dest=tmp_path)


# ---------- CLI integration ----------

def test_cli_plugin_new_writes_files(tmp_path: Path):
    """Drives `maverick plugin new` end-to-end via subprocess."""
    result = subprocess.run(
        [sys.executable, "-m", "maverick.cli", "plugin", "new",
         "from-cli", "--kind", "tool", "--dest", str(tmp_path)],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "from-cli" / "pyproject.toml").exists()
    assert "Scaffolded from-cli (tool)" in result.stdout


def test_cli_plugin_new_rejects_bad_name(tmp_path: Path):
    result = subprocess.run(
        [sys.executable, "-m", "maverick.cli", "plugin", "new",
         "Bad_Name", "--kind", "tool", "--dest", str(tmp_path)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert "lowercase" in result.stderr


def test_emitted_pytest_smoke_runs(tmp_path: Path):
    """The emitted test_plugin.py must actually pass when pytest runs it."""
    scaffold("hello-tool", "tool", dest=tmp_path)
    src = tmp_path / "hello-tool" / "src"
    test_file = src / "hello_tool" / "test_plugin.py"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", str(test_file)],
        capture_output=True, text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(src)},
        timeout=30,
    )
    assert result.returncode == 0, (
        f"emitted test failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )


def test_scaffolded_manifest_parses_with_repo_and_description(tmp_path: Path):
    """The generated maverick-plugin.toml must round-trip through the
    manifest parser: scaffold emitted `repository`/`summary` keys the
    parser never reads (it wants `repo`/`description`), silently dropping
    both fields."""
    from maverick.plugin_manifest import parse
    scaffold("hello-tool", "tool", dest=tmp_path)
    manifest_path = tmp_path / "hello-tool" / "maverick-plugin.toml"
    parsed = parse(manifest_path)
    assert parsed is not None
    assert parsed.repo and "hello-tool" in parsed.repo
    assert parsed.description and "tool" in parsed.description
