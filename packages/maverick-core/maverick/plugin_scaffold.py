"""Cookiecutter-style generator for new Lightwork plugins.

Driven by ``maverick plugin new <name> --kind tool|channel|persona``,
this writes a working plugin skeleton the contributor can `pip install
-e` and exercise immediately. The pyproject already wires the right
``[project.entry-points."maverick.<kind>"]`` block so the kernel
discovers the plugin without any manual config.

Skills are NOT a plugin kind here — they ship as standalone SKILL.md
files installed via ``maverick skill install``. MCP servers aren't a
plugin kind either — they live in ``[mcp_servers.<name>]`` in
config.toml. Only tool / channel / persona need a Python package.
"""
from __future__ import annotations

import re
from pathlib import Path

VALID_KINDS = ("tool", "channel", "persona")
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}[a-z0-9]$")


class ScaffoldError(ValueError):
    """Raised on invalid name / kind / pre-existing destination."""


def _slug_to_module(slug: str) -> str:
    """``my-weather-tool`` → ``my_weather_tool`` (PEP 8 module name)."""
    return slug.replace("-", "_")


def validate_name(name: str) -> None:
    if not _NAME_RE.match(name):
        raise ScaffoldError(
            f"plugin name {name!r} must be 3-42 chars, lowercase, "
            "dashes allowed; start with a letter, end alphanumeric"
        )


def validate_kind(kind: str) -> None:
    if kind not in VALID_KINDS:
        raise ScaffoldError(
            f"kind {kind!r} not supported; pick one of {', '.join(VALID_KINDS)}"
        )


_PYPROJECT_TMPL = '''\
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "{slug}"
version = "0.1.0"
description = "A Lightwork {kind} plugin"
requires-python = ">=3.11"
readme = "README.md"
license = {{ text = "MIT" }}
authors = [{{ name = "your name", email = "you@example.com" }}]
dependencies = []

[project.entry-points."maverick.{kind}s"]
{slug} = "{module}:{factory}"

[tool.setuptools.packages.find]
where = ["src"]
'''

_MANIFEST_TMPL = '''\
# Lightwork plugin manifest. Validated at load time against
# MAVERICK_API_VERSION; mismatches surface a warning, not a hard fail.

[plugin]
name             = "{slug}"
version          = "0.1.0"
api_version      = "2"
kind             = "{kind}"
author           = "your name"
license          = "MIT"
repo             = "https://github.com/your-org/{slug}"
description      = "A {kind} plugin for Lightwork"

[plugin.permissions]
# Declare what your plugin actually needs. The kernel refuses to load
# the plugin unless each requested permission is granted
# ([plugins] grant), while permission enforcement is on (the default).
network     = {network}
fs_write    = false
subprocess  = false
'''

_TOOL_INIT_TMPL = '''\
"""Lightwork tool plugin: {slug}.

Wire-up: ``pyproject.toml`` declares this module's ``{factory}``
function as a ``maverick.tools`` entry point. At kernel boot,
``maverick.plugins.discover_tools()`` calls it with no args and
expects a ``Tool``.
"""
from __future__ import annotations

from typing import Any

# Defer the import so `pip install -e .` doesn't fail when Lightwork
# isn't on the path yet (e.g. running unit tests in CI).
def _tool_class():
    from maverick.tools import Tool
    return Tool


def _run(args: dict[str, Any]) -> str:
    # TODO: replace this stub with the real tool body. Until you do it RAISES
    # rather than returning a fake result, so an unfinished/un-edited tool fails
    # visibly instead of silently "succeeding" with placeholder output.
    _ = (args.get("name") or "world").strip()  # example: read an arg
    raise NotImplementedError(
        "{slug}: generated tool stub is not implemented yet -- fill in _run()"
    )


_SCHEMA: dict[str, Any] = {{
    "type": "object",
    "properties": {{
        "name": {{"type": "string", "description": "Who to greet."}},
    }},
}}


def {factory}():
    return _tool_class()(
        name="{slug_under}",
        description="Demo tool from the {slug} plugin.",
        input_schema=_SCHEMA,
        fn=_run,
    )
'''

_CHANNEL_INIT_TMPL = '''\
"""Lightwork channel plugin: {slug}.

Subclass ``maverick_channels.Channel`` and implement ``start``,
``send``, ``stop``. ``pyproject.toml`` registers the *class* (not an
instance) at the ``maverick.channels`` entry point; Lightwork passes the
agent ``handler`` when it instantiates the channel per-deployment.
"""
from __future__ import annotations

from maverick_channels import Channel, Handler


class {class_name}(Channel):
    name = "{slug_under}"

    def __init__(self, handler: Handler) -> None:
        super().__init__(handler)
        # TODO: pull config from ``[channels.{slug_under}]`` in config.toml.

    async def start(self) -> None:
        # TODO: open the inbound connection (poller, webhook, websocket),
        # then dispatch each message to ``self.handler``.
        pass

    async def send(self, user_id: str, text: str) -> None:
        # TODO: deliver `text` back to `user_id` on this channel.
        raise NotImplementedError

    async def stop(self) -> None:
        # TODO: close connections, flush buffers.
        pass


# Entry-point exports the CLASS — Lightwork instantiates per-deployment.
{factory} = {class_name}
'''

_PERSONA_INIT_TMPL = '''\
"""Lightwork persona plugin: {slug}.

A persona returns a string that's appended to the orchestrator's
system prompt. Use it to shape voice + style without forking the
agent kernel.
"""
from __future__ import annotations


def {factory}() -> str:
    # TODO: replace with your persona prompt.
    return (
        "You are a friendly, plain-language assistant. "
        "Prefer short answers. Avoid jargon."
    )
'''

_TEST_TMPL = '''\
"""Smoke test for {slug}. Confirms the entry-point loads + the {kind}
factory returns the expected shape."""
from __future__ import annotations

from {module} import {factory}


def test_factory_returns_expected_kind():
    obj = {factory}{factory_call}
    # {kind_assertions}
'''

_README_TMPL = '''\
# {slug}

A Lightwork **{kind}** plugin.

## Install (development)

```bash
pip install -e .
# Then add to the kernel allowlist:
printf '[plugins]\\nenabled = ["{slug}"]\\n' >> ~/.maverick/config.toml
```

## Run the test

```bash
pip install pytest
pytest -v
```

## Publish

```bash
python -m build
python -m twine upload dist/*
```

Then publish it to a catalog index (any static host serving index.json) and
add that index under `[catalogs] indexes` so users can discover your plugin
from the dashboard's catalog tab.
'''


def _ascii_title(slug: str) -> str:
    return " ".join(p.capitalize() for p in slug.replace("_", " ").replace("-", " ").split())


def _factory_call(kind: str) -> str:
    return "()" if kind in ("tool", "persona") else "(handler=lambda msg: None)"


def _kind_assertions(kind: str) -> str:
    if kind == "tool":
        return "from maverick.tools import Tool; assert isinstance(obj, Tool)"
    if kind == "channel":
        return "from maverick_channels import Channel; assert isinstance(obj, Channel)"
    return "assert isinstance(obj, str) and obj.strip()"


def _files_for(slug: str, kind: str, base: Path) -> list[tuple[Path, str]]:
    """Compute every file the scaffold writes. Pure function: no side effects."""
    module = _slug_to_module(slug)
    factory = {
        "tool": f"{module}_tool",
        "channel": f"{module}_channel",
        "persona": f"{module}_persona",
    }[kind]
    class_name = "".join(p.capitalize() for p in module.split("_")) + "Channel"
    slug_under = module
    # Reasonable defaults: tools touch network because most do; channels too.
    needs_net = kind in ("tool", "channel")
    files: list[tuple[Path, str]] = []
    files.append((base / "pyproject.toml", _PYPROJECT_TMPL.format(
        slug=slug, kind=kind, module=module, factory=factory,
    )))
    files.append((base / "maverick-plugin.toml", _MANIFEST_TMPL.format(
        slug=slug, kind=kind, network=str(needs_net).lower(),
    )))
    body = {
        "tool": _TOOL_INIT_TMPL,
        "channel": _CHANNEL_INIT_TMPL,
        "persona": _PERSONA_INIT_TMPL,
    }[kind].format(
        slug=slug, factory=factory, slug_under=slug_under,
        class_name=class_name,
    )
    files.append((base / "src" / module / "__init__.py", body))
    files.append((base / "src" / module / "test_plugin.py", _TEST_TMPL.format(
        slug=slug, module=module, factory=factory, kind=kind,
        factory_call=_factory_call(kind),
        kind_assertions=_kind_assertions(kind),
    )))
    files.append((base / "README.md", _README_TMPL.format(slug=slug, kind=kind)))
    return files


def scaffold(name: str, kind: str, *, dest: Path) -> list[Path]:
    """Write the scaffold for ``name`` (a ``kind`` plugin) under ``dest``.

    ``dest`` is the parent directory; the function creates
    ``dest/<name>/`` and refuses to overwrite if it already exists.
    Returns the list of files written.
    """
    validate_name(name)
    validate_kind(kind)
    base = dest / name
    if base.exists():
        raise ScaffoldError(f"{base} already exists; refusing to overwrite")
    files = _files_for(name, kind, base)
    written: list[Path] = []
    for path, body in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        written.append(path)
    return written


__all__ = ["scaffold", "validate_name", "validate_kind", "VALID_KINDS", "ScaffoldError"]
