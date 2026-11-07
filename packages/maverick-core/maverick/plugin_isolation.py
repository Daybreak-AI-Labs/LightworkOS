"""Plugin sandboxing via subinterpreters.

Third-party plugin code currently runs in the host interpreter: a leaky or
crashing plugin tool corrupts module state, and a hostile one reads whatever
the process can. This module adds an **execution isolation seam** for plugin
tool calls with two backends:

* ``subinterpreter`` — run the call in a fresh CPython subinterpreter
  (``_xxsubinterpreters``, the PEP 554/684 substrate). Fresh module state per
  call: a plugin that mutates globals, monkey-patches stdlib, or leaks can't
  touch the host interpreter's state. Same process, though — this is *fault
  and state* isolation, not a security boundary.
* ``subprocess`` — run the call in a child Python with the secret-scrubbed
  env (``tools.scrub_child_env``). Stronger: separate address space, no host
  env secrets, survives hard crashes (a segfaulting plugin kills the child,
  not the agent). The default recommendation, and the fallback wherever the
  subinterpreter substrate is missing.

Opt-in via ``[plugins] isolation = "subprocess" | "subinterpreter"`` (env
``MAVERICK_PLUGIN_ISOLATION``); default ``"none"`` keeps today's in-process
behavior. The call contract is deliberately narrow — ``entry("pkg.mod:fn")``
called with one JSON-able dict, returning ``str`` — exactly the plugin-tool
shape, so the proxy in :mod:`maverick.plugins` can wrap discovered tools
without the plugin changing anything.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

log = logging.getLogger(__name__)

_MODES = ("none", "subprocess", "subinterpreter")
_TIMEOUT_S = 60.0


def _enterprise_default_mode() -> str:
    """The isolation default when nothing is configured: ``subprocess`` (out-of-
    process) under enterprise mode for tool calls; plugin import and factories
    still run in-process. ``none`` for single-tenant/dev."""
    try:
        from .enterprise import enterprise_enabled
        return "subprocess" if enterprise_enabled() else "none"
    except Exception as exc:
        raise RuntimeError("plugin isolation policy is unavailable") from exc


def isolation_mode() -> str:
    """Configured isolation mode.

    ``MAVERICK_PLUGIN_ISOLATION`` env wins over ``[plugins] isolation`` config.
    When neither is set the default depends on the deployment profile: enterprise
    mode defaults to ``subprocess`` (see :func:`_enterprise_default_mode`), dev to
    ``none`` (today's in-process behavior). An explicit setting always wins."""
    env = os.environ.get("MAVERICK_PLUGIN_ISOLATION")
    if env is not None:
        mode = env.strip().lower()
        if mode in _MODES:
            return mode
        raise ValueError("invalid plugin isolation mode")
    try:
        from .config import config_source_errors, load_config, single_read
        with single_read(fresh=True):
            root = load_config()
            if config_source_errors():
                raise ValueError("plugin configuration source is unreadable")
        if root is None:
            root = {}
        if not isinstance(root, dict):
            raise ValueError("invalid plugin configuration")
        config = root.get("plugins", {})
        if not isinstance(config, dict):
            raise ValueError("invalid plugin configuration")
    except Exception as exc:
        raise RuntimeError("plugin isolation policy is unavailable") from exc
    if "isolation" in config:
        mode = str(config["isolation"]).strip().lower()
        if mode in _MODES:
            return mode
        raise ValueError("invalid plugin isolation mode")
    return _enterprise_default_mode()


def _subinterpreters_available() -> bool:
    try:
        import _xxsubinterpreters  # noqa: F401
        return True
    except ImportError:
        return False


def _bootstrap_code(entry: str, args_json: str, out_path: str, *,
                    factory: bool = False, args_from_stdin: bool = False,
                    describe: bool = False) -> str:
    """Code that imports pkg.mod:fn, calls it with the args dict, and writes
    the result (or an ERROR string) to ``out_path``.

    Subinterpreters cannot receive call data through ``sys.argv`` (they inherit
    the host's argv), so that backend still bakes JSON-able control values into
    the code string. The subprocess backend must not place plugin arguments in
    ``python -c`` argv, so it sets ``args_from_stdin`` and streams args over
    stdin instead.
    """
    return textwrap.dedent("""
        import importlib, json, sys
        # The child resolves imports the way the parent could: a plugin that
        # was importable in-process stays importable under isolation.
        for _p in reversed(json.loads(%(path)s)):
            if _p and _p not in sys.path:
                sys.path.insert(0, _p)
        # Values come ONLY from baked literals or stdin: a subinterpreter
        # inherits the HOST's sys.argv (pytest's, uvicorn's, ...), and the
        # subprocess command line is visible to same-host observers, so argv
        # must not be a channel here.
        entry = %(entry)s
        if %(args_from_stdin)s:
            args = json.loads(sys.stdin.read() or "{}")
        else:
            args = json.loads(%(args)s)
        out_path = %(out)s
        try:
            mod_name, _, fn_name = entry.partition(":")
            fn = getattr(importlib.import_module(mod_name), fn_name)
            if %(describe)s:
                # Discovery: construct the Tool here and report only what the
                # host needs to build a proxy for it. Nothing callable crosses.
                tool = fn()
                result = {
                    "name": getattr(tool, "name", None),
                    "description": getattr(tool, "description", None),
                    "input_schema": getattr(tool, "input_schema", None),
                    "parallel_safe": bool(getattr(tool, "parallel_safe", False)),
                    "strict": bool(getattr(tool, "strict", False)),
                }
            elif %(factory)s:
                # Plugin-tool shape: entry is a factory() -> Tool; run tool.fn.
                result = fn().fn(args)
            else:
                result = fn(args)
            payload = result if isinstance(result, str) else json.dumps(result)
        except BaseException as e:
            payload = "ERROR: plugin call failed: %%s: %%s" %% (type(e).__name__, e)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(payload)
    """) % {
        "entry": json.dumps(entry),
        "args": json.dumps(args_json),
        "out": json.dumps(out_path),
        "path": json.dumps(json.dumps([p for p in sys.path if p])),
        "factory": "True" if factory else "False",
        "args_from_stdin": "True" if args_from_stdin else "False",
        "describe": "True" if describe else "False",
    }


_DESCRIBE_LIMIT = 256 * 1024


def describe_isolated(entry: str, *, timeout_s: float = _TIMEOUT_S) -> dict | str:
    """Construct the plugin tool at ``entry`` ("pkg.mod:factory") in a scrubbed
    child process and return its description (``name``, ``description``,
    ``input_schema``, ``parallel_safe``, ``strict``), or an ``ERROR: ...``
    string. The host never imports the module: this is how discovery stays
    out of process under ``[plugins] isolation = "subprocess"``."""
    if ":" not in entry:
        return f"ERROR: bad plugin entry {entry!r} (expected 'pkg.mod:factory')"
    from .tools import scrub_child_env
    with tempfile.TemporaryDirectory(prefix="mvk-plugin-iso-") as td:
        out_path = str(Path(td) / "result.txt")
        code = _bootstrap_code(entry, "{}", out_path, describe=True, args_from_stdin=True)
        try:
            proc = subprocess.run(
                [sys.executable, "-c", code], input="{}",
                capture_output=True, text=True, timeout=timeout_s,
                env=scrub_child_env(),
            )
        except subprocess.TimeoutExpired:
            return f"ERROR: plugin description timed out after {timeout_s:g}s"
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip()[-200:]
            return f"ERROR: plugin process exited {proc.returncode}: {tail}"
        try:
            raw = Path(out_path).read_text(encoding="utf-8")
        except OSError:
            return "ERROR: plugin produced no description"
    if raw.startswith("ERROR:"):
        return raw
    if len(raw) > _DESCRIBE_LIMIT:
        return "ERROR: plugin description is too large"
    try:
        described = json.loads(raw)
    except ValueError:
        return "ERROR: plugin description is not JSON"
    if not isinstance(described, dict):
        return "ERROR: plugin description is not an object"
    return described


def run_isolated(entry: str, args: dict, *, mode: str | None = None,
                 timeout_s: float = _TIMEOUT_S, factory: bool = False) -> str:
    """Call ``entry`` ("pkg.mod:fn") with ``args`` under the configured isolation.

    Returns the call's string result, or an ``ERROR: ...`` string — isolation
    failures degrade to an error result, never an exception into the agent
    loop. ``mode="none"`` (or unset config) imports and calls in-process.

    ``timeout_s`` is enforced by the **subprocess** backend (the call is killed
    on expiry). The **subinterpreter** backend runs ``run_string`` synchronously
    and cannot be safely interrupted, so it does NOT enforce ``timeout_s`` — use
    the subprocess backend when a hard wall-clock bound is required.
    """
    try:
        mode = isolation_mode() if mode is None else mode
        if mode not in _MODES:
            raise ValueError("invalid plugin isolation mode")
    except (RuntimeError, ValueError):
        return "ERROR: plugin isolation policy is unavailable or invalid"
    try:
        args_json = json.dumps(args or {})
    except (TypeError, ValueError):
        return "ERROR: plugin args are not JSON-serializable"

    if ":" not in entry:
        return f"ERROR: bad plugin entry {entry!r} (expected 'pkg.mod:fn')"

    if mode == "none":
        try:
            import importlib
            mod_name, _, fn_name = entry.partition(":")
            fn = getattr(importlib.import_module(mod_name), fn_name)
            target = fn().fn if factory else fn
            result = target(json.loads(args_json))
            return result if isinstance(result, str) else json.dumps(result)
        except Exception as e:
            return f"ERROR: plugin call failed: {type(e).__name__}: {e}"

    with tempfile.TemporaryDirectory(prefix="mvk-plugin-iso-") as td:
        out_path = str(Path(td) / "result.txt")

        if mode == "subinterpreter":
            if not _subinterpreters_available():
                log.warning("plugin isolation: subinterpreters unavailable on "
                            "this Python; falling back to subprocess")
                mode = "subprocess"
            else:
                if timeout_s and timeout_s != _TIMEOUT_S:
                    log.warning("plugin isolation: subinterpreter mode does not "
                                "enforce timeout_s=%.0fs (synchronous, no safe "
                                "interruption) -- use subprocess mode for a hard "
                                "timeout", timeout_s)
                import _xxsubinterpreters as si
                code = _bootstrap_code(entry, args_json, out_path, factory=factory)
                interp = si.create()
                try:
                    si.run_string(interp, code)
                except Exception as e:
                    return f"ERROR: plugin subinterpreter failed: {e}"
                finally:
                    try:
                        si.destroy(interp)
                    except Exception:  # pragma: no cover
                        pass
                try:
                    return Path(out_path).read_text(encoding="utf-8")
                except OSError:
                    return "ERROR: plugin produced no result"

        # subprocess backend (also the subinterpreter fallback path)
        from .tools import scrub_child_env
        code = _bootstrap_code(entry, "{}", out_path, factory=factory,
                               args_from_stdin=True)
        try:
            proc = subprocess.run(
                [sys.executable, "-c", code],
                input=args_json,
                capture_output=True, text=True, timeout=timeout_s,
                env=scrub_child_env(),
            )
        except subprocess.TimeoutExpired:
            return f"ERROR: plugin call timed out after {timeout_s:g}s"
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip()[-200:]
            return f"ERROR: plugin process exited {proc.returncode}: {tail}"
        try:
            return Path(out_path).read_text(encoding="utf-8")
        except OSError:
            return "ERROR: plugin produced no result"


__all__ = ["describe_isolated", "isolation_mode", "run_isolated"]
