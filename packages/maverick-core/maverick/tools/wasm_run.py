"""WASM sandbox tool.

Run a WebAssembly/WASI module under the **wasmtime** runtime — the strongest
practical isolation for running an untrusted compute artifact: no ambient
filesystem, no network, no host syscalls beyond what is explicitly granted.
A capability-grant model native to WASI: the module sees ONLY the directories
preopened via ``dirs`` and the env/args passed here.

Auth: each run requires fresh human approval. Requires the ``wasmtime`` binary on PATH
(https://wasmtime.dev — single static binary).

ops:
  - run(module, args, dirs, env, stdin, timeout)  — execute a .wasm/.wat module
  - version()                                     — runtime version

All shell goes through the sandbox chokepoint (CLAUDE.md #4); the module
path and any preopened dirs are confined to the sandbox workdir, and env
vars are passed explicitly (never the host environment).
"""
from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import Any

from ..approval_cards import ApprovalCardError
from ..safety import ConsentDenied, consume_operation_consent
from . import Tool
from .execution_consent import execution_target, file_version, request_execution_consent

log = logging.getLogger(__name__)

_WASM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["run", "version"]},
        "module": {"type": "string", "description": ".wasm/.wat path (in workdir)"},
        "args": {"type": "array", "items": {"type": "string"},
                 "description": "argv passed to the module"},
        "dirs": {"type": "array", "items": {"type": "string"},
                 "description": "workdir-relative dirs to preopen (WASI grants)"},
        "env": {"type": "object",
                "description": "explicit KEY: value env for the module"},
        "stdin": {"type": "string"},
        "timeout": {"type": "integer", "description": "seconds (default 60)"},
    },
    "required": ["op"],
}

_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _need_wasmtime() -> str | None:
    if shutil.which("wasmtime"):
        return None
    return "ERROR: wasmtime not on PATH. Install: https://wasmtime.dev"


def _safe_path(sandbox, user_path: str) -> str:
    if sandbox is None:
        if user_path.startswith("-"):
            raise ValueError(f"path {user_path!r} may not begin with '-'")
        return user_path
    workdir = Path(sandbox.workdir).resolve()
    candidate = (workdir / user_path).resolve()
    try:
        candidate.relative_to(workdir)
    except ValueError as e:
        raise ValueError(f"path {user_path!r} escapes the sandbox workdir") from e
    return str(candidate)


def _op_run(args: dict, sandbox) -> str:
    err = _need_wasmtime()
    if err:
        return err
    module = (args.get("module") or "").strip()
    if not module:
        return "ERROR: run requires module (.wasm/.wat path)"
    raw_dirs = args.get("dirs") or []
    if not isinstance(raw_dirs, list):
        return "ERROR: dirs must be an array of workdir-relative paths"
    try:
        module = _safe_path(sandbox, module)
        dirs = [_safe_path(sandbox, d) for d in raw_dirs]
    except ValueError as e:
        return f"ERROR: {e}"
    cmd = ["wasmtime", "run"]
    for d in dirs:
        cmd.extend(["--dir", d])
    env = args.get("env") or {}
    if not isinstance(env, dict):
        return "ERROR: env must be an object of KEY: value"
    for k, v in env.items():
        if not _ENV_KEY.match(str(k)):
            return f"ERROR: invalid env key {k!r}"
        cmd.extend(["--env", f"{k}={v}"])
    cmd.append(module)
    module_args = [str(a) for a in (args.get("args") or [])]
    if module_args:
        cmd.append("--")
        cmd.extend(module_args)
    timeout = max(1, min(int(args.get("timeout") or 60), 600))
    parameters = {"command": cmd, "stdin": args.get("stdin"), "timeout_seconds": timeout}
    try:
        permit = request_execution_consent(
            "wasm_run",
            target_provider=lambda: execution_target(sandbox),
            parameters=parameters,
            detail=f"Run the {Path(module).name} WebAssembly module with a {timeout}-second limit.",
            effect="Runs the selected WebAssembly module with the reviewed directory grants.",
            review_items=[f"Module: {module}", f"Preopened directories: {', '.join(dirs) or 'none'}",
                          "Environment values and input are included in the exact-operation digest."],
            timeout=timeout,
            input_versions_provider=lambda: file_version(Path(module)),
        )
    except ConsentDenied:
        return "ERROR: WebAssembly execution was not approved; no module was run"
    except (ApprovalCardError, OSError):
        return "ERROR: module, execution target, or approval authority changed; review it again"
    from . import sandbox_run
    try:
        with consume_operation_consent(permit):
            code, out, stderr = sandbox_run(sandbox, cmd, timeout=timeout,
                                            stdin=args.get("stdin"))
    except (ApprovalCardError, OSError):
        return "ERROR: module, execution target, or approval authority changed; review it again"
    if code != 0:
        return f"ERROR: wasmtime ({code}): {stderr.strip()[-400:]}"
    tail = f"\n[stderr] {stderr.strip()[-200:]}" if stderr.strip() else ""
    return (out or "(no output)") + tail


def _op_version(_args: dict, sandbox) -> str:
    err = _need_wasmtime()
    if err:
        return err
    from . import sandbox_run
    _c, out, _e = sandbox_run(sandbox, ["wasmtime", "--version"], timeout=15)
    return out.strip() or "wasmtime (version unknown)"


def _run(args: dict[str, Any], sandbox) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        if op == "run":
            return _op_run(args, sandbox)
        if op == "version":
            return _op_version(args, sandbox)
    except Exception as e:
        return f"ERROR: wasm_run failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def wasm_run(sandbox=None) -> Tool:
    return Tool(
        name="wasm_run",
        description=(
            "Run a WebAssembly/WASI module under wasmtime: capability-grant "
            "isolation (module sees ONLY the preopened dirs/env/args given). "
            "ops: run (module + args/dirs/env/stdin/timeout), version. "
            "Requires wasmtime on PATH."
        ),
        input_schema=_WASM_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )
