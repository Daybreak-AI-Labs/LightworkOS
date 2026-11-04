"""Agent-callable self-diagnosis.

Wraps the same checks ``maverick doctor`` runs (config + provider
keys + sandbox health + audit dir + shield availability) and returns
a short readable summary the agent can use to decide whether to
proceed or pause for the user.

ops:
  - diagnose()   — full check, returns a multi-line summary
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any

from ..paths import data_dir
from ..sandbox.gvisor import (
    GVisorRuntimeValidationError,
    validate_docker_gvisor_runtime,
)
from ..sandbox_names import BUILTIN_SANDBOX_BACKENDS
from . import Tool

_DIAG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "required": [],
}


def _check_python() -> list[str]:
    v = sys.version_info
    if v < (3, 11):
        return [f"  ✗ python {v.major}.{v.minor} (need >= 3.11)"]
    return [f"  ✓ python {v.major}.{v.minor}"]


def _check_provider_keys() -> list[str]:
    keys = {
        "ANTHROPIC_API_KEY": "anthropic",
        "OPENAI_API_KEY":    "openai",
        "DEEPSEEK_API_KEY":  "deepseek",
        "MOONSHOT_API_KEY":  "moonshot",
        "XAI_API_KEY":       "xai",
        "GEMINI_API_KEY":    "gemini",
    }
    found, missing = [], []
    for env, name in keys.items():
        if os.environ.get(env, "").strip():
            found.append(name)
        else:
            missing.append(name)
    out = [f"  ✓ providers with keys: {', '.join(found) or '(none)'}"]
    if not found:
        out.append("    ! no provider keys set — agent cannot make LLM calls")
    return out


def _check_config_dir() -> list[str]:
    home = data_dir()
    if not home.exists():
        return ["  ! ~/.maverick does not exist (will be created on first run)"]
    out = ["  ✓ ~/.maverick exists"]
    audit = home / "audit"
    if audit.exists():
        try:
            mode = oct(audit.stat().st_mode)[-3:]
            out.append(f"    audit dir mode: {mode}")
        except OSError:
            pass
    return out


def _check_gvisor(cfg: dict[str, Any]) -> list[str]:
    if not shutil.which("docker"):
        return ["    [FAIL] gvisor needs the docker binary, not on PATH"]
    try:
        validate_docker_gvisor_runtime(cfg.get("runtime", "runsc"))
    except GVisorRuntimeValidationError as exc:
        return [f"    [FAIL] {exc}"]
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        return ["    [FAIL] gvisor Docker daemon/runtime probe failed"]
    return []


def _check_modal(cfg: dict[str, Any]) -> list[str]:
    out: list[str] = []
    allow_network = cfg.get("allow_network", False)
    acknowledged = allow_network is True or (
        isinstance(allow_network, str)
        and allow_network.strip().lower() in {"1", "true", "yes", "on"}
    )
    if not acknowledged:
        out.append(
            "    [FAIL] modal requires allow_network=true; "
            "otherwise execution fails closed"
        )
    try:
        import importlib.util

        modal_present = importlib.util.find_spec("modal") is not None
    except (ImportError, ValueError):
        modal_present = False
    if not modal_present:
        out.append("    [FAIL] modal package not installed")
    return out


def _recognized_sandbox_backend(backend: str) -> bool:
    return backend in BUILTIN_SANDBOX_BACKENDS or backend.startswith("ep:")


def _check_external_backend(backend: str) -> list[str]:
    name = backend[3:].strip()
    try:
        from ..sandbox.sdk import installed_entry_point_names

        installed = installed_entry_point_names()
    except Exception:
        installed = ()
    if name and name in installed:
        return []
    return [
        f"    [FAIL] external sandbox entry point "
        f"{name or '(empty)'!r} is not installed"
    ]


def _check_sandbox() -> list[str]:
    try:
        from ..config import get_sandbox
        cfg = get_sandbox()
    except Exception:
        cfg = {}
    backend = str(cfg.get("backend", "local") or "local").strip().lower()
    out = [f"  ✓ sandbox backend: {backend}"]
    if backend == "docker":
        if not shutil.which("docker"):
            out.append("    ✗ docker binary not on PATH")
    if backend == "gvisor":
        out.extend(_check_gvisor(cfg))
    if backend == "podman":
        if not shutil.which("podman"):
            out.append("    ✗ podman binary not on PATH")
    if backend == "devcontainer":
        if not shutil.which("docker"):
            out.append("    ✗ devcontainer needs the docker binary, not on PATH")
    if backend == "kubernetes":
        if not shutil.which("kubectl"):
            out.append("    ✗ kubectl binary not on PATH")
    if backend == "firecracker":
        provider = str(cfg.get("provider", "local") or "local").strip().lower()
        if provider == "local" and not shutil.which("firecracker"):
            out.append("    ✗ firecracker binary not on PATH")
        elif provider == "e2b" and not os.environ.get("E2B_API_KEY"):
            out.append("    ✗ firecracker provider=e2b but E2B_API_KEY unset")
    if backend == "modal":
        out.extend(_check_modal(cfg))
    if backend == "ssh":
        if not shutil.which("ssh"):
            out.append("    ✗ ssh binary not on PATH")
    if backend.startswith("ep:"):
        out.extend(_check_external_backend(backend))
    if not _recognized_sandbox_backend(backend):
        out.append(
            "    [FAIL] unrecognized sandbox backend; supported: "
            + ", ".join(BUILTIN_SANDBOX_BACKENDS)
            + ", or ep:<name>"
        )
    return out


# Coding-language toolchains the agent can build/test against, probed by the
# binary it invokes. Only the `local` sandbox runs on the host toolchain;
# container backends get it from their image (see build_sandbox's
# image-by-language selection), so this check is informational, never fatal.
_TOOLCHAINS = [
    ("python", "python3"),
    ("rust", "cargo"),
    ("go", "go"),
    ("node/ts", "node"),
]


def _check_toolchains() -> list[str]:
    present = [name for name, binary in _TOOLCHAINS if shutil.which(binary)]
    out = [f"  ✓ coding toolchains on PATH: {', '.join(present) or '(none)'}"]
    try:
        from ..config import get_sandbox
        backend = str(get_sandbox().get("backend", "local") or "local").strip().lower()
    except Exception:
        backend = "local"
    if backend == "local":
        missing = [n for n, b in _TOOLCHAINS if not shutil.which(b)]
        if missing:
            out.append(
                "    ! local sandbox runs on host toolchains; without "
                f"{', '.join(missing)} the agent can't build/test those "
                "languages -- install them or use a container sandbox"
            )
    else:
        out.append(
            f"    ({backend} sandbox provides the toolchain from its image; "
            "set [sandbox] language or MAVERICK_LANGUAGE to choose it)"
        )
    return out


def _check_shield() -> list[str]:
    try:
        import maverick_shield  # noqa: F401
        return ["  ✓ shield installed"]
    except ImportError:
        return [
            "  ! shield not installed (kernel runs without it; "
            "install from the reviewed checkout with "
            "`python -m pip install -e ./packages/maverick-shield` for "
            "guardrails)",
        ]


def _run(args: dict[str, Any]) -> str:
    lines: list[str] = ["Lightwork self-diagnose:"]
    lines.extend(_check_python())
    lines.extend(_check_provider_keys())
    lines.extend(_check_config_dir())
    lines.extend(_check_sandbox())
    lines.extend(_check_toolchains())
    lines.extend(_check_shield())
    return "\n".join(lines)


def diagnose() -> Tool:
    return Tool(
        name="diagnose",
        description=(
            "Run a self-diagnosis on the Lightwork install: Python "
            "version, configured provider keys, sandbox readiness, "
            "coding-language toolchains (rust/go/node), config dir, "
            "shield availability. Use when something feels off (e.g. "
            "unexpected ERROR responses) before asking the user."
        ),
        input_schema=_DIAG_SCHEMA,
        fn=_run,
    )
