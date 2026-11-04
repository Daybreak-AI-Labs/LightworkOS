"""Container build tool.

Builds a container image from a Dockerfile + context directory by issuing
``docker build`` through the sandbox chokepoint (CLAUDE.md rule #4 — never a
bare ``subprocess``). The context dir and Dockerfile are confined to
``sandbox.workdir`` (model-supplied paths can't escape the workspace), and the
tag + build-arg keys are validated so nothing breaks out of the argv. The
build is high-risk (Dockerfile ``RUN`` executes code and the build context can
expose workspace files), so it is consent-gated before execution. Returns
the build status + a tail of the output.

ops:
  - build(context, tag[, dockerfile][, build_args][, timeout])
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from . import Tool, sandbox_run

# Docker tag grammar (simplified): name[:tag], lowercase name, optional registry/path.
_TAG = re.compile(r"^[a-z0-9]([a-z0-9._/-]*[a-z0-9])?(:[A-Za-z0-9._-]+)?$")
_ARG_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _context_input_versions(context: Path, dockerfile: Path) -> dict[str, str]:
    """Commit to every build-context file without persisting its contents."""

    from ..approval_cards import digest

    def file_sha256(path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    manifest: list[dict[str, object]] = []
    for path in sorted(context.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(context).as_posix()
        if path.is_symlink():
            manifest.append({"path": relative, "symlink": str(path.readlink())})
        elif path.is_file():
            manifest.append(
                {
                    "path": relative,
                    "size": path.stat().st_size,
                    "sha256": file_sha256(path),
                }
            )
    return {
        "context_manifest_sha256": digest(manifest),
        "dockerfile_sha256": file_sha256(dockerfile),
    }


def _confine(base: Path, raw: str, workdir: Path) -> Path | None:
    """Resolve ``raw`` (relative to ``base``) and refuse it if it escapes ``workdir``."""
    cand = Path(raw)
    cand = (base / cand).resolve() if not cand.is_absolute() else cand.resolve()
    try:
        cand.relative_to(workdir)
    except ValueError:
        return None
    return cand


def _build(sandbox: Any, args: dict[str, Any]) -> str:
    workdir = Path(getattr(sandbox, "workdir", ".")).resolve()
    if not workdir.is_dir():
        return f"ERROR: workdir {workdir} not found"

    context_raw = (args.get("context") or ".").strip()
    context = _confine(workdir, context_raw, workdir)
    if context is None:
        return f"ERROR: context {context_raw!r} escapes the workspace"
    if not context.is_dir():
        return f"ERROR: context dir not found: {context_raw}"

    tag = (args.get("tag") or "").strip()
    if not tag or not _TAG.match(tag):
        return "ERROR: missing or invalid 'tag' (expected name[:tag])"

    dockerfile_raw = (args.get("dockerfile") or "Dockerfile").strip()
    df = _confine(context, dockerfile_raw, workdir)
    if df is None:
        return f"ERROR: dockerfile {dockerfile_raw!r} escapes the workspace"
    if not df.is_file():
        return f"ERROR: Dockerfile not found: {dockerfile_raw}"

    argv = ["docker", "build", "-t", tag, "-f", str(df)]
    bargs = args.get("build_args") or {}
    if isinstance(bargs, dict):
        for k, v in bargs.items():
            if not _ARG_KEY.match(str(k)):
                return f"ERROR: invalid build-arg key {k!r}"
            argv += ["--build-arg", f"{k}={v}"]
    argv.append(str(context))

    try:
        timeout = float(args.get("timeout", 600))
    except (TypeError, ValueError):
        timeout = 600.0
    target = {
        "context": str(context),
        "dockerfile": str(df),
        "image_tag": tag,
    }
    parameters = {"argv": argv, "timeout_seconds": timeout}

    def current_target() -> dict[str, str]:
        return {
            "context": str(context.resolve(strict=True)),
            "dockerfile": str(df.resolve(strict=True)),
            "image_tag": tag,
        }

    def current_credentials() -> dict[str, str]:
        from ..approval_cards import digest

        backend = type(sandbox)
        return {
            "kind": "sandbox-runtime",
            "generation_sha256": digest(
                {
                    "backend": f"{backend.__module__}.{backend.__qualname__}",
                    "workdir": str(getattr(sandbox, "workdir", ".")),
                }
            ),
        }

    from ..approval_cards import ApprovalCardError
    from ..safety import (
        ConsentDenied,
        consume_operation_consent,
        require_operation_consent,
    )

    try:
        permit = require_operation_consent(
            "container_build",
            risk="high",
            scope=f"{tag} in {context}",
            detail=f"Build container image {tag} from the reviewed workspace context.",
            provenance="container_build",
            target=target,
            parameters=parameters,
            parameter_summary=[
                "Build the reviewed tag from the committed context, Dockerfile, arguments, and timeout."
            ],
            known_effects=[
                "Runs Dockerfile instructions and writes an image to the local container runtime."
            ],
            unresolved_assumptions=[
                "Dockerfile instructions may access services allowed by the sandbox and container runtime."
            ],
            before="The reviewed image build has not started.",
            after="The container runtime may contain the reviewed image and build cache layers.",
            irreversible=False,
            target_provider=current_target,
            parameters_provider=lambda: {"argv": list(argv), "timeout_seconds": timeout},
            input_versions_provider=lambda: _context_input_versions(context, df),
            credential_versions_provider=current_credentials,
            budget_provider=lambda: {"timeout_seconds": timeout},
            allow_auto_approve=False,
            consult_ledger=False,
        )
    except ConsentDenied:
        return "ERROR: container build was not approved; no build was started"
    except (ApprovalCardError, OSError):
        return (
            "ERROR: container build target or approval authority changed; "
            "review it again"
        )

    try:
        with consume_operation_consent(permit):
            code, out, err = sandbox_run(sandbox, argv, timeout=timeout)
    except (ApprovalCardError, OSError):
        return (
            "ERROR: container build target or approval authority changed; "
            "review it again"
        )
    tail = (out or "")[-1500:]
    if err:
        tail = (tail + "\n" + err[-500:]).strip()
    status = "ok" if code == 0 else f"FAILED (exit {code})"
    return f"docker build {status} for {tag}\n{tail}".strip()


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["build"]},
        "context": {
            "type": "string",
            "description": "build context dir (within the workspace)",
        },
        "tag": {"type": "string", "description": "image tag, e.g. myapp:dev"},
        "dockerfile": {
            "type": "string",
            "description": "Dockerfile path (default: <context>/Dockerfile)",
        },
        "build_args": {
            "type": "object",
            "description": "--build-arg KEY=VALUE pairs",
        },
        "timeout": {
            "type": "number",
            "description": "build timeout seconds (default 600)",
        },
    },
    "required": ["context", "tag"],
}


def container_build(sandbox: Any) -> Tool:
    return Tool(
        name="container_build",
        description=(
            "Build a container image from a Dockerfile + context via 'docker "
            "build', routed through the sandbox. op=build with 'context' (dir, "
            "workspace-confined) and 'tag' (name[:tag]); optional 'dockerfile', "
            "'build_args' (object), 'timeout'. Paths can't escape the workspace; "
            "tag and build-arg keys are validated. High-risk consent is required "
            "before execution. Returns status + output tail."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _build(sandbox, args),
    )
