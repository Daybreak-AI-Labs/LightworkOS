"""Devcontainer sandbox backend.

Reads the project's ``.devcontainer/devcontainer.json`` (or
``devcontainer.json`` at repo root) and runs commands inside the
configured container image — so the agent operates in the same
environment the user's IDE / Codespaces / GitHub Actions devcontainer
spec describes.

Why ship this separately from Docker?
  - Users who already maintain a devcontainer spec want their AI
    agent to use the exact same toolchain.
  - VSCode + GitHub Codespaces standardize on this format; meeting
    users where they are.

Strategy:
  - Look up ``.devcontainer/devcontainer.json`` (preferred) or
    ``devcontainer.json``. JSONC (JSON with comments) is supported
    by stripping ``// ...`` lines + trailing commas.
  - Read ``image`` (required). ``dockerFile`` build is out of scope
    for v1 (delegate to a pre-built image; we'll surface a useful
    error if only dockerFile is set).
  - Read ``remoteUser`` (default ``root``), ``workspaceFolder``
    (default ``/workspaces/<repo-name>``), ``containerEnv``
    (env vars), ``forwardPorts`` (ignored — exec model).
  - ``runArgs`` are intentionally rejected in v1 to preserve sandbox
    isolation guarantees.
  - For each ``exec()``: ``docker run --rm`` with the parsed config.

Config::

    [sandbox]
    backend = "devcontainer"
    project_dir = "/path/to/your/repo"  # contains .devcontainer/
    timeout = 60
    allow_network = false               # OFF by default (parity with docker/
                                        # podman/kubernetes --network none); opt in
    allow_root = false                  # keep the invoking uid:gid; true = root
    memory = "4g"                       # RAM cap (shared knob; "" / null disables)

Every exec runs ``docker run`` with ``--cap-drop ALL``,
``--security-opt no-new-privileges``, a pids limit, and the ``--memory`` cap
above, matching the hardened DockerBackend. Network is disabled by default
(``--network none``) exactly like the other container backends -- set
``allow_network = true`` when a run genuinely needs egress. By default the
container user is pinned to the invoking non-root uid:gid; the repository's
``remoteUser`` is not trusted to identify an unprivileged account. Set
``allow_root = true`` (or ``MAVERICK_SANDBOX_ALLOW_ROOT``) to opt into the
repository's user setting, including root.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .local import _SECRET_ENV_RE, ExecResult, container_user_args, scrub_env

log = logging.getLogger(__name__)

# containerEnv keys come from a repo-supplied devcontainer.json (attacker-
# influenced). Only inject keys matching a safe shell identifier shape so a
# crafted name can't smuggle extra `docker run` semantics.
_SAFE_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# `image` comes from a repo-supplied devcontainer.json and is placed as the
# IMAGE positional in `docker run`. Docker's CLI parses any leading-dash token
# before the first positional as a FLAG, so an `image` value like
# "--privileged" injects a run option that negates our --cap-drop/no-new-
# privileges hardening. Require a docker reference shape and reject anything
# starting with '-' (mirrors the leading-dash guards in git_advanced /
# ffmpeg_tool).
_SAFE_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]*$")


def _strip_jsonc(text: str) -> str:
    """Strip // line comments + /* block */ comments + trailing commas."""
    # Block comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Line comments (skip if inside a string — naive but works for
    # well-formed devcontainer.json which doesn't have //-in-strings).
    out_lines = []
    for line in text.splitlines():
        out_lines.append(re.sub(r"(?<!:)//.*$", "", line))
    text = "\n".join(out_lines)
    # Trailing commas before } or ]
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text


@dataclass
class DevcontainerSpec:
    image: str
    remote_user: str = "root"
    workspace_folder: str = "/workspaces/repo"
    container_env: dict[str, str] = field(default_factory=dict)


def _find_devcontainer_json(project_dir: Path) -> Path | None:
    candidates = [
        project_dir / ".devcontainer" / "devcontainer.json",
        project_dir / "devcontainer.json",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def _parse_devcontainer(path: Path) -> DevcontainerSpec:
    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(_strip_jsonc(raw))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"failed to parse {path}: {e}") from e
    if not isinstance(data, dict):
        raise RuntimeError(f"{path}: top-level must be an object")
    image = data.get("image")
    if not image:
        if data.get("dockerFile") or data.get("build"):
            raise RuntimeError(
                f"{path}: only `image` is supported in v1 — "
                "your spec uses `dockerFile` or `build`. Build the "
                "image yourself + reference it via `image`."
            )
        raise RuntimeError(f"{path}: missing required `image` field")

    image = str(image)
    if not _SAFE_IMAGE_RE.match(image):
        # A leading-dash / option-shaped image would be parsed by `docker run`
        # as a flag (e.g. `--privileged`), defeating the sandbox hardening.
        raise RuntimeError(
            f"{path}: refusing option-like `image` value {image!r} "
            "(must be a plain image reference, not start with '-')"
        )

    run_args = data.get("runArgs") or []
    if run_args:
        raise RuntimeError(
            f"{path}: `runArgs` is not supported for security reasons in v1. "
            "Configure sandbox options in Lightwork config instead."
        )

    repo_name = path.parent.name
    if path.parent.name == ".devcontainer":
        repo_name = path.parent.parent.name
    return DevcontainerSpec(
        image=image,
        remote_user=str(data.get("remoteUser") or "root"),
        workspace_folder=str(
            data.get("workspaceFolder") or f"/workspaces/{repo_name}",
        ),
        container_env={
            str(k): str(v) for k, v in (data.get("containerEnv") or {}).items()
        },
    )


@dataclass
class DevcontainerBackend:
    project_dir: Path
    timeout: float = 60.0
    # OFF by default -- parity with docker/podman/kubernetes, which all default
    # to ``--network none``. A devcontainer that genuinely needs egress opts in
    # via ``[sandbox] allow_network = true``. Defaulting this True shipped weaker
    # isolation than the DockerBackend this backend claims parity with.
    allow_network: bool = False
    memory: str | None = "4g"
    # Run as the invoking uid:gid by default (via ``container_user_args``) rather
    # than root. The workspace is a WRITABLE host bind-mount, so a root container
    # user lets a prompt-injected agent write root-owned files on the host. Set
    # ``[sandbox] allow_root = true`` (or ``MAVERICK_SANDBOX_ALLOW_ROOT``) to keep
    # root for images that require it -- matching DockerBackend.
    allow_root: bool = False
    spec_override: DevcontainerSpec | None = None

    def __post_init__(self) -> None:
        self.project_dir = Path(self.project_dir).resolve()
        self._verify_docker()
        if self.spec_override is not None:
            self.spec = self.spec_override
        else:
            p = _find_devcontainer_json(self.project_dir)
            if p is None:
                raise RuntimeError(
                    f"no devcontainer.json found under {self.project_dir} "
                    "(looked at .devcontainer/devcontainer.json + ./devcontainer.json)"
                )
            self.spec = _parse_devcontainer(p)
            log.info("devcontainer: %s -> image=%s", p, self.spec.image)

    @property
    def workdir(self) -> Path:
        """Sandbox SDK contract: the host directory commands run against.

        For a devcontainer that IS the project dir (mounted as the
        workspace); tools that confine model-supplied paths to
        ``sandbox.workdir`` need it on this backend.
        """
        return self.project_dir

    def _verify_docker(self) -> None:
        try:
            subprocess.run(
                ["docker", "version"],
                capture_output=True, timeout=5, check=True, env=scrub_env(),
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(
                "Docker not available — required for devcontainer backend. "
                "Install Docker or change [sandbox] backend in ~/.maverick/config.toml."
            ) from e

    def exec(self, cmd: str, timeout: float | None = None) -> ExecResult:
        from .workspace_guard import validate_container_workspace
        validate_container_workspace(self.project_dir)
        effective = self.timeout if timeout is None else timeout
        container_name = f"maverick-devc-{uuid.uuid4().hex}"
        args = [
            "docker", "run", "--rm",
            "--name", container_name,
            "-v", f"{self.project_dir}:{self.spec.workspace_folder}",
            "-w", self.spec.workspace_folder,
            # Match DockerBackend's containment for a possibly prompt-injected
            # agent: drop every Linux capability and block privilege
            # escalation. Without these, devcontainer ran as root (the default
            # remoteUser) against a writable host mount with full caps.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "512",
        ]
        if self.memory:
            # Cap container RAM and pin --memory-swap to it so the limit can't be
            # sidestepped via swap -- parity with DockerBackend's DoS guard.
            # Without it a prompt-injected agent could exhaust host memory.
            args.extend(["--memory", str(self.memory),
                         "--memory-swap", str(self.memory)])
        operator_allows_root = self.allow_root or os.environ.get(
            "MAVERICK_SANDBOX_ALLOW_ROOT", ""
        ).strip().lower() in {"1", "true", "yes", "on"}
        if operator_allows_root:
            if self.spec.remote_user and self.spec.remote_user != "root":
                args.extend(["--user", self.spec.remote_user])
        else:
            # A repo-provided username can name UID 0, or another host UID.
            # Pin to the trusted invoking identity rather than the spec.
            user_args = container_user_args(False)
            try:
                uid, gid = (int(part) for part in user_args[1].split(":"))
            except (IndexError, TypeError, ValueError):
                uid, gid = 0, 0
            if uid <= 0 or gid <= 0:
                raise RuntimeError(
                    "devcontainer requires a non-root invoking user unless "
                    "the operator enables sandbox allow_root"
                )
            args.extend(user_args)
        for k, v in self.spec.container_env.items():
            # containerEnv is repo-supplied: reject names that aren't plain
            # shell identifiers, and skip secret-shaped names so a malicious
            # spec can't seed the container with attacker-controlled creds.
            if not _SAFE_ENV_NAME_RE.match(k):
                log.warning(
                    "devcontainer: skipping containerEnv key %r "
                    "(not a valid identifier)", k,
                )
                continue
            if _SECRET_ENV_RE.search(k):
                log.warning(
                    "devcontainer: skipping containerEnv key %r "
                    "(matches secret-name pattern)", k,
                )
                continue
            args.extend(["-e", f"{k}={v}"])
        if not self.allow_network:
            args.extend(["--network", "none"])
        args.extend([self.spec.image, "sh", "-c", cmd])

        try:
            result = subprocess.run(
                args, capture_output=True, text=True, errors="replace", timeout=effective,
                env=scrub_env(),
            )
            return ExecResult(
                stdout=result.stdout[-8000:],
                stderr=result.stderr[-2000:],
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired as e:
            # Best-effort cleanup; never let a hung daemon's `rm` raise
            # over the TIMEOUT ExecResult.
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container_name],
                    capture_output=True, timeout=10, env=scrub_env(),
                )
            except Exception:
                pass
            stdout = e.stdout or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            return ExecResult(
                stdout=stdout[-8000:],
                stderr=f"TIMEOUT after {effective}s",
                exit_code=124,
            )


__all__ = ["DevcontainerBackend", "DevcontainerSpec"]
