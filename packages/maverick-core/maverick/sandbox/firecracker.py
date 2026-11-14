"""Firecracker microVM sandbox backend.

Plain Docker shares the host kernel, which is weak isolation for
adversarial agents. A Firecracker microVM boots in ~125ms, gives
kernel-level isolation, and constrains network/disk by default; hosted
sandboxes such as Vercel Sandbox, E2B and Daytona use it.

This backend talks to a local Firecracker API socket (firecracker-go
is the canonical impl; the python client at github.com/firecracker-
microvm/firecracker-go-sdk has no direct python equivalent, so we
shell out to `firecracker` + `firectl`). For deployments that don't
have Firecracker installed (most desktops), the backend falls back
to a clear NotImplementedError at construction so the operator gets
an obvious error rather than a silent downgrade to local subprocess.

For E2B-hosted deployments (a managed Firecracker service), the
`provider="e2b"` mode talks to E2B's REST API instead of a local
socket. That path is the realistic config for VPS users who don't
want to operate Firecracker themselves.

Status: experimental SCAFFOLD. Full microVM lifecycle (kernel image,
rootfs, network bridge, balloon, snapshot/restore) is operator-side
work that varies per host distro; this module gives the agent loop
the same ``.exec(cmd) -> ExecResult`` interface and routes to either
a local firectl invocation or the E2B API.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from ..paths import data_dir
from .local import ExecResult, scrub_env

log = logging.getLogger(__name__)


@dataclass
class FirecrackerBackend:
    """Run agent commands inside a Firecracker microVM.

    Two modes:
      provider="local"  : talk to a local firectl + firecracker on PATH
      provider="e2b"    : POST to E2B's sandbox REST API

    Warm reuse (``[sandbox] warm = true``): keep ONE microVM alive between
    execs instead of boot-per-exec. What each provider's exec mechanism
    genuinely allows:

      - **e2b**: the REST API holds a sandbox open (create once -> POST
        repeated ``/processes`` against its id -> DELETE). Warm mode reuses
        the sandbox id across execs and tears it down in :meth:`close` (E2B's
        server-side idle TTL is the backstop if close is never reached). A
        stale/expired id is recreated once, transparently.
      - **local (firectl)**: firectl boots a one-shot microVM whose init runs
        the command and exits — there is no exec channel (no in-guest agent /
        vsock RPC) into a running VM in this scaffold, so a pre-booted VM
        could never be handed a command. Warm is therefore honestly a no-op
        here (logged once); boot-per-exec stands until the deploy/ image grows
        a guest agent.

    Trade-off, stated plainly: a warm VM keeps filesystem and process state
    between execs *within this backend instance's lifetime* — that is the
    point (toolchains stay warm) and is the same trust domain as one run.
    Because that state cannot be guaranteed scrubbed remotely, warm
    Firecracker sandboxes are excluded from the cross-RUN pool
    (``sandbox/pool.py``) — they never carry state into another run.
    """
    # Neither provider currently transfers the host workspace into the VM.
    workdir_is_local: ClassVar[bool] = False
    workdir: Path
    image: str = "ubuntu:24.04-maverick"
    timeout: float = 60.0
    provider: str = "local"
    api_key: str | None = None
    network: str = "egress-deny"   # egress-deny | egress-allow | bridge=<name>
    warm: bool = False             # keep the microVM alive between execs (e2b only)
    _warm_id: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        # Validate the network policy once, at construction, so a bad value
        # (typo, attacker-influenced config) is rejected loudly instead of
        # silently reaching an exec path with undefined isolation behaviour.
        if (
            self.network not in ("egress-deny", "egress-allow")
            and not self.network.startswith("bridge=")
        ):
            raise ValueError(
                "Firecracker network must be one of: 'egress-deny', "
                f"'egress-allow', or 'bridge=<name>', got {self.network!r}"
            )
        if self.provider == "local":
            if not shutil.which("firecracker"):
                raise NotImplementedError(
                    "Firecracker backend requires the `firecracker` binary "
                    "on PATH. Install per "
                    "https://github.com/firecracker-microvm/firecracker/"
                    "blob/main/docs/getting-started.md or set "
                    "[sandbox] provider = \"e2b\" to use E2B's hosted "
                    "Firecracker service instead."
                )
        elif self.provider == "e2b":
            self.api_key = self.api_key or os.environ.get("E2B_API_KEY")
            if not self.api_key:
                raise ValueError(
                    "E2B Firecracker backend requires E2B_API_KEY"
                )
        else:
            raise ValueError(
                f"Firecracker provider must be 'local' or 'e2b', got {self.provider!r}"
            )
        if self.warm and self.provider == "local":
            log.info(
                "Firecracker warm mode requested, but the local firectl path "
                "boots a one-shot microVM per exec (no in-guest exec agent); "
                "warm reuse applies to provider=\"e2b\" only."
            )

    def exec(self, cmd: str, timeout: float | None = None) -> ExecResult:
        # Keep overrides local to the call; overlapping executions must not
        # borrow or restore each other's deadline as the instance default.
        if self.provider == "e2b":
            return self._exec_e2b(cmd, timeout)
        return self._exec_local(cmd, timeout)


    def _e2b_network_config(self) -> dict:
        if self.network == "egress-deny":
            return {"egress": "deny"}
        if self.network == "egress-allow":
            return {"egress": "allow"}
        if self.network.startswith("bridge="):
            return {"bridge": self.network.split("=", 1)[1]}
        raise ValueError(
            "Firecracker network must be one of: "
            "'egress-deny', 'egress-allow', or 'bridge=<name>'"
        )

    def _exec_local(self, cmd: str, timeout: float | None = None) -> ExecResult:
        """Run inside a freshly-booted local microVM.

        Full impl: spin up a microVM with kernel+rootfs, copy workdir
        in via vsock, run cmd, capture stdio, tear down. The reference
        impl in `deploy/firecracker/` ships the kernel + rootfs build
        scripts; this module is the agent-side interface only.

        Scaffold: if `firectl` is installed, use it; otherwise refuse, or
        (with MAVERICK_FIRECRACKER_STRICT=0) fall back to plain
        `docker run --read-only` and log the gap.
        """
        if shutil.which("firectl"):
            return self._firectl(cmd) if timeout is None else self._firectl(cmd, timeout)
        # No firectl: an operator who configured `provider = "firecracker"`
        # asked for hard microVM isolation, so silently downgrading to a Docker
        # namespace boundary defeats that choice. Fail CLOSED by default; the
        # operator must explicitly opt into the weaker fallback with
        # MAVERICK_FIRECRACKER_STRICT=0, so the secure posture does not
        # depend on remembering to set an env var.
        from ..env_setting import env_or_config

        strict = env_or_config("MAVERICK_FIRECRACKER_STRICT", "sandbox", "firecracker_strict", "1")
        if (strict or "1").strip().lower() not in {"0", "false", "no", "off"}:
            raise RuntimeError(
                "Firecracker local backend: firectl not on PATH, so microVM "
                "isolation is unavailable. Refusing to silently downgrade to "
                "Docker (which is a weaker boundary than you selected). Install "
                "firectl for microVM isolation, or set "
                "MAVERICK_FIRECRACKER_STRICT=0 to explicitly allow the Docker "
                "fallback."
            )
        # Operator explicitly opted into the downgrade (STRICT=0). Use a
        # hardened docker invocation and log so they know they're not getting
        # full microVM isolation.
        log.warning(
            "Firecracker local backend: firectl not on PATH and "
            "MAVERICK_FIRECRACKER_STRICT=0; falling back to a hardened "
            "`docker --network=none --read-only` for this run. Install "
            "firectl for full microVM isolation."
        )
        return self._docker_fallback(cmd) if timeout is None else self._docker_fallback(cmd, timeout)

    def _firectl(self, cmd: str, timeout: float | None = None) -> ExecResult:
        """Run a one-shot command via firectl. Scaffold."""
        # firectl invocation pattern (kernel + rootfs paths come from
        # ~/.maverick/firecracker/{kernel,rootfs}.img by convention).
        kernel = data_dir("firecracker", "kernel.img")
        rootfs = data_dir("firecracker", "rootfs.img")
        if not kernel.exists() or not rootfs.exists():
            return ExecResult(
                exit_code=127,
                stdout="",
                stderr=(
                    f"firecracker kernel/rootfs not found at "
                    f"{kernel} / {rootfs}. Build them with "
                    "deploy/firecracker/fetch-kernel.sh + "
                    "deploy/firecracker/build-rootfs.sh (see "
                    "deploy/firecracker/README.md)."
                ),
            )
        args = [
            "firectl",
            "--kernel", str(kernel),
            "--root-drive", str(rootfs),
            "--ncpus", "1",
            "--memory", "512",
        ]
        if self.network == "egress-deny":
            args += ["--no-network"]
        elif self.network.startswith("bridge="):
            args += ["--tap-device", self.network.split("=", 1)[1]]
        elif self.network != "egress-allow":
            return ExecResult(
                stdout="",
                stderr=(
                    "firecracker invalid network policy; expected "
                    "egress-deny|egress-allow|bridge=<name>"
                ),
                exit_code=126,
            )
        args += ["--", "/bin/sh", "-c", cmd]
        try:
            # Scrub secrets from the host firectl invocation, matching every
            # other backend's host-CLI calls (docker/podman/k8s/ssh) -- the
            # CLI shouldn't inherit ANTHROPIC_API_KEY et al.
            proc = subprocess.run(
                args, capture_output=True, text=True, errors="replace",
                timeout=self.timeout if timeout is None else timeout,
                env=scrub_env(),
            )
        except subprocess.TimeoutExpired:
            return ExecResult(exit_code=124, stdout="", stderr="firecracker timeout")
        return ExecResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def _docker_fallback(self, cmd: str, timeout: float | None = None) -> ExecResult:
        """Best-effort sandbox when firectl isn't available.

        Applies the same containment the regular ``DockerBackend`` uses
        (``--cap-drop ALL`` + ``--security-opt no-new-privileges`` + a pids
        cap) so the fallback isn't *weaker* than the normal Docker path."""
        args = [
            "docker", "run", "--rm",
            "--network=none", "--read-only",
            "--tmpfs", "/tmp",
            # This fallback stands in for hard VM isolation, so it must be at
            # least as contained as the plain Docker backend: drop all caps,
            # block privilege escalation, and cap pids.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "512",
            "-v", f"{self.workdir}:/work:ro",
            "-w", "/work",
            "python:3.12-slim",
            "sh", "-c", cmd,
        ]
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, errors="replace",
                timeout=self.timeout if timeout is None else timeout,
                env=scrub_env(),
            )
        except subprocess.TimeoutExpired:
            return ExecResult(exit_code=124, stdout="", stderr="docker timeout")
        return ExecResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def _e2b_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    def _e2b_create(self, client) -> tuple[str | None, int]:
        """Create one e2b sandbox; returns ``(id, status_code)``."""
        from ..governed_http import admit_client_request

        admit_client_request(client, "https://api.e2b.dev/sandboxes")
        sb = client.post(
            "https://api.e2b.dev/sandboxes",
            headers=self._e2b_headers(),
            json={"template": self.image, "network": self._e2b_network_config()},
        )
        if sb.status_code >= 300:
            return None, sb.status_code
        return sb.json().get("id"), sb.status_code

    def _e2b_process(self, client, sb_id: str, cmd: str):
        from ..governed_http import admit_client_request

        admit_client_request(client, f"https://api.e2b.dev/sandboxes/{sb_id}/processes")
        return client.post(
            f"https://api.e2b.dev/sandboxes/{sb_id}/processes",
            headers=self._e2b_headers(),
            json={"cmd": cmd, "cwd": "/work"},
        )

    @staticmethod
    def _e2b_exec_result(run) -> ExecResult:
        data = run.json() if run.status_code < 300 else {}
        return ExecResult(
            exit_code=int(data.get("exitCode", 1)),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", "")
                      or (f"http {run.status_code}" if run.status_code >= 300 else ""),
        )

    def _exec_e2b(self, cmd: str, timeout: float | None = None) -> ExecResult:
        """Run on E2B's hosted Firecracker. Requires E2B_API_KEY."""
        try:
            import httpx
        except ImportError:
            return ExecResult(
                exit_code=127, stdout="",
                stderr=(
                    "E2B Firecracker requires httpx. Install: "
                    "pip install httpx"
                ),
            )
        # E2B API shape: POST /sandboxes -> {id};
        # POST /sandboxes/{id}/processes {cmd} -> {stdout,stderr,exitCode}.
        # Full lifecycle (start/poll/tear down) is in the e2b SDK; this
        # scaffold uses the raw REST.
        try:
            with httpx.Client(timeout=self.timeout if timeout is None else timeout) as client:
                if self.warm:
                    return self._exec_e2b_warm(client, cmd)
                sb_id, status = self._e2b_create(client)
                if sb_id is None:
                    return ExecResult(
                        exit_code=126, stdout="",
                        stderr=f"e2b sandbox create failed: {status}",
                    )
                # Tear the microVM down in a finally: if _e2b_process raises (a
                # transient ReadTimeout/ConnectError -- exactly the failures this
                # system retries), skipping the DELETE would orphan a *billable*
                # sandbox until E2B's idle TTL reaps it. The delete is best-effort
                # so a teardown failure never masks the real exec error.
                try:
                    run = self._e2b_process(client, sb_id, cmd)
                    return self._e2b_exec_result(run)
                finally:
                    try:
                        from ..governed_http import admit_client_request

                        admit_client_request(client, f"https://api.e2b.dev/sandboxes/{sb_id}")
                        client.delete(
                            f"https://api.e2b.dev/sandboxes/{sb_id}",
                            headers=self._e2b_headers(),
                        )
                    except Exception:  # noqa: BLE001 - cleanup must not raise
                        log.warning(
                            "e2b sandbox %s delete failed; relying on idle TTL",
                            sb_id,
                        )
        except Exception as e:
            return ExecResult(exit_code=125, stdout="", stderr=f"e2b error: {e}")

    def _exec_e2b_warm(self, client, cmd: str) -> ExecResult:
        """Exec against the kept-alive e2b sandbox, creating it on first use.

        A reused id that the API rejects (expired server-side) is recreated
        ONCE; the retried exec then runs in the fresh microVM. No delete here
        — :meth:`close` (or E2B's idle TTL) tears the sandbox down.
        """
        reused = self._warm_id is not None
        for attempt in (0, 1):
            if self._warm_id is None:
                sb_id, status = self._e2b_create(client)
                if sb_id is None:
                    return ExecResult(
                        exit_code=126, stdout="",
                        stderr=f"e2b sandbox create failed: {status}",
                    )
                self._warm_id = sb_id
                reused = False
            run = self._e2b_process(client, self._warm_id, cmd)
            if run.status_code >= 300 and reused and attempt == 0:
                log.info(
                    "e2b warm sandbox %s rejected exec (http %s); recreating once",
                    self._warm_id, run.status_code,
                )
                self._warm_id = None
                continue
            return self._e2b_exec_result(run)
        return ExecResult(  # pragma: no cover - loop always returns above
            exit_code=125, stdout="", stderr="e2b warm exec failed")

    def close(self) -> None:
        """Tear down the warm e2b microVM, if any. Idempotent; never raises.

        On failure the id is still dropped — E2B's server-side idle TTL is the
        reaper of last resort (logged so the operator can see it).
        """
        sb_id, self._warm_id = self._warm_id, None
        if not sb_id:
            return
        try:
            import httpx
            with httpx.Client(timeout=min(self.timeout, 15.0)) as client:
                from ..governed_http import admit_client_request

                admit_client_request(client, f"https://api.e2b.dev/sandboxes/{sb_id}")
                client.delete(
                    f"https://api.e2b.dev/sandboxes/{sb_id}",
                    headers=self._e2b_headers(),
                )
        except Exception as e:
            log.warning(
                "e2b warm sandbox %s teardown failed: %s (E2B's idle TTL will reap it)",
                sb_id, e,
            )
