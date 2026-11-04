"""Modal sandbox backend.

Runs agent shell commands in `Modal Sandboxes <https://modal.com/docs/guide/sandbox>`_
— ephemeral cloud containers with hard resource limits — so a Lightwork on a
laptop can execute untrusted work on burstable remote compute without running
its own cluster. Satisfies sandbox SDK v2 (``workdir`` + ``exec(cmd,
timeout=None)``); select with ``[sandbox] backend = "modal"``.

A Cloudflare Workers backend is **declined for shell semantics**: Workers run
JS/WASM request handlers, not processes — there is no honest
``exec("pytest ...")`` on that platform. The Workers deployment story
is covered where it fits: the self-hosted relay reference (a Worker-shaped
HTTP shim) and ``wasm_run`` (WASI module execution). A "sandbox backend" that
silently downgraded shell to something else would violate the contract.

``modal`` is the ``[modal]`` extra, imported lazily; per-call sandboxes are
created with the configured image/cpu/memory/timeout and torn down after the
command. Modal does not currently expose a per-sandbox no-egress switch here,
so ``allow_network=false`` fails closed instead of silently running with
provider-default networking. The Modal client object is injectable so tests run
offline.
"""
from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_IMAGE = "python:3.12-slim"


class ModalBackend:
    """Execute commands in ephemeral Modal sandboxes (one per exec)."""

    # The host path is not transferred into the ephemeral filesystem.
    workdir_is_local = False

    def __init__(self, workdir: Path | str = ".", *, image: str = _DEFAULT_IMAGE,
                 timeout: float = 60.0, cpu: float | None = None,
                 memory_mb: int | None = None, allow_network: bool = False,
                 app_name: str = "maverick-sandbox", client=None):
        self.workdir = Path(workdir)
        self.image = image
        self.timeout = timeout
        self.cpu = cpu
        self.memory_mb = memory_mb
        self.allow_network = allow_network
        self.app_name = app_name
        self._client = client  # injected in tests; lazy real client otherwise

    def _modal(self):
        if self._client is not None:
            return self._client
        try:
            import modal
        except ImportError as e:
            raise RuntimeError(
                "Modal sandbox backend needs the modal package. "
                "Install: python -m pip install -e './packages/maverick-core[modal]' and run "
                "`modal token new` once."
            ) from e
        self._client = modal
        return modal

    def exec(self, cmd: str, timeout: float | None = None):
        """Run ``cmd`` in a fresh Modal sandbox; return an ExecResult-shaped
        object (stdout / stderr / exit_code)."""
        from .local import ExecResult
        effective = self.timeout if timeout is None else float(timeout)
        if not self.allow_network:
            return ExecResult(
                stdout="",
                stderr=(
                    "networking is disabled for modal backend "
                    "(allow_network=false), but Modal sandboxes cannot "
                    "self-enforce no-network execution. Set "
                    "[sandbox] allow_network = true to acknowledge and use "
                    "Modal provider-default networking."
                ),
                exit_code=2,
            )
        try:
            modal = self._modal()
            app = modal.App.lookup(self.app_name, create_if_missing=True)
            kwargs = {
                "image": modal.Image.from_registry(self.image),
                "app": app,
                "timeout": max(1, int(effective)),
            }
            if self.cpu:
                kwargs["cpu"] = self.cpu
            if self.memory_mb:
                kwargs["memory"] = self.memory_mb
            sb = modal.Sandbox.create("sh", "-c", cmd, **kwargs)
            try:
                sb.wait()
                stdout = sb.stdout.read() if hasattr(sb.stdout, "read") else str(sb.stdout)
                stderr = sb.stderr.read() if hasattr(sb.stderr, "read") else str(sb.stderr)
                code = sb.returncode if sb.returncode is not None else 1
            finally:
                try:
                    sb.terminate()
                except Exception:  # pragma: no cover -- already finished
                    pass
            return ExecResult(stdout=stdout[-8000:], stderr=stderr[-2000:],
                              exit_code=int(code))
        except Exception as e:
            # Surfaced as a failed command, mirroring how other backends report
            # infrastructure errors rather than crashing the agent loop.
            log.warning("modal sandbox exec failed: %s", e)
            return ExecResult(stdout="", stderr=f"modal sandbox error: {e}",
                              exit_code=125)


__all__ = ["ModalBackend"]
