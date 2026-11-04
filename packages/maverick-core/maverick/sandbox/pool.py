"""Opt-in explicit sandbox policy handoff, never mutable backend reuse.

Park retires an idle lease and retains only immutable policy. Acquire consumes
that policy and constructs a fresh, verified, digest-pinned backend. Ordinary
runner teardown does not park: this adds daemon checks without avoiding guest
startup, so automatic lifecycle activation remains unqualified.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from .docker import DockerBackend
from .lease import BackendLease
from .local import container_user_args, scrub_env
from .podman import PodmanBackend

log = logging.getLogger(__name__)
POOL_MAX = 2
POOL_TTL_SECONDS = 600.0
_TRUE = {"1", "true", "yes", "on"}
# Docker reports "sha256:<hex>", Podman the bare 64-hex ID; each engine is
# handed back exactly the form it reported.
_DIGEST = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
# Reviewed schemas, deliberately not inferred from current dataclass fields:
# adding a backend field requires a new eligibility/policy decision.
_COMMON_STATE = frozenset({
    "workdir", "image", "timeout", "allow_network", "allow_root", "pids_limit",
    "memory", "cpus", "pending_cleanup", "_pool_lease",
})
_DOCKER_STATE = _COMMON_STATE | {"runtime", "reuse_container", "read_only_paths",
                                  "_read_only_mounts", "_warm_name"}


def cross_run_pool_enabled(sandbox_cfg: dict | None = None) -> bool:
    """The existing [sandbox] cross_run_pool knob, default OFF."""
    if sandbox_cfg is None:
        try:
            from ..config import load_config
            sandbox_cfg = (load_config() or {}).get("sandbox") or {}
        except Exception:  # pragma: no cover - config never blocks teardown
            return False
    raw = sandbox_cfg.get("cross_run_pool", False)
    return raw if isinstance(raw, bool) else str(raw).strip().lower() in _TRUE


@dataclass(frozen=True)
class SandboxPolicy:
    engine: str
    image: str
    digest: str | None
    allow_network: bool
    allow_root: bool
    pids_limit: int | None
    memory: str | None
    cpus: str | None
    runtime: str | None
    reuse_container: bool
    read_only_paths: tuple[str, ...]
    user_args: tuple[str, ...]
    client_environment_sha256: str


def _policy(engine, image, *, allow_network, allow_root, pids_limit, memory,
            cpus, runtime, reuse_container=False, read_only_paths=()) -> SandboxPolicy | None:
    if type(engine) is not str or engine not in {"docker", "podman"}:
        return None
    if type(image) is not str or not image.strip():
        return None
    if type(allow_network) is not bool or type(allow_root) is not bool:
        return None
    if pids_limit is not None and (type(pids_limit) is not int or pids_limit < 0):
        return None
    if any(value is not None and type(value) is not str for value in (memory, cpus, runtime)):
        return None
    if reuse_container is not False or read_only_paths != () or (engine == "podman" and runtime is not None):
        return None
    # Retain no client environment/credential values. A changed execution
    # environment invalidates a parked policy; each new exec still scrubs it.
    environment = json.dumps(scrub_env(), sort_keys=True, separators=(",", ":"))
    return SandboxPolicy(
        engine, image, None, allow_network, allow_root, pids_limit, memory, cpus,
        runtime, False, (), tuple(container_user_args(allow_root)),
        hashlib.sha256(environment.encode("utf-8")).hexdigest(),
    )


def _policy_of(sandbox: object) -> SandboxPolicy | None:
    if type(sandbox) is DockerBackend:
        engine, expected = "docker", _DOCKER_STATE
    elif type(sandbox) is PodmanBackend:
        engine, expected = "podman", _COMMON_STATE
    else:
        return None
    if set(vars(sandbox)) != expected:
        return None
    if (type(sandbox.pending_cleanup) is not dict or sandbox.pending_cleanup
            or type(sandbox._pool_lease) is not BackendLease):
        return None
    if engine == "docker" and (
        sandbox.reuse_container is not False or sandbox._warm_name is not None
        or sandbox.read_only_paths != () or sandbox._read_only_mounts != ()
    ):
        return None
    return _policy(engine, sandbox.image, allow_network=sandbox.allow_network,
                   allow_root=sandbox.allow_root, pids_limit=sandbox.pids_limit,
                   memory=sandbox.memory, cpus=sandbox.cpus,
                   runtime=getattr(sandbox, "runtime", None))


def _image_digest(engine: str, image: str) -> str | None:
    """An unavailable/malformed image ID is never replaced by a mutable tag."""
    try:
        proc = subprocess.run(
            [engine, "image", "inspect", "--format", "{{.Id}}", "--", image],
            capture_output=True, text=True, timeout=10, env=scrub_env(),
        )
        digest = (proc.stdout or "").strip()
        if proc.returncode == 0 and _DIGEST.fullmatch(digest):
            return digest
    except Exception as exc:
        log.debug("sandbox pool: image identity unavailable (%s)", type(exc).__name__)
    return None


def _same_controls(left: SandboxPolicy, right: SandboxPolicy) -> bool:
    # Tags may alias the same content. Actual admission compares the digest;
    # the cheap first pass compares only immutable execution controls.
    return replace(left, image="", digest=None) == replace(right, image="", digest=None)


@dataclass(frozen=True)
class _Entry:
    policy: SandboxPolicy
    parked_at: float


class SandboxPool:
    """Bounded policy transfers; no backend, workspace or credential retained."""

    def __init__(self, max_entries: int = POOL_MAX, ttl: float = POOL_TTL_SECONDS,
                 clock: Callable[[], float] = time.monotonic):
        self.max_entries = max(1, int(max_entries))
        self.ttl = float(ttl)
        if not math.isfinite(self.ttl) or self.ttl <= 0:
            raise ValueError("sandbox pool TTL must be finite and positive")
        self.clock = clock
        self._entries: list[_Entry] = []
        self._lock = threading.Lock()

    def _prune_locked(self) -> None:
        now = self.clock()
        self._entries = [e for e in self._entries if 0 <= now - e.parked_at < self.ttl]

    def park(self, sandbox: object) -> bool:
        """True transfers ownership once and permanently retires the old handle.

        Expiry or eviction never reactivates it. False leaves ownership with
        the caller. Cleanup remains permitted after a successful transfer.
        """
        lease = getattr(sandbox, "_pool_lease", None)
        if type(lease) is not BackendLease:
            return False
        policy = lease.inspect_idle(lambda: _policy_of(sandbox))
        if policy is None:
            return False
        digest = _image_digest(policy.engine, policy.image)
        if digest is None:
            return False
        with self._lock:
            self._prune_locked()
            # Probe outside the pool lock; recheck complete state/ownership
            # afterward. An execution or competing park may have started.
            if not lease.retire_if_idle(lambda: _policy_of(sandbox) == policy):
                return False
            if len(self._entries) >= self.max_entries:
                self._entries.pop(0)
            self._entries.append(_Entry(replace(policy, image=digest, digest=digest), self.clock()))
        return True

    def acquire(self, engine: str, image: str, *, workdir: Path | str,
                timeout: float, allow_network: object = False,
                allow_root: object = False, pids_limit: object = 512,
                memory: object = "4g", cpus: object = None,
                runtime: object = None, reuse_container: bool = False,
                read_only_paths: tuple[str, ...] = ()) -> object | None:
        """Consume one matching policy and construct a fresh verified lease.

        Invalid/unavailable policy or construction returns None; the caller
        then builds fresh normally, surfacing any real configuration error.
        """
        kwargs = dict(allow_network=allow_network, allow_root=allow_root,
                      pids_limit=pids_limit, memory=memory, cpus=cpus, runtime=runtime,
                      reuse_container=reuse_container, read_only_paths=read_only_paths)
        policy = _policy(engine, image, **kwargs)
        try:
            duration = float(timeout)
        except (TypeError, ValueError):
            return None
        if policy is None or not math.isfinite(duration) or duration <= 0:
            return None
        with self._lock:
            self._prune_locked()
            if not any(_same_controls(e.policy, policy) for e in self._entries):
                return None
        digest = _image_digest(engine, image)
        if digest is None or _policy(engine, image, **kwargs) != policy:
            return None
        wanted = replace(policy, image=digest, digest=digest)
        with self._lock:
            self._prune_locked()
            for index, entry in enumerate(self._entries):
                if entry.policy == wanted:
                    self._entries.pop(index)  # only one concurrent consumer
                    break
            else:
                return None
        return self._construct(wanted, workdir, duration)

    @staticmethod
    def _construct(policy: SandboxPolicy, workdir: Path | str, timeout: float):
        # Never redirect a previous handle. Normal construction rebuilds all
        # state and verifies the daemon. Run by ID so a later tag move cannot
        # change the selected image's content.
        try:
            kwargs = dict(workdir=Path(workdir), image=policy.digest, timeout=timeout,
                          allow_network=policy.allow_network, allow_root=policy.allow_root,
                          pids_limit=policy.pids_limit, memory=policy.memory, cpus=policy.cpus)
            if policy.engine == "docker":
                return DockerBackend(runtime=policy.runtime, **kwargs)
            return PodmanBackend(**kwargs)
        except Exception as exc:
            log.debug("sandbox pool: fresh lease unavailable (%s)", type(exc).__name__)
            return None

    def __len__(self) -> int:
        with self._lock:
            self._prune_locked()
            return len(self._entries)


_shared: SandboxPool | None = None
_shared_lock = threading.Lock()


def shared_pool() -> SandboxPool:
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = SandboxPool()
        return _shared


def reset_shared_pool() -> None:
    """Drop retained policies (tests); retired leases remain retired."""
    global _shared
    with _shared_lock:
        _shared = None


def park_at_run_end(sandbox: object) -> bool:
    """Explicit opt-in embedder hook; ordinary runner teardown does not call it."""
    return cross_run_pool_enabled() and shared_pool().park(sandbox)


__all__ = ["POOL_MAX", "POOL_TTL_SECONDS", "SandboxPolicy", "SandboxPool",
           "shared_pool", "reset_shared_pool", "park_at_run_end", "cross_run_pool_enabled"]
