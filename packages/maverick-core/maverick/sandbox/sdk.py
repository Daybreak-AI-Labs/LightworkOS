"""Sandbox SDK v2 — the formal backend contract.

v1 was duck typing: "anything with ``.exec(cmd) -> ExecResult``" — fine
in-tree, but a third party cannot ship a backend without forking, and a
subtly-wrong one (no timeout kwarg, wrong result shape) fails deep inside a
run. v2 makes the contract explicit and loadable:

* :class:`SandboxV2` — a ``runtime_checkable`` Protocol: ``workdir``,
  ``exec(cmd, timeout=None) -> ExecResult``-shaped result. Optional
  capabilities (``put_file``, ``close`` and workspace locality) are *declared*:
  :func:`capabilities` reports what a backend supports.
* :func:`conformance` — static checks a backend class/instance against the
  contract (presence, call signature, timeout kwarg) and returns the list of
  violations; ``[]`` means conformant. No command is executed.
* **Entry-point loading** — ``[sandbox] backend = "ep:<name>"`` resolves the
  ``maverick.sandboxes`` entry-point group, instantiates the factory with
  ``(workdir, timeout, **[sandbox] options)``, and **refuses** a
  non-conformant backend (a broken sandbox must never silently fall through
  to unsandboxed local execution).

``SDK_VERSION = 2``; in-tree backends conform as-is (v2 formalizes v1's
shape — no behavior change).
"""
from __future__ import annotations

import inspect
import logging
import math
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger(__name__)

SDK_VERSION = 2

# Optional capability methods a backend MAY provide; capabilities() reports
# which are present so callers feature-detect instead of try/except-ing.
_OPTIONAL = ("put_file", "close", "stop", "exec_authenticated_tests")


@dataclass(frozen=True)
class LegacyExecutionPolicy:
    """Backend-author declaration of a physically enforced fixed execution cap.

    Only an exec(cmd) implementation that owns and enforces this finite cap may
    advertise ``legacy_execution_policy``. This is a trusted backend contract,
    not a claim that inspecting Python signatures proves cancellation support.
    """

    max_seconds: float

    def __post_init__(self):
        if isinstance(self.max_seconds, bool) or not isinstance(self.max_seconds, (int, float)) or not math.isfinite(self.max_seconds) or self.max_seconds <= 0:
            raise ValueError("legacy execution cap must be finite and positive")


class LegacySandboxAdapter:
    """Adapt only an explicitly bounded legacy owner, never a timeout thread."""

    def __init__(self, backend):
        policy = getattr(backend, "legacy_execution_policy", None)
        if not isinstance(policy, LegacyExecutionPolicy):
            raise TypeError("legacy sandbox requires an explicit finite legacy_execution_policy")
        execute = getattr(backend, "exec", None)
        if not callable(execute):
            raise TypeError("legacy sandbox must implement exec(cmd)")
        try:
            inspect.signature(execute).bind("command")
        except (TypeError, ValueError) as error:
            raise TypeError("legacy sandbox must bind exec(cmd) before dispatch") from error
        self._backend = backend
        self._policy = policy
        self._execute = execute

    def __getattr__(self, name):
        return getattr(self._backend, name)

    def exec(self, cmd: str, timeout: float | None = None):
        # A new policy or method needs fresh admission. Do not change a shared
        # backend timeout or infer support from an exception after invocation.
        current = getattr(self._backend, "exec", None)
        if (getattr(self._backend, "legacy_execution_policy", None) is not self._policy
                or getattr(current, "__self__", None) is not getattr(self._execute, "__self__", None)
                or getattr(current, "__func__", current) is not getattr(self._execute, "__func__", self._execute)):
            raise RuntimeError("legacy sandbox execution policy changed; readmit the backend")
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
                raise ValueError("sandbox timeout must be finite and positive")
            if self._policy.max_seconds > timeout:
                raise ValueError("legacy sandbox cannot enforce the shorter requested timeout")
        return self._execute(cmd)


def execution_callable(backend):
    """Choose the declared call shape before any sandbox command is invoked."""
    execute = getattr(backend, "exec", None)
    if not callable(execute):
        raise TypeError("configured sandbox must implement exec(cmd, timeout=None)")
    try:
        inspect.signature(execute).bind("command", timeout=1.0)
    except (TypeError, ValueError):
        if not isinstance(getattr(backend, "legacy_execution_policy", None), LegacyExecutionPolicy):
            raise TypeError("configured sandbox must support a timeout or declare a finite legacy execution policy") from None
        return LegacySandboxAdapter(backend).exec
    return execute


@runtime_checkable
class SandboxV2(Protocol):
    """The minimal contract every execution backend must satisfy."""

    workdir: Any

    def exec(self, cmd: str, timeout: float | None = None) -> Any: ...


def capabilities(backend: Any) -> set[str]:
    """Return execution, declared workspace and optional method capabilities."""
    caps = {"exec"}
    if workdir_is_local(backend):
        caps.add("local_workdir")
    for name in _OPTIONAL:
        if callable(getattr(backend, name, None)):
            caps.add(name)
    return caps


def workdir_is_local(backend: Any) -> bool:
    """Whether local workspace tools may use the backend's workdir path.

    Existing SDK v2 backends default to local for compatibility. Backends
    whose workdir lives on another host must explicitly declare
    ``workdir_is_local = False``; this declaration is inherited by subclasses.
    Treat invalid declarations as unavailable rather than guessing.
    """
    return getattr(backend, "workdir_is_local", True) is True


def conformance(backend: Any) -> list[str]:
    """Check ``backend`` (class or instance) against the v2 contract.

    Static only — nothing is executed. Returns violations; ``[]`` == OK.
    """
    problems: list[str] = []
    exec_fn = getattr(backend, "exec", None)
    if not callable(exec_fn):
        problems.append("missing exec(cmd, timeout=None)")
    else:
        try:
            sig = inspect.signature(exec_fn)
            params = [p for p in sig.parameters.values()
                      if p.name not in ("self", "cls")]
            names = [p.name for p in params]
            if not names:
                problems.append("exec() takes no command argument")
            accepts_timeout = (
                "timeout" in names
                or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params)
            )
            if not accepts_timeout:
                problems.append(
                    "exec() must accept a per-call timeout kwarg "
                    "(timeout=None) — tools plumb longer caps for test runs")
            elif names:
                try:
                    sig.replace(parameters=params).bind("command", timeout=1.0)
                except TypeError:
                    problems.append("exec() must bind a command and per-call timeout keyword")
        except (TypeError, ValueError):  # builtins/C callables
            problems.append("exec() signature is not introspectable")
    if not _declares_workdir(backend):
        problems.append("missing workdir attribute")
    return problems


def _declares_workdir(backend: Any) -> bool:
    """Instance attr, class attr/property, dataclass annotation, or an
    ``__init__(workdir=...)`` parameter all count as declaring ``workdir``
    (a class can't be probed for instance attributes without instantiating,
    which may need docker/ssh)."""
    if hasattr(backend, "workdir"):
        return True
    if "workdir" in getattr(backend, "__annotations__", {}):
        return True
    init = getattr(backend, "__init__", None)
    if callable(init):
        try:
            return "workdir" in inspect.signature(init).parameters
        except (TypeError, ValueError):
            return False
    return False


def _sandbox_entry_points() -> list[Any]:
    from importlib import metadata

    eps = metadata.entry_points()
    return list(
        eps.select(group="maverick.sandboxes")
        if hasattr(eps, "select")
        else eps.get("maverick.sandboxes", [])
    )


def installed_entry_point_names() -> tuple[str, ...]:
    """Installed third-party sandbox names without loading vendor code."""
    return tuple(sorted({str(ep.name) for ep in _sandbox_entry_points()}))


def load_entry_point_backend(name: str, *, workdir, timeout: float,
                             options: dict | None = None) -> Any:
    """Resolve + instantiate a third-party backend from ``maverick.sandboxes``.

    The factory is called ``factory(workdir=..., timeout=..., **options)``.
    A missing entry point or a non-conformant backend raises — a sandbox the
    operator explicitly selected must never silently degrade to something
    else (least of all unsandboxed local exec).
    """
    group = _sandbox_entry_points()
    matches = [ep for ep in group if ep.name == name]
    if not matches:
        available = sorted(ep.name for ep in group)
        raise RuntimeError(
            f"sandbox entry point {name!r} not found "
            f"(installed: {available or 'none'}). Install the backend package "
            "or fix [sandbox] backend.")
    factory = matches[0].load()
    backend = factory(workdir=workdir, timeout=timeout, **(options or {}))
    if isinstance(getattr(backend, "legacy_execution_policy", None), LegacyExecutionPolicy):
        # The fixed cap must satisfy this run's requested policy before the
        # entry point is admitted, even if no command is ever dispatched.
        adapter = LegacySandboxAdapter(backend)
        if adapter._policy.max_seconds > timeout:
            raise ValueError("legacy sandbox cannot enforce the shorter requested timeout")
        backend = adapter
    problems = conformance(backend)
    if problems:
        raise RuntimeError(
            f"sandbox backend {name!r} does not conform to sandbox SDK v"
            f"{SDK_VERSION}: " + "; ".join(problems))
    log.info("loaded external sandbox %r (capabilities: %s)",
             name, sorted(capabilities(backend)))
    return backend


__all__ = [
    "SDK_VERSION",
    "SandboxV2",
    "LegacyExecutionPolicy",
    "LegacySandboxAdapter",
    "execution_callable",
    "capabilities",
    "workdir_is_local",
    "conformance",
    "installed_entry_point_names",
    "load_entry_point_backend",
]
