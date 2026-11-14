"""Execution backends.

Local (subprocess), Docker (throwaway containers), SSH (remote host
via system ssh binary). All implement ``.exec(cmd) -> ExecResult``
so the agent loop is backend-agnostic.

The agent never instantiates a backend directly -- always go through
``build_sandbox()`` so the [sandbox] config section is the single
source of truth.
"""
from __future__ import annotations

import importlib.util
import logging
import os
import shutil
import subprocess
from pathlib import Path, PurePosixPath

from ..sandbox_names import BUILTIN_SANDBOX_BACKENDS
from .devcontainer import DevcontainerBackend
from .docker import DockerBackend
from .firecracker import FirecrackerBackend
from .gvisor import GVisorRuntimeValidationError, validate_docker_gvisor_runtime
from .kubernetes import KubernetesBackend
from .kubernetes_authority import deployment_isolation_mode
from .local import ExecResult, LocalBackend
from .podman import PodmanBackend
from .sdk import SDK_VERSION, SandboxV2
from .ssh import SSHBackend

__all__ = [
    "BUILTIN_SANDBOX_BACKENDS",
    "LocalBackend",
    "DockerBackend",
    "PodmanBackend",
    "DevcontainerBackend",
    "KubernetesBackend",
    "FirecrackerBackend",
    "SSHBackend",
    "ExecResult",
    "build_sandbox",
    "fs_is_host_visible",
    "container_backend_required",
    "SandboxPolicyError",
    "SDK_VERSION",
    "SandboxV2",
]

log = logging.getLogger(__name__)

Sandbox = (
    LocalBackend | DockerBackend | PodmanBackend | DevcontainerBackend
    | KubernetesBackend | FirecrackerBackend | SSHBackend
)


# Default container image per coding language. When ``[sandbox] image`` isn't
# set explicitly, build_sandbox picks one from the language hint (``[sandbox]
# language`` or the ``MAVERICK_LANGUAGE`` env var -- the same signal
# coding_mode threads through evaluate_candidate/run_failing_tests) so a
# Rust/Go/JS task lands in a container that can actually run ``cargo test`` /
# ``go test`` / the JS runner, instead of python:3.12-slim with no toolchain.
_DEFAULT_IMAGE = "python:3.12-slim"
_IMAGE_BY_LANGUAGE = {
    "python":     "python:3.12-slim",
    "py":         "python:3.12-slim",
    "rust":       "rust:1-slim",
    "go":         "golang:1-bookworm",
    "golang":     "golang:1-bookworm",
    "javascript": "node:22-bookworm-slim",
    "typescript": "node:22-bookworm-slim",
    "js":         "node:22-bookworm-slim",
    "ts":         "node:22-bookworm-slim",
    "node":       "node:22-bookworm-slim",
    "ruby":       "ruby:3-slim",
    "java":       "eclipse-temurin:21-jdk",
    "kotlin":     "eclipse-temurin:21-jdk",
}


_TRUE_CONFIG_VALUES = {"1", "true", "yes", "on"}
_FALSE_CONFIG_VALUES = {"0", "false", "no", "off", ""}


def _config_bool(value: object, default: bool = False) -> bool:
    """Parse hand-edited/interpolated config booleans without string truthiness.

    TOML booleans arrive as ``bool``, but quoted values and ``${ENV}``
    interpolation arrive as strings.  Using ``bool("false")`` would enable
    security-sensitive toggles such as Docker network/root access, so accept
    common boolean spellings explicitly and fall back to the supplied default
    for unrecognized values.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUE_CONFIG_VALUES:
            return True
        if normalized in _FALSE_CONFIG_VALUES:
            return False
        log.warning("invalid sandbox boolean %r; using default %s", value, default)
        return default
    if isinstance(value, int):
        return bool(value)
    log.warning("invalid sandbox boolean %r; using default %s", value, default)
    return default


def _resolve_image(full_cfg: dict) -> str:
    """Pick the container image for the container-based backends.

    Precedence: explicit ``[sandbox] image`` > language toolchain default
    (from ``[sandbox] language`` or the ``MAVERICK_LANGUAGE`` env hint) >
    ``python:3.12-slim``. An unknown language falls back to the Python image
    rather than guessing, so behaviour is unchanged unless a language is set.
    """
    explicit = full_cfg.get("image")
    if explicit:
        return explicit
    lang_value = full_cfg.get("language") or os.environ.get("MAVERICK_LANGUAGE", "")
    if not isinstance(lang_value, str):
        return _DEFAULT_IMAGE
    lang = lang_value.strip().lower()
    return _IMAGE_BY_LANGUAGE.get(lang, _DEFAULT_IMAGE)


_LOCAL_WARNING_EMITTED = False


def fs_is_host_visible(sandbox: object | None) -> bool:
    """Whether files the sandbox writes are visible to THIS (host) process.

    True when there is no sandbox (commands fall back to a host subprocess) or
    the backend runs against the host filesystem (``LocalBackend``, which sets
    ``host_visible_fs = True``). Container / remote backends (docker, podman,
    kubernetes, firecracker, ssh, modal) execute in a separate filesystem
    namespace, so a host-side ``Path.exists()`` on an output path is meaningless
    there -- callers should report the path rather than stat it. Unknown
    backends default to NOT host-visible, the conservative choice: a tool then
    states it can't verify instead of emitting a false "output missing" warning.
    """
    if sandbox is None:
        return True
    return bool(getattr(sandbox, "host_visible_fs", False))


class SandboxPolicyError(RuntimeError):
    """Raised when the configured sandbox backend violates deployment policy
    (e.g. the unsandboxed ``local`` backend under enterprise/require-container)."""


def _validated_gvisor_runtime(value: object) -> str:
    """Validate the configured name against Docker's runtime metadata."""
    try:
        return validate_docker_gvisor_runtime(value)
    except GVisorRuntimeValidationError as exc:
        raise SandboxPolicyError(str(exc)) from exc
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        raise SandboxPolicyError(
            "cannot validate sandbox backend=gvisor because Docker's runtime "
            f"registry probe failed: {exc}"
        ) from exc


def _config_truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _container_backend_required(full_cfg: dict | None = None) -> bool:
    """Whether a container sandbox backend is mandatory (so ``local`` is refused).

    True when ``MAVERICK_REQUIRE_CONTAINER_BACKEND`` is set, ``[sandbox]
    require_container = true``, or enterprise mode is on. Off by default so
    single-tenant/dev installs keep the (warned) local backend.
    """
    try:
        deployment_required = deployment_isolation_mode() is not None
    except ValueError:
        # Invalid deployment modes still require isolation; construction rejects
        # them through the same parser before any backend can be selected.
        return True
    if deployment_required or _config_truthy_env("MAVERICK_REQUIRE_CONTAINER_BACKEND"):
        return True
    if full_cfg and _config_bool(full_cfg.get("require_container"), False):
        return True
    try:
        from ..enterprise import enterprise_enabled
        return bool(enterprise_enabled())
    except Exception:  # pragma: no cover -- never block startup on a lookup error
        return False


def container_backend_required() -> bool:
    """Public, config-aware predicate: is a container sandbox mandatory here?

    Loads ``[sandbox]`` itself and passes it to :func:`_container_backend_required`,
    so ``[sandbox] require_container = true`` in ``config.toml`` is honoured — the
    bare no-arg helper only sees the env var / enterprise mode because
    ``build_sandbox`` is where config is normally loaded. Callers outside
    ``build_sandbox`` (e.g. the self-modify eval isolation gate) MUST use this,
    not the private helper, or the config knob silently no-ops (fail-open)."""
    try:
        from ..config import load_config
        full_cfg = (load_config() or {}).get("sandbox", {})
    except Exception:  # pragma: no cover -- config never blocks the predicate
        full_cfg = None
    return _container_backend_required(full_cfg)


def _resolve_local_under_policy(chosen: str, full_cfg: dict | None) -> str:
    """Container-default under enterprise: when ``chosen == "local"`` but a
    container backend is required (enterprise mode / require-container), upgrade
    ``local`` to an available container backend (docker, then podman) instead of
    running ``shell=True`` on the host. Only when NO container runtime is
    installed do we refuse, fail-closed -- we never silently fall back to the
    unsandboxed host. Returns ``chosen`` unchanged when the policy is inactive or
    the backend isn't ``local``."""
    if chosen != "local" or not _container_backend_required(full_cfg):
        return chosen
    auto = _default_container_backend()
    if auto is None:
        raise SandboxPolicyError(
            "refusing the unsandboxed 'local' sandbox backend: enterprise / "
            "require-container policy is active but [sandbox] backend = "
            "\"local\" runs shell=True on the host with no isolation, and no "
            "container runtime (docker / podman) was found to default to. "
            "Install docker or podman, or set [sandbox] backend to a "
            "container backend (gvisor / kubernetes / firecracker)."
        )
    log.warning(
        "enterprise/require-container policy is active and [sandbox] backend is "
        "'local' (no host isolation); defaulting to the available '%s' container "
        "backend. Pin [sandbox] backend explicitly to silence this.", auto,
    )
    return auto


def _default_container_backend() -> str | None:
    """The container backend to default to when ``local`` is refused: the first
    of ``docker`` / ``podman`` whose CLI is on PATH, or ``None`` if neither is
    installed (caller then fails closed rather than running on the host)."""
    for backend in ("docker", "podman"):
        if shutil.which(backend):
            return backend
    return None


def _warn_local_unsandboxed() -> None:
    """Warn (once per process) that the agent will run model-generated shell
    directly on the host with no container isolation.

    The local backend executes ``shell=True`` commands on this machine, so a
    prompt-injected agent gets host code execution. The Shield is the only
    screen, and it is fail-open (optional dependency) -- escalate the message
    when it isn't installed. Suppress with MAVERICK_SUPPRESS_SANDBOX_WARNING=1
    (e.g. when the operator has deliberately accepted host execution, or for
    quiet test runs). The wizard already defaults real installs to a container
    backend when one is available; this catches CLI / embedder / hand-edited
    configs that land on the unisolated default.
    """
    global _LOCAL_WARNING_EMITTED
    if _LOCAL_WARNING_EMITTED:
        return
    if os.environ.get("MAVERICK_SUPPRESS_SANDBOX_WARNING") == "1":
        _LOCAL_WARNING_EMITTED = True
        return
    _LOCAL_WARNING_EMITTED = True
    shield_present = importlib.util.find_spec("maverick_shield") is not None
    msg = (
        "sandbox backend is 'local': model-generated shell runs directly on "
        "this host with NO container isolation. A prompt-injected agent can "
        "execute arbitrary code here. For untrusted goals, set [sandbox] "
        "backend = \"docker\" (or podman) in ~/.maverick/config.toml."
    )
    if not shield_present:
        msg += (
            " maverick-shield is NOT installed, so tool calls are not screened "
            "either (fail-open). This is the least-protected configuration."
        )
    log.warning("%s Silence with MAVERICK_SUPPRESS_SANDBOX_WARNING=1.", msg)


def _degrade_to_local(chosen: str, full_cfg: dict, wd: Path, timeout: float):
    """Build the unsandboxed LocalBackend for an unrecognized backend name --
    or refuse it under the require-container policy.

    The top-of-``build_sandbox`` gate catches an explicit ``backend="local"``;
    this catches the *other* path to a host shell -- a typo'd / unsupported
    backend that matched no known backend and would otherwise silently degrade.
    Both must fail closed under enterprise / require-container, else a config
    typo (``"dcoker"``) quietly runs untrusted agent code on the host.
    """
    if _container_backend_required(full_cfg):
        raise SandboxPolicyError(
            f"refusing to fall back to the unsandboxed 'local' sandbox "
            f"backend: configured backend {chosen!r} matched no known backend "
            f"and enterprise / require-container policy is active. Fix the "
            f"[sandbox] backend value (known: docker, podman, gvisor, "
            f"devcontainer, kubernetes, firecracker, ssh)."
        )
    log.warning(
        "unrecognized sandbox backend %r; falling back to local with NO "
        "container isolation. Known backends: docker, podman, "
        "devcontainer, kubernetes, firecracker, ssh, local.",
        chosen,
    )
    _warn_local_unsandboxed()
    return LocalBackend(workdir=wd, timeout=timeout)


def _read_only_paths_for_backend(chosen: str, full_cfg: dict | None):
    """Return immutable mounts only for backends that actually enforce them."""
    paths = (full_cfg or {}).get("read_only_paths") or ()
    if paths and chosen not in {"docker", "gvisor"}:
        raise ValueError(
            "sandbox.read_only_paths requires backend='docker' or 'gvisor'; "
            f"backend={chosen!r} cannot enforce immutable mounts"
        )
    return paths


def _deployment_policy(cfg, full_cfg, backend, sandbox_config):
    from .kubernetes_authority import deployment_kubernetes_config
    try:
        deployment = deployment_kubernetes_config()
    except ValueError as exc:
        raise SandboxPolicyError(str(exc)) from exc
    if deployment is None:
        return cfg, full_cfg
    if backend is not None and str(backend).strip().lower() != "kubernetes":
        raise SandboxPolicyError("Production execution is pinned to the separate Kubernetes executor")
    if sandbox_config is not None and str(sandbox_config.get("backend", "local")).strip().lower() != "kubernetes":
        raise SandboxPolicyError("The pinned evaluator policy does not match the production Kubernetes executor")
    return {**cfg, **deployment}, {**(full_cfg or {}), **deployment}


def _offline_policy(full_cfg: dict | None, backend) -> dict | None:
    """The network policy's no-network rule for the work area.

    When ``[security] network_policy`` is not open, or ``[sandbox]
    network_policy = "deny-all"``, commands get no network: container and
    micro-machine backends start without it (the Kubernetes backend verifies
    its deny-all NetworkPolicy first), ``local`` must become a container (or
    is refused when none is installed), and backends that cannot be kept
    offline are refused. Only ever narrows; open leaves settings untouched.
    """
    from .network_policy import offline_reason, work_area_offline

    if not work_area_offline():
        return full_cfg
    chosen = str(backend or "local").strip().lower()
    if chosen == "ssh" or chosen.startswith("ep:"):
        reason = offline_reason() or "the network policy blocks internet access for commands"
        raise SandboxPolicyError(
            f"{reason}, but the {chosen!r} work area cannot be kept offline; "
            "choose a container work area")
    return {**(full_cfg or {}), "allow_network": False, "network": "egress-deny",
            "require_container": True}


def build_sandbox(
    workdir: str | Path | None = None,
    backend: str | None = None,
    *,
    sandbox_config: dict | None = None,
) -> Sandbox:
    """Construct the configured sandbox backend.

    Reads ``[sandbox]`` from ``~/.maverick/config.toml``; either argument
    overrides the corresponding config value. Under containment mode
    (:mod:`maverick.containment`) the backend gets no network and, except for
    remote and project-folder backends, a throwaway 0700 folder that lives as
    long as the returned backend.
    """
    from ..containment import active_profile

    held: list = []
    box = _build_sandbox(workdir, backend, sandbox_config=sandbox_config,
                         contained=active_profile(), held=held)
    for ephemeral in held:
        try:
            box._containment_workdir = ephemeral  # type: ignore[attr-defined]
        except AttributeError:  # pragma: no cover -- slotted third-party backend
            _EPHEMERAL_WORKDIRS.append(ephemeral)
    return box


# Throwaway folders of backends that cannot carry one (kept until exit).
_EPHEMERAL_WORKDIRS: list = []


def _contain(contained, chosen: str, full_cfg: dict | None, wd: Path, held: list):
    """Containment's changes to one backend's settings: no network, and a
    throwaway folder unless the folder is remote or a project's own."""
    if contained is None:
        return full_cfg, wd
    if contained.no_network:
        if chosen == "ssh" or chosen.startswith("ep:"):
            # Neither backend reads allow_network; refuse, as _offline_policy does.
            raise SandboxPolicyError(
                "containment blocks internet access for commands, but the "
                f"{chosen!r} work area cannot be kept offline; choose a container work area")
        full_cfg = {**(full_cfg or {}), "allow_network": False, "network": "egress-deny"}
    if contained.ephemeral_workspace and chosen not in ("ssh", "devcontainer"):
        from ..containment import make_ephemeral_workdir

        ephemeral = make_ephemeral_workdir()
        held.append(ephemeral)
        wd = ephemeral.path
    return full_cfg, wd


def _build_sandbox(
    workdir: str | Path | None,
    backend: str | None,
    *,
    sandbox_config: dict | None,
    contained,
    held: list,
) -> Sandbox:
    if sandbox_config is not None:
        # Privileged callers (DGM) pass an already scope-pinned policy snapshot
        # so request-tenant config cannot swap the evaluator after preflight.
        full_cfg = dict(sandbox_config) if isinstance(sandbox_config, dict) else {}
        cfg = full_cfg
    else:
        try:
            from ..config import get_sandbox
            cfg = get_sandbox()
            full_cfg = None
            try:
                from ..config import load_config
                full_cfg = load_config().get("sandbox", {})
            except Exception:
                full_cfg = {}
        except Exception:
            cfg = {}
            full_cfg = {}

    cfg, full_cfg = _deployment_policy(cfg, full_cfg, backend, sandbox_config)
    full_cfg = _offline_policy(full_cfg, backend or cfg.get("backend"))

    # Normalize the backend selector: it comes from user-typed TOML (or a CLI
    # flag) and is matched case-sensitively against the literals below, so
    # "Docker" / " docker " would otherwise fall through to the unsandboxed
    # local backend -- silently giving NO container isolation to a user who
    # explicitly asked for it. Lowercase + strip so the configured backend
    # actually applies.
    chosen = str(backend or cfg.get("backend") or "local").strip().lower()
    # Enterprise gate (container-default under enterprise): when 'local' is
    # chosen but a container backend is required, upgrade to an available one or
    # fail closed. Extracted to keep build_sandbox under the complexity cap.
    chosen = _resolve_local_under_policy(chosen, full_cfg)
    read_only_paths = _read_only_paths_for_backend(chosen, full_cfg)
    wd = Path(workdir or cfg.get("workdir", str(Path.cwd()))).expanduser()
    full_cfg, wd = _contain(contained, chosen, full_cfg, wd, held)
    # Coerce defensively: [sandbox] timeout is hand-editable, and a non-numeric
    # ("fast") or non-positive value would otherwise raise here and crash the
    # kernel at startup -- config.py's contract is to fall back to defaults on
    # bad config, not abort. Warn + default so a typo doesn't take the agent down.
    try:
        timeout = float(cfg.get("timeout", 60))
        if timeout <= 0:
            raise ValueError("non-positive")
    except (TypeError, ValueError):
        log.warning("invalid [sandbox] timeout %r; using 60s", cfg.get("timeout"))
        timeout = 60.0

    if chosen == "modal":
        # Ephemeral Modal cloud sandboxes ([modal] extra). A Cloudflare
        # Workers backend is declined for shell semantics (see
        # sandbox/modal_backend.py docstring).
        from .modal_backend import ModalBackend
        return ModalBackend(
            workdir=wd, image=_resolve_image(full_cfg), timeout=timeout,
            cpu=full_cfg.get("cpus"), memory_mb=full_cfg.get("memory_mb"),
            allow_network=_config_bool(full_cfg.get("allow_network"), False),
        )

    if chosen.startswith("ep:"):
        # Sandbox SDK v2: a third-party backend from the maverick.sandboxes
        # entry-point group. Conformance-checked at load; raises (never
        # silently falls back to unsandboxed local) on a broken backend.
        from .sdk import load_entry_point_backend
        options = full_cfg.get("options") or {}
        return load_entry_point_backend(
            chosen[3:].strip(), workdir=wd, timeout=timeout,
            options=options if isinstance(options, dict) else {},
        )

    if chosen in ("docker", "gvisor"):
        image = _resolve_image(full_cfg)
        # gVisor is Docker with the runsc runtime; reuse every Docker knob and
        # just swap the runtime. A configured [sandbox] runtime overrides the
        # default only when Docker's registration metadata identifies an approved
        # runsc name/path or the official containerd runsc runtime type.
        runtime = (
            _validated_gvisor_runtime(full_cfg.get("runtime"))
            if chosen == "gvisor"
            else None
        )
        kwargs = dict(
            allow_network=_config_bool(full_cfg.get("allow_network"), False),
            pids_limit=full_cfg.get("pids_limit", 512),
            memory=full_cfg.get("memory", "4g"),
            cpus=full_cfg.get("cpus"),
            allow_root=_config_bool(full_cfg.get("allow_root"), False),
        )
        # Opt-in cross-run pooling (default OFF -> this block is dead and
        # behavior is unchanged): consume an explicitly transferred policy
        # into a fresh backend with the same image digest + security flags.
        # Ordinary runner teardown does not park. Docker's reuse_container is the WITHIN-run
        # warm knob and is not cross-run pool eligible because it keeps a live
        # container mounted to the run workdir.
        reuse_container = _config_bool(full_cfg.get("reuse_container"), False)
        if (
            _config_bool(full_cfg.get("cross_run_pool"), False)
            and not reuse_container
            and not read_only_paths
        ):
            from . import pool as _pool
            pooled = _pool.shared_pool().acquire(
                "docker", image, workdir=wd, timeout=timeout,
                runtime=runtime, **kwargs)
            if pooled is not None:
                return pooled
        return DockerBackend(
            workdir=wd, image=image, timeout=timeout, runtime=runtime,
            reuse_container=reuse_container,
            read_only_paths=read_only_paths,
            **kwargs,
        )
    if chosen == "podman":
        image = _resolve_image(full_cfg)
        kwargs = dict(
            allow_network=_config_bool(full_cfg.get("allow_network"), False),
            pids_limit=full_cfg.get("pids_limit", 512),
            memory=full_cfg.get("memory", "4g"),
            cpus=full_cfg.get("cpus"),
            allow_root=_config_bool(full_cfg.get("allow_root"), False),
        )
        if _config_bool(full_cfg.get("cross_run_pool"), False):
            from . import pool as _pool
            pooled = _pool.shared_pool().acquire(
                "podman", image, workdir=wd, timeout=timeout, **kwargs)
            if pooled is not None:
                return pooled
        return PodmanBackend(
            workdir=wd, image=image, timeout=timeout, **kwargs,
        )
    if chosen == "devcontainer":
        project_dir = Path(
            full_cfg.get("project_dir") or workdir or Path.cwd()
        ).expanduser()
        return DevcontainerBackend(
            project_dir=project_dir, timeout=timeout,
            # Default OFF -- parity with docker/podman/kubernetes (--network
            # none). Previously defaulted True, shipping weaker isolation than
            # the DockerBackend this backend claims parity with.
            allow_network=_config_bool(full_cfg.get("allow_network"), False),
            memory=full_cfg.get("memory", "4g"),
            # Drop to the invoking uid:gid unless the operator opts into root,
            # exactly like docker/podman.
            allow_root=_config_bool(full_cfg.get("allow_root"), False),
        )
    if chosen == "kubernetes":
        return KubernetesBackend(
            image=_resolve_image(full_cfg),
            namespace=full_cfg.get("namespace", "default"),
            context=full_cfg.get("context"),
            kubeconfig=full_cfg.get("kubeconfig"),
            # HOST directory, same as every other container backend -- it's
            # streamed into the pod's emptyDir via `kubectl cp`, not used as
            # an in-pod path (see KubernetesBackend's module docstring).
            workdir=wd,
            timeout=timeout,
            allow_network=_config_bool(full_cfg.get("allow_network"), False),
            extra_kubectl_args=full_cfg.get("extra_kubectl_args") or [],
            run_as_user=int(full_cfg.get("run_as_user", 1000)),
            memory=full_cfg.get("memory", "4g"),
            cpus=full_cfg.get("cpus"),
        )
    if chosen == "firecracker":
        return FirecrackerBackend(
            workdir=wd,
            image=full_cfg.get("image", "ubuntu:24.04-maverick"),
            timeout=timeout,
            provider=full_cfg.get("provider", "local"),
            api_key=full_cfg.get("api_key"),
            network=full_cfg.get("network", "egress-deny"),
            # Warm microVM reuse between execs (e2b provider only; see
            # FirecrackerBackend docstring). Default OFF.
            warm=_config_bool(full_cfg.get("warm"), False),
        )
    if chosen == "ssh":
        host = full_cfg.get("host")
        if not host:
            raise ValueError(
                "sandbox backend=ssh requires [sandbox] host = \"user@example.com\""
            )
        return SSHBackend(
            host=host,
            workdir=PurePosixPath(
                str(workdir if workdir is not None else full_cfg.get("workdir", "~/maverick-workspace"))
            ),
            timeout=timeout,
            ssh_args=full_cfg.get("ssh_args", []),
            host_key_checking=full_cfg.get("host_key_checking", "accept-new"),
        )
    if chosen != "local":
        # Matched no known backend: route through the helper, which fail-closes
        # under require-container instead of silently degrading to a host shell.
        return _degrade_to_local(chosen, full_cfg, wd, timeout)
    _warn_local_unsandboxed()
    return LocalBackend(workdir=wd, timeout=timeout)
