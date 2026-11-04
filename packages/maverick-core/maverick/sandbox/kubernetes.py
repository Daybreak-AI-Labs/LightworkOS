"""Kubernetes sandbox backend.

Spawns a transient pod per ``exec()`` call: the pod is started detached
(running ``sleep``) with an emptyDir volume mounted at ``/workspace``, the
host workspace snapshot is streamed in via ``kubectl cp``, and the command
runs via ``kubectl exec``. A bounded archive is validated before publishing
changed files and deletions. Concurrent local edits cause a recoverable
conflict. Validated exports and pre-publication originals survive publication
failure; failed exports retain the pod for a bounded recovery window.
See docs/sandbox-kubernetes-recovery.md for the recovery contract.

Why kubectl-driven instead of the official Python client?
  - The Python client adds 50+ MB of generated code + grpcio + a
    handful of transitive deps. ``kubectl`` is one binary the user
    already has if they're running on K8s.
  - The exec semantics map 1:1 with our other sandboxes (Docker,
    Podman, Devcontainer); the abstraction is "spawn a fresh
    container per command", not "manage long-lived pods".

Config::

    [sandbox]
    backend = "kubernetes"
    image = "python:3.12-slim"
    namespace = "default"
    context = "minikube"        # optional kubeconfig context
    workdir = "/home/me/maverick-workspace"   # HOST directory (like every
                                               # other backend); streamed
                                               # into the pod's /workspace
    timeout = 120
    allow_network = false        # requires a deny-all NetworkPolicy (below)

``allow_network = false`` (the default, and what the wizard writes) means
"no egress". A transient ``kubectl run`` pod cannot enforce that on
itself, so before every command the backend checks the namespace for
a deny-all NetworkPolicy (empty ``podSelector``, ``Egress`` in
``policyTypes``, no egress rules). When one is present the commands run
under it; when none is, exec() fails closed with exit code 2 and prints
the manifest to apply (``_DENY_ALL_NETWORKPOLICY``). ``allow_network =
true`` skips the check and lets pods use the cluster network. Policies are
additive: use a dedicated namespace without egress allow rules and a CNI that
enforces NetworkPolicy. The API check does not test live packet filtering.

Loud-fallback: missing kubectl binary or ``kubectl version`` failure
raises ``RuntimeError`` at construction so the wizard's smoke test
catches it before the agent runs. The container image must have ``tar``
(``kubectl cp`` streams a tarball over ``kubectl exec``) -- true of every
common base image (python/node/ubuntu/alpine slim variants all ship it).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ..file_lock import cross_process_lock, ensure_private_directory
from ..paths import maverick_home
from . import workspace_transfer
from .local import ExecResult, scrub_env

log = logging.getLogger(__name__)

# The in-pod absolute path the host workdir is streamed into. Hard-coded
# (not user-configurable) exactly like DockerBackend's container-side
# "/workspace" mount point -- only the HOST side is configurable, via
# ``[sandbox] workdir``.
_POD_WORKDIR = "/workspace"

# Deny-all NetworkPolicy the operator applies once per namespace so pods get no
# egress (and no ingress). Surfaced when allow_network=false, since a transient
# `kubectl run` pod can't enforce this on itself.
_DENY_ALL_NETWORKPOLICY = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: maverick-deny-all
  namespace: {ns}
spec:
  podSelector: {{}}
  policyTypes: [Ingress, Egress]\
"""


@dataclass
class KubernetesBackend:
    image: str = "python:3.12-slim"
    namespace: str = "default"
    context: str | None = None
    # The HOST directory commands run against -- same contract as every
    # other backend's ``workdir`` (Docker's bind-mount source, Podman's,
    # Devcontainer's ``project_dir``): file tools resolve model-supplied
    # paths against it, and it's what this backend streams into/out of the
    # pod via ``kubectl cp``. Defaults to cwd so direct construction (tests,
    # ad-hoc scripts) doesn't require passing one explicitly.
    workdir: Path = field(default_factory=Path.cwd)
    timeout: float = 120.0
    allow_network: bool = False
    extra_kubectl_args: list[str] = field(default_factory=list)
    # Containment for a possibly prompt-injected agent (mirrors docker/podman):
    # never run as uid 0, block privilege escalation, and bound RAM/CPU so a
    # runaway can't exhaust the node. Falsy memory/cpu disables that limit.
    run_as_user: int = 1000
    memory: str | None = "4g"
    cpus: str | None = None
    # Fixed budgets for the pod-lifecycle steps `exec()` now performs beyond
    # running the command itself: waiting for the pod to become Ready before
    # `kubectl cp`/`kubectl exec` can reach it, and each `kubectl cp` leg.
    # Not exposed as [sandbox] config -- these bound internal plumbing, not a
    # user-facing capability (contrast ``timeout``, which bounds the command).
    pod_ready_timeout: float = 60.0
    transfer_timeout: float = 120.0
    kubeconfig: str | None = None

    def __post_init__(self) -> None:
        self.workdir = Path(self.workdir).expanduser().resolve()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._verify_kubectl()

    def deny_all_networkpolicy_manifest(self) -> str:
        """The deny-all NetworkPolicy for this namespace, ready to apply."""
        return _DENY_ALL_NETWORKPOLICY.format(ns=self.namespace)

    def _deny_all_policy_present(self) -> bool:
        """True when the namespace carries a NetworkPolicy that denies all
        egress for every pod: an empty ``podSelector``, ``Egress`` in
        ``policyTypes`` and no ``egress`` rules. Any kubectl or parse failure
        counts as absent (fail closed)."""
        args = [*self._kubectl_prefix(), "get", "networkpolicy", "-o", "json"]
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=15, env=scrub_env(),
            )
            if proc.returncode != 0:
                return False
            items = json.loads(proc.stdout or "{}").get("items") or []
        except (subprocess.TimeoutExpired, OSError, ValueError, AttributeError):
            return False
        if not isinstance(items, list):
            return False
        found = False
        for item in items:
            spec = item.get("spec") if isinstance(item, dict) else None
            if not isinstance(spec, dict):
                return False
            # NetworkPolicies are additive. A second policy with allow rules
            # can reopen egress despite a namespace-wide deny policy. Use a
            # dedicated namespace with no egress grants; reject ambiguous scopes.
            if spec.get("egress"):
                return False
            selector = spec.get("podSelector") or {}
            if not isinstance(selector, dict):
                return False
            if selector.get("matchLabels") or selector.get("matchExpressions"):
                continue  # scoped to some pods, not the whole namespace
            if "Egress" not in (spec.get("policyTypes") or []):
                continue
            if spec.get("egress"):
                continue  # has allow rules, so not deny-all
            found = True
        return found

    def _pod_overrides(self, container_name: str) -> dict:
        """A non-root, resource-bounded pod spec for ``kubectl run --overrides``.

        ``kubectl run`` otherwise emits a bare pod that runs as the image's
        default user (often root) with no resource limits and the namespace's
        default ServiceAccount token auto-mounted. We pin a non-root
        securityContext + drop all capabilities + block privilege escalation,
        make the image filesystem read-only (the workspace stays writable),
        disable the ServiceAccount token automount (a prompt-injected agent in
        the pod has no cluster API credential to steal), and set
        requests/limits so a runaway can't starve the node.

        ``container_name`` MUST be the pod name: ``kubectl run`` names the
        single container after the pod, and a per-container ``securityContext``
        only takes effect when the override's container name matches the
        generated one. A hard-coded mismatched name would silently leave the
        container hardening (drop-ALL caps, no-priv-escalation) unapplied."""
        limits: dict[str, str] = {}
        if self.memory:
            # The shared sandbox configuration uses Docker-style sizes (4g).
            # Kubernetes requires case-sensitive quantities such as 4Gi.
            memory = str(self.memory).strip()
            docker_size = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([kmgt])(?:b)?", memory)
            if docker_size:
                memory = docker_size[1] + docker_size[2].upper() + "i"
            limits["memory"] = memory
        if self.cpus:
            limits["cpu"] = str(self.cpus)
        container: dict = {
            "name": container_name,
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "capabilities": {"drop": ["ALL"]},
                "readOnlyRootFilesystem": True,
            },
            # The workspace volume (below) -- kubectl cp streams the host
            # workdir in here before the command runs, and back out after.
            "volumeMounts": [{"name": "workspace", "mountPath": _POD_WORKDIR}],
        }
        if limits:
            container["resources"] = {"limits": limits, "requests": limits}
        return {
            "spec": {
                "automountServiceAccountToken": False,
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": int(self.run_as_user),
                    "runAsGroup": int(self.run_as_user),
                    "fsGroup": int(self.run_as_user),
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [container],
                # emptyDir: node-local scratch space for the copied-in
                # workspace: it needs no PVC/StorageClass and is deleted
                # with the pod, matching the "transient per-exec pod"
                # design (nothing to provision or clean up cluster-side).
                "volumes": [{"name": "workspace", "emptyDir": {}}],
            }
        }

    def _kubectl_prefix(self) -> list[str]:
        args = ["kubectl"]
        if self.kubeconfig:
            args.extend(["--kubeconfig", self.kubeconfig])
        if self.context:
            args.extend(["--context", self.context])
        args.extend(["-n", self.namespace])
        args.extend(self.extra_kubectl_args)
        return args

    def _verify_kubectl(self) -> None:
        try:
            subprocess.run(
                ["kubectl", "version", "--client", "--output=yaml"],
                capture_output=True, timeout=5, check=True, env=scrub_env(),
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(
                "kubectl not available — required for kubernetes backend. "
                "Install kubectl or change [sandbox] backend in "
                "~/.maverick/config.toml."
            ) from e

    def _delete_pod(self, pod_name: str) -> None:
        """Best-effort force-delete a pod; never raises.

        ``kubectl run --rm`` deletes the pod only on a clean exit. Any other
        completed export gets an explicit delete. Failed exports deliberately
        retain the pod until recovery or its active deadline. This helper is
        called only when the workspace is safe locally or execution never began.
        """
        try:
            result = subprocess.run(
                [*self._kubectl_prefix(), "delete", "pod", pod_name,
                 "--ignore-not-found=true", "--grace-period=0", "--force"],
                capture_output=True, timeout=10, env=scrub_env(),
            )
            if result.returncode:
                log.warning("kubernetes sandbox: failed to delete pod %s (exit %s)",
                            pod_name, result.returncode)
        except Exception:  # failure-policy: fail_soft_with_audit -- cleanup warning
            log.warning("kubernetes sandbox: could not delete pod %s", pod_name)

    def _start_and_wait(self, pod_name: str, execution_timeout: float | None = None) -> ExecResult | None:
        """Start the pod detached (long-lived ``sleep``, not ``--rm -i``) and
        block until it's Ready. Returns None on success, else an ExecResult
        describing the failure.

        A detached start is required so there's a running container for
        `kubectl cp` to stream into *before* the real command runs --
        `kubectl run --rm -i` (the old one-shot approach) runs the command
        immediately and tears the pod down, leaving no window to copy
        anything in.
        """
        # Long enough to outlive the command timeout plus both cp legs; the
        # pod is force-deleted explicitly once exec() is done with it, so
        # this is just a backstop against an orphaned sleep outliving us.
        # Retain a one-hour recovery window when export fails. Normal runs
        # delete immediately; the deadline stops an orphaned container.
        sleep_budget = int(execution_timeout or self.timeout) + int(2 * self.transfer_timeout) + 3600
        overrides = self._pod_overrides(pod_name)
        overrides["spec"]["activeDeadlineSeconds"] = sleep_budget + int(self.pod_ready_timeout)
        overrides["spec"]["volumes"][0]["emptyDir"]["sizeLimit"] = str(workspace_transfer.MAX_TOTAL_BYTES)
        run_args = [
            *self._kubectl_prefix(),
            "run", pod_name,
            "--restart=Never", "--quiet",
            f"--image={self.image}",
            # Merge lists by container name; JSON merge replaces the generated
            # container and would discard its image and command arguments.
            "--override-type=strategic", "--command",
            "--overrides", json.dumps(overrides),
            "--",
            "sleep", str(sleep_budget),
        ]
        try:
            proc = subprocess.run(
                run_args, capture_output=True, text=True,
                timeout=self.pod_ready_timeout, env=scrub_env(),
            )
        except subprocess.TimeoutExpired:
            return ExecResult(
                stdout="", exit_code=1,
                stderr=f"kubectl run timed out starting pod {pod_name!r}",
            )
        if proc.returncode != 0:
            return ExecResult(
                stdout="", exit_code=1,
                stderr=f"kubectl run failed: {proc.stderr.strip()[-2000:]}",
            )

        wait_args = [
            *self._kubectl_prefix(), "wait", f"pod/{pod_name}",
            "--for=condition=Ready", f"--timeout={int(self.pod_ready_timeout)}s",
        ]
        try:
            proc = subprocess.run(
                wait_args, capture_output=True, text=True,
                timeout=self.pod_ready_timeout + 5, env=scrub_env(),
            )
        except subprocess.TimeoutExpired:
            return ExecResult(
                stdout="", exit_code=1,
                stderr=f"pod {pod_name!r} did not become Ready in time",
            )
        if proc.returncode != 0:
            return ExecResult(
                stdout="", exit_code=1,
                stderr=f"pod {pod_name!r} did not become Ready: {proc.stderr.strip()[-2000:]}",
            )
        return None

    def _copy_in(self, pod_name: str, source: Path | None = None) -> ExecResult | None:
        """Stream the host workdir into the pod's emptyDir. Returns None on
        success, else an ExecResult describing the failure.

        The trailing ``/.`` on the source is required: ``kubectl cp`` tars
        the source directory and untars it at the destination, so a bare
        ``<dir>`` would land as ``<dest>/<basename(dir)>`` instead of
        populating ``<dest>`` itself.
        """
        # A Windows drive colon is parsed by kubectl as POD:PATH. A relative
        # local operand plus an explicit subprocess cwd works on every host.
        src = "./."
        dest = f"{self.namespace}/{pod_name}:{_POD_WORKDIR}"
        args = [*self._kubectl_prefix(), "cp", src, dest]
        try:
            # kubectl archives an empty source as the destination directory
            # itself. Restoring that header can chmod the root-owned emptyDir
            # mount, which a non-root worker cannot do. There is no input to
            # transfer on a first run; retain the volume's kubelet permissions.
            if not any((source or self.workdir).iterdir()):
                return None
            proc = subprocess.run(
                args, capture_output=True, text=True,
                timeout=self.transfer_timeout, env=scrub_env(), cwd=source or self.workdir,
            )
        except subprocess.TimeoutExpired:
            return ExecResult(
                stdout="", exit_code=1,
                stderr="kubectl cp (workspace -> pod) timed out",
            )
        if proc.returncode != 0:
            return ExecResult(
                stdout="", exit_code=1,
                stderr=f"kubectl cp (workspace -> pod) failed: {proc.stderr.strip()[-2000:]}",
            )
        return None

    def _run_command(self, pod_name: str, cmd: str, effective: float) -> ExecResult:
        # Copy-in is complete before we atomically claim a fresh private child.
        # Never point a tool's disposable TMPDIR at the customer workspace root
        # or reuse an existing path. Remove only an empty child; interrupted or
        # unmanaged scratch remains ordinary recoverable workspace data.
        scratch = f"{_POD_WORKDIR}/.maverick-tmp-{uuid.uuid4().hex}"
        wrapped = ('(umask 077; mkdir "$1") || exit 74; cd "$2" || exit 74; '
                   'TMPDIR="$1"; export TMPDIR; sh -c "$3"; status=$?; '
                   'rmdir "$1" 2>/dev/null || :; exit "$status"')
        args = [*self._kubectl_prefix(), "exec", pod_name, "--", "sh", "-c", wrapped,
                "workspace-command", scratch, _POD_WORKDIR, cmd]
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=effective,
                env=scrub_env(),
            )
            return ExecResult(
                stdout=result.stdout[-8000:],
                stderr=result.stderr[-2000:],
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired as e:
            stdout = e.stdout or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            return ExecResult(
                stdout=stdout[-8000:],
                stderr=f"TIMEOUT after {effective}s",
                exit_code=124,
            )

    def _copy_out(self, pod_name: str, baseline: dict, recovery: Path) -> str:
        """Validate a private staged archive before reconciling host files.

        Tar metadata lets us reject links before interpreting missing entries
        as deletions. kubectl cp's symlink-skipping extraction cannot do that.
        """
        # Linux kill(-1) stops other same-user processes in this pod's private
        # PID namespace (not PID 1 or this shell). Freeze leftover/background
        # writers before tar; an empty process set may return ESRCH. The shell
        # then becomes the exporter. No host PID namespace is requested.
        args = [*self._kubectl_prefix(), "exec", pod_name, "--", "sh", "-c",
                'kill -s STOP -1 2>/dev/null || :; exec "$@"', "workspace-export",
                "tar", "-C", _POD_WORKDIR, "-cf", "-", "."]
        try:
            archive = recovery / "export.tar"
            if workspace_transfer.capture_archive(args, archive, self.transfer_timeout) != 0:
                return "; workspace export failed; pod retained for recovery"
            workspace_transfer.extract_archive(archive, recovery / "exported")
            (recovery / "export.complete").touch()
            workspace_transfer.publish(self.workdir, baseline, recovery / "exported", recovery / "originals")
        except subprocess.TimeoutExpired:
            return "; workspace export timed out; pod retained for recovery"
        except Exception as exc:  # failure-policy: fail_closed -- preserve recovery data
            return f"; workspace export/publication failed ({type(exc).__name__}: {str(exc)[:300]})"
        return ""

    def exec(self, cmd: str, timeout: float | None = None) -> ExecResult:
        effective = self.timeout if timeout is None else timeout
        pod_name = f"maverick-sb-{uuid.uuid4().hex[:12]}"

        if not self.allow_network:
            # A single transient `kubectl run` pod cannot enforce no-egress
            # on its own -- that needs a namespace-level NetworkPolicy the
            # operator applies. Reverify an exclusive deny policy before
            # each command; otherwise fail closed (never
            # silently run with network) and print the manifest to apply.
            # Refusing EVERY command here would leave the wizard's default
            # config unable to run anything.
            if not self._deny_all_policy_present():
                manifest = self.deny_all_networkpolicy_manifest()
                log.warning(
                    "kubernetes backend: allow_network=false but namespace %r "
                    "has no deny-all NetworkPolicy, so a transient pod would "
                    "have network. Apply this once, then retry:\n%s",
                    self.namespace, manifest,
                )
                return ExecResult(
                    stdout="",
                    stderr=(
                        "networking is disabled for the kubernetes backend "
                        f"(allow_network=false), but namespace {self.namespace!r} "
                        "has no verified exclusive deny-all NetworkPolicy. A transient pod cannot "
                        "enforce no-network on its own. Use a dedicated namespace without egress "
                        "allow rules and apply this policy "
                        "(kubectl apply -f -), then retry -- or set "
                        "allow_network=true to let pods use the network:\n"
                        + manifest
                    ),
                    exit_code=2,
                )

        key = hashlib.sha256(str(self.workdir).encode()).hexdigest()
        locks = ensure_private_directory(maverick_home() / "sandbox-workspace-locks")
        with cross_process_lock(locks / (key + ".lock"), strict=True):
            return self._exec_with_workspace(pod_name, cmd, effective)

    def _exec_with_workspace(self, pod_name: str, cmd: str, effective: float) -> ExecResult:
        if maverick_home().resolve().is_relative_to(self.workdir):
            return ExecResult(stdout="", exit_code=74,
                              stderr="Choose a dedicated workspace outside the folder containing Lightwork settings and recovery storage.")
        recovery = workspace_transfer.recovery_directory()
        command_started = complete = False
        try:
            baseline = workspace_transfer.snapshot(self.workdir, recovery / "input")
            workspace_transfer.save_manifest(recovery, {
                "namespace": self.namespace, "context": self.context, "pod": pod_name,
                "workdir": str(self.workdir), "baseline": baseline,
            })
            failure = self._start_and_wait(pod_name, effective)
            if failure is not None:
                return failure
            failure = self._copy_in(pod_name, recovery / "input")
            if failure is not None:
                return failure
            command_started = True
            result = self._run_command(pod_name, cmd, effective)
            copy_out_note = self._copy_out(pod_name, baseline, recovery)
            if copy_out_note:
                result = ExecResult(
                    stdout=result.stdout,
                    stderr=result.stderr + copy_out_note + self._recovery_note(pod_name, recovery),
                    # The command may have run successfully, but its output
                    # files were not delivered. Do not advertise overall success.
                    exit_code=result.exit_code or 74,
                )
            else:
                complete = True
            return result
        except Exception as exc:  # failure-policy: fail_closed -- return transfer failure
            return ExecResult(stdout="", exit_code=74,
                              stderr=f"workspace transfer failed ({type(exc).__name__})"
                              + (self._recovery_note(pod_name, recovery) if command_started else ""))
        finally:
            if not command_started or complete or (recovery / "export.complete").exists():
                self._delete_pod(pod_name)
            if not command_started or complete:
                try:
                    workspace_transfer.cleanup(recovery)
                except OSError:
                    log.warning("kubernetes transfer cache could not be removed: %s", recovery)

    def _recovery_note(self, pod_name: str, recovery: Path) -> str:
        note = f"; saved transfer files: {recovery}"
        if not (recovery / "export.complete").exists():
            note += (f"; recover pod {self.namespace}/{pod_name} within one hour using the configured "
                     "kubectl context; see docs/sandbox-kubernetes-recovery.md")
        else:
            note += "; exported files and any pre-publication originals are retained for review"
        return note


__all__ = ["KubernetesBackend"]
