"""Sandbox evaluation harness for governed code self-modification.

The Darwin-Gödel-Machine insight is empirical validation: compare a proposed
change with the code it would replace on targeted work. This module produces
``baseline_score`` vs ``candidate_score`` as development telemetry; it does not
authorize promotion.

The patch is applied to throwaway workspace copies, never to the source tree:
materialize a baseline, clone a candidate arm, apply there, and compare them.
Execution isolation is a separate boundary. The stock runner requires a
non-host, no-egress sandbox with bounded output and authenticated test results;
direct development APIs may explicitly choose a host-visible backend and must
not treat the temporary directory as process containment.

Three seams keep it testable offline and bounded, following the
pattern :mod:`maverick.self_harness_eval` uses:

* ``materialize(src, dest)`` — make a bounded, no-follow regular-file snapshot;
  Git work trees include tracked working bytes only and sensitive material is
  excluded or refused. Injectable for trusted snapshot-based copies.
* ``apply_fn(patch, workdir)`` — apply the diff. Default: ``git apply`` routed
  through ``sandbox.exec`` (kernel rule 4), ``--check`` first so a non-applying
  patch fails cleanly instead of half-writing.
* ``score_fn(workdir) -> Score`` — run the eval (a test/benchmark pass) and
  return ``(value, samples)``. This is the live seam; a real one runs the suite
  in the sandbox. The offline default is deterministic so the harness is
  runnable without a model or a toolchain.

Posture: pure mechanism. This module promotes nothing and reads no config; it
returns an :class:`EvalResult` for research and review. It **fails closed** —
any error (copy failed, patch didn't apply, scorer raised) yields a result whose
``ok`` is False and whose scores don't clear the gate.
"""
from __future__ import annotations

import logging
import math
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .self_modify_evidence import (
    AuthenticatedTestCounts,
    AuthenticatedTestEvidence,
    AuthenticatedTestRequest,
    evidence_backend_readiness,
    validate_test_evidence,
)

log = logging.getLogger(__name__)

# Directories never worth copying into a throwaway eval tree (VCS + build/test
# caches). Skipping them keeps the copy cheap and avoids re-running stale caches.
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".venv", "venv", "node_modules", ".tox", "build", "dist",
    ".maverick-eval",  # our own scratch, never recurse into it
})
_MAX_MATERIALIZE_FILES = 20_000
_MAX_MATERIALIZE_BYTES = 512 * 1024 * 1024
_MAX_MATERIALIZE_FILE_BYTES = 32 * 1024 * 1024
_SENSITIVE_MATERIAL_DIRS = frozenset({
    ".aws", ".azure", ".gnupg", ".kube", ".ssh",
})
_SENSITIVE_MATERIAL_FILES = frozenset({
    ".env", ".netrc", ".npmrc", ".pypirc", ".secrets.baseline",
    "application_default_credentials.json", "credentials.json",
    "terraform.tfstate", "terraform.tfvars",
})
_SENSITIVE_MATERIAL_SUFFIXES = (
    ".jks", ".kdbx", ".key", ".keystore", ".p12", ".pem", ".pfx",
)
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",  # pragma: allowlist secret
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",  # pragma: allowlist secret
    b"-----BEGIN RSA PRIVATE KEY-----",  # pragma: allowlist secret
    b"-----BEGIN DSA PRIVATE KEY-----",  # pragma: allowlist secret
    b"-----BEGIN EC PRIVATE KEY-----",  # pragma: allowlist secret
    b"-----BEGIN OPENSSH PRIVATE KEY-----",  # pragma: allowlist secret
)


def _git_tracked_paths(src: Path) -> frozenset[str] | None:
    """Tracked working-tree paths below ``src``, or ``None`` outside Git.

    The working bytes are still captured (so modified tracked tests are bound by
    provenance), but ignored and untracked files never enter an autonomous eval
    copy.  ``git ls-files`` is index-only and does not execute hooks or access the
    network.
    """
    try:
        probe = subprocess.run(
            ["git", "-C", str(src), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, check=False, timeout=10,
        )
        if probe.returncode != 0 or probe.stdout.strip().lower() != b"true":
            return None
        listed = subprocess.run(
            ["git", "-C", str(src), "ls-files", "-z", "--cached"],
            capture_output=True, check=False, timeout=30,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    if listed.returncode != 0:
        raise ValueError("could not enumerate tracked evaluation source")
    paths: set[str] = set()
    for raw in listed.stdout.split(b"\0"):
        if not raw:
            continue
        value = os.fsdecode(raw).replace("\\", "/")
        parts = value.split("/")
        if (not value or value.startswith("/")
                or any(part in ("", ".", "..") for part in parts)):
            raise ValueError("git returned an unsafe tracked path")
        paths.add(value)
    return frozenset(paths)


def _sensitive_material_path(relative: Path) -> bool:
    parts = tuple(part.casefold() for part in relative.parts)
    if any(part in _SENSITIVE_MATERIAL_DIRS for part in parts[:-1]):
        return True
    basename = parts[-1] if parts else ""
    if (basename in _SENSITIVE_MATERIAL_FILES
            or basename.startswith(".env.")
            or basename in {"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}
            or basename.endswith(_SENSITIVE_MATERIAL_SUFFIXES)):
        return True
    return False


@dataclass(frozen=True)
class Score:
    """A scorer's output: a scalar ``value`` (higher is better) over ``samples``
    eval cases. ``samples`` feeds the governed gate's evidence floor."""

    value: float
    samples: int = 0


@dataclass(frozen=True)
class ApplyResult:
    ok: bool
    reason: str = ""


@dataclass(frozen=True)
class EvalResult:
    """Baseline-vs-candidate measurement for a proposed patch.

    ``baseline_score``/``candidate_score`` and ``samples`` are exactly what
    :func:`maverick.self_modify.propose_code_change` needs. ``applied`` records
    whether the patch applied to the isolated copy at all; when it didn't (or a
    scorer errored) ``ok`` is False and the scores are inert (equal), so the
    evidence gate sees no improvement and refuses — fail closed.
    """

    ok: bool
    baseline_score: float
    candidate_score: float
    samples: int
    applied: bool
    reason: str = ""
    # The baseline arm's own sample count, exposed so a caller can cache the
    # baseline Score across cycles (the tree is invariant on an autonomous run).
    baseline_samples: int = 0

    @property
    def improvement(self) -> float:
        return self.candidate_score - self.baseline_score

    @property
    def baseline(self) -> Score:
        """The baseline arm as a reusable Score (for cross-cycle caching)."""
        return Score(self.baseline_score, self.baseline_samples)


# --- isolation policy (Gap 4): never run a candidate's code on the host -------

class EvalSandboxError(RuntimeError):
    """Raised when the eval cannot run under the deployment's isolation policy —
    e.g. require-container/enterprise is active but no container backend was
    supplied, so applying + testing a candidate patch would execute untrusted
    code directly on the host."""


def container_required() -> bool:
    """Whether a container sandbox is mandatory for the eval (so host exec is
    refused). Uses the public, CONFIG-AWARE predicate
    ``sandbox.container_backend_required`` so ``[sandbox] require_container = true``
    in ``config.toml`` is honoured — not the bare private helper, which only sees
    ``MAVERICK_REQUIRE_CONTAINER_BACKEND`` / enterprise mode and would let the
    config knob silently no-op (fail-open). Off by default (single-tenant/dev
    keeps the warned host path)."""
    try:
        from .sandbox import container_backend_required
        return bool(container_backend_required())
    except Exception:  # pragma: no cover -- cannot prove isolation -> require it
        return True


def _host_visible(sb) -> bool:
    try:
        from .sandbox import fs_is_host_visible
        return bool(fs_is_host_visible(sb))
    except Exception:  # pragma: no cover -- unknown backend -> assume host-visible
        return True


_HOST_EVAL_WARNED = False


def resolve_eval_sandbox(sandbox, workdir: Path):
    """Return the sandbox the eval should exec in, enforcing isolation policy.

    A candidate patch is untrusted code; applying and *running its tests* is
    arbitrary execution. So under require-container/enterprise policy this
    REFUSES to fall back to host exec (``LocalBackend``) and raises
    :class:`EvalSandboxError` — fail closed. An explicit container backend is
    used as-is; a host-visible backend under policy is also refused. Only when
    the policy is inactive does it default to a warned ``LocalBackend`` (dev /
    single-tenant), matching ``build_sandbox``'s posture."""
    if sandbox is not None:
        if container_required() and _host_visible(sandbox):
            raise EvalSandboxError(
                "refusing to evaluate a candidate patch on a host-visible sandbox "
                "under require-container/enterprise policy: running its tests would "
                "execute untrusted code on the host. Pass a container backend "
                "(docker/gvisor/podman/firecracker).")
        return sandbox
    if container_required():
        raise EvalSandboxError(
            "refusing host-exec self-modify evaluation: require-container/enterprise "
            "policy is active but no container sandbox was supplied. Applying and "
            "testing a candidate patch on the host is arbitrary code execution. "
            "Inject a container backend into evaluate_patch(sandbox=...).")
    global _HOST_EVAL_WARNED
    if not _HOST_EVAL_WARNED:
        _HOST_EVAL_WARNED = True
        log.warning(
            "self_modify_eval: no container sandbox supplied; a candidate patch's "
            "tests will run on the HOST with no isolation. Acceptable only for a "
            "trusted single-tenant/dev box. Set [sandbox] require_container=true "
            "(or inject a container backend) to enforce isolation.")
    from .sandbox.local import LocalBackend
    return LocalBackend(workdir=Path(workdir))


def require_secure_eval_sandbox(sandbox, workdir: Path):
    """Resolve and validate the stricter stock self-modification profile.

    Candidate code must run outside the host filesystem, without egress or root
    opt-ins. Backends must also guarantee bounded host-output capture and
    authenticate structured terminal test results; candidate text is never a
    score. Direct development APIs may still use ``resolve_eval_sandbox``; the
    operable runner always uses this stricter boundary.
    """
    sb = resolve_eval_sandbox(sandbox, workdir)
    problems: list[str] = []
    if _host_visible(sb):
        problems.append("requires a non-host sandbox")
    allow_network = getattr(sb, "allow_network", None)
    network = getattr(sb, "network", None)
    if allow_network is not False and network != "egress-deny":
        problems.append("requires enforceable egress denial")
    if bool(getattr(sb, "allow_root", False)):
        problems.append("refuses root-enabled sandboxes")
    if hasattr(sb, "pids_limit") and not sb.pids_limit:
        problems.append("requires a process limit")
    if hasattr(sb, "memory") and not sb.memory:
        problems.append("requires a memory limit")
    if getattr(sb, "bounded_output", None) is not True:
        problems.append("requires bounded host-output capture")
    evidence_readiness = evidence_backend_readiness(sb)
    if not evidence_readiness.ready:
        problems.append(evidence_readiness.message)
    if problems:
        raise EvalSandboxError(
            "stock self-modification evaluation is not ready: "
            + "; ".join(problems),
        )
    return sb


# --- seam 1: materialize an isolated copy ------------------------------------

_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _unsafe_material_alias(info) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)


def _material_identity(info) -> tuple:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_size, getattr(info, "st_mtime_ns", None),
    )


def _tracked_parent_dirs(tracked_paths: frozenset[str] | None) -> frozenset[str] | None:
    if tracked_paths is None:
        return None
    parents: set[str] = set()
    for tracked in tracked_paths:
        parts = tracked.split("/")
        for index in range(1, len(parts)):
            parents.add("/".join(parts[:index]))
    return frozenset(parents)


def _collect_materialization_entries(
    src: Path, tracked_paths: frozenset[str] | None,
) -> tuple[set[Path], list[tuple[Path, Path, tuple, int]]]:
    """Enumerate a bounded set of regular files without following aliases."""
    tracked_dirs = _tracked_parent_dirs(tracked_paths)
    files: list[tuple[Path, Path, tuple, int]] = []
    directories: set[Path] = {Path()}
    total_bytes = 0
    for dirpath, dirnames, filenames in os.walk(src, topdown=True, followlinks=False):
        base = Path(dirpath)
        kept: list[str] = []
        for name in sorted(dirnames):
            if name in _SKIP_DIRS:
                continue
            relative_dir = (base / name).relative_to(src)
            relative_key = relative_dir.as_posix()
            if tracked_dirs is not None and relative_key not in tracked_dirs:
                continue
            if _sensitive_material_path(relative_dir):
                continue
            info = (base / name).lstat()
            if _unsafe_material_alias(info) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("materialization source contains a directory alias")
            directories.add(relative_dir)
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            source_file = base / name
            relative = source_file.relative_to(src)
            if tracked_paths is not None and relative.as_posix() not in tracked_paths:
                continue
            if _sensitive_material_path(relative):
                continue
            info = source_file.lstat()
            if (_unsafe_material_alias(info) or not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1):
                raise ValueError(
                    "materialization source contains a non-regular or linked file")
            if info.st_size > _MAX_MATERIALIZE_FILE_BYTES:
                raise ValueError("materialization source file exceeds size limit")
            total_bytes += info.st_size
            if (len(files) + 1 > _MAX_MATERIALIZE_FILES
                    or total_bytes > _MAX_MATERIALIZE_BYTES):
                raise ValueError("materialization source exceeds snapshot quota")
            files.append((
                source_file, relative, _material_identity(info),
                stat.S_IMODE(info.st_mode),
            ))
    return directories, files


def _scan_private_key_material(fd: int, size: int) -> None:
    """Scan a bounded open file, including markers split across read chunks."""
    remaining = size
    carry = b""
    carry_size = max(len(marker) for marker in _PRIVATE_KEY_MARKERS) - 1
    while remaining:
        probe = os.read(fd, min(remaining, 1024 * 1024))
        if not probe:
            raise ValueError("materialization source truncated during secret scan")
        window = carry + probe
        if any(marker in window for marker in _PRIVATE_KEY_MARKERS):
            raise ValueError("materialization source contains private key material")
        carry = window[-carry_size:]
        remaining -= len(probe)


def _copy_materialized_file(
    source_file: Path, relative: Path, expected: tuple, mode: int,
    *, src: Path, dest: Path,
) -> None:
    source_file.resolve(strict=True).relative_to(src)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(source_file, flags)
    try:
        before = os.fstat(fd)
        if _material_identity(before) != expected or _unsafe_material_alias(before):
            raise ValueError("materialization source changed during capture")
        # Scan before creating the destination so rejected key material never
        # appears in either evaluation arm.
        _scan_private_key_material(fd, before.st_size)
        if _material_identity(os.fstat(fd)) != expected:
            raise ValueError("materialization source changed during secret scan")
        os.lseek(fd, 0, os.SEEK_SET)
        target = dest.joinpath(*relative.parts)
        with target.open("xb") as out:
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError("materialization source truncated during capture")
                out.write(chunk)
                remaining -= len(chunk)
        if _material_identity(os.fstat(fd)) != expected:
            raise ValueError("materialization source changed during capture")
        os.chmod(target, mode)
    finally:
        os.close(fd)


def _default_materialize(
    src: Path, dest: Path, *, require_tracked_source: bool = False,
) -> None:
    """Create one bounded, no-follow regular-file snapshot of ``src``.

    This runs on the host before sandbox execution. Symlinks, reparse points,
    hardlinks, special files, races, sensitive material, and quota overflow are
    refused or excluded. A partial destination is removed on failure.
    """
    requested_src, dest = Path(src), Path(dest)
    if dest.exists():
        raise FileExistsError("materialization destination already exists")
    root_info = requested_src.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or _unsafe_material_alias(root_info):
        raise ValueError("materialization source must be a real directory")
    src = requested_src.resolve(strict=True)
    tracked_paths = _git_tracked_paths(src)
    if require_tracked_source and tracked_paths is None:
        raise ValueError("autonomous evaluation requires a Git-tracked source tree")
    directories, files = _collect_materialization_entries(src, tracked_paths)

    try:
        dest.mkdir(parents=True)
        ordered_dirs = sorted(
            directories, key=lambda path: (len(path.parts), path.as_posix()))
        for relative_dir in ordered_dirs:
            if relative_dir.parts:
                dest.joinpath(*relative_dir.parts).mkdir()
        for source_file, relative, expected, mode in files:
            _copy_materialized_file(
                source_file, relative, expected, mode, src=src, dest=dest)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise


# --- seam 2: apply the patch --------------------------------------------------

def _learning_apply_refusal() -> str | None:
    """Return a generic refusal when the privileged apply boundary is closed."""
    try:
        from .learning_guard import Halted, check_learning_halt
        check_learning_halt("self_modify", "apply")
    except Halted as exc:
        return f"learning safety check halted apply: {exc}"
    except Exception as exc:
        # This API promises a result rather than an exception.  Authority
        # outages and active stops are both safety refusals under the strict
        # learning guard; callers can reconcile or roll back without mutating.
        log.warning(
            "self_modify_eval: learning safety check failed (%s)",
            type(exc).__name__,
        )
        return "learning safety check refused apply"
    return None


def run_git_apply(patch: str, workdir: Path, sb, *,
                  budget=None) -> tuple[bool, str]:
    """Stage ``patch`` and apply it to ``workdir`` via an ALREADY-RESOLVED backend
    ``sb`` (kernel rule 4: shell only via ``sandbox.exec``): ``git apply --check``
    first so a non-applying patch writes nothing, then the real ``git apply -p1``.
    Returns ``(ok, message)``; never raises. This is the shared apply mechanic
    behind the isolated eval (:func:`git_apply`); the caller resolves the
    backend.

    Strict-first with a ``--recount`` fallback: if the strict ``--check`` fails,
    retry with ``git apply --recount``, which re-derives each hunk's line counts
    from its body instead of trusting the ``@@`` header. This rescues the common
    LLM failure mode where a hand-written diff has correct context/body but a
    MISCOUNTED hunk header (models can't reliably count diff lines) — git errors
    "corrupt patch" on the header while the change itself is sound. It is a no-op
    for well-formed patches (they clear the strict gate above and never reach it)
    and does NOT rescue a genuine context mismatch (wrong context lines still
    fail both gates). Both rungs run ``--check`` before their real apply, so a
    non-applying patch still writes nothing; a patch that fails BOTH gates fails
    closed with the ORIGINAL strict error as the reason."""
    workdir = Path(workdir)
    if not (patch or "").strip():
        return False, "empty patch"
    # This shared mechanic covers both throwaway candidate application and the
    # promoted live-tree path. Rollback never calls it and stays available.
    refusal = _learning_apply_refusal()
    if refusal is not None:
        return False, refusal
    patch_file: Path | None = None
    fd: int | None = None
    try:
        fd, raw_path = tempfile.mkstemp(
            prefix=".maverick-patch-", suffix=".diff", dir=workdir)
        patch_file = Path(raw_path)
        info = os.fstat(fd)
        if not patch_file.is_file() or info.st_nlink != 1:
            raise OSError("staged patch is not a single-link regular file")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            fd = None
            handle.write(patch)
    except OSError:  # pragma: no cover -- temp write failure
        if fd is not None:
            os.close(fd)
        if patch_file is not None:
            patch_file.unlink(missing_ok=True)
        return False, "could not securely stage patch"
    try:
        staged_name = shlex.quote(patch_file.name)
        # Rung 1 — strict: the check gate guarantees a non-applying patch writes
        # nothing; a clean patch takes this path and behaves exactly as before.
        chk = _budgeted_exec(
            sb, f"git apply --check -p1 {staged_name}", budget=budget)
        if getattr(chk, "ok", False):
            # The check command may take long enough for an operator to arm a
            # HALT. Re-read every authority immediately before the real write.
            refusal = _learning_apply_refusal()
            if refusal is not None:
                return False, refusal
            res = _budgeted_exec(
                sb, f"git apply -p1 {staged_name}", budget=budget)
            if not getattr(res, "ok", False):
                return False, "git apply failed"
            return True, "applied"
        # Rung 2 — recount fallback: only reached when strict --check failed. Lets
        # git re-derive the hunk line counts from the body, rescuing a miscounted
        # header while still refusing a real context mismatch (it fails --check
        # too). The check gate again protects against a half-write.
        rchk = _budgeted_exec(
            sb, f"git apply --check --recount -p1 {staged_name}",
            budget=budget)
        if getattr(rchk, "ok", False):
            refusal = _learning_apply_refusal()
            if refusal is not None:
                return False, refusal
            res = _budgeted_exec(
                sb, f"git apply --recount -p1 {staged_name}", budget=budget)
            if not getattr(res, "ok", False):
                return False, "git apply failed"
            return True, "applied (recounted)"
        # Both gates failed → fail closed, reporting the ORIGINAL strict error so
        # a genuinely-broken patch gives a meaningful reason.
        return False, "patch does not apply"
    except Exception as e:  # pragma: no cover -- sandbox exec failure
        log.warning(
            "self_modify_eval: apply execution failed (%s)", type(e).__name__)
        return False, "apply execution failed or evaluation budget exhausted"
    finally:
        try:
            if patch_file is not None:
                patch_file.unlink()
        except OSError:
            pass


def git_apply(patch: str, workdir: Path, *, sandbox=None, budget=None) -> ApplyResult:
    """Apply a unified diff to an isolated ``workdir`` under the eval isolation
    policy: resolve a sandbox (refusing host exec under require-container), then
    run the shared :func:`run_git_apply`. Never raises."""
    workdir = Path(workdir)
    if not (patch or "").strip():
        return ApplyResult(False, "empty patch")
    try:
        sb = resolve_eval_sandbox(sandbox, workdir)
    except EvalSandboxError as e:
        return ApplyResult(False, str(e))
    ok, msg = run_git_apply(patch, workdir, sb, budget=budget)
    return ApplyResult(ok, msg)


def _budgeted_exec(sb, command: str, *, budget=None, timeout: float | None = None):
    """Run one sandbox command while charging the shared DGM tool budget.

    Every sandbox exec (tests and patch application alike) counts as a tool
    call, so a candidate cannot perform an unbounded number of sandbox
    executions despite ``[budget] max_tool_calls``.  The ``check`` fallback keeps compatibility with embedders and
    tests that provide the older, minimal budget protocol.
    """
    effective_timeout = timeout
    if budget is not None:
        record = getattr(budget, "record_tool_call", None)
        if callable(record):
            record()
        else:
            budget.check()
        remaining_fn = getattr(budget, "remaining_wall", None)
        if callable(remaining_fn):
            try:
                remaining = float(remaining_fn())
            except (TypeError, ValueError, OverflowError) as exc:
                raise TimeoutError("invalid remaining evaluation wall budget") from exc
            if not math.isfinite(remaining) or remaining <= 0.0:
                raise TimeoutError("evaluation wall-clock budget exhausted")
            if effective_timeout is None:
                backend_timeout = getattr(sb, "timeout", None)
                try:
                    requested = float(backend_timeout)
                except (TypeError, ValueError, OverflowError):
                    requested = remaining
            else:
                try:
                    requested = float(effective_timeout)
                except (TypeError, ValueError, OverflowError) as exc:
                    raise TimeoutError("invalid evaluation timeout") from exc
            if not math.isfinite(requested) or requested <= 0.0:
                raise TimeoutError("invalid evaluation timeout")
            effective_timeout = min(requested, remaining)
    if effective_timeout is None:
        return sb.exec(command)
    return sb.exec(command, timeout=effective_timeout)


def _budgeted_authenticated_test_exec(
    sb,
    request: AuthenticatedTestRequest,
    *,
    budget=None,
    timeout: float | None = None,
):
    """Execute tests only through the backend's controller-evidence channel.

    This mirrors :func:`_budgeted_exec`'s accounting without routing the test
    command through ordinary ``exec``.  Generic exec results are candidate-
    controlled diagnostics and are never a production DGM score.
    """
    readiness = evidence_backend_readiness(sb)
    if not readiness.ready:
        raise EvalSandboxError(readiness.message)
    effective_timeout = timeout
    if budget is not None:
        record = getattr(budget, "record_tool_call", None)
        if callable(record):
            record()
        else:
            budget.check()
        remaining_fn = getattr(budget, "remaining_wall", None)
        if callable(remaining_fn):
            try:
                remaining = float(remaining_fn())
            except (TypeError, ValueError, OverflowError) as exc:
                raise TimeoutError(
                    "invalid remaining evaluation wall budget",
                ) from exc
            if not math.isfinite(remaining) or remaining <= 0.0:
                raise TimeoutError("evaluation wall-clock budget exhausted")
            try:
                requested = float(
                    getattr(sb, "timeout", remaining)
                    if effective_timeout is None else effective_timeout
                )
            except (TypeError, ValueError, OverflowError) as exc:
                raise TimeoutError("invalid evaluation timeout") from exc
            if not math.isfinite(requested) or requested <= 0.0:
                raise TimeoutError("invalid evaluation timeout")
            effective_timeout = min(requested, remaining)
    return sb.exec_authenticated_tests(request, timeout=effective_timeout)


# --- seam 3: score (deterministic offline default) ---------------------------

def _default_score(workdir: Path) -> Score:
    """Deterministic offline scorer default — NOT a real evaluator. It counts
    Python files under the tree as a stand-in "score" so the whole harness is
    runnable and testable without a toolchain or a model. Inject a real
    ``score_fn`` (a sandboxed test/benchmark pass) for production."""
    n = sum(1 for _ in Path(workdir).rglob("*.py"))
    return Score(value=float(n), samples=n)


def _authenticated_test_score(
    sb, request: AuthenticatedTestRequest, evidence: object,
) -> Score:
    """Convert only exact, request-bound controller evidence into a score."""
    counts = validate_test_evidence(sb, request, evidence)
    if counts is None:
        return Score(0.0, 0)
    total = counts.passed + counts.failed + counts.skipped + counts.errors
    return Score(value=counts.passed / total, samples=total)


def pytest_score(
    *, sandbox=None, command: str = "python3 -m pytest -q",
    timeout: float = 600.0, budget=None,
    subject_sha256: str | None = None,
    execution_context_sha256: str | None = None,
) -> Callable[[Path], Score]:
    """Build a ``score_fn`` that runs a test command in the sandbox and scores by
    controller-authenticated terminal outcomes. The backend must implement the
    nonce-bound ``maverick.test-evidence.v1`` protocol; otherwise the result is
    ``0/0`` and the evidence gate refuses it. Candidate stdout/stderr, JUnit
    files, and same-process pytest plugins are never parsed. The command is NOT
    hard-coded to a
    package — the caller points it at the surface under evaluation.

    ``subject_sha256`` must bind the exact evaluated artifact/workspace and
    ``execution_context_sha256`` must bind its sandbox policy, identity, and
    arm. Missing or malformed bindings produce ``0/0``.

    Isolation (Gap 4): when no ``sandbox`` is given the backend is resolved
    through :func:`resolve_eval_sandbox`, which REFUSES host exec under
    require-container/enterprise policy — a candidate's tests never run on the
    host there. ``timeout`` bounds the run; an optional ``budget`` is checked
    before the run so an exhausted budget stops the eval (fail closed)."""
    def _score(workdir: Path) -> Score:
        try:
            sb = resolve_eval_sandbox(sandbox, Path(workdir))
        except EvalSandboxError as e:
            log.warning("self_modify_eval: %s", e)
            return Score(0.0, 0)
        try:
            request = AuthenticatedTestRequest.issue(
                command,
                subject_sha256=subject_sha256 or "",
                execution_context_sha256=execution_context_sha256 or "",
            )
            evidence = _budgeted_authenticated_test_exec(
                sb, request, budget=budget, timeout=timeout,
            )
        except Exception as e:  # pragma: no cover -- exec failure is a 0 score
            log.warning(
                "self_modify_eval: test command failed (%s)", type(e).__name__)
            return Score(0.0, 0)
        return _authenticated_test_score(sb, request, evidence)
    return _score


# --- the harness --------------------------------------------------------------

def evaluate_patch(
    patch: str,
    *,
    src: Path,
    workroot: Path,
    score_fn: Callable[[Path], Score] | None = None,
    apply_fn: Callable[[str, Path], ApplyResult] | None = None,
    materialize: Callable[[Path, Path], None] | None = None,
    sandbox=None,
    baseline: Score | None = None,
    budget=None,
) -> EvalResult:
    """Measure a patch on isolated copies of ``src``: score the unpatched tree
    (baseline), apply the patch to a second copy and score that (candidate).

    ``workroot`` is a caller-owned scratch directory the two copies are made
    under (and which the caller cleans up). Never mutates ``src``. Never raises —
    any failure (copy, apply, scorer) returns a non-``ok`` result whose scores do
    not clear the gate. The default seams make this runnable offline; inject
    ``score_fn=pytest_score(...)`` and a ``sandbox`` for a real evaluation.

    ``baseline`` (a precomputed :class:`Score`) skips the baseline arm entirely —
    no baseline copy, no baseline test run. Since ``src`` is invariant across an
    autonomous run (nothing is applied between cycles), the driver computes the
    baseline once and passes it back, turning N cycles' worth of full baseline
    suites into one. Omit it (or invalidate after a real apply) for correctness.

    Isolation (Gap 4): the harness resolves the sandbox up front and REFUSES to
    run under require-container/enterprise policy without a container backend —
    returning a non-``ok`` result rather than executing a candidate's code on the
    host. This is unconditional (there is no opt-out): a custom ``apply_fn``
    still hits the early check, though a custom ``score_fn`` is the caller's own
    responsibility to isolate."""
    src = Path(src)
    workroot = Path(workroot)
    score = score_fn or _default_score
    materialize = materialize or _default_materialize
    apply = apply_fn or (
        lambda p, wd: git_apply(p, wd, sandbox=sandbox, budget=budget))

    # Fail closed BEFORE copying/applying if policy forbids host exec here.
    try:
        resolve_eval_sandbox(sandbox, workroot)
    except EvalSandboxError as e:
        return EvalResult(False, 0.0, 0.0, 0, applied=False, reason=str(e))

    base_dir = workroot / "baseline"
    cand_dir = workroot / "candidate"
    try:
        if baseline is None:
            materialize(src, base_dir)
            materialize(base_dir, cand_dir)
        else:
            materialize(src, cand_dir)
    except Exception:
        log.warning("self_modify_eval: materialization failed; refusing")
        return EvalResult(False, 0.0, 0.0, 0, applied=False,
                          reason="could not securely isolate workspace")

    applied = apply(patch, cand_dir)
    if not applied.ok:
        return EvalResult(False, 0.0, 0.0, 0, applied=False, reason=applied.reason)

    try:
        base = baseline if baseline is not None else score(base_dir)
        cand = score(cand_dir)
    except Exception:  # pragma: no cover -- a scorer must not crash the pass
        log.warning("self_modify_eval: scorer failed; refusing")
        return EvalResult(False, 0.0, 0.0, 0, applied=True,
                          reason="scorer error")

    # Evidence count is the smaller of the two arms' sample counts — the honest
    # basis for the comparison (you can only compare on cases both arms saw).
    samples = min(base.samples, cand.samples)
    return EvalResult(
        ok=True, baseline_score=base.value, candidate_score=cand.value,
        samples=samples, applied=True, baseline_samples=base.samples,
        reason=f"baseline={base.value:.4f} candidate={cand.value:.4f} "
               f"over {samples} samples",
    )


__all__ = [
    "Score", "AuthenticatedTestCounts", "AuthenticatedTestRequest",
    "AuthenticatedTestEvidence", "ApplyResult", "EvalResult",
    "EvalSandboxError",
    "container_required", "resolve_eval_sandbox", "require_secure_eval_sandbox",
    "run_git_apply", "git_apply", "pytest_score", "evaluate_patch",
]
