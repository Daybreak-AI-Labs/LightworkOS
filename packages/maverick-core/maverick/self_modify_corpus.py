"""Targeted code-eval corpus + held-in/held-out split (Gap 2).

``self_modify_eval.pytest_score`` runs the WHOLE suite and scores by pass rate.
For a code change that fixes one thing and breaks nothing, that reads as ~flat
(9,000 passing → 9,000 passing) → the evidence gate sees ≈0 improvement and
refuses. To make "beats baseline" *discriminating* for code, the eval has to be
targeted (the tests that exercise the changed capability) and it has to guard
against overfitting the same way :mod:`maverick.self_harness_eval` does for
prompt lines: split the corpus into held-in and confirmation subsets and judge
the research result on the confirmation subset, not the adaptive score alone.

A :class:`CodeEvalCorpus` is just the pytest node-ids (or files) that pin the
targeted capability. :func:`evaluate_on_corpus` scores baseline vs candidate on
both splits on isolated copies (never the live tree, via the Phase-2 harness),
and reports:

* the **confirmation** baseline/candidate scores used as research telemetry;
* an **overfit** flag — candidate beat baseline on held-in but NOT held-out,
  which a caller treats as a refusal (the change learned the seen tests, not the
  capability).

Deterministic throughout (the split reuses ``self_harness_eval.corpus_split``'s
stable content-hash ordering), so a re-run validates against the same tests.
The cases and exact node IDs remain visible inside the candidate workspace and
process arguments, so this is not a sealed evaluator and cannot authorize live
code promotion. Isolation policy is inherited from ``self_modify_eval`` — under
require-container/enterprise it fails closed rather than running a candidate's
tests on the host.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import shlex
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .self_modify_eval import (
    ApplyResult,
    AuthenticatedTestRequest,
    EvalSandboxError,
    Score,
    _authenticated_test_score,
    _budgeted_authenticated_test_exec,
    _budgeted_exec,
    _default_materialize,
    git_apply,
    resolve_eval_sandbox,
)
from .self_modify_evidence import evidence_backend_readiness

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CodeEvalCorpus:
    """The targeted test set that pins the capability a code change touches.

    ``test_ids`` are pytest node-ids or paths (e.g.
    ``packages/x/tests/test_money.py::test_round``). ``command_prefix`` is the
    runner the ids are appended to. Keep it NARROW — the whole point is to
    measure the changed capability, not the entire suite."""

    test_ids: tuple[str, ...] = ()
    command_prefix: str = "python3 -m pytest -q"
    # Optional operator-owned setup command, run INSIDE the same sandbox exec as
    # every pytest invocation.  This matters for cold container backends: a
    # separate ``pip install`` exec would disappear with the container before
    # tests start.  Keep network disabled and prefer a prebuilt evaluator image
    # or an offline wheelhouse for production.
    bootstrap_command: str | None = None

    @property
    def evidence_scope(self) -> str:
        payload = "\0".join((
            self.command_prefix,
            self.bootstrap_command or "",
            *self.test_ids,
        ))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def split(self, *, held_out_frac: float = 0.3) -> tuple[list[str], list[str]]:
        """Deterministic ``(held_in, held_out)`` split of the test ids. Reuses the
        stable content-hash ordering from :func:`self_harness_eval.corpus_split`,
        so the same corpus always holds out the same tests."""
        from .self_harness_eval import corpus_split
        cases = [{"goal": t} for t in self.test_ids]
        return corpus_split(cases, held_out_frac=held_out_frac)


@dataclass(frozen=True)
class CorpusEvalResult:
    """Baseline-vs-candidate on both splits, plus the overfit verdict."""

    ok: bool
    baseline_score: float          # confirmation baseline
    candidate_score: float         # confirmation candidate
    samples: int                   # confirmation test count
    held_in_baseline: float = 0.0
    held_in_candidate: float = 0.0
    overfit: bool = False
    applied: bool = False
    reason: str = ""
    evidence_scope: str = ""

    @property
    def improvement(self) -> float:
        return self.candidate_score - self.baseline_score


def _captured_tree_manifest(root: Path) -> str:
    """Digest the exact materialized baseline tree without following aliases.

    Git revision alone is insufficient evidence: challenge tests and source can
    be dirty in the operator's working tree.  Hash paths, file modes, sizes, and
    contents from the captured baseline copy so the result is bound to the exact
    bytes that both evaluator arms inherited.
    """
    root = Path(root).resolve(strict=True)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    manifest = hashlib.sha256(b"maverick-captured-tree-v1\0")

    def _unsafe_alias(info) -> bool:
        return stat.S_ISLNK(info.st_mode) or bool(
            getattr(info, "st_file_attributes", 0) & reparse)

    def _record(kind: str, relative: Path, mode: int, size: int = 0,
                content_sha256: str = "") -> None:
        row = json.dumps(
            [kind, relative.as_posix(), mode, size, content_sha256],
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        manifest.update(len(row).to_bytes(8, "big"))
        manifest.update(row)

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(dirpath)
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            directory = base / name
            info = directory.lstat()
            if _unsafe_alias(info) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("captured tree contains a directory alias")
            _record("d", directory.relative_to(root), stat.S_IMODE(info.st_mode))
        for name in filenames:
            source = base / name
            before_path = source.lstat()
            if (_unsafe_alias(before_path) or not stat.S_ISREG(before_path.st_mode)
                    or before_path.st_nlink != 1):
                raise ValueError("captured tree contains a non-regular or linked file")
            expected = (
                before_path.st_dev, before_path.st_ino, before_path.st_mode,
                before_path.st_nlink, before_path.st_size,
                getattr(before_path, "st_mtime_ns", None),
            )
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(source, flags)
            try:
                opened = os.fstat(fd)
                observed = (
                    opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink,
                    opened.st_size, getattr(opened, "st_mtime_ns", None),
                )
                if observed != expected or _unsafe_alias(opened):
                    raise ValueError("captured tree changed while hashing")
                content = hashlib.sha256()
                remaining = opened.st_size
                while remaining:
                    chunk = os.read(fd, min(remaining, 1024 * 1024))
                    if not chunk:
                        raise ValueError("captured tree file truncated while hashing")
                    content.update(chunk)
                    remaining -= len(chunk)
                after = os.fstat(fd)
                if (
                    after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
                    after.st_size, getattr(after, "st_mtime_ns", None),
                ) != expected:
                    raise ValueError("captured tree changed while hashing")
                _record(
                    "f", source.relative_to(root), stat.S_IMODE(opened.st_mode),
                    opened.st_size, content.hexdigest(),
                )
            finally:
                os.close(fd)
    return manifest.hexdigest()


_SANDBOX_IDENTITY_FIELDS = (
    "backend", "engine", "image", "provider", "runtime", "network",
    "allow_network", "allow_root", "pids_limit", "memory", "memory_mb",
    "cpu", "cpus", "namespace", "service_account", "read_only", "warm",
    "reuse_container", "bounded_output", "authenticated_test_results",
    "test_evidence_protocol", "test_evidence_authority",
)


def _sandbox_identity(sb: object) -> str:
    """Stable, secret-free sandbox configuration identity where exposed."""
    cls = type(sb)
    payload: dict[str, object] = {
        "type": f"{cls.__module__}.{cls.__qualname__}",
    }
    for name in _SANDBOX_IDENTITY_FIELDS:
        try:
            value = getattr(sb, name)
        except Exception:
            continue
        if value is None or type(value) in (str, int, float, bool):
            if isinstance(value, float) and not math.isfinite(value):
                continue
            payload[name] = value
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _toolchain_identity(result: object) -> str:
    """Hash bounded version output from a successful evaluator preflight."""
    output = "\n".join((
        str(getattr(result, "stdout", "") or ""),
        str(getattr(result, "stderr", "") or ""),
    )).replace("\r\n", "\n").strip()
    if not output:
        return ""
    return hashlib.sha256(output.encode("utf-8")[:8192]).hexdigest()


def _execution_context_digest(
    *, arm: str, sandbox_identity: str, sandbox_policy_identity: str,
) -> str:
    """Bind evidence to one arm and its pinned controller execution policy."""
    payload = json.dumps(
        {
            "arm": arm,
            "sandbox_identity": sandbox_identity,
            "sandbox_policy_identity": sandbox_policy_identity,
            "schema": "maverick-code-eval-execution-context-v1",
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _evaluation_scope(
    corpus: CodeEvalCorpus, *, held_out_frac: float,
    held_in: list[str], held_out: list[str], captured_tree: str,
    candidate_tree: str,
    sandbox_identity: str, sandbox_policy_identity: str,
    toolchain_identity: str, baseline_execution_context: str,
    candidate_execution_context: str,
) -> str:
    payload = {
        "schema": "maverick-code-eval-scope-v2",
        "corpus": corpus.evidence_scope,
        "held_out_frac": format(held_out_frac, ".17g"),
        "held_in": held_in,
        "held_out": held_out,
        "captured_tree": captured_tree,
        "candidate_tree": candidate_tree,
        "baseline_execution_context": baseline_execution_context,
        "candidate_execution_context": candidate_execution_context,
        "sandbox": sandbox_identity,
        "sandbox_policy": sandbox_policy_identity,
        "toolchain": toolchain_identity,
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _subset_score(
    ids: list[str], sb, *, command_prefix: str,
    bootstrap_command: str | None, timeout: float, budget,
    subject_sha256: str, execution_context_sha256: str,
) -> Score:
    """Run the given test ids in the (already-resolved, per-copy) sandbox ``sb``
    and score by pass rate. An empty id list is a legitimately empty split →
    ``Score(0.0, 0)`` (the caller's finite guards then skip it). Fails closed
    (0/0) on a budget stop or exec error."""
    if not ids:
        return Score(0.0, 0)
    # ``--`` separates options from positional test args, so a config-supplied
    # id like ``-p evilplugin`` / ``--pdb`` is treated as a (non-existent) test
    # path rather than a pytest flag — defence in depth even though eval_tests is
    # admin/config-owned (config.py is a protected path).
    cmd = command_prefix + " -- " + " ".join(shlex.quote(i) for i in ids)
    if bootstrap_command:
        # ``&&`` is intentional: an unavailable toolchain/dependency is not a
        # candidate score of zero, it is an invalid evaluator environment.  No
        # pytest summary is emitted, and the caller refuses the comparison.
        cmd = f"{bootstrap_command} && {cmd}"
    try:
        request = AuthenticatedTestRequest.issue(
            cmd,
            subject_sha256=subject_sha256,
            execution_context_sha256=execution_context_sha256,
        )
        evidence = _budgeted_authenticated_test_exec(
            sb, request, budget=budget, timeout=timeout,
        )
    except Exception as e:  # pragma: no cover -- exec failure is a 0 score
        log.warning(
            "self_modify_corpus: test command failed (%s)", type(e).__name__)
        return Score(0.0, 0)
    return _authenticated_test_score(sb, request, evidence)


def _exec_ok(result) -> bool:
    ok = getattr(result, "ok", None)
    if ok is not None:
        return bool(ok)
    return getattr(result, "exit_code", 1) == 0


def _verify_workspace_binding(copy_dir: Path, sb, *, timeout: float, budget) -> str | None:
    """Prove ``sb`` is actually rooted at ``copy_dir`` before running code.

    Merely constructing a container/remote backend with a host path does not
    guarantee that the materialized evaluator tree is mounted there.  A backend
    pointed at an empty/default directory would apply and test a different tree.
    Write a nonce into the copy, read it *through the sandbox*, and refuse on any
    mismatch.  This also catches an explicit fixed-root sandbox accidentally
    reused for both baseline and candidate arms.
    """
    marker: Path | None = None
    fd: int | None = None
    nonce = secrets.token_hex(24)
    try:
        fd, raw_path = tempfile.mkstemp(
            prefix=".maverick-eval-binding-", dir=copy_dir)
        marker = Path(raw_path)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("binding marker is not a single-link regular file")
        with os.fdopen(fd, "w", encoding="ascii", newline="") as handle:
            fd = None
            handle.write(nonce)
        visible = marker.lstat()
        if (not stat.S_ISREG(visible.st_mode) or visible.st_nlink != 1
                or (visible.st_dev, visible.st_ino) != (before.st_dev, before.st_ino)):
            raise OSError("binding marker identity changed")
        # LocalBackend on Windows executes through cmd.exe (``type``); all
        # container backends shipped here are POSIX (``cat``).  Compare stdout
        # in the trusted controller instead of interpolating it into shell code.
        host_visible = bool(getattr(sb, "host_visible_fs", False))
        if os.name == "nt" and host_visible:
            command = f"type {marker.name}"
        else:
            command = f"cat -- {shlex.quote(marker.name)}"
        result = _budgeted_exec(sb, command, budget=budget, timeout=timeout)
        if not _exec_ok(result):
            return "sandbox cannot read its materialized workspace"
        if (getattr(result, "stdout", "") or "").strip() != nonce:
            return "sandbox workspace binding nonce mismatch"
        return None
    except Exception as e:
        log.warning(
            "self_modify_corpus: workspace binding failed (%s)", type(e).__name__)
        return "sandbox workspace binding failed or evaluation budget exhausted"
    finally:
        if fd is not None:
            os.close(fd)
        try:
            if marker is not None:
                marker.unlink()
        except OSError:
            pass


def _environment_preflight(corpus: CodeEvalCorpus, sb, *, timeout: float,
                           budget) -> tuple[str | None, str]:
    """Verify the configured evaluator command can start in this sandbox.

    The bootstrap is repeated as part of each real test command because cold
    container backends discard container-local state after every ``exec``.
    """
    command = f"{corpus.command_prefix} --version"
    if corpus.bootstrap_command:
        command = f"{corpus.bootstrap_command} && {command}"
    try:
        result = _budgeted_exec(sb, command, budget=budget, timeout=timeout)
    except Exception as e:
        log.warning(
            "self_modify_corpus: evaluator preflight failed (%s)", type(e).__name__)
        return "evaluator preflight failed or evaluation budget exhausted", ""
    if _exec_ok(result):
        return None, _toolchain_identity(result)
    return "evaluator command/bootstrap unavailable", ""


def _close_sandbox(sb) -> None:
    close = getattr(sb, "close", None)
    if callable(close):
        try:
            close()
        except Exception as e:  # pragma: no cover -- best-effort resource cleanup
            log.debug(
                "self_modify_corpus: sandbox close failed (%s)", type(e).__name__)


def _evaluate_corpus_arms(
    patch: str,
    *,
    corpus: CodeEvalCorpus,
    held_out_frac: float,
    held_in: tuple[str, ...],
    held_out: tuple[str, ...],
    captured_tree: str,
    base_dir: Path,
    cand_dir: Path,
    sb_base,
    sb_cand,
    timeout: float,
    budget,
    apply_fn: Callable[[str, Path, object], ApplyResult] | None,
    sandbox_policy_identity: str = "",
) -> CorpusEvalResult:
    """Evaluate already-isolated, already-bound baseline and candidate arms."""
    base_sandbox_identity = _sandbox_identity(sb_base)
    if base_sandbox_identity != _sandbox_identity(sb_cand):
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason="baseline and candidate sandbox identities differ")
    baseline_execution_context = _execution_context_digest(
        arm="baseline",
        sandbox_identity=base_sandbox_identity,
        sandbox_policy_identity=sandbox_policy_identity,
    )
    candidate_execution_context = _execution_context_digest(
        arm="candidate",
        sandbox_identity=base_sandbox_identity,
        sandbox_policy_identity=sandbox_policy_identity,
    )

    # Refuse before workspace probes, patching, or candidate execution when the
    # backend has only generic exec output. A boolean capability claim is not an
    # evidence channel; the concrete nonce-bound controller method is required.
    for label, sb in (("baseline", sb_base), ("candidate", sb_cand)):
        readiness = evidence_backend_readiness(sb)
        if not readiness.ready:
            return CorpusEvalResult(
                False, 0.0, 0.0, 0, applied=False,
                reason=f"{label} {readiness.message}",
            )

    for label, copy_dir, sb in (
        ("baseline", base_dir, sb_base), ("candidate", cand_dir, sb_cand)
    ):
        binding_error = _verify_workspace_binding(
            copy_dir, sb, timeout=timeout, budget=budget)
        if binding_error:
            return CorpusEvalResult(
                False, 0.0, 0.0, 0, applied=False,
                reason=f"{label} {binding_error}")

    def score(ids, sb, *, subject_sha256, execution_context_sha256):
        return _subset_score(
            ids, sb, command_prefix=corpus.command_prefix,
            bootstrap_command=corpus.bootstrap_command,
            timeout=timeout, budget=budget,
            subject_sha256=subject_sha256,
            execution_context_sha256=execution_context_sha256,
        )

    # Establish baseline viability and headroom before executing a candidate.
    environment_error, baseline_toolchain = _environment_preflight(
        corpus, sb_base, timeout=timeout, budget=budget)
    if environment_error:
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason=f"baseline {environment_error}")
    b_out = score(
        held_out,
        sb_base,
        subject_sha256=captured_tree,
        execution_context_sha256=baseline_execution_context,
    )
    if b_out.samples <= 0:
        return CorpusEvalResult(
            False, b_out.value, 0.0, 0, applied=False,
            reason="held-out baseline evaluator produced no comparable test results")
    if b_out.value >= 1.0:
        return CorpusEvalResult(
            False, b_out.value, b_out.value, b_out.samples, applied=False,
            reason="held-out baseline is saturated at 1.0; configure a "
                   "non-saturated challenge corpus before running DGM")

    try:
        applied = (
            apply_fn(patch, cand_dir, sb_cand) if apply_fn is not None else
            git_apply(patch, cand_dir, sandbox=sb_cand, budget=budget)
        )
    except Exception as e:
        log.warning(
            "self_modify_corpus: candidate apply failed (%s)", type(e).__name__)
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason="candidate patch apply failed or evaluation budget was exhausted")
    if not applied.ok:
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason="candidate patch could not be applied in the isolated workspace "
                   "or evaluation budget was exhausted")
    try:
        candidate_tree = _captured_tree_manifest(cand_dir)
    except Exception as e:
        log.warning(
            "self_modify_corpus: candidate-tree manifest failed (%s)",
            type(e).__name__,
        )
        return CorpusEvalResult(
            False, b_out.value, 0.0, 0, applied=True,
            reason="could not bind evaluation to the patched candidate workspace",
        )
    if hmac.compare_digest(candidate_tree, captured_tree):
        return CorpusEvalResult(
            False, b_out.value, 0.0, 0, applied=True,
            reason="candidate patch reported success but evaluation subject is unchanged",
        )

    environment_error, candidate_toolchain = _environment_preflight(
        corpus, sb_cand, timeout=timeout, budget=budget)
    if environment_error:
        return CorpusEvalResult(
            False, b_out.value, 0.0, 0, applied=True,
            reason=f"candidate {environment_error}")
    if baseline_toolchain != candidate_toolchain:
        return CorpusEvalResult(
            False, b_out.value, 0.0, 0, applied=True,
            reason="baseline and candidate evaluator toolchains differ")

    c_out = score(
        held_out,
        sb_cand,
        subject_sha256=candidate_tree,
        execution_context_sha256=candidate_execution_context,
    )
    b_in = score(
        held_in,
        sb_base,
        subject_sha256=captured_tree,
        execution_context_sha256=baseline_execution_context,
    )
    c_in = score(
        held_in,
        sb_cand,
        subject_sha256=candidate_tree,
        execution_context_sha256=candidate_execution_context,
    )
    if c_out.samples <= 0:
        return CorpusEvalResult(
            False, b_out.value, c_out.value, 0,
            held_in_baseline=b_in.value, held_in_candidate=c_in.value,
            applied=True,
            reason="held-out evaluator produced no comparable test results")
    if held_in and (b_in.samples <= 0 or c_in.samples <= 0):
        return CorpusEvalResult(
            False, b_out.value, c_out.value, b_out.samples,
            held_in_baseline=b_in.value, held_in_candidate=c_in.value,
            applied=True,
            reason="held-in evaluator produced no comparable test results")
    if b_out.samples != c_out.samples:
        return CorpusEvalResult(
            False, b_out.value, c_out.value, min(b_out.samples, c_out.samples),
            held_in_baseline=b_in.value, held_in_candidate=c_in.value,
            applied=True,
            reason=f"held-out test set changed between arms "
                   f"(baseline ran {b_out.samples}, candidate {c_out.samples}); "
                   "refusing to compare across different denominators")
    if b_in.samples != c_in.samples:
        return CorpusEvalResult(
            False, b_out.value, c_out.value, b_out.samples,
            held_in_baseline=b_in.value, held_in_candidate=c_in.value,
            applied=True,
            reason=f"held-in test set changed between arms "
                   f"(baseline ran {b_in.samples}, candidate {c_in.samples}); "
                   "refusing to compare across different denominators")

    overfit = (c_in.value > b_in.value) and (c_out.value <= b_out.value)
    reason = (f"held-out baseline={b_out.value:.4f} candidate={c_out.value:.4f} "
              f"over {b_out.samples} tests"
              + ("; OVERFIT: gained held-in only" if overfit else ""))
    return CorpusEvalResult(
        ok=not overfit,
        baseline_score=b_out.value, candidate_score=c_out.value,
        samples=b_out.samples,
        held_in_baseline=b_in.value, held_in_candidate=c_in.value,
        overfit=overfit, applied=True, reason=reason,
        evidence_scope=_evaluation_scope(
            corpus, held_out_frac=held_out_frac,
            held_in=held_in, held_out=held_out,
            captured_tree=captured_tree,
            candidate_tree=candidate_tree,
            sandbox_identity=base_sandbox_identity,
            sandbox_policy_identity=sandbox_policy_identity,
            toolchain_identity=baseline_toolchain,
            baseline_execution_context=baseline_execution_context,
            candidate_execution_context=candidate_execution_context,
        ),
    )


def evaluate_on_corpus(
    patch: str,
    *,
    src: Path,
    workroot: Path,
    corpus: CodeEvalCorpus,
    sandbox=None,
    sandbox_factory: Callable[[Path], object] | None = None,
    held_out_frac: float = 0.3,
    timeout: float = 600.0,
    budget=None,
    materialize: Callable[[Path, Path], None] | None = None,
    apply_fn: Callable[[str, Path, object], ApplyResult] | None = None,
    require_tracked_source: bool = False,
    expected_source_manifest: str | None = None,
    sandbox_policy_identity: str = "",
) -> CorpusEvalResult:
    """Score a patch on isolated copies against a development challenge corpus.

    Never mutates ``src``; never raises. ``overfit`` is set when the candidate
    improved the adaptive subset but not the confirmation subset. Fails closed
    (non-``ok``) on isolation-policy refusal, a non-applying patch, or an empty
    confirmation split. Because candidates can inspect repository tests and argv,
    the result is research telemetry only, never deployment authorization.

    Execution is **per copy**: baseline and candidate run in their own trees, so
    the exec backend is resolved for each. ``sandbox_factory(copy_dir)`` is the
    seam that builds a backend rooted at a copy (a real container backend per
    copy); the default resolves through :func:`resolve_eval_sandbox`, which under
    require-container/enterprise refuses host exec (fail closed). A custom
    ``apply_fn(patch, candidate_dir, candidate_sandbox)`` receives that exact
    resolved backend; the default applies through it directly."""
    src, workroot = Path(src), Path(workroot)
    if materialize is None:
        def source_materialize(source: Path, dest: Path) -> None:
            _default_materialize(
                source, dest, require_tracked_source=require_tracked_source)
    elif require_tracked_source:
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason="custom materializer cannot prove a tracked source snapshot")
    else:
        source_materialize = materialize
    clone_materialize = materialize or _default_materialize
    make_sb = sandbox_factory or (lambda wd: resolve_eval_sandbox(sandbox, Path(wd)))

    try:
        held_out_frac = float(held_out_frac)
        if not math.isfinite(held_out_frac) or not 0.0 <= held_out_frac <= 1.0:
            raise ValueError("held-out fraction out of range")
        held_in, held_out = corpus.split(held_out_frac=held_out_frac)
    except (TypeError, ValueError, OverflowError):
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason="invalid held-out evaluation fraction")
    if not held_out:
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason="corpus has no held-out split (need >= 2 targeted tests)")

    base_dir, cand_dir = workroot / "baseline", workroot / "candidate"
    try:
        source_materialize(src, base_dir)
        # Clone the candidate arm from the captured baseline snapshot so the
        # two arms cannot observe different source revisions during capture.
        clone_materialize(base_dir, cand_dir)
    except Exception as e:
        log.warning(
            "self_modify_corpus: workspace isolation failed (%s)", type(e).__name__)
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason="could not securely isolate workspace")
    try:
        captured_tree = _captured_tree_manifest(base_dir)
    except Exception as e:
        log.warning(
            "self_modify_corpus: captured-tree manifest failed (%s)",
            type(e).__name__,
        )
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason="could not bind evaluation to captured workspace")
    if expected_source_manifest is not None and not hmac.compare_digest(
        captured_tree, expected_source_manifest
    ):
        return CorpusEvalResult(
            False, 0.0, 0.0, 0, applied=False,
            reason="captured evaluation source does not match expected snapshot",
        )

    sandboxes: list[object] = []
    owns_sandboxes = sandbox_factory is not None or sandbox is None
    try:
        try:
            sb_base = resolve_eval_sandbox(make_sb(base_dir), base_dir)
            sandboxes.append(sb_base)
            sb_cand = resolve_eval_sandbox(make_sb(cand_dir), cand_dir)
            sandboxes.append(sb_cand)
        except EvalSandboxError as exc:
            return CorpusEvalResult(
                False, 0.0, 0.0, 0, applied=False,
                reason=f"sandbox security preflight refused: {exc}")
        except Exception as e:
            # ``build_sandbox`` can raise SandboxPolicyError/RuntimeError as well
            # as EvalSandboxError (missing runtime, invalid backend).  The corpus
            # contract is never-raise/fail-closed, so catch the whole setup seam.
            log.warning(
                "self_modify_corpus: sandbox setup failed (%s)", type(e).__name__)
            return CorpusEvalResult(
                False, 0.0, 0.0, 0, applied=False,
                reason="sandbox setup failed")

        return _evaluate_corpus_arms(
            patch,
            corpus=corpus,
            held_out_frac=held_out_frac,
            held_in=held_in,
            held_out=held_out,
            captured_tree=captured_tree,
            base_dir=base_dir,
            cand_dir=cand_dir,
            sb_base=sb_base,
            sb_cand=sb_cand,
            timeout=timeout,
            budget=budget,
            apply_fn=apply_fn,
            sandbox_policy_identity=sandbox_policy_identity,
        )
    finally:
        if owns_sandboxes:
            # Deduplicate a broken factory that returned the same object twice.
            seen: set[int] = set()
            for sb in reversed(sandboxes):
                if id(sb) not in seen:
                    seen.add(id(sb))
                    _close_sandbox(sb)


__all__ = ["CodeEvalCorpus", "CorpusEvalResult", "evaluate_on_corpus"]
