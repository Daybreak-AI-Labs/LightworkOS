"""Operable driver for the governed DGM research loop.

Phases 1-4 and the gap fixes are library code; nothing *invoked* them. This is the
glue that makes the capability operable: it builds the archive, proposer, eval,
policy, and authoritative-ledger track record from config, runs governed cycles, and
persists the DGM population across runs — the counterpart to
``self_improvement_runner`` for the code rung, and what the ``maverick
self-modify`` CLI drives.

Everything is constructed lazily and the whole thing is a **no-op unless
``[self_modify] enable`` is set** (and the self-improvement engine is on): a
default deployment never proposes, evaluates, or applies anything. The pieces are
injectable seams so a run is testable offline; the defaults wire the real ones:

* **proposer** — :func:`self_modify_loop.llm_proposer` on the coding-role model
  (kernel rule 2; ``model_for_role``). Absent a provider it degrades to the null
  proposer (the loop simply no-ops), never crashing.
* **evaluate** — an isolated-copy development measurement against
  ``[self_modify] eval_tests`` inside an enforced sandbox.
* **policy** — the widening ladder from ``[self_modify] tiers`` (or a single tier
  from ``editable_paths``), unlocked by the authoritative owner-only ledger.
* **archive** — persisted 0600 under the data dir for review and lineage.

The runner searches, evaluates, and archives, but has no live code-promotion or
apply path. Persistent parent branching is also disabled until evaluator
provenance is durably partitioned.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import self_modify as sm
from .learning_guard import Halted, check_learning_halt
from .self_modify_archive import ArchivePersistenceError, CodeArchive
from .self_modify_loop import (
    MAX_DGM_CYCLES,
    CycleReport,
    Proposal,
    SurfaceTier,
    WideningPolicy,
    run_loop,
)

log = logging.getLogger(__name__)


def archive_path() -> Path:
    from .paths import data_dir
    return data_dir("self_modify_archive.json", tenant=None)


def load_archive() -> CodeArchive:
    return CodeArchive.load(archive_path())


def _self_modify_config() -> dict:
    try:
        from .config import load_global_config
        cfg = (load_global_config() or {}).get("self_modify") or {}
        return cfg if isinstance(cfg, dict) else {}
    except Exception:  # pragma: no cover -- config never blocks
        return {}


def _sandbox_config() -> dict:
    try:
        from .config import load_global_config
        cfg = (load_global_config() or {}).get("sandbox") or {}
        return dict(cfg) if isinstance(cfg, dict) else {}
    except Exception:  # pragma: no cover -- secure preflight will refuse local
        return {}


def _sandbox_policy_digest(cfg: dict) -> str:
    """Hash the complete DGM sandbox policy after fail-closed redaction.

    The ordinary backend identity exposes only common attributes. External
    evaluator providers can carry security-relevant nested options, so the
    evidence scope also binds the full pinned policy without retaining secret
    values.
    """
    secret_markers = (
        "api_key", "private_key", "secret", "token", "password", "credential",
    )

    def scrub(value, *, key: str = ""):
        lowered = key.lower()
        if any(marker in lowered for marker in secret_markers):
            return "<redacted>"
        if isinstance(value, dict):
            return {
                str(k): scrub(v, key=str(k))
                for k, v in sorted(value.items(), key=lambda item: str(item[0]))
            }
        if isinstance(value, (list, tuple)):
            return [scrub(v, key=key) for v in value]
        if isinstance(value, str):
            from .safety.secret_detector import redact
            safe, _ = redact(value)
            return safe
        if value is None or type(value) in (bool, int):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else "<non-finite>"
        return f"<{type(value).__module__}.{type(value).__qualname__}>"

    encoded = json.dumps(
        scrub(cfg), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_policy(cfg: dict | None = None) -> WideningPolicy:
    """The widening ladder from config. ``[self_modify] tiers`` is a list of
    ``{name, editable_paths, min_promotions}`` tables (proof-gated widening); when
    absent, a single tier from ``editable_paths`` is used (unlocked at zero, so an
    enabled deployment with an allowlist can start editing). Tier 0 stays empty so
    a fresh deployment with no track record edits nothing."""
    cfg = _self_modify_config() if cfg is None else cfg
    raw_tiers = cfg.get("tiers")
    tiers: list[SurfaceTier] = [SurfaceTier("none", (), 0)]
    if isinstance(raw_tiers, list) and raw_tiers:
        for t in raw_tiers:
            if not isinstance(t, dict):
                continue
            raw_globs = t.get("editable_paths")
            if not isinstance(raw_globs, list) or not all(
                isinstance(glob, str) for glob in raw_globs
            ):
                continue
            globs = tuple(glob.strip() for glob in raw_globs if glob.strip())
            if not globs:
                continue
            raw_minp = t.get("min_promotions", 0)
            if (
                not isinstance(raw_minp, int)
                or isinstance(raw_minp, bool)
                or raw_minp < 0
            ):
                # A malformed proof threshold must make this tier unreachable,
                # never normalize it to zero and unlock a wider code surface.
                continue
            minp = raw_minp
            tiers.append(SurfaceTier(str(t.get("name") or f"tier{minp}"), globs, minp))
    else:
        # A present malformed tiers policy must not fall through to an ungated
        # legacy allowlist.  The fallback is only for true absence/empty tiers.
        if raw_tiers not in (None, []):
            return WideningPolicy(tiers=tuple(tiers))
        raw_globs = cfg.get("editable_paths") or []
        if not isinstance(raw_globs, list) or not all(
            isinstance(glob, str) for glob in raw_globs
        ):
            return WideningPolicy(tiers=tuple(tiers))
        globs = tuple(glob.strip() for glob in raw_globs if glob.strip())
        if globs:
            tiers.append(SurfaceTier("configured", globs, 0))
    return WideningPolicy(tiers=tuple(tiers))


def _default_proposer(
    *,
    tree: Path,
    objective: str,
    feedback="",
    budget=None,
    require_tracked_source: bool = True,
    base_revision: str | None = None,
    source_snapshot: str | None = None,
):
    """Build the grounded coding-role proposer for one reviewed repository.

    The live model receives only an explicit operator objective and a bounded,
    digest-carrying snapshot of the currently earned editable surface. Feedback
    is operator-supplied context only. Candidate/evaluator output is never fed
    back to a hosted proposer: even a scalar score can be a covert channel for
    source or secret material visible inside the sandbox.
    """
    try:
        from .llm import LLM, model_for_role
        from .self_modify_context import build_proposal_context
        from .self_modify_loop import llm_proposer

        def context_factory(surface):
            context = build_proposal_context(
                tree, surface, objective=objective,
                feedback=str(feedback or ""),
                require_tracked_source=require_tracked_source,
            )
            overrides = {}
            if base_revision is not None:
                overrides["base_revision"] = base_revision
            if source_snapshot is not None:
                overrides["snapshot_sha256"] = source_snapshot
            return replace(context, **overrides) if overrides else context

        return llm_proposer(
            LLM(model_for_role("coding")), context_factory=context_factory,
            budget=budget)
    except Exception:  # pragma: no cover -- no provider -> inert proposer
        log.info("self_modify_runner: no coding model available; proposer is inert")
        return lambda *_: None


def _default_evaluate(
    *,
    tree: Path,
    sandbox=None,
    budget=None,
    cfg: dict,
    require_tracked_source: bool = True,
    expected_source_manifest: str | None = None,
    sandbox_cfg: dict | None = None,
):
    """Build the ``evaluate(patch, surface)`` seam against the real ``tree``.

    Uses the targeted development corpus (``[self_modify] eval_tests``) when
    configured. At least two cases are required. Each call runs on a fresh
    throwaway copy under a temp workroot (cleaned up), inside the enforced
    isolation policy. Returns an object exposing ``ok`` / ``baseline_score`` /
    ``candidate_score`` / ``samples`` — what the loop reads.

    Isolation is **per copy**: the corpus path builds a distinct, strictly
    validated backend rooted at each copy. Fixed-root sandbox objects are refused
    because they cannot prove independent baseline/candidate workspace binding.

    Baseline caching is disabled so every candidate and baseline derive from
    the same captured source snapshot."""
    eval_tests = tuple(str(t).strip() for t in (cfg.get("eval_tests") or [])
                       if str(t).strip())
    if len(eval_tests) < 2:
        raise ValueError("a development challenge corpus requires at least two cases")
    if sandbox is not None:
        raise ValueError(
            "a fixed sandbox cannot independently bind baseline and candidate copies")
    # Pin one deployment-global policy snapshot for preflight, baseline and
    # candidate. Reloading between copies lets a changing overlay make the
    # arms execute under different authority even if their exposed backend
    # attributes happen to compare equal.
    pinned_sandbox_cfg = copy.deepcopy(
        sandbox_cfg if sandbox_cfg is not None else _sandbox_config()
    )
    sandbox_policy_identity = _sandbox_policy_digest(pinned_sandbox_cfg)
    eval_command = str(cfg.get("eval_command") or "python3 -m pytest -q").strip()
    bootstrap_raw = cfg.get("eval_bootstrap")
    eval_bootstrap = (str(bootstrap_raw).strip()
                      if bootstrap_raw is not None else None)
    eval_bootstrap = eval_bootstrap or None
    try:
        eval_timeout = float(cfg.get("eval_timeout_seconds", 600.0))
        if not (0.0 < eval_timeout <= 86_400.0):
            raise ValueError("out of range")
    except (TypeError, ValueError):
        log.warning(
            "self_modify_runner: invalid eval_timeout_seconds %r; using 600s",
            cfg.get("eval_timeout_seconds"))
        eval_timeout = 600.0
    def _per_copy_factory(copy_dir):
        # A fresh, config-driven backend rooted at this copy, then tightened to
        # the stock DGM profile (non-host, no egress/root opt-ins, bounded).
        from .sandbox import build_sandbox
        from .self_modify_eval import require_secure_eval_sandbox
        backend = build_sandbox(
            workdir=copy_dir,
            sandbox_config=copy.deepcopy(pinned_sandbox_cfg),
        )
        try:
            return require_secure_eval_sandbox(backend, copy_dir)
        except Exception:
            close = getattr(backend, "close", None)
            if callable(close):
                close()
            raise

    # Resolve the stock security profile before any model proposal can run.
    # This catches the default/local backend and egress/root opt-ins without
    # spending provider tokens on a candidate that can never be evaluated.
    preflight_dir = Path(tempfile.mkdtemp(
        prefix="maverick-selfmod-preflight-", dir=_work_root()))
    preflight_sb = None
    try:
        preflight_sb = _per_copy_factory(preflight_dir)
    finally:
        if preflight_sb is not None:
            close = getattr(preflight_sb, "close", None)
            if callable(close):
                close()
        shutil.rmtree(preflight_dir, ignore_errors=True)

    def _evaluate(patch: str, *_):
        work = Path(tempfile.mkdtemp(prefix="maverick-selfmod-", dir=_work_root()))
        try:
            from .self_modify_corpus import CodeEvalCorpus, evaluate_on_corpus
            return evaluate_on_corpus(
                patch, src=tree, workroot=work,
                corpus=CodeEvalCorpus(
                    test_ids=eval_tests, command_prefix=eval_command,
                    bootstrap_command=eval_bootstrap),
                sandbox_factory=_per_copy_factory, budget=budget,
                timeout=eval_timeout,
                require_tracked_source=require_tracked_source,
                expected_source_manifest=expected_source_manifest,
                sandbox_policy_identity=sandbox_policy_identity,
            )
        finally:
            shutil.rmtree(work, ignore_errors=True)

    return _evaluate


def _work_root() -> str:
    from .file_lock import ensure_private_directory
    from .paths import data_dir
    root = data_dir("self_modify_work", tenant=None)
    ensure_private_directory(root)
    return str(root)


def _capture_stock_tree(tree: Path) -> tuple[Path, Path, str, str]:
    """Capture one tracked source tree shared by the stock proposer/evaluator.

    The proposal prompt and both evaluation arms must derive from the same bytes;
    independently recapturing the operator worktree leaves a proposal/evaluation
    TOCTOU window. The returned root is caller-owned and must be removed.
    """
    root = Path(tempfile.mkdtemp(prefix="maverick-selfmod-source-", dir=_work_root()))
    captured = root / "source"
    try:
        from .self_modify_context import _git_revision
        from .self_modify_corpus import _captured_tree_manifest
        from .self_modify_eval import _default_materialize

        revision_before = _git_revision(tree)
        if revision_before == "unversioned":
            raise ValueError("stock self-modification requires a Git revision")
        _default_materialize(tree, captured, require_tracked_source=True)
        revision_after = _git_revision(tree)
        if revision_after != revision_before or revision_after == "unversioned":
            raise ValueError("Git revision changed during stock source capture")
        digest = _captured_tree_manifest(captured)
        return root, captured, digest, revision_before
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


@dataclass
class RunSummary:
    """Outcome of a runner invocation."""

    ran: bool
    reason: str = ""
    reports: list[CycleReport] = field(default_factory=list)

    @property
    def promoted(self) -> int:
        return sum(1 for r in self.reports if r.promoted)

    @property
    def evaluated(self) -> int:
        return sum(1 for r in self.reports if r.evaluated)


def run(  # noqa: C901 -- orchestration keeps each privileged refusal visible
    cycles: int = 1,
    *,
    tree: Path | None = None,
    sandbox=None,
    proposer: Callable[..., Proposal | None] | None = None,
    evaluate: Callable[[str, object], object] | None = None,
    controller: object | None = None,
    approve: Callable | None = None,
    apply: bool = False,
    budget=None,
    objective: str | None = None,
    feedback: str = "",
    branch_from_archive: bool = False,
    persist: bool = True,
) -> RunSummary:
    """Run ``cycles`` governed DGM cycles end-to-end. A no-op (``ran=False``)
    while the engine is disabled. Loads and (if ``persist``) saves the DGM
    archive; widening reads only the authoritative promotion ledger.
    Never raises — a failure yields a summary whose reports carry the reason.

    The ``proposer``/``evaluate`` seams default to the real coding-model proposer
    and isolated-copy evaluator; inject them (e.g. in tests, or to pin a model)
    to override. The runner proposes/evaluates/archives but never promotes or
    applies code. The stock proposer also requires an explicit ``objective``
    and builds its source context from the earned editable surface. Injected
    proposers remain responsible for their own grounding.

    ``apply`` and inline ``approve`` are retained as compatibility parameters
    but fail closed.  The former one-phase code path could replay approvals and
    record promotion before mutating the repository.  Live adoption must be
    reintroduced only through a nonce/evidence/base-revision-bound manifest and
    the durable PREPARE/CAS/COMMIT transaction API. Archive-parent branching is
    disabled until development and confirmation provenance is durably
    partitioned."""
    from . import self_improvement as si
    from .paths import explicit_tenant_id
    if explicit_tenant_id() is not None:
        return RunSummary(
            False,
            reason=(
                "self-modification is deployment-global and refuses to run "
                "inside an explicit tenant request context"
            ),
        )
    if not (sm.enabled() and sm.improvement_enabled()):
        return RunSummary(False, reason="self-modification disabled "
                          "([self_modify]/[self_improvement] enable)")
    capture_root: Path | None = None
    try:
        if (not isinstance(cycles, int) or isinstance(cycles, bool)
                or not 1 <= cycles <= MAX_DGM_CYCLES):
            return RunSummary(
                False,
                reason=f"cycles must be an integer from 1 to {MAX_DGM_CYCLES}",
            )
        try:
            check_learning_halt("self_modify", "start")
        except Halted:
            return RunSummary(
                False, reason="global learning HALT is active; no cycle ran")
        cfg = _self_modify_config()
        if approve is not None:
            return RunSummary(
                False,
                reason="inline self-modification approval is disabled; use a "
                       "nonce-bound transactional promotion integration",
            )
        if apply:
            return RunSummary(
                False,
                reason="live self-modification apply is disabled until the code "
                       "path uses PREPARE/CAS/COMMIT",
            )
        if branch_from_archive:
            return RunSummary(
                False,
                reason="persistent archive branching is disabled until evaluator "
                       "provenance is durably partitioned",
            )
        configured_tests = tuple(
            str(t).strip() for t in (cfg.get("eval_tests") or [])
            if str(t).strip())
        if evaluate is None and len(configured_tests) < 2:
            return RunSummary(
                False,
                reason="default self-modification evaluation requires a "
                       "non-saturated challenge corpus with at least two "
                       "[self_modify] eval_tests; inject an evaluator only for "
                       "a separately governed evaluation path")
        objective = str(objective or "").strip()
        if proposer is None and not objective:
            return RunSummary(
                False,
                reason="default self-modification proposal requires an explicit "
                       "operator objective")
        if budget is None:
            # Embedders used to get an unbounded DGM unless they happened to
            # construct and thread a Budget themselves. Use the same central
            # config/env/dashboard/tenant-aware funnel as normal agent runs.
            from .budget import budget_from_config
            budget = budget_from_config(task_class="self_modify")
        try:
            budget.check()
        except Exception as e:
            return RunSummary(
                False, reason=f"self-modification budget unavailable: {e}")
        policy = build_policy(cfg)
        archive = load_archive()
        ctrl = controller or si.shared()
        ledger = getattr(ctrl, "ledger", None)
        if ledger is None:
            # Proof-gated widening would otherwise fall back to the forgeable
            # archive booleans. si.shared() always carries a ledger, so this only
            # trips on a hand-built controller with none — warn loudly.
            return RunSummary(
                False,
                reason="self-modification requires an authoritative promotion ledger",
            )
        try:
            tree = (Path(tree) if tree is not None else Path.cwd()).resolve(strict=True)
        except (OSError, ValueError) as e:
            return RunSummary(False, reason=f"self-modification tree unavailable: {e}")
        if not tree.is_dir():
            return RunSummary(False, reason="self-modification tree must be a directory")

        stock_tree = tree
        stock_requires_tracked_source = True
        stock_snapshot: str | None = None
        stock_revision: str | None = None
        if proposer is None and evaluate is None:
            try:
                capture_root, stock_tree, stock_snapshot, stock_revision = (
                    _capture_stock_tree(tree)
                )
            except Exception:
                return RunSummary(
                    False,
                    reason="stock self-modification source capture failed closed",
                )
            # The private capture was populated exclusively from Git-tracked
            # input, so subsequent copies must consume that capture rather than
            # trying to rediscover a .git directory that was intentionally not
            # copied into it.
            stock_requires_tracked_source = False

        capture_invalid = False

        def verify_stock_capture() -> None:
            nonlocal capture_invalid
            if stock_snapshot is None:
                return
            from .self_modify_corpus import _captured_tree_manifest

            try:
                current_snapshot = _captured_tree_manifest(stock_tree)
            except Exception as exc:
                capture_invalid = True
                raise RuntimeError(
                    "stock self-modification source capture unavailable"
                ) from exc
            if current_snapshot != stock_snapshot:
                capture_invalid = True
                raise RuntimeError(
                    "stock self-modification source capture changed"
                )

        from .self_modify_eval import EvalSandboxError
        try:
            raw_ev = evaluate or _default_evaluate(
                tree=stock_tree, sandbox=sandbox, budget=budget, cfg=cfg,
                require_tracked_source=stock_requires_tracked_source,
                expected_source_manifest=stock_snapshot,
            )
        except EvalSandboxError as exc:
            return RunSummary(
                False,
                reason=f"stock self-modification evaluator blocked: {exc}",
            )
        except Exception:
            return RunSummary(
                False,
                reason="stock self-modification evaluator requires a bounded "
                       "non-host sandbox with egress and root disabled",
            )
        raw_prop = proposer or _default_proposer(
            tree=stock_tree, objective=objective,
            feedback=str(feedback or ""), budget=budget,
            require_tracked_source=stock_requires_tracked_source,
            base_revision=stock_revision,
            source_snapshot=stock_snapshot,
        )

        def prop(*args, **kwargs):
            check_learning_halt("self_modify", "proposal")
            verify_stock_capture()
            result = raw_prop(*args, **kwargs)
            verify_stock_capture()
            return result

        def ev(*args, **kwargs):
            check_learning_halt("self_modify", "evaluation")
            verify_stock_capture()
            result = raw_ev(*args, **kwargs)
            verify_stock_capture()
            check_learning_halt("self_modify", "post-evaluation")
            return result

        reports = run_loop(
            archive=archive, proposer=prop, evaluate=ev, policy=policy,
            cycles=cycles, rung="code", controller=ctrl, ledger=ledger,
            approve=None, tree=None,
            branch_from_archive=branch_from_archive)
        if capture_invalid:
            return RunSummary(
                False,
                reports=reports,
                reason="stock self-modification source capture changed; run refused",
            )
        try:
            check_learning_halt("self_modify", "before-archive-persist")
        except Halted:
            return RunSummary(
                False, reports=reports,
                reason="global learning HALT is active; archive was not persisted",
            )
        if persist:
            try:
                archive.save(archive_path())
            except ArchivePersistenceError:
                return RunSummary(
                    False,
                    reports=reports,
                    reason="research archive persistence failed closed",
                )
        return RunSummary(True, reports=reports)
    except Halted:
        return RunSummary(
            False, reason="global learning HALT interrupted the research cycle")
    except Exception as e:  # pragma: no cover -- a privileged driver never crashes a run
        log.warning("self_modify_runner: run failed closed (%s)", type(e).__name__)
        return RunSummary(
            False, reason="runner safety check or execution failed closed")
    finally:
        if capture_root is not None:
            shutil.rmtree(capture_root, ignore_errors=True)


__all__ = [
    "RunSummary", "archive_path", "load_archive", "build_policy", "run",
]
