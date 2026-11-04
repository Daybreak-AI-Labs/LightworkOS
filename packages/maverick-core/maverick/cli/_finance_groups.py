"""Finance and tax CLI groups (finance-agent-suite / tax-prep).

Registered via import at the end of the package
__init__ so the @main.group decorators fire on package import.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import click

from . import _strip_terminal_control, harness, main, open_world

_T = TypeVar("_T")


def _ensure_dreaming_allowed() -> None:
    """Translate the strict learning stop into a stable CLI refusal."""
    from ..learning_guard import Halted, check_learning_halt
    try:
        check_learning_halt("dreaming", "cli_start")
    except Halted as exc:
        raise click.ClickException(
            "dreaming refused: global learning HALT is active") from exc


def _run_dreaming_guarded(operation: Callable[[], _T]) -> _T:
    """Run one dream operation while keeping ``Halted`` out of tracebacks."""
    from ..learning_guard import Halted
    try:
        return operation()
    except Halted as exc:
        raise click.ClickException(
            "dreaming refused: global learning HALT is active") from exc


@main.group("finance")
def finance_grp() -> None:
    """Finance suite: the CFO-office control plane (finance-agent-suite)."""


@finance_grp.command("status")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--strict", is_flag=True,
              help="Exit non-zero if any control needs action (gate CI / deploys).")
def finance_status_cmd(fmt: str, strict: bool) -> None:
    """Report finance control coverage (SoD, maker-checker, DoA tiers, book of
    record, sanctions, encryption, egress, regimes).

    Control coverage only -- not an audit opinion. Agents draft; humans post, pay,
    file, and certify. With --strict, exits non-zero if any control needs action.
    """
    from ..finance.status import (
        finance_status,
        render_status_json,
        render_status_text,
    )
    checks = finance_status()
    click.echo(
        render_status_json(checks) if fmt == "json" else render_status_text(checks)
    )
    if strict:
        needs_action = [c.control for c in checks if c.status == "action_needed"]
        if needs_action:
            raise click.ClickException(
                f"{len(needs_action)} finance control(s) need action: "
                + ", ".join(needs_action)
            )


@finance_grp.command("lint-sod")
def finance_lint_sod_cmd() -> None:
    """Lint the finance roster for segregation-of-duties conflicts (CI gate)."""
    from ..finance.sod_linter import lint_finance_roster
    packs, conflicts = lint_finance_roster()
    if not conflicts:
        click.echo(f"OK: {len(packs)} finance packs are segregation-of-duties clean.")
        return
    for c in conflicts:
        click.echo(f"SoD CONFLICT: {c}", err=True)
    raise click.ClickException(f"{len(conflicts)} SoD conflict(s)")


def _run_self_harness_nightly(world) -> None:
    """Operate the self-harness on the dream beat when ``[self_harness]
    auto_run`` is active (the pristine governed profile enables it): the
    mine -> propose -> validate -> gate cycle for
    every configured role model, so the loop runs without a second cron entry.
    Each model's pass auto-builds its live A/B from ``[self_harness]
    eval_corpus`` when configured (else it is a dry inspection + stale-line
    retirement + canary review). With ``corpus_harvest`` on, hindsight pairs
    feed the corpus too. Refusal or failure stops the combined run visibly;
    earlier dreaming changes may already have been retained."""
    from ..learning_guard import Halted

    try:
        from .. import self_harness
        from ..config import config_source_errors
        st = self_harness.settings()
        if not st.get("_config_valid", True) or config_source_errors(include_tenant=True):
            raise ValueError("Nightly learning settings could not be read")
        if not (self_harness.enabled() and st.get("auto_run")):
            return
        from .. import self_improvement_runner as si_runner
        report = si_runner.run_nightly_self_harness(world)
        if report:
            click.echo(
                f"[self-harness] models={report['models_reviewed']} "
                f"mined={report['patterns_found']} "
                f"promoted={report['improvements_adopted']} "
                f"retired={report['improvements_retired']} "
                f"held_back={report['reviews_held_back']} "
                f"examples={report['examples_prepared']}")
    except Halted as exc:
        raise click.ClickException(
            "Nightly learning review was stopped by the learning safety policy. "
            "Earlier learning changes may already be saved. Review Learning "
            "before starting another pass."
        ) from exc
    except Exception as exc:
        logging.getLogger(__name__).warning(
            "Nightly learning review could not finish (%s).", type(exc).__name__
        )
        raise click.ClickException(
            "Nightly learning review could not finish. Earlier learning changes "
            "may already be saved. Review Learning before trying again."
        ) from exc


@main.command()
@click.option("--max-goals", default=50, show_default=True,
              help="How many recent finished goals to replay.")
@click.option("--rehearse", is_flag=True,
              help="After consolidating, RUN the queued rehearsal cases as "
                   "real (budgeted) practice goals. Spends tokens; gated by "
                   "the calibration interlock.")
@click.option("--rehearse-budget", default=1.0, show_default=True,
              help="Max $ per rehearsal case.")
@click.option("--dry-run", is_flag=True,
              help="Run the full cycle against TEMP COPIES of every learned "
                   "store and report what WOULD change, writing nothing.")
@click.option("--list-snapshots", "list_snaps", is_flag=True,
              help="List learning-state snapshots available for --rollback.")
@click.option("--rollback", default=None, metavar="SNAPSHOT",
              help="Restore every learned store from a snapshot "
                   "('latest' or a name from --list-snapshots), then exit.")
@click.option("--donations-dir", default=None, type=click.Path(),
              help="Also replay donated trajectory records from this "
                   "directory (fleet-level aggregation on a central "
                   "instance).")
@click.pass_context
def dream(ctx, max_goals: int, rehearse: bool, rehearse_budget: float,
          dry_run: bool, list_snaps: bool, rollback: str | None,
          donations_dir: str | None) -> None:
    """Run one offline dreaming cycle (experience consolidation).

    Replays recent successes and failure reflexions, groups them by
    department (domain packs), distills recurring wins into learned skills,
    consolidates recurring failures into dream insights (recalled on future
    similar goals), retires learned skills with a decayed track record, and
    prunes stale near-duplicate reflexions. The consolidation pass is
    deterministic and LLM-free by default -- costs no tokens. Opt in to
    [dreaming] llm_consolidation (or MAVERICK_LLM_CONSOLIDATION=1) to have the
    cheap summarizer model rewrite each lesson into a transferable one, metered
    by [dreaming] llm_consolidation_budget and fail-open to the deterministic
    text. Requires [dreaming] enable = true or MAVERICK_DREAMING=1; run from
    cron/systemd nightly.

    With --rehearse (and [dreaming] rehearse = true to queue cases), the
    biggest recurring failure patterns are re-run as budgeted practice goals
    (titled "[rehearsal] ...") so the next real attempt starts from a system
    that has already practiced. Refused while verifier calibration is frozen.
    """
    from .. import dreaming
    if list_snaps:
        snaps = dreaming.list_snapshots()
        click.echo("\n".join(snaps) if snaps else "(no snapshots yet)")
        return
    if rollback:
        try:
            restored = dreaming.rollback_learning_state(rollback)
        except ValueError as e:
            raise click.ClickException(str(e)) from e
        if not restored:
            raise click.ClickException("no snapshots to roll back to.")
        click.echo("Restored learned state from snapshot: "
                   + ", ".join(restored))
        return
    if not dreaming.enabled():
        raise click.ClickException(
            "dreaming is disabled. Set MAVERICK_DREAMING=1 or add\n"
            "  [dreaming]\n  enable = true\nto ~/.maverick/config.toml."
        )
    # Keep snapshot creation and provider initialization behind the same strict
    # stop as the cycle. Rollback/listing returned above and remain available.
    _ensure_dreaming_allowed()
    world = open_world(ctx.obj["db"])
    if dry_run:
        report = _run_dreaming_guarded(
            lambda: dreaming.dream_cycle_dry(
                world, max_goals=max_goals, donations_dir=donations_dir,
            ),
        )
        click.echo("(dry run -- nothing written) " + report.summary())
        return
    cfg = dreaming.settings()
    with dreaming.learning_mutation_scope() as snap:
        click.echo(f"[snapshot: {snap.name}]")
        # LLM-in-the-loop consolidation (two-key opt-in: the dreaming algorithm
        # knob plus the independent learning provider-egress authority):
        # wire the SAME configured LLM the platform runs on (cheap summarizer role)
        # into insight consolidation, metered by its own small budget and scanned by
        # the shield. Fail-open: with the knob off this stays the deterministic path.
        dream_llm = dream_budget = dream_shield = None
        if dreaming._llm_consolidation_authorized(cfg):
            from ..budget import Budget
            from ..llm import LLM, model_for_role
            dream_llm = LLM(model=model_for_role("summarizer"))
            dream_budget = Budget(
                max_dollars=float(cfg.get("llm_consolidation_budget", 1.0)),
            )
            try:
                from maverick_shield import Shield
                dream_shield = Shield.from_config()
            except Exception:  # pragma: no cover -- kernel runs without the shield
                dream_shield = None
        report = _run_dreaming_guarded(
            lambda: dreaming.dream_cycle(
                world, max_goals=max_goals, donations_dir=donations_dir,
                llm=dream_llm, budget=dream_budget, shield=dream_shield,
            ),
        )
        click.echo(report.summary())
        # Cognitive Data Engine: turn the flywheel as part of the nightly cycle --
        # triage failures by causal impact, mine self-correcting guardrails,
        # consolidate beneficial habits, propose improvements, all grounded in real
        # outcomes. No-op unless [data_engine] is enabled; incomplete work is visible.
        from ..learning_guard import Halted
        try:
            from .. import data_engine
            if data_engine.enabled():
                from ..flywheel import maybe_run
                fw = maybe_run()
                if not fw.complete:
                    raise RuntimeError("The improvement cycle did not finish")
                if fw.acted:
                    click.echo(
                        f"[flywheel] {len(fw.guardrails)} guardrails, {len(fw.memories)} "
                        f"habits, {len(fw.hypotheses)} improvements "
                        f"(recoverable lift ~{fw.predicted_lift:.2f})")
        except Halted as exc:
            raise click.ClickException(
                "The improvement cycle was stopped by the learning safety policy. "
                "Earlier learning changes may already be saved. Review Learning "
                "before starting another cycle."
            ) from exc
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "The improvement cycle could not finish (%s).", type(exc).__name__
            )
            raise click.ClickException(
                "The improvement cycle could not finish. Earlier learning changes "
                "may already be saved. Review Learning before trying again."
            ) from exc
        _run_self_harness_nightly(world)
    if not rehearse:
        return
    cases = dreaming.load_rehearsals()
    if not cases:
        click.echo("Rehearsal: no queued cases (enable [dreaming] rehearse "
                   "so dream cycles queue recurring failures).")
        return
    from ..budget import Budget
    from ..llm import LLM, model_for_role
    from ..orchestrator import run_goal
    from ..sandbox import build_sandbox

    llm = LLM(model=ctx.obj["model"] or model_for_role("orchestrator"))
    sandbox = build_sandbox()
    cases_by_prompt = {str(c.get("prompt", "")): c for c in cases}

    async def _practice(prompt: str) -> str:
        case = cases_by_prompt.get(prompt, {})
        gid = world.create_goal(
            f"[rehearsal] {prompt[:200]}",
            "Dream-time rehearsal of a previously-failing goal pattern.",
        )
        return await run_goal(
            llm=llm, world=world, budget=Budget(max_dollars=rehearse_budget),
            goal_id=gid, sandbox=sandbox, domain=case.get("domain"),
        )

    async def _score(prompt: str, output: str) -> float:
        # Verifier-scored rehearsal: completion alone is a weak signal, so a
        # case only counts as practiced when the calibrated verifier rates
        # the answer too. Scoring spends from its own small budget.
        from ..verifier import verify_proposal
        v = await verify_proposal(
            prompt, output, llm, Budget(max_dollars=max(0.25, rehearse_budget / 4)),
        )
        return float(getattr(v, "confidence", 0.0) or 0.0)

    try:
        passed, total = _run_dreaming_guarded(
            lambda: asyncio.run(dreaming.rehearse(_practice, scorer=_score)),
        )
    except dreaming.RehearsalFrozen as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"Rehearsal: {passed}/{total} previously-failing pattern(s) "
               "now complete (verifier-scored).")


@harness.command("preview")
@click.option("--model", "model_id", default=None,
              help="Model to mine weaknesses for (default: the configured "
                   "orchestrator model).")
@click.option("--min-support", default=3, show_default=True,
              help="Minimum recurring failures before a weakness is a pattern.")
@click.option("--limit", default=500, show_default=True,
              help="How many recent reflexions to scan.")
def self_harness_cmd(model_id: str | None, min_support: int, limit: int) -> None:
    """Inspect the harness weaknesses self-harness would target (dry run).

    Mines this model's recurring failure reflexions into weakness signatures
    and shows the minimal operating-guidance line it would PROPOSE for each --
    it writes nothing. Promotion needs a live held-in/held-out A/B scorer and
    the self-improvement gate ([self_improvement] enable); this command is the
    operator's read-only view of what the loop sees. Requires [self_harness]
    enable = true or MAVERICK_SELF_HARNESS=1.
    """
    from .. import reflexion, self_harness
    if not self_harness.enabled():
        raise click.ClickException(
            "self-harness is off. Set [self_harness] enable = true or "
            "MAVERICK_SELF_HARNESS=1.")
    if min_support < 1:
        # mine_failures treats min_support < 1 as "disabled" and returns nothing;
        # without this guard the command would silently print "No recurring
        # weaknesses", which reads as "your model has none" rather than "you
        # turned mining off". Fail loudly instead.
        raise click.ClickException(
            "--min-support must be >= 1 (a weakness needs at least one recurring "
            "failure to be a pattern).")
    if not model_id:
        from ..llm import model_for_role
        model_id = model_for_role("orchestrator")
    records = [r.to_dict() for r in reflexion.list_recent(limit=limit)]
    eligible = self_harness.count_eligible(records, model_id=model_id)
    sigs = self_harness.mine_failures(
        records, model_id=model_id, min_support=min_support)
    if not sigs:
        click.echo(f"No recurring weaknesses for {model_id!r} "
                   f"(scanned {len(records)} reflexions, {eligible} eligible "
                   f"for this model, min-support {min_support}).")
        # Distinguish "nothing recurs" from "everything was excluded": only
        # unscoped, model-tagged failures are mined, so an operator whose
        # failures are all scoped/remote (or under another model) would
        # otherwise read this as "this model never fails".
        if records and eligible == 0:
            click.echo("  Note: self-harness mines only UNSCOPED, model-tagged "
                       "failures; scoped (channel/user) failures are excluded "
                       "by design.")
        return
    click.echo(f"Weaknesses for {model_id!r} ({len(sigs)} pattern(s)):")
    for sig in sigs:
        proposal = self_harness.propose_addendum(sig)
        line = proposal.addendum_line if proposal else "(no minimal proposal)"
        click.echo(f"\n  [{sig.support}x {sig.failure_class}] {sig.signature}")
        click.echo(f"    would add: {line}")


@main.command("demo")
def demo_cmd() -> None:
    """The two-minute tour: watch the workforce learn, prove it, no API key.

    Seeds a throwaway world (finance goals, repeated failures), runs a real
    dream cycle (consolidation), a real hindsight replay (before vs after
    learning), and the value report -- entirely deterministic and LLM-free,
    in a temp directory that is deleted afterwards. Nothing touches your
    real ~/.maverick state.
    """
    import tempfile
    from pathlib import Path as _P

    from .. import dreaming, hindsight, reflexion, workforce_value
    from ..world_model import WorldModel

    tmp = _P(tempfile.mkdtemp(prefix="maverick-demo-"))
    try:
        world = WorldModel(tmp / "world.db")
        # A quarter's worth of finance work: wins land, one pattern keeps
        # failing -- the raw material every real deployment produces.
        for title in ("Reconcile the March ledger totals",
                      "Reconcile the April ledger totals",
                      "Reconcile the May ledger totals"):
            gid = world.create_goal(title, domain="finance_sox")
            eid = world.start_episode(gid)
            world.end_episode(eid, "tied out", "success")
            world.set_goal_status(gid, "done", result="tied out")
        for title in ("Reconcile the partner ledger feed",
                      "Reconcile the quarterly partner ledger"):
            gid = world.create_goal(title, domain="finance_sox")
            world.set_goal_status(gid, "blocked", result="partner feed lagged")
        state = tmp / "state"
        rpath = state / "reflexions.ndjson"
        for goal in ("Reconcile the partner ledger feed",
                     "Reconcile the quarterly partner ledger"):
            reflexion.record(goal_text=goal, failure_class="agent_error",
                             failure_msg="partner feed lagged a day",
                             reflection="wait for the partner close before "
                                        "reconciling the feed",
                             domain="finance_sox", path=rpath)
        click.echo("1) DREAM -- consolidate the quarter's experience:")
        report = dreaming.dream_cycle(
            world, reflexion_path=rpath,
            insights_path=state / "insights.ndjson",
            skill_store=state / "learned-skills",
            skill_stats_path=tmp / "skill_stats.json",
            rehearsals_path=tmp / "rehearsals.ndjson",
            user_notes_path=tmp / "user_notes.ndjson",
            settings_override={"enable": True, "min_cluster": 2,
                               "prune": False, "user_notes": False},
            # Like the dry run: throwaway stores in a temp directory, so no
            # learning receipt belongs in the installation's activity record.
            audit=False,
        )
        click.echo("   " + report.summary())
        click.echo("\n2) HINDSIGHT -- did learning help on the failures?")
        empty = tmp / "before"
        empty.mkdir()
        h = hindsight.replay(world, before=empty, after=state)
        click.echo("   " + h.summary().replace("\n", "\n   "))
        click.echo("\n3) PROOF -- the value report:")
        v = workforce_value.compute(world, window_days=365, human_cost=120.0)
        click.echo("   " + workforce_value.format_report(v)
                   .replace("\n", "\n   "))
        click.echo("\nDeterministic, token-free, and every step above is "
                   "audited/reversible in a real deployment.")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@main.command("forward")
@click.option("--days", default=30, show_default=True,
              help="Horizon: obligations due within N days.")
@click.pass_context
def forward_cmd(ctx, days: int) -> None:
    """The forward ledger (v1): every known upcoming obligation, pre-staged.

    Lists pending/active goals with deadlines inside the horizon -- overdue
    first -- with the blockers a human will be asked for (open questions),
    so decisions arrive prepared instead of discovered late.
    """
    import time as _time

    from ..forward_ledger import upcoming
    world = open_world(ctx.obj["db"])
    now = _time.time()
    rows = upcoming(world, days=days, now=now)
    if not rows:
        click.echo(f"No goal deadlines within {days} day(s). "
                   "(Set deadlines on goals to populate the forward ledger.)")
        return
    for deadline, g, nq in ((r.deadline, r.goal, r.open_questions) for r in rows):
        delta = (deadline - now) / 86400.0
        when = f"OVERDUE {-delta:.1f}d" if delta < 0 else f"due in {delta:.1f}d"
        title = _strip_terminal_control(g.title)[:70]
        dept = f" [{_strip_terminal_control(g.domain)}]" if g.domain else ""
        blocked = f"  ({nq} question(s) awaiting you)" if nq else ""
        click.echo(f"#{g.id:<5} {when:<16} {title}{dept}{blocked}")


@main.group("tax")
def tax_group() -> None:
    """Tax preparation pipeline: uploaded documents -> first-pass draft return."""


@tax_group.command("prepare")
@click.argument("docs_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--filing-status", type=click.Choice(["single", "mfj", "hoh"]),
              default="single", show_default=True,
              help="Filing status for the first-pass computation.")
@click.option("--dependents", default=0, show_default=True,
              help="Qualifying children under 17 (child tax credit).")
@click.option("--state", "state_code", default=None, metavar="XX",
              help="Resident state for the state return (default: inferred "
                   "from W-2 box 15).")
@click.option("--estimated-payments", default=0.0, show_default=True,
              help="Federal estimated tax already paid (Form 1040-ES).")
@click.option("--prior-year-overpayment", default=0.0, show_default=True,
              help="Prior-year overpayment applied to this year.")
@click.option("--taxpayer-65", is_flag=True,
              help="Taxpayer is 65 or older (additional standard deduction).")
@click.option("--spouse-65", is_flag=True,
              help="Spouse is 65 or older (MFJ; additional standard deduction).")
@click.option("--taxpayer-blind", is_flag=True,
              help="Taxpayer is blind (additional standard deduction).")
@click.option("--spouse-blind", is_flag=True,
              help="Spouse is blind (MFJ; additional standard deduction).")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]),
              default="text", show_default=True,
              help="Output format: human review package or structured JSON "
                   "for programmatic intake.")
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Also write the review package to this file.")
def tax_prepare(docs_dir: str, filing_status: str, dependents: int,
                state_code: str | None, estimated_payments: float,
                prior_year_overpayment: float,
                taxpayer_65: bool, spouse_65: bool, taxpayer_blind: bool,
                spouse_blind: bool, fmt: str, out_path: str | None) -> None:
    """Turn a folder of uploaded documents into a first-pass draft return.

    Reads every ``*.txt`` document in DOCS_DIR (text exports of the client's
    W-2s, 1099s, etc. -- extraction agents handle PDFs upstream), classifies
    and extracts each one deterministically, assembles the workpaper, runs
    the TY2025 federal first pass AND the resident-state first pass (no-tax
    and flat-rate states computed; graduated states handed to the preparer /
    tax engine), and prints the preparer review package: every line cited to
    its source document, every out-of-scope item flagged as an OPEN ITEM.
    A credentialed preparer reviews, completes, and signs -- this never
    files anything.
    """
    from .. import tax_constants, tax_prep
    try:
        from ..config import get_tax
        if get_tax()["auto_update"]:
            status, detail = tax_constants.check_for_update()
            if status == "applied":
                click.echo(f"[tax] {detail}", err=(fmt == "json"))
    except Exception:  # the update channel must never block a prep run
        pass
    federal, state_tables, provenance = tax_constants.active_constants()
    docs = []
    for p in sorted(Path(docs_dir).glob("*.txt")):
        text = p.read_text(encoding="utf-8", errors="replace")
        docs.append(tax_prep.extract(text, label=p.name))
    wp = tax_prep.Workpaper(filing_status=filing_status,
                            dependents_under_17=dependents, docs=docs,
                            state=(state_code or ""),
                            estimated_payments=estimated_payments,
                            prior_year_overpayment=prior_year_overpayment,
                            taxpayer_65_or_older=taxpayer_65,
                            spouse_65_or_older=spouse_65,
                            taxpayer_blind=taxpayer_blind,
                            spouse_blind=spouse_blind)
    draft = tax_prep.compute_first_pass(wp, constants=federal)
    state = (tax_prep.compute_state_first_pass(
                 wp, tax_prep.infer_state(wp), federal=draft,
                 constants=state_tables)
             if docs else None)
    if fmt == "json":
        import json
        data = tax_prep.review_package_dict(draft, state)
        data["constants"] = f"TY{federal['year']} {provenance}"
        package = json.dumps(data, indent=2)
    else:
        package = tax_prep.render_review_package(draft, state)
        package += f"\n\nConstants: TY{federal['year']} {provenance}"
    click.echo(package)
    if out_path:
        Path(out_path).write_text(package + "\n", encoding="utf-8")
        click.echo(f"\nWrote review package -> {out_path}",
                   err=(fmt == "json"))


@tax_group.command("backtest")
@click.argument("cases_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--tolerance", default=None, type=float,
              help="Dollar tolerance for an in-scope line match "
                   "(default $1.00).")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]),
              default="text", show_default=True,
              help="Output format: human report or structured JSON.")
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="Also write the back-test report to this file.")
def tax_backtest(cases_dir: str, tolerance: float | None, fmt: str,
                 out_path: str | None) -> None:
    """Measure first-pass accuracy against a firm's PRIOR FILED returns.

    Point this at a folder of case subdirectories -- each holding a client's
    source ``*.txt`` documents plus a ``filed.json`` with the figures the firm
    actually filed -- and it runs the deterministic pipeline on every case and
    reports how close the draft lands. Returns carrying items the engine
    deliberately doesn't compute (Schedule C/D/E, itemized, graduated-state,
    unsupported status) are listed OUT OF SCOPE and excluded from the accuracy
    number, so "matched N of M in-scope within $T" is an honest signal a firm
    can act on in an afternoon -- on its own data, not synthetic samples.
    """
    from .. import tax_backtest as bt
    tol = bt.DEFAULT_TOLERANCE if tolerance is None else tolerance
    report = bt.run_backtest_dir(cases_dir, tolerance=tol)
    if fmt == "json":
        import json
        text = json.dumps(bt.backtest_dict(report), indent=2)
    else:
        text = bt.render_backtest(report)
    click.echo(text)
    if out_path:
        Path(out_path).write_text(text + "\n", encoding="utf-8")
        click.echo(f"\nWrote back-test report -> {out_path}")


@tax_group.command("onboard")
@click.argument("profile", type=click.Path(exists=True, dir_okay=False))
def tax_onboard(profile: str) -> None:
    """Scope a firm's pilot from its intake profile (a TOML file).

    Sorts every state the firm serves into computed-first-pass (no-tax / flat)
    vs handed-off (graduated -- their tax engine owns it), resolves the firm's
    document-label taxonomy to the canonical types, and prints a ready-to-pilot
    verdict with blockers (must fix) separated from warnings. Run this first to
    set expectations, then `maverick tax backtest` to prove accuracy on the
    firm's own prior filed returns -- together they make "intake in days"
    concrete. Exits non-zero when there are blockers.
    """
    from .. import tax_onboarding as ob
    rep = ob.assess_readiness(ob.load_profile(profile))
    click.echo(ob.render_readiness(rep))
    if not rep.ready_to_pilot:
        raise click.ClickException("onboarding blockers must be resolved "
                                   "before intake (see above)")


@tax_group.command("update")
@click.option("--file", "bundle_file", type=click.Path(exists=True),
              default=None, help="Apply a signed constants bundle from a "
              "file (air-gapped transport).")
@click.option("--url", default=None,
              help="Check this URL instead of [tax] update_url.")
@click.option("--status", "show_status", is_flag=True,
              help="Show the applied constants version and exit.")
@click.option("--rollback", "do_rollback", is_flag=True,
              help="Restore the previously applied constants bundle.")
def tax_update(bundle_file: str | None, url: str | None,
               show_status: bool, do_rollback: bool) -> None:
    """Update the tax computation constants from a SIGNED publisher bundle.

    New tax law ships as a content release, not a code release: the bundle
    is Ed25519-verified against [tax] trusted_constants_pubkeys
    (fail-closed), sanity-validated (rates, brackets, state codes), and
    downgrade-protected before it can replace the tables. With [tax]
    auto_update + update_url configured, `maverick tax prepare` runs this
    check automatically (throttled), so a published law change reaches
    every prep run without an upgrade. The previous bundle is kept for
    --rollback; every apply writes an audit row.
    """
    from .. import tax_constants
    if show_status:
        federal, _, provenance = tax_constants.active_constants()
        click.echo(f"TY{federal['year']} constants: {provenance}")
        return
    if do_rollback:
        ok, reason = tax_constants.rollback()
        if not ok:
            raise click.ClickException(reason)
        click.echo(reason)
        return
    if bundle_file:
        ok, reason = tax_constants.apply_bundle_file(bundle_file)
        if not ok:
            raise click.ClickException(reason)
        click.echo(reason)
        return
    status, detail = tax_constants.check_for_update(url=url, force=True)
    if status == "error":
        raise click.ClickException(detail)
    click.echo(f"{status}: {detail}")


@main.command("proof")
@click.option("--days", default=90, show_default=True,
              help="Window to report over.")
@click.option("--human-cost", default=None, type=float,
              help="Your fully-loaded cost of one comparable human "
                   "deliverable (defaults conservative).")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option("--fleet", is_flag=True,
              help="Also break down ingested fleet experience per vendor.")
@click.pass_context
def proof(ctx, days: int, human_cost, as_json: bool, fleet: bool) -> None:
    """The workforce value report: did the AI workforce pay for itself AND
    get better?

    Assembles throughput (deliverables), economics (agent cost vs your
    human-baseline -> cost avoided + ROI), the capability improvement curve
    (from `maverick hindsight --ledger` runs), and governance (signed audit
    chain) into one read-only report -- per department. The artifact a POC
    ends on and a diligence team runs. Measures only; changes nothing.
    """
    from .. import workforce_value
    world = open_world(ctx.obj["db"])
    v = workforce_value.compute(world, window_days=days, human_cost=human_cost)
    if as_json:
        import json as _json
        click.echo(_json.dumps(workforce_value.to_dict(v), indent=2))
    else:
        click.echo(workforce_value.format_report(v))
    if fleet:
        by_vendor = workforce_value.fleet_breakdown()
        if not by_vendor:
            click.echo("\n(fleet: no ingested external experience yet)")
        else:
            click.echo("\nBy vendor (fleet-ingested):")
            for vendor, c in sorted(by_vendor.items()):
                click.echo(f"  {vendor:<20} {c['deliverables']} deliverable(s), "
                           f"{c['failures']} failure(s)")


@main.command("savings")
@click.option("--days", default=90, show_default=True,
              help="Window to report over.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def savings_cmd(ctx, days: int, as_json: bool) -> None:
    """Money saved vs the typical human cost, from real completed work.

    Uses YOUR cost assumptions ([value] in config, or the dashboard Savings
    page): fully-loaded human hourly rate x human hours per task, compared
    against actual agent spend. Read-only; reports zeros (never invents a
    number) until goals have run.
    """
    from .. import savings as savings_mod
    world = open_world(ctx.obj["db"])
    r = savings_mod.compute(world, window_days=max(1, min(days, 730)))
    if as_json:
        import json as _json
        click.echo(_json.dumps(savings_mod.to_dict(r), indent=2))
        return
    click.echo(f"Savings - last {r.window_days} days ({r.currency})")
    if not r.available:
        click.echo(r.unavailable_reason)
        return
    click.echo("=" * 44)
    click.echo(f"Deliverables completed : {r.deliverables}")
    click.echo(f"Human hours given back : {r.human_hours:,.1f}h")
    click.echo(f"Typical human cost     : ${r.human_cost:,.2f}  "
               f"(${r.hourly_rate:,.2f}/h x {r.hours_per_task:g}h/task)")
    click.echo(f"Actual agent spend     : ${r.agent_cost:,.2f}")
    click.echo(f"Saved                  : ${r.saved:,.2f}")
    if r.agent_cost:
        click.echo(f"ROI                    : {r.roi_multiple:.1f}x")
    if r.by_department:
        click.echo("\nBy department (saved):")
        for d in r.by_department[:12]:
            if not d.deliverables and d.agent_cost == 0:
                continue
            click.echo(f"  {d.department:<22} {d.deliverables:>4} done  "
                       f"${d.saved:>10,.2f} saved  "
                       f"(${d.hourly_rate:,.2f}/h x {d.hours_per_task:g}h)")
    click.echo("\nTune your rate/hours on the dashboard Savings page or "
               "[value] in config.toml.")


@main.command("fleet-memory")
@click.option("--register", default=None, metavar="VENDOR:AGENT_ID",
              help="Register an external agent on the fleet roster.")
@click.option("--description", default="", help="Roster description.")
def fleet_memory_cmd(register: str | None, description: str) -> None:
    """The agent-agnostic learning plane (Learning System of Record).

    External agents (Agentforce, Copilot, custom, OSS runtimes) deposit
    experience into and recall from Lightwork's governed memory via the MCP /
    REST surface; this command manages the roster and shows the console
    view. Requires [fleet_memory] enable = true.
    """
    from .. import fleet_memory
    if register:
        vendor, _, agent_id = register.partition(":")
        if not agent_id:
            raise click.ClickException("--register takes VENDOR:AGENT_ID")
        if not fleet_memory.register_agent(agent_id, vendor,
                                           description=description):
            raise click.ClickException(
                "registration failed (ids must be alphanumeric/._- , <=64 chars)")
        click.echo(f"registered {vendor}:{agent_id}")
        return
    st = fleet_memory.status()
    if not st["agents"]:
        click.echo("fleet roster is empty -- add agents with "
                   "`maverick fleet-memory --register vendor:agent-id`")
        return
    for a in st["agents"]:
        src = a["source"]
        counts = st["ingested"].get(src, {})
        click.echo(f"{src:<40} ingested: {counts.get('success', 0)} success / "
                   f"{counts.get('failure', 0)} failure")
