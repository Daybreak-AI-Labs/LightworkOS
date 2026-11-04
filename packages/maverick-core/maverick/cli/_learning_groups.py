"""Learning-proof, domains, and insights CLI commands.

Registered by importing this module at the end
of the package __init__ so the @main.command decorators fire on package import.
"""
from __future__ import annotations

from pathlib import Path

import click

from . import main


@main.command("hindsight")
@click.option("--before", default="latest",
              help="Older learned-state snapshot to compare against "
                   "('latest' = most recent dream snapshot, or a snapshot "
                   "name from `maverick dream --list-snapshots`).")
@click.option("--limit", default=100, show_default=True,
              help="How many recent goals to replay.")
@click.option("--all-goals", is_flag=True,
              help="Replay all recent goals, not just failed ones.")
@click.option("--ledger", is_flag=True,
              help="Save an aggregate hindsight summary and audit event.")
@click.option("--strict", is_flag=True,
              help="Exit non-zero if any coverage regression is found "
                   "(a learning-regression CI gate).")
@click.pass_context
def hindsight(ctx, before: str, limit: int, all_goals: bool, ledger: bool,
              strict: bool) -> None:
    """Did today's learned state get better or WORSE on past work?

    Replays recent goals against a prior learned-state snapshot and today's
    state, comparing whether each goal is still covered by a recalled lesson
    (reflexion / dream insight / learned skill). Surfaces *regressions* --
    goals a retired skill, expired insight, or pruned reflexion no longer
    covers. Deterministic and read-only (no agent re-runs, no tokens);
    snapshots come from `maverick dream`.
    """
    from .. import dreaming
    from .. import hindsight as _h
    from . import open_world  # lazy: keep maverick.cli.open_world monkeypatch-reachable
    snaps = dreaming.list_snapshots()
    if not snaps:
        raise click.ClickException(
            "no learned-state snapshots yet -- run `maverick dream` "
            "(it snapshots before each cycle) at least twice first."
        )
    chosen = snaps[-1] if before == "latest" else before
    if chosen not in snaps:
        raise click.ClickException(
            f"no such snapshot {chosen!r}. Available: {', '.join(snaps)}"
        )
    snap_dir = dreaming.snapshots_dir() / chosen
    world = open_world(ctx.obj["db"])
    report = _h.replay(
        world, before=snap_dir, after=None, limit=limit,
        status=None if all_goals else "blocked",
    )
    click.echo(report.summary())
    if ledger:
        if not _h.write_ledger(report, before_label=chosen):
            raise click.ClickException(
                "hindsight recording incomplete; the local summary may already "
                "be saved. Inspect the ledger and audit log before retrying."
            )
        click.echo("[saved to the local hindsight ledger and audit log]")
    if strict and report.regressed:
        raise click.ClickException(
            f"{len(report.regressed)} learning regression(s) detected"
        )


@main.command("prove-learning")
@click.option("--scores", "scores_path", required=True,
              type=click.Path(exists=True, dir_okay=False),
              help='JSON file {"baseline": [...], "treatment": [...]} of paired '
                   "per-task success scores in [0,1]: the SAME held-out tasks "
                   "run with learning FROZEN (control) vs LIVE (treatment), e.g. "
                   "via MAVERICK_LEARNING_FROZEN=1 then =0.")
@click.option("--confidence", default=0.95, show_default=True,
              help="Confidence level for the bootstrap CI.")
@click.option("--seed", default=1234, show_default=True,
              help="Bootstrap seed -- the reported lift is reproducible per seed.")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as JSON.")
@click.option("--strict", is_flag=True,
              help="Exit non-zero unless learning SIGNIFICANTLY improved the "
                   "suite (a provable-learning CI gate).")
def prove_learning(scores_path: str, confidence: float, seed: int,
                   as_json: bool, strict: bool) -> None:
    """Prove whether self-learning improves success on a held-out suite.

    Takes paired success scores -- the same held-out tasks run with learning
    FROZEN (control) vs LIVE (treatment) -- and reports the mean paired lift
    with a seeded bootstrap CI, so the verdict is reproducible and falsifiable.
    Collect the two arms by running your suite under MAVERICK_LEARNING_FROZEN=1
    then =0 (the kernel honors that hard override). --strict turns it into a CI
    gate that fails unless learning significantly helped (never on a regression).
    """
    import json as _json
    from dataclasses import asdict

    from ..learning_proof import paired_lift
    try:
        data = _json.loads(Path(scores_path).read_text(encoding="utf-8"))
        baseline = [float(x) for x in data["baseline"]]
        treatment = [float(x) for x in data["treatment"]]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise click.ClickException(
            'scores file must be {"baseline": [...], "treatment": [...]} with '
            f"equal-length numeric lists: {e}"
        ) from e
    try:
        result = paired_lift(
            baseline, treatment, confidence=confidence, seed=seed,
        )
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    click.echo(_json.dumps(asdict(result), indent=2) if as_json
               else result.summary())
    if strict and not result.improved:
        raise click.ClickException(
            "learning did not significantly improve the held-out suite"
        )


@main.command("domains-lint")
@click.option("--ci", is_flag=True,
              help="Exit non-zero when any pack has an ERROR-level finding.")
@click.option("--warnings", "show_warnings", is_flag=True,
              help="Also print warning-level findings (quality gaps).")
def domains_lint(ci: bool, show_warnings: bool) -> None:
    """Lint every domain pack (built-in + operator) for envelope and
    quality gaps.

    Errors weaken the safety envelope (empty tool allowlist = ALL tools,
    missing/unknown max_risk); warnings are pack-quality gaps (thin persona,
    no knowledge sources, no deny list). Operator packs in the workspace
    domains dir are linted alongside the built-ins.
    """
    from ..domain import available_domains, lint_profile, rejected_workspace_domains
    from ..domain_prose_lint import known_tool_names, lint_profiles
    domains = available_domains()
    n_err = n_warn = 0
    for name in sorted(domains):
        errors, warnings = lint_profile(domains[name])
        n_err += len(errors)
        n_warn += len(warnings)
        for e in errors:
            click.echo(f"ERROR  {name}: {e}", err=True)
        if show_warnings:
            for w in warnings:
                click.echo(f"warn   {name}: {w}")
    for name, errors in sorted(rejected_workspace_domains().items()):
        n_err += len(errors)
        for error in errors:
            click.echo(f"ERROR  {name}: {error}", err=True)
    # The prose lint (text defects, duplicate personas, unknown tools) is part
    # of the same gate: a pack that reads wrong is as broken as one that is
    # envelope-unsafe. Mechanical classes fix with
    # ``python -m maverick.domain_prose_lint --fix``.
    prose = lint_profiles(domains, known_tools=known_tool_names())
    n_err += len(prose)
    for f in prose:
        click.echo(f"ERROR  {f}", err=True)
    click.echo(f"{len(domains)} pack(s): {n_err} error(s), {n_warn} warning(s)"
               + ("" if show_warnings else " (use --warnings to list them)"))
    if ci and n_err:
        raise click.ClickException(f"{n_err} pack error(s)")


@main.command("domains-audit")
@click.option("--json", "json_out", type=click.Path(),
              help="Write the full machine-readable audit document to this path.")
@click.option("--suite", default=None,
              help="Limit the report to one suite (e.g. finance, hr, healthcare).")
def domains_audit(json_out: str | None, suite: str | None) -> None:
    """Governance-posture inventory of the specialist roster.

    The auditable answer to "what can these agents do, and what stops them?":
    per pack, the compartment seal, risk ceiling, whether any state-mutating
    tool is reachable, the hard refusals it carries, and the human sign-off on
    its deliverable. ``--json`` exports the full document for a GRC system;
    ``domains-lint`` remains the pass/fail well-formedness gate.
    """
    from ..domain_audit import audit_roster, summarize, to_json
    audits = audit_roster()
    if suite:
        audits = [a for a in audits if a.suite == suite]
        if not audits:
            raise click.ClickException(f"no packs in suite {suite!r}")
    s = summarize(audits)
    click.echo(f"{s['packs']} pack(s) across {s['suites']} suite(s); "
               f"{s['builders']} builder(s)")
    click.echo(f"  drafting agents that can reach a state-mutator: "
               f"{s['drafting_agents_reaching_a_mutator']}  (must be 0)")
    click.echo(f"  with enforced persisted sign-off: {s['packs_with_human_gate']}")
    click.echo(
        "  with prompt-only unenforced gate:  "
        f"{s['packs_with_unenforced_prompt_gate']}"
    )
    click.echo(f"  with suite/pack refusals:     {s['packs_with_refusals_beyond_universal']}")
    click.echo(f"  with a declared deliverable:  {s['packs_with_deliverable']}")
    click.echo(f"  with a reasoning-effort tier: {s['packs_with_effort_tier']}")
    _ap = s.get("autonomy_posture", {})
    click.echo(
        "  autonomy posture (baseline rung): "
        f"observe={_ap.get('observe', 0)} suggest={_ap.get('suggest', 0)} "
        f"request={_ap.get('request', 0)} auto={_ap.get('auto', 0)}; "
        f"onboarding={s.get('packs_onboarding', 0)}")
    flagged = [a for a in audits if a.reachable_dangerous and not a.is_builder]
    for a in flagged:
        click.echo(f"  FLAG {a.name}: reaches {', '.join(a.reachable_dangerous)}", err=True)
    if json_out:
        import json as _json
        Path(json_out).write_text(_json.dumps(to_json(audits), indent=2),
                                  encoding="utf-8")
        click.echo(f"Wrote audit document -> {json_out}")
    if flagged:
        raise click.ClickException(
            f"{len(flagged)} drafting pack(s) can reach a state-mutator")


@main.command("workforce-graduation")
@click.option("--db", "db_path", type=click.Path(), default=None,
              help="World DB to read the approvals history from (default: the configured one).")
def workforce_graduation(db_path: str | None) -> None:
    """Which onboarding agents have earned graduation to more autonomy?

    Reads the human approval decisions on each agent's gated actions (the same
    record predictive-approvals learns from) and lists the hires with a clean
    enough record to graduate -- the advisory signal a client acts on by setting
    ``onboarding = false`` under ``[workforce.agents]`` (or by enabling
    ``[workforce] auto_graduate``). Advisory only: it never changes a config.
    """
    from ..agent_autonomy import graduation_candidates
    from ..domain import available_domains
    try:
        from ..world_model import close_world_if_owned, open_world
        wm = open_world(Path(db_path)) if db_path else open_world()
        try:
            approvals = wm.list_approvals(limit=5000)
        finally:
            close_world_if_owned(wm)
    except Exception as e:  # pragma: no cover -- no DB / empty install
        raise click.ClickException(f"could not read approvals history: {e}") from e
    names = sorted(available_domains())
    cands = graduation_candidates(approvals, names)
    if not cands:
        click.echo("No agents have earned graduation yet "
                   "(need a clean record of human-approved actions).")
        return
    click.echo(f"{len(cands)} agent(s) ready to graduate from onboarding:")
    for v in cands:
        click.echo(f"  {v.name}: {v.reason} (confidence {v.confidence:.2f})")
    click.echo("\nGraduate one by adding to ~/.maverick/config.toml:")
    click.echo("  [[workforce.agents]]\n  name = \"<agent>\"\n  onboarding = false")


@main.command("earned-autonomy")
@click.option("--reconcile", "do_reconcile", is_flag=True,
              help="Score unscored consequence cards against landed real "
                   "outcomes first (may graduate or demote action types).")
@click.option("--revoke", "revoke_action", default=None, metavar="ACTION",
              help="Clear ACTION's evidence qualification. Explicit standing "
                   "consent grants are managed separately.")
def earned_autonomy(do_reconcile: bool, revoke_action: str | None) -> None:
    """Review action-level prediction evidence; evidence does not grant approval."""
    from ..earned_autonomy import enabled, shared
    engine = shared()
    if revoke_action:
        ok = engine.revoke(revoke_action)
        if not ok:
            raise click.ClickException(f"evidence revocation not confirmed for {revoke_action!r}")
        click.echo(f"Evidence qualification cleared for {revoke_action!r}. "
                   "Explicit standing consent grants are unchanged.")
    if do_reconcile:
        from . import _learning_cli_preflight, _run_learning_cli
        _learning_cli_preflight("earned_autonomy")
        report = _run_learning_cli("earned_autonomy", engine.reconcile)
        click.echo(f"Reconciled {report.scored} card(s): {report.hits} hit(s), "
                   f"{report.misses} miss(es), {report.superseded} superseded; "
                   f"graduated {list(report.graduated) or 'none'}, demoted "
                   f"{list(report.demoted) or 'none'}.")
    states = engine.status()
    if not enabled():
        click.echo("Earned-autonomy evidence collection is disabled. "
                   "Evidence does not grant approval.")
    if not states:
        click.echo("No consequence-card evidence yet (cards are pinned when "
                   "rehearsed high-risk actions run, and scored when reality "
                   "reports back via `maverick record-outcome`).")
        return
    click.echo(f"Cards: {engine.cards.verify()}  Ledger: {engine.ledger.verify()}")
    for s in states:
        dial = "evidence qualified; no approval granted" if s.graduated else "no approval granted by evidence"
        click.echo(f"  {s.action}: {dial} -- "
                   f"{s.hits}/{s.samples} accurate, streak {s.streak}")


@main.command("domains-eval")
@click.option("--check", "check_only", is_flag=True,
              help="Lint the eval suite against the roster and exit (no provider needed).")
def domains_eval(check_only: bool) -> None:
    """Per-pack behavioral evals: does a specialist do its job?

    The rubric scorer is deterministic, but running a case needs to spawn the
    pack agent (a provider key). This command lints the golden suite -- every
    case names a real pack and carries a non-empty rubric -- which is the
    CI-safe, key-free gate; ``run_eval(cases, runner)`` in maverick.domain_eval
    executes them live when a caller supplies an agent runner.
    """
    from ..domain_eval import GOLDEN_CASES, check_suite
    problems = check_suite()
    for p in problems:
        click.echo(f"ERROR  {p}", err=True)
    click.echo(f"{len(GOLDEN_CASES)} golden eval case(s) across "
               f"{len({c.domain for c in GOLDEN_CASES})} pack(s); "
               f"{len(problems)} problem(s)")
    for c in GOLDEN_CASES:
        dims = []
        if c.expect_includes:
            dims.append(f"includes={list(c.expect_includes)}")
        if c.expect_excludes:
            dims.append(f"excludes={list(c.expect_excludes)}")
        if c.expect_refusal:
            dims.append("refuses")
        if c.expect_citation:
            dims.append("cites")
        click.echo(f"  {c.domain}: {', '.join(dims)}")
    if not check_only:
        click.echo("\nLive scoring needs a provider key; run via "
                   "maverick.domain_eval.run_eval(cases, runner).")
    if problems:
        raise click.ClickException(f"{len(problems)} eval-suite problem(s)")


@main.command("insights-export")
@click.argument("out", type=click.Path())
@click.option("--max", "max_insights", default=50, show_default=True,
              help="How many of the most recent insights to bundle.")
def insights_export(out: str, max_insights: int) -> None:
    """Export local dream insights as a SIGNED bundle for a trusted peer.

    Federated insight exchange: only consolidated lessons cross the boundary
    (never raw trajectories or user content). The bundle is signed with this
    instance's Ed25519 audit key; give the peer your public key (printed
    here) to add to their [dreaming] trusted_insight_pubkeys. Transport is
    yours: move the file however your security policy allows.
    """
    from ..insight_exchange import export_insights
    try:
        path = export_insights(out, max_insights=max_insights)
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e
    import json as _json
    bundle = _json.loads(Path(path).read_text(encoding="utf-8"))
    click.echo(f"Wrote {len(bundle['insights'])} insight(s) -> {path}")
    click.echo(f"Your public key (for the peer's trusted_insight_pubkeys):\n"
               f"  {bundle['peer_key']}")


@main.command("insights-import")
@click.argument("bundle", type=click.Path(exists=True))
def insights_import(bundle: str) -> None:
    """Import a peer's signed insight bundle (fail-closed verification).

    Requires the peer's public key in [dreaming] trusted_insight_pubkeys;
    unsigned, untrusted, or tampered bundles are rejected outright. Each
    imported lesson is redacted, Shield-scanned, provenance-tagged, and
    merged through the same dedup gate local dreaming uses.
    """
    from ..insight_exchange import import_insights
    from ..orchestrator import _build_shield
    imported, reason = import_insights(
        bundle, shield=_build_shield(), operator_ref="local CLI operator",
        operator_basis="local_process",
    )
    if reason != "ok":
        raise click.ClickException(reason)
    click.echo(f"Imported {imported} peer insight(s).")
