"""Seed the demo world model with a handful of finished goals.

Runs once at stack start (the compose `seed` service / the k8s init
container) inside the maverick image, against the shared state volume.
Uses the REAL world-model API — ``WorldModel.create_goal`` +
``set_goal_status`` (maverick/world_model.py) — so the dashboard renders
exactly what a live deployment would.

Statuses are the ones the world model actually writes: ``done`` for
successes and ``blocked``/``cancelled`` for failures (there is no literal
``failed`` status). Only *finished* goals are seeded: anything left
``active`` with no agent attached would be reclaimed as orphaned by the
dashboard on startup.

Idempotent for the public demo owner: if demo-owned goals already exist, it
exits without writing. Non-demo state in a reused volume is ignored by the
public /demo page and must not suppress seeding the public sample data.
"""
from __future__ import annotations

from maverick.world_model import DEFAULT_DB, WorldModel

# (title, description, status, result)
DEMO_GOALS = [
    (
        "Summarize Q2 incident reports",
        "Read the 14 incident postmortems from Q2 and produce a themes memo.",
        "done",
        "Memo delivered: 3 recurring themes (flaky deploy gate, on-call "
        "alert fatigue, stale runbooks) with owners and suggested fixes.",
    ),
    (
        "Triage open dependency CVEs",
        "Check the dependency tree against the advisory feed and rank by "
        "exploitability.",
        "done",
        "12 advisories triaged: 2 actionable (urllib3, jinja2) with pinned "
        "upgrade PRs drafted; 10 not applicable to our usage.",
    ),
    (
        "Draft the self-hosting upgrade guide",
        "Turn the 0.1.x -> 0.2.x migration notes into a step-by-step guide "
        "for VPS operators.",
        "done",
        "Guide drafted with rollback section and a pre-flight checklist; "
        "reviewed and filed under docs/.",
    ),
    (
        "Benchmark swarm fan-out on the nightly suite",
        "Run the continuous benchmark at fan-out 4 and 8 and compare cost "
        "per solved task.",
        "done",
        "Fan-out 8 solved 6% more tasks at 2.1x cost; recommendation: keep "
        "4 as the default, 8 behind a flag for hard goals.",
    ),
    (
        "Reconcile vendor invoices against PO ledger",
        "Match March vendor invoices to purchase orders and flag mismatches.",
        "blocked",
        "Blocked: the ledger export needs finance-system credentials that "
        "were not provisioned for this demo environment.",
    ),
    (
        "Migrate analytics jobs to the new scheduler",
        "Port the nightly analytics cron jobs to `maverick schedule`.",
        "cancelled",
        "Cancelled by operator: superseded by the platform team's own "
        "migration ticket.",
    ),
]


def main() -> None:
    world = WorldModel(DEFAULT_DB)
    if world.list_goals(owner="demo", limit=1):
        print("seed_demo: demo goals already present; nothing to do")
        return
    for title, description, status, result in DEMO_GOALS:
        goal_id = world.create_goal(title, description, owner="demo")
        world.set_goal_status(goal_id, status, result)
        print(f"seed_demo: #{goal_id} [{status}] {title}")
    print(f"seed_demo: seeded {len(DEMO_GOALS)} finished goals into {DEFAULT_DB}")


if __name__ == "__main__":
    main()
