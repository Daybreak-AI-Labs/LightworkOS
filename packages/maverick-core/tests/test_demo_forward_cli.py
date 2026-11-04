"""`maverick demo` (token-free learning tour) and `maverick forward` (v1)."""
from __future__ import annotations

import time

from click.testing import CliRunner
from maverick.cli import main
from maverick.world_model import WorldModel


def test_demo_runs_token_free_and_shows_the_arc(tmp_path):
    res = CliRunner().invoke(main, ["--db", str(tmp_path / "x.db"), "demo"])
    assert res.exit_code == 0, res.output
    assert "DREAM" in res.output and "HINDSIGHT" in res.output
    assert "wrote 1 insight" in res.output
    assert "2 gained, 0 regressed" in res.output
    assert "Deliverables completed : 3" in res.output


def test_forward_lists_overdue_first_with_blockers(tmp_path):
    db = tmp_path / "w.db"
    w = WorldModel(db)
    now = time.time()
    g1 = w.create_goal("File the quarterly VAT return", domain="finance_vat_uk")
    w.set_goal_deadline(g1, now - 86400) if hasattr(w, "set_goal_deadline") else None
    # set deadlines directly (no setter API): update via SQL
    with w._writing() as conn:
        conn.execute("UPDATE goals SET deadline=? WHERE id=?", (now - 86400, g1))
    g2 = w.create_goal("Renew the supplier contract")
    with w._writing() as conn:
        conn.execute("UPDATE goals SET deadline=? WHERE id=?", (now + 5 * 86400, g2))
    w.add_question("Which VAT scheme applies?", goal_id=g1) if hasattr(w, "add_question") else None
    res = CliRunner().invoke(main, ["--db", str(db), "forward", "--days", "30"])
    assert res.exit_code == 0, res.output
    lines = [ln for ln in res.output.splitlines() if ln.startswith("#")]
    assert "OVERDUE" in lines[0] and "VAT" in lines[0]
    assert "due in" in lines[1]


def test_forward_strips_terminal_controls_from_goal_text(tmp_path):
    db = tmp_path / "w.db"
    w = WorldModel(db)
    now = time.time()
    title = "attacker-prefix \x1b]52;c;cHduZWQ=\x07 after-osc52 \x1b[2J after-clear"
    domain = "ops\x1b[31mred"
    goal_id = w.create_goal(title, domain=domain)
    with w._writing() as conn:
        conn.execute("UPDATE goals SET deadline=? WHERE id=?", (now - 86400, goal_id))

    res = CliRunner().invoke(main, ["--db", str(db), "forward", "--days", "30"])

    assert res.exit_code == 0, res.output
    assert "\x1b]52" not in res.output
    assert "\x1b[2J" not in res.output
    assert "\x1b[31m" not in res.output
    assert "attacker-prefix  after-osc52  after-clear [opsred]" in res.output


def test_forward_empty_is_friendly(tmp_path):
    db = tmp_path / "w.db"
    WorldModel(db)
    res = CliRunner().invoke(main, ["--db", str(db), "forward"])
    assert res.exit_code == 0 and "No goal deadlines" in res.output
