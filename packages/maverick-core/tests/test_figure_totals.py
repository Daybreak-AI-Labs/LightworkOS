import pytest
from maverick.budget import Budget
from maverick.figure_totals import answer_issues, rows_issues
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel

_PAYROLL = """\
| Employee | Week 1 Gross | Week 2 Gross | Two-Week Gross |
|---|---:|---:|---:|
| Ana Ruiz | $1,030.80 | $1,340.04 | $2,370.84 |
| Ben Okafor | $1,277.56 | $1,849.10 | $3,126.66 |
| Chloe Tan | $1,175.08 | $729.36 | $1,904.44 |
"""


def test_a_total_row_that_does_not_add_up_is_named():
    # Live: a payroll's grand total was typed as $20,405.96; the rows add to
    # $20,404.96.
    issues = answer_issues(_PAYROLL + "| **Grand total** | | | **$7,402.94** |\n")
    assert issues == ['The "Grand total" row gives Two-Week Gross as 7,402.94, but the rows above it add to '
                      "7,401.94."]
    assert answer_issues(_PAYROLL + "| **Grand total** | $3,483.44 | $3,918.50 | **$7,401.94** |\n") == []


def test_a_total_line_under_a_table_that_nearly_matches_a_column_is_named():
    issues = answer_issues(_PAYROLL + "\n**Grand total gross pay: $7,402.94**\n")
    assert issues == ['"Grand total gross pay: $7,402.94" does not match the table: its Two-Week Gross column '
                      "adds to 7,401.94."]
    assert answer_issues(_PAYROLL + "\nGrand total gross pay: $7,401.94\n") == []
    # A figure far from every column is about something else.
    assert answer_issues(_PAYROLL + "\nTotal hours this year: 4,120\n") == []


def test_subtotal_tax_and_total_chains_add_up():
    invoice = ("| Item | Amount |\n|---|---|\n| Design | $1,000.00 |\n| Copy | $200.00 |\n"
               "| Subtotal | $1,200.00 |\n| Sales tax (8.25%) | $99.00 |\n| **Total** | **$1,299.00** |\n")
    assert answer_issues(invoice) == []
    assert answer_issues(invoice.replace("$1,299.00", "$1,300.00")) == [
        'The "Total" row gives Amount as 1,300.00, but the rows above it add to 1,299.00.']


def test_group_totals_a_grand_total_discounts_and_averages_are_understood():
    groups = ("| Team | Cost |\n|---|---|\n| Ops A | 10 |\n| Ops B | 20 |\n| Total Ops | 30 |\n"
              "| Sales A | 5 |\n| Total Sales | 5 |\n| Grand total | 35 |\n")
    assert answer_issues(groups) == []
    discount = "| Line | Amount |\n|---|---|\n| Work | 500 |\n| Discount | 50 |\n| Total | 450 |\n"
    assert answer_issues(discount) == []
    average = "| Name | Score | Hours |\n|---|---|---|\n| A | 80 | 10 |\n| B | 90 | 20 |\n| Total | 85 | 30 |\n"
    assert answer_issues(average) == []


def test_percent_columns_and_tables_without_totals_are_left_alone():
    table = "| Month | Revenue | Growth |\n|---|---|---|\n| Jan | 100 | — |\n| Feb | 110 | 10% |\n"
    assert answer_issues(table + "| Total | 210 | 7% |\n") == []
    assert answer_issues(table) == [] and answer_issues("No tables here. Total: $5") == []


def test_spreadsheet_rows_are_checked_the_same_way():
    rows = [["Employee", "Gross"], ["Ana", 2370.84], ["Ben", 3126.66], ["Grand Total", 5498.5]]
    assert rows_issues(rows) == [
        'The "Grand Total" row gives Gross as 5,498.50, but the rows above it add to 5,497.50.']
    assert rows_issues([*rows[:3], ["Grand Total", "=SUM(B2:B3)"]]) == []
    assert rows_issues([*rows[:3], ["Grand Total", 5497.5]]) == [] and rows_issues([]) == []


def test_a_metrics_table_whose_total_row_is_its_own_figure_is_left_alone():
    metrics = ("| Metric | Value |\n|---|---|\n| Orders | 120 |\n| Average order | 83.33 |\n"
               "| Total revenue | 10,000 |\n")
    assert answer_issues(metrics) == []


def test_a_sheet_with_formula_rows_is_left_to_excel():
    rows = [["Item", "Amount"], ["Design", "=B5*2"], ["Copy", 200], ["Total", 1400]]
    assert rows_issues(rows) == []


def test_the_spreadsheet_tool_says_when_a_written_total_is_off(tmp_path):
    from maverick.tools import spreadsheet as ss

    rows = [["Employee", "Gross"], ["Ana", 2370.84], ["Ben", 3126.66], ["Grand Total", 5498.5]]
    out = ss._run({"op": "write", "path": str(tmp_path / "pay.csv"), "rows": rows})
    assert out.startswith("wrote 4") and "The totals do not add up" in out and "5,497.50" in out
    rows[-1][1] = 5497.5
    assert "totals" not in ss._run({"op": "write", "path": str(tmp_path / "pay.csv"), "rows": rows})


@pytest.mark.asyncio
async def test_a_final_answer_whose_total_is_off_is_revised_before_any_model_judges_it(
        tmp_path, fake_llm, make_llm_response):
    wrong = _PAYROLL + "\nGrand total gross pay: $7,402.94\n"
    fake_llm.scripted = [make_llm_response(text=t) for t in (
        "FINAL: " + wrong,
        "FINAL: " + _PAYROLL + "\nGrand total gross pay: $7,401.94\n",
        '{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        "FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("run payroll", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    revision_brief = str(fake_llm.calls[1].get("messages", ""))
    assert "The totals do not add up" in revision_brief and "7,401.94" in revision_brief
    # Live: a revision kept only the changes and pointed to emails "above".
    assert "The person sees only the new FINAL" in revision_brief
    goal = world.get_goal(gid)
    assert goal.status == "done" and "$7,401.94" in goal.result and "$7,402.94" not in goal.result


def test_a_figure_typed_with_its_cents_garbled_is_named():
    from maverick.figure_totals import drift_issues

    evidence = "tool=compute -> 1647.38\ntool=compute -> 20203.24\nrate 33.62, previous total 20,254.96"
    answer = ("Correct week 2 gross pay: $1,647.56. New total: $20,203.42. Rate $33.62. "
              "Overtime 6 hours. The old total was $20,254.96; tax 8.25%.")
    assert drift_issues(answer, evidence) == [
        "The answer gives 1,647.56, but the tools returned 1,647.38.",
        "The answer gives 20,203.42, but the tools returned 20,203.24."]
    assert drift_issues("Week 2 pay is $1,647.38 and the total $20,203.24.", evidence) == []
    # A different whole amount, a figure the tools never came near, or no
    # tool figures at all: nothing to compare.
    assert drift_issues("A fee of $1,650.00 and a deposit of $512.75.", evidence) == []
    assert drift_issues("Total $1,647.56", "") == []


@pytest.mark.asyncio
async def test_a_final_figure_that_garbles_a_computed_one_is_revised(tmp_path, fake_llm, make_llm_response):
    from maverick.llm import ToolCall

    fake_llm.scripted = [
        make_llm_response(text="Recomputing week 2.", tool_calls=[
            ToolCall(id="c1", name="compute", input={"op": "evaluate", "expr": "33.62*40 + 33.62*1.5*6"})]),
        make_llm_response(text="FINAL: Ben's corrected week 2 pay is $1,647.56."),
        make_llm_response(text="FINAL: Ben's corrected week 2 pay is $1,647.38."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("recheck Ben's pay", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    brief = str(fake_llm.calls[2].get("messages", ""))
    assert "The answer gives 1,647.56, but the tools returned 1,647.38." in brief
    goal = world.get_goal(gid)
    assert goal.status == "done" and "$1,647.38" in goal.result and "1,647.56" not in goal.result
