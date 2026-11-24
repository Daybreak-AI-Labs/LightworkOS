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
    # A figure after a comma in a query's CSV output counts as returned.
    assert drift_issues("Week 2 pay is $1,647.38.", "week,pay\n2,1647.38") == []


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


def test_a_percentage_worked_out_wrong_is_named():
    # Live: "Expected tax at 8.25%: $24.00" for a $291.14 subtotal, and the
    # conclusion that the receipt's correct $24.02 was wrong.
    from maverick.figure_totals import percent_issues

    answer = ("Subtotal shown: $291.14\nExpected tax at 8.25%: $24.00\nTax shown on receipt: $24.02\n"
              "Conclusion: the tax does not appear to be correct.")
    assert percent_issues(answer) == ["291.14 × 8.25% is 24.02, not 24.00."]
    right = "Subtotal: $1,200.00\nSales tax (8.25%): $99.00\nTotal: $1,299.00\nOverhead 15% on $2,000.00: $300.00"
    assert percent_issues(right) == []
    # A percentage with no base nearby, several amounts on a line, or an
    # unrelated amount: nothing to compare.
    assert percent_issues("Margins rose 4% to $12.40 a unit.") == []
    # A growth table row is a ratio of its own (live: a month-over-month table).
    assert percent_issues("| 2026-03 | 26,634.51 | 16,461.57 | 61.80% |") == []
    assert percent_issues("March: 26,634.51 against 16,461.57, up 61.80%") == []
    assert percent_issues("Fee: $24.00\n\n\n\n\nRate 8.25% applies to $291.14 and $50.00 items.") == []


@pytest.mark.asyncio
async def test_a_final_with_a_percentage_worked_out_wrong_is_revised(tmp_path, fake_llm, make_llm_response):
    fake_llm.scripted = [make_llm_response(text=t) for t in (
        "FINAL: Subtotal shown: $291.14\nExpected tax at 8.25%: $24.00\nThe receipt's $24.02 is wrong.",
        "FINAL: Subtotal shown: $291.14\nExpected tax at 8.25%: $24.02\nThe receipt's tax is right.",
        '{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        "FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("check the receipt's tax", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    assert "291.14 × 8.25% is 24.02, not 24.00." in str(fake_llm.calls[1].get("messages", ""))
    assert "tax is right" in world.get_goal(gid).result


def test_a_figure_taken_from_a_past_tasks_result_is_named():
    from maverick.figure_totals import recalled_issues

    recalled = "#380 ✓ (0.38) Statement totals\n   result: Total deposits: $100,079.96 Total withdrawals: $99,417.70"
    tools = "45638.36\n44976.1\nOpening balance: $12,480.55"
    answer = "Total deposits: $100,079.96\nTotal withdrawals: $44,976.10\nOpening balance: $12,480.55"
    assert recalled_issues(answer, recalled, tools) == [
        "The answer gives 100,079.96, which comes from a past task's result, not from this task's data. "
        "Take each figure from this task's own files, reading a file's text where a query's table does not "
        "hold it."]
    # A figure this run's own tools also returned stands.
    assert recalled_issues("Opening balance: $12,480.55", recalled + " $12,480.55", tools) == []
    assert recalled_issues(answer, "", tools) == []
    # Live: a query returned "45638.36,44976.1,266.32,4284.61"; a figure
    # right after a comma in CSV output is still this run's own.
    query = "total_deposits,total_withdrawals,min,max\n45638.36,44976.1,266.32,4284.61"
    assert recalled_issues("Largest withdrawal: $4,284.61", recalled + " $4,284.61", query) == []
    # Live: the query gave 44976.1; the answer's $44,976.10 is the same figure.
    assert recalled_issues("Withdrawals: $44,976.10", recalled + " $44,976.10", query) == []
    # Live: compute printed a lease's second-year rent as 4326, and the
    # answer's correct $4,326.00 went back as copied from a past task's
    # result, which named the same rent.
    lease = "4326, 4455.78, 4589.45, 4727.13"
    assert recalled_issues("Year 2: $4,326.00; Year 3: $4,455.78", recalled + " $4,326.00", lease) == []


def test_a_date_taken_from_a_past_tasks_result_is_named():
    # Live: one lease answer put the expiry a year early (March 31, 2029; the
    # lease runs 60 months from April 1, 2025). The next run on the same lease
    # recalled it, started its compute call from 2029-03-31, and gave the
    # same wrong dates; the verifier accepted both at 1.00.
    import datetime

    from maverick.figure_totals import recalled_issues

    recalled = ("#451 ✓ (0.29) Lease summary\n   result: Last day to give notice to renew: October 2, 2028 "
                "The lease expires on March 31, 2029.")
    tools = "begins on April 1, 2025 and continues for sixty (60) full calendar months\n2028-10-02"
    answer = "Last day to give notice: October 2, 2028. The lease expires on March 31, 2029."
    assert recalled_issues(answer, recalled, tools) == [
        "The answer gives March 31, 2029, which comes from a past task's result, not from this task's files. "
        "Work each date out with compute from the dates this task's files state."]
    # A date this run's tools returned, in any form, stands: compute printed
    # 2028-10-02, and a file wrote 3/31/2029 or 31/03/2029.
    assert recalled_issues("Notice by Oct. 2, 2028.", recalled, tools) == []
    assert recalled_issues(answer, recalled, tools + "\nExpires 3/31/2029") == []
    assert recalled_issues(answer, recalled, tools + "\nExpires 31/03/2029") == []
    assert recalled_issues("It expires 2029-03-31.", recalled, tools) == [
        "The answer gives March 31, 2029, which comes from a past task's result, not from this task's files. "
        "Work each date out with compute from the dates this task's files state."]
    # Live: a correct answer named the past task's date only to rule it out.
    assert recalled_issues("Give notice by October 2, 2029, not October 3, 2029.",
                           "result: Last day: October 3, 2029", "2029-10-02") == []
    # The person's own dates, and today's, are not copied by mistake.
    assert recalled_issues(answer, recalled, tools, "The lease ends March 31, 2029.") == []
    today = datetime.date.today()
    dated = f"result: Aged as of {today:%B} {today.day}, {today.year}."
    assert recalled_issues(f"Aged as of {today.isoformat()}.", dated, "") == []
    assert recalled_issues(answer, "", tools) == []
    # A money figure and a date copied together are both named.
    both = recalled_issues("Total $100,079.96 due March 31, 2029.",
                           recalled + " Total deposits: $100,079.96", tools)
    assert both[0].startswith("The answer gives 100,079.96, which comes from a past task's result")
    assert both[1].startswith("The answer gives March 31, 2029, which comes from a past task's result")
    assert both[1].endswith("Take each figure from this task's own files, reading a file's text where a "
                            "query's table does not hold it. Work each date out with compute from the dates "
                            "this task's files state.")


def test_a_whole_amount_a_tool_returned_is_not_a_garbled_figure():
    from maverick.figure_totals import drift_issues

    # compute prints $4,326.00 as 4326; beside 4326.5 elsewhere, the answer's
    # $4,326.00 is the tool's own figure, not 4,326.50 garbled.
    assert drift_issues("Year 2 rent: $4,326.00", "4326\nDeposit: 4326.50") == []
    assert drift_issues("Year 2 rent: $4,326.10", "4326\nDeposit: 4326.50") == [
        "The answer gives 4,326.10, but the tools returned 4,326.50."]
    # Live: compute gave 4589.4534 and 4727.137002 for a lease's rents; the
    # answer's $4,589.45 and $4,727.14 are those figures rounded to cents.
    assert drift_issues("Year 4: $4,589.45; Year 5: $4,727.14", "4589.4534\n4727.137002") == []
    assert drift_issues("Year 4: $4,589.54", "4589.4534") == [
        "The answer gives 4,589.54, but the tools returned 4,589.45."]
    # A row of cells read as one figure too long to round leaves the check standing.
    joined = "120,340,560,780,910,230,450,670,890,110,330,553,495.25"
    assert drift_issues(f"Units: {joined[:-6]}495.27", joined) == [
        "The answer gives 120,340,560,780,910,230,450,670,890,110,330,553,495.27, but the tools returned "
        "120,340,560,780,910,230,450,670,890,110,330,553,495.25."]


@pytest.mark.asyncio
async def test_a_final_that_copies_a_past_tasks_figures_is_revised(tmp_path, fake_llm, make_llm_response,
                                                                   monkeypatch):
    # Live: a statement's own compute calls returned 45,638.36 and 44,976.10,
    # but the answer copied 100,079.96 and 99,417.70 from an earlier task on a
    # different file that recall_past_goals showed as done.
    from types import SimpleNamespace

    from maverick.llm import ToolCall
    from maverick.tools import recall

    past = SimpleNamespace(id=380, status="done", title="Statement totals",
                           result="Total deposits: $100,079.96. Total withdrawals: $99,417.70.")
    monkeypatch.setattr(recall, "recall_past_goals", lambda *a, **k: [(0.38, past)])
    fake_llm.scripted = [
        make_llm_response(text="Checking.", tool_calls=[
            ToolCall(id="r1", name="recall_past_goals", input={"query": "statement totals"}),
            ToolCall(id="c1", name="compute", input={"op": "evaluate", "expr": "45000 + 638.36"})]),
        make_llm_response(text="FINAL: Total deposits: $100,079.96."),
        make_llm_response(text="FINAL: Total deposits: $45,638.36."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("total the statement's deposits", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    brief = str(fake_llm.calls[2].get("messages", ""))
    assert "100,079.96, which comes from a past task's result" in brief
    assert "$45,638.36" in world.get_goal(gid).result


@pytest.mark.asyncio
async def test_a_final_that_copies_a_past_tasks_date_is_revised(tmp_path, fake_llm, make_llm_response,
                                                                monkeypatch):
    # Live: a lease run recalled an earlier answer that put the expiry at
    # March 31, 2029, counted its notice date back from that, and the
    # verifier accepted it; the lease runs 60 months from April 1, 2025.
    from types import SimpleNamespace

    from maverick.llm import ToolCall
    from maverick.tools import recall

    past = SimpleNamespace(id=451, status="done", title="Lease summary",
                           result="Last day to give notice: October 2, 2028. The lease expires on March 31, 2029.")
    monkeypatch.setattr(recall, "recall_past_goals", lambda *a, **k: [(0.29, past)])
    fake_llm.scripted = [
        make_llm_response(text="Checking.", tool_calls=[
            ToolCall(id="r1", name="recall_past_goals", input={"query": "lease notice"}),
            ToolCall(id="c1", name="compute", input={"op": "evaluate", "expr": "date('2029-03-31', '-180 days')"})]),
        make_llm_response(text="FINAL: The lease expires March 31, 2029; give notice by October 2, 2028."),
        make_llm_response(text="Rechecking.", tool_calls=[
            ToolCall(id="c2", name="compute", input={
                "op": "evaluate", "expr": "date(date('2025-04-01', '+60 months', '-1 day'), '-180 days')"})]),
        make_llm_response(text="FINAL: The lease expires March 31, 2030; give notice by 2029-10-02."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("when must we give the lease renewal notice?", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    brief = str(fake_llm.calls[2].get("messages", ""))
    assert "March 31, 2029, which comes from a past task's result" in brief
    # compute returned 2028-10-02 from the copied expiry, so that date is its own.
    assert "October 2, 2028, which comes from" not in brief
    assert "2029-10-02" in world.get_goal(gid).result


@pytest.mark.asyncio
@pytest.mark.parametrize(("typed", "issue"), [
    (1647.56, "The answer gives 1,647.56, but the tools returned 1,647.38."),
    (100079.96, "The answer gives 100,079.96, which comes from a past task's result"),
])
async def test_a_figure_typed_into_a_workbook_still_counts_as_typed(tmp_path, fake_llm, make_llm_response,
                                                                    monkeypatch, typed, issue):
    # Review: a write's read-back repeats every figure the agent typed into
    # the file, so the typed figure read as one a tool returned. Ben's pay
    # typed as 1,647.56 (compute gave 1,647.38), or a past task's total typed
    # into a statement, then passed both checks.
    from types import SimpleNamespace

    from maverick.llm import ToolCall
    from maverick.tools import recall

    past = SimpleNamespace(id=380, status="done", title="Statement totals", result="Total: $100,079.96.")
    monkeypatch.setattr(recall, "recall_past_goals", lambda *a, **k: [(0.38, past)])
    fake_llm.scripted = [
        make_llm_response(text="Working it out.", tool_calls=[
            ToolCall(id="r1", name="recall_past_goals", input={"query": "pay"}),
            ToolCall(id="c1", name="compute", input={"op": "evaluate", "expr": "33.62*40 + 33.62*1.5*6"})]),
        make_llm_response(text="Saving it.", tool_calls=[
            ToolCall(id="s1", name="spreadsheet", input={"op": "write", "path": "pay.xlsx",
                                                         "rows": [["Employee", "Pay"], ["Ben", typed]]})]),
        make_llm_response(text=f"FINAL: Ben's pay is ${typed:,.2f}, also saved in the workbook."),
        make_llm_response(text="FINAL: Ben's pay is $1,647.38."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("recheck Ben's pay", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    assert f"Ben,{typed}" in str(fake_llm.calls[2].get("messages", ""))  # the read-back the agent saw
    assert issue in str(fake_llm.calls[3].get("messages", ""))
    assert "$1,647.38" in world.get_goal(gid).result


@pytest.mark.asyncio
async def test_a_workbook_formula_result_rounded_to_cents_is_not_sent_back(tmp_path, fake_llm, make_llm_response):
    # Review: the read-back gives a formula's result unrounded (833.3333333333),
    # and the answer's correct $833.33 went back as "gives 833.33, but the
    # tools returned 833.33" before any model judged it.
    from maverick.llm import ToolCall

    fake_llm.scripted = [
        make_llm_response(text="Saving it.", tool_calls=[
            ToolCall(id="s1", name="spreadsheet", input={"op": "write", "path": "loan.xlsx", "rows": [
                ["Balance", "Rate", "Monthly interest"], [100000, 0.1, "=A2*B2/12"]]})]),
        make_llm_response(text="FINAL: The first month's interest is $833.33, also saved in the workbook."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("work out the loan's first month of interest", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    assert "The answer gives 833.33" not in str(fake_llm.calls)
    judge = fake_llm.calls[2]
    assert "judging another agent's answer" in str(judge.get("system", "")) or "independent verifier" in str(
        judge.get("system", ""))
    assert "100000,0.1,833.3333333333" in str(judge.get("messages", ""))  # the model verifier sees the file
    assert "$833.33" in world.get_goal(gid).result


@pytest.mark.asyncio
async def test_a_total_a_workbook_formula_worked_out_counts_as_a_tools_result(tmp_path, fake_llm, make_llm_response,
                                                                             monkeypatch):
    # Review: leaving a write's whole read-back out of the figure checks left
    # out what the file's formulas worked out too, so a correct March total of
    # $100,079.96, a =SUM of this task's rows, went back as copied from a past
    # task that had the same total.
    from types import SimpleNamespace

    from maverick.llm import ToolCall
    from maverick.tools import recall

    past = SimpleNamespace(id=380, status="done", title="March statement", result="Total: $100,079.96.")
    monkeypatch.setattr(recall, "recall_past_goals", lambda *a, **k: [(0.38, past)])
    rows = [["Account", "Amount"], ["Ops", 50000.0], ["Payroll", 50079.96], ["Total", "=SUM(B2:B3)"]]
    fake_llm.scripted = [
        make_llm_response(text="Checking.", tool_calls=[
            ToolCall(id="r1", name="recall_past_goals", input={"query": "march total"})]),
        make_llm_response(text="Saving it.", tool_calls=[
            ToolCall(id="s1", name="spreadsheet", input={"op": "write", "path": "stmt.xlsx", "rows": rows})]),
        make_llm_response(text="FINAL: The March total is $100,079.96, also saved in the workbook."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("total the March statement", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    assert "Total,100079.96" in str(fake_llm.calls[2].get("messages", ""))  # the read-back the agent saw
    assert "comes from a past task's result" not in str(fake_llm.calls)
    assert "$100,079.96" in world.get_goal(gid).result


@pytest.mark.asyncio
async def test_a_wide_row_of_figures_in_a_workbook_does_not_fail_the_goal(tmp_path, fake_llm, make_llm_response):
    # Review: the read-back's CSV text runs a row of 3-digit cells together
    # into one 39-digit figure, and rounding it to cents raised
    # InvalidOperation, so the whole goal ended as "internal error".
    from maverick.llm import ToolCall

    row = ["Widget", 120, 340, 560, 780, 910, 230, 450, 670, 890, 110, 330, 553, "=AVERAGE(B2:M2)"]
    fake_llm.scripted = [
        make_llm_response(text="Saving it.", tool_calls=[
            ToolCall(id="s1", name="spreadsheet", input={"op": "write", "path": "units.xlsx", "rows": [
                ["Product", *[f"M{n}" for n in range(1, 13)], "Average"], row]})]),
        make_llm_response(text="FINAL: Widget averaged 495.25 units a month, also saved in the workbook."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("average Widget's monthly units", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    goal = world.get_goal(gid)
    assert goal.status == "done"
    assert "495.25 units" in goal.result


def test_figures_the_person_gave_are_theirs_to_quote():
    from maverick.figure_totals import drift_issues, recalled_issues

    # Review: a payroll check quoting the report's $1,647.56 beside the
    # recomputed $1,647.38 went back as "the tools returned 1,647.38".
    given = "The payroll report shows Ben's week 2 gross as $1,647.56. Is the report right?"
    answer = "The report's $1,647.56 is wrong: the correct gross is $1,647.38."
    assert drift_issues(answer, "1647.38", given) == []
    # An earlier answer in the chat is not the request: repeating its wrong
    # figure after a recheck is still caught.
    assert drift_issues("Confirmed: $1,647.56.", "1647.38", "Can you double-check that?") != []
    # A recurring budget's rent, given in the request, matches last month's.
    recalled = "<tool_output tool='recall_past_goals' id=1>\nOctober budget: rent $2,450.00, loan $389.27\n</tool_output 1>"
    budget = "Build my November budget. Rent $2,450.00, car loan $389.27."
    assert recalled_issues("Rent $2,450.00; loan $389.27", recalled, "", budget) == []
    # Review: "Do the same for April" is the follow-up most likely to recall
    # a past task with other figures; copying them is still caught.
    march = "<tool_output tool='recall_past_goals' id=2>\nTotal deposits: $100,079.96\n</tool_output 2>"
    assert recalled_issues("April deposits: $100,079.96.", march, "45638.36",
                           "Do the same deposit total for the April statement") != []


def test_a_total_under_a_list_that_does_not_add_up_is_named():
    # Live: a lease answer listed each year's rent times 12 ($267,580.32 in
    # all) under "Grand total: $267,580.44", and the model judge accepted it.
    lease = ("- **Monthly base rent by lease year:**\n  1. **Lease Year 1:** **$4,200.00**\n"
             "  2. **Lease Year 2:** **$4,326.00**\n\n"
             "- **Total base rent over the full 60-month term:** **$267,580.44**\n\nQuick check of the total:\n"
             "- Year 1: $4,200.00 × 12 = $50,400.00\n- Year 2: $4,326.00 × 12 = $51,912.00\n"
             "- Year 3: $4,455.78 × 12 = $53,469.36\n- Year 4: $4,589.45 × 12 = $55,073.40\n"
             "- Year 5: $4,727.13 × 12 = $56,725.56\n\n**Grand total: $267,580.44**")
    assert answer_issues(lease) == [
        "The total 267,580.44 does not equal the amounts listed above it, which add up to 267,580.32."]
    # A total that adds up, or one that is a figure of its own (a term's rent
    # under monthly rents), stands.
    assert answer_issues(lease.replace("Grand total: $267,580.44", "Grand total: $267,580.32")) == []
    monthly = "- Year 1: $4,200.00\n- Year 2: $4,326.00\n- Total over the term: $102,312.00"
    assert answer_issues(monthly) == []
