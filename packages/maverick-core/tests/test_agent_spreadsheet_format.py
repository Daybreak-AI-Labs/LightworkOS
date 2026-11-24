"""A request for a spreadsheet gets an Excel workbook, not only a CSV."""
from __future__ import annotations

import pytest
from maverick.budget import Budget
from maverick.llm import ToolCall
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.task_files import files_for
from maverick.world_model import WorldModel

_ROWS = [["Rep", "Commission"], ["Alicia", 5068.25], ["Brian", 5329.81]]


async def _run(tmp_path, fake_llm, make_llm_response, title: str, *, revise: bool):
    csv = ToolCall(id="c1", name="write_file", input={"path": "commissions.csv",
                                                       "content": "Rep,Commission\nAlicia,5068.25\n"})
    xlsx = ToolCall(id="c2", name="spreadsheet", input={"op": "write", "path": "commissions.xlsx", "rows": _ROWS})
    script = [make_llm_response(text="Saving.", tool_calls=[csv]),
              make_llm_response(text="FINAL: I saved commissions.csv with each rep's commission.")]
    if revise:
        deliver = ToolCall(id="c3", name="deliver_file", input={"path": "commissions.xlsx"})
        script += [make_llm_response(text="Writing the workbook.", tool_calls=[xlsx]),
                   make_llm_response(text="Handing it over.", tool_calls=[deliver]),
                   make_llm_response(text="FINAL: I saved commissions.xlsx with each rep's commission.")]
    script += [make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
               make_llm_response(text="FINAL: (no skill)")]
    fake_llm.scripted = script
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal(title, "", owner="alice")
    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)
    return world, gid


@pytest.mark.asyncio
async def test_a_csv_for_a_spreadsheet_request_goes_back_for_a_workbook(tmp_path, fake_llm, make_llm_response):
    # Live, twice: "Give me a spreadsheet with each rep's commission" got a
    # CSV and "If you want, I can also reformat it into an .xlsx file".
    world, gid = await _run(tmp_path, fake_llm, make_llm_response,
                            "Work out Q3 commission. Give me a spreadsheet with each rep's total.", revise=True)
    brief = str(fake_llm.calls[2].get("messages", ""))
    assert "Excel" in brief and ".xlsx" in brief and "deliver_file" in brief
    assert {f.name for f in files_for(world, gid)} >= {"commissions.xlsx"}
    assert world.get_goal(gid).status == "done"


@pytest.mark.asyncio
async def test_a_csv_asked_for_by_name_is_kept(tmp_path, fake_llm, make_llm_response):
    world, gid = await _run(tmp_path, fake_llm, make_llm_response,
                            "Give me a CSV spreadsheet of each rep's commission.", revise=False)
    assert "Excel" not in str(fake_llm.calls[2].get("messages", ""))
    assert world.get_goal(gid).status == "done"


@pytest.mark.parametrize(("request_text", "wants"), [
    ("Give me a spreadsheet with each rep's commission", True),
    ("Give me the tax per order as a spreadsheet", True),
    ("Make an Excel workbook of the budget", True),
    ("Put it into an Excel file", True),
    ("From the attached spreadsheet, list overdue invoices", False),
    ("Read my spreadsheet and tell me the total", False),
    ("Make a chart from the attached spreadsheet", False),
])
def test_only_a_spreadsheet_to_receive_counts(request_text, wants):
    from maverick.agent import _WORKBOOK_REQUEST

    assert bool(_WORKBOOK_REQUEST.search(request_text)) is wants


@pytest.mark.asyncio
async def test_a_named_file_type_pasted_into_the_answer_goes_back_to_be_saved(tmp_path, fake_llm, make_llm_response):
    # Live: "Give me the cleaned CSV and tell me how many duplicate rows you
    # removed" got the CSV pasted into the answer and nothing to download.
    write = ToolCall(id="c1", name="spreadsheet", input={"op": "write", "path": "contacts_clean.csv",
                                                         "rows": [["email"], ["a@example.com"]]})
    deliver = ToolCall(id="c2", name="deliver_file", input={"path": "contacts_clean.csv"})
    fake_llm.scripted = [
        make_llm_response(text="FINAL: Here is the cleaned CSV:\n\nemail\na@example.com\n\n1 duplicate removed."),
        make_llm_response(text="Saving it.", tool_calls=[write]),
        make_llm_response(text="Handing it over.", tool_calls=[deliver]),
        make_llm_response(text="FINAL: I saved contacts_clean.csv. 1 duplicate removed."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("Clean up this contact list. Give me the cleaned CSV and tell me how many "
                            "duplicates you removed.", "", owner="alice")
    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)
    brief = str(fake_llm.calls[1].get("messages", ""))
    assert "a CSV file" in brief and "deliver_file" in brief
    assert {f.name for f in files_for(world, gid)} >= {"contacts_clean.csv"}
    assert world.get_goal(gid).status == "done"


@pytest.mark.parametrize(("request_text", "wanted"), [
    ("Give me the cleaned CSV", "a CSV file"),
    ("Export the list as a CSV", "a CSV file"),
    ("Turn these notes into a Word document", "a Word document"),
    ("Send me a PDF of the invoice", "a PDF"),
    ("Make a 5-slide deck for the board", "slides"),
    ("Summarize the attached PDF", None),
    ("From my CSV, give me the total", None),
    ("Read the attached Word document and list the dates", None),
    ("Give me a summary of the attached PDF", None),
])
def test_only_a_file_to_receive_counts(request_text, wanted):
    from maverick.agent import _FILE_TYPE_REQUESTS

    found = [label for pattern, _suffixes, label, _how in _FILE_TYPE_REQUESTS if pattern.search(request_text)]
    assert found == ([wanted] if wanted else []), found


@pytest.mark.parametrize(("request_text", "asks"), [
    ("Here's last week's timesheet as a Word file. Work out each employee's pay. Give me a table.", False),
    ("Attached is our price list as a PDF; give me a Word document with the new prices", True),
    ("I've attached the sales as a CSV. What were total sales?", False),
    ("Here is the data. Give me the result as a CSV.", True),
])
def test_a_file_the_person_sends_is_not_a_file_they_ask_for(request_text, asks):
    # Live: "Here's last week's timesheet as a Word file" sent a correct
    # payroll answer back to make a Word document nobody asked for.
    from maverick.agent import _FILE_TYPE_REQUESTS, _asks_to_receive

    assert any(_asks_to_receive(pattern, request_text) for pattern, *_rest in _FILE_TYPE_REQUESTS) is asks


@pytest.mark.asyncio
async def test_the_verifier_reads_the_files_on_the_task_page(tmp_path, fake_llm, make_llm_response):
    # Live: a child agent wrote an aging workbook whose summary left out the
    # largest customer; its write's read-back stayed in the child's context,
    # and the root's verifier, seeing only the answer, accepted it at 0.92.
    from maverick.tools import spreadsheet as ss

    ss._run({"op": "write", "path": str(tmp_path / "aging.xlsx"),
             "sheets": {"Summary": [["Customer", "Current", "Total"], ["Cedar Auto", 7887.79, "=B2"]]}})
    deliver = ToolCall(id="c1", name="deliver_file", input={"path": "aging.xlsx"})
    fake_llm.scripted = [
        make_llm_response(text="Handing it over.", tool_calls=[deliver]),
        make_llm_response(text="FINAL: I delivered aging.xlsx with the aging summary."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("Build the accounts receivable aging report.", "", owner="alice")
    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)
    judge = next(c for c in fake_llm.calls if "judging another agent's answer" in str(c.get("system", ""))
                 or "independent verifier" in str(c.get("system", "")))
    assert "delivered_file" in str(judge.get("system", ""))
    seen = str(judge.get("messages", ""))
    assert "tool='delivered_file'" in seen and "aging.xlsx" in seen
    assert "Cedar Auto,7887.79,7887.79" in seen, seen[-1500:]
    assert world.get_goal(gid).status == "done"
