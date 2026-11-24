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
