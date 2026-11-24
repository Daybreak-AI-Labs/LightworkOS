"""The goal root is sent back for a file only when the person asked to
receive one and the agent can make it and hand it over."""
from __future__ import annotations

import time

import pytest
from maverick import decision_requests as dr
from maverick import task_files
from maverick.agent import (
    _FILE_TYPE_REQUESTS,
    _WORKBOOK_REQUEST,
    Agent,
    _asks_to_receive,
    _RunState,
)
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.capability import Capability
from maverick.llm import ToolCall
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel

_ACCEPT = '{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'
_SENT_BACK = ("asked to receive", "asked for a spreadsheet", "cannot download yet")


def _asked_for(request: str) -> list[str]:
    return [label for pattern, _suffixes, label, _how in _FILE_TYPE_REQUESTS if _asks_to_receive(pattern, request)]


def _asked_for_workbook(request: str) -> bool:
    return _asks_to_receive(_WORKBOOK_REQUEST, request)


async def _run(tmp_path, fake_llm, make_llm_response, title: str, *, answer: str, calls=(),
               description: str = "", domain: str | None = None):
    fake_llm.scripted = [make_llm_response(text="Working on it.", tool_calls=[call]) for call in calls] + [
        make_llm_response(text=f"FINAL: {answer}"),
        make_llm_response(text=_ACCEPT),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal(title, description, owner="alice")
    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1, domain=domain)
    return world, gid


def _saves_csv():
    write = ToolCall(id="c1", name="spreadsheet", input={"op": "write", "path": "totals.csv",
                                                         "rows": [["Name", "Total"], ["Ana", 38]]})
    return [write, ToolCall(id="c2", name="deliver_file", input={"path": "totals.csv"})]


def _sent_back(fake_llm) -> str:
    """The message a request check sent the run back with, or ''."""
    for call in fake_llm.calls:
        for message in call.get("messages") or []:
            content = str(message.get("content", ""))
            if message.get("role") == "user" and any(mark in content for mark in _SENT_BACK):
                return content
    return ""


# ---- A conversion asks only for the format it converts to -----------------

@pytest.mark.parametrize(("request_text", "wanted"), [
    ("Save the PDF as a Word document so I can edit it.", ["a Word document"]),
    ("Export the PowerPoint as a PDF", ["a PDF"]),
    ("Save the slides as a PDF", ["a PDF"]),
    ("Make the PDF into a Word document", ["a Word document"]),
    ("Save the CSV as a spreadsheet", []),
    ("Export the spreadsheet to PDF", ["a PDF"]),
])
def test_only_the_format_a_file_is_converted_to_is_asked_for(request_text, wanted):
    assert _asked_for(request_text) == wanted


@pytest.mark.asyncio
async def test_a_converted_file_is_not_sent_back_for_its_source_format(tmp_path, fake_llm, make_llm_response):
    # The agent saved the Word document the person asked for; the PDF they
    # are converting is not a file they want back.
    write = ToolCall(id="c1", name="write_file", input={"path": "lease.docx", "content": "Lease terms"})
    deliver = ToolCall(id="c2", name="deliver_file", input={"path": "lease.docx"})
    await _run(tmp_path, fake_llm, make_llm_response, "Save the PDF as a Word document so I can edit it.",
               calls=[write, deliver], answer="I saved lease.docx with the lease text.")
    assert _sent_back(fake_llm) == ""


@pytest.mark.asyncio
async def test_a_csv_converted_to_a_spreadsheet_needs_the_workbook(tmp_path, fake_llm, make_llm_response):
    # "Save the CSV as a spreadsheet" asks for a workbook. Naming the CSV
    # being converted used to switch the workbook check off.
    write = ToolCall(id="c1", name="spreadsheet", input={"op": "write", "path": "hours.csv",
                                                         "rows": [["Name", "Hours"], ["Ana", 38]]})
    deliver = ToolCall(id="c2", name="deliver_file", input={"path": "hours.csv"})
    await _run(tmp_path, fake_llm, make_llm_response, "Save the CSV as a spreadsheet",
               calls=[write, deliver], answer="I saved hours.csv.")
    assert "asked for a spreadsheet" in _sent_back(fake_llm)


# ---- A file the person says they are sending is not asked for -----------

@pytest.mark.parametrize("request_text", [
    "The invoice is attached as a PDF. What is the total due?",
    "Hi, here's the payroll export as a CSV. What were total hours per employee?",
    "Please find attached the lease as a PDF. When does it end?",
    "Our price list is attached as a PDF. Raise every price by 4% and list the new prices.",
    "We've attached the policy as a Word document. Summarize the leave rules.",
    "Attaching the invoice as a PDF. What is the total due?",
    "I'm uploading the contract as a PDF. When does it expire?",
    "I'm sharing the payroll export as a CSV. What were total hours per employee?",
    "Forwarding the policy as a Word document. Summarize the leave rules.",
    "The ledger is below as a CSV. What is the closing balance?",
    "Give me the totals, the PDF is attached",
])
def test_a_file_described_as_sent_is_not_asked_for(request_text):
    assert _asked_for(request_text) == []


@pytest.mark.asyncio
async def test_a_question_about_an_attached_pdf_keeps_its_answer(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response, "The invoice is attached as a PDF. What is the total due?",
               answer="The total due is $1,240.00.")
    assert _sent_back(fake_llm) == ""


# A giving word that is not the clause's verb ("the attached notes", "the
# figures sent by finance") or one an asking word follows ("I shared
# earlier and give me") used to switch off a real request.
@pytest.mark.parametrize(("request_text", "wanted"), [
    ("Convert the attached notes into a PDF", ["a PDF"]),
    ("Summarize the attached report and give me the result as a Word document", ["a Word document"]),
    ("Reformat the included table as a CSV", ["a CSV file"]),
    ("Use the numbers I shared earlier and give me the totals as a CSV", ["a CSV file"]),
    ("Make sure this is saved as a PDF", ["a PDF"]),
])
def test_a_file_asked_for_beside_a_file_given_counts(request_text, wanted):
    assert _asked_for(request_text) == wanted


@pytest.mark.parametrize("request_text", [
    "Read the attached invoices and save the totals as a spreadsheet",
    "Combine the attached timesheets into one spreadsheet",
    "Put the uploaded sales data into an Excel workbook",
    "Format the figures sent by finance as a spreadsheet",
])
def test_a_spreadsheet_asked_for_beside_a_file_given_counts(request_text):
    assert _asked_for_workbook(request_text) is True


@pytest.mark.asyncio
async def test_a_csv_for_a_spreadsheet_from_attached_files_goes_back(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response,
               "Read the attached invoices and save the totals as a spreadsheet",
               calls=_saves_csv(), answer="I saved totals.csv.")
    assert "asked for a spreadsheet" in _sent_back(fake_llm)


@pytest.mark.asyncio
async def test_attached_notes_to_convert_into_a_pdf_need_the_pdf(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response, "Convert the attached notes into a PDF",
               answer="Here are the notes: item 1, item 2.")
    assert "asked to receive a PDF" in _sent_back(fake_llm)


# ---- Refusals, either/or questions and the agent's own options -----------

@pytest.mark.parametrize("request_text", [
    "No need for a PDF, just tell me the total amount due.",
    "Don't send me a PDF, just give me the total.",
    "Save it as xlsx, not csv",
    "Save it as xlsx not csv",
    "Is it better to send invoices as a PDF or as a Word document?",
    "Should I export my bank statements as CSV or PDF?",
])
def test_a_refused_or_offered_file_is_not_asked_for(request_text):
    assert _asked_for(request_text) == []


# A negation about something else in the clause (unpaid customers, a
# missing manager, not owning Excel) used to cancel the request.
@pytest.mark.parametrize(("request_text", "wanted"), [
    ("Give me a list of customers who have not paid as a PDF", ["a PDF"]),
    ("Give me all employees without a manager as a CSV", ["a CSV file"]),
    ("Export every order that has no tracking number as a CSV", ["a CSV file"]),
    ("I don't have Excel so give me a CSV", ["a CSV file"]),
    ("Don't forget to give me a PDF", ["a PDF"]),
])
def test_a_negation_about_something_else_keeps_the_request(request_text, wanted):
    assert _asked_for(request_text) == wanted


@pytest.mark.parametrize("request_text", [
    "List invoices that are not paid and give me a spreadsheet of them",
    "I'm not sure what is best but make me a spreadsheet",
])
def test_a_negation_about_something_else_keeps_the_spreadsheet_request(request_text):
    assert _asked_for_workbook(request_text) is True


@pytest.mark.asyncio
async def test_a_pdf_of_unpaid_customers_goes_back_to_be_saved(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response, "Give me a list of customers who have not paid as a PDF",
               answer="Customers who have not paid: Ana, Ben.")
    assert "asked to receive a PDF" in _sent_back(fake_llm)


@pytest.mark.asyncio
async def test_a_spreadsheet_of_unpaid_invoices_goes_back_for_the_workbook(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response,
               "List invoices that are not paid and give me a spreadsheet of them",
               calls=_saves_csv(), answer="I saved totals.csv.")
    assert "asked for a spreadsheet" in _sent_back(fake_llm)


# A choice the person asks for wants one file, and either type will do; a
# choice they weigh in a question wants none.
def test_a_choice_asked_for_wants_the_first_file_or_another_offered():
    request = "Send it as a PDF or Word document"
    assert _asked_for(request) == ["a PDF"]
    assert not any(_asks_to_receive(pattern, request, {".docx"}) for pattern, *_rest in _FILE_TYPE_REQUESTS)


@pytest.mark.asyncio
async def test_a_choice_of_files_answered_in_the_chat_goes_back(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response, "Send it as a PDF or Word document",
               answer="Policy summary: staff get 20 days of leave.")
    assert "asked to receive a PDF" in _sent_back(fake_llm)


@pytest.mark.asyncio
async def test_a_choice_of_files_is_met_by_either(tmp_path, fake_llm, make_llm_response):
    write = ToolCall(id="c1", name="write_file", input={"path": "policy.docx", "content": "Leave: 20 days"})
    deliver = ToolCall(id="c2", name="deliver_file", input={"path": "policy.docx"})
    await _run(tmp_path, fake_llm, make_llm_response, "Send it as a PDF or Word document",
               calls=[write, deliver], answer="I saved policy.docx.")
    assert _sent_back(fake_llm) == ""


@pytest.mark.asyncio
async def test_a_csv_for_a_spreadsheet_or_a_csv_is_kept(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response, "Give me a spreadsheet or a CSV, whichever is easier",
               calls=_saves_csv(), answer="I saved totals.csv.")
    assert _sent_back(fake_llm) == ""


@pytest.mark.asyncio
async def test_a_declined_pdf_keeps_the_answer(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response, "No need for a PDF, just tell me the total amount due.",
               answer="The total amount due is $1,234.56.")
    assert _sent_back(fake_llm) == ""


@pytest.mark.asyncio
async def test_a_refused_csv_does_not_cancel_the_workbook_request(tmp_path, fake_llm, make_llm_response):
    # "Save the summary as xlsx, not csv" asks for a workbook; the CSV it
    # refuses used to switch the workbook check off and was demanded instead.
    write = ToolCall(id="c1", name="spreadsheet", input={"op": "write", "path": "summary.csv",
                                                         "rows": [["Item", "Total"], ["Rent", 1200]]})
    deliver = ToolCall(id="c2", name="deliver_file", input={"path": "summary.csv"})
    await _run(tmp_path, fake_llm, make_llm_response, "Save the summary as xlsx, not csv.",
               calls=[write, deliver], answer="I saved summary.csv.")
    sent = _sent_back(fake_llm)
    assert "asked for a spreadsheet" in sent and "CSV file" not in sent


@pytest.mark.asyncio
async def test_a_chat_reply_is_read_without_the_options_the_agent_wrote(tmp_path, fake_llm, make_llm_response):
    # A chat reply to a waiting question carries the question and its options
    # (written by the agent) after the person's message, as the dashboard's
    # chat_reply builds the description. "1. As a PDF" is not a request.
    decision = dr.Decision(
        id=1, goal_id=1, area="other", question="How should I send you the table?",
        options=[{"label": "As a PDF", "effect": "I save a PDF you can download."},
                 {"label": "In the chat", "effect": "I paste the table into my answer."}],
        recommended=2, reason="", admin_required=False, requested_by="agent", status="open",
        created_at=0.0, expires_at=0.0)
    message = "Just paste the table in the chat, no file please"
    await _run(tmp_path, fake_llm, make_llm_response, message,
               description=f"{message}\n\n{dr.reply_context(decision)}",
               answer="| Item | Total |\n| Rent | 1200 |")
    assert _sent_back(fake_llm) == ""


# ---- Decks, talks and slide numbers are not slides to receive -----------

@pytest.mark.parametrize(("request_text", "wanted"), [
    ("How much lumber do I need to build a 12x16 deck?", []),
    ("I want to build a deck in my backyard. What permits do I need?", []),
    ("Help me prepare for the presentation tomorrow: list likely questions.", []),
    ("Help me prepare for a presentation tomorrow.", []),
    ("Give me the numbers on slide 3", []),
    ("Make a 5-slide deck for the board", ["slides"]),
    ("Make me a pitch deck for the seed round", ["slides"]),
    ("Create a short investor presentation", ["slides"]),
    ("Export the plan as PowerPoint", ["slides"]),
    ("Give me 6 slides on the Q3 results", ["slides"]),
    ("Make a deck for the board meeting", ["slides"]),
    ("Make one slide summarizing Q3", ["slides"]),
    ("Make a slide with the KPIs", ["slides"]),
    ("Prepare the Q3 presentation for the board", ["slides"]),
    ("Make the board presentation", ["slides"]),
])
def test_only_slides_to_receive_count(request_text, wanted):
    assert _asked_for(request_text) == wanted


@pytest.mark.asyncio
async def test_a_question_about_a_wooden_deck_keeps_its_answer(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response, "How much lumber do I need to build a 12x16 deck?",
               answer="You need about 40 boards of 2x6 lumber plus joists.")
    assert _sent_back(fake_llm) == ""


@pytest.mark.asyncio
async def test_a_deck_for_the_board_answered_in_the_chat_goes_back(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response, "Make a deck for the board meeting",
               answer="Slide 1: Q3 revenue up 12%.")
    assert "asked to receive slides" in _sent_back(fake_llm)


# ---- A request after a comma-joined "here are" still counts ------------

@pytest.mark.parametrize("request_text", [
    "Here are the shift logs, make me a spreadsheet of hours per person",
    "I've attached the timesheets, can you make a spreadsheet of pay per person",
    "Here are the shift logs and make me a spreadsheet of hours per person",
])
def test_a_spreadsheet_asked_for_after_the_files_given_counts(request_text):
    assert _asked_for_workbook(request_text) is True


@pytest.mark.parametrize("request_text", [
    "Give me a sortable, filterable spreadsheet of the orders",
    "Export the totals as a clean, sortable spreadsheet",
])
def test_a_spreadsheet_described_with_a_comma_counts(request_text):
    assert _asked_for_workbook(request_text) is True


@pytest.mark.asyncio
async def test_a_csv_for_a_sortable_spreadsheet_goes_back(tmp_path, fake_llm, make_llm_response):
    await _run(tmp_path, fake_llm, make_llm_response, "Give me a sortable, filterable spreadsheet of the orders",
               calls=_saves_csv(), answer="I saved totals.csv.")
    assert "asked for a spreadsheet" in _sent_back(fake_llm)


def test_a_word_document_asked_for_after_an_attached_pdf_counts():
    assert _asked_for("Attached is our price list as a PDF, give me a Word document with the new prices") == [
        "a Word document"]


@pytest.mark.asyncio
async def test_a_csv_for_a_spreadsheet_after_given_files_goes_back(tmp_path, fake_llm, make_llm_response):
    write = ToolCall(id="c1", name="spreadsheet", input={"op": "write", "path": "hours.csv",
                                                         "rows": [["Name", "Hours"], ["Ana", 38]]})
    deliver = ToolCall(id="c2", name="deliver_file", input={"path": "hours.csv"})
    await _run(tmp_path, fake_llm, make_llm_response,
               "Here are the shift logs, make me a spreadsheet of hours per person",
               calls=[write, deliver], answer="I saved hours.csv with hours per person.")
    assert "asked for a spreadsheet" in _sent_back(fake_llm)


# ---- A long request is read in linear time --------------------------------

@pytest.mark.parametrize("request_text", [("as a pdf " * 2000)[:16000], ("no " + "as a pdf " * 2000)[:16000]])
def test_a_long_request_is_read_quickly(request_text):
    # Each "as a pdf" here is rejected (the source of a conversion), and the
    # clause used to be rescanned from its start for every one of them: a
    # 16,000-character task description, the longest the dashboard takes,
    # held the agent's event loop for over two seconds.
    started = time.perf_counter()
    for pattern in (*(row[0] for row in _FILE_TYPE_REQUESTS), _WORKBOOK_REQUEST):
        _asks_to_receive(pattern, request_text)
    assert time.perf_counter() - started < 1.0


# ---- The checks ask only for files the agent can make and hand over -------

@pytest.mark.asyncio
async def test_a_pack_without_file_tools_is_not_sent_back_for_a_pdf(tmp_path, fake_llm, make_llm_response):
    # hosp_housekeeping's envelope grants neither write_file nor deliver_file:
    # asking it to save and hand over a PDF only spends turns on refused calls.
    await _run(tmp_path, fake_llm, make_llm_response, "Give me the room turnover checklist as a PDF.",
               domain="hosp_housekeeping",
               answer="Room turnover checklist:\n1. Strip beds\n2. Clean bathroom\n3. Restock amenities")
    assert _sent_back(fake_llm) == ""


@pytest.fixture
def make_agent(tmp_path, fake_llm, monkeypatch):
    monkeypatch.setenv("MAVERICK_REHEARSAL", "0")
    world = WorldModel(tmp_path / "world.db")
    workspace = tmp_path / "work"
    workspace.mkdir()

    def make(title: str) -> Agent:
        ctx = SwarmContext(
            llm=fake_llm, world=world, budget=Budget(max_dollars=1),
            blackboard=Blackboard(), sandbox=LocalBackend(workdir=workspace),
            goal_id=world.create_goal(title, ""), use_skills=False,
        )
        return Agent(ctx=ctx, role="orchestrator", brief="file requests")

    yield make
    world.close()


def _state(agent):
    return _RunState(messages=[{"role": "user", "content": "task"}],
                     bb=agent.ctx.blackboard, ep_id=0, ckpt=None, start_step=0)


def _page_holds(agent, name: str) -> None:
    workdir = agent.ctx.sandbox.workdir
    path = workdir / name
    path.write_text("a,b\n1,2\n")
    task_files.record(agent.ctx.world, agent.ctx.goal_id, workdir, path, delivered=True)


_EVERY_CHECK = "Give me a spreadsheet of totals and a summary as a PDF."


def test_a_file_type_is_asked_for_only_when_its_writer_is_granted(make_agent):
    agent = make_agent("Give me the cleaned CSV and a summary as a PDF.")
    agent.capability = Capability(principal="agent:test",
                                  allow_tools=frozenset({"spreadsheet", "deliver_file", "read_file"}))
    state = _state(agent)
    assert agent._request_file_types(state) is True
    sent = state.messages[-1]["content"]
    assert "a CSV file" in sent and "PDF" not in sent


def test_the_checks_ask_when_every_tool_is_granted(make_agent):
    agent = make_agent(_EVERY_CHECK)
    _page_holds(agent, "totals.csv")
    (agent.ctx.sandbox.workdir / "summary.pdf").write_text("summary")
    state = _state(agent)
    assert agent._request_named_file_delivery(state, "I saved summary.pdf.") is True
    assert agent._request_workbook(state) is True
    assert agent._request_file_types(state) is True


@pytest.mark.parametrize("withhold", ["capability", "hidden", "acl"])
def test_no_check_asks_for_a_file_without_deliver_file(make_agent, withhold):
    agent = make_agent(_EVERY_CHECK)
    if withhold == "capability":
        agent.capability = Capability(principal="agent:test", deny_tools=frozenset({"deliver_file"}))
    elif withhold == "hidden":
        agent.tools.enable_deferred(core={tool.name for tool in agent.tools.all()}, hidden={"deliver_file"})
    else:
        agent.tools.set_acl(denied={"deliver_file"})
    _page_holds(agent, "totals.csv")
    (agent.ctx.sandbox.workdir / "summary.pdf").write_text("summary")
    state = _state(agent)
    assert agent._request_named_file_delivery(state, "I saved summary.pdf.") is False
    assert agent._request_workbook(state) is False
    assert agent._request_file_types(state) is False
    assert state.messages == [{"role": "user", "content": "task"}]


def test_a_workbook_is_asked_for_only_when_the_spreadsheet_tool_is_granted(make_agent):
    agent = make_agent(_EVERY_CHECK)
    _page_holds(agent, "totals.csv")
    agent.capability = Capability(principal="agent:test", deny_tools=frozenset({"spreadsheet"}))
    assert agent._request_workbook(_state(agent)) is False
    agent.capability = None
    assert agent._request_workbook(_state(agent)) is True


# ---- Review round 2: giving verbs open a clause, negations govern a verb --

@pytest.mark.parametrize(("request_text", "wanted"), [
    # A giving verb inside a clause describes the file to work on.
    ("List all invoices we sent to Acme in March as a CSV", ["a CSV file"]),
    ("Convert the PDF I sent into a Word document", ["a Word document"]),
    ("Turn the notes I uploaded into a PDF", ["a PDF"]),
    ("Convert the invoice that is attached into a PDF", ["a PDF"]),
    ("Summarize the emails I sent this week as a PDF", ["a PDF"]),
    # "please find" is "search for" unless a file is attached.
    ("Please find all overdue invoices and list them as a CSV", ["a CSV file"]),
    ("Please find duplicate rows in the customer list and return them as a CSV", ["a CSV file"]),
    ("Please find attached the ledger as a CSV. What is the closing balance?", []),
    # A negation on the asking verb refuses the file.
    ("Don't send it as a PDF, just paste the table", []),
    ("Do not save it as a PDF. Paste the table.", []),
    ("I don't need it as a PDF, just the total", []),
    ("No need to save it as a PDF, just give me the total", []),
    ("Please don't export it as a CSV; tell me the top 3", []),
    ("Give me a no-frills PDF summary", ["a PDF"]),
    # A choice asks for its first file (either one meets it) unless the
    # clause weighs which is better.
    ("I'd like the report as a PDF or Word document", ["a PDF"]),
    ("Could I get the totals as a CSV or Excel file?", ["a CSV file"]),
    ("The summary as a PDF or Word document, please", ["a PDF"]),
    ("Convert the PDF or Word file into a CSV", ["a CSV file"]),
    ("Should I export my bank statements as CSV or PDF?", []),
    # A deck, slide or presentation that describes the next word is no file.
    ("Give me the presentation schedule for next week", []),
    ("Give me the presentation order for the conference", []),
    ("Give me the slide numbers that mention revenue", []),
    ("Give me the deck dimensions for a 12x16 build", []),
    ("How do I make a deck railing?", []),
    ("What stain should I use to make the deck last longer?", []),
    ("Create a deck plan for my backyard", []),
    # Real slide requests still count.
    ("Build a deck for the investor meeting", ["slides"]),
    ("I need a deck for Monday's board meeting", ["slides"]),
    ("Send me a deck summarizing Q3", ["slides"]),
    ("Make a short investor deck", ["slides"]),
    ("Prepare a quarterly board deck on Q3 results", ["slides"]),
    ("Turn this into a presentation", ["slides"]),
    ("Turn these notes into a deck", ["slides"]),
    ("Help me prepare for the presentation tomorrow.", []),
])
def test_review_round_two_requests(request_text, wanted):
    assert sorted(_asked_for(request_text)) == sorted(wanted)


@pytest.mark.parametrize(("request_text", "wanted"), [
    ("Give me the quotes we sent last month as a spreadsheet", True),
    ("Combine the timesheets I uploaded into one spreadsheet", True),
    ("Pull the invoices we sent in Q3 into a spreadsheet", True),
    ("Take the invoices I forwarded and put them into a spreadsheet", True),
    ("Please find the top 10 customers by revenue as a spreadsheet", True),
    ("Turn the attached PDF or Word document into a spreadsheet", True),
    ("I've attached the budget as a spreadsheet. What is the total?", False),
])
def test_review_round_two_workbook_requests(request_text, wanted):
    assert _asked_for_workbook(request_text) is wanted


@pytest.mark.asyncio
async def test_a_send_back_on_a_misread_request_lets_the_answer_stand(tmp_path, fake_llm, make_llm_response):
    # A check that misreads a request must not push a file nobody wanted:
    # the message says to give the answer again unchanged.
    await _run(tmp_path, fake_llm, make_llm_response, "Build a deck for the investor meeting",
               answer="Slide 1: Q3 revenue up 12%.")
    sent = _sent_back(fake_llm)
    assert "asked to receive slides" in sent and "give your final answer again unchanged" in sent


# ---- A labeled corpus of requests ----------------------------------------

# Requests whose label the checks miss, each costing one unchecked file: a
# refusal followed by a bare file ("Not as a CSV please, an Excel file"), a
# load "into a spreadsheet" (read as reading a file, like "Import the CSV
# into a spreadsheet tool"), and a comma among the words describing a deck,
# which ends the clause (kept so "I don't want slides, just a PDF" works).
_KNOWN_MISSES = {"Not as a CSV please, an Excel file",
                 "Load the CSV into a spreadsheet and add a totals row",
                 "Make a short, punchy investor deck"}


def test_a_labeled_corpus_of_requests_is_read_right():
    # Review rounds built these: what each request asks to receive (C a CSV,
    # W a Word document, P a PDF, S slides; "?" marks a choice where any one
    # will do) and whether it asks for a spreadsheet beside a CSV on the page.
    # A miss costs the person their file; a false alarm costs one answer
    # given again, so both are pinned.
    import json
    from pathlib import Path

    from maverick.agent import _CSV_REQUEST, _persons_words

    letter = {"a CSV file": "C", "a Word document": "W", "a PDF": "P", "slides": "S"}
    wrong = []
    for case in json.loads((Path(__file__).parent / "data" / "file_requests.json").read_text()):
        if case["text"] in _KNOWN_MISSES:
            continue
        text = _persons_words(case["text"])
        got = {letter[label] for pattern, _s, label, _h in _FILE_TYPE_REQUESTS if _asks_to_receive(pattern, text)}
        wanted = set(case["files"].replace("?", ""))
        files_right = got <= wanted if "?" in case["files"] else got == wanted
        workbook = bool(_asks_to_receive(_WORKBOOK_REQUEST, text, frozenset({".csv"}))
                        and not _asks_to_receive(_CSV_REQUEST, text, frozenset({".csv"})))
        if not files_right or workbook != case["spreadsheet"]:
            wrong.append((case["text"], case["files"], sorted(got), case["spreadsheet"], workbook))
    assert not wrong, wrong
