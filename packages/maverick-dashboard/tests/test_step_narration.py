"""Steps read in plain words; recorded prompt and tool text never becomes the narration."""
from __future__ import annotations

import pytest
from maverick_dashboard.step_narration import GENERIC, agent_parts, narrate, who

ROOT = "orchestrator-0-72eb85"
HELPER = "researcher-1-a1b2c3"
BRIEF = ("role=orchestrator depth=0 brief=Top-level goal: Summarize last quarter's vendor spend. "
         "Prior conversation (most recent last): user: Summarize... Decompose into sub-tasks, "
         "spawn workers, synthesize, verify, and respond with FINAL:.")


@pytest.mark.parametrize(("kind", "agent", "content", "expected"), [
    ("plan", ROOT, BRIEF, "Started working on your request"),
    ("plan", HELPER, "role=researcher depth=1 brief=Find the AP ledger totals", "Researcher started on its part of the work"),
    ("plan", ROOT, "resumed from checkpoint at step 4", "Picked up where it left off"),
    ("observation", ROOT, "tool=read_file -> vendor,amount\nNorthwind,96400", "Read a file"),
    ("observation", ROOT, "tool=read_file -> ERROR: no such file", "Tried to read a file, but it did not work"),
    ("observation", ROOT, "tool=ask_user -> What quarter do you mean?", "Asked you a question"),
    ("observation", ROOT, "tool=spawn_subagent -> researcher finished", "Asked a helper to take on part of the work"),
    # enabled_domains() includes customer-built agents, so this is not always a specialist.
    ("observation", ROOT, "tool=spawn_specialist -> done", "Asked an agent or specialist for help"),
    ("observation", ROOT, "tool=web_search -> 10 results", "Searched the web"),
    ("observation", ROOT, "tool=shell -> ERROR: shell command was not approved; no command was run",
     "Did not run a command: a person rejected it"),
    ("observation", ROOT, "tool=ledger_read -> rows", "Used a tool: read financial records"),
    ("observation", ROOT, "I will read the ledger next.", "Worked out the next step"),
    ("observation", HELPER, "**Total:** $412,800", "Researcher worked out its next step"),
    ("finding", ROOT, "Here is a summary...\n| Vendor | Q3 |", "Wrote the answer"),
    ("finding", HELPER, "Totals by vendor...", "Researcher reported back"),
    ("verify", ROOT, "verifier accepted (conf=0.91)", "Checked the answer against your request: it passed"),
    ("verify", ROOT, "verifier rejected (conf=0.40): misses the email", "Checked the answer and asked for a revision"),
    ("verify", ROOT, "verifier rejected after retry; accepting second attempt per one-revision cap",
     "Checked the answer again: concerns remained, so the revised answer was kept"),
    ("verify", ROOT, "verification skipped (conversational answer: no tools, no code)",
     "Skipped the extra check: a short conversational answer that used no tools or files"),
    ("verify", ROOT, "verification skipped (risk-proportional: low-risk answer, no tools/code)",
     "Skipped the extra check: a low-risk answer that used no tools or code"),
    ("verify", ROOT, "verifier did not complete (budget)",
     "Started the extra check, but it could not finish within the spending limit"),
    ("verify", ROOT, "test-driven verifier: 3/3 passed", "Ran the required tests"),
    ("verify", ROOT, "patch rejected: corrupt hunk", "The proposed code change did not pass a check, so it is being revised"),
    ("verify", ROOT, "something new the kernel says", "Checked the work"),
    ("error", ROOT, "cancelled via dashboard", "Stopped because someone pressed Stop"),
    ("error", ROOT, "halted: HALT file present", "Stopped because work was halted"),
    ("error", ROOT, "verifier failed: timeout", "The extra check could not run"),
    ("error", ROOT, "budget exceeded: $1.00 cap", "Stopped at a spending or time limit"),
    ("error", ROOT, "tool=shell DENIED by capability (principal=agent:x)", "Was not allowed to run a command"),
    ("error", ROOT, "tool=read_file path=/etc/passwd DENIED by capability", "Was not allowed to read a file"),
    ("error", ROOT, "Traceback (most recent call last): KeyError: 'x'", "Ran into a problem"),
    ("note", ROOT, "review checkpoint stopped the run at dollars=2", "Paused at a review checkpoint"),
    ("note", HELPER, "stopping at $0.90/$1.00 to reserve the final 10% for synthesis",
     "Stopped early to keep enough budget for the final answer"),
    ("note", ROOT, "anything else", "Made a note"),
    ("model_fallback", ROOT, "primary=a:m1 backup=b:m2",
     "Switched to the backup AI model because the main one was unavailable"),
    ("artifact", ROOT, "report.md v2", "Produced a file"),
    ("status", "Lightwork", "pending", "Updated the task status"),
    ("progress", ROOT, "3/5", "Made progress"),
    ("denial", ROOT, "denied", "Was not allowed to do a step"),
    ("supervision", "supervisor", "paused by operator", "Paused by a person"),
    ("supervision", "supervisor", "cancelled by operator", "Stopped by a person"),
    ("skill", "orchestrator", "distilled local skill -> /x/y.md", "Saved what it learned as a reusable skill"),
    ("budget_summary", "orchestrator", "$0.04 in 3 calls", "Added up what the task cost"),
    ("sample_data", "system", "This task runs on bundled sample data.", "Ran on made-up sample files"),
])
def test_every_recorded_step_kind_has_plain_words(kind, agent, content, expected):
    step = narrate(kind, agent, content)
    assert step.text == expected
    assert step.hidden is False


@pytest.mark.parametrize("kind", ["brand_new_kind", "probe", "cert", "", None])
def test_an_unknown_kind_falls_back_to_a_plain_line_and_keeps_raw_text_out(kind):
    step = narrate(kind, ROOT, "role=orchestrator depth=0 brief=secret prompt")
    assert step.text == GENERIC
    assert "brief" not in step.text


@pytest.mark.parametrize("kind", ["trace_meta", "tool_signal", "prm"])
def test_internal_bookkeeping_is_hidden_from_the_main_view(kind):
    assert narrate(kind, ROOT, "search_replace_used=1").hidden is True


def test_internal_prompt_text_never_reaches_any_narration():
    kinds = ["plan", "observation", "finding", "verify", "error", "note", "artifact", "status", "x"]
    for kind in kinds:
        for agent in (ROOT, HELPER, "Lightwork", "supervisor", ""):
            text = narrate(kind, agent, BRIEF).text
            assert "role=" not in text and "brief=" not in text and "FINAL" not in text, (kind, agent, text)


def test_repeated_successful_reads_share_a_group_and_a_counted_form():
    first = narrate("observation", ROOT, "tool=read_file -> a")
    second = narrate("observation", ROOT, "tool=read_file -> b")
    assert first.group == second.group == "tool:read_file"
    assert first.plural.format(count=3) == "Read 3 files"
    assert narrate("observation", ROOT, "tool=read_file -> ERROR: gone").group != first.group


def test_agents_read_as_roles_and_specialists_not_internal_names():
    assert agent_parts("proc_po_chaser-1-a1b2c3") == ("proc_po_chaser", 1)
    assert agent_parts("Lightwork") == ("Lightwork", None)
    assert who(ROOT) == "Planner"
    assert who(HELPER) == "Researcher"
    assert who("supervisor") == "A person"
    assert who("Lightwork") == "Lightwork"
    specialist = who("proc_po_chaser-0-a1b2c3")
    assert specialist and "_" not in specialist and "0" not in specialist


def _framed(tool: str, body: str) -> str:
    return f"tool={tool} -> <tool_output tool='{tool}' id=c87793af89fc9533>\n{body}\n</tool_output c87793af89fc9533>"


def test_a_framed_failure_is_not_narrated_as_done():
    # Tool output arrives inside its <tool_output> frame, so "starts with ERROR"
    # never matched: a failed calculation read "Ran a calculation".
    from maverick_dashboard.step_narration import narrate

    step = narrate("observation", "orchestrator-0-1646c8",
                   _framed("compute", "ERROR: 'simplify' requires sympy."))
    assert step.text == "Tried to run a calculation, but it did not work"


def test_a_rejected_command_says_it_did_not_run():
    from maverick_dashboard.step_narration import narrate

    step = narrate("observation", "orchestrator-0-63fc0d",
                   _framed("shell", "ERROR: shell command was not approved; no command was run"))
    assert step.text == "Did not run a command: a person rejected it"


def test_a_framed_success_still_reads_as_done():
    from maverick_dashboard.step_narration import narrate

    assert narrate("observation", "orchestrator-0-4d2072",
                   _framed("shell", "Python 3.12.16\n42")).text == "Ran a command"


def test_a_command_nobody_decided_on_is_not_called_rejected():
    from maverick_dashboard.step_narration import narrate

    step = narrate("observation", "orchestrator-0-63fc0d", _framed(
        "shell", "ERROR: shell command was not approved: nobody approved it in time, "
                 "so no command was run"))
    assert step.text == "Did not run a command: nobody approved it in time"
    step = narrate("observation", "orchestrator-0-63fc0d", _framed(
        "shell", "ERROR: shell command was not approved: no person could be asked to approve it "
                 "for this task, so no command was run"))
    assert step.text == "Did not run a command: no person could be asked to approve it"
    step = narrate("observation", "orchestrator-0-63fc0d", _framed(
        "shell", "ERROR: shell command was not approved: a person rejected it, so no "
                 "command was run. Do not ask to run it again."))
    assert step.text == "Did not run a command: a person rejected it"
