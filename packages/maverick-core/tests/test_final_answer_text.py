"""Which part of a model reply is the answer the person sees."""
import pytest
from maverick.budget import Budget
from maverick.coding_mode import final_answer_text
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel

_BODY = """Here are the invoices that are actually overdue as of **November 23, 2026**:

| Invoice | Client | Amount |
|---|---|---:|
| INV-1002 | Bluefin Logistics | $4,380.50 |
| INV-1005 | Northgate Realty | $2,100.00 |

### Reminder emails

**Bluefin Logistics**
Subject: Friendly reminder about overdue invoices

Hi Bluefin Logistics team, invoice INV-1002 for $4,380.50 is now overdue. Could you let us know when
payment is on its way? Thank you, [Your Name]

**Northgate Realty**
Subject: Friendly reminder about an overdue invoice

Hi Northgate Realty team, invoice INV-1005 for $2,100.00 is now overdue. Could you let us know when
payment is on its way? Thank you, [Your Name]
"""
_SUMMARY = "FINAL: INV-1002 and INV-1005 are overdue. Draft reminder emails are included above."


def test_an_answer_written_before_a_closing_final_summary_is_kept():
    # Live: the model wrote the tables and the emails, then a one-line FINAL
    # summary saying the emails were "included above". Only the summary
    # reached the person and the verifier, so every run lost the emails.
    answer = final_answer_text(_BODY + "\n" + _SUMMARY)
    assert answer.startswith("Here are the invoices") and "Subject: Friendly reminder" in answer
    assert answer.endswith("Draft reminder emails are included above.")


def test_a_planning_line_before_final_is_still_dropped():
    assert final_answer_text("I'll check the table first.\nFINAL: " + _BODY) == _BODY.strip()
    assert final_answer_text("No marker yet") is None


def test_a_long_final_after_working_notes_stands_alone():
    notes = "Working notes:\n| a | b |\n|---|---|\n| 1 | 2 |\n"
    assert final_answer_text(notes + "FINAL: " + _BODY) == _BODY.strip()


def test_quoted_content_and_patches_never_join_the_answer():
    fenced = "```\n" + _BODY + "\n```\n"
    assert final_answer_text(fenced + "FINAL: done") == "done"
    patch = "FINAL:\n<<<<<<< SEARCH\nold\n=======\nnew\n>>>>>>> REPLACE\n"
    assert final_answer_text(_BODY + patch).startswith("<<<<<<< SEARCH")


@pytest.mark.asyncio
async def test_the_person_gets_the_whole_answer(tmp_path, fake_llm, make_llm_response):
    fake_llm.scripted = [make_llm_response(text=t) for t in (
        _BODY + "\n" + _SUMMARY,
        '{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        "FINAL: (no skill)")]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("overdue invoices and reminder emails", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    assert "Subject: Friendly reminder" in str(fake_llm.calls[1].get("messages", ""))  # the verifier saw it
    goal = world.get_goal(gid)
    assert goal.status == "done" and "Subject: Friendly reminder about an overdue invoice" in goal.result
