"""Intake tools -- the conversational intake agent's hands.

Each tool is bound to a shared :class:`maverick.intake.IntakeSession`: as the
agent interviews the business it calls these to record what it learns, attach
documents, and finally draft the specialist pack. ``finalize_intake`` runs the
generation engine (LLM-propose + clamp) and returns the draft for human
approval -- it never activates or saves the agent itself.
"""
from __future__ import annotations

from . import Tool


def intake_tools(session, *, llm=None, kb=None) -> list[Tool]:
    async def _record(args: dict) -> str:
        if args.get("name"):
            session.name = str(args["name"]).strip()
        if args.get("description"):
            session.description = str(args["description"]).strip()
        if args.get("industry"):
            session.industry = str(args["industry"]).strip()
        return (f"Recorded: name={session.name!r}, industry={session.industry!r}. "
                f"Ready to draft: {session.is_ready()}.")

    async def _add_goal(args: dict) -> str:
        goal = str(args.get("goal", "")).strip()
        if not goal:
            return "ERROR: 'goal' is required."
        session.goals.append(goal)
        return f"Recorded goal #{len(session.goals)}."

    async def _add_document(args: dict) -> str:
        path = str(args.get("path", "")).strip()
        if not path:
            return "ERROR: 'path' is required."
        session.doc_paths.append(path)
        return (f"Attached {path}. {len(session.doc_paths)} document(s) queued; "
                "they are ingested only after human approval.")

    async def _finalize(args: dict) -> str:
        if not session.is_ready():
            return ("Not enough yet -- capture the business name and what it does "
                    "(record_business) before finalizing.")
        try:
            prof = session.finalize(llm=llm, kb=kb)
        except Exception as e:  # never break the interview on a generation error
            return f"Could not draft the pack ({type(e).__name__}); please retry."
        return (
            "Drafted a domain pack (DRAFT -- awaiting the human's approval):\n"
            f"  name: {prof.name}\n"
            f"  compartment: {prof.compartment}\n"
            f"  max_risk: {prof.max_risk}\n"
            f"  allow_tools: {prof.allow_tools}\n"
            f"  knowledge_sources: {prof.knowledge_sources}\n"
            f"  persona: {prof.persona[:300]}\n"
            "Tell the user to review and approve before it goes live."
        )

    return [
        Tool(
            name="record_business",
            description="Record the business's name, what it does, and industry "
                        "as you learn them.",
            input_schema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "industry": {"type": "string"},
                },
            },
            fn=_record,
        ),
        Tool(
            name="add_goal",
            description="Record one goal the business has for its agent.",
            input_schema={
                "type": "object",
                "properties": {"goal": {"type": "string"}},
                "required": ["goal"],
            },
            fn=_add_goal,
        ),
        Tool(
            name="add_document",
            description="Attach an uploaded document or diagram (by path) to "
                        "ingest into the business's knowledge base on finalize.",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            fn=_add_document,
        ),
        Tool(
            name="finalize_intake",
            description="Draft the specialist domain pack from what you've "
                        "collected, for human approval. Does not activate it.",
            input_schema={"type": "object", "properties": {}},
            fn=_finalize,
        ),
    ]
