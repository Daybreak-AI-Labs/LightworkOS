"""Conversational intake: the intake tools driving a session, plus assembly of
the intake agent. Imports maverick.tools, so it runs in CI (full deps)."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from maverick.intake import IntakeSession
from maverick.tools.intake_tools import intake_tools


class _StubLLM:
    def complete(self, system, messages, **kw):
        return SimpleNamespace(
            text='{"persona": "shop assistant", "allow_tools": ["read_file"]}'
        )


def test_intake_tools_drive_session_to_a_draft(tmp_path):
    from maverick_knowledge import DeterministicEmbedder, KnowledgeBase

    doc = tmp_path / "policy.txt"
    doc.write_text("We ship within two business days.")
    session = IntakeSession()
    kb = KnowledgeBase(embedder=DeterministicEmbedder(dim=64))
    tools = {t.name: t for t in intake_tools(session, llm=_StubLLM(), kb=kb)}

    asyncio.run(tools["record_business"].fn(
        {"name": "Kappa Shop", "description": "a retailer"}))
    asyncio.run(tools["add_goal"].fn({"goal": "answer shipping questions"}))
    asyncio.run(tools["add_document"].fn({"path": str(doc)}))
    assert session.name == "Kappa Shop"
    assert session.goals == ["answer shipping questions"]
    assert session.doc_paths == [str(doc)]

    out = asyncio.run(tools["finalize_intake"].fn({}))
    assert "DRAFT" in out and "kappa_shop" in out
    # Drafting never ingests the uploaded documents: ingestion is deferred until
    # the human approves activation (attach_docs_to_profile), so nothing about
    # an upload is stored or sent before the approval gate. The draft therefore
    # carries no pending collection and the docs are not searchable yet.
    assert "intake_pending_" not in out
    assert kb.search("kappa_shop", "shipping", k=3) == []   # not ingested pre-approval


def test_finalize_refuses_when_not_ready():
    session = IntakeSession()
    tools = {t.name: t for t in intake_tools(session)}
    out = asyncio.run(tools["finalize_intake"].fn({}))
    assert "Not enough" in out
