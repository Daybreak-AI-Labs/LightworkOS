"""Native and Copilot previews share the exact hosted rate-based review."""
from maverick_dashboard import knowledge_library_api as native
from maverick_dashboard import product_operations_knowledge as operations


def test_copilot_preserves_nonzero_ceiling_rate_basis_model_and_native_review(monkeypatch):
    review = {"count": 3, "cost_ceiling": .000125,
              "price_basis": "Captured standard rate; not a guaranteed provider invoice.",
              "model": "Configured embedding model", "limits": {"max_wall_seconds": 300},
              "review": "c" * 64}
    monkeypatch.setattr(native, "_reindex_authority", lambda _request: "a" * 64)
    def prepare(function, collection):
        from maverick.knowledge_reindex_jobs import preview
        assert function is preview and collection == "policies"
        return review
    monkeypatch.setattr(native, "_reindex_call", prepare)
    result = operations.rebuild_prepare(object(), {}, {"collection": "policies"})
    assert result.native == {"context": "a" * 64, "collection": "policies", "review": "c" * 64}
    changes = {row["label"]: row["after"] for row in result.changes}
    # A non-zero ceiling never reads as free.
    assert changes["Provider admission ceiling"] == "under $0.01. " + review["price_basis"]
    assert changes["Embedding model"] == review["model"]
    assert "local computation only" not in str(changes)


def test_copilot_decides_held_documents_through_the_native_admin_route(monkeypatch):
    held = {"id": "d" * 32, "collection": "it", "source": "welcome.txt",
            "reason": "It contains the words \"you are now\".", "excerpt": "you are now ready to log in"}
    monkeypatch.setattr(native, "held_documents", lambda _request: {"context": "a" * 64, "documents": [held]})
    calls = []

    def decide(request, hold_id, body):
        calls.append((hold_id, body.decision, body.context, body.confirmed))
        return {"context": body.context, "document": {**held, "state": "included"}}

    monkeypatch.setattr(native, "decide_held_document", decide)
    snapshot = operations.held_snapshot(object(), {})
    # The suspect text never enters the Copilot's context.
    assert "excerpt" not in str(snapshot.details) and "ready to log in" not in str(snapshot)
    preview = operations.held_prepare(object(), {}, {"document": "d" * 32, "decision": "include"})
    assert preview.native == {"context": "a" * 64, "document": "d" * 32, "decision": "include"}
    outcome = operations.held_execute(object(), {}, {}, preview.native, "e" * 32)
    assert calls == [("d" * 32, "include", "a" * 64, True)] and outcome.status == "confirmed"
    assert any(entry.id == "knowledge.held_documents" for entry in operations.entries())
