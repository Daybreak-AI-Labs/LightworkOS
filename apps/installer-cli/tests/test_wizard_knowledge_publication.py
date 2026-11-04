"""Backend selection states publication limits without silently switching it."""
from maverick_installer import wizard


def test_qdrant_choice_explains_limit_and_keeps_selected_url(monkeypatch):
    printed = []
    choices_seen = []
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(wizard.console, "print", lambda *args, **_kwargs: printed.extend(map(str, args)))

    def select(_message, choices, **_kwargs):
        choices_seen.extend(choices)
        return next(choice for choice in choices if choice.startswith(
            "qdrant" if any(item.startswith("qdrant") for item in choices) else "deterministic"
        ))

    monkeypatch.setattr(wizard, "_q_select", select)
    monkeypatch.setattr(wizard, "_q_text", lambda *_args, **_kwargs: "http://qdrant.internal:6333")
    assert wizard.pick_knowledge() == {
        "enable": True, "embedder": "deterministic", "store": "qdrant", "reindex_jobs": True,
        "reindex_max_dollars": 5.0,
        "url": "http://qdrant.internal:6333",
    }
    assert any(choice.startswith("qdrant") and "new ingestion unavailable" in choice for choice in choices_seen)
    assert any("SQLite or pgvector to ingest new documents" in line for line in printed)
