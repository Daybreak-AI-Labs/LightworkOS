"""Embed each specialist text once per test run.

``domain_router`` keeps one process-wide index and rebuilds it whenever the
roster changes, so tests that alternate rosters (shipped packs, a tenant's
custom pack, a department's subset) re-embed all 2,031 shipped packs each
time. With the optional local model installed that is minutes of CPU per
rebuild, in every xdist worker that runs one of those files. The vectors
depend only on the text and the loaded model, so this returns the vector
already computed in this run for the same text and asks the real embedder
only for texts nobody has embedded yet. Without the model the real embedder
returns ``None`` and so does this, as before.

Workers share the vectors through a JSON file in the run's shared temporary
directory, under a file lock, so one worker embeds the roster while the
others wait for it and read the result instead of competing for the CPU.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_VECTORS: dict[str, list[float]] = {}


def _shared_file(tmp_path_factory) -> Path:
    base = tmp_path_factory.getbasetemp()
    # Under xdist each worker's base sits inside the run's shared directory.
    return (base.parent if os.environ.get("PYTEST_XDIST_WORKER") else base) / "pack-embeddings.json"


def _embed_missing(real, missing: list[str], shared: Path) -> bool:
    try:
        from filelock import FileLock  # ships with the model's own dependencies
    except ImportError:
        vectors = real(missing)
        if vectors is None:
            return False
        _VECTORS.update(zip(missing, vectors, strict=True))
        return True
    with FileLock(str(shared) + ".lock"):
        if shared.exists():
            _VECTORS.update(json.loads(shared.read_text(encoding="utf-8")))
        missing = [text for text in missing if text not in _VECTORS]
        if missing:
            vectors = real(missing)
            if vectors is None:
                return False
            _VECTORS.update(zip(missing, vectors, strict=True))
            shared.write_text(json.dumps(_VECTORS), encoding="utf-8")
    return True


def without_local_model(monkeypatch) -> None:
    """Rank the roster the way a host without the optional local model does.

    ``rank_specialists`` blends in semantic scores only when
    ``maverick.skill.embeddings`` can load its model, and falls back to the
    deterministic lexical index when it cannot. A test of the ranking logic,
    the routes around it or input handling pins that fallback, so it asserts
    the same thing whether or not FastEmbed is installed and never runs model
    inference over the 2,031 shipped packs (minutes on a two-core runner).
    The roster index is process-wide, so it is rebuilt here instead of reusing
    one that another test built with the model.
    """
    from maverick import domain_router
    from maverick.skill import embeddings

    monkeypatch.setattr(embeddings, "_get_model", lambda: None)
    monkeypatch.setattr(domain_router, "_CACHE", None)


def reuse_embeddings(monkeypatch, tmp_path_factory) -> None:
    """Wrap ``maverick.skill.embeddings.embed`` with the run-wide memo."""
    from maverick.skill import embeddings

    real = embeddings.embed
    shared = _shared_file(tmp_path_factory)

    def embed(texts):
        if not texts or embeddings._get_model() is None:
            return real(texts)
        missing = [text for text in dict.fromkeys(texts) if text not in _VECTORS]
        if missing and not _embed_missing(real, missing, shared):
            return None
        return [list(_VECTORS[text]) for text in texts]

    monkeypatch.setattr(embeddings, "embed", embed)
