"""The learning-pass recent window is read strictly on every platform."""
from __future__ import annotations

import os

import pytest
from fastapi import HTTPException
from maverick import reflexion
from maverick_dashboard import learning_passes


def test_recent_window_reads_the_real_file_and_refuses_an_unreadable_record(tmp_path, monkeypatch):
    path = tmp_path / "reflexions.ndjson"
    monkeypatch.setattr(reflexion, "DEFAULT_PATH", path)
    assert reflexion.default_path() == path
    path.write_text("not a reflexion record\n", encoding="utf-8")
    # A present but unreadable history stops the pass; it never reads as an empty window.
    with pytest.raises(HTTPException) as refused:
        learning_passes._recent(["claude-x"])
    assert refused.value.status_code == 409
    path.write_text("", encoding="utf-8")
    assert learning_passes._recent(["claude-x"]) == ([], os.path.normcase(str(path.resolve())))
