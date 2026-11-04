"""Regression tests: tool ._run/_run handlers must never raise on hostile
arg VALUES the model can put in its JSON object (non-str where a str is
expected, unhashable op, overlong path, non-finite numbers). The contract
is a returned string (often ``ERROR: ...``), never an uncaught exception.

These cover a fuzz mop-up pass over packages/maverick-core/maverick/tools/.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from maverick.sandbox.local import LocalBackend
from maverick.tools import compute as compute_mod
from maverick.tools import file_watcher as fw_mod
from maverick.tools import github_repo_search as ghrs_mod
from maverick.tools import image_edit as ie_mod
from maverick.tools import notebook_exec as nb_mod
from maverick.tools import redact as redact_mod
from maverick.tools import s3_attachments as s3_mod
from maverick.tools import sanctions_screen as sanc_mod
from maverick.tools import semantic_code_search as scs_mod
from maverick.tools import teams_tool as teams_mod
from maverick.tools import translate as tr_mod


@pytest.fixture()
def sandbox():
    return LocalBackend(workdir=Path(tempfile.mkdtemp()))


# --- str-coercion of the (x or "").strip() idiom on non-str values ----------

def test_github_repo_search_int_query(monkeypatch):
    # int query must coerce to str, not raise AttributeError on .strip().
    monkeypatch.setattr(ghrs_mod, "_http_get_json", lambda url: (200, {}))
    assert isinstance(ghrs_mod._run({"query": 5}), str)


def test_github_repo_search_inf_limit(monkeypatch):
    # int(float("inf")) would raise OverflowError; must not. Stub the HTTP
    # call so the limit-coercion path runs offline.
    monkeypatch.setattr(ghrs_mod, "_http_get_json", lambda url: (200, {}))
    out = ghrs_mod._run({"query": "ok", "limit": 1e400})
    assert isinstance(out, str)


def test_redact_non_str_text():
    out = redact_mod._run({"op": "redact", "text": 12345})
    assert isinstance(out, str)
    out2 = redact_mod._run({"op": "verify", "text": [1, 2, 3]})
    assert isinstance(out2, str)


def test_sanctions_screen_int_name():
    out = sanc_mod._run({"name": 42})
    assert isinstance(out, str)


def test_semantic_code_search_int_query():
    out = scs_mod._run({"query": 99})
    assert out.startswith("ERROR")


def test_teams_non_str_text_and_title():
    out = teams_mod._run({"text": 5, "title": 7})
    assert isinstance(out, str)


def test_translate_non_str_text():
    out = tr_mod._run({"op": "translate", "text": 5})
    assert isinstance(out, str)


# --- unhashable op (model sends a list/dict for "op") -----------------------

def test_compute_unhashable_op():
    assert compute_mod._run({"op": [None, 1]}).startswith("ERROR")


def test_s3_attachments_unhashable_op():
    assert s3_mod._run({"op": ["x"]}).startswith("ERROR")


def test_image_edit_unhashable_op(sandbox):
    assert ie_mod._run({"op": [1, 2]}, sandbox).startswith("ERROR")


# --- overlong / non-str path -> OSError(ENAMETOOLONG) on Path.exists() ------

def test_file_watcher_overlong_path(sandbox):
    out = fw_mod._run(sandbox, {"path": "x" * 5000})
    assert out.startswith("ERROR")


def test_file_watcher_non_str_path(sandbox):
    assert isinstance(fw_mod._run(sandbox, {"path": 7}), str)


def test_file_watcher_inf_max_files(sandbox):
    out = fw_mod._run(sandbox, {"path": ".", "since": 0, "max_files": 1e400})
    assert isinstance(out, str)


def test_notebook_exec_overlong_path(sandbox):
    out = nb_mod._run({"path": "x" * 5000}, sandbox)
    assert out.startswith("ERROR")


def test_notebook_exec_non_str_path(sandbox):
    assert isinstance(nb_mod._run({"path": 5}, sandbox), str)
