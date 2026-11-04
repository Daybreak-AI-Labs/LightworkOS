"""L3 real-proposer-text data path for RLAIF/DPO.

The donated Klear corpus is PII-safe (hashed/structural messages, no raw
text), so real DPO text comes from an operator side-channel keyed by
trajectory id. These cover that resolution + the refuse-the-stand-in gate.
All torch-free: the GPU train() loop itself is operator-side and untested.
"""
from __future__ import annotations

import json
import sys

from maverick.training import rlaif


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return path


# ---------- load_text_sidecar ----------

def test_sidecar_json_object_form(tmp_path):
    p = _write(tmp_path / "s.json", json.dumps({"a": "alpha", "b": "beta"}))
    assert rlaif.load_text_sidecar(p) == {"a": "alpha", "b": "beta"}


def test_sidecar_jsonl_form_skips_garbage(tmp_path):
    p = _write(
        tmp_path / "s.jsonl",
        '{"id": "a", "text": "alpha"}\n'
        "not json\n"
        "\n"
        '{"id": "b", "text": "beta"}\n'
        '{"id": "c"}\n',  # missing text -> skipped
    )
    assert rlaif.load_text_sidecar(p) == {"a": "alpha", "b": "beta"}


def test_sidecar_object_skips_non_string_values(tmp_path):
    p = _write(tmp_path / "s.json", json.dumps({"a": "alpha", "b": 5}))
    assert rlaif.load_text_sidecar(p) == {"a": "alpha"}


# ---------- row_text precedence ----------

def test_row_text_prefers_sidecar():
    row = {"id": "a", "text": "inline", "messages": [{"content": "msg"}]}
    assert rlaif.row_text(row, {"a": "side"}) == "side"


def test_row_text_inline_then_messages():
    assert rlaif.row_text({"id": "a", "text": "inline"}) == "inline"
    joined = rlaif.row_text({"id": "a", "messages": [
        {"content": "one"}, {"text": "two"}, {"content": "  "}]})
    assert joined == "one\ntwo"


def test_row_text_none_when_no_real_text():
    # Structural-only row (the standard PII-safe shape) has no real text.
    row = {"id": "a", "messages": [{"role": "coder", "type": "final"}]}
    assert rlaif.row_text(row) is None
    assert rlaif.row_text(row, {"other": "x"}) is None


# ---------- attach_pair_texts ----------

def _pair(cid="a", rid="b"):
    return {"task_family": "swe", "chosen_id": cid, "rejected_id": rid,
            "margin": 1.0, "weight": 1.0}


def test_attach_populates_from_sidecar():
    pairs = [_pair()]
    rows_by_id = {"a": {"id": "a"}, "b": {"id": "b"}}
    out, dropped = rlaif.attach_pair_texts(
        pairs, rows_by_id, sidecar={"a": "chosen!", "b": "rejected!"})
    assert dropped == 0
    assert out[0]["chosen_text"] == "chosen!" and out[0]["rejected_text"] == "rejected!"
    # input not mutated
    assert "chosen_text" not in pairs[0]


def test_attach_require_real_drops_incomplete_pairs():
    pairs = [_pair("a", "b"), _pair("a", "c")]
    rows_by_id = {"a": {"id": "a"}, "b": {"id": "b"}, "c": {"id": "c"}}
    out, dropped = rlaif.attach_pair_texts(
        pairs, rows_by_id, sidecar={"a": "x", "b": "y"}, require_real=True)
    assert dropped == 1 and len(out) == 1
    assert out[0]["rejected_id"] == "b"  # the pair with both texts survived


def test_attach_keeps_pairs_when_not_requiring_real():
    pairs = [_pair("a", "b")]
    rows_by_id = {"a": {"id": "a"}, "b": {"id": "b"}}
    out, dropped = rlaif.attach_pair_texts(
        pairs, rows_by_id, sidecar={"a": "only-chosen"})
    assert dropped == 0 and len(out) == 1
    assert out[0]["chosen_text"] == "only-chosen" and "rejected_text" not in out[0]


# ---------- main(): refuse the stand-in, torch-free ----------

def _klear(tmp_path):
    rows = [
        {"id": "a", "task_family": "swe", "terminal_reward": 1.0,
         "messages": [{"role": "coder", "type": "final"}], "rewards": []},
        {"id": "b", "task_family": "swe", "terminal_reward": 0.0,
         "messages": [{"role": "coder", "type": "tool_call", "name": "x",
                       "error": "e"}], "rewards": []},
    ]
    p = tmp_path / "traj.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return p


def test_main_require_real_text_refuses_without_sidecar(tmp_path, capsys):
    data = _klear(tmp_path)
    rc = rlaif.main([
        "--data", str(data), "--base-model", "x",
        "--out", str(tmp_path / "out"), "--require-real-text",
    ])
    assert rc == 1
    assert "Refusing to train on the structural stand-in" in capsys.readouterr().err
    # never created an output dir (bailed before training)
    assert not (tmp_path / "out").exists()


def test_main_with_sidecar_passes_data_path_then_needs_torch(
    tmp_path, capsys, monkeypatch,
):
    # Keep this optional-dependency test deterministic when the developer
    # environment happens to have the training extra installed.
    monkeypatch.setitem(sys.modules, "torch", None)
    data = _klear(tmp_path)
    side = tmp_path / "texts.jsonl"
    side.write_text(
        '{"id": "a", "text": "the chosen attempt transcript"}\n'
        '{"id": "b", "text": "the rejected attempt transcript"}\n',
        encoding="utf-8",
    )
    rc = rlaif.main([
        "--data", str(data), "--base-model", "x",
        "--out", str(tmp_path / "out"), "--require-real-text",
        "--text-sidecar", str(side),
    ])
    err = capsys.readouterr().err
    # Got PAST the data path (real text attached, pair kept) and into train(),
    # which fails only because torch isn't installed here.
    assert "1/1 pair(s) have it" in err
    assert rc == 1 and "needs torch" in err


# ---------- DPO row resolution (shared by full-param + QLoRA paths) ----------

def test_resolve_pair_text_precedence_and_require():
    pair = {"chosen_text": "cached", "chosen_id": "a"}
    assert rlaif.resolve_pair_text(pair, "chosen") == "cached"
    # real text via sidecar when no cached text
    p2 = {"chosen_id": "a"}
    assert rlaif.resolve_pair_text(
        p2, "chosen", rows_by_id={"a": {"id": "a"}},
        text_sidecar={"a": "real"}) == "real"
    # require_real with no text -> raises
    import pytest
    with pytest.raises(ValueError):
        rlaif.resolve_pair_text(
            p2, "chosen", rows_by_id={"a": {"id": "a"}}, require_real_text=True)


def test_pairs_to_dpo_rows_builds_and_skips_incomplete():
    pairs = [
        {"chosen_text": "good1", "rejected_text": "bad1", "weight": 0.9},
        {"chosen_text": "good2", "rejected_id": "z"},  # missing rejected text
    ]
    # require_real -> the incomplete pair is skipped, not raised
    rows = rlaif.pairs_to_dpo_rows(pairs, require_real_text=True)
    assert len(rows) == 1
    assert rows[0] == {"chosen": "good1", "rejected": "bad1", "weight": 0.9}


# ---------- QLoRA path: graceful missing-dep (no torch/peft here) ----------

def test_main_lora_path_needs_qlora_deps(tmp_path, capsys):
    data = _klear(tmp_path)
    side = tmp_path / "texts.jsonl"
    side.write_text('{"id": "a", "text": "c"}\n{"id": "b", "text": "r"}\n',
                    encoding="utf-8")
    rc = rlaif.main([
        "--data", str(data), "--base-model", "Qwen/Qwen3-Coder-30B-A3B",
        "--out", str(tmp_path / "out"), "--require-real-text",
        "--text-sidecar", str(side), "--lora", "--bits", "4",
    ])
    err = capsys.readouterr().err
    assert rc == 1 and "QLoRA DPO needs" in err  # routed to the QLoRA backend
