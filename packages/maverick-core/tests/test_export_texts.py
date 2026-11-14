"""Producer for the real-text DPO sidecar (proposer_texts.jsonl).

Verifies the transcript id matches what ingest assigns (so the sidecar lines
up with trajectories.jsonl), the event->text join, and the CLI round-trip
into rlaif.load_text_sidecar. World-free via dependency injection.
"""
from __future__ import annotations

import json

from maverick.training import export_texts, rlaif
from maverick.training.ingest import build_trajectory


def _record(brief_hash="abc123", ts=1700000000, goal_id=7):
    return {"task_brief_hash": brief_hash, "ts": ts, "goal_id": goal_id,
            "model_id": "m", "outcome": "success", "reward": 1.0}


def _events():
    return [
        {"agent": "orchestrator", "kind": "plan", "content": "decompose the goal", "ts": 1},
        {"agent": "coder-1", "kind": "observation", "content": "tool=shell -> ok", "ts": 2},
        {"agent": "coder-1", "kind": "finding", "content": "patch applied", "ts": 3},
        {"agent": "x", "kind": "noise", "content": "   ", "ts": 4},  # empty -> skipped
    ]


# ---------- id consistency with ingest ----------

def test_trajectory_id_matches_ingest():
    rec = _record()
    # build_trajectory is what writes trajectories.jsonl's row id.
    assert export_texts.record_trajectory_id(rec) == build_trajectory(rec, []).trajectory_id


# ---------- event -> transcript ----------

def test_events_to_text_joins_and_skips_empty():
    txt = export_texts.events_to_text(_events())
    assert "[orchestrator/plan] decompose the goal" in txt
    assert "[coder-1/finding] patch applied" in txt
    assert "noise" not in txt        # the blank-content event is dropped
    assert txt.count("\n") == 2      # three non-empty events


def test_events_to_text_empty_when_no_content():
    assert export_texts.events_to_text([]) == ""
    assert export_texts.events_to_text([{"agent": "a", "kind": "k", "content": ""}]) == ""


# ---------- export_texts (DI) ----------

def test_export_texts_builds_id_to_transcript_map():
    records = [_record("h1", 10, 1), _record("h2", 20, 2)]
    fetch = lambda rec: _events() if rec["goal_id"] == 1 else []  # noqa: E731
    out = export_texts.export_texts(records, fetch)
    # only the record with events gets a transcript; the empty one is omitted
    assert set(out) == {export_texts.record_trajectory_id(records[0])}
    assert "patch applied" in out[export_texts.record_trajectory_id(records[0])]


# ---------- rejected-draft text rides in the sidecar ----------

def test_export_texts_emits_rejected_draft_text():
    """The rejected draft text (carried in the record, not goal_events) is
    emitted under ingest's rejected id, so the DPO sidecar has BOTH halves."""
    from maverick.training.ingest import rejected_trajectory_id
    rec = _record("h1", 10, 1)
    rec["rejected_attempts"] = [{"text": "the weak first draft", "confidence": 0.6}]
    out = export_texts.export_texts([rec], lambda r: _events())
    assert out[export_texts.record_trajectory_id(rec)]    # chosen transcript
    rej_id = rejected_trajectory_id(rec, 0)
    assert out[rej_id] == "the weak first draft"         # rejected half

def test_export_texts_skips_rejected_without_text():
    rec = _record("h1", 10, 1)
    rec["rejected_attempts"] = [{"confidence": 0.6}]     # stripped (no donate_text)
    out = export_texts.export_texts([rec], lambda r: _events())
    assert set(out) == {export_texts.record_trajectory_id(rec)}  # no rejected entry


def test_export_texts_emits_candidate_patches():
    """Best-of-N candidate patches export under ingest's candidate id, so the DPO
    sidecar carries both halves of a candidate pair."""
    from maverick.training.ingest import candidate_trajectory_id
    rec = _record("h1", 10, 1)
    rec["scored_candidates"] = [
        {"text": "PASS patch", "score": 1.0, "all_pass": True},
        {"text": "FAIL patch", "score": 0.0, "all_pass": False},
    ]
    out = export_texts.export_texts([rec], lambda r: _events())
    assert out[candidate_trajectory_id(rec, 0)] == "PASS patch"
    assert out[candidate_trajectory_id(rec, 1)] == "FAIL patch"


# ---------- CLI round-trip into the rlaif sidecar loader ----------

def test_main_writes_sidecar_loadable_by_rlaif(tmp_path, monkeypatch):
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    record = {**_record("hh", 99, 0), "source_ownership": "unowned"}
    (outbox / "rec.json").write_text(json.dumps(record), encoding="utf-8")
    # Inject canned events regardless of the (empty test) world DB.
    monkeypatch.setattr(export_texts, "fetch_steps_for_goal",
                        lambda world, gid: _events())
    out = tmp_path / "proposer_texts.jsonl"
    rc = export_texts.main(["--in", str(outbox), "--out", str(out)])
    assert rc == 0 and out.exists()
    side = rlaif.load_text_sidecar(out)        # the consumer reads it back
    identity = export_texts.record_trajectory_id(record)
    assert side[identity] and "patch applied" in side[identity]


def test_main_empty_outbox_writes_empty_and_warns(tmp_path, capsys):
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    out = tmp_path / "proposer_texts.jsonl"
    rc = export_texts.main(["--in", str(outbox), "--out", str(out)])
    assert rc == 0 and out.exists() and out.read_text() == ""
    assert "no transcripts" in capsys.readouterr().err.lower()


def test_main_writes_raw_transcripts_owner_only(tmp_path):
    import os
    import stat

    import pytest
    if os.name != "posix":
        pytest.skip("POSIX permission bits")
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    out = tmp_path / "proposer_texts.jsonl"
    out.write_text("old", encoding="utf-8")
    os.chmod(out, 0o644)
    assert export_texts.main(["--in", str(outbox), "--out", str(out)]) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_export_skips_a_donation_whose_events_fail(caplog):
    good, bad = _record("good", 1, 1), _record("bad", 2, 2)

    def fetch(rec):
        if rec["goal_id"] == 2:
            raise RuntimeError("goal_events failed")
        return _events()

    with caplog.at_level("WARNING"):
        out = export_texts.export_texts([bad, good], fetch)
    assert list(out) == [export_texts.record_trajectory_id(good)]
    assert "skipped 1 donation" in caplog.text


def test_main_writes_through_symlinked_dir_and_to_devices(tmp_path):
    import os

    import pytest
    if os.name != "posix":
        pytest.skip("POSIX symlinks and /dev/null")
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real, target_is_directory=True)
    assert export_texts.main(["--in", str(outbox), "--out", str(tmp_path / "link" / "o.jsonl")]) == 0
    assert (real / "o.jsonl").exists()
    assert export_texts.main(["--in", str(outbox), "--out", "/dev/null"]) == 0
