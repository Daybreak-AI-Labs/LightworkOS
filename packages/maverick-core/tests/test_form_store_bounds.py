"""Hosted-form submissions stay bounded and receive unique cursors."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


def test_concurrent_submissions_have_unique_monotonic_sequences(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import form_store

    with ThreadPoolExecutor(max_workers=12) as pool:
        sequences = list(pool.map(lambda n: form_store.append("lead", {"n": n}), range(32)))
    assert sorted(sequences) == list(range(1, 33))
    events, cursor = form_store.since("lead", "0")
    assert cursor == "32"
    assert [event["_seq"] for event in events] == list(range(1, 33))


def test_full_form_refuses_a_new_submission_without_losing_old_ones(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import form_store

    monkeypatch.setattr(form_store, "_MAX_LINES", 2)
    assert form_store.append("lead", {"n": "1"}) == 1
    assert form_store.append("lead", {"n": "2"}) == 2
    with pytest.raises(form_store.FormStoreFull):
        form_store.append("lead", {"n": "3"})
    events, cursor = form_store.since("lead", "0")
    assert cursor == "2"
    assert [event["n"] for event in events] == ["1", "2"]


def test_legacy_punctuation_token_uses_its_existing_file(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import form_store

    old_path = tmp_path / "forms" / "a-b.ndjson"
    old_path.parent.mkdir()
    old_path.write_text('{"seq":1,"ts":0.0,"fields":{"n":"old"}}\n', encoding="utf-8")
    assert form_store.append("a.b", {"n": "new"}) == 2
    events, _ = form_store.since("a.b", "0")
    assert [event["n"] for event in events] == ["old", "new"]


@pytest.mark.parametrize("damaged_line", [
    "{damaged\n",
    '{"seq":2,"ts":0,"fields":[]}\n',
    '{"seq":2,"ts":"bad","fields":{"n":"2"}}\n',
    "",  # A deleted accepted row leaves a sequence gap.
])
def test_damaged_accepted_row_blocks_poll_and_new_intake(monkeypatch, tmp_path, damaged_line):
    _isolate(monkeypatch, tmp_path)
    from maverick import form_store

    for n in range(1, 4):
        assert form_store.append("lead", {"n": str(n)}) == n
    path = form_store._path("lead")
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    path.write_text(lines[0] + damaged_line + lines[2], encoding="utf-8")
    damaged_content = path.read_text(encoding="utf-8")

    with pytest.raises(form_store.FormStoreUnavailable):
        form_store.since("lead", "0", limit=25)
    with pytest.raises(form_store.FormStoreUnavailable):
        form_store.since("lead", "")
    with pytest.raises(form_store.FormStoreUnavailable):
        form_store.pending("lead", "0")
    assert form_store.append("lead", {"n": "4"}) == 0
    assert path.read_text(encoding="utf-8") == damaged_content


def test_missing_accepted_queue_does_not_reset_sequence(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import form_store

    assert form_store.since("never-used", "") == ([], "0")
    with pytest.raises(form_store.FormStoreUnavailable):
        form_store.since("never-used", "1")

    assert form_store.append("lead", {"n": "1"}) == 1
    path = form_store._path("lead")
    assert form_store._accepted_marker(path).exists()
    path.unlink()
    with pytest.raises(form_store.FormStoreUnavailable):
        form_store.since("lead", "0")
    with pytest.raises(form_store.FormStoreUnavailable):
        form_store.pending("lead", "0")
    assert form_store.append("lead", {"n": "2"}) == 0
    assert not path.exists()


def test_failed_first_append_leaves_no_accepted_marker_and_can_retry(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import file_lock, form_store

    original = file_lock.open_private_append

    def fail_before_file_creation(*args, **kwargs):
        raise OSError("simulated first write failure")

    monkeypatch.setattr(file_lock, "open_private_append", fail_before_file_creation)
    assert form_store.append("lead", {"n": "first"}) == 0
    path = form_store._path("lead")
    assert path.with_name(path.name + ".lock").exists()
    assert not path.exists()
    assert not form_store._accepted_marker(path).exists()
    assert form_store.pending("lead", "0") == 0

    monkeypatch.setattr(file_lock, "open_private_append", original)
    assert form_store.append("lead", {"n": "retry"}) == 1
    assert form_store._accepted_marker(path).exists()
    assert form_store.since("lead", "0")[0][0]["n"] == "retry"


def test_valid_pre_upgrade_queue_gets_durable_marker_on_read(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import form_store

    path = form_store._path("legacy")
    path.parent.mkdir()
    path.write_text('{"seq":1,"ts":0,"fields":{"n":"old"}}\n', encoding="utf-8")
    assert not form_store._accepted_marker(path).exists()
    assert form_store.since("legacy", "0")[1] == "1"
    assert form_store._accepted_marker(path).exists()
    path.unlink()
    with pytest.raises(form_store.FormStoreUnavailable):
        form_store.since("legacy", "0")
