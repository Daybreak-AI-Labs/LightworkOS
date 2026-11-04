"""The federation replay cache prunes by AGE, not a count cap, so a still-fresh
nonce is never evicted early (which would reopen the replay hole under load)."""
from __future__ import annotations

import pytest
from maverick import federation


@pytest.fixture(autouse=True)
def _clear():
    federation._seen_sigs.clear()
    yield
    federation._seen_sigs.clear()


def test_detects_replay():
    assert federation._replay_seen("sig-a", now=1000.0) is False
    assert federation._replay_seen("sig-a", now=1001.0) is True  # replay


def test_replay_claim_survives_process_memory_reset():
    assert federation._replay_seen("durable-sig", now=1000.0) is False
    federation._seen_sigs.clear()  # simulate a fresh worker/restarted process

    assert federation._replay_seen("durable-sig", now=1001.0) is True


def test_replay_fast_path_is_partitioned_by_scope_and_state(tmp_path):
    first_state = federation._FederationState(tmp_path / "a.sqlite3")
    second_state = federation._FederationState(tmp_path / "b.sqlite3")

    assert not federation._replay_seen(
        "same-sig", now=1000.0, scope="delegation:local:peer-a", state=first_state,
    )
    assert not federation._replay_seen(
        "same-sig", now=1000.0, scope="delegation:local:peer-b", state=first_state,
    )
    assert not federation._replay_seen(
        "same-sig", now=1000.0, scope="delegation:local:peer-a", state=second_state,
    )
    assert federation._replay_seen(
        "same-sig", now=1001.0, scope="delegation:local:peer-a", state=first_state,
    )


def test_old_entries_pruned_by_age():
    w = federation._SIGN_FRESHNESS_S
    federation._replay_seen("old", now=1000.0)
    # Far past the freshness window: "old" is pruned, so it's no longer "seen".
    assert federation._replay_seen("new", now=1000.0 + w + 10) is False
    old_hash = federation.hashlib.sha256(b"old").hexdigest()
    assert all(key[2] != old_hash for key in federation._seen_sigs)


def test_fresh_nonces_survive_high_volume():
    # Under the OLD count-only eviction (cap 4096), a fresh nonce was dropped
    # once the cap was exceeded — reopening replay above ~13.6 sigs/sec. With
    # age-pruning, every in-window nonce is kept regardless of volume.
    base = 1000.0
    sigs = [f"sig-{i}" for i in range(5000)]  # well past the old 4096 cap
    for i, s in enumerate(sigs):
        assert federation._replay_seen(s, now=base + i * 0.001) is False
    # All 5000 are still within the freshness window, so every replay is caught.
    for i, s in enumerate(sigs):
        assert federation._replay_seen(s, now=base + 1.0 + i * 0.001) is True


def test_future_dated_signature_retained_until_envelope_expires():
    w = federation._SIGN_FRESHNESS_S
    first_seen = 1000.0
    created_at = first_seen + w - 1

    assert (
        federation._replay_seen("future", created_at=created_at, now=first_seen)
        is False
    )
    # The signature is older than one window from first receipt, but the signed
    # envelope is still fresh because its created_at was accepted in the future.
    assert federation._fresh(created_at, now=first_seen + w + 1) is True
    assert (
        federation._replay_seen(
            "future", created_at=created_at, now=first_seen + w + 1,
        )
        is True
    )

    # Once the envelope can no longer pass freshness, the cache may prune it.
    assert federation._fresh(created_at, now=created_at + w + 1) is False
    assert federation._replay_seen("replacement", now=created_at + w + 1) is False
    future_hash = federation.hashlib.sha256(b"future").hexdigest()
    assert all(key[2] != future_hash for key in federation._seen_sigs)


def test_concurrent_same_sig_admits_exactly_one():
    """The federation server is multithreaded, so _replay_seen must be atomic:
    when many threads race the SAME fresh signature, exactly one sees it as
    new (False) and the rest as a replay (True). A non-atomic check-then-insert
    would admit the captured signature more than once."""
    import threading

    barrier = threading.Barrier(32)
    results: list[bool] = []
    lock = threading.Lock()

    def _worker():
        barrier.wait()  # maximise the race on the shared cache
        seen = federation._replay_seen("race-sig", now=2000.0)
        with lock:
            results.append(seen)

    threads = [threading.Thread(target=_worker) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one admission (False); every other call is a replay (True).
    assert results.count(False) == 1
    assert results.count(True) == 31
