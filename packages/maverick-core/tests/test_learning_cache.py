"""Cross-run learning cache: roundtrip + normalization equivalence, TTL via an
injected clock, the LRU cap, secret refusal, required provenance, and the
off-by-default knob. Fully offline; the secret fixture is built at runtime so
no real-looking credential is committed."""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick.cache import learning as lc
from maverick.file_lock import private_path_is_restricted


@pytest.fixture
def now():
    return {"t": 1_000_000.0}


@pytest.fixture
def cache(tmp_path, now):
    return lc.LearningCache(tmp_path / "lc.json", clock=lambda: now["t"])


def test_roundtrip_and_normalization_equivalence(cache):
    cache.put("Build  the APP.", "make -j test", verified_by="verifier:goal-1")
    entry = cache.get("build the app")  # different casing/spacing/punctuation
    assert entry is not None
    assert entry["result"] == "make -j test"
    assert entry["verified_by"] == "verifier:goal-1"
    assert lc.task_key("Build  the APP.") == lc.task_key("build the app")
    assert lc.normalize("Build  the APP.") == "build the app"
    assert cache.get("a different task") is None


def test_persists_across_instances_with_0600(tmp_path, now):
    path = tmp_path / "lc.json"
    first = lc.LearningCache(path, clock=lambda: now["t"])
    first.put("repo build command", "make build", verified_by="verifier:g2")
    assert private_path_is_restricted(path, 0o600)
    assert private_path_is_restricted(path.parent, 0o700)
    second = lc.LearningCache(path, clock=lambda: now["t"])  # a fresh "run"
    assert second.get("Repo build command")["result"] == "make build"


def test_two_instances_on_one_file_keep_each_others_entries(tmp_path, now):
    # Each instance loaded the file once and rewrote it whole, so the second
    # writer (or a cache hit in a stale one) erased the first one's entries.
    path = tmp_path / "lc.json"
    a = lc.LearningCache(path, clock=lambda: now["t"])
    b = lc.LearningCache(path, clock=lambda: now["t"])
    a.put("task one", "r1", verified_by="verifier:g1")
    b.put("task two", "r2", verified_by="verifier:g2")
    assert a.get("task one") is not None
    fresh = lc.LearningCache(path, clock=lambda: now["t"])
    assert fresh.get("task one")["result"] == "r1"
    assert fresh.get("task two")["result"] == "r2"


def test_prune_drops_an_entry_with_a_non_numeric_expiry(tmp_path, now):
    # get() already treated such an entry as expired; prune() raised ValueError.
    import json
    path = tmp_path / "lc.json"
    lc.LearningCache(path, clock=lambda: now["t"]).put("t", "r", verified_by="v:1")
    raw = json.loads(path.read_text())
    next(iter(raw["entries"].values()))["expires_at"] = "soon"
    path.write_text(json.dumps(raw))
    assert lc.LearningCache(path, clock=lambda: now["t"]).prune() == 1


def test_temp_file_is_restrictive_before_replace(tmp_path, now, monkeypatch):
    import maverick.file_lock as file_lock

    path = tmp_path / "lc.json"
    cache = lc.LearningCache(path, clock=lambda: now["t"])
    real_create = file_lock._secure_mkstemp
    observed: list[tuple[int, bool, int]] = []

    def record_create(directory, *, prefix, suffix, mode):
        fd, temp_path = real_create(
            directory,
            prefix=prefix,
            suffix=suffix,
            mode=mode,
        )
        observed.append(
            (
                mode,
                file_lock.private_path_is_restricted(temp_path, mode),
                Path(temp_path).stat().st_size,
            )
        )
        return fd, temp_path

    monkeypatch.setattr(file_lock, "_secure_mkstemp", record_create)
    cache.put("private task", "private ops data", verified_by="verifier:g2")

    assert observed == [(0o600, True, 0)]
    assert "private ops data" in path.read_text(encoding="utf-8")
    assert private_path_is_restricted(path, 0o600)
    assert list(tmp_path.glob("*.tmp")) == []


def test_ttl_expiry_with_injected_clock(cache, now):
    cache.put("schema for svc Y", "{...}", verified_by="verifier:g3", ttl_days=1)
    assert cache.get("schema for svc Y") is not None
    now["t"] += 86_400.0 + 1  # one day + 1s later
    assert cache.get("schema for svc Y") is None
    assert cache.stats()["entries"] == 0  # expired entry was dropped, not kept


def test_lru_cap_evicts_least_recently_used(tmp_path, now):
    cache = lc.LearningCache(tmp_path / "lc.json", max_entries=2, clock=lambda: now["t"])
    cache.put("task a", "ra", verified_by="v:1")
    now["t"] += 1
    cache.put("task b", "rb", verified_by="v:1")
    now["t"] += 1
    cache.get("task a")  # bump a's recency above b's
    now["t"] += 1
    cache.put("task c", "rc", verified_by="v:1")  # over cap -> evict b
    assert cache.get("task b") is None
    assert cache.get("task a") is not None
    assert cache.get("task c") is not None


def test_refuses_to_store_secrets(cache):
    # Constructed at runtime: obviously fake, but matches the anthropic key
    # pattern the detector knows.
    fake_secret = "sk-ant-" + "a" * 24
    with pytest.raises(ValueError, match="secret"):
        cache.put("api key for x", f"the key is {fake_secret}", verified_by="v:1")
    assert cache.get("api key for x") is None
    assert cache.stats()["entries"] == 0


def test_verified_by_is_required(cache):
    with pytest.raises(TypeError):
        cache.put("task", "result")  # no verified_by at all
    with pytest.raises(ValueError, match="verified_by"):
        cache.put("task", "result", verified_by="   ")
    with pytest.raises(ValueError):
        cache.put("task", "result", verified_by="v:1", ttl_days=0)


def test_invalidate_prune_stats_and_tags(cache, now):
    cache.put("short lived", "x", verified_by="v:1", ttl_days=1, tags=["build"])
    cache.put("long lived", "y", verified_by="v:1", ttl_days=10)
    assert cache.get("short lived")["tags"] == ["build"]
    now["t"] += 2 * 86_400.0
    assert cache.prune() == 1  # only the expired entry goes
    assert cache.stats()["entries"] == 1
    assert cache.invalidate("long lived") is True
    assert cache.invalidate("long lived") is False
    assert cache.stats()["entries"] == 0


def test_corrupt_file_fails_open(tmp_path, now):
    path = tmp_path / "lc.json"
    path.write_text("{not json", encoding="utf-8")
    cache = lc.LearningCache(path, clock=lambda: now["t"])
    assert cache.stats()["entries"] == 0
    cache.put("t", "r", verified_by="v:1")  # and it still works
    assert cache.get("t")["result"] == "r"


def test_off_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_LEARNING_CACHE", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", lambda *a, **k: {})
    assert lc.enabled() is False
    monkeypatch.setenv("MAVERICK_LEARNING_CACHE", "1")
    assert lc.enabled() is True
    monkeypatch.delenv("MAVERICK_LEARNING_CACHE", raising=False)
    monkeypatch.setattr(
        config_mod, "load_config", lambda *a, **k: {"memory": {"learning_cache": True}},
    )
    assert lc.enabled() is True


def test_shared_singleton_and_reset():
    lc.reset_shared()
    try:
        a = lc.shared()
        assert a is lc.shared()
        lc.reset_shared()
        assert lc.shared() is not a
    finally:
        lc.reset_shared()


def test_native_goal_reuse_rechecks_original_source_and_exact_tenant(monkeypatch):
    from maverick import orchestrator, pilot_learning
    from maverick.paths import tenant_scope
    from maverick.world_model import open_world

    monkeypatch.setenv("MAVERICK_LEARNING_CACHE", "1")
    lc.reset_shared()
    try:
        with tenant_scope(tenant="source-cache-a"):
            world = open_world()
            def task(title, owner="user:source-owner"):
                return world.get_goal(world.create_goal(title, "", owner=owner))

            source, later = task("Synthetic repeat process"), task("Synthetic repeat process")
            cache = lc.shared()
            # A verifier label alone cannot qualify legacy cached text.
            cache.put(orchestrator._learning_cache_task(source), "Unbound synthetic answer", verified_by=f"verifier:goal-{source.id}")
            assert orchestrator._maybe_learning_cache_block(later, None) is None
            orchestrator._maybe_store_learning_cache(source, "Synthetic checked answer", 0.99)
            assert "Synthetic checked answer" in orchestrator._maybe_learning_cache_block(later, None)

            with tenant_scope(tenant="source-cache-b"):
                other_world = open_world()
                other = other_world.get_goal(other_world.create_goal(source.title, "", owner=source.owner))
                assert other.id == source.id
                assert lc.shared() is not cache
                assert orchestrator._maybe_learning_cache_block(other, None) is None

            pilot_learning.protect(source.id, pilot_id="PLE-synthetic-reuse", plan_version=1,
                                   input_version=1, actor=source.owner)
            assert pilot_learning.excluded(source.id) and not pilot_learning.excluded(later.id)
            assert orchestrator._maybe_learning_cache_block(later, None) is None

            deleted, next_deleted = task("Synthetic erased source"), task("Synthetic erased source")
            orchestrator._maybe_store_learning_cache(deleted, "Synthetic erased answer", 0.99)
            assert orchestrator._maybe_learning_cache_block(next_deleted, None)
            with world._writing() as connection:
                connection.execute("DELETE FROM goals WHERE id=?", (deleted.id,))
            assert orchestrator._maybe_learning_cache_block(next_deleted, None) is None

            unowned, next_unowned = task("Synthetic claimed source", ""), task("Synthetic claimed source", "")
            orchestrator._maybe_store_learning_cache(unowned, "Synthetic formerly shared answer", 0.99)
            assert orchestrator._maybe_learning_cache_block(next_unowned, None)
            assert world.bind_goal_owner(unowned.id, "user:new-owner")
            assert orchestrator._maybe_learning_cache_block(next_unowned, None) is None

            screened, next_screened = task("Synthetic screened source"), task("Synthetic screened source")
            orchestrator._maybe_store_learning_cache(screened, "Synthetic checked during screening", 0.99)
            class Shield:
                def scan_output(self, _text):
                    from types import SimpleNamespace
                    pilot_learning.protect(screened.id, pilot_id="PLE-synthetic-screening", plan_version=1,
                                           input_version=1, actor=screened.owner)
                    return SimpleNamespace(allowed=True)
            assert orchestrator._maybe_learning_cache_block(next_screened, Shield()) is None

            expired, next_expired = task("Synthetic expired source"), task("Synthetic expired source")
            orchestrator._maybe_store_learning_cache(expired, "Synthetic expired answer", 0.99)
            assert orchestrator._maybe_learning_cache_block(next_expired, None)
            expires_at = cache.get(orchestrator._learning_cache_task(expired))["expires_at"]
            monkeypatch.setattr(cache, "_clock", lambda: expires_at + 1)
            assert orchestrator._maybe_learning_cache_block(next_expired, None) is None
    finally:
        lc.reset_shared()


def test_shared_tenant_instances_are_bounded(monkeypatch):
    from maverick.paths import tenant_scope

    monkeypatch.setattr(lc, "_MAX_SHARED_INSTANCES", 2)
    lc.reset_shared()
    try:
        with tenant_scope(tenant="cache-bound-a"):
            first = lc.shared()
            assert lc.shared() is first
        with tenant_scope(tenant="cache-bound-b"):
            assert lc.shared() is not first
        with tenant_scope(tenant="cache-bound-c"):
            lc.shared()
        assert len(lc._shared) == 2
        with tenant_scope(tenant="cache-bound-a"):
            assert lc.shared() is not first
    finally:
        lc.reset_shared()
