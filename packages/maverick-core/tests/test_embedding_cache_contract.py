"""Local deterministic embedder contract; no model downloads or provider calls."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from maverick import self_learning as sl
from maverick.paths import reset_tenant, set_tenant
from maverick.skill import embeddings as se
from maverick.skills import Skill


def test_two_processes_keep_unverified_corpora_warm_without_shared_cache_churn(tmp_path):
    script = """
import json, sys
from pathlib import Path
from maverick.skill import embeddings as se
class LocalModel:
    calls = 0
    def embed(self, texts):
        self.calls += len(texts)
        return [[1.0, 0.5] for text in texts]
se._model = LocalModel()
se._model_name = se.MODEL_NAME
se.CACHE_PATH = Path(sys.argv[1])
for line in sys.stdin:
    result = se.cached_corpus_vectors({'a': 'sales', 'b': 'weather'}, dimension=2)
    print(json.dumps({'count': len(result), 'calls': se._model.calls,
                      'revision': se.embedding_identity()['revision']}), flush=True)
"""
    path = tmp_path / "skill_embeddings.json"
    workers = [subprocess.Popen([sys.executable, "-u", "-c", script, str(path)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True) for _ in range(2)]
    try:
        results = []
        for index in (0, 1, 0, 1):
            worker = workers[index]
            worker.stdin.write("query\n")
            worker.stdin.flush()
            results.append(json.loads(worker.stdout.readline()))
        assert [item["calls"] for item in results] == [2, 2, 2, 2]
        assert results[0]["revision"] != results[1]["revision"]
        assert all(item["count"] == 2 for item in results)
        assert not path.exists()
    finally:
        for worker in workers:
            worker.stdin.close()
        for worker in workers:
            try:
                worker.wait(timeout=30)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=10)
            worker.stdout.close()
            worker.stderr.close()


@pytest.fixture
def embedding_runtime(monkeypatch, tmp_path):
    identity = {"provider": "deterministic-test", "model": "fixture", "revision": "1"}
    calls = []

    def embed(texts):
        calls.append(list(texts))
        return [[1.0, 0.0] if "sales" in t else [0.0, 1.0] for t in texts]

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(se, "CACHE_PATH", tmp_path / "skill_embeddings.json")
    monkeypatch.setattr(se, "embedding_identity", lambda: dict(identity))
    monkeypatch.setattr(se, "_have_fastembed", lambda: True)
    monkeypatch.setattr(se, "embed", embed)
    monkeypatch.setattr("maverick.skills._decay_weights", lambda names: {})
    return identity, calls


def skill(tmp_path, body, name="shared"):
    path = tmp_path / (name + ".md")
    path.write_text(body)
    return Skill(name=name, triggers=[], tools_needed=[], body=body, path=path)


@pytest.mark.parametrize("mtime", [1, 1_700_000_000])
def test_changed_text_with_equal_or_older_mtime_is_reembedded(embedding_runtime, tmp_path, mtime):
    _, calls = embedding_runtime
    old = skill(tmp_path, "sales")
    os.utime(old.path, (1_700_000_000, 1_700_000_000))
    assert se.relevant_skills_embed("sales", [old]) == [old]
    replacement = skill(tmp_path, "weather")
    os.utime(replacement.path, (mtime, mtime))
    assert se.relevant_skills_embed("sales", [replacement]) == []
    assert calls[-1] == [se._skill_to_embed_text(replacement)]


def test_model_revision_change_and_dimension_change_rebuild(embedding_runtime, monkeypatch, tmp_path):
    identity, calls = embedding_runtime
    item = skill(tmp_path, "sales")
    assert se.relevant_skills_embed("sales", [item]) == [item]
    identity["revision"] = "2"
    assert se.relevant_skills_embed("sales", [item]) == [item]
    assert len(calls) == 4
    monkeypatch.setattr(se, "embed", lambda texts: [[1.0, 0.0, 0.0] for _ in texts])
    assert se.relevant_skills_embed("sales", [item]) == [item]
    raw = json.loads(se.CACHE_PATH.read_text())
    assert raw["entries"]["shared"]["dimension"] == 3


def test_catalog_warm_query_only_matches_fresh_ranking(embedding_runtime):
    _, calls = embedding_runtime
    entries = [("skill", SimpleNamespace(name=n, summary=s, source=n, version="1", sha256=n))
               for n, s in [("z", "sales"), ("a", "sales"), ("w", "weather")]]
    first = sl._rank_embed("sales", entries, 3)
    assert [c.name for c in first] == ["a", "z"]
    assert len(calls) == 2 and len(calls[1]) == 3
    assert sl._rank_embed("sales", list(reversed(entries)), 3) == first
    assert calls[2:] == [["sales"]]


def test_deletion_persisted_without_embedding_miss(embedding_runtime):
    _, calls = embedding_runtime
    se.cached_corpus_vectors({"a": "sales", "b": "weather"})
    before = len(calls)
    assert set(se.cached_corpus_vectors({"a": "sales"})) == {"a"}
    assert len(calls) == before
    assert set(json.loads(se.CACHE_PATH.read_text())["entries"]) == {"a"}


@pytest.mark.parametrize("bad", [None, [], [[1.0]], [[1.0, float("nan")], [1.0, 0.0]],
                                  [[True, 0.0], [1.0, 0.0]], [[0.0, 0.0], [1.0, 0.0]],
                                  [[1.0, 0.0], [1.0, 0.0, 0.0]]])
def test_incomplete_refresh_preserves_prior_cache(embedding_runtime, monkeypatch, bad):
    se.cached_corpus_vectors({"prior": "sales"})
    prior = se.CACHE_PATH.read_bytes()
    monkeypatch.setattr(se, "embed", lambda texts: bad)
    assert se.cached_corpus_vectors({"a": "sales", "b": "weather"}, dimension=2) is None
    assert se.CACHE_PATH.read_bytes() == prior


def test_model_switch_during_embedding_does_not_publish(embedding_runtime, monkeypatch):
    identity, _ = embedding_runtime

    def swapped(texts):
        identity["revision"] = "changed-in-flight"
        return [[1.0, 0.0] for _ in texts]

    monkeypatch.setattr(se, "embed", swapped)
    assert se.cached_corpus_vectors({"a": "sales"}) is None
    assert not se.CACHE_PATH.exists()


def test_corrupt_persisted_vector_is_rebuilt(embedding_runtime):
    _, calls = embedding_runtime
    se.cached_corpus_vectors({"a": "sales"})
    raw = json.loads(se.CACHE_PATH.read_text())
    raw["entries"]["a"]["vector"] = [float("nan"), 1.0]
    se.CACHE_PATH.write_text(json.dumps(raw))
    result = se.cached_corpus_vectors({"a": "sales"})
    assert result["a"].vector == [1.0, 0.0]
    assert len(calls) == 2


def test_batches_and_corpus_bounds(embedding_runtime):
    _, calls = embedding_runtime
    result = se.cached_corpus_vectors({str(i): "sales" for i in range(130)})
    assert len(result) == 130
    assert list(map(len, calls)) == [64, 64, 2]
    assert se.cached_corpus_vectors({str(i): "sales" for i in range(2049)}) is None
    assert se.cached_corpus_vectors({"a": "x" * 8193}) is None


def test_simultaneous_refreshes_return_their_exact_snapshot(embedding_runtime):
    barrier = threading.Barrier(2)

    def run(text):
        barrier.wait(timeout=5)
        return se.cached_corpus_vectors({"same": text})["same"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        sales, weather = list(pool.map(run, ["sales", "weather"]))
    assert (sales.text, sales.vector) == ("sales", [1.0, 0.0])
    assert (weather.text, weather.vector) == ("weather", [0.0, 1.0])
    entry = json.loads(se.CACHE_PATH.read_text())["entries"]["same"]
    assert entry["vector"] == ([1.0, 0.0] if entry["text"] == "sales" else [0.0, 1.0])


def test_tenant_collision_cache_stays_separate(embedding_runtime):
    paths = []
    for tenant, text in [("acme-1", "sales"), ("acme_1", "weather")]:
        token = set_tenant(tenant)
        try:
            se.cached_corpus_vectors({"same": text})
            paths.append(se._cache_path())
        finally:
            reset_tenant(token)
    assert paths[0] != paths[1]
    assert json.loads(paths[0].read_text())["entries"]["same"]["vector"] == [1.0, 0.0]
    assert json.loads(paths[1].read_text())["entries"]["same"]["vector"] == [0.0, 1.0]


def test_finite_large_cosine_is_stable():
    assert se._cosine([1e308, 1e308], [1e308, 1e308]) == pytest.approx(1.0)
    assert se._cosine([float("nan"), 1.0], [1.0, 1.0]) == 0.0


def test_actual_loaded_model_identity_invalidates_on_reload(monkeypatch):
    models = []

    def model(model_name):
        instance = SimpleNamespace(name=model_name)
        models.append(instance)
        return instance

    monkeypatch.setitem(sys.modules, "fastembed", SimpleNamespace(TextEmbedding=model))
    monkeypatch.setattr(se, "_model", None)
    monkeypatch.setattr(se, "_model_name", None)
    first = se.embedding_identity()
    assert se.embedding_identity() == first
    monkeypatch.setattr(se, "MODEL_NAME", "fixture-model-change")
    second = se.embedding_identity()
    assert first["model"] != second["model"]
    assert first["revision"] != second["revision"]
    assert len(models) == 2
    # A loaded model with an attested weights revision may opt into durable reuse.
    models[-1].cache_revision = "attested-fixture-revision"
    assert se.embedding_identity()["revision"] == "attested-fixture-revision"


def test_purpose_and_outcome_weights_survive_warm_cache(embedding_runtime, monkeypatch, tmp_path):
    from maverick.access_policy import purpose_scope
    from maverick.skills import relevant_skills

    unrestricted = skill(tmp_path, "sales", "a")
    governed = skill(tmp_path, "sales", "z")
    governed.purposes = ("audit",)
    monkeypatch.setattr("maverick.skills._decay_weights", lambda names: {"a": 0.1, "z": 1.0})
    assert relevant_skills("sales", [unrestricted, governed]) == [unrestricted]
    with purpose_scope("audit"):
        assert relevant_skills("sales", [unrestricted, governed]) == [governed, unrestricted]
        assert relevant_skills("sales", [unrestricted, governed]) == [governed, unrestricted]
    with purpose_scope("marketing"):
        assert relevant_skills("sales", [unrestricted, governed]) == [unrestricted]
