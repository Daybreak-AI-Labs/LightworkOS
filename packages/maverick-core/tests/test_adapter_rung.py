"""Tests for maverick.adapter_rung -- the governed weights (adapter) rung."""
from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick import adapter_rung as ar
from maverick.self_harness_eval import corpus_split

_TEST_GLOBAL_APPROVER_KEYS: list[str] = []


@pytest.fixture(autouse=True)
def _reset_adapter_caches(monkeypatch):
    """The config/pointer memo caches are module-global; clear them around each
    test so mtime-keyed entries never leak across the isolated per-test HOMEs."""
    from maverick import approval_signing

    _TEST_GLOBAL_APPROVER_KEYS.clear()
    monkeypatch.setattr(
        approval_signing,
        "trusted_global_approver_keys",
        lambda: list(_TEST_GLOBAL_APPROVER_KEYS),
    )
    ar._reset_caches()
    yield
    ar._reset_caches()
    _TEST_GLOBAL_APPROVER_KEYS.clear()


def _examples() -> list[ar.TrainExample]:
    return [
        ar.TrainExample("p1", "good", "bad", provenance="human_correction"),
        ar.TrainExample("p2", "good", "bad", provenance="tenant_trace"),
        ar.TrainExample("p3", "good", "bad", provenance="human_example"),
    ]


# --- provenance boundary ---------------------------------------------------------

def test_screen_refuses_model_output_by_default():
    review = ar.screen_examples(_examples() + [
        ar.TrainExample("p", "c", provenance="model_output")])
    assert review.ok
    assert len(review.kept) == 3
    assert any("model_output" in r for r in review.refused)


def test_screen_model_output_needs_explicit_opt_in():
    review = ar.screen_examples(
        [ar.TrainExample("p", "c", provenance="model_output")],
        allow_model_output=True)
    assert review.ok and len(review.kept) == 1
    assert review.provenance_counts == {"model_output": 1}


def test_screen_refuses_synthetic_by_default_and_unknown_always():
    review = ar.screen_examples([
        ar.TrainExample("p", "c", provenance="synthetic"),
        ar.TrainExample("p", "c", provenance="scraped"),
    ], allow_synthetic=False)
    assert not review.ok and not review.kept and len(review.refused) == 2
    # Unknown provenance is refused even with every opt-in flag raised.
    review2 = ar.screen_examples(
        [ar.TrainExample("p", "c", provenance="scraped")],
        allow_synthetic=True, allow_model_output=True)
    assert not review2.ok


def test_dataset_digest_is_order_independent():
    a, b, c = _examples()
    d1 = ar.screen_examples([a, b, c]).dataset_sha256
    d2 = ar.screen_examples([c, a, b]).dataset_sha256
    assert d1 == d2 and len(d1) == 64


# --- payload hygiene -------------------------------------------------------------

def test_payload_refuses_code_and_pickle_formats(tmp_path):
    d = tmp_path / "adapter"
    d.mkdir()
    (d / "adapter.safetensors").write_bytes(b"x")
    (d / "post_init.py").write_text("import os\n", encoding="utf-8")
    (d / "weights.bin").write_bytes(b"\x80\x04")  # torch pickle container
    review = ar.review_adapter_payload(d)
    assert not review.ok
    assert set(review.refused) == {"post_init.py", "weights.bin"}


def test_payload_refuses_symlink_and_empty(tmp_path):
    d = tmp_path / "adapter"
    d.mkdir()
    assert not ar.review_adapter_payload(d).ok  # empty
    outside = tmp_path / "outside.safetensors"
    outside.write_bytes(b"x")
    try:
        (d / "adapter.safetensors").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")
    review = ar.review_adapter_payload(d)
    assert not review.ok and "symlink" in review.reason


def test_payload_digest_tracks_bytes(tmp_path):
    d = tmp_path / "adapter"
    d.mkdir()
    f = d / "adapter.safetensors"
    f.write_bytes(b"aaa")
    d1 = ar.payload_digest_dir(d)
    f.write_bytes(b"bbb")
    assert ar.payload_digest_dir(d) != d1


def test_payload_digest_streams_without_path_read_bytes(tmp_path, monkeypatch):
    d = tmp_path / "adapter"
    d.mkdir()
    (d / "adapter.safetensors").write_bytes(b"stream-me-in-small-chunks")
    monkeypatch.setattr(ar, "ADAPTER_IO_CHUNK_BYTES", 3)

    def explode(_path):
        raise AssertionError("security digest must not allocate an entire weight file")

    monkeypatch.setattr(Path, "read_bytes", explode)
    assert len(ar.payload_digest_dir(d)) == 64


def test_payload_review_enforces_file_count_and_byte_ceilings(tmp_path, monkeypatch):
    d = tmp_path / "adapter"
    d.mkdir()
    (d / "adapter.safetensors").write_bytes(b"abc")
    (d / "adapter_config.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(ar, "MAX_ADAPTER_FILES", 1)
    review = ar.review_adapter_payload(d)
    assert not review.ok and "exceeds 1 files" in review.reason

    monkeypatch.setattr(ar, "MAX_ADAPTER_FILES", 10)
    monkeypatch.setattr(ar, "MAX_ADAPTER_FILE_BYTES", 2)
    review = ar.review_adapter_payload(d)
    assert not review.ok and "file exceeds 2 bytes" in review.reason


# --- manifest + trainers ---------------------------------------------------------

def test_stub_trainer_is_deterministic_and_manifest_roundtrips(tmp_path):
    review = ar.screen_examples(_examples())
    m1 = ar.get_trainer("stub").train(review, "ollama:some-base", tmp_path / "a")
    m2 = ar.get_trainer("stub").train(review, "ollama:some-base", tmp_path / "b")
    assert (tmp_path / "a" / "adapter.safetensors").read_bytes() == \
           (tmp_path / "b" / "adapter.safetensors").read_bytes()
    loaded = ar.AdapterManifest.load(tmp_path / "a")
    assert loaded.adapter_id == m1.adapter_id
    assert loaded.base_model == "ollama:some-base"
    assert loaded.dataset_sha256 == review.dataset_sha256
    assert loaded.examples == 3 and loaded.trainer == "stub"
    assert loaded.payload_sha256 == ar.payload_digest_dir(tmp_path / "a")
    assert m1.adapter_id != m2.adapter_id  # identity is per-training-run


def test_trainer_registry():
    assert isinstance(ar.get_trainer("stub"), ar.StubTrainer)
    assert isinstance(ar.get_trainer("dpo-lora"), ar.DpoLoraTrainer)
    with pytest.raises(ValueError, match="unknown adapter trainer"):
        ar.get_trainer("full-finetune")


# --- held-out fitness ------------------------------------------------------------

def _cases(n: int = 64) -> list[str]:
    return [f"case-{i:03d}" for i in range(n)]


def _base_pass(case: str) -> bool:
    return int(case.split("-")[1]) % 2 == 0


def test_evaluate_adapter_genuine_uplift():
    def scorer(ref, ids):
        if "+adapter:" in ref:
            return dict.fromkeys(ids, True)
        return {c: _base_pass(c) for c in ids}

    res = ar.evaluate_adapter("ollama:b", "ollama:b+adapter:x", _cases(),
                              score_fn=scorer)
    assert res.ok and not res.overfit
    assert res.candidate_score > res.baseline_score
    assert res.samples >= 20


def test_evaluate_adapter_flags_memoriser_as_overfit():
    held_in, _ = corpus_split([{"goal": c} for c in _cases()], held_out_frac=0.35)
    seen = set(held_in)

    def scorer(ref, ids):
        if "+adapter:" in ref:
            return {c: (c in seen) or _base_pass(c) for c in ids}
        return {c: _base_pass(c) for c in ids}

    res = ar.evaluate_adapter("ollama:b", "ollama:b+adapter:x", _cases(),
                              score_fn=scorer)
    assert not res.ok and res.overfit and "OVERFIT" in res.reason


def test_evaluate_adapter_needs_cases():
    res = ar.evaluate_adapter("b", "b+adapter:x", ["only-one"],
                              score_fn=lambda ref, ids: {})
    assert not res.ok and "held-out" in res.reason


# --- store: activation pointer + rollback ----------------------------------------

def _manifest(tmp_path, name="a") -> ar.AdapterManifest:
    review = ar.screen_examples(_examples())
    return ar.get_trainer("stub").train(review, "ollama:some-base", tmp_path / name)


def test_store_activate_archives_previous_and_rollback_restores(tmp_path):
    store = ar.AdapterStore(root=tmp_path / "store")
    m_a, m_b = _manifest(tmp_path, "a"), _manifest(tmp_path, "b")
    store.activate(m_a, record_id="rec-a")
    bytes_a = (tmp_path / "store" / ar.ACTIVE_BASENAME).read_bytes()
    store.activate(m_b, record_id="rec-b")
    assert store.active()["adapter_id"] == m_b.adapter_id
    assert store.previous()["adapter_id"] == m_a.adapter_id
    restored = store.rollback()
    assert restored["adapter_id"] == m_a.adapter_id
    assert (tmp_path / "store" / ar.ACTIVE_BASENAME).read_bytes() == bytes_a
    assert store.previous() is None  # one-step: the handle is consumed


def test_store_rollback_without_previous_deactivates(tmp_path):
    store = ar.AdapterStore(root=tmp_path / "store")
    store.activate(_manifest(tmp_path), record_id="rec-a")
    assert store.rollback() is None
    assert store.active() is None


def test_store_survives_corrupt_pointer(tmp_path):
    store = ar.AdapterStore(root=tmp_path / "store")
    (tmp_path / "store").mkdir()
    (tmp_path / "store" / ar.ACTIVE_BASENAME).write_text("{not json", encoding="utf-8")
    assert store.active() is None


def test_single_tenant_legacy_pointer_migrates_without_behavior_change(tmp_path):
    root = tmp_path / "store"
    root.mkdir()
    legacy = {
        "adapter_id": "legacy-adapter",
        "base_model": "ollama:some-base",
        "payload_sha256": "a" * 64,
        "promotion_record_id": "legacy-record",
        "activated_at": 123.0,
    }
    ar._atomic_write_json(root / ar.ACTIVE_BASENAME, legacy)
    store = ar.AdapterStore(root=root)
    assert store.active() == legacy

    store.activate(_manifest(tmp_path, "new"), record_id="new-record")
    assert store.previous() == legacy
    assert store.rollback() == legacy
    assert store.active() == legacy
    assert (root / ar.POINTER_STATE_BASENAME).exists()


def test_default_store_isolates_two_tenants_under_concurrency(tmp_path, monkeypatch):
    import maverick.config as config
    from maverick.paths import tenant_scope

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(config, "get_adapter_rung", lambda: {
        "enable": True, "base_model": "ollama:some-base", "store_dir": None,
        "trainer": "stub", "allow_synthetic": False, "allow_model_output": False,
    })
    barrier = threading.Barrier(2)

    def activate_for(tenant: str):
        with tenant_scope(tenant=tenant):
            manifest = _manifest(tmp_path / "payloads", tenant)
            store = ar.AdapterStore()
            barrier.wait(timeout=5)
            store.activate(manifest, record_id=f"rec-{tenant}")
            return store.root, store.active(), manifest

    with ThreadPoolExecutor(max_workers=2) as pool:
        alpha_f = pool.submit(activate_for, "alpha")
        beta_f = pool.submit(activate_for, "beta")
        alpha = alpha_f.result(timeout=10)
        beta = beta_f.result(timeout=10)

    assert alpha[0] != beta[0]
    assert alpha[0] == tmp_path / "home" / "tenants" / "alpha" / "adapters"
    assert beta[0] == tmp_path / "home" / "tenants" / "beta" / "adapters"
    assert alpha[1]["tenant_id"] == alpha[2].tenant_id == "alpha"
    assert beta[1]["tenant_id"] == beta[2].tenant_id == "beta"
    assert alpha[1]["authority"] == beta[1]["authority"] == "dev-unbound"
    ar._reset_caches()
    with tenant_scope(tenant="alpha"):
        assert ar.effective_wire_model("ollama", "some-base") == "some-base"
    with tenant_scope(tenant="beta"):
        assert ar.effective_wire_model("ollama", "some-base") == "some-base"
    # Tenant tags prevent two clients with the same adapter id from colliding
    # in a shared local serving registry.
    beta[2].adapter_id = alpha[2].adapter_id
    assert ar.tuned_model_name(alpha[2]) != ar.tuned_model_name(beta[2])


def test_explicit_shared_root_refuses_cross_tenant_pointer_overwrite(tmp_path):
    from maverick.paths import tenant_scope

    root = tmp_path / "operator-store"
    with tenant_scope(tenant="alpha"):
        alpha = _manifest(tmp_path / "payloads", "alpha")
        ar.AdapterStore(root=root).activate(alpha, record_id="rec-alpha")
    with tenant_scope(tenant="beta"):
        beta = _manifest(tmp_path / "payloads", "beta")
        with pytest.raises(ValueError, match="another tenant|tenant mismatch"):
            ar.AdapterStore(root=root).activate(beta, record_id="rec-beta")
    with tenant_scope(tenant="alpha"):
        assert ar.AdapterStore(root=root).active()["promotion_record_id"] == "rec-alpha"


def test_activation_pointer_swap_rejects_a_stale_concurrent_plan(tmp_path):
    store = ar.AdapterStore(root=tmp_path / "store")
    first = store.plan_activation(_manifest(tmp_path, "a"), record_id="rec-a")
    stale = store.plan_activation(_manifest(tmp_path, "b"), record_id="rec-b")

    store.apply_activation(first)
    with pytest.raises(RuntimeError, match="CAS conflict"):
        store.apply_activation(stale)
    assert store.active()["promotion_record_id"] == "rec-a"


def test_two_governed_writers_serialize_full_prepare_to_commit(tmp_path):
    from maverick.self_improvement import PromotionLedger, SelfImprovementController

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    controller = SelfImprovementController(
        ledger=ledger, approval_verifier=verifier)
    store = ar.AdapterStore(root=tmp_path / "store")
    _manifest(tmp_path, "a")
    _manifest(tmp_path, "b")
    barrier = threading.Barrier(2)

    def promote(name):
        barrier.wait(timeout=5)
        return ar.govern_adapter_change(
            tmp_path / name, _cases(), score_fn=_genuine_scorer,
            approve=approve, controller=controller, store=store,
            approval_public_keys=public_keys,
            serving_provisioner=_fake_serving_provisioner)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(promote, "a")
        second = pool.submit(promote, "b")
        results = [first.result(timeout=15), second.result(timeout=15)]
    assert all(result.promoted for result in results), [result.reason for result in results]
    assert ledger.transactions(state="prepared") == []
    assert len(ledger.transactions(state="committed")) == 2
    with store.transaction_locked():
        state = store._read_state_locked(verify_serving=True)
    assert state.active is not None and state.previous is not None


# --- serving seam ----------------------------------------------------------------

def test_tuned_model_name_is_tag_safe(tmp_path):
    m = _manifest(tmp_path)
    m.base_model = "ollama:family3:14b"
    name = ar.tuned_model_name(m)
    assert ":" not in name and name.startswith("family3-14b-lw-")


def test_tuned_model_name_identity_resists_lossy_slug_and_prefix_collisions(tmp_path):
    first = _manifest(tmp_path, "a")
    second = _manifest(tmp_path, "b")
    first.adapter_id = "shared-prefix-0000000000000001"
    second.adapter_id = "shared-prefix-0000000000000002"
    assert first.payload_sha256 == second.payload_sha256
    assert ar.tuned_model_name(first) != ar.tuned_model_name(second)

    # These base ids collapse to the same human-readable slug.  The identity
    # suffix must still bind the original, unmodified model specification.
    second.adapter_id = first.adapter_id
    first.base_model = "ollama:foo/bar"
    second.base_model = "ollama:foo-bar"
    assert ar.tuned_model_name(first).split("-lw-", 1)[0] == \
        ar.tuned_model_name(second).split("-lw-", 1)[0]
    assert ar.tuned_model_name(first) != ar.tuned_model_name(second)


def test_manifest_identity_rejects_command_and_path_injection(tmp_path):
    manifest = _manifest(tmp_path)
    manifest.base_model = "ollama:safe\nPARAMETER stop never"
    with pytest.raises(ValueError, match="base_model"):
        ar.tuned_model_name(manifest)
    with pytest.raises(ValueError, match="base_model"):
        manifest.save(tmp_path / "a")

    manifest.base_model = "ollama:safe"
    manifest.adapter_id = "../tenant-escape"
    with pytest.raises(ValueError, match="adapter_id"):
        manifest.save(tmp_path / "a")


def test_modelfile_and_serving_artifacts(tmp_path):
    m = _manifest(tmp_path, "a")
    serving = ar.emit_serving_artifacts(m, tmp_path / "a")
    text = Path(serving["modelfile"]).read_text(encoding="utf-8")
    assert "FROM some-base" in text
    assert f"ADAPTER {(tmp_path / 'a').resolve()}" in text
    assert serving["create_command"].startswith(
        f"ollama create {ar.tuned_model_name(m)} -f ")
    # The rendered Modelfile itself stays inside the hygiene allowlist.
    assert ar.review_adapter_payload(tmp_path / "a").ok


def test_default_ollama_provisioner_replaces_poisoned_preexisting_alias(
    tmp_path, monkeypatch,
):
    store = ar.AdapterStore(root=tmp_path / "store")
    source = tmp_path / "source"
    manifest = _manifest(source.parent, source.name)
    staged, manifest = store.stage_payload(source, manifest)
    binding = ar._serving_binding(manifest, staged)
    ar.emit_serving_artifacts(manifest, staged, binding=binding)
    final_name = binding["model_name"]
    good_digest, poison_digest = "1" * 64, "2" * 64
    installed = {final_name: poison_digest}
    commands: list[tuple[str, ...]] = []

    def fake_run(argv, *, required=True):
        commands.append(tuple(argv))
        operation = argv[1]
        if operation == "create":
            installed[argv[2]] = good_digest
        elif operation == "rm":
            installed.pop(argv[2], None)
        return True

    def fake_copy(source_name, destination_name):
        commands.append(("api", "copy", source_name, destination_name))
        installed[destination_name] = installed[source_name]

    monkeypatch.setattr(ar, "_run_ollama", fake_run)
    monkeypatch.setattr(ar, "_ollama_model_digest", installed.get)
    monkeypatch.setattr(ar, "_ollama_copy_model", fake_copy)
    attestation = ar._ollama_install_and_verify(binding)

    assert attestation["model_digest"] == good_digest
    assert installed[final_name] == good_digest
    assert ("ollama", "rm", final_name) in commands
    assert any(command[1] == "copy" for command in commands)


def test_approver_refusal_never_mutates_live_ollama_alias_or_pointer(
    tmp_path, monkeypatch,
):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    _, verifier, public_keys = _external_approval(keydir)
    manifest = _manifest(tmp_path)
    final_name = ar.tuned_model_name(manifest)
    good_digest, incumbent_digest = "1" * 64, "2" * 64
    installed = {final_name: incumbent_digest}
    commands: list[tuple[str, ...]] = []

    def fake_run(argv, *, required=True):
        commands.append(tuple(argv))
        if argv[1] == "create":
            installed[argv[2]] = good_digest
        elif argv[1] == "rm":
            installed.pop(argv[2], None)
        return True

    def fake_copy(source_name, destination_name):
        commands.append(("api", "copy", source_name, destination_name))
        installed[destination_name] = installed[source_name]

    monkeypatch.setattr(ar, "_run_ollama", fake_run)
    monkeypatch.setattr(ar, "_ollama_model_digest", installed.get)
    monkeypatch.setattr(ar, "_ollama_copy_model", fake_copy)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")

    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=lambda _request: None, approval_verifier=verifier,
        approval_public_keys=public_keys, ledger=ledger, store=store)

    assert not refused.promoted and "approval" in refused.reason
    assert installed == {final_name: incumbent_digest}
    assert store.active() is None and ledger.transactions() == []
    assert ("ollama", "rm", final_name) not in commands
    assert not any(command[:2] == ("api", "copy") for command in commands)


def _enable_cfg(monkeypatch, tmp_path, **over):
    import maverick.config as config
    cfg = {"enable": True, "base_model": "ollama:some-base",
           "store_dir": str(tmp_path / "store"), "trainer": "stub",
           "allow_synthetic": False, "allow_model_output": False, **over}
    monkeypatch.setattr(config, "get_adapter_rung", lambda: cfg)
    return cfg


def test_effective_model_spec_disabled_is_identity(tmp_path, monkeypatch):
    _enable_cfg(monkeypatch, tmp_path, enable=False)
    assert ar.effective_model_spec("ollama:some-base") == "ollama:some-base"


def test_low_level_and_legacy_pointer_cannot_reroute_provider(tmp_path, monkeypatch):
    _enable_cfg(monkeypatch, tmp_path)
    store = ar.AdapterStore(root=tmp_path / "store")
    store.activate(_manifest(tmp_path), record_id="dev-record")
    assert store.active()["authority"] == "dev-unbound"
    assert ar._cached_active_pointer(store.root) is None
    assert ar.effective_wire_model("ollama", "some-base") == "some-base"


def test_effective_model_spec_rewrites_only_matching_base(tmp_path, monkeypatch):
    _enable_cfg(monkeypatch, tmp_path)
    _store, m, _result, _ledger = _promote_for_serving(tmp_path, monkeypatch)
    assert ar.effective_model_spec("ollama:some-base") == \
           f"ollama:{ar.tuned_model_name(m)}"
    assert ar.effective_model_spec("ollama:other") == "ollama:other"
    assert ar.effective_model_spec("anthropic:some-base") == "anthropic:some-base"


def test_parse_spec_stays_pure_even_with_active_adapter(tmp_path, monkeypatch):
    # The rewrite lives in the PROVIDER client, not the parser: _parse_spec must
    # return the base id byte-identically so allow-lists, pricing, and metrics
    # key on the stable base (the code-review layering/cardinality findings).
    from maverick.llm import _parse_spec
    _enable_cfg(monkeypatch, tmp_path)
    store = ar.AdapterStore(root=tmp_path / "store")
    m = _manifest(tmp_path)
    store.activate(m, record_id="rec-a")
    assert _parse_spec("ollama:some-base") == ("ollama", "some-base")
    assert _parse_spec("ollama:untouched") == ("ollama", "untouched")


def test_ollama_client_resolves_adapter_at_wire_time(tmp_path, monkeypatch):
    # The wire-level seam: OllamaClient._build_kwargs swaps base -> tuned name
    # when (and only when) the rung is enabled with a matching active pointer.
    pytest.importorskip("openai")  # OllamaClient rides the OpenAI-compatible client
    from maverick.providers.ollama_provider import OllamaClient

    _enable_cfg(monkeypatch, tmp_path)
    _store, m, _result, _ledger = _promote_for_serving(tmp_path, monkeypatch)
    client = OllamaClient()
    kw = client._build_kwargs("sys", [{"role": "user", "content": "hi"}],
                              None, 64, "some-base")
    assert kw["model"] == ar.tuned_model_name(m)
    # Non-matching base and disabled rung both serve the base unchanged.
    kw2 = client._build_kwargs("sys", [{"role": "user", "content": "hi"}],
                               None, 64, "other-model")
    assert kw2["model"] == "other-model"
    _enable_cfg(monkeypatch, tmp_path, enable=False)
    ar._reset_caches()
    kw3 = client._build_kwargs("sys", [{"role": "user", "content": "hi"}],
                               None, 64, "some-base")
    assert kw3["model"] == "some-base"


def test_effective_wire_model_matches_local_alias(tmp_path, monkeypatch):
    # 'local' is a registry alias for ollama; a pointer recorded under either
    # provider spelling must resolve for both.
    _enable_cfg(monkeypatch, tmp_path)
    _store, m, _result, _ledger = _promote_for_serving(tmp_path, monkeypatch)
    assert ar.effective_wire_model("local", "some-base") == ar.tuned_model_name(m)
    assert ar.effective_wire_model("vllm", "some-base") == "some-base"
    assert ar.effective_wire_model("anthropic", "some-base") == "some-base"


def test_serving_cache_evicts_pointer_when_staged_weights_are_tampered(
    tmp_path, monkeypatch,
):
    store, _manifest_value, result, _ledger = _promote_for_serving(
        tmp_path, monkeypatch)
    staged_dir = Path(result.pointer["serving"]["adapter_dir"])

    ar._reset_caches()
    assert ar._cached_active_pointer(store.root) is not None
    weight = next(staged_dir.rglob("*.safetensors"))
    os.chmod(weight, 0o600)
    weight.write_bytes(b"tampered-after-cache")

    assert ar._cached_active_pointer(store.root) is None


def test_serving_cache_hit_does_not_reread_weight_bytes(tmp_path, monkeypatch):
    store, _manifest_value, _result, _ledger = _promote_for_serving(
        tmp_path, monkeypatch)

    ar._reset_caches()
    assert ar._cached_active_pointer(store.root) is not None  # strict full verify

    def explode(*_args, **_kwargs):
        raise AssertionError("stable cache hit re-read adapter weight bytes")

    monkeypatch.setattr(ar, "_stream_payload_file", explode)
    assert ar._cached_active_pointer(store.root) is not None


def test_hot_path_stops_routing_when_durable_receipt_is_rolled_back(
    tmp_path, monkeypatch,
):
    _enable_cfg(monkeypatch, tmp_path)
    _store, manifest, result, ledger = _promote_for_serving(tmp_path, monkeypatch)
    assert ar.effective_wire_model("ollama", "some-base") == \
        ar.tuned_model_name(manifest)

    # Simulate receipt revocation before pointer cleanup.  The journal stat
    # changes, so even a primed hot-path cache must re-check authority.
    ledger.mark_rolled_back(result.candidate_id, at=456.0)
    assert ar.effective_wire_model("ollama", "some-base") == "some-base"


def test_hot_path_rejects_immediate_post_cache_ollama_alias_replacement(
    tmp_path, monkeypatch,
):
    _enable_cfg(monkeypatch, tmp_path)
    _store, manifest, result, _ledger = _promote_for_serving(tmp_path, monkeypatch)
    serving = result.pointer["serving"]
    name = serving["model_name"]
    installed = {name: serving["deployment"]["model_digest"]}
    monkeypatch.setattr(ar, "_ollama_model_digest", installed.get)

    assert ar.effective_wire_model("ollama", "some-base") == \
        ar.tuned_model_name(manifest)
    installed[name] = "f" * 64  # swap immediately; do not advance time
    assert ar.effective_wire_model("ollama", "some-base") == "some-base"


def test_committed_receipt_cannot_authorize_swapped_self_consistent_pointer_files(
    tmp_path, monkeypatch,
):
    store, _manifest_value, result, _ledger = _promote_for_serving(
        tmp_path, monkeypatch)
    second = _manifest(tmp_path, "b")
    weight = tmp_path / "b" / "adapter.safetensors"
    weight.write_bytes(b"different-immutable-adapter-weights")
    second.payload_sha256 = ar.payload_digest_dir(tmp_path / "b")
    second.save(tmp_path / "b")
    staged, second = store.stage_payload(tmp_path / "b", second)
    binding = ar._serving_binding(second, staged)
    ar.emit_serving_artifacts(second, staged, binding=binding)
    binding = {**binding, "deployment": _fake_serving_provisioner(binding)}

    swapped = json.loads(json.dumps(result.pointer))
    swapped.update({
        "adapter_id": second.adapter_id,
        "base_model": second.base_model,
        "dataset_sha256": second.dataset_sha256,
        "payload_sha256": second.payload_sha256,
        "serving": binding,
    })
    with store.transaction_locked():
        state = store._read_state_locked(verify_serving=True)
        store._write_state_locked(ar._PointerState(
            active=swapped, previous=state.previous,
            pending_rollback=state.pending_rollback))

    monkeypatch.setattr(
        ar, "_ollama_model_digest",
        lambda name: binding["deployment"]["model_digest"]
        if name == binding["model_name"] else None)
    with pytest.raises(ValueError, match="exact approved serving payload"):
        ar._verify_authoritative_pointer(
            swapped, artifact_identity=store.artifact_identity)
    ar._reset_caches()
    assert ar._cached_active_pointer(store.root) is None


def test_committed_receipt_cannot_redirect_to_a_copied_ledger(
    tmp_path, monkeypatch,
):
    store, _manifest_value, result, ledger = _promote_for_serving(
        tmp_path, monkeypatch)
    copied = tmp_path / "copied-ledger.json"
    copied.write_bytes(ledger.path.read_bytes())
    source_journal = Path(f"{ledger.path}.journal")
    if source_journal.exists():
        Path(f"{copied}.journal").write_bytes(source_journal.read_bytes())
    redirected = json.loads(json.dumps(result.pointer))
    redirected["receipt"]["ledger_path"] = str(copied.resolve())

    with pytest.raises(ValueError, match="exact approved serving payload"):
        ar._verify_authoritative_pointer(
            redirected, artifact_identity=store.artifact_identity)


# --- config defaults ---------------------------------------------------------------

def test_get_adapter_rung_defaults(monkeypatch):
    import maverick.config as config
    monkeypatch.setattr(config, "load_config", lambda path=None: {})
    assert config.get_adapter_rung() == {
        "enable": False, "base_model": None, "store_dir": None,
        "trainer": "stub", "allow_synthetic": False, "allow_model_output": False,
    }


def test_get_adapter_rung_rejects_truthy_string_booleans(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"adapter_rung": {
        "enable": "false",
        "allow_synthetic": "false",
        "allow_model_output": "true",
    }})

    settings = config.get_adapter_rung()
    assert settings["enable"] is False
    assert settings["allow_synthetic"] is False
    assert settings["allow_model_output"] is False


# --- the governed decision ---------------------------------------------------------

def _keys(tmp_path) -> Path:
    cryptography = pytest.importorskip("cryptography")  # noqa: F841
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    keydir = tmp_path / "keys"
    keydir.mkdir()
    (keydir / "operator.priv.hex").write_text(priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex(), encoding="utf-8")
    (keydir / "operator.pub").write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return keydir


def _external_approval(keydir: Path):
    """Test stand-in for a signer that lives outside the agent process."""
    from maverick import approval_signing as signing

    private_hex = (keydir / "operator.priv.hex").read_text(encoding="utf-8").strip()
    public_hex = (keydir / "operator.pub").read_bytes().hex()
    if public_hex not in _TEST_GLOBAL_APPROVER_KEYS:
        _TEST_GLOBAL_APPROVER_KEYS.append(public_hex)

    def approve(request):
        return signing.sign_request(request, private_hex)

    def verify(candidate):
        signature = getattr(candidate, "approval_signature", None)
        if not signature:
            return None
        return signing.verify(
            signing.ApprovalRequest.for_candidate(candidate),
            str(signature), [public_hex])

    return approve, verify, [public_hex]


def _fake_serving_provisioner(binding: dict) -> dict:
    """Deterministic stand-in for an independently inspected Ollama install."""
    import hashlib
    digest = hashlib.sha256(json.dumps({
        "model_name": binding["model_name"],
        "modelfile_sha256": binding["modelfile_sha256"],
    }, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "version": 1,
        "provider": "ollama",
        "verified": True,
        "model_name": binding["model_name"],
        "model_digest": digest,
        "source_modelfile_sha256": binding["modelfile_sha256"],
        "verified_at": 123.0,
    }


def _promote_for_serving(tmp_path, monkeypatch):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    manifest = _manifest(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")
    result = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=approve, approval_verifier=verifier,
        approval_public_keys=public_keys,
        serving_provisioner=_fake_serving_provisioner,
        ledger=ledger, store=store)
    assert result.promoted, result.reason
    assert result.pointer["authority"] == "governed-v1"
    assert result.pointer["serving"]["deployment"]["verified"] is True
    deployment_digest = result.pointer["serving"]["deployment"]["model_digest"]
    monkeypatch.setattr(ar, "_ollama_model_digest", lambda _name: deployment_digest)
    return store, manifest, result, ledger


def _genuine_scorer(ref, ids):
    if "+adapter:" in ref:
        return dict.fromkeys(ids, True)
    return {c: _base_pass(c) for c in ids}


def test_govern_adapter_change_promotes_and_activates(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")
    m = _manifest(tmp_path)
    res = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=approve, approval_verifier=verifier,
        approval_public_keys=public_keys,
        serving_provisioner=_fake_serving_provisioner,
        ledger=ledger, store=store)
    assert res.hygiene_ok and res.promoted, res.reason
    assert res.fitness.samples >= 20
    assert store.active()["adapter_id"] == m.adapter_id
    assert store.active()["promotion_record_id"] == res.candidate_id
    rec = ledger.get(res.candidate_id)
    assert rec is not None and rec.rung == "weights"
    # The canonical approved payload binds every routed field, including the
    # immutable store identity and complete serving/deployment attestation.
    import hashlib
    approved_payload = res.pointer["receipt"]["approved_payload"]
    approved = json.loads(approved_payload)
    assert approved["artifact_identity"] == store.artifact_identity
    assert approved["ledger_path"] == str(ledger.path.resolve())
    assert approved["pointer"] == {
        key: res.pointer[key]
        for key in (
            "authority", "tenant_id", "promotion_record_id", "adapter_id",
            "base_model", "dataset_sha256", "payload_sha256", "serving")
    }
    assert rec.approval_signature and rec.payload_sha256 == \
        hashlib.sha256(approved_payload.encode("utf-8")).hexdigest()
    assert res.pointer["receipt"]["version"] == 3
    assert "approval_key_id" in res.pointer["receipt"]
    assert "approval_pubkey" not in res.pointer["receipt"]
    # Serving artifacts point at the tuned model.
    assert ar.tuned_model_name(m) in res.serving["create_command"]


def test_live_pointer_refuses_self_nominated_or_revoked_approver_root(
    tmp_path,
    monkeypatch,
):
    store, _manifest_value, result, _ledger = _promote_for_serving(
        tmp_path,
        monkeypatch,
    )
    assert _TEST_GLOBAL_APPROVER_KEYS
    _TEST_GLOBAL_APPROVER_KEYS.clear()

    with pytest.raises(ValueError, match="server-trusted|trust registry"):
        ar._verify_authoritative_pointer(
            result.pointer,
            artifact_identity=store.artifact_identity,
        )


def test_external_approval_promotes_without_private_key_or_env_mutation(
    tmp_path, monkeypatch,
):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")
    _manifest(tmp_path)
    monkeypatch.delenv("MAVERICK_APPROVER_KEYS_DIR", raising=False)
    monkeypatch.delenv("MAVERICK_SELF_IMPROVEMENT", raising=False)

    promoted = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=approve, approval_verifier=verifier,
        approval_public_keys=public_keys,
        serving_provisioner=_fake_serving_provisioner,
        ledger=ledger, store=store)

    assert promoted.promoted, promoted.reason
    assert "MAVERICK_APPROVER_KEYS_DIR" not in os.environ
    assert "MAVERICK_SELF_IMPROVEMENT" not in os.environ
    assert ledger.get(promoted.candidate_id).approver_id


def test_external_approval_requires_explicit_trusted_public_keys(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    approve, _, _ = _external_approval(keydir)
    _manifest(tmp_path)
    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=approve, ledger=PromotionLedger(path=tmp_path / "ledger.json"),
        store=ar.AdapterStore(root=tmp_path / "store"))
    assert not refused.promoted
    assert "explicit trusted approval public keys" in refused.reason


def test_injected_controller_cannot_disable_weights_human_gate(tmp_path):
    from maverick.self_improvement import PromotionLedger, SelfImprovementController

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    controller = SelfImprovementController(
        ledger=ledger, approval_verifier=verifier)
    controller.rung_policy["weights"]["require_human"] = False
    _manifest(tmp_path)
    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=approve, controller=controller,
        approval_public_keys=public_keys,
        serving_provisioner=_fake_serving_provisioner,
        store=ar.AdapterStore(root=tmp_path / "store"))
    assert not refused.promoted
    assert "must require cryptographic human approval" in refused.reason


def test_verified_model_install_is_required_before_prepare_or_reroute(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    _manifest(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")

    def unavailable(_binding):
        raise RuntimeError("serving daemon unavailable")

    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=approve, approval_verifier=verifier,
        approval_public_keys=public_keys,
        serving_provisioner=unavailable, ledger=ledger, store=store)
    assert not refused.promoted
    assert "serving installation failed" in refused.reason
    assert store.active() is None
    assert ledger.transactions() == []


def test_external_approval_signature_cannot_replay_across_tenants(tmp_path):
    from maverick.paths import tenant_scope
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    captured: dict[str, str] = {}

    def approve_and_capture(request):
        signature = approve(request)
        captured["signature"] = signature
        return signature

    with tenant_scope(tenant="tenant-a"):
        alpha_dir = tmp_path / "alpha-payloads"
        alpha = _manifest(alpha_dir)
        promoted = ar.govern_adapter_change(
            alpha_dir / "a", _cases(), score_fn=_genuine_scorer,
            change_id="cross-tenant-replay", approve=approve_and_capture,
            approval_verifier=verifier,
            approval_public_keys=public_keys,
            serving_provisioner=_fake_serving_provisioner,
            ledger=PromotionLedger(path=tmp_path / "alpha-ledger.json"),
            store=ar.AdapterStore(root=tmp_path / "alpha-store"))
        assert promoted.promoted, promoted.reason

    with tenant_scope(tenant="tenant-b"):
        beta_dir = tmp_path / "beta-payloads"
        beta = _manifest(beta_dir)
        # Keep every non-tenant approval field byte-identical.  Rejection then
        # proves the tenant binding itself prevents signature replay.
        beta.adapter_id = alpha.adapter_id
        beta.save(beta_dir / "a")
        replay = ar.govern_adapter_change(
            beta_dir / "a", _cases(), score_fn=_genuine_scorer,
            change_id="cross-tenant-replay",
            approval_signature=captured["signature"],
            approval_verifier=verifier,
            approval_public_keys=public_keys,
            serving_provisioner=_fake_serving_provisioner,
            ledger=PromotionLedger(path=tmp_path / "beta-ledger.json"),
            store=ar.AdapterStore(root=tmp_path / "beta-store"))

    assert not replay.promoted
    assert "signature is invalid" in replay.reason


def test_deploy_and_recovery_refuse_in_memory_promotion_ledger(tmp_path):
    from maverick.self_improvement import (
        PromotionLedger,
        PromotionLedgerError,
        SelfImprovementController,
    )

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    manifest = _manifest(tmp_path)
    ledger = PromotionLedger()
    store = ar.AdapterStore(root=tmp_path / "store")
    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=approve, approval_verifier=verifier,
        approval_public_keys=public_keys,
        ledger=ledger, store=store)
    assert not refused.promoted
    assert "in-memory promotion ledgers cannot deploy adapters" in refused.reason
    assert store.active() is None

    store.activate(manifest, record_id="dev-only-record")
    with pytest.raises(PromotionLedgerError, match="in-memory|durable"):
        ar.recover_adapter_promotions(
            SelfImprovementController(ledger=ledger), store=store)
    with pytest.raises(PromotionLedgerError, match="in-memory|durable"):
        ar.rollback_adapter("dev-only-record", store=store, ledger=ledger)


def test_governed_promotion_serves_immutable_content_addressed_copy(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    source_manifest = _manifest(tmp_path)
    store = ar.AdapterStore(root=tmp_path / "store")
    promoted = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=approve, approval_verifier=verifier,
        approval_public_keys=public_keys,
        serving_provisioner=_fake_serving_provisioner,
        ledger=PromotionLedger(path=tmp_path / "ledger.json"), store=store)
    assert promoted.promoted, promoted.reason
    staged = Path(promoted.pointer["serving"]["adapter_dir"])
    assert staged.parent == store.root / "payloads"
    assert len(staged.name) == 64
    assert staged != (tmp_path / "a").resolve()

    # The caller-owned training directory is no longer serving authority.
    (tmp_path / "a" / "adapter.safetensors").write_bytes(b"source-mutated")
    assert store.active()["payload_sha256"] == source_manifest.payload_sha256


def test_runtime_key_directory_requires_explicit_unsafe_dev_switch(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    _manifest(tmp_path)
    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir, ledger=ledger,
        store=ar.AdapterStore(root=tmp_path / "store"))
    assert not refused.promoted
    assert "runtime private-key signing is disabled" in refused.reason


def test_enterprise_profile_forbids_unsafe_dev_signing(tmp_path, monkeypatch):
    from maverick.self_improvement import PromotionLedger

    monkeypatch.setenv("MAVERICK_PROFILE", "enterprise")
    keydir = _keys(tmp_path)
    _manifest(tmp_path)
    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir,
        ledger=PromotionLedger(path=tmp_path / "ledger.json"),
        store=ar.AdapterStore(root=tmp_path / "store"),
        unsafe_dev_auto_sign=True)
    assert not refused.promoted
    assert "forbidden in enterprise" in refused.reason


def test_enterprise_env_forbids_unsafe_dev_signing_under_standard_profile(
    tmp_path, monkeypatch,
):
    from maverick.self_improvement import PromotionLedger

    monkeypatch.setenv("MAVERICK_PROFILE", "standard")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    keydir = _keys(tmp_path)
    _manifest(tmp_path)
    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir,
        ledger=PromotionLedger(path=tmp_path / "ledger.json"),
        store=ar.AdapterStore(root=tmp_path / "store"),
        unsafe_dev_auto_sign=True)
    assert not refused.promoted
    assert "forbidden in enterprise" in refused.reason


def test_enterprise_config_forbids_unsafe_dev_signing_under_standard_profile(
    tmp_path, monkeypatch,
):
    import maverick.config as config
    from maverick.self_improvement import PromotionLedger

    monkeypatch.setenv("MAVERICK_PROFILE", "standard")
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.setattr(
        config, "load_config", lambda path=None: {"enterprise": {"mode": True}})
    keydir = _keys(tmp_path)
    _manifest(tmp_path)
    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir,
        ledger=PromotionLedger(path=tmp_path / "ledger.json"),
        store=ar.AdapterStore(root=tmp_path / "store"),
        unsafe_dev_auto_sign=True)
    assert not refused.promoted
    assert "forbidden in enterprise" in refused.reason


def test_client_disabled_learning_is_not_forced_on_by_adapter(tmp_path, monkeypatch):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    _manifest(tmp_path)
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "0")
    refused = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        approve=approve, approval_verifier=verifier,
        approval_public_keys=public_keys,
        ledger=PromotionLedger(path=tmp_path / "ledger.json"),
        store=ar.AdapterStore(root=tmp_path / "store"))
    assert not refused.promoted and "disabled" in refused.reason
    assert os.environ["MAVERICK_SELF_IMPROVEMENT"] == "0"


def test_governed_tenant_binding_survives_serving_and_rollback(tmp_path):
    from maverick.paths import tenant_scope
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    with tenant_scope(tenant="tenant-a"):
        store = ar.AdapterStore(root=tmp_path / "store")
        manifest = _manifest(tmp_path)
        promoted = ar.govern_adapter_change(
            tmp_path / "a", _cases(), score_fn=_genuine_scorer,
            keys_dir=keydir, ledger=ledger, store=store,
            unsafe_dev_auto_sign=True)
        assert promoted.promoted, promoted.reason
        pointer = store.active()
        assert manifest.tenant_id == pointer["tenant_id"] == "tenant-a"
        assert pointer["serving"]["tenant_id"] == "tenant-a"
        assert promoted.serving["tenant_id"] == "tenant-a"
        assert promoted.serving["model_name"] == ar.tuned_model_name(manifest)
        record = ledger.get(promoted.candidate_id)
        assert record.provenance["tenant_id"] == "tenant-a"
        assert ar.rollback_adapter(
            promoted.candidate_id, store=store, ledger=ledger) is None
        assert store.active() is None and record is not None
        assert ledger.get(promoted.candidate_id).rolled_back


def test_activation_failure_aborts_prepare_without_committed_authority(
    tmp_path, monkeypatch,
):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")
    _manifest(tmp_path)

    def fail_activation(plan):
        raise OSError("simulated pointer CAS failure")

    monkeypatch.setattr(store, "_apply_activation_locked", fail_activation)
    res = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir, ledger=ledger, store=store,
        change_id="adapter-activation-failure", unsafe_dev_auto_sign=True)

    assert not res.promoted and "transaction aborted" in res.reason
    assert store.active() is None
    assert ledger.get(res.candidate_id) is None
    aborted = ledger.transactions(state="aborted")
    assert len(aborted) == 1 and aborted[0].record.id == res.candidate_id


def test_commit_ack_failure_recovers_prepared_live_activation(tmp_path, monkeypatch):
    from maverick.self_improvement import (
        PromotionLedger,
        PromotionLedgerError,
        SelfImprovementController,
    )

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    controller = SelfImprovementController(ledger=ledger)
    store = ar.AdapterStore(root=tmp_path / "store")
    manifest = _manifest(tmp_path)
    real_commit = ledger.commit
    calls = {"count": 0}

    def fail_once(transaction_id, *, artifact, at):
        calls["count"] += 1
        if calls["count"] == 1:
            raise PromotionLedgerError("simulated lost COMMIT acknowledgement")
        return real_commit(transaction_id, artifact=artifact, at=at)

    monkeypatch.setattr(ledger, "commit", fail_once)
    first = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir, ledger=ledger, controller=controller, store=store,
        change_id="adapter-recovery", unsafe_dev_auto_sign=True)

    assert not first.promoted and "recovery is required" in first.reason
    assert store.active()["adapter_id"] == manifest.adapter_id
    assert len(ledger.transactions(state="prepared")) == 1
    assert ledger.get(first.candidate_id) is None

    # Recovery is independent of a fresh payload and private signing key.
    (keydir / "operator.priv.hex").unlink()
    (tmp_path / "a" / "adapter.safetensors").unlink()
    ar.recover_adapter_promotions(controller, store=store)
    assert ledger.transactions(state="prepared") == []
    committed = ledger.transactions(state="committed")
    assert len(committed) == 1 and committed[0].record.id == first.candidate_id
    assert ledger.get(first.candidate_id) is not None


def test_corrupt_incumbent_blocks_next_prepare_and_preserves_pointer(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")
    _manifest(tmp_path, "a")
    first = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir, ledger=ledger, store=store,
        unsafe_dev_auto_sign=True)
    assert first.promoted, first.reason
    modelfile = Path(first.pointer["serving"]["modelfile"])
    os.chmod(modelfile, 0o600)
    modelfile.write_text("tampered\n", encoding="utf-8")

    _manifest(tmp_path, "b")
    second = ar.govern_adapter_change(
        tmp_path / "b", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir, ledger=ledger, store=store,
        unsafe_dev_auto_sign=True)
    assert not second.promoted
    assert "digest mismatch" in second.reason
    assert ledger.get(second.candidate_id) is None
    assert ledger.transactions(state="prepared") == []
    with store.transaction_locked():
        raw = store._read_state_locked(verify_serving=False)
    assert raw.active["promotion_record_id"] == first.candidate_id


def test_govern_adapter_change_refuses_dirty_payload_before_eval(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    _manifest(tmp_path)
    (tmp_path / "a" / "evil.py").write_text("import os\n", encoding="utf-8")

    def exploding_scorer(ref, ids):  # pragma: no cover -- must never run
        raise AssertionError("eval ran on a dirty payload")

    res = ar.govern_adapter_change(tmp_path / "a", _cases(),
                                   score_fn=exploding_scorer, keys_dir=keydir,
                                   ledger=ledger,
                                   store=ar.AdapterStore(root=tmp_path / "store"),
                                   unsafe_dev_auto_sign=True)
    assert not res.hygiene_ok and not res.promoted
    assert "evil.py" in res.reason


def test_govern_adapter_change_refuses_swapped_weights(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    _manifest(tmp_path)
    # Weights swapped AFTER training/manifest: digest mismatch, refused.
    (tmp_path / "a" / "adapter.safetensors").write_bytes(b"swapped")
    res = ar.govern_adapter_change(tmp_path / "a", _cases(),
                                   score_fn=_genuine_scorer, keys_dir=keydir,
                                   ledger=ledger,
                                   store=ar.AdapterStore(root=tmp_path / "store"),
                                   unsafe_dev_auto_sign=True)
    assert not res.promoted and "digest mismatch" in res.reason


def test_govern_adapter_change_refuses_overfit_and_rollback_restores(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")
    m_a = _manifest(tmp_path, "a")
    res_a = ar.govern_adapter_change(tmp_path / "a", _cases(),
                                     score_fn=_genuine_scorer, keys_dir=keydir,
                                     ledger=ledger, store=store,
                                     unsafe_dev_auto_sign=True)
    assert res_a.promoted

    held_in, _ = corpus_split([{"goal": c} for c in _cases()], held_out_frac=0.35)
    seen = set(held_in)

    def memoriser(ref, ids):
        if "+adapter:" in ref:
            return {c: (c in seen) or _base_pass(c) for c in ids}
        return {c: _base_pass(c) for c in ids}

    _manifest(tmp_path, "b")
    res_b = ar.govern_adapter_change(tmp_path / "b", _cases(),
                                     score_fn=memoriser, keys_dir=keydir,
                                     ledger=ledger, store=store,
                                     unsafe_dev_auto_sign=True)
    assert not res_b.promoted and res_b.fitness.overfit
    assert store.active()["adapter_id"] == m_a.adapter_id  # unchanged

    # Promote a genuine second adapter, then one-step rollback to the first.
    m_c = _manifest(tmp_path, "c")
    res_c = ar.govern_adapter_change(tmp_path / "c", _cases(),
                                     score_fn=_genuine_scorer, keys_dir=keydir,
                                     ledger=ledger, store=store,
                                     unsafe_dev_auto_sign=True)
    assert res_c.promoted and store.active()["adapter_id"] == m_c.adapter_id
    ar.rollback_adapter(res_c.candidate_id, store=store, ledger=ledger)
    assert store.active()["adapter_id"] == m_a.adapter_id
    assert ledger.get(res_c.candidate_id).rolled_back


def test_rollback_receipt_failure_leaves_recoverable_durable_intent(tmp_path, monkeypatch):
    from maverick.self_improvement import (
        PromotionLedger,
        PromotionLedgerError,
        SelfImprovementController,
    )

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")
    _manifest(tmp_path)
    promoted = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir, ledger=ledger, store=store,
        unsafe_dev_auto_sign=True)
    assert promoted.promoted

    real_mark = ledger.mark_rolled_back

    def fail_receipt(record_id, *, at):
        raise PromotionLedgerError("simulated rollback journal failure")

    monkeypatch.setattr(ledger, "mark_rolled_back", fail_receipt)
    with pytest.raises(PromotionLedgerError, match="COMMIT is in doubt"):
        ar.rollback_adapter(promoted.candidate_id, store=store, ledger=ledger)
    assert store.active() is None
    assert store._state(strict=True).pending_rollback is not None
    assert not ledger.get(promoted.candidate_id).rolled_back

    monkeypatch.setattr(ledger, "mark_rolled_back", real_mark)
    ar.recover_adapter_promotions(
        SelfImprovementController(ledger=ledger), store=store)
    assert store._state(strict=True).pending_rollback is None
    assert ledger.get(promoted.candidate_id).rolled_back


def test_process_death_after_rollback_pointer_cas_recovers_commit(tmp_path, monkeypatch):
    from maverick.self_improvement import PromotionLedger, SelfImprovementController

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")
    _manifest(tmp_path)
    promoted = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir, ledger=ledger, store=store,
        unsafe_dev_auto_sign=True)
    assert promoted.promoted, promoted.reason

    real_write = store._write_state_locked
    calls = {"count": 0}

    def die_after_publish(state):
        calls["count"] += 1
        real_write(state)
        if calls["count"] == 2:
            raise SystemExit("simulated process death after pointer CAS")

    monkeypatch.setattr(store, "_write_state_locked", die_after_publish)
    with pytest.raises(SystemExit):
        ar.rollback_adapter(promoted.candidate_id, store=store, ledger=ledger)
    monkeypatch.setattr(store, "_write_state_locked", real_write)

    assert store.active() is None
    assert store._state(strict=True).pending_rollback is not None
    assert not ledger.get(promoted.candidate_id).rolled_back
    ar.recover_adapter_promotions(
        SelfImprovementController(ledger=ledger), store=store)
    assert ledger.get(promoted.candidate_id).rolled_back
    assert store._state(strict=True).pending_rollback is None


def test_process_death_after_rollback_prepare_recovers_abort(tmp_path, monkeypatch):
    from maverick.self_improvement import PromotionLedger, SelfImprovementController

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    store = ar.AdapterStore(root=tmp_path / "store")
    manifest = _manifest(tmp_path)
    promoted = ar.govern_adapter_change(
        tmp_path / "a", _cases(), score_fn=_genuine_scorer,
        keys_dir=keydir, ledger=ledger, store=store,
        unsafe_dev_auto_sign=True)
    real_write = store._write_state_locked

    def die_after_prepare(state):
        real_write(state)
        raise SystemExit("simulated process death after rollback PREPARE")

    monkeypatch.setattr(store, "_write_state_locked", die_after_prepare)
    with pytest.raises(SystemExit):
        ar.rollback_adapter(promoted.candidate_id, store=store, ledger=ledger)
    monkeypatch.setattr(store, "_write_state_locked", real_write)

    assert store.active()["adapter_id"] == manifest.adapter_id
    assert store._state(strict=True).pending_rollback is not None
    ar.recover_adapter_promotions(
        SelfImprovementController(ledger=ledger), store=store)
    assert store.active()["adapter_id"] == manifest.adapter_id
    assert not ledger.get(promoted.candidate_id).rolled_back
    assert store._state(strict=True).pending_rollback is None


def test_active_pointer_file_is_private(tmp_path):
    from maverick.file_lock import private_path_is_restricted

    store = ar.AdapterStore(root=tmp_path / "store")
    store.activate(_manifest(tmp_path), record_id="rec-a")
    assert private_path_is_restricted(
        tmp_path / "store" / ar.ACTIVE_BASENAME, 0o600)


def test_manifest_load_ignores_unknown_keys(tmp_path):
    m = _manifest(tmp_path)
    path = tmp_path / "a" / ar.MANIFEST_BASENAME
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["future_field"] = "x"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert ar.AdapterManifest.load(tmp_path / "a").adapter_id == m.adapter_id


# --- hardening regressions (code-review findings) --------------------------------

def test_payload_refuses_directory_symlink(tmp_path):
    # A symlink to a DIRECTORY must be refused: Path.is_dir() follows the link,
    # so an is_dir() check ahead of the symlink check would skip (not refuse) it,
    # smuggling unreviewed content past the boundary and out of the digest.
    outside = tmp_path / "external"
    outside.mkdir()
    (outside / "post_init.py").write_text("import os\n", encoding="utf-8")
    d = tmp_path / "adapter"
    d.mkdir()
    (d / "adapter.safetensors").write_bytes(b"w")
    try:
        (d / "sub").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")
    review = ar.review_adapter_payload(d)
    assert not review.ok and "symlink" in review.reason


def test_payload_requires_a_weight_file(tmp_path):
    # Metadata-only dir (no .safetensors/.gguf) is not an adapter, even though
    # every file is individually allowed.
    d = tmp_path / "adapter"
    d.mkdir()
    (d / "adapter_config.json").write_text("{}", encoding="utf-8")
    (d / "README.md").write_text("card", encoding="utf-8")
    review = ar.review_adapter_payload(d)
    assert not review.ok and "no weight file" in review.reason
    (d / "adapter_model.safetensors").write_bytes(b"w")
    assert ar.review_adapter_payload(d).ok


def test_payload_accepts_standard_hf_adapter_files(tmp_path):
    # A realistic HF/PEFT export must clear hygiene: weights + config + tokenizer
    # protobuf + model card + .gitattributes.
    d = tmp_path / "adapter"
    d.mkdir()
    (d / "adapter_model.safetensors").write_bytes(b"w")
    (d / "adapter_config.json").write_text("{}", encoding="utf-8")
    (d / "tokenizer.model").write_bytes(b"\x0a\x00proto")  # sentencepiece protobuf
    (d / "README.md").write_text("card", encoding="utf-8")
    (d / ".gitattributes").write_text("*.safetensors filter=lfs\n", encoding="utf-8")
    review = ar.review_adapter_payload(d)
    assert review.ok, review.reason
    # ...but a smuggled script alongside them is still refused.
    (d / "run.py").write_text("import os\n", encoding="utf-8")
    assert not ar.review_adapter_payload(d).ok


def _fake_rlaif(monkeypatch, captured: dict):
    """Install a fake maverick.training.rlaif.train that records its args and
    writes a valid safetensors adapter, so the dpo-lora seam is exercised
    without torch/peft/GPU."""
    import types

    def fake_train(pairs, base_model, out_dir, *, lora=False, **kw):
        captured["pairs"] = pairs
        captured["base_model"] = base_model
        captured["lora"] = lora
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / "adapter_model.safetensors").write_bytes(b"trained")
        return 0

    fake_mod = types.SimpleNamespace(train=fake_train)
    import maverick.training as training_pkg
    monkeypatch.setattr(training_pkg, "rlaif", fake_mod, raising=False)
    monkeypatch.setitem(__import__("sys").modules, "maverick.training.rlaif", fake_mod)
    return captured


def test_dpo_lora_passes_dict_pairs_and_strips_prefix(tmp_path, monkeypatch):
    captured: dict = {}
    _fake_rlaif(monkeypatch, captured)
    review = ar.screen_examples([
        ar.TrainExample("prompt one", "good answer", "bad answer",
                        provenance="human_correction"),
        ar.TrainExample("prompt two", "great", "meh", provenance="tenant_trace"),
    ])
    manifest = ar.get_trainer("dpo-lora").train(review, "ollama:some-base", tmp_path / "a")
    # pairs are dicts with the keys rlaif requires, NOT tuples.
    assert isinstance(captured["pairs"], list) and captured["pairs"]
    for row in captured["pairs"]:
        assert set(row) >= {"chosen_text", "rejected_text", "weight"}
        assert isinstance(row["chosen_text"], str)
    # the ollama: serving prefix is stripped before it reaches from_pretrained.
    assert captured["base_model"] == "some-base"
    assert captured["lora"] is True
    # a real, hygiene-clean, digest-bound manifest is produced.
    assert manifest.trainer == "dpo-lora"
    assert ar.review_adapter_payload(tmp_path / "a").ok
    assert manifest.payload_sha256 == ar.payload_digest_dir(tmp_path / "a")


def test_dpo_lora_requires_preference_pairs(tmp_path, monkeypatch):
    captured: dict = {}
    _fake_rlaif(monkeypatch, captured)
    review = ar.screen_examples([
        ar.TrainExample("p", "just a completion", "", provenance="human_example")])
    with pytest.raises(RuntimeError, match="preference pairs"):
        ar.get_trainer("dpo-lora").train(review, "ollama:some-base", tmp_path / "a")
    assert "pairs" not in captured  # never reached rlaif


def test_govern_threads_configured_min_improvement(tmp_path, monkeypatch):
    # A small held-out uplift below the configured floor must be refused when
    # govern builds its own controller (no explicit controller passed).
    import maverick.config as config
    from maverick.self_improvement import PromotionLedger
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"self_improvement": {"min_improvement": 0.5}},
    )
    monkeypatch.setattr(config, "config_source_errors", dict)
    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    _manifest(tmp_path)

    def small_uplift(ref, ids):
        # base resolves ~half; adapter adds only the first held-out case (< 0.5).
        if "+adapter:" in ref:
            return {c: (_base_pass(c) or c == ids[0]) for c in ids}
        return {c: _base_pass(c) for c in ids}

    res = ar.govern_adapter_change(tmp_path / "a", _cases(),
                                   score_fn=small_uplift, keys_dir=keydir,
                                   ledger=ledger,
                                   store=ar.AdapterStore(root=tmp_path / "store"),
                                   unsafe_dev_auto_sign=True)
    assert not res.promoted
    assert "min" in res.reason.lower() or "gate refused" in res.reason.lower()


def test_govern_refuses_untrusted_promotion_policy_source(tmp_path, monkeypatch):
    import maverick.config as config
    from maverick.self_improvement import PromotionLedger

    monkeypatch.setattr(
        config,
        "config_source_errors",
        lambda **_kwargs: {"config.toml": "invalid TOML"},
    )
    keydir = _keys(tmp_path)
    approve, verifier, public_keys = _external_approval(keydir)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    _manifest(tmp_path)

    result = ar.govern_adapter_change(
        tmp_path / "a",
        _cases(),
        score_fn=_genuine_scorer,
        approve=approve,
        approval_verifier=verifier,
        approval_public_keys=public_keys,
        ledger=ledger,
        store=ar.AdapterStore(root=tmp_path / "store"),
    )

    assert not result.promoted
    assert "policy source is invalid" in result.reason
    assert ledger.all() == []


@pytest.mark.parametrize("margin", ["0.25", True, float("nan"), -0.1, 1.1])
def test_govern_refuses_invalid_explicit_promotion_margin(
    tmp_path, monkeypatch, margin,
):
    import maverick.config as config
    from maverick.self_improvement import PromotionLedger

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"self_improvement": {"min_improvement": margin}},
    )
    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    _manifest(tmp_path)

    result = ar.govern_adapter_change(
        tmp_path / "a",
        _cases(),
        score_fn=_genuine_scorer,
        keys_dir=keydir,
        ledger=ledger,
        store=ar.AdapterStore(root=tmp_path / "store"),
        unsafe_dev_auto_sign=True,
    )

    assert not result.promoted
    assert "min_improvement is invalid" in result.reason
    assert ledger.all() == []


def test_govern_refuses_empty_base_model_id(tmp_path):
    from maverick.self_improvement import PromotionLedger

    keydir = _keys(tmp_path)
    ledger = PromotionLedger(path=tmp_path / "ledger.json")
    review = ar.screen_examples(_examples())
    ar.get_trainer("stub").train(review, "ollama:", tmp_path / "a")  # blank model id
    res = ar.govern_adapter_change(tmp_path / "a", _cases(),
                                   score_fn=_genuine_scorer, keys_dir=keydir,
                                   ledger=ledger,
                                   store=ar.AdapterStore(root=tmp_path / "store"),
                                   unsafe_dev_auto_sign=True)
    assert not res.promoted and "no model id" in res.reason


def test_effective_model_spec_skips_non_ollama_base(tmp_path, monkeypatch):
    # A vLLM/TGI base must never be rewritten to the ollama: provider.
    _enable_cfg(monkeypatch, tmp_path, base_model="vllm:Qwen3-Coder")
    store = ar.AdapterStore(root=tmp_path / "store")
    review = ar.screen_examples(_examples())
    m = ar.get_trainer("stub").train(review, "vllm:Qwen3-Coder", tmp_path / "a")
    store.activate(m, record_id="rec-a")
    assert ar.effective_model_spec("vllm:Qwen3-Coder") == "vllm:Qwen3-Coder"


def test_emit_serving_artifacts_notes_non_ollama_base(tmp_path):
    review = ar.screen_examples(_examples())
    m = ar.get_trainer("stub").train(review, "vllm:Qwen3-Coder", tmp_path / "a")
    serving = ar.emit_serving_artifacts(m, tmp_path / "a")
    assert serving["create_command"] is None and "manually" in serving["note"]
    assert not (tmp_path / "a" / ar.SERVING_BASENAME).exists()


def test_effective_model_spec_disabled_does_not_read_config_tree(tmp_path, monkeypatch):
    # The disabled default path must not pay a full get_adapter_rung() per call.
    import maverick.config as config
    calls = {"n": 0}

    def counting():
        calls["n"] += 1
        return {"enable": False}

    monkeypatch.setattr(config, "get_adapter_rung", counting)
    ar._reset_caches()
    for _ in range(5):
        assert ar.effective_model_spec("ollama:base") == "ollama:base"
    # memoized by config stat signature -> at most one real read, not five.
    assert calls["n"] <= 1


def test_atomic_write_json_delegates_to_shared_helper(tmp_path, monkeypatch):
    # Regression: _atomic_write_json routes through file_lock.atomic_write_text
    # (unique mkstemp temp name), not a PID-keyed temp that collides.
    import maverick.file_lock as fl
    seen = {}
    real = fl.atomic_write_text

    def spy(path, text, *, mode=0o600):
        seen["mode"] = mode
        return real(path, text, mode=mode)

    monkeypatch.setattr(fl, "atomic_write_text", spy)
    ar._atomic_write_json(tmp_path / "p.json", {"a": 1})
    assert seen.get("mode") == 0o600
    assert json.loads((tmp_path / "p.json").read_text()) == {"a": 1}
    assert fl.private_path_is_restricted(tmp_path / "p.json", 0o600)
