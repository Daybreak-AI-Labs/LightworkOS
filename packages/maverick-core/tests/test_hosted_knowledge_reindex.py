"""Paid rebuilds use only synthetic HTTP responses and real local cost receipts."""
from __future__ import annotations

import uuid
from datetime import date, timedelta

import httpx
import pytest
from maverick import config
from maverick import knowledge_reindex_jobs as jobs
from maverick import provider_cost_cap as cap
from maverick_knowledge import DeterministicEmbedder, KnowledgeBase, SqliteVectorStore
from maverick_knowledge.embed import HostedEmbedder


@pytest.fixture()
def setup(tmp_path, monkeypatch):
    from maverick import embedding_prices

    monkeypatch.setattr(embedding_prices, "_utc_today", lambda: date.fromisoformat(embedding_prices._AS_OF))
    policy = {"knowledge": {"reindex_jobs": True, "reindex_max_dollars": 5.0}}
    monkeypatch.setattr(config, "load_config", lambda: policy)
    monkeypatch.setattr(jobs, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(cap, "_ledger_path", lambda: tmp_path / "provider.json")
    kb = KnowledgeBase(store=SqliteVectorStore(tmp_path / "knowledge.db"), embedder=DeterministicEmbedder(8))
    for number in range(65):
        kb.ingest_text("policies", f"Exact passage {number}", source=f"source-{number}")
    kb.embedder = HostedEmbedder("text-embedding-3-small", "https://api.openai.com/v1", "synthetic-not-a-key", dim=1536)
    yield kb, "a" * 64, policy
    kb.close()


def _start(kb, context):
    review = jobs.preview(kb, "policies")
    return jobs.start(kb, context=context, job_id=uuid.uuid4().hex, collection="policies", review=review["review"])


def _body(count, tokens=100):
    return {"model": "text-embedding-3-small", "usage": {"total_tokens": tokens, "prompt_tokens": tokens},
            "data": [{"index": index, "embedding": [float(index + 1)] * 1536} for index in reversed(range(count))]}


def _receipt(context, job_id, index=0):
    job = jobs._read(jobs._path(context, job_id))
    request = jobs._sha([context, job_id, index])
    rows = cap.reservations_for_work_item("knowledge-reindex:" + context + ":" + job_id)
    return next(row for row in rows.receipts if row.request_id == request), job


def test_paid_job_reserves_before_http_and_publishes_only_after_all_batches(setup, monkeypatch):
    kb, context, _ = setup
    original = kb.store.read_collection("policies", limit=1000)
    job = _start(kb, context)
    calls = []
    def post(url, *, json, headers, timeout):
        assert url == "https://api.openai.com/v1/embeddings"
        assert 0 < timeout <= 60
        assert headers["Authorization"] == "Bearer synthetic-not-a-key"
        assert kb.store.read_collection("policies", limit=1000) == original
        receipt, saved = _receipt(context, job["job_id"], sum(calls))
        assert receipt.state == "held" and receipt.projected > 0
        assert saved["pending_batch"]["state"] == "dispatched"
        calls.append(len(json["input"]))
        return httpx.Response(200, json=_body(calls[-1]), request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "completed", final
    assert calls == [64, 1]
    assert final["observed_dollars"] == pytest.approx(200 * .02 / 1_000_000)
    assert final["unresolved_dollars"] == 0
    receipt, _ = _receipt(context, job["job_id"])
    assert receipt.state == "settled" and receipt.cost_basis == "observed"
    assert receipt.pricing_evidence["verified"] is True
    assert kb.store.read_collection("policies", limit=1000) != original
    jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert calls == [64, 1]


@pytest.mark.parametrize("usage", [None, {}, {"total_tokens": None}, {"total_tokens": True},
                                  {"total_tokens": -1}, {"total_tokens": 1.5}, {"total_tokens": "100"}])
def test_invalid_usage_retains_hold_and_never_retries(setup, monkeypatch, usage):
    kb, context, _ = setup
    original = kb.store.read_collection("policies", limit=1000)
    job = _start(kb, context)
    calls = []
    def post(url, **kwargs):
        calls.append(url)
        body = _body(64)
        body["usage"] = ({**usage, "prompt_tokens": usage["total_tokens"]}
                         if isinstance(usage, dict) and "total_tokens" in usage else usage)
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "unconfirmed"
    assert final["unresolved_dollars"] > 0 and final["observed_dollars"] == 0
    receipt, _ = _receipt(context, job["job_id"])
    assert receipt.state == "unknown" and receipt.actual is None
    jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert len(calls) == 1
    assert kb.store.read_collection("policies", limit=1000) == original


def test_reported_usage_above_bound_is_recorded_then_stops(setup, monkeypatch):
    kb, context, _ = setup
    job = _start(kb, context)
    original = kb.store.read_collection("policies", limit=1000)
    calls = []
    def post(url, **kwargs):
        calls.append(url)
        return httpx.Response(200, json=_body(64, 900_000), request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "failed" and len(calls) == 1
    assert final["observed_dollars"] == pytest.approx(.018)
    receipt, _ = _receipt(context, job["job_id"])
    assert receipt.actual == pytest.approx(.018)
    assert kb.store.read_collection("policies", limit=1000) == original


def test_process_interruption_holds_paid_attempt_and_resume_does_not_resend(setup, monkeypatch):
    kb, context, _ = setup
    job = _start(kb, context)
    calls = []
    def post(url, **kwargs):
        calls.append(url)
        raise KeyboardInterrupt("Process exits after dispatch")
    monkeypatch.setattr(httpx, "post", post)
    with pytest.raises(KeyboardInterrupt):
        jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    receipt, _ = _receipt(context, job["job_id"])
    assert receipt.state == "unknown"
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "unconfirmed" and len(calls) == 1


def test_sealed_paid_checkpoint_resumes_only_unsent_batch(setup, monkeypatch):
    kb, context, _ = setup
    job = _start(kb, context)
    calls = []
    def post(url, *, json, **kwargs):
        calls.append(len(json["input"]))
        return httpx.Response(200, json=_body(calls[-1]), request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    original = jobs._update
    def interrupted(path, **changes):
        if changes == {"pending_batch": None, "unresolved_dollars": 0.0}:
            raise KeyboardInterrupt("Sealed shadow exists; mutable progress not yet acknowledged")
        return original(path, **changes)
    monkeypatch.setattr(jobs, "_update", interrupted)
    with pytest.raises(KeyboardInterrupt):
        jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    monkeypatch.setattr(jobs, "_update", original)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "completed" and calls == [64, 1]
    assert final["observed_dollars"] == pytest.approx(.000004)


def test_cancel_after_paid_batch_preserves_live_index_and_exact_charge(setup, monkeypatch):
    kb, context, _ = setup
    job = _start(kb, context)
    original = kb.store.read_collection("policies", limit=1000)
    def post(url, **kwargs):
        jobs.cancel(context, job["job_id"])
        return httpx.Response(200, json=_body(64), request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "cancelled" and final["done"] == 64
    assert final["observed_dollars"] == pytest.approx(.000002)
    assert kb.store.read_collection("policies", limit=1000) == original


def test_current_policy_and_model_change_prevent_paid_dispatch(setup, monkeypatch):
    kb, context, policy = setup
    job = _start(kb, context)
    def no_post(*args, **kwargs):
        pytest.fail("No paid request is authorized")
    monkeypatch.setattr(httpx, "post", no_post)
    policy["knowledge"]["reindex_max_dollars"] = 0.0
    assert jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)["state"] == "failed"
    policy["knowledge"]["reindex_max_dollars"] = 5.0
    review = jobs.preview(kb, "policies")
    kb.embedder.model = "text-embedding-3-large"
    with pytest.raises(ValueError, match="changed"):
        jobs.start(kb, context=context, job_id=uuid.uuid4().hex, collection="policies", review=review["review"])


def test_personal_task_cap_counts_earlier_batches_and_native_usage_ledger(setup, monkeypatch):
    from maverick import spending_limits
    from maverick.quotas import UsageLedger

    kb, context, _ = setup
    monkeypatch.setattr(spending_limits, "load", lambda: {
        "workspace": None, "default": {"amount": .0061, "period": "task"}, "users": {}})
    job = _start(kb, context)
    calls = []
    def post(url, **kwargs):
        calls.append(url)
        return httpx.Response(200, json=_body(64, 300_000), request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "failed" and calls == ["https://api.openai.com/v1/embeddings"]
    assert final["done"] == 64 and final["observed_dollars"] == pytest.approx(.006)
    receipt = UsageLedger().settlement(job["job_id"], "local")
    assert receipt["total"]["dollars"] == pytest.approx(.006)
    assert receipt["total"]["in_tokens"] == 300_000


@pytest.mark.parametrize("returned_model", ["text-embedding-3-large", None])
def test_different_response_model_keeps_unknown_cost_hold(setup, monkeypatch, returned_model):
    kb, context, _ = setup
    job = _start(kb, context)
    def post(url, **kwargs):
        body = _body(64)
        if returned_model is None:
            body.pop("model")
        else:
            body["model"] = returned_model
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "unconfirmed" and final["observed_dollars"] == 0
    receipt, _ = _receipt(context, job["job_id"])
    assert receipt.state == "unknown" and receipt.actual is None


def test_swapped_sealed_shadow_is_rejected_without_another_paid_call(setup, monkeypatch):
    from maverick.file_lock import atomic_read_text, atomic_write_text

    kb, context, _ = setup
    first = _start(kb, context)
    calls = []
    def post(url, **kwargs):
        calls.append(url)
        jobs.cancel(context, first["job_id"])
        return httpx.Response(200, json=_body(64), request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    assert jobs.run(kb, context=context, job_id=first["job_id"], authority=lambda: None)["state"] == "cancelled"
    second = _start(kb, context)
    first_path = jobs._path(context, first["job_id"]).with_suffix(".shadow")
    second_path = jobs._path(context, second["job_id"]).with_suffix(".shadow")
    atomic_write_text(second_path, atomic_read_text(first_path))
    assert jobs.run(kb, context=context, job_id=second["job_id"], authority=lambda: None)["state"] == "failed"
    assert len(calls) == 1


def test_same_identity_publication_recovery_requires_the_actual_atomic_publish(setup, monkeypatch):
    kb, context, _ = setup
    # A same-model rebuild must not confuse old identical metadata with a new
    # publication. Use local deterministic computation to isolate that boundary.
    kb.embedder = DeterministicEmbedder(8)
    job = _start(kb, context)
    before = kb.store.read_collection("policies", limit=1000)
    replace = kb.store.replace_embeddings
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt("Process exits before the atomic publication")
    monkeypatch.setattr(kb.store, "replace_embeddings", interrupted)
    with pytest.raises(KeyboardInterrupt):
        jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert kb.store.read_collection("policies", limit=1000) == before
    published = []
    def real_replace(*args):
        published.append(True)
        return replace(*args)
    monkeypatch.setattr(kb.store, "replace_embeddings", real_replace)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "completed" and published == [True]
    assert all(row.meta.get("reindex_publication") for row in kb.store.read_collection("policies", limit=1000))


def test_expired_review_refuses_before_any_provider_call(setup, monkeypatch):
    from maverick import embedding_prices

    kb, context, _ = setup
    job = _start(kb, context)
    monkeypatch.setattr(embedding_prices, "_utc_today", lambda: date.fromisoformat(embedding_prices._VALID_UNTIL) + timedelta(days=1))
    def denied(*args, **kwargs):
        pytest.fail("Expired rate evidence cannot authorize paid dispatch")
    monkeypatch.setattr(httpx, "post", denied)
    assert jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)["state"] == "failed"


def test_completed_publication_is_recovered_without_fresh_paid_admission(setup, monkeypatch):
    from maverick import embedding_prices

    kb, context, _ = setup
    job = _start(kb, context)
    calls = []
    def post(url, *, json, **kwargs):
        calls.append(len(json["input"]))
        return httpx.Response(200, json=_body(calls[-1]), request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    replace = kb.store.replace_embeddings
    def interrupted(*args):
        replace(*args)
        raise KeyboardInterrupt("Complete transaction committed before job acknowledgement")
    monkeypatch.setattr(kb.store, "replace_embeddings", interrupted)
    with pytest.raises(KeyboardInterrupt):
        jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    monkeypatch.setattr(embedding_prices, "_utc_today", lambda: date.fromisoformat(embedding_prices._VALID_UNTIL) + timedelta(days=1))
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "completed" and calls == [64, 1]
    assert "verified after interruption" in final["message"]


def test_voyage_default_transport_disables_truncation_and_accounts_native_usage(setup, monkeypatch):
    kb, context, _ = setup
    kb.embedder = HostedEmbedder("voyage-3", "https://api.voyageai.com/v1", "synthetic-not-a-key", dim=1024)
    job = _start(kb, context)
    calls = []
    def post(url, *, json, **kwargs):
        assert url == "https://api.voyageai.com/v1/embeddings"
        assert json["truncation"] is False and json["model"] == "voyage-3"
        count = len(json["input"])
        calls.append(count)
        body = {"usage": {"total_tokens": 100}, "data": [
            {"index": index, "embedding": [1.0] * 1024} for index in range(count)]}
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "completed" and calls == [64, 1]
    assert final["observed_dollars"] == pytest.approx(.000012)


@pytest.mark.parametrize("daily_cap,expected_state,expected_calls", [(.02, "completed", 2), (.005, "failed", 0)])
def test_native_organization_admission_and_ledger_settlement(setup, monkeypatch, daily_cap, expected_state, expected_calls):
    from maverick.tenant import provider_admission, registry

    kb, context, _ = setup
    registry.create_tenant("embedding-review", plan="free", max_daily_dollars=daily_cap)
    monkeypatch.setenv("MAVERICK_TENANT", "embedding-review")
    job = _start(kb, context)
    calls = []
    def post(url, *, json, **kwargs):
        calls.append(len(json["input"]))
        assert provider_admission.outstanding("embedding-review") > 0
        return httpx.Response(200, json=_body(calls[-1]), request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == expected_state, final
    assert len(calls) == expected_calls
    if expected_calls:
        assert provider_admission.outstanding("embedding-review") == 0
        assert registry.tenant_spend_today("embedding-review") == pytest.approx(.000004)


def test_partial_organization_acknowledgement_never_releases_or_resends(setup, monkeypatch):
    from maverick.tenant import provider_admission, registry

    kb, context, _ = setup
    registry.create_tenant("embedding-review", plan="free", max_daily_dollars=.02)
    monkeypatch.setenv("MAVERICK_TENANT", "embedding-review")
    job = _start(kb, context)
    calls = []
    def post(url, **kwargs):
        calls.append(url)
        return httpx.Response(200, json=_body(64), request=httpx.Request("POST", url))
    def unavailable(*args):
        raise OSError("Organization acknowledgement unavailable")
    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(provider_admission, "acknowledge_budget", unavailable)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "unconfirmed"
    assert provider_admission.outstanding("embedding-review") > 0
    receipt, _ = _receipt(context, job["job_id"])
    assert receipt.state == "settled" and receipt.actual == pytest.approx(.000002)
    jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert len(calls) == 1


def test_recovery_refuses_changed_requester_without_mutating_the_record(setup, monkeypatch):
    from maverick import connections

    kb, context, _ = setup
    job = _start(kb, context)
    path = jobs._path(context, job["job_id"])
    original = jobs._read(path)
    monkeypatch.setattr(connections, "current_principal", lambda: "different-account")
    with pytest.raises(ValueError, match="account changed"):
        jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert jobs._read(path) == original


@pytest.mark.parametrize("changed", ["credential", "source", "cost_authority"])
def test_intervening_configuration_or_source_change_stops_next_paid_batch(setup, monkeypatch, changed):
    kb, context, policy = setup
    job = _start(kb, context)
    calls = []
    after_edit = []
    def post(url, **kwargs):
        calls.append(url)
        if changed == "credential":
            policy["knowledge"]["api_key"] = "rotated-synthetic-credential"
        elif changed == "cost_authority":
            monkeypatch.setattr(cap, "authority_identity", lambda: "changed-cost-authority")
        else:
            kb.store.delete_where("policies", "source", "source-2")
        after_edit.extend(kb.store.read_collection("policies", limit=1000))
        return httpx.Response(200, json=_body(64), request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "failed" and len(calls) == 1
    assert final["observed_dollars"] == pytest.approx(.000002)
    assert kb.store.read_collection("policies", limit=1000) == after_edit
    assert "rotated-synthetic-credential" not in str(jobs._read(jobs._path(context, job["job_id"])))
