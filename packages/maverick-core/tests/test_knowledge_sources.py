"""Saved remote Knowledge sources: the refresh claim and the freshness window."""
from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace

import pytest
from maverick import config
from maverick import knowledge_sources as native
from maverick.knowledge_content_projection import inspect_existing_source
from maverick.paths import tenant_scope
from maverick.research_registry import ResearchAssetRef

TENANT = "acme"
OWNER = "user:alice"
SHA = "a" * 64


class _Registry:
    @staticmethod
    def data_use_resolver(tenant, decision_id, decision_sha256):
        return SimpleNamespace(tenant=tenant, decision_id=decision_id, decision_sha256=decision_sha256, asset_id="asset-1",
                               action="analyze", purpose_codes=("support",), purpose="support",
                               expires_at=4_000_000_000.0, authority_sha256=SHA)

    @staticmethod
    def preflight_dataset_ingestion(tenant, **_kwargs):
        return None

    @staticmethod
    def register_dataset(tenant, actor, *, dataset_id, version, **_kwargs):
        return ResearchAssetRef(kind="dataset", asset_id=dataset_id, version=version, manifest_sha256=SHA)


def _embedding():
    from maverick.knowledge_reindex_jobs import _configuration_revision

    return {"billing": None, "price_basis": "local", "configuration": _configuration_revision()}


def _plan(interval):
    return {"name": "Team drive", "binding": {"kind": "test"}, "decision_id": "dec-1", "decision_sha256": SHA,
            "asset_id": "asset-1", "purpose": "support", "interval_seconds": interval, "max_dollars": 0.0,
            "permission_evidence_sha256": SHA}


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(native, "enabled", lambda: True)
    monkeypatch.setattr(native.readers, "account", lambda *args, **kwargs: None)
    with tenant_scope(tenant=TENANT):
        svc = native.KnowledgeSources(TENANT, OWNER, registry=_Registry(), authority=lambda: None)
        monkeypatch.setattr(svc, "_embedding_review", lambda plan: _embedding())
        yield svc


def _prepared(service, interval, *, due=False):
    saved = service.save(_plan(interval), expected_revision=0)["source"]
    row = service.sources.get(saved["id"])
    if due:  # the scheduler picks a source up once its next refresh has passed
        row = service.sources.update(row["id"], lambda current: current.update(next_refresh=time.time() - 5),
                                     expected_revision=row["revision"], action="test.due", actor=OWNER)
    return {"source": row["id"], "plan_sha256": row["plan_sha256"], "revision": row["revision"],
            "embedding": _embedding()}, row


def _fill_ledger_with_an_unarchivable_receipt(monkeypatch):
    """A full ledger whose only receipt still awaits its activity record, so
    archiving cannot make room and the create is refused."""
    from maverick import audit

    monkeypatch.setattr(native, "MAX_JOBS", 1)
    with monkeypatch.context() as undelivered:
        undelivered.setattr(audit, "record", lambda *args, **kwargs: False)
        receipt = native.JOB_STORE.create({"id": "KNJ-" + "0" * 32, "source": "other", "tenant": TENANT, "owner": OWNER,
                                           "state": "completed"}, action="knowledge_source.refresh_queued", actor=OWNER)
    assert receipt.get("_audit_pending")


def test_a_refresh_that_cannot_be_recorded_does_not_leave_the_source_claimed(service, monkeypatch):
    prepared, before = _prepared(service, 3600, due=True)
    _fill_ledger_with_an_unarchivable_receipt(monkeypatch)

    with pytest.raises(Exception, match=r"."):
        service.start(prepared, "1" * 32)

    row = service.sources.get(before["id"])
    assert row["active_job"] is None
    assert (row["state"], row["projection_allowed"]) == (before["state"], before["projection_allowed"])
    # A scheduled source is not retried on the scheduler's very next cycle.
    assert row["next_refresh"] >= time.time() + 3600 - 60 and before["next_refresh"] < time.time()
    # The source is not stuck: once the ledger has room, a new refresh starts.
    monkeypatch.setattr(native, "MAX_JOBS", 100)
    current = service.sources.get(before["id"])
    again = dict(prepared, revision=current["revision"])
    assert service.start(again, "2" * 32)["state"] == "queued"


def test_a_job_saved_before_its_create_failed_keeps_the_source_claim(service, monkeypatch):
    # The job ledger saved the record and then failed (e.g. its flush raised):
    # the queued job exists, so its source claim must stay with it.
    prepared, before = _prepared(service, 3600)
    real = service.jobs.create

    def saved_then_failed(*args, **kwargs):
        real(*args, **kwargs)
        raise OSError("flush failed after the record was saved")

    monkeypatch.setattr(service.jobs, "create", saved_then_failed)
    with pytest.raises(OSError):
        service.start(prepared, "5" * 32)
    job_id = "KNJ-" + "5" * 32
    assert service.jobs.get(job_id) is not None
    row = service.sources.get(before["id"])
    assert row["active_job"] == job_id and row["state"] == "queued"


def test_a_started_refresh_still_claims_the_source(service):
    prepared, before = _prepared(service, 3600)
    job = service.start(prepared, "3" * 32)
    row = service.sources.get(before["id"])
    assert job["state"] == "queued" and row["active_job"] == "KNJ-" + "3" * 32 and row["state"] == "queued"


@pytest.mark.parametrize(("interval", "slack_seconds"), [(3600, 3600), (21600, 3600), (86400, 3600), (0, 0)])
def test_a_completed_refresh_stays_fresh_past_its_next_scheduled_refresh(service, interval, slack_seconds):
    prepared, before = _prepared(service, interval)
    job = service.start(prepared, "4" * 32)
    service._finish(service.jobs.get(job["id"]), "completed", "done", items=[], changed=0, unchanged=0, removed=0,
                    snapshot="KNV-" + "b" * 32)
    row = service.sources.get(before["id"])
    assert row["projection_allowed"] is True
    if interval:
        # Latency in the scheduler or the refresh itself must not open a gap: the
        # old snapshot stays usable for an hour after the refresh was due.
        assert row["fresh_until"] - row["next_refresh"] == pytest.approx(slack_seconds, abs=5)
    else:
        assert row.get("next_refresh") is None
        assert row["fresh_until"] - row["last_refresh"] == pytest.approx(86400, abs=5)


def test_a_scheduled_failure_still_backs_off_when_its_receipt_cannot_be_kept(service, monkeypatch):
    """A refresh that fails before it starts (for example its review) records a
    withheld receipt and backs the source off. When the full ledger cannot make
    room the receipt is refused, but the source must still back off rather than
    be retried on the scheduler's next 2-second cycle."""
    from maverick.governed_records import GovernedRecordCapacityError

    _, before = _prepared(service, 3600, due=True)
    _fill_ledger_with_an_unarchivable_receipt(monkeypatch)

    with pytest.raises(GovernedRecordCapacityError):
        native.KnowledgeSources.record_scheduled_error(service.sources.get(before["id"]), RuntimeError("review failed"))

    row = service.sources.get(before["id"])
    assert row["state"] == "withheld" and row["projection_allowed"] is False
    assert row["next_refresh"] >= time.time() + 3600 - 60 and before["next_refresh"] < time.time()


def test_a_full_ledger_archives_its_oldest_receipt_and_admits_the_refresh(service, monkeypatch):
    prepared, before = _prepared(service, 3600, due=True)
    monkeypatch.setattr(native, "MAX_JOBS", 1)
    native.JOB_STORE.create({"id": "KNJ-" + "0" * 32, "source": "other", "tenant": TENANT, "owner": OWNER, "state": "completed"},
                            action="knowledge_source.refresh_queued", actor=OWNER)

    assert service.start(prepared, "5" * 32)["state"] == "queued"
    # The older receipt is kept and readable; it no longer counts against the cap.
    assert native.JOB_STORE.get("KNJ-" + "0" * 32)["state"] == "completed"
    assert native.JOB_STORE.count() == 1


def test_a_queued_refresh_refused_before_it_starts_is_withheld_and_backs_off(service):
    # Its permit expired (or changed, or the owner lost authority): run()
    # refuses before queued -> running. It stayed queued and claimed the source
    # forever, retried every worker cycle, with the schedule stuck behind it.
    prepared, before = _prepared(service, 3600)
    job = service.start(prepared, "6" * 32)
    job = service.jobs.get(job["id"])
    service.jobs.update(job["id"], lambda row: row.update(deadline=time.time() - 1),
                        expected_revision=job["revision"], action="test.expire", actor=OWNER)
    expired = service.jobs.get(job["id"])
    with pytest.raises(PermissionError) as refused:
        service.run(expired["id"])
    native.KnowledgeSources.withhold_queued(expired, refused.value)
    assert service.jobs.get(job["id"])["state"] == "withheld"
    row = service.sources.get(before["id"])
    assert row["active_job"] is None and row["state"] == "withheld"
    assert row["next_refresh"] >= time.time() + 3600 - 60
    # Only a job that is still queued is changed.
    with pytest.raises(native.RecordConflict):
        native.KnowledgeSources.withhold_queued(expired, refused.value)


@pytest.mark.parametrize("interval", [0, 3600])
@pytest.mark.parametrize("interruption", ["receipt_saved", "release_not_saved"])
def test_withholding_recovers_its_source_release_without_rewriting_the_receipt(service, monkeypatch, interval, interruption):
    prepared, before = _prepared(service, interval)
    job = service.start(prepared, "7" * 32)
    store = service.jobs if interruption == "receipt_saved" else service.sources
    real_update = store.update

    def interrupted(*args, **kwargs):
        if interruption == "receipt_saved":
            real_update(*args, **kwargs)
        raise OSError("interrupted between the withheld receipt and source release")

    with monkeypatch.context() as fault:
        fault.setattr(store, "update", interrupted)
        with pytest.raises(OSError):
            native.KnowledgeSources.withhold_queued(job, PermissionError("expired"))

    retained = service.jobs.get(job["id"])
    assert retained["state"] == "withheld"
    assert service.sources.get(before["id"])["active_job"] == job["id"]
    native.KnowledgeSources.withhold_queued(retained)
    assert service.jobs.get(job["id"]) == retained
    released = service.sources.get(before["id"])
    assert released["active_job"] is None
    assert released["state"] == "withheld" and released["projection_allowed"] is False
    if interval:
        assert released["next_refresh"] >= time.time() + interval - 60
    else:
        assert released["next_refresh"] is None
    # A separate reviewed intent can now claim the source again.
    assert service.start(dict(prepared, revision=released["revision"]), "8" * 32)["state"] == "queued"


@pytest.mark.parametrize("state", ["queued", "running", "publishing", "unconfirmed", "completed"])
def test_withheld_recovery_never_takes_over_a_different_job_state(service, state):
    prepared, before = _prepared(service, 3600)
    job = service.start(prepared, "9" * 32)
    current = service.jobs.get(job["id"])
    current = service.jobs.update(job["id"], lambda row: row.update(state=state),
                                  expected_revision=current["revision"], action="test.state", actor=OWNER)
    with pytest.raises(native.RecordConflict):
        native.KnowledgeSources.withhold_queued(current)
    assert service.jobs.get(job["id"]) == current
    assert service.sources.get(before["id"])["active_job"] == job["id"]


def test_withheld_recovery_keeps_a_newer_source_claim(service):
    prepared, before = _prepared(service, 3600)
    job = service.start(prepared, "a" * 32)
    current = service.jobs.get(job["id"])
    retained = service.jobs.update(job["id"], lambda row: row.update(state="withheld"),
                                   expected_revision=current["revision"], action="test.withheld", actor=OWNER)
    source = service.sources.get(before["id"])
    replacement = service.sources.update(source["id"], lambda row: row.update(active_job="KNJ-" + "b" * 32),
                                          expected_revision=source["revision"], action="test.replaced", actor=OWNER)
    with pytest.raises(native.RecordConflict):
        native.KnowledgeSources.withhold_queued(retained)
    assert service.sources.get(before["id"]) == replacement
    assert service.jobs.get(job["id"]) == retained


def test_withheld_recovery_waits_for_its_activity_receipt(service, monkeypatch):
    from maverick import audit

    prepared, before = _prepared(service, 3600)
    job = service.start(prepared, "c" * 32)
    with monkeypatch.context() as unavailable:
        unavailable.setattr(audit, "record", lambda *args, **kwargs: False)
        with pytest.raises(native.RecordConflict):
            native.KnowledgeSources.withhold_queued(job, PermissionError("expired"))
    retained = service.jobs.get(job["id"])
    assert retained["state"] == "withheld" and retained.get("_audit_pending")
    assert service.sources.get(before["id"])["active_job"] == job["id"]
    with pytest.raises(native.RecordConflict):
        native.KnowledgeSources.withhold_queued(retained)
    assert service.jobs.retry_pending() == 1
    native.KnowledgeSources.withhold_queued(retained)
    assert service.sources.get(before["id"])["active_job"] is None


def _set_limits(monkeypatch, section):
    monkeypatch.setattr(config, "load_config", lambda: {"knowledge_sources": section})


class _KnowledgeBase:
    """Stands in for the native Knowledge writer: it keeps every ingested text."""

    def __init__(self):
        self.records = {}

    def ingest_text(self, collection, text, **_kwargs):
        self.records[(collection, hashlib.sha256(text.encode()).hexdigest())] = {"text": text, "metadata": {}}
        return 1

    def exact_document(self, collection, document_sha256):
        return self.records[(collection, document_sha256)]

    def close(self):
        pass


def test_the_notice_states_this_workspaces_configured_limits(service, monkeypatch):
    _, row = _prepared(service, 3600)
    _set_limits(monkeypatch, {})
    assert ("At most 64 items, 4 MiB per download and 256 KiB of extracted source text are supported."
            in service.public(row)["notice"])
    assert "Each refresh must finish within 5 minutes." in service.public(row)["notice"]
    _set_limits(monkeypatch, {"max_items": 200, "max_download_mib": 8, "max_text_kib": 512, "max_refresh_minutes": 30})
    assert ("At most 200 items, 8 MiB per download and 512 KiB of extracted source text are supported. "
            "Each refresh must finish within 30 minutes." in service.public(row)["notice"])


def test_an_invalid_limit_refuses_the_saved_source_listing_with_its_name(service, monkeypatch):
    _, row = _prepared(service, 3600)
    _set_limits(monkeypatch, {"max_text_kib": 0})
    with pytest.raises(config.KnowledgeSourcesConfigError, match=r"knowledge_sources\.max_text_kib must be a whole number"):
        service.public(row)


def _start_refresh(service, monkeypatch, texts, limits, *, knowledge_base=None):
    """Save a source, then queue and run a refresh under ``limits`` whose inventory lists one file per text."""
    rows = [{"id": name, "name": f"{name}.txt", "revision": "r1", "mime": "text/plain", "size": None,
             "citation": "", "kind": "file"} for name in texts]
    monkeypatch.setattr(native.readers, "inventory", lambda binding, actor, guard: rows)
    monkeypatch.setattr(native.readers, "document", lambda binding, actor, item, guard: (texts[item["id"]], "r" * 64, {"warnings": []}))
    monkeypatch.setattr(service, "_open", lambda: knowledge_base if knowledge_base is not None else _KnowledgeBase())
    prepared, _ = _prepared(service, 3600)
    _set_limits(monkeypatch, limits)
    job = service.start(dict(prepared, inventory_sha256=native.digest(rows)), "e" * 32)
    return service.run(job["id"])


def test_a_refresh_refuses_extracted_text_above_the_configured_limit_and_names_it(service, monkeypatch):
    result = _start_refresh(service, monkeypatch, {"first": "a" * 600, "second": "b" * 600}, {"max_text_kib": 1})
    assert result["state"] == "partial"
    assert [item["state"] for item in result["items"]] == ["imported", "error"]
    assert result["items"][1]["message"] == "The extracted source exceeds 1 KiB. Choose a smaller source."


def test_a_refresh_admits_text_within_a_raised_limit(service, monkeypatch):
    # 390 KiB in all: over the 256 KiB default, so only the raised limit admits it.
    monkeypatch.setattr(service, "_publish", lambda job, items, kb: {"id": "KNV-" + "c" * 32, "reference": {"id": "ref"}})
    result = _start_refresh(service, monkeypatch, {"first": "a" * 200_000, "second": "b" * 200_000}, {"max_text_kib": 512})
    assert result["state"] == "completed"
    assert [item["state"] for item in result["items"]] == ["imported", "imported"]


def test_a_refresh_with_an_invalid_limit_fails_with_the_named_setting(service, monkeypatch):
    result = _start_refresh(service, monkeypatch, {"first": "a" * 600}, {"max_text_kib": 0})
    assert result["state"] == "failed"
    assert result["message"] == "knowledge_sources.max_text_kib must be a whole number from 1 to 8192"


def _retained_snapshot(service, items, *, text):
    """A complete snapshot of ``items`` retained under a saved source, as a refresh writes it."""
    _, row = _prepared(service, 3600)
    version = "f" * 32
    identifier = "KNV-" + native.digest([row["id"], version])[:32]
    kb, manifest = _KnowledgeBase(), []
    for number in range(items):
        collection = f"remote-{row['id'][4:]}-{number:016x}"
        document_sha = hashlib.sha256(f"{text}{number}".encode()).hexdigest()
        record = {"text": f"{text}{number}", "metadata": {"remote_source_id": row["id"], "remote_item_id": f"item-{number}"}}
        kb.records[(collection, document_sha)] = record
        manifest.append({"remote_id": f"item-{number}", "collection": collection, "document_sha256": document_sha,
                         "native_document_sha256": native.digest(native._committed_document(record))})
    service.snapshots.create({"id": identifier, "tenant": TENANT, "owner": OWNER, "version": version, "source": row["id"],
                              "plan_sha256": native.content_binding(row["plan"]), "items": manifest, "binding": row["plan"]["binding"],
                              "name": row["plan"]["name"], "observed_at": time.time(), "reference": None},
                             action="test.snapshot", actor=OWNER)
    return kb, row["id"], version


def test_an_existing_snapshot_validates_under_any_allowed_item_limit(service, monkeypatch):
    kb, identifier, version = _retained_snapshot(service, 100, text="x")
    _set_limits(monkeypatch, {"max_items": 1})  # lower than the manifest it was retained under
    assert len(native.exact_source_snapshot(TENANT, identifier, version, knowledge_base=kb)["items"]) == 100


def test_a_manifest_above_the_hard_ceiling_is_still_refused(service):
    kb, identifier, version = _retained_snapshot(service, 1001, text="x")
    with pytest.raises(ValueError, match="item manifest is incomplete"):
        native.exact_source_snapshot(TENANT, identifier, version, knowledge_base=kb)


def test_the_projection_text_bound_follows_the_current_max_text_kib(service, monkeypatch):
    kb, identifier, version = _retained_snapshot(service, 3, text="t" * 600)
    _set_limits(monkeypatch, {"max_text_kib": 1})
    with pytest.raises(ValueError, match="bounded text projection"):
        native.exact_source_snapshot(TENANT, identifier, version, knowledge_base=kb)
    _set_limits(monkeypatch, {"max_text_kib": 2})
    assert native.exact_source_snapshot(TENANT, identifier, version, knowledge_base=kb)["text_bytes"] == 3 * 601


def _prose(kib, seed):
    """Plain ASCII prose of ``kib`` KiB, distinct for each ``seed``."""
    line = f"Document {seed}: staff report each incident within one working day, and managers keep the record for seven years.\n"
    return (line * (kib * 1024 // len(line) + 1))[: kib * 1024]


def _real_knowledge_base(tmp_path):
    """The real Knowledge writer (default chunking) on a local store."""
    from maverick_knowledge import DeterministicEmbedder, KnowledgeBase, SqliteVectorStore

    return KnowledgeBase(store=SqliteVectorStore(tmp_path / "knowledge.db"), embedder=DeterministicEmbedder(8))


def _retained_real_snapshot(service, kb, texts):
    """A complete snapshot whose documents went through the real Knowledge writer, as a refresh stores them."""
    _, row = _prepared(service, 3600)
    version = "f" * 32
    identifier = "KNV-" + native.digest([row["id"], version])[:32]
    manifest = []
    for number, text in enumerate(texts):
        collection = f"remote-{row['id'][4:]}-{number:016x}"
        remote_id = f"item-{number}"
        kb.ingest_text(collection, text, source=f"remote:{row['id']}:{remote_id}", trust_tier=1, sensitivity="internal",
                       ingested_by=OWNER, extra_meta={"remote_source_id": row["id"], "remote_item_id": remote_id}, replace_source=True)
        document_sha = hashlib.sha256(text.encode()).hexdigest()
        record = kb.exact_document(collection, document_sha)
        manifest.append({"remote_id": remote_id, "collection": collection, "document_sha256": document_sha,
                         "native_document_sha256": native.digest(native._committed_document(record))})
    service.snapshots.create({"id": identifier, "tenant": TENANT, "owner": OWNER, "version": version, "source": row["id"],
                              "plan_sha256": native.content_binding(row["plan"]), "items": manifest, "binding": row["plan"]["binding"],
                              "name": row["plan"]["name"], "observed_at": time.time(), "reference": None},
                             action="test.snapshot", actor=OWNER)
    return row["id"], version


def test_a_retained_source_at_its_configured_text_bound_still_projects(service, monkeypatch, tmp_path):
    # Every chunk is projected, and the chunker overlaps neighbours, so the
    # exact projection is about 1.4 times the text. 390 KiB is within 512 KiB.
    kb = _real_knowledge_base(tmp_path)
    try:
        source, version = _retained_real_snapshot(service, kb, [_prose(195, 1), _prose(195, 2)])
        _set_limits(monkeypatch, {"max_text_kib": 512})
        inspected = inspect_existing_source(TENANT, native.source_ref(source, version), knowledge_base=kb)
    finally:
        kb.close()
    assert len(inspected["content_sha256"]) == 64


def test_a_refresh_at_the_configured_text_bound_completes(service, monkeypatch, tmp_path):
    kb = _real_knowledge_base(tmp_path)
    result = _start_refresh(service, monkeypatch, {"first": _prose(195, 1), "second": _prose(195, 2)},
                            {"max_text_kib": 512}, knowledge_base=kb)
    assert result["state"] == "completed", result["message"]
    assert [item["state"] for item in result["items"]] == ["imported", "imported"]


@pytest.mark.parametrize("operation", [None, "d" * 32])
def test_a_save_under_an_invalid_limit_writes_nothing(service, monkeypatch, operation):
    _set_limits(monkeypatch, {"max_text_kib": 0})
    with pytest.raises(config.KnowledgeSourcesConfigError, match=r"knowledge_sources\.max_text_kib must be a whole number"):
        service.save(_plan(3600), expected_revision=0, operation=operation)
    assert service.sources.list(limit=10) == []
    if operation is not None:
        assert native.DECISION_STORE.get("KNO-" + operation) is None


def test_a_refresh_defaults_to_a_five_minute_deadline_and_budget(service, monkeypatch):
    _set_limits(monkeypatch, {})
    prepared, _ = _prepared(service, 3600)
    before = time.time()
    job = service.start(prepared, "6" * 32)
    stored = service.jobs.get(job["id"])
    assert stored["deadline"] - before == pytest.approx(300, abs=5)
    assert stored["max_wall_seconds"] == 300


def test_a_raised_refresh_time_limit_raises_the_deadline_and_the_budget_wall_cap(service, monkeypatch):
    from maverick.tenant import provider_admission

    prepared, _ = _prepared(service, 3600)
    _set_limits(monkeypatch, {"max_refresh_minutes": 30})
    before = time.time()
    job = service.start(prepared, "7" * 32)
    stored = service.jobs.get(job["id"])
    assert stored["deadline"] - before == pytest.approx(1800, abs=5)
    # A paid embedder gets a budget whose wall cap is the same reviewed limit as the deadline.
    monkeypatch.setattr(provider_admission, "bind_budget", lambda budget, principal, scope=None: None)
    kb = SimpleNamespace(embedder=SimpleNamespace(dim=8))
    service._prepare_embedder(kb, dict(stored, prepared={"embedding": {"billing": {"unit": "test"}}}))
    assert kb.embedder.budget.max_wall_seconds == 1800


def test_a_refresh_queued_before_the_setting_existed_keeps_its_five_minute_budget(service, monkeypatch):
    from maverick.tenant import provider_admission

    prepared, _ = _prepared(service, 3600)
    _set_limits(monkeypatch, {})
    job = service.start(prepared, "9" * 32)
    legacy = {key: value for key, value in service.jobs.get(job["id"]).items() if key != "max_wall_seconds"}
    monkeypatch.setattr(provider_admission, "bind_budget", lambda budget, principal, scope=None: None)
    kb = SimpleNamespace(embedder=SimpleNamespace(dim=8))
    service._prepare_embedder(kb, dict(legacy, prepared={"embedding": {"billing": {"unit": "test"}}}))
    assert kb.embedder.budget.max_wall_seconds == 300


@pytest.mark.parametrize("value", [0, 61, 2.5])
def test_an_out_of_range_refresh_time_limit_fails_the_refresh_with_the_named_setting(service, monkeypatch, value):
    result = _start_refresh(service, monkeypatch, {"first": "a" * 600}, {"max_refresh_minutes": value})
    assert result["state"] == "failed"
    assert result["message"] == "knowledge_sources.max_refresh_minutes must be a whole number from 1 to 60"
    assert native.JOB_STORE.get(result["id"])["max_wall_seconds"] == 300


def _grant(**values):
    """One item's permission record, with every field present."""
    return {"emails": [], "domains": [], "anyone": False, "has_group_grants": False, "unknown": False, **values}


def _reader(email="alice@contoso.com"):
    return SimpleNamespace(action="analyze", purpose="support", principal="user:alice", verified_email=email)


def _grant_items(service, identifier, version, permissions):
    """Give a retained snapshot's items the permission records a filtered refresh would store."""
    snapshot_id = "KNV-" + native.digest([identifier, version])[:32]
    row = service.snapshots.get(snapshot_id)
    items = [dict(item, permissions=permissions[item["remote_id"]]) if item["remote_id"] in permissions else dict(item)
             for item in row["items"]]
    service.snapshots.update(snapshot_id, lambda current: current.update(items=items), expected_revision=row["revision"],
                             action="test.permissions", actor=OWNER)
    source = service.sources.get(identifier)
    service.sources.update(identifier, lambda current: current.update(projection_allowed=True, snapshot=snapshot_id,
                                                                      fresh_until=time.time() + 3600),
                           expected_revision=source["revision"], action="test.use", actor=OWNER)


def _shared_items():
    """Seven items, one for each case the filter must decide."""
    return {
        "by-email": _grant(emails=["alice@contoso.com"]),
        "by-domain": _grant(domains=["contoso.com"]),
        "by-link": _grant(anyone=True),
        "other-user": _grant(emails=["bob@contoso.com"]),
        "group-only": _grant(has_group_grants=True),
        "unknown": _grant(unknown=True),
        "group-and-alice": _grant(emails=["alice@contoso.com"], has_group_grants=True),
    }


def test_the_filter_admits_only_items_shared_with_the_signed_in_address(service, monkeypatch):
    kb, identifier, version = _retained_snapshot(service, 8, text="x")
    permissions = dict(zip([f"item-{n}" for n in range(8)], list(_shared_items().values()) + [None], strict=True))
    _grant_items(service, identifier, version, {key: value for key, value in permissions.items() if value is not None})
    _set_limits(monkeypatch, {"permission_filter": "by_email"})
    result = native.exact_source_snapshot(TENANT, identifier, version, knowledge_base=kb, authority=_reader())
    visible = {item["item"]["remote_id"] for item in result["visible_items"]}
    # The first seven are in the grant map; item-7 has no permissions record at all.
    assert visible == {"item-0", "item-1", "item-2", "item-6"}
    assert result["withheld_for_permissions"] == 4
    assert len(result["items"]) == 8  # the commitment still covers every item


def test_the_filter_off_ignores_permission_records(service, monkeypatch):
    kb, identifier, version = _retained_snapshot(service, 2, text="x")
    _grant_items(service, identifier, version, {"item-0": _grant(emails=["bob@contoso.com"])})
    _set_limits(monkeypatch, {})
    result = native.exact_source_snapshot(TENANT, identifier, version, knowledge_base=kb, authority=_reader())
    assert len(result["visible_items"]) == 2 and result["withheld_for_permissions"] == 0


def test_a_principal_without_a_verified_email_sees_nothing_under_the_filter(service, monkeypatch):
    kb, identifier, version = _retained_snapshot(service, 2, text="x")
    _grant_items(service, identifier, version, {"item-0": _grant(anyone=True), "item-1": _grant(domains=["contoso.com"])})
    _set_limits(monkeypatch, {"permission_filter": "by_email"})
    result = native.exact_source_snapshot(TENANT, identifier, version, knowledge_base=kb, authority=_reader(""))
    assert result["visible_items"] == [] and result["withheld_for_permissions"] == 2


def test_an_old_snapshot_without_permission_data_is_withheld_until_refreshed(service, monkeypatch):
    kb, identifier, version = _retained_snapshot(service, 3, text="x")
    _grant_items(service, identifier, version, {})
    _set_limits(monkeypatch, {"permission_filter": "by_email"})
    result = native.exact_source_snapshot(TENANT, identifier, version, knowledge_base=kb, authority=_reader())
    assert result["visible_items"] == [] and result["withheld_for_permissions"] == 3


def test_a_document_withheld_by_permission_is_refused_at_use(service, monkeypatch):
    kb, identifier, version = _retained_snapshot(service, 2, text="x")
    _grant_items(service, identifier, version, {"item-0": _grant(emails=["bob@contoso.com"]),
                                                "item-1": _grant(domains=["contoso.com"])})
    _set_limits(monkeypatch, {"permission_filter": "by_email"})
    snapshot = service.snapshots.get("KNV-" + native.digest([identifier, version])[:32])
    by_id = {item["remote_id"]: item for item in snapshot["items"]}
    native.require_remote_document_authority(TENANT, by_id["item-1"]["collection"], by_id["item-1"]["document_sha256"], _reader())
    with pytest.raises(PermissionError):
        native.require_remote_document_authority(TENANT, by_id["item-0"]["collection"], by_id["item-0"]["document_sha256"], _reader())


def _capturing_publish(service, monkeypatch):
    """Keep the manifest a refresh would retain, instead of registering it."""
    captured = []

    def publish(job, items, kb):
        captured.append(items)
        return {"id": "KNV-" + "c" * 32, "reference": {"id": "ref"}}

    monkeypatch.setattr(service, "_publish", publish)
    return captured


def test_a_refresh_with_the_filter_off_reads_and_stores_no_permissions(service, monkeypatch):
    def unexpected(*args):
        raise AssertionError("no permission is read while the filter is off")

    monkeypatch.setattr(native.readers, "permissions", unexpected)
    captured = _capturing_publish(service, monkeypatch)
    result = _start_refresh(service, monkeypatch, {"first": "a" * 600}, {})
    assert result["state"] == "completed"
    assert captured and all("permissions" not in item for item in captured[0])


def test_a_refresh_with_the_filter_on_stores_each_items_permission_record(service, monkeypatch):
    records = {"first": _grant(emails=["alice@contoso.com"]), "second": _grant(anyone=True)}
    monkeypatch.setattr(native.readers, "permissions", lambda binding, actor, item, guard: records[item["id"]])
    captured = _capturing_publish(service, monkeypatch)
    result = _start_refresh(service, monkeypatch, {"first": "a" * 600, "second": "b" * 600}, {"permission_filter": "by_email"})
    assert result["state"] == "completed"
    stored = {item["remote_id"]: item for item in captured[0]}
    assert stored["first"]["permissions"] == records["first"]
    assert stored["second"]["permissions"] == records["second"]
    # Only the reviewed record fields are kept: no token, no raw provider payload.
    assert all(set(item["permissions"]) == set(records["first"]) for item in captured[0])
    assert "token" not in repr(captured[0]).lower()


def test_a_permission_read_failure_marks_the_item_unknown_and_the_refresh_completes(service, monkeypatch):
    captured = _capturing_publish(service, monkeypatch)
    # The real reader refuses this test's binding, which is the same as a provider read that fails.
    result = _start_refresh(service, monkeypatch, {"first": "a" * 600}, {"permission_filter": "by_email"})
    assert result["state"] == "completed", result["message"]
    assert captured[0][0]["permissions"] == _grant(unknown=True)


def test_the_projection_shows_only_the_visible_items_and_keeps_the_commitment(service, monkeypatch, tmp_path):
    kb = _real_knowledge_base(tmp_path)
    try:
        source, version = _retained_real_snapshot(service, kb, ["Shared handbook WORDMARK-ALPHA text.",
                                                                "Restricted payroll WORDMARK-BETA text."])
        _grant_items(service, source, version, {"item-0": _grant(emails=["alice@contoso.com"]),
                                                "item-1": _grant(emails=["bob@contoso.com"])})
        ref = native.source_ref(source, version)
        _set_limits(monkeypatch, {})
        full = inspect_existing_source(TENANT, ref, knowledge_base=kb)
        _set_limits(monkeypatch, {"permission_filter": "by_email"})
        filtered = inspect_existing_source(TENANT, ref, knowledge_base=kb, include_retrieval_chunks=True, remote_authority=_reader())
    finally:
        kb.close()
    # The commitment covers every retained item, so the registered version still matches for every reader.
    assert filtered["content_sha256"] == full["content_sha256"]
    assert "WORDMARK-ALPHA" in filtered["summary"] and "WORDMARK-BETA" not in filtered["summary"]
    assert filtered["retrieval_chunks"] and all("WORDMARK-BETA" not in chunk for chunk in filtered["retrieval_chunks"])
    assert filtered["permissions_withheld"] == 1


def _refresh_same_source(service, monkeypatch, identifier, texts, limits, *, knowledge_base, operation):
    """Queue and run another refresh of an existing saved source, reusing the knowledge base it wrote."""
    rows = [{"id": name, "name": f"{name}.txt", "revision": "r1", "mime": "text/plain", "size": None,
             "citation": "", "kind": "file"} for name in texts]
    monkeypatch.setattr(native.readers, "inventory", lambda binding, actor, guard: rows)
    monkeypatch.setattr(native.readers, "document", lambda binding, actor, item, guard: (texts[item["id"]], "r" * 64, {"warnings": []}))
    monkeypatch.setattr(service, "_open", lambda: knowledge_base)
    row = service.sources.get(identifier)
    prepared = {"source": identifier, "plan_sha256": row["plan_sha256"], "revision": row["revision"], "embedding": _embedding()}
    _set_limits(monkeypatch, limits)
    job = service.start(dict(prepared, inventory_sha256=native.digest(rows)), operation)
    return service.run(job["id"])


def _publish_as_current_snapshot(service, monkeypatch):
    """Retain each refresh's manifest as the source's current snapshot, without the registry step."""
    def publish(job, items, kb):
        identifier = "KNV-" + native.digest([job["id"]])[:32]
        service.snapshots.create({"id": identifier, "tenant": TENANT, "owner": OWNER, "version": native.digest([job["id"]])[:32],
                                  "source": job["source"], "plan_sha256": native.content_binding(job["plan"]),
                                  "items": sorted(items, key=lambda row: row["remote_id"]), "binding": job["plan"]["binding"],
                                  "name": job["plan"]["name"], "observed_at": time.time(), "reference": None},
                                 action="test.snapshot", actor=OWNER)
        source = service.sources.get(job["source"])
        service.sources.update(job["source"], lambda current: current.update(snapshot=identifier), expected_revision=source["revision"],
                               action="test.snapshot_link", actor=OWNER)
        return {"id": identifier, "reference": {"id": "ref"}}

    monkeypatch.setattr(service, "_publish", publish)


def test_a_filter_off_refresh_drops_the_permission_records_it_reuses(service, monkeypatch):
    # A sharing grant read while the filter was on must not govern the item after a filter-off refresh.
    kb, texts = _KnowledgeBase(), {"first": "a" * 600}
    monkeypatch.setattr(native.readers, "permissions", lambda binding, actor, item, guard: _grant(emails=["alice@contoso.com"]))
    _publish_as_current_snapshot(service, monkeypatch)
    assert _start_refresh(service, monkeypatch, texts, {"permission_filter": "by_email"}, knowledge_base=kb)["state"] == "completed"
    identifier = service.jobs.get("KNJ-" + "e" * 32)["source"]
    assert _refresh_same_source(service, monkeypatch, identifier, texts, {}, knowledge_base=kb, operation="1" * 32)["state"] == "completed"
    # The revision is unchanged, so the item was reused; its stored record must not keep the old grant.
    snapshot = service.snapshots.get(service.sources.get(identifier)["snapshot"])
    stored = snapshot["items"][0]
    assert stored["provider_revision"] == "r1" and "permissions" not in stored
    # Filter back on without a refresh: the item is withheld, and the page asks for a refresh.
    _set_limits(monkeypatch, {"permission_filter": "by_email"})
    assert native._visible(stored, "alice@contoso.com") is False
    assert service.public(service.sources.get(identifier))["permissions_need_refresh"] is True


def test_a_projection_without_an_authority_projects_no_item_under_the_filter(service, monkeypatch):
    kb, identifier, version = _retained_snapshot(service, 2, text="x")
    _grant_items(service, identifier, version, {"item-0": _grant(anyone=True), "item-1": _grant(domains=["contoso.com"])})
    _set_limits(monkeypatch, {"permission_filter": "by_email"})
    result = native.exact_source_snapshot(TENANT, identifier, version, knowledge_base=kb)
    assert result["visible_items"] == [] and result["withheld_for_permissions"] == 2
    assert len(result["items"]) == 2  # the commitment still covers every item
