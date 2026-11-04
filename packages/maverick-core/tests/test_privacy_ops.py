"""Privacy ops record types: DPA review, AI registry, RoPA, DSAR tracker."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick import privacy_ops


@pytest.fixture(autouse=True)
def _fresh_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))


GOOD_DPA = """
Data Processing Agreement between Controller and Acme Corp.
The processor shall process personal data only on documented instructions
from the controller. All personnel are bound by confidentiality obligations.
The processor implements the technical and organisational measures of
Article 32, including encryption of data at rest. Sub-processors require
prior written authorization and flow-down of these terms. The processor
shall assist the controller with data subject requests. The processor shall
notify the controller of any personal data breach without undue delay.
Upon termination the processor shall delete or return all personal data.
The controller has audit and inspection rights. International transfers are
covered by Standard Contractual Clauses. Data is retained for 12 months
(retention schedule, Annex 2).
"""

BAD_DPA = """
Master agreement. The vendor provides marketing analytics over customer
personal data, including transfer to processing centers outside the EU.
Payment terms are net 30. Either party may terminate with notice.
"""


class TestDpaReview:
    def test_complete_dpa_scores_low_residual(self):
        r = privacy_ops.review_dpa("Acme Corp", GOOD_DPA,
                                   document_name="acme-dpa.pdf")
        assert r["clauses_total"] == len(privacy_ops.DPA_CHECKLIST)
        assert r["clauses_present"] >= 9
        assert r["residual_risk"] in ("minimal", "low")
        # Transfers are declared, so inherent exposure stays high even
        # though the safeguards clause is present.
        assert r["inherent_risk"] == "high"
        by_key = {c["key"]: c for c in r["clauses"]}
        assert by_key["security"]["status"] == "present"
        assert by_key["security"]["excerpt"], "verdicts carry evidence"

    def test_bare_contract_scores_high_residual_with_missing_clauses(self):
        r = privacy_ops.review_dpa("SketchyVendor", BAD_DPA)
        assert r["residual_risk"] == "high"
        by_key = {c["key"]: c for c in r["clauses"]}
        assert by_key["instructions"]["status"] == "missing"
        assert by_key["breach"]["status"] == "missing"
        assert "international transfers" in r["exposures"]

    def test_round_trip_and_summaries(self):
        r = privacy_ops.review_dpa("Acme Corp", GOOD_DPA)
        assert privacy_ops.get_dpa_review(r["id"])["vendor"] == "Acme Corp"
        rows = privacy_ops.list_dpa_reviews()
        assert rows[0]["id"] == r["id"]
        assert "clauses" not in rows[0], "summaries stay light"
        assert privacy_ops.get_dpa_review("../../etc/passwd") is None

    def test_long_actor_labels_remain_collision_resistant(self):
        common = "user:" + ("a" * 300)
        first = privacy_ops.review_dpa(
            "One", GOOD_DPA, reviewed_by=common + "-one",
        )
        second = privacy_ops.review_dpa(
            "Two", GOOD_DPA, reviewed_by=common + "-two",
        )
        assert len(first["reviewed_by"]) <= 256
        assert len(second["reviewed_by"]) <= 256
        assert first["reviewed_by"] != second["reviewed_by"]
        assert "#sha256:" in first["reviewed_by"]


class TestAiRegistry:
    def test_high_risk_classification_with_signals(self):
        r = privacy_ops.register_ai_system(
            "CV screener", "Ranks job candidates by resume for hiring")
        assert r["tier"] == "high"
        assert any("employment" in s for s in r["signals"])
        assert any("Art. 43" in o for o in r["obligations"])

    def test_prohibited_and_limited_and_minimal(self):
        assert privacy_ops.classify_ai_system(
            "CitizenRank", "social scoring of residents")["tier"] == "prohibited"
        assert privacy_ops.classify_ai_system(
            "HelpBot", "customer service chatbot")["tier"] == "limited"
        assert privacy_ops.classify_ai_system(
            "SpamFilter", "filters junk mail internally")["tier"] == "minimal"

    def test_registry_round_trip(self):
        r = privacy_ops.register_ai_system("HelpBot", "support chatbot",
                                           provider="Anthropic", owner="cx")
        assert privacy_ops.get_ai_system(r["id"])["provider"] == "Anthropic"
        assert privacy_ops.list_ai_systems()[0]["id"] == r["id"]


class TestRopa:
    def test_upsert_and_export_shape(self):
        r = privacy_ops.upsert_ropa({
            "activity": "Email marketing", "purpose": "Campaigns",
            "data_categories": "Contact data", "retention": "24 months"})
        rid = r["id"]
        privacy_ops.upsert_ropa(
            {"retention": "12 months"},
            ropa_id=rid,
            expected_revision=r["revision"],
        )
        rows = privacy_ops.export_ropa_art30()
        row = next(x for x in rows if x["id"] == rid)
        assert row["retention"] == "12 months"
        assert row["activity"] == "Email marketing"   # untouched fields kept
        assert set(privacy_ops.ROPA_FIELDS) <= set(row)

    def test_draft_from_assessment_maps_answers(self):
        from maverick.assessment import AssessmentSession, save_session
        s = AssessmentSession(type="pia", subject="Acme CRM")
        s.record("pia_transfers", "yes", "us-east-1, no SCCs")
        s.record("pia_retention", "no")
        s.record("pia_security", "yes")
        s.record("pia_processors", "no")
        save_session(s)
        r = privacy_ops.draft_ropa_from_assessment(s.id)
        assert r is not None
        assert "Acme CRM" in r["activity"]
        assert "WITHOUT Chapter V safeguard" in r["transfers"]
        assert "No defined retention" in r["retention"]
        assert "without countersigned DPA" in r["recipients"]
        assert r["assessment_id"] == s.id

    def test_draft_from_unknown_assessment_is_none(self):
        assert privacy_ops.draft_ropa_from_assessment("nope") is None

    def test_atomic_partial_updates_and_stale_revision_cas(self, monkeypatch):
        import maverick.audit as audit

        monkeypatch.setattr(audit, "record", lambda *a, **k: True)
        created = privacy_ops.upsert_ropa({
            "activity": "Payroll", "purpose": "Pay employees",
        })
        assert created is not None
        rid = created["id"]
        initial_revision = created["revision"]

        updates = [
            ("retention", {"retention": "7 years"}),
            ("controller", {"controller": "Acme Ltd"}),
        ]

        def attempt(item):
            label, payload = item
            try:
                return label, privacy_ops.upsert_ropa(
                    payload,
                    ropa_id=rid,
                    expected_revision=initial_revision,
                )
            except privacy_ops.RecordConflict:
                return label, None

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, updates))

        assert sum(record is not None for _, record in outcomes) == 1

        final = next(r for r in privacy_ops.list_ropa() if r["id"] == rid)
        assert final["revision"] == initial_revision + 1
        losing_label = next(label for label, record in outcomes if record is None)
        losing_payload = dict(updates)[losing_label]
        retried = privacy_ops.upsert_ropa(
            losing_payload,
            ropa_id=rid,
            expected_revision=final["revision"],
        )
        assert retried is not None
        assert retried["retention"] == "7 years"
        assert retried["controller"] == "Acme Ltd"
        assert retried["revision"] == initial_revision + 2
        with pytest.raises(ValueError, match="revision is required"):
            privacy_ops.upsert_ropa(
                {"purpose": "unversioned overwrite"},
                ropa_id=rid,
            )
        with pytest.raises(privacy_ops.RecordConflict):
            privacy_ops.upsert_ropa(
                {"purpose": "stale overwrite"},
                ropa_id=rid,
                expected_revision=initial_revision,
            )


class TestDsar:
    def test_open_sets_statutory_due_date(self):
        r = privacy_ops.open_dsar("jordan@example.com", "access",
                                  channel="email")
        assert r["status"] == "open"
        listed = privacy_ops.list_dsars()[0]
        assert 28 <= listed["days_left"] <= 30
        assert listed["overdue"] is False
        with pytest.raises(ValueError):
            privacy_ops.open_dsar("x", "espionage")

    def test_access_fulfillment_runs_real_export(self, tmp_path):
        r = privacy_ops.open_dsar("jordan@example.com", "access",
                                  channel="email")
        done = privacy_ops.fulfill_dsar(r["id"])
        assert done["status"] == "fulfilled"
        path = done["fulfillment"]["export_path"]
        bundle = json.loads(open(path, encoding="utf-8").read())
        assert bundle["subject"]["user_id"] == "jordan@example.com"
        assert "counts" in done["fulfillment"]
        # The bundle next door must not be mistaken for a request record
        # (regression: the store globs *.json, exports live in a subdir).
        listed = privacy_ops.list_dsars()
        assert [x["status"] for x in listed if x["id"] == r["id"]] == ["fulfilled"]

    def test_unreadable_world_does_not_fulfill_or_claim_zero_holdings(self, monkeypatch):
        opened = privacy_ops.open_dsar("alice", "access", channel="email")

        class UnreadableWorld:
            def list_conversations(self, _channel):
                raise OSError("private world path should not be shown")

        monkeypatch.setattr(
            "maverick.dsar._resolve_world",
            lambda _tenant, *, strict=False: UnreadableWorld(),
        )

        worksheet = privacy_ops.dsar_estate_worksheet(opened["id"])
        assert worksheet["platform_holdings"] == {"enabled": False, "error": "unavailable"}
        with pytest.raises(ValueError, match="could not be verified"):
            privacy_ops.fulfill_dsar(opened["id"])
        assert privacy_ops.get_dsar(opened["id"])["status"] == "open"
        assert privacy_ops.read_dsar_export(opened["id"]) is None

    def test_malformed_audit_file_does_not_fulfill_or_claim_zero_holdings(self):
        from maverick.paths import data_dir

        opened = privacy_ops.open_dsar("alice", "access", channel="email")
        audit_dir = data_dir("audit")
        audit_dir.mkdir(parents=True, exist_ok=True)
        (audit_dir / "2026-01-01.ndjson").write_text(
            "{malformed audit record}\n", encoding="utf-8"
        )

        worksheet = privacy_ops.dsar_estate_worksheet(opened["id"])
        assert worksheet["platform_holdings"] == {"enabled": False, "error": "unavailable"}
        with pytest.raises(ValueError, match="could not be verified"):
            privacy_ops.fulfill_dsar(opened["id"])
        assert privacy_ops.get_dsar(opened["id"])["status"] == "open"
        assert privacy_ops.read_dsar_export(opened["id"]) is None

    def test_close_removes_export_only_after_durable_close(self, monkeypatch):
        opened = privacy_ops.open_dsar("jordan@example.com", "access", channel="email")
        fulfilled = privacy_ops.fulfill_dsar(opened["id"])
        path = Path(fulfilled["fulfillment"]["export_path"])
        assert path.is_file()  # Available to deliver before close.
        original_unlink = Path.unlink
        observed = []

        def unlink_after_commit(target, *args, **kwargs):
            if target == path:
                observed.append(privacy_ops._DSAR.load(opened["id"])["status"])
            return original_unlink(target, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", unlink_after_commit)
            closed = privacy_ops.close_dsar(opened["id"], closed_by="privacy-lead")

        assert observed == ["closed"]
        assert closed["status"] == "closed"
        assert closed["export_cleanup"]["status"] == "removed"
        assert not path.exists()
        revision = closed["revision"]
        repeated = privacy_ops.close_dsar(opened["id"])
        assert repeated["export_cleanup"]["status"] == "removed"
        assert repeated["revision"] == revision

    def test_failed_export_cleanup_is_visible_and_retryable(self, monkeypatch):
        opened = privacy_ops.open_dsar("jordan@example.com", "portability", channel="email")
        fulfilled = privacy_ops.fulfill_dsar(opened["id"])
        path = Path(fulfilled["fulfillment"]["export_path"])
        original_unlink = Path.unlink

        def refuse_once(target, *args, **kwargs):
            if target == path:
                raise PermissionError("simulated file lock")
            return original_unlink(target, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(Path, "unlink", refuse_once)
            first = privacy_ops.close_dsar(opened["id"])

        assert first["status"] == "closed" and path.is_file()
        assert first["export_cleanup"]["status"] == "failed"
        assert "could not be safely removed" in first["export_cleanup"]["message"]
        assert privacy_ops.get_dsar(opened["id"])["export_cleanup"]["status"] == "failed"
        retried = privacy_ops.close_dsar(opened["id"])
        assert retried["status"] == "closed"
        assert retried["export_cleanup"]["status"] == "removed"
        assert not path.exists()

    def test_close_refuses_tampered_export_path_and_artifact(self, tmp_path):
        opened = privacy_ops.open_dsar("jordan@example.com", "access", channel="email")
        fulfilled = privacy_ops.fulfill_dsar(opened["id"])
        path = Path(fulfilled["fulfillment"]["export_path"])
        unrelated = tmp_path / "unrelated.json"
        unrelated.write_text("leave me alone", encoding="utf-8")

        def plant_other_path(record):
            record["fulfillment"] = {**record["fulfillment"], "export_path": str(unrelated)}

        privacy_ops._DSAR.update(opened["id"], plant_other_path)
        refused = privacy_ops.close_dsar(opened["id"])
        assert refused["export_cleanup"]["status"] == "failed"
        assert path.is_file() and unrelated.read_text(encoding="utf-8") == "leave me alone"

        def restore_path(record):
            record["fulfillment"] = {**record["fulfillment"], "export_path": str(path)}

        privacy_ops._DSAR.update(opened["id"], restore_path)
        path.write_text("{}", encoding="utf-8")
        refused_artifact = privacy_ops.close_dsar(opened["id"])
        assert refused_artifact["export_cleanup"]["status"] == "failed"
        assert path.is_file() and path.read_text(encoding="utf-8") == "{}"

    def test_close_removes_bound_orphan_from_interrupted_fulfillment(self):
        from maverick.file_lock import ensure_private_directory
        from maverick.paths import data_dir

        opened = privacy_ops.open_dsar("jordan@example.com", "access", channel="email")
        out_dir = ensure_private_directory(data_dir("dsar_requests") / "exports")
        path = out_dir / f"{opened['id']}-export.json"
        intent = privacy_ops._dsar_export_intent(opened)
        bundle = {
            "subject": {"user_id": opened["subject_id"], "channel": "email"},
            "tenant": None, "counts": {"facts": 1},
        }
        privacy_ops._write_dsar_export_artifact(path, intent, bundle)
        assert privacy_ops.get_dsar(opened["id"])["status"] == "open"

        closed = privacy_ops.close_dsar(opened["id"])

        assert closed["status"] == "closed"
        assert closed["export_cleanup"]["status"] == "removed"
        assert not path.exists()

    def test_erasure_fulfillment_is_structured_not_shell_text(self):
        subject = "jordan@example.com & calc.exe | whoami > owned.txt"
        channel = "email & echo %COMSPEC% ^ !PATH!"
        r = privacy_ops.open_dsar(subject, "erasure", channel=channel)
        ready = privacy_ops.fulfill_dsar(r["id"])
        assert ready["status"] == "awaiting_erasure"
        handoff = ready["fulfillment"]
        assert handoff["erase_argv"] == [
            "maverick", "erase", "--user", subject, "--channel", channel,
        ]
        assert "erase_command" not in handoff
        assert subject not in handoff["operator_instruction"]
        assert "shell command" in handoff["operator_instruction"]
        closed = privacy_ops.close_dsar(r["id"], closed_by="privacy-lead")
        assert closed["status"] == "closed"

    def test_concurrent_fulfillment_exports_exactly_once(self, monkeypatch):
        import maverick.audit as audit
        from maverick import dsar

        monkeypatch.setattr(audit, "record", lambda *a, **k: True)
        calls = 0
        calls_lock = threading.Lock()

        def fake_export(user_id, *, channel=None, tenant=None, strict=False):
            assert strict is True
            nonlocal calls
            with calls_lock:
                calls += 1
            time.sleep(0.03)
            return {
                "subject": {"user_id": user_id, "channel": channel},
                "tenant": tenant,
                "counts": {"facts": 1},
            }

        monkeypatch.setattr(dsar, "export_subject_data", fake_export)
        opened = privacy_ops.open_dsar(
            "jordan@example.com", "access", channel="email",
            opened_by="user:alice",
        )
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(
                lambda _: privacy_ops.fulfill_dsar(
                    opened["id"], fulfilled_by="user:alice",
                ),
                range(8),
            ))

        assert calls == 1
        assert all(result is not None for result in results)
        assert {r["status"] for r in results if r is not None} == {"fulfilled"}
        assert len({r["fulfillment"]["export_path"] for r in results
                    if r is not None}) == 1
        stored = privacy_ops.list_dsars()[0]
        assert stored["revision"] == opened["revision"] + 1
        assert "_audit_pending" not in stored

    def test_planted_or_cross_subject_export_is_regenerated(self, monkeypatch):
        import maverick.audit as audit
        from maverick import dsar
        from maverick.file_lock import atomic_write_text, ensure_private_directory
        from maverick.paths import data_dir

        monkeypatch.setattr(audit, "record", lambda *a, **k: True)
        calls = []

        def fake_export(user_id, *, channel=None, tenant=None, strict=False):
            assert strict is True
            calls.append((user_id, channel, tenant))
            return {
                "subject": {"user_id": user_id, "channel": channel},
                "tenant": tenant,
                "counts": {"facts": 1},
            }

        monkeypatch.setattr(dsar, "export_subject_data", fake_export)
        first = privacy_ops.open_dsar("alice", "access", channel="email")
        out_dir = ensure_private_directory(data_dir("dsar_requests") / "exports")
        first_path = out_dir / f"{first['id']}-export.json"
        atomic_write_text(first_path, "{}", mode=0o600)
        first_done = privacy_ops.fulfill_dsar(first["id"])
        assert first_done is not None and first_done["status"] == "fulfilled"
        assert calls == [("alice", "email", None)]

        second = privacy_ops.open_dsar("bob", "access", channel="teams")
        second_path = out_dir / f"{second['id']}-export.json"
        atomic_write_text(
            second_path,
            first_path.read_text(encoding="utf-8"),
            mode=0o600,
        )
        second_done = privacy_ops.fulfill_dsar(second["id"])
        assert second_done is not None and second_done["status"] == "fulfilled"
        assert calls[-1] == ("bob", "teams", None)
        artifact = json.loads(second_path.read_text(encoding="utf-8"))
        assert artifact["subject"] == {"user_id": "bob", "channel": "teams"}
        assert artifact["_lightwork_export"]["intent"]["request_id"] == second["id"]
        assert len(second_done["fulfillment"]["artifact_sha256"]) == 64

    def test_planted_export_with_non_ascii_digest_is_regenerated(self, monkeypatch):
        import maverick.audit as audit
        from maverick import dsar
        from maverick.file_lock import atomic_write_text, ensure_private_directory
        from maverick.paths import data_dir

        monkeypatch.setattr(audit, "record", lambda *a, **k: True)
        calls = []

        def fake_export(user_id, *, channel=None, tenant=None, strict=False):
            assert strict is True
            calls.append((user_id, channel, tenant))
            return {
                "subject": {"user_id": user_id, "channel": channel},
                "tenant": tenant,
                "counts": {"facts": 1},
            }

        monkeypatch.setattr(dsar, "export_subject_data", fake_export)
        opened = privacy_ops.open_dsar("alice", "access", channel="email")
        out_dir = ensure_private_directory(data_dir("dsar_requests") / "exports")
        path = out_dir / f"{opened['id']}-export.json"
        privacy_ops._write_dsar_export_artifact(
            path,
            privacy_ops._dsar_export_intent(opened),
            {"subject": {"user_id": opened["subject_id"], "channel": "email"},
             "tenant": None, "counts": {"facts": 1}},
        )
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["_lightwork_export"]["sha256"] = "é" * 64
        atomic_write_text(path, json.dumps(artifact), mode=0o600)

        done = privacy_ops.fulfill_dsar(opened["id"])
        assert done is not None and done["status"] == "fulfilled"
        assert calls == [(opened["subject_id"], "email", None)]
        assert len(done["fulfillment"]["artifact_sha256"]) == 64

    def test_crash_after_artifact_write_reuses_bound_export(self, monkeypatch):
        import maverick.audit as audit
        from maverick import dsar

        monkeypatch.setattr(audit, "record", lambda *a, **k: True)
        calls = 0

        def fake_export(user_id, *, channel=None, tenant=None, strict=False):
            assert strict is True
            nonlocal calls
            calls += 1
            return {
                "subject": {"user_id": user_id, "channel": channel},
                "tenant": tenant,
                "counts": {"facts": 1},
            }

        monkeypatch.setattr(dsar, "export_subject_data", fake_export)
        opened = privacy_ops.open_dsar("alice", "access", channel="email")
        original_write = privacy_ops._RecordStore._write_path

        def crash_after_artifact(
            cls, path, record, previous, *, bump_revision=True,
            effect_guard=None,
        ):
            if path.stem == opened["id"] and record.get("status") == "fulfilled":
                raise OSError("simulated crash before record commit")
            return original_write(
                path,
                record,
                previous,
                bump_revision=bump_revision,
                effect_guard=effect_guard,
            )

        with monkeypatch.context() as crash:
            crash.setattr(
                privacy_ops._RecordStore,
                "_write_path",
                classmethod(crash_after_artifact),
            )
            with pytest.raises(OSError, match="simulated crash"):
                privacy_ops.fulfill_dsar(opened["id"])

        assert calls == 1
        assert privacy_ops._DSAR.load(opened["id"])["status"] == "open"
        recovered = privacy_ops.fulfill_dsar(opened["id"])
        assert recovered is not None and recovered["status"] == "fulfilled"
        assert calls == 1
        assert Path(recovered["fulfillment"]["export_path"]).is_file()


def test_audit_outbox_retries_without_revision_churn(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *a, **k: False)
    created = privacy_ops.review_dpa(
        "Acme", GOOD_DPA, reviewed_by="user:alice",
    )
    revision = created["revision"]
    pending = created.get("_audit_pending")
    assert isinstance(pending, list) and len(pending) == 1
    event_id = pending[0]["event_id"]

    captured = []

    def accept(kind, **payload):
        captured.append((kind, payload))
        return True

    monkeypatch.setattr(audit, "record", accept)
    assert privacy_ops.retry_pending_audits() == 1
    stored = privacy_ops.get_dpa_review(created["id"])
    assert stored is not None
    assert stored["revision"] == revision
    assert "_audit_pending" not in stored
    assert captured[0][1]["event_id"] == event_id
    assert captured[0][1]["revision"] == revision
    assert captured[0][1]["status"] == "pending_review"
    assert len(captured[0][1]["record_sha256"]) == 64
    assert captured[0][1]["occurred_at"] > 0
    assert privacy_ops.retry_pending_audits() == 0
    assert privacy_ops.get_dpa_review(created["id"])["revision"] == revision


def test_privacy_store_refuses_linked_root(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    root = tmp_path / "dpa_reviews"
    try:
        root.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this host")
    with pytest.raises(PermissionError, match="aliases"):
        privacy_ops.review_dpa("Acme", GOOD_DPA)
    assert list(outside.iterdir()) == []


def test_privacy_store_refuses_hardlink_and_mismatched_identity(tmp_path):
    from maverick.file_lock import atomic_write_text

    created = privacy_ops.review_dpa("Acme", GOOD_DPA)
    root = tmp_path / "dpa_reviews"
    source = root / f"{created['id']}.json"
    linked = root / "DPA-deadbeef00.json"
    try:
        linked.hardlink_to(source)
    except OSError:
        pytest.skip("hardlinks are unavailable on this host")
    with pytest.raises(PermissionError, match="single-link"):
        privacy_ops._DPA.load(created["id"])
    linked.unlink()

    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["id"] = "DPA-deadbeef00"
    atomic_write_text(source, json.dumps(payload), mode=0o600)
    with pytest.raises(PermissionError, match="identity"):
        privacy_ops._DPA.load(created["id"])


@pytest.mark.parametrize("revision", [False, "1", 1.5, -1])
def test_privacy_store_rejects_non_monotonic_revision(tmp_path, revision):
    from maverick.file_lock import atomic_write_text

    created = privacy_ops.review_dpa("Acme", GOOD_DPA)
    path = tmp_path / "dpa_reviews" / f"{created['id']}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["revision"] = revision
    atomic_write_text(path, json.dumps(payload), mode=0o600)

    with pytest.raises(PermissionError, match="revision"):
        privacy_ops._DPA.load(created["id"])


@pytest.mark.parametrize(
    "field",
    ["document_sha256", "binding_sha256"],
)
def test_document_evidence_hash_tampering_refuses_read_and_mutation(
    tmp_path,
    field,
):
    from maverick.file_lock import atomic_write_text

    evidence = privacy_ops._build_document_evidence(
        data=GOOD_DPA.encode("utf-8"),
        text=GOOD_DPA,
        mime="text/plain",
        source="msgraph",
        doc_id="private-document-id",
        ref={"drive_id": "private-drive-id"},
        extraction={
            "method": "plain_text",
            "scope": "document_bytes",
            "confidence": "untrusted",
            "review_required": True,
        },
    )
    created = privacy_ops.review_dpa(
        "Acme",
        GOOD_DPA,
        _document_evidence=evidence,
    )
    path = tmp_path / "dpa_reviews" / f"{created['id']}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    replacement = "0" * 64
    if payload["document_evidence"][field] == replacement:
        replacement = "1" * 64
    payload["document_evidence"][field] = replacement
    atomic_write_text(path, json.dumps(payload), mode=0o600)
    tampered_bytes = path.read_bytes()

    with pytest.raises(
        privacy_ops.PrivacyStateError,
        match="evidence binding does not verify",
    ):
        privacy_ops._DPA.load(created["id"])
    with pytest.raises(
        privacy_ops.PrivacyStateError,
        match="evidence binding does not verify",
    ):
        privacy_ops._DPA.update(
            created["id"],
            lambda record: record.update(status="approved"),
            expected_revision=created["revision"],
        )
    assert path.read_bytes() == tampered_bytes


def test_corrupt_existing_privacy_record_is_never_treated_as_absent(tmp_path):
    from maverick.file_lock import atomic_write_text

    created = privacy_ops.review_dpa("Acme", GOOD_DPA)
    path = tmp_path / "dpa_reviews" / f"{created['id']}.json"
    atomic_write_text(path, "{not-json", mode=0o600)
    corrupt_bytes = path.read_bytes()

    with pytest.raises(privacy_ops.PrivacyStateError, match="corrupt"):
        privacy_ops._DPA.load(created["id"])
    with pytest.raises(privacy_ops.PrivacyStateError, match="corrupt"):
        privacy_ops._DPA.save(
            {**created, "vendor": "Replacement must not publish"},
            expected_revision=created["revision"],
        )
    assert path.read_bytes() == corrupt_bytes


def test_duplicate_persisted_audit_event_id_is_rejected(tmp_path):
    from maverick.file_lock import atomic_write_text

    created = privacy_ops.review_dpa("Acme", GOOD_DPA)
    path = tmp_path / "dpa_reviews" / f"{created['id']}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    receipt = privacy_ops._pending_audit("review", "user:alice")
    payload["_audit_pending"] = [receipt, dict(receipt)]
    atomic_write_text(path, json.dumps(payload), mode=0o600)

    with pytest.raises(PermissionError, match="invalid audit outbox"):
        privacy_ops._DPA.load(created["id"])


def test_privacy_store_rejects_malformed_filename(tmp_path):
    from maverick.file_lock import atomic_write_text, ensure_private_directory

    root = ensure_private_directory(tmp_path / "dsar_requests")
    malformed = root / "DSAR-attacker!.json"
    atomic_write_text(
        malformed,
        json.dumps({"id": "DSAR-attacker!", "status": "open"}),
        mode=0o600,
    )
    with pytest.raises(PermissionError, match="identity"):
        privacy_ops._DSAR.list()


def test_privacy_handle_read_does_not_follow_swap_to_secret(tmp_path, monkeypatch):
    created = privacy_ops.review_dpa("Acme", GOOD_DPA)
    record_path = tmp_path / "dpa_reviews" / f"{created['id']}.json"
    secret = tmp_path / "outside-secret.json"
    secret.write_text(
        json.dumps({"id": created["id"], "vendor": "DO NOT DISCLOSE"}),
        encoding="utf-8",
    )
    secret.chmod(0o600)
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(secret)
        probe.unlink()
    except OSError:
        pytest.skip("symlinks are unavailable on this host")

    real_open = privacy_ops.os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        candidate = Path(path)
        if not swapped and candidate.name == record_path.name:
            swapped = True
            record_path.unlink()
            record_path.symlink_to(secret)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(privacy_ops.os, "open", swapping_open)
    with pytest.raises(PermissionError, match="changed during open"):
        privacy_ops._DPA.load(created["id"])
    assert swapped is True


def test_audit_outbox_is_at_least_once_with_stable_event_id(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *a, **k: False)
    created = privacy_ops.review_dpa("Acme", GOOD_DPA, reviewed_by="user:alice")
    event_id = created["_audit_pending"][0]["event_id"]
    captured = []
    monkeypatch.setattr(
        audit,
        "record",
        lambda kind, **payload: captured.append(payload["event_id"]) or True,
    )
    original_write = privacy_ops._RecordStore._write_path

    def crash_before_clear(
        cls, path, record, previous, *, bump_revision=True, effect_guard=None,
    ):
        if not bump_revision:
            raise OSError("simulated crash after signed append")
        return original_write(
            path, record, previous, bump_revision=bump_revision,
            effect_guard=effect_guard,
        )

    with monkeypatch.context() as crash:
        crash.setattr(
            privacy_ops._RecordStore,
            "_write_path",
            classmethod(crash_before_clear),
        )
        with pytest.raises(OSError, match="simulated crash"):
            privacy_ops.retry_pending_audits()
    assert privacy_ops.retry_pending_audits() == 1
    assert captured == [event_id, event_id]


def test_audit_retry_limit_bounds_failed_attempts(monkeypatch):
    import maverick.audit as audit

    calls = 0

    def unavailable(*args, **kwargs):
        nonlocal calls
        calls += 1
        return False

    monkeypatch.setattr(audit, "record", unavailable)
    for index in range(5):
        privacy_ops.review_dpa(f"Vendor {index}", GOOD_DPA)
    original_read = privacy_ops._DPA._read_path
    reads = 0

    def counted_read(path):
        nonlocal reads
        reads += 1
        return original_read(path)

    monkeypatch.setattr(privacy_ops._DPA, "_read_path", counted_read)
    calls = 0
    assert privacy_ops.retry_pending_audits(limit=2) == 0
    assert calls == 2
    assert reads == 2


def test_audit_retry_cursor_rotates_past_nonpending_records(monkeypatch):
    import maverick.audit as audit

    monkeypatch.setattr(privacy_ops, "_AUDIT_RETRY_CURSORS", {})
    monkeypatch.setattr(privacy_ops, "_AUDIT_RETRY_STORE_OFFSET", 0)
    captured = []
    monkeypatch.setattr(
        audit,
        "record",
        lambda kind, **payload: captured.append(payload["event_id"]) or True,
    )
    privacy_ops._DPA.save({
        "id": "DPA-0000000000",
        "status": "pending_review",
        "created_at": 1,
    })
    privacy_ops._DPA.save({
        "id": "DPA-1111111111",
        "status": "pending_review",
        "created_at": 2,
        "_audit_pending": [{
            "event_id": "stable-event-id",
            "action": "create",
            "actor": "system",
            "prepared_at": 1.0,
        }],
    })

    # The first one-record pass visits a record with no outbox receipt. The
    # persistent filename/store cursors make the next one-record pass advance
    # rather than rescanning that lexical prefix forever.
    assert privacy_ops.retry_pending_audits(limit=1) == 0
    assert captured == []
    assert privacy_ops.retry_pending_audits(limit=1) == 1
    assert captured == ["stable-event-id"]


def test_audit_outbox_cap_aborts_mutation_without_dropping_receipts():
    created = privacy_ops.upsert_ropa(
        {"activity": "Payroll", "purpose": "Pay employees"},
        _audit=False,
    )
    assert created is not None
    pending = [
        privacy_ops._pending_audit("prior", f"system:{index}")
        for index in range(privacy_ops._MAX_AUDIT_PENDING_RECEIPTS)
    ]

    def fill_outbox(record):
        record["_audit_pending"] = pending

    full = privacy_ops._ROPA.update(created["id"], fill_outbox)
    assert full is not None
    before = privacy_ops._ROPA.load(created["id"])
    assert before is not None
    with pytest.raises(privacy_ops.AuditOutboxError, match="outbox is full"):
        privacy_ops.upsert_ropa(
            {"purpose": "This change must not be published"},
            ropa_id=created["id"],
            expected_revision=before["revision"],
            updated_by="user:alice",
        )
    after = privacy_ops._ROPA.load(created["id"])
    assert after is not None
    assert after["revision"] == before["revision"]
    assert after["purpose"] == "Pay employees"
    assert after["_audit_pending"] == before["_audit_pending"]
    assert len(after["_audit_pending"]) == privacy_ops._MAX_AUDIT_PENDING_RECEIPTS


def test_audit_flush_attempts_are_bounded_per_record(monkeypatch):
    import maverick.audit as audit

    created = privacy_ops.upsert_ropa(
        {"activity": "Payroll", "purpose": "Pay employees"},
        _audit=False,
    )
    assert created is not None

    def fill_outbox(record):
        record["_audit_pending"] = [
            privacy_ops._pending_audit("prior") for _ in range(5)
        ]

    saved = privacy_ops._ROPA.update(created["id"], fill_outbox)
    assert saved is not None
    delivered = []
    monkeypatch.setattr(
        audit,
        "record",
        lambda *args, **kwargs: delivered.append(kwargs["event_id"]) or True,
    )
    monkeypatch.setattr(privacy_ops, "_MAX_AUDIT_DELIVERIES_PER_FLUSH", 2)
    flushed = privacy_ops._audit_mutation(privacy_ops._ROPA, "ropa", saved)
    assert len(delivered) == 2
    assert len(flushed["_audit_pending"]) == 3
    assert flushed["revision"] == saved["revision"]


def test_persisted_audit_outbox_shape_is_validated(tmp_path):
    from maverick.file_lock import atomic_write_text

    created = privacy_ops.review_dpa("Acme", GOOD_DPA)
    path = tmp_path / "dpa_reviews" / f"{created['id']}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["_audit_pending"] = "not-a-receipt-queue"
    atomic_write_text(path, json.dumps(payload), mode=0o600)
    with pytest.raises(PermissionError, match="invalid audit outbox"):
        privacy_ops._DPA.load(created["id"])


class TestDepthHooks:
    """The workspace feeding itself: AIRA -> registry, connected sources ->
    DPA review, OneTrust export -> RoPA."""

    def _aira(self, prohibited="no", high_risk="no",
              purpose_note="conversational assistant for customer tickets"):
        from maverick.assessment import AssessmentSession, save_session
        s = AssessmentSession(type="aira", subject="Support triage bot")
        s.record("aira_purpose", "yes", purpose_note)
        s.record("aira_prohibited", prohibited)
        s.record("aira_high_risk", high_risk)
        save_session(s)
        return s

    def test_register_from_assessment_carries_purpose_and_provenance(self):
        s = self._aira()
        r = privacy_ops.register_ai_system_from_assessment(s.id)
        assert r["name"] == "Support triage bot"
        assert r["purpose"] == "conversational assistant for customer tickets"
        assert r["assessment_id"] == s.id
        # Keyword screening alone: a support assistant is Art. 50 limited.
        assert r["tier"] == "limited"

    def test_attestations_ratchet_tier_upward_only(self):
        s = self._aira(high_risk="yes")
        r = privacy_ops.register_ai_system_from_assessment(s.id)
        assert r["tier"] == "high"
        assert any("Annex III" in sig for sig in r["signals"])
        s2 = self._aira(prohibited="yes")
        r2 = privacy_ops.register_ai_system_from_assessment(s2.id)
        assert r2["tier"] == "prohibited"
        assert privacy_ops.register_ai_system_from_assessment("nope") is None

    def test_review_dpa_from_document_text_and_docx(self, monkeypatch):
        from maverick import doc_discovery

        def fake_fetch(source, doc_id, ref=None, **kw):
            if doc_id == "plain":
                return GOOD_DPA.encode(), "text/plain"
            if doc_id == "word":
                import io
                import zipfile
                buf = io.BytesIO()
                body = "".join(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>"
                               for line in GOOD_DPA.splitlines())
                with zipfile.ZipFile(buf, "w") as z:
                    z.writestr("word/document.xml",
                               f"<w:document>{body}</w:document>")
                return (buf.getvalue(),
                        "application/vnd.openxmlformats-officedocument"
                        ".wordprocessingml.document")
            return b"%PDF-1.7 binary", "application/pdf"

        monkeypatch.setattr(doc_discovery, "fetch", fake_fetch)
        r = privacy_ops.review_dpa_from_document(
            "Acme Corp", "msgraph", "plain", document_name="acme-dpa.txt")
        assert r["clauses_present"] >= 9
        assert r["document_name"] == "acme-dpa.txt"
        r2 = privacy_ops.review_dpa_from_document(
            "Acme Corp", "msgraph", "word", document_name="acme-dpa.docx")
        assert r2["clauses_present"] >= 9
        with pytest.raises(ValueError, match="cannot extract text"):
            privacy_ops.review_dpa_from_document(
                "Acme Corp", "msgraph", "scan", document_name="scan.pdf")

    def test_docx_zip_bomb_is_rejected_before_entry_read(self, monkeypatch):
        import io
        import zipfile

        buf = io.BytesIO()
        oversized = b"<w:document>" + (
            b"A" * privacy_ops._MAX_DOCX_DOCUMENT_XML_BYTES
        ) + b"</w:document>"
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("word/document.xml", oversized)

        opened = False
        original_open = zipfile.ZipFile.open

        def tracked_open(self, *args, **kwargs):
            nonlocal opened
            opened = True
            return original_open(self, *args, **kwargs)

        monkeypatch.setattr(zipfile.ZipFile, "open", tracked_open)
        assert privacy_ops._document_text(
            buf.getvalue(),
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document",
        ) == ""
        assert opened is False

    def _ooxml(self, members):
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in members.items():
                archive.writestr(name, body)
        return buffer.getvalue()

    def test_ooxml_extraction_covers_xlsx_and_pptx_with_the_stdlib(self):
        xlsx = self._ooxml({
            "xl/sharedStrings.xml":
                "<sst><si><t>alice@example.com</t></si>"
                "<si><t>SSN 123-45-6789</t></si></sst>",
            "xl/worksheets/sheet1.xml":
                "<worksheet><sheetData><row><c><v>42</v></c></row>"
                "</sheetData></worksheet>",
            # A relationship part sits under the same folder and must not be
            # mistaken for a sheet.
            "xl/worksheets/_rels/sheet1.xml.rels": "<Relationships/>",
        })
        meta = {}
        text = privacy_ops._document_text(
            xlsx,
            "application/vnd.openxmlformats-officedocument"
            ".spreadsheetml.sheet",
            _metadata=meta,
        )
        assert meta["method"] == "xlsx_shared_strings_and_sheets"
        assert "alice@example.com" in text and "123-45-6789" in text
        assert "42" in text

        pptx = self._ooxml({"ppt/slides/slide1.xml":
                            "<p:sld><a:p><a:r><a:t>deck secret</a:t></a:r>"
                            "</a:p></p:sld>"})
        meta = {}
        text = privacy_ops._document_text(
            pptx,
            "application/vnd.openxmlformats-officedocument"
            ".presentationml.presentation",
            _metadata=meta,
        )
        assert meta["method"] == "pptx_slide_xml"
        assert "deck secret" in text

    def test_ooxml_extraction_unescapes_so_entities_cannot_evade(self):
        """An identifier written as a character reference must not survive
        tag-stripping still escaped -- that is an evasion, not cosmetics."""
        docx = self._ooxml({"word/document.xml":
                            "<w:document><w:body><w:p><w:r><w:t>"
                            "a&amp;b&#64;example.com</w:t></w:r></w:p>"
                            "</w:body></w:document>"})
        text = privacy_ops._document_text(
            docx,
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document",
        )
        assert "a&b@example.com" in text
        # Escaped markup stays inert text; it is never re-read as a tag.
        inert = self._ooxml({"word/document.xml":
                             "<w:document><w:body><w:p><w:r><w:t>"
                             "&lt;w:t&gt;kept&lt;/w:t&gt;</w:t></w:r></w:p>"
                             "</w:body></w:document>"})
        assert "<w:t>kept</w:t>" in privacy_ops._document_text(
            inert,
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document",
        )

    def test_ooxml_extraction_refuses_duplicate_named_parts(self):
        """A forged archive must not make "which entry wins" ambiguous."""
        import io
        import warnings
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            with warnings.catch_warnings():   # building the forgery warns
                warnings.simplefilter("ignore")
                archive.writestr("word/document.xml", "<w:t>benign</w:t>")
                archive.writestr("word/document.xml", "<w:t>payload</w:t>")
        assert privacy_ops._document_text(
            buffer.getvalue(),
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document",
        ) == ""

    def test_import_onetrust_ropa_maps_drifting_headers(self):
        csv_text = (
            '"Processing Activity Name","Purpose of Processing",'
            '"Personal Data Categories","Cross-Border Transfers",'
            '"Retention Period","Irrelevant Column"\n'
            '"CRM marketing","Campaign targeting","Contact details, usage",'
            '"SCCs to US vendors","24 months","x"\n'
            '"","orphan row without a name","","","",""\n'
            '"Payroll","Salary processing","Bank details","None",'
            '"7 years","y"\n')
        imported = privacy_ops.import_onetrust_ropa(csv_text)
        assert [e["activity"] for e in imported] == ["CRM marketing",
                                                     "Payroll"]
        assert imported[0]["transfers"] == "SCCs to US vendors"
        assert all(e["source"] == "onetrust" for e in imported)
        # Imported rows land in the same register the CSV export reads.
        assert {e["activity"] for e in privacy_ops.export_ropa_art30()} == {
            "CRM marketing", "Payroll"}


class TestPdfExtraction:
    """DPA review straight from a digital PDF — the format DPAs actually
    arrive in. Scanned PDFs still refuse honestly."""

    @staticmethod
    def _stream_object(
        number,
        body,
        *,
        flate=False,
        filter_value=None,
    ):
        if filter_value is not None:
            filter_entry = b" /Filter " + filter_value
        else:
            filter_entry = b" /Filter /FlateDecode" if flate else b""
        return (
            str(number).encode()
            + b" 0 obj\n<< /Length "
            + str(len(body)).encode()
            + filter_entry
            + b" >>\nstream\n"
            + body
            + b"\nendstream\nendobj\n"
        )

    @classmethod
    def _pdf_document(
        cls,
        body,
        *,
        compress=False,
        encoded=None,
        flate=None,
        filter_value=None,
        contents=b"4 0 R",
        extra_objects=(),
    ):
        import zlib

        if encoded is None:
            encoded = zlib.compress(body) if compress else body
        if flate is None:
            flate = compress
        return (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents "
            + contents
            + b" >>\nendobj\n"
            + cls._stream_object(
                4,
                encoded,
                flate=flate,
                filter_value=filter_value,
            )
            + b"".join(extra_objects)
            + b"trailer\n<< /Size 32 /Root 1 0 R >>\n"
            b"startxref\n0\n%%EOF\n"
        )

    @classmethod
    def _pdf(cls, lines, compress=False):
        escaped = (
            str(line).replace("\\", "\\\\").replace("(", "\\(")
            .replace(")", "\\)")
            for line in lines
        )
        body = "\n".join(
            f"BT /F1 10 Tf 54 700 Td ({line}) Tj ET" for line in escaped
        ).encode()
        return cls._pdf_document(body, compress=compress)

    def test_review_dpa_from_pdf_compressed_and_not(self, monkeypatch):
        from maverick import doc_discovery
        lines = [ln for ln in GOOD_DPA.splitlines() if ln]
        for compress in (False, True):
            pdf = self._pdf(lines, compress=compress)
            monkeypatch.setattr(doc_discovery, "fetch",
                                lambda *a, _p=pdf, **k: (_p,
                                                         "application/pdf"))
            r = privacy_ops.review_dpa_from_document(
                "Acme Corp", "msgraph", "d1", document_name="acme-dpa.pdf")
            assert r["clauses_present"] >= 9, (compress, r)
            assert r["status"] == "pending_review"
            assert r["extraction_confidence"] == "untrusted"
            assert r["review_required"] is True

    def test_tj_arrays_and_hex_strings(self):
        s = (b"BT [(Standard )(Contractual )(Clauses )(cover )(the )"
             b"(international )(transfers )(of )(personal )(data.)] TJ ET "
             b"BT <41756469742072696768747320616e6420726574656e74696f6e2073"
             b"6368656475"
             b"6c6520646566696e65642e> Tj ET")
        txt = privacy_ops._pdf_text(self._pdf_document(s))
        assert ("Standard Contractual Clauses cover the international "
                "transfers of personal data.") in txt
        assert "Audit rights and retention schedule defined." in txt

    def test_scanned_pdf_still_refuses(self, monkeypatch):
        from maverick import doc_discovery
        scanned = self._pdf_document(b"\x00\x89PNG\x01\x02 image pixels")
        monkeypatch.setattr(
            doc_discovery, "fetch",
            lambda *a, **k: (scanned, "application/pdf"))
        with pytest.raises(ValueError, match="cannot extract text"):
            privacy_ops.review_dpa_from_document("Acme", "msgraph", "scan")

class TestDsarIntake:
    """Inbound messages become tracked requests — deterministically, with
    the matched phrases kept as provenance."""

    def test_detects_each_kind_with_signals(self):
        erase = privacy_ops.detect_dsar(
            "Hi, under GDPR Article 17 please delete my data and confirm.",
            sender="sam@example.com")
        assert erase["kind"] == "erasure"
        assert erase["subject_id"] == "sam@example.com"
        assert any("delete my data" in s for s in erase["signals"])
        access = privacy_ops.detect_dsar(
            "I would like a copy of my personal data you hold on me. "
            "Regards, jordan.ellis@example.com")
        assert access["kind"] == "access"
        assert access["subject_id"] == "jordan.ellis@example.com"
        port = privacy_ops.detect_dsar(
            "Please transfer my data to my new provider (data portability).",
            sender="pat@example.com")
        assert port["kind"] == "portability"
        # Erasure phrasing wins over an access-ish word later in the text.
        both = privacy_ops.detect_dsar(
            "Right to be forgotten: erase my data. I previously made an "
            "access request.", sender="x@example.com")
        assert both["kind"] == "erasure"

    def test_ordinary_mail_is_not_a_request(self):
        assert privacy_ops.detect_dsar(
            "Hey team, the Q3 report deletes the old slide deck.") is None
        assert privacy_ops.detect_dsar("") is None

    def test_open_from_message_carries_provenance(self):
        rec = privacy_ops.open_dsar_from_message(
            "Subject: please erase my account\n\nUnder Article 17 I ask "
            "you to remove my personal data.\n-- casey@example.com",
            channel="email")
        assert rec["kind"] == "erasure"
        assert rec["subject_id"] == "casey@example.com"
        assert rec["status"] == "open"
        assert rec["intake"]["signals"]
        assert "erase my account" in rec["intake"]["excerpt"]
        # No subject anywhere -> no request opened.
        assert privacy_ops.open_dsar_from_message(
            "please delete my data thanks") is None


class TestIncidentRegister:
    """Art. 33/34: a 72-hour clock the register tracks, and a notification
    decision that stays a documented human call either way."""

    def test_open_starts_the_72h_clock(self):
        r = privacy_ops.open_incident(
            "Misdirected owner statement batch", severity="high",
            categories="contact details, account balances",
            affected_estimate="~120 owners", affected_people=120,
            reported_by="ops")
        assert r["status"] == "open"
        assert r["affected_people"] == 120
        updated = privacy_ops.set_incident_affected_people(
            r["id"], None, updated_by="ops")
        assert updated["affected_people"] is None
        assert updated["affected_estimate"] == "~120 owners"
        listed = privacy_ops.list_incidents()[0]
        assert 70 <= listed["hours_left"] <= 72
        assert listed["clock_breached"] is False
        with pytest.raises(ValueError):
            privacy_ops.open_incident("x", severity="catastrophic")
        with pytest.raises(ValueError):
            privacy_ops.open_incident("   ")
        with pytest.raises(ValueError, match="affected_people"):
            privacy_ops.open_incident("x", affected_people=-1)

    def test_the_clock_runs_from_when_the_organisation_became_aware(self):
        now = time.time()
        aware = now - 30 * 3600
        r = privacy_ops.open_incident("Laptop with a customer list stolen",
                                      aware_at=aware, reported_by="dpo")
        assert r["aware_at"] == aware
        assert r["notify_deadline_at"] == pytest.approx(aware + 72 * 3600)
        assert r["created_at"] >= now
        listed = privacy_ops.list_incidents()[0]
        assert 40 <= listed["hours_left"] <= 42
        with pytest.raises(ValueError, match="future"):
            privacy_ops.open_incident("Not yet", aware_at=now + 3600)
        with pytest.raises(ValueError, match="aware"):
            privacy_ops.open_incident("Garbage", aware_at=float("nan"))
        default = privacy_ops.open_incident("Found today")
        assert default["aware_at"] == pytest.approx(default["created_at"])
        assert default["notify_deadline_at"] == pytest.approx(default["aware_at"] + 72 * 3600)

    def test_notification_decision_documents_both_ways(self):
        r = privacy_ops.open_incident("Lost badge with cached emails")
        assert r["revision"] == 1
        assert "_audit_pending" not in r
        doc = privacy_ops.decide_incident_notification(
            r["id"], False, rationale="device encrypted, remotely wiped; "
            "no risk to rights and freedoms", decided_by="dpo")
        assert doc["status"] == "documented"
        assert doc["revision"] == 2
        assert doc["notification"]["notifiable"] is False
        assert doc["notification"]["decided_by"] == "dpo"
        assert "encrypted" in doc["notification"]["rationale"]
        r2 = privacy_ops.open_incident("Processor breach at Initech",
                                       severity="high")
        notify = privacy_ops.decide_incident_notification(
            r2["id"], True, rationale="personal data exfiltrated",
            decided_by="dpo")
        assert notify["status"] == "notify"
        closed = privacy_ops.close_incident(r2["id"], closed_by="dpo")
        assert closed["status"] == "closed"
        assert closed["closed_by"] == "dpo"
        with pytest.raises(privacy_ops.RecordConflict, match="closed"):
            privacy_ops.decide_incident_notification(
                r2["id"], False, rationale="changed after closure",
                decided_by="dpo",
            )
        assert privacy_ops.decide_incident_notification(
            "nope", True, rationale="not found",
        ) is None

    def test_clock_breach_flags_only_undecided_open_incidents(self, monkeypatch):
        import time as _t
        undecided = privacy_ops.open_incident("Slow-burn misconfig")
        decided = privacy_ops.open_incident("Contained laptop loss")
        privacy_ops.decide_incident_notification(decided["id"], False,
                                                 rationale="contained")
        real = _t.time
        monkeypatch.setattr(_t, "time", lambda: real() + 80 * 3600)
        listed = {x["id"]: x for x in privacy_ops.list_incidents()}
        assert listed[undecided["id"]]["clock_breached"] is True
        assert listed[decided["id"]]["clock_breached"] is False

    def test_context_heads_are_bounded_read_only_and_count_every_register(self):
        privacy_ops.open_incident("First")
        privacy_ops.open_incident("Second")
        heads = privacy_ops.privacy_program_context_heads(
            limit_per_register=1,
            register_names=("incidents",),
        )
        assert set(heads) == {"incidents"}
        assert heads["incidents"]["total_records"] == 2
        assert len(heads["incidents"]["records"]) == 1


class TestPdfExtraction(TestPdfExtraction):  # noqa: F811
    """Extend the concurrent PDF suite without duplicating inherited tests."""

    def test_decompression_bomb_and_truncated_flate_fail_closed(
        self,
        monkeypatch,
    ):
        import zlib

        body = b"BT (" + (b"A" * 4096) + b") Tj ET"
        monkeypatch.setattr(privacy_ops, "_MAX_PDF_EXPANDED_STREAM_BYTES", 128)
        assert privacy_ops._pdf_text(
            self._pdf_document(body, compress=True)
        ) == ""

        monkeypatch.setattr(
            privacy_ops,
            "_MAX_PDF_EXPANDED_STREAM_BYTES",
            8 * 1024,
        )
        encoded = zlib.compress(body)
        monkeypatch.setattr(
            privacy_ops,
            "_MAX_PDF_COMPRESSED_STREAM_BYTES",
            len(encoded) - 1,
        )
        assert privacy_ops._pdf_text(
            self._pdf_document(body, encoded=encoded, flate=True)
        ) == ""

        monkeypatch.setattr(
            privacy_ops,
            "_MAX_PDF_COMPRESSED_STREAM_BYTES",
            len(encoded),
        )
        truncated = encoded[:-2]
        assert privacy_ops._pdf_text(
            self._pdf_document(body, encoded=truncated, flate=True)
        ) == ""

    def test_pdf_resource_limits_reject_before_crediting_text(self, monkeypatch):
        visible = b"BT (This visible quarterly summary is intentionally harmless.) Tj ET"
        hidden = self._stream_object(
            5,
            b"BT (The controller has audit and inspection rights.) Tj ET",
        )
        pdf = self._pdf_document(visible, extra_objects=(hidden,))

        monkeypatch.setattr(privacy_ops, "_MAX_PDF_STREAMS", 1)
        assert privacy_ops._pdf_text(pdf) == ""

        monkeypatch.setattr(privacy_ops, "_MAX_PDF_STREAMS", 2)
        monkeypatch.setattr(privacy_ops, "_MAX_PDF_DECODED_TEXT_BYTES", 32)
        assert privacy_ops._pdf_text(pdf) == ""

        monkeypatch.setattr(privacy_ops, "_MAX_PDF_DECODED_TEXT_BYTES", 1024)
        monkeypatch.setattr(privacy_ops, "_MAX_PDF_INPUT_BYTES", 64)
        assert privacy_ops._pdf_text(pdf) == ""

    def test_aggregate_referenced_stream_limit_is_enforced(self, monkeypatch):
        first = b"BT (First visible page content is deliberately long.) Tj ET"
        second = b"BT (Second visible page content is deliberately long.) Tj ET"
        object_five = self._stream_object(5, second)
        pdf = self._pdf_document(
            first,
            contents=b"[4 0 R 5 0 R]",
            extra_objects=(object_five,),
        )
        monkeypatch.setattr(
            privacy_ops,
            "_MAX_PDF_AGGREGATE_STREAM_BYTES",
            len(first) + len(second) - 1,
        )
        assert privacy_ops._pdf_text(pdf) == ""

    def test_hidden_unreferenced_stream_cannot_overstate_findings(self):
        visible = (
            b"BT (Quarterly finance summary for internal planning only.) Tj ET"
        )
        hidden = self._stream_object(
            5,
            b"BT (The controller has audit and inspection rights. "
            b"International transfers use Standard Contractual Clauses.) Tj ET",
        )
        orphan_page = (
            b"6 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>\n"
            b"endobj\n"
        )
        text, metadata = privacy_ops._pdf_extraction(
            self._pdf_document(
                visible,
                extra_objects=(hidden, orphan_page),
            )
        )
        assert "Quarterly finance summary" in text
        assert "audit and inspection rights" not in text
        assert "Standard Contractual Clauses" not in text
        assert metadata["referenced_streams"] == 1
        assert privacy_ops.review_dpa("Acme", text)["clauses_present"] == 0

    def test_stream_bytes_cannot_masquerade_as_pdf_objects(self):
        hidden = self._stream_object(
            5,
            b"BT (The controller has audit and inspection rights.) Tj ET",
        )
        visible_with_fake_structure = (
            b"BT (Quarterly finance summary for internal planning only.) Tj ET\n"
            b"9 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>\n"
            b"endobj\n"
        )
        text = privacy_ops._pdf_text(self._pdf_document(
            visible_with_fake_structure,
            extra_objects=(hidden,),
        ))
        assert text == ""

    def test_trailer_root_excludes_unrooted_catalog_tree(self):
        visible = b"BT (Quarterly finance summary for internal planning only.) Tj ET"
        hidden = self._stream_object(
            5,
            b"BT (The controller has audit and inspection rights.) Tj ET",
        )
        fake_page = (
            b"6 0 obj\n<< /Type /Page /Parent 7 0 R /Contents 5 0 R >>\n"
            b"endobj\n"
        )
        fake_pages = (
            b"7 0 obj\n<< /Type /Pages /Kids [6 0 R] /Count 1 >>\n"
            b"endobj\n"
        )
        fake_catalog = (
            b"8 0 obj\n<< /Type /Catalog /Pages 7 0 R >>\nendobj\n"
        )
        text = privacy_ops._pdf_text(self._pdf_document(
            visible,
            extra_objects=(hidden, fake_page, fake_pages, fake_catalog),
        ))
        assert "Quarterly finance summary" in text
        assert "audit and inspection rights" not in text

    def test_missing_or_ambiguous_final_trailer_fails_closed(self):
        body = b"BT (Quarterly finance summary for internal planning only.) Tj ET"
        pdf = self._pdf_document(body)
        assert privacy_ops._pdf_text(pdf.split(b"trailer", 1)[0]) == ""
        assert privacy_ops._pdf_text(
            pdf + b"trailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"
        ) == ""

    def test_unsupported_or_ambiguous_stream_filters_fail_closed(self):
        import zlib

        body = b"BT (The controller has audit and inspection rights.) Tj ET"
        assert privacy_ops._pdf_text(self._pdf_document(
            body,
            filter_value=b"/ASCII85Decode",
        )) == ""
        compressed = zlib.compress(body)
        assert privacy_ops._pdf_text(self._pdf_document(
            body,
            encoded=compressed,
            filter_value=b"[/FlateDecode]",
        )) == ""
        assert privacy_ops._pdf_text(self._pdf_document(
            body,
            encoded=compressed,
            filter_value=b"/FlateDecode /Filter /FlateDecode",
        )) == ""
        assert privacy_ops._pdf_text(self._pdf_document(
            body,
            encoded=compressed,
            filter_value=b"/FlateDecode /DecodeParms << /Predictor 12 >>",
        )) == ""

    def test_content_lexer_rejects_semantic_operator_injection(self):
        visible = b"BT (Quarterly finance summary for internal planning only.) Tj ET"
        favorable = b"BT (The controller has audit and inspection rights.) Tj ET"

        assert privacy_ops._pdf_text(self._pdf_document(
            visible + b"\n% " + favorable,
        )) == ""
        assert privacy_ops._pdf_text(self._pdf_document(
            visible + b"\n(not shown (audit and inspection rights) Tj) Do",
        )) == ""

        escaped_operand = (
            visible
            + b"\n(\\(audit and inspection rights\\) Tj) Do"
        )
        text = privacy_ops._pdf_text(self._pdf_document(escaped_operand))
        assert "Quarterly finance summary" in text
        assert "audit and inspection rights" not in text

        assert privacy_ops._pdf_text(self._pdf_document(
            b"(The controller has audit and inspection rights.) Tj",
        )) == ""
        assert privacy_ops._pdf_text(self._pdf_document(
            b"BT (Quarterly finance summary for internal planning only.) Tj",
        )) == ""
        assert privacy_ops._pdf_text(self._pdf_document(
            b"q BI /W 1 /H 1 ID " + favorable + b" EI Q",
        )) == ""

    def test_provenance_binds_bytes_mime_and_private_locator(self, monkeypatch):
        from maverick import doc_discovery

        pdf = self._pdf(
            [line for line in GOOD_DPA.splitlines() if line],
            compress=True,
        )
        fetch_calls = []

        def fake_fetch(source, doc_id, ref=None, **kwargs):
            fetch_calls.append((source, doc_id, ref, kwargs))
            return pdf, "application/pdf; charset=binary"

        monkeypatch.setattr(doc_discovery, "fetch", fake_fetch)
        locator = "opaque-doc-12345"
        ref = {"drive_id": "opaque-drive-67890"}
        record = privacy_ops.review_dpa_from_document(
            "Acme",
            "msgraph",
            locator,
            ref=ref,
            document_name="agreement.pdf",
        )

        assert fetch_calls[0][3]["max_bytes"] == (
            privacy_ops._MAX_DOCUMENT_INPUT_BYTES
        )
        evidence = record["document_evidence"]
        assert evidence["document_sha256"] == hashlib.sha256(pdf).hexdigest()
        assert evidence["document_size_bytes"] == len(pdf)
        assert evidence["resolved_mime"] == "application/pdf"
        assert evidence["method"] == "pdf_page_content_streams"
        assert evidence["scope"] == "page_referenced"
        assert evidence["confidence"] == "untrusted"
        assert evidence["review_required"] is True
        assert evidence["referenced_streams"] == 1
        assert record["review_required"] is True
        assert locator not in json.dumps(evidence)
        assert ref["drive_id"] not in json.dumps(evidence)
        bound = dict(evidence)
        binding = bound.pop("binding_sha256")
        assert binding == privacy_ops._canonical_sha256(bound)

        another = privacy_ops.review_dpa_from_document(
            "Acme",
            "msgraph",
            "different-document-locator",
            ref=ref,
            document_name="agreement.pdf",
        )
        assert (
            another["document_evidence"]["document_sha256"]
            == evidence["document_sha256"]
        )
        assert (
            another["document_evidence"]["source_binding_sha256"]
            != evidence["source_binding_sha256"]
        )

        private_locator = "employee-alice-secret-folder/report-42.pdf"
        unnamed = privacy_ops.review_dpa_from_document(
            "Acme",
            "msgraph",
            private_locator,
            ref={"drive_id": "private-drive"},
        )
        assert unnamed["document_name"] == "Connected document"
        assert private_locator not in json.dumps(unnamed)
        assert "private-drive" not in json.dumps(unnamed)

    def test_review_boundary_rejects_oversize_fetch_result(self, monkeypatch):
        from maverick import doc_discovery

        fetch_kwargs = {}

        def fake_fetch(*args, **kwargs):
            fetch_kwargs.update(kwargs)
            return b"A" * 65, "text/plain"

        monkeypatch.setattr(privacy_ops, "_MAX_DOCUMENT_INPUT_BYTES", 64)
        monkeypatch.setattr(doc_discovery, "fetch", fake_fetch)
        with pytest.raises(ValueError, match="cannot extract text"):
            privacy_ops.review_dpa_from_document(
                "Acme",
                "msgraph",
                "oversize",
            )
        assert fetch_kwargs["max_bytes"] == 64

    def test_untrusted_evidence_cannot_disable_human_review(self):
        text = GOOD_DPA
        evidence = privacy_ops._build_document_evidence(
            data=text.encode("utf-8"),
            text=text,
            mime="text/plain",
            source="msgraph",
            doc_id="private-doc",
            ref=None,
            extraction={
                "method": "test_extractor",
                "scope": "document_bytes",
                "confidence": "untrusted",
                "review_required": False,
            },
        )
        record = privacy_ops.review_dpa(
            "Acme",
            text,
            _document_evidence=evidence,
        )
        assert record["status"] == "pending_review"
        assert record["review_required"] is True
        assert record["document_evidence"]["review_required"] is True


class TestDsarClocks:
    """Regime-aware deadlines, verification and extensions on the tracker."""

    def test_jurisdiction_sets_regime_clock_and_acknowledgement(self):
        r = privacy_ops.open_dsar(
            "casey@example.com", "access", jurisdiction="us_ca_ccpa",
            source="public_form", status="unverified",
            requester={"name": "Casey", "relationship": "customer",
                       "message": "x" * 5000, "authorised_agent": False},
        )
        assert r["status"] == "unverified"
        assert r["verification"] == {"status": "unverified"}
        assert r["due_basis"] == "statutory"
        assert r["due_at"] == pytest.approx(r["received_at"] + 45 * 86400)
        assert r["acknowledge_by"] is not None
        assert r["extended_until"] is None and r["extension_reason"] == ""
        assert r["source"] == "public_form"
        assert len(r["requester"]["message"]) == 4000
        listed = privacy_ops.list_dsars()[0]
        assert listed["effective_due_at"] == r["due_at"]
        assert listed["overdue"] is False and listed["due_soon"] is False

    def test_legacy_open_keeps_fallback_clock(self):
        r = privacy_ops.open_dsar("jordan@example.com", "erasure")
        assert r["jurisdiction"] == "" and r["due_basis"] == "fallback_30_days"
        assert r["verification"] == {"status": "not_required"}
        assert r["source"] == "dashboard"

    def test_verify_moves_unverified_to_open(self):
        r = privacy_ops.open_dsar(
            "casey@example.com", "correction", jurisdiction="eu_gdpr",
            source="public_form", status="unverified",
        )
        with pytest.raises(ValueError):
            privacy_ops.verify_dsar(r["id"], method="magic", reference="x")
        done = privacy_ops.verify_dsar(
            r["id"], method="email_challenge", reference="link opened",
            verified_by="public-rights-form",
        )
        assert done["status"] == "open"
        assert done["verification"]["method"] == "email_challenge"
        assert done["verification"]["verified_at"] > 0
        assert privacy_ops.verify_dsar("DSAR-nope", method="other", reference="x") is None

    def test_extension_is_validated_against_the_regime(self):
        r = privacy_ops.open_dsar("casey@example.com", "access", jurisdiction="us_va")
        with pytest.raises(ValueError):
            privacy_ops.extend_dsar(r["id"], reason="", days=10)
        with pytest.raises(ValueError):
            privacy_ops.extend_dsar(r["id"], reason="complex", days=46)
        ext = privacy_ops.extend_dsar(r["id"], reason="complex request", days=30)
        assert ext["extended_until"] == pytest.approx(r["due_at"] + 30 * 86400)
        assert ext["extension_reason"] == "complex request"
        assert privacy_ops.list_dsars()[0]["effective_due_at"] == ext["extended_until"]
        with pytest.raises(ValueError):
            privacy_ops.extend_dsar(r["id"], reason="again", days=5)
        no_ext = privacy_ops.open_dsar("b@example.com", "access", jurisdiction="br_lgpd")
        with pytest.raises(ValueError):
            privacy_ops.extend_dsar(no_ext["id"], reason="late", days=5)

    def test_acknowledge_and_clock_states(self):
        r = privacy_ops.open_dsar("casey@example.com", "access", jurisdiction="us_ca_ccpa")
        later = r["received_at"] + 20 * 86400
        clock = privacy_ops.dsar_clock(r, now=later)
        assert clock["acknowledge_overdue"] is True
        acked = privacy_ops.acknowledge_dsar(r["id"], acknowledged_by="privacy-lead")
        assert acked["acknowledged_at"] > 0
        assert privacy_ops.dsar_clock(acked, now=later)["acknowledge_overdue"] is False
        near = privacy_ops.dsar_clock(acked, now=r["due_at"] - 3 * 86400)
        assert near["due_soon"] is True and near["overdue"] is False
        past = privacy_ops.dsar_clock(acked, now=r["due_at"] + 86400)
        assert past["overdue"] is True

    def test_verify_acknowledge_and_extend_tell_webhook_subscribers(self, monkeypatch):
        from maverick import webhook_events

        sent: list[tuple[str, str, str]] = []
        monkeypatch.setattr(
            webhook_events, "emit",
            lambda event, **kw: sent.append((event, kw["record_type"], kw["record_id"])) or 1,
        )
        r = privacy_ops.open_dsar(
            "casey@example.com", "access", jurisdiction="us_ca_ccpa",
            source="public_form", status="unverified",
        )
        privacy_ops.verify_dsar(r["id"], method="email_challenge", reference="link opened")
        privacy_ops.acknowledge_dsar(r["id"], acknowledged_by="privacy-lead")
        privacy_ops.extend_dsar(r["id"], reason="complex request", days=30)
        # A repeat that changes nothing sends nothing.
        privacy_ops.acknowledge_dsar(r["id"], acknowledged_by="privacy-lead")
        assert [e for e, _rt, _rid in sent] == [
            "dsar.opened", "dsar.verified", "dsar.acknowledged", "dsar.extended",
        ]
        assert all(rt == "dsar" and rid == r["id"] for _e, rt, rid in sent)
        assert {"dsar.verified", "dsar.acknowledged", "dsar.extended"} <= webhook_events.EVENT_TYPES

    def test_manual_kinds_need_a_recorded_answer(self):
        # A button click no longer marks a manual right answered: the action,
        # answer date and proof must be recorded when closing.
        r = privacy_ops.open_dsar("casey@example.com", "opt_out", jurisdiction="us_ca_ccpa")
        with pytest.raises(ValueError, match="Record what was changed or stopped"):
            privacy_ops.fulfill_dsar(r["id"], fulfilled_by="ops")
        assert privacy_ops.get_dsar(r["id"])["status"] == "open"
        today = _day(time.time())
        with pytest.raises(ValueError, match="what was changed or stopped"):
            privacy_ops.close_dsar(r["id"], closed_by="ops", outcome={
                "kind": "answered", "answered_on": today, "reference": "Opt-out ticket 7"})
        done = privacy_ops.close_dsar(r["id"], closed_by="ops", outcome={
            "kind": "answered", "answered_on": today, "reference": "Opt-out ticket 7",
            "note": "Stopped sale and sharing in the CRM and ad platforms"})
        assert done["status"] == "closed"
        assert done["outcome"]["kind"] == "answered" and done["outcome"]["reference"] == "Opt-out ticket 7"


def _day(ts: float) -> str:
    import datetime as _dt

    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime("%Y-%m-%d")


class TestDsarOutcomes:
    """A request counts as answered only when an answer is on record; a
    deletion also needs the erasure result or the lawful reason for keeping
    the data. Closing without either is reported as exactly that."""

    def _report(self):
        return privacy_ops.program_report(assessment_types={"none"})["dsar"]

    def test_close_without_an_answer_is_not_answered_on_time(self):
        r = privacy_ops.open_dsar("jordan@example.com", "erasure", jurisdiction="eu_gdpr")
        privacy_ops.close_dsar(r["id"], closed_by="dpo")
        dsar = self._report()
        assert dsar["handled"] == 1
        assert dsar["answered"] == 0
        assert dsar["handled_on_time"] == 0
        assert dsar["closed_without_response"] == 1

    def test_recorded_answers_count_and_open_work_stays_open(self):
        today = _day(time.time())
        erased = privacy_ops.open_dsar("a@example.com", "erasure", jurisdiction="eu_gdpr")
        privacy_ops.close_dsar(erased["id"], closed_by="dpo", outcome={
            "kind": "answered", "answered_on": today, "erasure": "erased",
            "reference": "CRM ticket 4521"})
        refused = privacy_ops.open_dsar("b@example.com", "access", jurisdiction="eu_gdpr")
        privacy_ops.close_dsar(refused["id"], closed_by="dpo", outcome={
            "kind": "refused", "answered_on": today, "lawful_basis": "Manifestly unfounded",
            "reference": "Letter 12"})
        manual = privacy_ops.open_dsar("c@example.com", "opt_out", jurisdiction="us_ca_ccpa")
        privacy_ops.close_dsar(manual["id"], closed_by="ops", outcome={
            "kind": "answered", "answered_on": today, "reference": "Opt-out ticket 9",
            "note": "Stopped sale and sharing in the CRM and ad platforms"})
        withdrawn = privacy_ops.open_dsar("d@example.com", "access")
        privacy_ops.close_dsar(withdrawn["id"], closed_by="dpo",
                               outcome={"kind": "withdrawn", "note": "Requester withdrew by phone"})
        waiting = privacy_ops.open_dsar("e@example.com", "erasure")
        privacy_ops.fulfill_dsar(waiting["id"], fulfilled_by="ops")  # awaiting erasure
        privacy_ops.open_dsar("f@example.com", "access", source="public_form", status="unverified")
        dsar = self._report()
        assert dsar["open"] == 2               # waiting for deletion + unverified
        assert dsar["handled"] == 4            # closed or answered only
        assert dsar["answered"] == 3
        assert dsar["handled_on_time"] == 3
        assert dsar["answered_late"] == 0
        assert dsar["withdrawn"] == 1
        assert dsar["closed_without_response"] == 0
        stored = privacy_ops.get_dsar(erased["id"])["outcome"]
        assert stored["kind"] == "answered" and stored["erasure"] == "erased"
        assert stored["recorded_by"] == "dpo" and stored["answered_on"] == today

    def test_outcome_needs_the_facts_that_make_it_true(self):
        today = _day(time.time())
        r = privacy_ops.open_dsar("g@example.com", "erasure", jurisdiction="eu_gdpr")
        bad = (
            {"kind": "maybe"},
            {"kind": "answered", "reference": "x", "erasure": "erased"},  # no date
            {"kind": "answered", "answered_on": "2999-01-01", "reference": "x", "erasure": "erased"},
            {"kind": "answered", "answered_on": "2001-01-01", "reference": "x", "erasure": "erased"},
            {"kind": "answered", "answered_on": today, "reference": "x"},  # erasure result missing
            {"kind": "answered", "answered_on": today, "reference": "x", "erasure": "not_erased"},
            {"kind": "answered", "answered_on": today, "erasure": "erased"},  # no proof reference
            {"kind": "refused", "answered_on": today, "reference": "x"},  # no lawful basis
        )
        for outcome in bad:
            with pytest.raises(ValueError):
                privacy_ops.close_dsar(r["id"], closed_by="dpo", outcome=outcome)
        assert privacy_ops.get_dsar(r["id"])["status"] == "open"
        kept = privacy_ops.close_dsar(r["id"], closed_by="dpo", outcome={
            "kind": "answered", "answered_on": today, "reference": "x",
            "erasure": "not_erased", "lawful_basis": "Tax records kept for 6 years"})
        assert kept["status"] == "closed"
        assert kept["outcome"]["lawful_basis"] == "Tax records kept for 6 years"

    def test_a_request_marked_answered_stays_answered_when_closed(self):
        r = privacy_ops.open_dsar("k@example.com", "opt_out", jurisdiction="us_ca_ccpa")
        with pytest.raises(ValueError):
            privacy_ops.fulfill_dsar(r["id"], fulfilled_by="ops")  # no click-through answer
        privacy_ops.close_dsar(r["id"], closed_by="ops", outcome={
            "kind": "answered", "answered_on": _day(time.time()), "reference": "Opt-out ticket 11",
            "note": "Stopped sale and sharing in the CRM and ad platforms"})
        dsar = self._report()
        assert dsar["answered"] == 1 and dsar["closed_without_response"] == 0
        # A deletion handed over for erasure is not an answer by itself.
        d = privacy_ops.open_dsar("l@example.com", "erasure")
        privacy_ops.fulfill_dsar(d["id"], fulfilled_by="ops")
        privacy_ops.close_dsar(d["id"], closed_by="ops")
        assert self._report()["closed_without_response"] == 1

    def test_a_closed_request_can_have_its_answer_recorded_once(self):
        today = _day(time.time())
        r = privacy_ops.open_dsar("h@example.com", "access", jurisdiction="eu_gdpr")
        privacy_ops.close_dsar(r["id"], closed_by="dpo")
        assert self._report()["closed_without_response"] == 1
        fixed = privacy_ops.close_dsar(r["id"], closed_by="dpo", outcome={
            "kind": "answered", "answered_on": today, "reference": "Sent from the privacy inbox"})
        assert fixed["outcome"]["kind"] == "answered"
        assert self._report()["handled_on_time"] == 1
        with pytest.raises(privacy_ops.RecordConflict):
            privacy_ops.close_dsar(r["id"], closed_by="dpo", outcome={
                "kind": "refused", "answered_on": today, "reference": "x", "lawful_basis": "y"})
        assert privacy_ops.get_dsar(r["id"])["outcome"]["kind"] == "answered"  # never rewritten

    def test_on_time_uses_the_extended_deadline(self, monkeypatch):
        import time as _t

        real = _t.time
        start = real()
        r = privacy_ops.open_dsar("i@example.com", "access", jurisdiction="eu_gdpr",
                                  received_at=start)
        privacy_ops.extend_dsar(r["id"], reason="Many systems to search", days=30)
        late = privacy_ops.open_dsar("j@example.com", "access", jurisdiction="eu_gdpr",
                                     received_at=start)
        monkeypatch.setattr(_t, "time", lambda: start + 70 * 86400)
        answered_on = _day(start + 40 * 86400)  # after 30 days, inside the extension
        privacy_ops.close_dsar(r["id"], closed_by="dpo", outcome={
            "kind": "answered", "answered_on": answered_on, "reference": "x"})
        privacy_ops.close_dsar(late["id"], closed_by="dpo", outcome={
            "kind": "answered", "answered_on": answered_on, "reference": "x"})
        dsar = self._report()
        assert dsar["answered"] == 2
        assert dsar["handled_on_time"] == 1
        assert dsar["answered_late"] == 1


def test_every_webhook_event_the_privacy_records_emit_is_in_the_catalogue():
    # webhook_events.emit drops an unlisted name with a warning, so a typo or an
    # invented name means subscribers silently receive nothing.
    import re

    from maverick import webhook_events

    source = (Path(privacy_ops.__file__)).read_text(encoding="utf-8")
    emitted = set(re.findall(r'_emit_record_event\(\s*"([a-z_.]+)"', source))
    assert "dsar.opened" in emitted and "incident.closed" in emitted
    assert emitted <= set(webhook_events.EVENT_TYPES)


def test_revising_the_affected_people_sends_no_event_the_catalogue_does_not_know(caplog):
    incident = privacy_ops.open_incident("Misdirected batch", affected_people=120, reported_by="ops")
    with caplog.at_level("WARNING", logger="maverick.webhook_events"):
        privacy_ops.set_incident_affected_people(incident["id"], 80, updated_by="ops")
    assert "unknown event type" not in caplog.text
