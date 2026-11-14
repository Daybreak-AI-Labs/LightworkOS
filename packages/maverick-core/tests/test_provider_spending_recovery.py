"""Real local accounting review/export/repair, with synthetic authority and no network."""
import json

import pytest
from maverick import audit, config, workspace_recovery
from maverick import provider_cost_cap as cap
from maverick import provider_spending_recovery as spending
from maverick.paths import tenant_scope


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"openai": 20.0})
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-06")
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "_ledger_path", lambda: tmp_path / "provider_spend.json")
    monkeypatch.setattr(cap, "_deployment_ledger_path", lambda: tmp_path / "provider_spend.json")
    monkeypatch.setattr(workspace_recovery, "_key", lambda: bytes(range(32)))
    monkeypatch.setattr(audit, "record", lambda *a, **kw: True)
    monkeypatch.setattr("maverick.installation_recovery.blockers", list)
    with tenant_scope(tenant="review-workspace"):
        yield cap._ledger_path()
    config.reset_config_cache()


def test_known_hold_review_requires_explicit_bound_confirmation_and_keeps_other_holds(ledger):
    selected = cap.reserve("openai", 3, request_id="selected")
    other = cap.reserve("openai", 4, request_id="other")
    cap.settle(selected, None)
    review = spending.prepare_hold("openai", selected.period, selected.request_id, 2,
                                   "Final invoice INV-7, verified against this request.", actor="user:owner", context="context-a")
    for actor, context, confirm in [("user:other", "context-a", True), ("user:owner", "other", True),
                                     ("user:owner", "context-a", False)]:
        with pytest.raises(spending.SpendingReviewError):
            spending.apply(review["id"], actor=actor, context=context, isolated=False, confirm=confirm)
    completed = spending.apply(review["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)
    assert completed["state"] == "completed"
    assert cap.check("openai").spent == 2 and cap.check("openai").reserved == 4
    assert spending.apply(review["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)["state"] == "completed"
    cap.settle(other, 1)
    assert cap.check("openai").spent == 3
    retained = spending._REVIEWS.get(review["id"])
    assert retained["actor"] == "user:owner" and retained["evidence"].startswith("Final invoice")


def test_running_hold_cannot_be_reconciled_in_normal_mode_and_stale_review_refuses(ledger):
    held = cap.reserve("openai", 3, request_id="running")
    with pytest.raises(spending.SpendingReviewError, match="may still be running"):
        spending.prepare_hold("openai", held.period, held.request_id, 1, "Final receipt verified", actor="user:owner", context="context-a")
    cap.settle(held, None)
    review = spending.prepare_hold("openai", held.period, held.request_id, 1, "Final receipt verified", actor="user:owner", context="context-a")
    # Another confirmed cost changes the exact balance reviewed by the owner.
    cap.record("openai", 1)
    before = ledger.read_bytes()
    with pytest.raises(cap.ProviderAccountingUnavailable):
        spending.apply(review["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)
    assert ledger.read_bytes() == before


def test_signed_complete_repair_preserves_failed_bytes_and_never_rewinds_known_spend(ledger):
    cap.record("openai", 5)
    held = cap.reserve("openai", 3, request_id="preserved-hold")
    exported = spending.export_accounting()
    ledger.write_text("{damaged", encoding="utf-8")
    with pytest.raises(spending.SpendingReviewError, match="isolated"):
        spending.stage_import(exported, actor="user:owner", context="context-a", isolated=False)
    imported = spending.stage_import(exported, actor="user:owner", context="context-a", isolated=True)
    totals = [{"provider": "openai", "period": held.period, "confirmed": 4}]
    with pytest.raises(spending.SpendingReviewError, match="cannot reduce"):
        spending.prepare_repair(imported["id"], totals, "Final invoice all rows verified", actor="user:owner", context="context-a", isolated=True, receipts_complete=True)
    totals[0]["confirmed"] = 7
    review = spending.prepare_repair(imported["id"], totals, "Final invoice all rows verified", actor="user:owner", context="context-a", isolated=True, receipts_complete=True)
    with pytest.raises(spending.SpendingReviewError, match="isolated"):
        spending.apply(review["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)
    assert spending.apply(review["id"], actor="user:owner", context="context-a", isolated=True, confirm=True)["state"] == "completed"
    assert cap.check("openai").spent == 7 and cap.check("openai").reserved == 3
    from maverick.paths import data_dir
    assert data_dir("provider_accounting_reviews", review["id"] + ".failed").read_bytes() == b"{damaged"
    assert ledger.with_suffix(".json.required").exists()
    assert spending.apply(review["id"], actor="user:owner", context="context-a", isolated=True, confirm=True)["state"] == "completed"


def test_import_rejects_changed_authenticated_bytes_and_other_target(ledger, monkeypatch):
    cap.record("openai", 5)
    exported = spending.export_accounting()
    changed = json.loads(exported)
    changed["ledger"]["2026-09-06"]["openai"] = 0
    with pytest.raises(spending.SpendingReviewError, match="authenticated"):
        spending.stage_import(json.dumps(changed).encode(), actor="user:owner", context="context-a", isolated=True)
    monkeypatch.setattr(spending, "target", lambda: "different-workspace")
    with pytest.raises(spending.SpendingReviewError):
        spending.stage_import(exported, actor="user:owner", context="context-a", isolated=True)


def test_healthy_accounting_cannot_be_replaced_from_an_older_valid_export(ledger):
    cap.record("openai", 5)
    exported = spending.export_accounting()
    cap.record("openai", 8)
    before = ledger.read_bytes()
    with pytest.raises(spending.SpendingReviewError, match="readable"):
        spending.prepare_repair(exported, [{"provider": "openai", "period": cap.period_key(), "confirmed": 5}],
                                "Verified older receipt", actor="user:owner", context="context-a", isolated=True, receipts_complete=True)
    assert ledger.read_bytes() == before
    assert cap.check("openai").spent == 13


def test_interrupted_settlement_can_finalize_after_expiry_without_reapplying(ledger, monkeypatch):
    held = cap.reserve("openai", 3, request_id="interrupted")
    cap.settle(held, None)
    selected = spending.prepare_hold("openai", held.period, held.request_id, 2, "Verified final receipt",
                                    actor="user:owner", context="context-a")
    original = spending._REVIEWS.update
    def fail_completion(*args, **kwargs):
        if kwargs.get("action") == "complete":
            raise OSError("synthetic completion persistence failure")
        return original(*args, **kwargs)
    monkeypatch.setattr(spending._REVIEWS, "update", fail_completion)
    with pytest.raises(OSError):
        spending.apply(selected["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)
    assert cap.check("openai").spent == 2
    assert spending.review(selected["id"], actor="user:owner", context="context-a")["state"] == "applying"
    before = ledger.read_bytes()
    monkeypatch.setattr(spending._REVIEWS, "update", original)
    monkeypatch.setattr(spending.time, "time", lambda: selected["expires_at"] + 1)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-07")
    assert spending.apply(selected["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)["state"] == "completed"
    assert ledger.read_bytes() == before
    old = spending.status("2026-09-06")
    assert old["providers"][0]["spent"] == 2
    with pytest.raises(spending.SpendingReviewError):
        spending.review(selected["id"], actor="user:other", context="context-a")


def test_expired_review_without_ledger_change_cannot_apply(ledger, monkeypatch):
    held = cap.reserve("openai", 3, request_id="expired")
    cap.settle(held, None)
    selected = spending.prepare_hold("openai", held.period, held.request_id, 1, "Verified final receipt",
                                    actor="user:owner", context="context-a")
    before = ledger.read_bytes()
    monkeypatch.setattr(spending.time, "time", lambda: selected["expires_at"] + 1)
    with pytest.raises(cap.ProviderAccountingUnavailable):
        spending.apply(selected["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)
    assert ledger.read_bytes() == before


def test_repair_requires_complete_receipts_and_can_include_later_provider_periods(ledger):
    cap.record("openai", 5)
    exported = spending.export_accounting()
    ledger.write_text("{damaged", encoding="utf-8")
    totals = [{"provider": "openai", "period": cap.period_key(), "confirmed": 7},
              {"provider": "former-provider", "period": "2026-08", "confirmed": 9}]
    kwargs = {"actor": "user:owner", "context": "context-a", "isolated": True}
    with pytest.raises(spending.SpendingReviewError, match="every call"):
        spending.prepare_repair(exported, totals, "Final invoices across all providers", **kwargs)
    before = ledger.read_bytes()
    for malformed in [totals[1:], totals + [totals[0]], [totals[0], {**totals[1], "period": "2026-99"}]]:
        with pytest.raises(spending.SpendingReviewError):
            spending.prepare_repair(exported, malformed, "Final invoices across all providers", receipts_complete=True, **kwargs)
        assert ledger.read_bytes() == before
    selected = spending.prepare_repair(exported, totals, "Final invoices across all providers", receipts_complete=True, **kwargs)
    spending.apply(selected["id"], confirm=True, **kwargs)
    assert cap.check("openai").spent == 7
    past = spending.status("2026-08", provider="former-provider")
    assert past["providers"][0]["spent"] == 9 and past["providers"][0]["cap"] is None


def test_reservations_after_500_are_visible_and_reconcilable(ledger):
    period = cap.period_key()
    rows = {f"hold-{number:04d}": {"projected": 0.01, "state": "unknown", "actual": None} for number in range(501)}
    cap._save(ledger, {period: {"openai": 5.01}, cap._RECEIPTS: {period: {"openai": rows}}})
    first = spending.status()
    assert len(first["providers"][0]["holds"]) == 100
    assert first["providers"][0]["holds_total"] == 501
    last = spending.status(offset=500)["providers"][0]
    assert last["holds_next_offset"] is None and last["holds"][0]["id"] == "hold-0500"
    selected = spending.prepare_hold("openai", period, "hold-0500", 0.02, "Exact final invoice item verified",
                                    actor="user:owner", context="context-a")
    spending.apply(selected["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)
    assert spending.status()["providers"][0]["holds_total"] == 500
    assert cap.check("openai").spent == pytest.approx(0.02)


def test_repair_completion_retry_preserves_failed_copy_and_exact_ledger(ledger, monkeypatch):
    cap.record("openai", 5)
    exported = spending.export_accounting()
    ledger.write_text("{damaged", encoding="utf-8")
    selected = spending.prepare_repair(exported, [{"provider": "openai", "period": cap.period_key(), "confirmed": 7}],
                                      "Every final receipt verified since export", actor="user:owner", context="context-a",
                                      isolated=True, receipts_complete=True)
    original = spending._REVIEWS.update
    def fail_completion(*args, **kwargs):
        if kwargs.get("action") == "complete":
            raise OSError("synthetic completion persistence failure")
        return original(*args, **kwargs)
    monkeypatch.setattr(spending._REVIEWS, "update", fail_completion)
    with pytest.raises(OSError):
        spending.apply(selected["id"], actor="user:owner", context="context-a", isolated=True, confirm=True)
    assert cap.check("openai").spent == 7
    from maverick.paths import data_dir
    failed = data_dir("provider_accounting_reviews", selected["id"] + ".failed")
    assert failed.read_bytes() == b"{damaged"
    before = ledger.read_bytes()
    monkeypatch.setattr(spending._REVIEWS, "update", original)
    monkeypatch.setattr(spending.time, "time", lambda: selected["expires_at"] + 1)
    assert spending.apply(selected["id"], actor="user:owner", context="context-a", isolated=True, confirm=True)["state"] == "completed"
    assert ledger.read_bytes() == before and failed.read_bytes() == b"{damaged"


def test_oversized_ledger_is_refused_before_loading_its_contents(ledger, monkeypatch):
    cap.record("openai", 5)
    before = ledger.read_bytes()
    monkeypatch.setattr(cap, "_MAX_LEDGER_BYTES", 1)
    def forbidden_read(*_a, **_kw):
        pytest.fail("oversized ledger must not be materialized")
    monkeypatch.setattr(cap, "atomic_read_text", forbidden_read)
    with pytest.raises(cap.ProviderAccountingUnavailable):
        cap.reserve("openai", 1)
    assert ledger.read_bytes() == before


def test_review_is_invalidated_when_shared_authority_identity_changes(ledger, monkeypatch):
    # Keep the same synthetic balance and caller to isolate DSN identity binding.
    monkeypatch.setattr("maverick.world_model_backends.is_postgres_configured", lambda: True)
    monkeypatch.setenv("MAVERICK_PG_DSN", "host=first.invalid")
    held = cap.reserve("openai", 3, request_id="dsn-bound")
    cap.settle(held, None)
    selected = spending.prepare_hold("openai", held.period, held.request_id, 2, "Final provider receipt verified",
                                    actor="user:owner", context="context-a")
    original_target = spending.target()
    before = ledger.read_bytes()
    monkeypatch.setenv("MAVERICK_PG_DSN", "host=second.invalid")
    assert spending.target() != original_target
    assert "host=" not in original_target
    with pytest.raises(spending.SpendingReviewError, match="workspace"):
        spending.apply(selected["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)
    assert ledger.read_bytes() == before


def test_reconciled_hold_also_settles_the_organization_admission_hold(ledger):
    # An unknown zero-projection organization hold counts as infinite against
    # today's cap. Reconciling the provider receipt must settle it as well, or
    # the workspace stays blocked from provider calls until the day ends.
    from maverick.tenant import provider_admission as organization

    held = cap.reserve("openai", 0, request_id="unknown-cost")
    assert held.organization_tenant == "review-workspace"
    cap.settle(held, None)
    assert organization.outstanding("review-workspace") == float("inf")
    review = spending.prepare_hold("openai", held.period, held.request_id, 2,
                                   "Final invoice INV-9, verified against this request.",
                                   actor="user:owner", context="context-a")
    spending.apply(review["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)
    assert organization.outstanding("review-workspace") < float("inf")
    key = organization._key("openai", "unknown-cost")
    call = organization._load("review-workspace", key=key)["calls"][key]
    assert (call["state"], call["actual"]) == ("settled", 2.0)
    # Re-applying a completed review stays idempotent for both authorities.
    spending.apply(review["id"], actor="user:owner", context="context-a", isolated=False, confirm=True)
    assert organization.outstanding("review-workspace") < float("inf")


def test_hold_review_completes_when_the_organization_reference_was_never_attached(ledger, monkeypatch):
    # A crash between the provider hold and publishing its reference leaves the
    # organization call with no reference. The review must still complete and
    # leave both ledgers settled at the reviewed cost.
    from maverick.tenant import provider_admission as organization

    with monkeypatch.context() as crash:
        crash.setattr(organization, "attach_reference",
                      lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()))
        crash.setattr(organization, "cancel_before_dispatch", lambda handle: None)
        crash.setattr(cap, "_settle_provider", lambda *a, **k: None)  # the crash skipped cleanup
        with pytest.raises(KeyboardInterrupt):
            cap.reserve("openai", 0, request_id="crashed")
    key = organization._key("openai", "crashed")
    assert organization._load("review-workspace", key=key)["calls"][key]["reference"] is None
    # The crashed process never settled its provider hold: reconcile it in
    # isolated recovery mode.
    review = spending.prepare_hold("openai", "2026-09-06", "crashed", 2,
                                   "Final invoice INV-11, verified against this request.",
                                   actor="user:owner", context="context-a", isolated=True)
    done = spending.apply(review["id"], actor="user:owner", context="context-a", isolated=True, confirm=True)
    assert done["state"] == "completed"
    call = organization._load("review-workspace", key=key)["calls"][key]
    assert (call["state"], call["actual"]) == ("settled", 2.0)
    assert cap.check("openai").spent == 2


def test_an_unreadable_earlier_tenant_ledger_is_named_and_repairable(tmp_path, monkeypatch):
    """A corrupt pre-upgrade per-tenant ledger blocks calls (fail closed), the
    refusal names the file, export still works, and a reviewed repair whose
    confirmed totals include that spend lets the deployment resume."""
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"openai": 20.0})
    monkeypatch.setattr(cap, "_admission_cap", lambda name: 20.0)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-06")
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(workspace_recovery, "_key", lambda: bytes(range(32)))
    monkeypatch.setattr(audit, "record", lambda *a, **kw: True)
    monkeypatch.setattr("maverick.installation_recovery.blockers", list)
    cap.record("openai", 2.0)                                   # deployment ledger is healthy
    old = tmp_path / "tenants" / "acme" / "provider_spend.json"
    old.parent.mkdir(parents=True)
    old.write_text("{damaged", encoding="utf-8")
    cap._FOLDED.clear()
    with pytest.raises(cap.EarlierTenantLedgerUnreadable, match="tenants/acme/provider_spend.json"):
        cap.check("openai")
    status = spending.status()
    assert status["available"] is False and "tenants/acme" in status["message"]
    exported = spending.export_accounting()
    kwargs = {"actor": "user:owner", "context": "context-a", "isolated": True}
    review = spending.prepare_repair(exported, [{"provider": "openai", "period": "2026-09-06", "confirmed": 9}],
                                     "Final invoices include the earlier workspace", receipts_complete=True, **kwargs)
    spending.apply(review["id"], confirm=True, **kwargs)
    cap._FOLDED.clear()                                         # a fresh process
    assert cap.check("openai").spent == 9
    assert old.read_text(encoding="utf-8") == "{damaged"        # evidence kept
    config.reset_config_cache()
