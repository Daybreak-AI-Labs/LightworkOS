"""Cost-governance layer: a per-principal usage ledger + daily quota check.

Budget caps one run; quotas cap a principal across runs over a rolling day, so
an operator can chargeback / rate-limit spend per user. Default-off and opt-in
(``[quotas] enforce`` or ``MAVERICK_QUOTA_*``). Recording remains fail-soft,
but enforcement rejects corrupt state rather than treating unknown usage as
zero. ``HOME`` is isolated per-test by the autouse conftest
fixture, so every ledger lands under the temp ``~/.maverick``.
"""
from __future__ import annotations

import pytest
from maverick.quotas import (
    UsageLedger,
    over_quota,
    quotas_enforced,
    record_usage,
)


@pytest.fixture(autouse=True)
def _clear_quota_env(monkeypatch):
    for env in (
        "MAVERICK_QUOTA_ENFORCE",
        "MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY",
        "MAVERICK_QUOTA_MAX_TOKENS_PER_DAY",
        "MAVERICK_TENANT",
    ):
        monkeypatch.delenv(env, raising=False)


def _enforce(monkeypatch, *, dollars=0.0, tokens=0):
    monkeypatch.setenv("MAVERICK_QUOTA_ENFORCE", "1")
    if dollars:
        monkeypatch.setenv("MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY", str(dollars))
    if tokens:
        monkeypatch.setenv("MAVERICK_QUOTA_MAX_TOKENS_PER_DAY", str(tokens))


# --- ledger ----------------------------------------------------------------

def test_record_and_usage_roundtrip():
    led = UsageLedger()
    led.record("alice", 1.50, 1000, 200)
    u = led.usage("alice")
    assert u == {"dollars": 1.5, "in_tokens": 1000, "out_tokens": 200}


def test_record_accumulates_within_day():
    led = UsageLedger()
    led.record("alice", 1.0, 100, 10)
    led.record("alice", 2.0, 50, 5)
    u = led.usage("alice")
    assert u["dollars"] == pytest.approx(3.0)
    assert u["in_tokens"] == 150
    assert u["out_tokens"] == 15


def test_usage_unknown_principal_is_zero():
    assert UsageLedger().usage("nobody") == {
        "dollars": 0.0, "in_tokens": 0, "out_tokens": 0,
    }


def test_principals_are_isolated():
    led = UsageLedger()
    led.record("alice", 5.0, 0, 0)
    led.record("bob", 1.0, 0, 0)
    assert led.usage("alice")["dollars"] == pytest.approx(5.0)
    assert led.usage("bob")["dollars"] == pytest.approx(1.0)


def test_record_persists_across_instances():
    UsageLedger().record("alice", 2.0, 0, 0)
    # A fresh instance reads from disk -> concurrent processes accrue correctly.
    assert UsageLedger().usage("alice")["dollars"] == pytest.approx(2.0)


def test_distinct_days_do_not_mix():
    led = UsageLedger()
    led.record("alice", 1.0, 0, 0, day="2026-01-01")
    led.record("alice", 4.0, 0, 0, day="2026-01-02")
    assert led.usage("alice", day="2026-01-01")["dollars"] == pytest.approx(1.0)
    assert led.usage("alice", day="2026-01-02")["dollars"] == pytest.approx(4.0)


def test_negative_inputs_clamped():
    led = UsageLedger()
    led.record("alice", -5.0, -10, -1)
    assert led.usage("alice") == {"dollars": 0.0, "in_tokens": 0, "out_tokens": 0}


def test_blank_principal_ignored():
    led = UsageLedger()
    led.record("", 5.0, 0, 0)
    assert led._load() == {}


def test_ledger_is_tenant_scoped(monkeypatch):
    from maverick.paths import set_tenant
    tok = set_tenant("team-a")
    try:
        UsageLedger().record("alice", 9.0, 0, 0)
    finally:
        from maverick.paths import reset_tenant
        reset_tenant(tok)
    # Different tenant -> different ledger file -> no spend visible.
    tok2 = set_tenant("team-b")
    try:
        assert UsageLedger().usage("alice")["dollars"] == pytest.approx(0.0)
    finally:
        from maverick.paths import reset_tenant
        reset_tenant(tok2)


def test_corrupt_ledger_fails_closed_and_is_not_overwritten(tmp_path):
    path = tmp_path / "ledger.json"
    path.write_text("{ not json")
    led = UsageLedger(path=path)
    original = path.read_text(encoding="utf-8")
    from maverick.quotas import UsageLedgerError
    with pytest.raises(UsageLedgerError):
        led.usage("alice")
    with pytest.raises(UsageLedgerError):
        led.record("alice", 1.0, 0, 0)
    assert path.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("content", ["[]", '{"alice":NaN}', '{"alice":{},"alice":{}}'])
def test_parseable_untrusted_ledger_is_rejected(tmp_path, content):
    from maverick.quotas import UsageLedgerError
    path = tmp_path / "ledger.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(UsageLedgerError):
        UsageLedger(path=path)._load()


def test_record_usage_fail_soft_on_bad_path(monkeypatch, caplog):
    # An unwritable ledger path must not raise out of record_usage.
    import maverick.quotas as q

    class _Boom:
        def record(self, *a, **k):
            raise OSError("disk full")
    monkeypatch.setattr(q, "UsageLedger", lambda *a, **k: _Boom())
    record_usage("alice", 1.0, 1, 1)  # no exception


# --- enforcement toggle ----------------------------------------------------

def test_default_off():
    assert quotas_enforced() is False


def test_enforced_via_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_QUOTA_ENFORCE", "1")
    assert quotas_enforced() is True


def test_enforced_via_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[quotas]\nenforce = true\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert quotas_enforced() is True


# --- over_quota ------------------------------------------------------------

def test_over_quota_none_when_disabled(monkeypatch):
    record_usage("alice", 1000.0, 0, 0)
    assert over_quota("alice") is None  # enforcement off


def test_over_quota_none_when_no_caps(monkeypatch):
    _enforce(monkeypatch)  # enforce on, but no caps set -> no limit
    record_usage("alice", 1000.0, 0, 0)
    assert over_quota("alice") is None


def test_over_quota_dollars(monkeypatch):
    _enforce(monkeypatch, dollars=5.0)
    record_usage("alice", 4.0, 0, 0)
    assert over_quota("alice") is None
    record_usage("alice", 1.5, 0, 0)  # now 5.5 >= 5.0
    reason = over_quota("alice")
    assert reason and "spend quota" in reason


def test_over_quota_tokens(monkeypatch):
    _enforce(monkeypatch, tokens=1000)
    record_usage("alice", 0.0, 600, 300)  # 900 < 1000
    assert over_quota("alice") is None
    record_usage("alice", 0.0, 100, 50)   # 1050 >= 1000
    reason = over_quota("alice")
    assert reason and "token quota" in reason


def test_over_quota_blank_principal(monkeypatch):
    _enforce(monkeypatch, dollars=1.0)
    assert over_quota("") is None


def test_over_quota_isolates_principals(monkeypatch):
    _enforce(monkeypatch, dollars=5.0)
    record_usage("alice", 10.0, 0, 0)
    assert over_quota("alice") is not None
    assert over_quota("bob") is None  # bob hasn't spent


def test_record_is_concurrency_safe(tmp_path):
    """Concurrent records must not lose updates. The load-modify-save in record()
    races without a lock, so simultaneous runs clobber each other -- undercounting
    spend and letting a principal slip past its daily quota."""
    import threading

    ledger = UsageLedger(path=tmp_path / "ledger.json")
    threads_n, per = 16, 40

    def worker():
        for _ in range(per):
            ledger.record("user:alice", 1.0, 10, 5)

    threads = [threading.Thread(target=worker) for _ in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    used = ledger.usage("user:alice")
    total = threads_n * per
    assert used["dollars"] == float(total)
    assert used["in_tokens"] == total * 10
    assert used["out_tokens"] == total * 5
