"""Provider-level cost caps: ledger math, UTC day/month rollover via injected
clock, no-cap passthrough, enforce(), prune, atomic 0600 persistence.
Offline; config comes from a per-test TOML via MAVERICK_CONFIG.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from maverick import provider_cost_cap as pcc
from maverick.file_lock import private_path_is_restricted

T0 = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc).timestamp()
DAY = 86400.0


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_PROVIDER_CAPS_PERIOD", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "nonexistent.toml"))


@pytest.fixture
def caps_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[budget.provider_caps]\nanthropic = 50.0\nopenai = 20.0\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))


@pytest.fixture
def ledger(tmp_path):
    return tmp_path / "provider_spend.json"


# --- record / check math -----------------------------------------------------

def test_record_is_concurrency_safe(ledger):
    """The record() load-modify-save must not lose updates under concurrency.
    Without serialization two writers load the same total and the second save
    clobbers the first -- spend is undercounted and a provider slips past its
    cap. (The flock serializes even across processes; threads exercise the same
    sidecar lock.)"""
    import threading

    n, per = 16, 40
    amount = 0.25

    def worker():
        for _ in range(per):
            pcc.record("anthropic", amount, now=T0, path=ledger)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    spent = pcc.check("anthropic", now=T0, path=ledger).spent
    assert spent == pytest.approx(n * per * amount), spent


def test_record_and_check_math(caps_config, ledger):
    pcc.record("anthropic", 10.0, now=T0, path=ledger)
    pcc.record("anthropic", 5.5, now=T0, path=ledger)
    st = pcc.check("anthropic", now=T0, path=ledger)
    assert st.allowed is True
    assert st.spent == pytest.approx(15.5)
    assert st.cap == 50.0
    assert st.remaining == pytest.approx(34.5)


def test_providers_are_tracked_separately(caps_config, ledger):
    pcc.record("anthropic", 10.0, now=T0, path=ledger)
    pcc.record("openai", 19.0, now=T0, path=ledger)
    assert pcc.check("anthropic", now=T0, path=ledger).spent == 10.0
    assert pcc.check("openai", now=T0, path=ledger).spent == 19.0


def test_provider_names_canonicalized(caps_config, ledger):
    pcc.record("  Anthropic ", 10.0, now=T0, path=ledger)
    assert pcc.check("ANTHROPIC", now=T0, path=ledger).spent == 10.0


def test_negative_and_blank_records_ignored(caps_config, ledger):
    pcc.record("anthropic", -5.0, now=T0, path=ledger)
    pcc.record("", 5.0, now=T0, path=ledger)
    assert not ledger.exists()
    assert pcc.check("anthropic", now=T0, path=ledger).spent == 0.0


def test_would_exceed(caps_config, ledger):
    pcc.record("anthropic", 45.0, now=T0, path=ledger)
    assert pcc.would_exceed("anthropic", 6.0, now=T0, path=ledger) is True
    assert pcc.would_exceed("anthropic", 5.0, now=T0, path=ledger) is False
    assert pcc.would_exceed("mistral", 1e9, now=T0, path=ledger) is False  # no cap


def test_at_cap_is_blocked(caps_config, ledger):
    pcc.record("anthropic", 50.0, now=T0, path=ledger)
    st = pcc.check("anthropic", now=T0, path=ledger)
    assert st.allowed is False and st.remaining == 0.0


# --- enforce -------------------------------------------------------------------

def test_enforce_raises_when_over(caps_config, ledger):
    pcc.record("openai", 25.0, now=T0, path=ledger)
    with pytest.raises(pcc.ProviderCapExceeded) as exc:
        pcc.enforce("openai", now=T0, path=ledger)
    assert exc.value.provider == "openai"
    assert exc.value.spent == 25.0
    assert exc.value.cap == 20.0
    assert exc.value.period_key == "2026-06-10"


def test_enforce_passes_under_cap(caps_config, ledger):
    pcc.record("openai", 1.0, now=T0, path=ledger)
    st = pcc.enforce("openai", now=T0, path=ledger)
    assert st.allowed and st.remaining == pytest.approx(19.0)


def test_enforce_noop_without_cap(ledger):
    pcc.record("anthropic", 10_000.0, now=T0, path=ledger)  # no config at all
    st = pcc.enforce("anthropic", now=T0, path=ledger)
    assert st.allowed and st.cap is None and st.remaining is None


def test_enforce_raises_when_projection_would_exceed(caps_config, ledger):
    # Under the cap on recorded spend ($19 < $20), but this call's projected $5
    # would push it to $24 -- projection must block it BEFORE dispatch, where the
    # old spend-only check let it (and a concurrent set of such calls) sail past.
    pcc.record("openai", 19.0, now=T0, path=ledger)
    with pytest.raises(pcc.ProviderCapExceeded):
        pcc.enforce("openai", projected_dollars=5.0, now=T0, path=ledger)


def test_enforce_passes_when_projection_fits(caps_config, ledger):
    pcc.record("openai", 10.0, now=T0, path=ledger)
    st = pcc.enforce("openai", projected_dollars=5.0, now=T0, path=ledger)  # 15 < 20
    assert st.allowed


def test_enforce_noop_projection_without_cap(ledger):
    # A huge projection on a provider with no cap configured is still a no-op.
    st = pcc.enforce("anthropic", projected_dollars=10_000.0, now=T0, path=ledger)
    assert st.allowed and st.cap is None


# --- period rollover (injected clock) --------------------------------------------

def test_day_rollover_resets_the_window(caps_config, ledger):
    pcc.record("anthropic", 50.0, now=T0, path=ledger)
    assert pcc.check("anthropic", now=T0, path=ledger).allowed is False
    next_day = T0 + DAY
    assert pcc.check("anthropic", now=next_day, path=ledger).allowed is True
    assert pcc.check("anthropic", now=next_day, path=ledger).spent == 0.0


def test_month_period(monkeypatch, tmp_path, ledger):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '[budget]\nprovider_caps_period = "month"\n'
        "[budget.provider_caps]\nanthropic = 50.0\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    pcc.record("anthropic", 30.0, now=T0, path=ledger)
    pcc.record("anthropic", 25.0, now=T0 + 10 * DAY, path=ledger)  # same month
    st = pcc.check("anthropic", now=T0 + 15 * DAY, path=ledger)    # June 25
    assert st.spent == 55.0 and st.allowed is False
    # July: fresh window.
    july = datetime(2026, 7, 1, tzinfo=timezone.utc).timestamp()
    assert pcc.check("anthropic", now=july, path=ledger).allowed is True


def test_period_env_wins_over_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[budget]\nprovider_caps_period = "month"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert pcc.period_from_config() == "month"
    monkeypatch.setenv("MAVERICK_PROVIDER_CAPS_PERIOD", "day")
    assert pcc.period_from_config() == "day"


def test_period_key_shapes():
    assert pcc.period_key(T0, period="day") == "2026-06-10"
    assert pcc.period_key(T0, period="month") == "2026-06"


# --- prune ------------------------------------------------------------------------

def test_prune_drops_old_periods(caps_config, ledger):
    pcc.record("anthropic", 1.0, now=T0, path=ledger)
    pcc.record("anthropic", 2.0, now=T0 + DAY, path=ledger)
    pcc.record("anthropic", 3.0, now=T0 + 2 * DAY, path=ledger)
    assert len(json.loads(ledger.read_text(encoding="utf-8"))) == 3
    removed = pcc.prune(now=T0 + 2 * DAY, path=ledger)
    assert removed == 2
    data = json.loads(ledger.read_text(encoding="utf-8"))
    assert list(data) == ["2026-06-12"]
    assert pcc.check("anthropic", now=T0 + 2 * DAY, path=ledger).spent == 3.0
    assert pcc.prune(now=T0 + 2 * DAY, path=ledger) == 0  # idempotent


# --- persistence ---------------------------------------------------------------------

def test_ledger_is_atomic_0600_json(caps_config, ledger):
    pcc.record("anthropic", 1.0, now=T0, path=ledger)
    assert private_path_is_restricted(ledger, 0o600)
    assert private_path_is_restricted(ledger.parent, 0o700)
    assert json.loads(ledger.read_text(encoding="utf-8")) == {
        "2026-06-10": {"anthropic": 1.0},
    }
    assert list(ledger.parent.glob("*.tmp")) == []  # no temp droppings


def test_corrupt_ledger_blocks_admission_and_preserves_original(caps_config, ledger):
    ledger.write_text("{ nope", encoding="utf-8")
    with pytest.raises(pcc.ProviderAccountingUnavailable):
        pcc.check("anthropic", now=T0, path=ledger)
    pcc.record("anthropic", 2.0, now=T0, path=ledger)
    assert ledger.read_text(encoding="utf-8") == "{ nope"


def test_default_ledger_under_data_dir(caps_config):
    # conftest isolates HOME, so the default path lands in the temp home.
    from maverick.paths import data_dir
    pcc.record("anthropic", 4.0, now=T0)
    assert data_dir("provider_spend.json").exists()
    assert pcc.check("anthropic", now=T0).spent == 4.0


# --- config readers fail soft ---------------------------------------------------------

def test_caps_from_config_defaults_empty():
    assert pcc.caps_from_config() == {}
    assert pcc.period_from_config() == "day"


def test_caps_from_config_rejects_nonfinite_ceiling(monkeypatch):
    monkeypatch.setattr(
        pcc,
        "_budget_cfg",
        lambda: {
            "provider_caps": {
                "openai": float("inf"),
                "anthropic": float("nan"),
                "safe": 12.5,
            },
        },
    )

    assert pcc.caps_from_config() == {"safe": 12.5}


def test_caps_from_config_drops_bogus_entries(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[budget.provider_caps]\n"
        'anthropic = 50.0\nopenai = "lots"\nfree = 0.0\nneg = -3\nflag = true\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert pcc.caps_from_config() == {"anthropic": 50.0}


def test_bogus_period_falls_back_to_day(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[budget]\nprovider_caps_period = "week"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert pcc.period_from_config() == "day"
