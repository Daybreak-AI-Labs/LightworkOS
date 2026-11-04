"""The DSAR estate worksheet: where a human looks beyond the platform.

The assertions that matter: the worksheet reflects the platform's own
holdings, surfaces only identifying data-map assets, lists every vendor
that is not offboarded as a processor (a newly registered vendor starts
under review and may already hold the subject's data), and degrades every absent module to ``enabled: false``
instead of failing.
"""
from __future__ import annotations

import pytest
from maverick import config, privacy_ops


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[privacy_ops]\nenable = true\n\n"
        "[data_map]\nenable = true\n\n"
        "[vendor_management]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_worksheet_builds_the_estate_search_plan():
    from maverick import data_map, vendor_management

    request = privacy_ops.open_dsar(
        "alice@example.com", kind="access", opened_by="ops",
    )
    data_map.register_data_asset(
        "crm.contacts", system="snowflake", kind="table", owner="data",
        actor="ops", columns=["id", "email", "phone"],
    )
    # A flagged-but-non-identifying asset stays off the worksheet.
    data_map.register_data_asset(
        "vault.secrets", system="snowflake", kind="table", owner="sec",
        actor="ops", columns=["api_key"],
    )
    vendor_management.register_vendor(
        "Acme Analytics", category="analytics", criticality="high",
        owner="procurement", actor="ops",
    )
    gone = vendor_management.register_vendor(
        "Retired Mailer", category="email", criticality="low",
        owner="procurement", actor="ops",
    )
    vendor_management.set_vendor_status(
        gone["id"], "offboarded", actor="ops",
        expected_revision=gone["revision"],
    )

    plan = privacy_ops.dsar_estate_worksheet(request["id"])
    assert plan["request_id"] == request["id"]
    assert plan["kind"] == "access"
    assert plan["platform_holdings"]["enabled"] is True
    assert isinstance(plan["platform_holdings"]["sections"], dict)
    assert [asset["name"] for asset in plan["data_map"]["assets"]] == [
        "crm.contacts"
    ]
    assert plan["data_map"]["assets"][0]["categories"] == ["email", "phone"]
    assert plan["processors"]["vendors"][0]["name"] == "Acme Analytics"
    assert [v["name"] for v in plan["processors"]["vendors"]] == [
        "Acme Analytics"
    ]
    assert plan["processors"]["vendors"][0]["status"] == "under_review"
    # Document discovery has no configured sources here: no hits, and
    # discover() contributes nothing rather than erroring.
    assert plan["documents"].get("hits", []) == []


def test_worksheet_degrades_when_the_estate_modules_are_off(tmp_path):
    (tmp_path / "config.toml").write_text(
        "[privacy_ops]\nenable = true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    request = privacy_ops.open_dsar(
        "bob@example.com", kind="erasure", opened_by="ops",
    )
    plan = privacy_ops.dsar_estate_worksheet(request["id"])
    assert plan["data_map"]["enabled"] is False
    assert plan["processors"]["enabled"] is False
    assert plan["platform_holdings"]["enabled"] is True
    with pytest.raises(KeyError):
        privacy_ops.dsar_estate_worksheet("DSAR-nope")


def _seed_platform_world():
    """Alice has a conversation and a goal on slack; bob has one too (isolation)."""
    from maverick.world_model import world_for_tenant

    world = world_for_tenant("__active__")
    conv = world.get_or_create_conversation("slack", "alice@example.com")
    goal = world.create_goal("alice's renewal", "renew the contract")
    world.append_turn(conv.id, "user", "please renew", goal_id=goal)
    bob = world.get_or_create_conversation("slack", "bob@example.com")
    bob_goal = world.create_goal("bob's goal", "something else")
    world.append_turn(bob.id, "user", "hello", goal_id=bob_goal)
    return world


def test_worksheet_counts_the_conversations_and_goals_the_platform_holds():
    """The estate plan must not tell the officer the platform holds nothing when
    it holds conversations and goals: it counts the nested world sections and
    reads them for the request's own channel."""
    _seed_platform_world()
    request = privacy_ops.open_dsar(
        "alice@example.com", kind="access", channel="slack", opened_by="ops",
    )

    sections = privacy_ops.dsar_estate_worksheet(request["id"])[
        "platform_holdings"]["sections"]

    assert sections["conversations"] == 1
    assert sections["turns"] == 1
    assert sections["goals"] == 1
    assert "audit" in sections  # the previously reported section is kept


def test_worksheet_uses_the_request_channel_when_the_id_is_on_two_channels():
    """The same id on two channels is ambiguous without the request's channel;
    the export fails closed, so the worksheet must use the request's channel
    rather than report an empty estate."""
    world = _seed_platform_world()
    world.get_or_create_conversation("telegram", "alice@example.com")
    request = privacy_ops.open_dsar(
        "alice@example.com", kind="access", channel="slack", opened_by="ops",
    )

    holdings = privacy_ops.dsar_estate_worksheet(request["id"])["platform_holdings"]

    assert holdings["sections"]["conversations"] == 1
    assert holdings["resolved"] is True


def test_worksheet_says_so_when_the_account_cannot_be_resolved():
    """With no channel on the request and the id on two channels, nothing can be
    counted safely: say that, rather than reporting zero records."""
    world = _seed_platform_world()
    world.get_or_create_conversation("telegram", "alice@example.com")
    request = privacy_ops.open_dsar(
        "alice@example.com", kind="access", opened_by="ops",
    )

    holdings = privacy_ops.dsar_estate_worksheet(request["id"])["platform_holdings"]

    assert holdings["enabled"] is True
    assert holdings["resolved"] is False
    # Nothing was read: the zeros keep the section's shape and are not a count.
    assert set(holdings["sections"]) == {
        "conversations", "turns", "goals", "episodes", "facts", "fact_history", "audit",
    }
    assert set(holdings["sections"].values()) == {0}


def test_fulfil_names_the_ambiguous_account_and_keeps_the_request_open():
    """The same two-channel subject must not be fulfilled with an empty export
    (nothing is read when the account cannot be resolved), and the refusal
    must say what the officer can do, not blame storage."""
    world = _seed_platform_world()
    world.get_or_create_conversation("telegram", "alice@example.com")
    request = privacy_ops.open_dsar(
        "alice@example.com", kind="access", opened_by="ops",
    )

    with pytest.raises(ValueError, match="more than one channel"):
        privacy_ops.fulfill_dsar(request["id"])

    assert privacy_ops.get_dsar(request["id"])["status"] == "open"
    assert privacy_ops.read_dsar_export(request["id"]) is None
