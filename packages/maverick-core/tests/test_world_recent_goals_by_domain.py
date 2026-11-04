"""The newest few goals of many domains in one grouped read.

The Results page needs each deliverable pack's latest runs. It used to ask the
world model once per pack (2,031 queries on a full catalog); this is the same
answer from one query per few hundred packs.
"""
from __future__ import annotations

import pytest
from maverick.world_model import WorldModel


def _per_domain_answer(world: WorldModel, domains, *, owner=None, per_domain=5):
    """What the old one-query-per-domain loop returned."""
    answer = {}
    for domain in domains:
        goals = world.list_goals(domain=domain, owner=owner, limit=per_domain, order="desc")
        if goals:
            answer[domain] = goals
    return answer


def _seed(world: WorldModel) -> None:
    for index in range(7):
        world.create_goal(f"finance run {index}", domain="finance_close", owner="user:alice")
    world.create_goal("alice tax run", domain="tax_provision", owner="user:alice")
    for index in range(3):
        world.create_goal(f"tax run {index}", domain="tax_provision", owner="user:bob")
    world.create_goal("no department", domain="")
    world.create_goal("ops run", domain="ops_runbook")


@pytest.mark.parametrize("encrypted", ["0", "1"])
def test_matches_the_one_query_per_domain_answer(tmp_path, monkeypatch, encrypted):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", encrypted)
    world = WorldModel(tmp_path / "world.db")
    _seed(world)
    domains = ["finance_close", "tax_provision", "ops_runbook", "never_ran", ""]
    expected = _per_domain_answer(world, [d for d in domains if d])
    got = world.recent_goals_by_domain(domains)
    assert got == expected
    # newest first, capped per domain, empty domains absent
    assert [g.title for g in got["finance_close"]] == [f"finance run {i}" for i in range(6, 1, -1)]
    assert "never_ran" not in got and "" not in got


def test_owner_filter_is_applied_before_the_per_domain_cap(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    _seed(world)
    domains = ["finance_close", "tax_provision"]
    # Alice's only tax run is older than Bob's three: the cap must apply to her
    # rows, not to everyone's, or she would see nothing.
    got = world.recent_goals_by_domain(domains, owner="user:alice", per_domain=2)
    assert got == _per_domain_answer(world, domains, owner="user:alice", per_domain=2)
    assert [g.title for g in got["tax_provision"]] == ["alice tax run"]
    assert world.recent_goals_by_domain(domains, owner="user:nobody") == {}


def test_per_domain_count_is_honoured(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    _seed(world)
    assert len(world.recent_goals_by_domain(["finance_close"], per_domain=1)["finance_close"]) == 1
    assert len(world.recent_goals_by_domain(["finance_close"], per_domain=50)["finance_close"]) == 7


def test_no_domains_is_an_empty_answer_without_a_query(tmp_path, monkeypatch):
    world = WorldModel(tmp_path / "world.db")

    def refuse(*_args, **_kwargs):
        raise AssertionError("no query expected")

    monkeypatch.setattr(world, "_read_all", refuse)
    assert world.recent_goals_by_domain([]) == {}
    assert world.recent_goals_by_domain(["", ""]) == {}


def test_a_full_catalog_is_a_handful_of_queries_not_one_per_domain(tmp_path, monkeypatch):
    world = WorldModel(tmp_path / "world.db")
    domains = [f"pack_{index:04d}" for index in range(2_031)]
    for domain in domains[::300]:
        world.create_goal(f"run of {domain}", domain=domain)
    calls: list[str] = []
    real = world._read_all

    def counting(sql, params=()):
        calls.append(sql)
        return real(sql, params)

    monkeypatch.setattr(world, "_read_all", counting)
    got = world.recent_goals_by_domain(domains)
    assert sorted(got) == sorted(domains[::300])
    # SQLite caps bound parameters per statement, so the domains go in chunks.
    assert len(calls) <= 6
    assert got == _per_domain_answer(world, domains[::300])
