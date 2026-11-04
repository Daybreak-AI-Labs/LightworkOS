"""The Results page at catalog scale: one grouped read for every pack's latest
runs, and 25 deliverables per page instead of all 2,031 (1.16 MB of HTML,
356,000 px tall on a phone)."""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import _deliverable_specs, app
from maverick_dashboard.deliverables import (
    PAGE_SIZE,
    build_inbox,
    paginate,
    recent_runs_by_domain,
)

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@dataclass
class _Run:
    id: int
    title: str
    status: str
    updated_at: float


def _spec(index: int, *, gate: str | None = None, consumers=("analyst",)) -> dict:
    return {"domain": f"pack_{index:03d}", "deliverable": f"Deliverable {index:03d}",
            "shape": "report", "consumers": list(consumers), "cadence": "",
            "gate": gate, "suite": None}


def _titles(model: dict) -> list[str]:
    return [it["deliverable"] for it in model["items"]]


class TestPaginate:
    def test_page_size_is_twenty_five(self):
        assert PAGE_SIZE == 25

    def test_first_page_holds_one_page_of_the_whole_list(self):
        got = paginate(list(range(60)))
        assert got["page_items"] == list(range(25))
        assert (got["page"], got["pages"], got["total"]) == (1, 3, 60)
        assert (got["first"], got["last"]) == (1, 25)
        assert (got["prev"], got["next"]) == (None, 2)

    def test_later_pages_and_the_short_last_page(self):
        second = paginate(list(range(60)), 2)
        assert second["page_items"] == list(range(25, 50))
        assert (second["first"], second["last"], second["prev"], second["next"]) == (26, 50, 1, 3)
        last = paginate(list(range(60)), 3)
        assert last["page_items"] == list(range(50, 60))
        assert (last["first"], last["last"], last["prev"], last["next"]) == (51, 60, 2, None)

    @pytest.mark.parametrize("asked,expected", [
        (0, 1), (-4, 1), (99, 3), ("2", 2), (" 3 ", 3), ("zzz", 1), ("2.5", 1), (None, 1), ("", 1),
    ])
    def test_an_odd_page_number_never_breaks_the_page(self, asked, expected):
        got = paginate(list(range(60)), asked)
        assert got["page"] == expected and got["page_items"]

    def test_everything_on_one_page_has_no_neighbours(self):
        got = paginate(list(range(3)))
        assert got["pages"] == 1 and got["page_items"] == [0, 1, 2]
        assert got["prev"] is None and got["next"] is None

    def test_an_empty_list_is_one_empty_page(self):
        got = paginate([])
        assert got["page_items"] == [] and got["pages"] == 1 and got["total"] == 0
        assert (got["first"], got["last"]) == (0, 0)

    def test_page_size_can_be_chosen(self):
        assert paginate(list(range(10)), 2, per_page=4)["page_items"] == [4, 5, 6, 7]


class TestInbox:
    def test_the_model_pages_its_own_items_and_keeps_the_whole_view(self):
        m = build_inbox([_spec(i) for i in range(60)], {})
        assert len(m["items"]) == 60   # the header counts the whole view, not a page
        page = m["paginate"]("2")
        assert [it["deliverable"] for it in page["page_items"]][:2] == ["Deliverable 025", "Deliverable 026"]
        assert (page["page"], page["pages"], page["total"]) == (2, 3, 60)

    def test_results_come_before_deliverables_nobody_has_produced(self):
        # With 2,031 packs and a handful of results, alphabetical order alone
        # would bury every result on a late page.
        specs = [_spec(i) for i in range(60)]
        runs = {"pack_058": [_Run(1, "Q3 close", "done", 5.0)],
                "pack_040": [_Run(2, "Q2 close", "running", 4.0)]}
        m = build_inbox(specs, runs)
        assert _titles(m)[:3] == ["Deliverable 040", "Deliverable 058", "Deliverable 000"]
        assert [it["deliverable"] for it in m["paginate"](1)["page_items"]][:2] == [
            "Deliverable 040", "Deliverable 058",
        ]

    def test_gated_finished_work_still_floats_above_everything(self):
        specs = [_spec(i, gate="review" if i == 59 else None) for i in range(60)]
        runs = {"pack_059": [_Run(1, "Needs review", "done", 5.0)],
                "pack_002": [_Run(2, "Ungated", "done", 6.0)]}
        assert _titles(build_inbox(specs, runs))[:2] == ["Deliverable 059", "Deliverable 002"]


class _World:
    def __init__(self, *, grouped=None, per_domain=None):
        self.grouped_calls: list[tuple] = []
        self.single_calls: list[tuple] = []
        self._grouped = grouped
        self._per_domain = per_domain or {}

    def recent_goals_by_domain(self, domains, *, owner=None, per_domain=5):
        self.grouped_calls.append((list(domains), owner, per_domain))
        if self._grouped is None:
            raise RuntimeError("window functions unavailable")
        return self._grouped

    def list_goals(self, *, domain=None, owner=None, limit=None, order="asc", **_):
        self.single_calls.append((domain, owner, limit, order))
        if domain == "broken":
            raise RuntimeError("bad domain query")
        return self._per_domain.get(domain, [])


class TestRecentRunsByDomain:
    def test_one_grouped_call_answers_every_domain(self):
        run = _Run(1, "x", "done", 1.0)
        world = _World(grouped={"a": [run]})
        got = recent_runs_by_domain(world, ["a", "b", "c"], owner="user:alice")
        assert got == {"a": [run]}
        assert world.grouped_calls == [(["a", "b", "c"], "user:alice", 5)]
        assert world.single_calls == []

    def test_a_store_that_cannot_group_falls_back_to_one_query_per_domain(self):
        run = _Run(1, "x", "done", 1.0)
        world = _World(grouped=None, per_domain={"a": [run]})
        got = recent_runs_by_domain(world, ["a", "broken", "c"], owner="user:alice")
        assert got == {"a": [run], "broken": [], "c": []}   # a bad domain never breaks the page
        assert world.single_calls == [
            ("a", "user:alice", 5, "desc"), ("broken", "user:alice", 5, "desc"), ("c", "user:alice", 5, "desc"),
        ]

    def test_a_store_without_the_grouped_read_still_works(self):
        class Old:
            def list_goals(self, *, domain=None, owner=None, limit=None, order="asc"):
                return [_Run(7, domain, "done", 1.0)]

        got = recent_runs_by_domain(Old(), ["a"])
        assert [r.id for r in got["a"]] == [7]


class TestPageAtCatalogScale:
    @staticmethod
    def _world(tmp_path, monkeypatch):
        from maverick import world_model
        monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
        return world_model.WorldModel(tmp_path / "world.db")

    @staticmethod
    def _first_card(html: str) -> str:
        return html.split('class="dlv-card__label">')[1].split("<")[0]

    def test_a_full_catalog_renders_one_page_of_cards_in_a_small_document(self, tmp_path, monkeypatch):
        self._world(tmp_path, monkeypatch)
        total = len(_deliverable_specs())
        assert total > 3 * PAGE_SIZE          # the shipped catalogue is the thousands case
        everything = client.get("/deliverables?role=all")
        assert everything.status_code == 200
        assert everything.text.count('class="card"') == PAGE_SIZE
        assert len(everything.content) < 300_000       # was 1,161,885 bytes for 2,031 cards
        assert 'aria-label="Results pages"' in everything.text
        assert f"Showing 1–{PAGE_SIZE} of {total:,}" in everything.text
        assert f"Page 1 of {-(-total // PAGE_SIZE)}" in everything.text
        assert 'rel="prev"' not in everything.text     # nothing before the first page
        # The pager keeps the "everything" view and moves on.
        assert 'href="/deliverables?role=all&amp;page=2" rel="next"' in everything.text
        second = client.get("/deliverables?role=all&page=2")
        assert second.status_code == 200 and second.text.count('class="card"') == PAGE_SIZE
        assert f"Showing {PAGE_SIZE + 1}–{2 * PAGE_SIZE} of {total:,}" in second.text
        assert 'href="/deliverables?role=all&amp;page=1" rel="prev"' in second.text
        assert self._first_card(everything.text) != self._first_card(second.text)

    def test_a_chosen_role_stays_chosen_across_pages(self, tmp_path, monkeypatch):
        self._world(tmp_path, monkeypatch)
        in_view = [s for s in _deliverable_specs() if "controller" in s["consumers"]]
        assert len(in_view) > PAGE_SIZE       # a role with more than one page of deliverables
        first = client.get("/deliverables?role=controller")
        assert first.status_code == 200
        assert first.text.count('class="card"') == PAGE_SIZE
        assert f"Showing 1–{PAGE_SIZE} of {len(in_view):,}" in first.text
        assert 'href="/deliverables?role=controller&amp;page=2" rel="next"' in first.text

    def test_the_default_view_pages_without_inventing_a_role(self, tmp_path, monkeypatch):
        world = self._world(tmp_path, monkeypatch)
        # Results pages contain only the caller's actual finished work, not
        # thousands of never-produced specialist templates.
        for i in range(PAGE_SIZE + 1):
            gid = world.create_goal(f"Finished task {i}", "")
            world.set_goal_status(gid, "done", result="ok")
        first = client.get("/deliverables")
        assert "Finished task 25" in first.text
        assert "Finished task 0" not in first.text
        assert 'href="/deliverables?page=2" rel="next"' in first.text
        second = client.get("/deliverables?page=2")
        assert "Finished task 0" in second.text
        assert 'href="/deliverables?page=1" rel="prev"' in second.text

    def test_odd_page_numbers_are_forgiven(self, tmp_path, monkeypatch):
        self._world(tmp_path, monkeypatch)
        pages = -(-len(_deliverable_specs()) // PAGE_SIZE)
        junk = client.get("/deliverables?role=all&page=zzz")
        assert junk.status_code == 200 and f"Page 1 of {pages}" in junk.text
        last = client.get("/deliverables?role=all&page=99999")
        assert last.status_code == 200 and f"Page {pages} of {pages}" in last.text
        assert 'rel="next"' not in last.text and 'class="card"' in last.text

    def test_a_role_with_a_few_deliverables_has_no_pager(self, tmp_path, monkeypatch):
        self._world(tmp_path, monkeypatch)
        r = client.get("/deliverables?role=fpa_analyst")
        assert r.status_code == 200
        assert "13-week cash forecast" in r.text
        assert 'aria-label="Results pages"' not in r.text and "Showing " not in r.text

    def test_runs_are_read_with_one_grouped_query_not_one_per_pack(self, tmp_path, monkeypatch):
        from maverick import world_model
        world = self._world(tmp_path, monkeypatch)
        gid = world.create_goal("Refresh the cash forecast", "", domain="finance_cash13w")
        world.set_goal_status(gid, "done", result="ok")
        per_pack: list[str] = []
        real = world_model.WorldModel.list_goals

        def counting(self, *args, **kwargs):
            if kwargs.get("domain") is not None:
                per_pack.append(kwargs["domain"])
            return real(self, *args, **kwargs)

        monkeypatch.setattr(world_model.WorldModel, "list_goals", counting)
        r = client.get("/deliverables?role=all")
        assert r.status_code == 200
        assert per_pack == []
        # ...and the result still reaches the page, ahead of the unproduced packs.
        assert f'href="/chat/goal/{gid}"' in r.text
