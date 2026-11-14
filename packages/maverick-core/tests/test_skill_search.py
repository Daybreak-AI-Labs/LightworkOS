"""Skill search engine + HF dataset publish/pull.

Offline + deterministic: ranking is checked against hand-built docs; the HF
pull goes through a FAKE fetcher (no network). Round-trips export -> import
through the real ``skills.validate_skill_file`` gate.
"""
from __future__ import annotations

import json

import pytest
from maverick.skill.search import (
    SkillSearchIndex,
    build_index,
    export_jsonl,
    import_records,
    index_from_records,
    main,
    make_doc,
    parse_jsonl,
    pull_dataset,
)


def _sample_docs():
    return [
        make_doc(
            name="web-research",
            tags=["research", "web"],
            triggers=["research and summarize", "compare alternatives"],
            tools_needed=["shell", "spawn_swarm"],
            body="Research a topic by spawning parallel researchers and synthesizing.",
        ),
        make_doc(
            name="code-refactor",
            tags=["coding"],
            triggers=["refactor this code", "clean up the module"],
            tools_needed=["edit_file"],
            body="Refactor a Python module: extract functions, dedupe, run tests.",
        ),
        make_doc(
            name="trip-planning",
            tags=["travel"],
            triggers=["plan a trip", "build an itinerary"],
            tools_needed=["http_fetch"],
            body="Plan travel: flights, hotels, day-by-day itinerary.",
        ),
    ]


class TestRanking:
    def test_query_matches_most_relevant_skill_first(self):
        index = SkillSearchIndex(_sample_docs())
        hits = index.search("research and summarize a topic")
        assert hits
        assert hits[0].name == "web-research"

    def test_refactor_query_ranks_code_skill(self):
        index = SkillSearchIndex(_sample_docs())
        hits = index.search("refactor a python module")
        assert hits[0].name == "code-refactor"

    def test_no_match_returns_empty(self):
        index = SkillSearchIndex(_sample_docs())
        assert index.search("quantum chromodynamics") == []

    def test_name_hit_outranks_body_hit(self):
        # "refactor" is in code-refactor's NAME and triggers; only mentioned in
        # web-research if at all. Field boost should float the named skill up.
        index = SkillSearchIndex(_sample_docs())
        hits = index.search("refactor")
        assert hits[0].name == "code-refactor"

    def test_limit_caps_results(self):
        index = SkillSearchIndex(_sample_docs())
        hits = index.search("a", limit=1)  # near-empty query; whatever matches
        assert len(hits) <= 1

    def test_ranking_is_deterministic(self):
        index = SkillSearchIndex(_sample_docs())
        a = [h.name for h in index.search("plan a trip itinerary")]
        b = [h.name for h in index.search("plan a trip itinerary")]
        assert a == b

    def test_scores_are_descending(self):
        index = SkillSearchIndex(_sample_docs())
        hits = index.search("research code trip")
        scores = [h.score for h in hits]
        assert scores == sorted(scores, reverse=True)

    def test_empty_index_is_safe(self):
        assert SkillSearchIndex([]).search("anything") == []


class TestJsonlRoundTrip:
    def test_export_then_parse_round_trips(self, tmp_path):
        docs = _sample_docs()
        out = tmp_path / "skills.jsonl"
        n = export_jsonl(docs, out)
        assert n == len(docs)
        records = parse_jsonl(out.read_text())
        assert {r["name"] for r in records} == {d.name for d in docs}
        web = next(r for r in records if r["name"] == "web-research")
        assert "research" in web["tags"]
        assert "research and summarize" in web["triggers"]

    def test_parse_skips_malformed_and_nameless_lines(self):
        text = "\n".join([
            json.dumps({"name": "ok", "body": "x"}),
            "{ this is not json",
            json.dumps({"description": "no name"}),
            "",
            json.dumps({"name": "ok2", "body": "y"}),
        ])
        records = parse_jsonl(text)
        assert {r["name"] for r in records} == {"ok", "ok2"}

    def test_index_from_records_is_searchable(self, tmp_path):
        out = tmp_path / "skills.jsonl"
        export_jsonl(_sample_docs(), out)
        records = parse_jsonl(out.read_text())
        index = index_from_records(records)
        assert index.search("itinerary")[0].name == "trip-planning"


class TestHFPull:
    def test_pull_dataset_uses_injected_fetcher(self):
        payload = "\n".join([
            json.dumps({"name": "imported-one", "triggers": ["do a thing"], "body": "body text"}),
            json.dumps({"name": "imported-two", "triggers": ["do another"], "body": "more"}),
        ])
        calls = []

        def fake_fetcher(repo_id):
            calls.append(repo_id)
            return payload

        records = pull_dataset("acme/skills", fake_fetcher)
        assert calls == ["acme/skills"]
        assert {r["name"] for r in records} == {"imported-one", "imported-two"}

    def test_import_records_writes_valid_skill_files(self, tmp_path):
        records = [{
            "name": "imported-skill",
            "description": "an imported skill",
            "tags": ["misc"],
            "triggers": ["do the imported thing"],
            "tools_needed": ["shell"],
            "body": "# Steps\n\n1. Do the imported thing carefully.\n2. Verify the result.\n",
        }]
        result = import_records(records, tmp_path)
        assert result["installed"] == ["imported-skill"]
        written = tmp_path / "imported-skill.md"
        assert written.exists()
        # The written file must pass the real publish-gate lint.
        from maverick.skills import validate_skill_file
        assert validate_skill_file(written).ok

    def test_import_rejects_name_with_trailing_newline(self, tmp_path):
        # "deploy-app\n" passed the kebab check ($ matches before a final
        # newline), missed the existing deploy-app.md, and installed a second
        # skill named deploy-app.
        record = {
            "description": "an imported skill",
            "triggers": ["do the imported thing"],
            "tools_needed": ["shell"],
            "body": "# Steps\n\n1. Do the imported thing carefully.\n2. Verify it.\n",
        }
        assert import_records([{**record, "name": "deploy-app"}], tmp_path)["installed"]
        result = import_records([{**record, "name": "deploy-app\n"}], tmp_path)
        assert result["installed"] == []
        assert any("invalid skill name" in r for r in result["rejected"])
        assert sorted(p.name for p in tmp_path.iterdir()) == ["deploy-app.md"]

    def test_import_rejects_record_with_embedded_secret(self, tmp_path):
        records = [{
            "name": "leaky-skill",
            "triggers": ["leak the thing"],
            "tools_needed": ["shell"],
            "body": "# Steps\n\nexport OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
        }]
        result = import_records(records, tmp_path)
        assert result["installed"] == []
        assert any("leaky-skill" in r for r in result["rejected"])
        assert not (tmp_path / "leaky-skill.md").exists()

    def test_import_rejects_path_traversal_name(self, tmp_path):
        # The dataset is untrusted third-party input. A name with path separators
        # or ".." would make the pre-validation temp write escape dest_dir and
        # truncate-then-delete an arbitrary writable file. Such names must be
        # rejected before any filesystem path is constructed. Regression for the
        # import_records path-traversal hole.
        dest = tmp_path / "skills"
        dest.mkdir()
        records = [{
            "name": "../../escape",
            "triggers": ["t"],
            "tools_needed": ["shell"],
            "body": "# Steps\n\n1. do the thing.\n",
        }]
        result = import_records(records, dest)
        assert result["installed"] == []
        assert any("invalid skill name" in r for r in result["rejected"])
        # Nothing escaped dest_dir, and dest_dir itself stayed empty (no temp write).
        assert not (tmp_path / "escape.md").exists()
        assert list(dest.iterdir()) == []

    def test_import_skips_existing_without_overwrite(self, tmp_path):
        records = [{"name": "dup", "triggers": ["t"], "tools_needed": ["shell"],
                    "body": "# Steps\n\n1. first version of the body here.\n"}]
        first = import_records(records, tmp_path)
        assert first["installed"] == ["dup"]
        second = import_records(records, tmp_path)
        assert second["skipped"] == ["dup"]
        assert second["installed"] == []

    def test_import_overwrite_replaces(self, tmp_path):
        records = [{"name": "dup", "triggers": ["t"], "tools_needed": ["shell"],
                    "body": "# Steps\n\n1. body content that is long enough.\n"}]
        import_records(records, tmp_path)
        result = import_records(records, tmp_path, overwrite=True)
        assert result["installed"] == ["dup"]

    def test_pulled_then_indexed_end_to_end(self, tmp_path):
        payload = json.dumps({
            "name": "deploy-helper", "tags": ["ops"],
            "triggers": ["deploy the service"], "body": "deploy steps here",
        })
        records = pull_dataset("acme/skills", lambda _r: payload)
        index = index_from_records(records)
        assert index.search("deploy the service")[0].name == "deploy-helper"


class TestBuildIndexFromDisk:
    def test_build_index_reads_installed_skills(self, tmp_path, monkeypatch):
        # Write a SKILL.md with optional description/tags frontmatter and assert
        # build_index picks them up via the real skills.load_skills path.
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "data-export.md").write_text(
            "---\n"
            "name: data-export\n"
            "description: export tables to parquet\n"
            "tags:\n"
            "  - data\n"
            "  - export\n"
            "triggers:\n"
            "  - export the data\n"
            "tools_needed:\n"
            "  - duckdb\n"
            "---\n\n"
            "# Steps\n\n1. Query.\n2. Write parquet.\n",
            encoding="utf-8",
        )
        index = build_index(skills_dir)
        assert len(index.docs) == 1
        doc = index.docs[0]
        assert doc.description == "export tables to parquet"
        assert set(doc.tags) == {"data", "export"}
        hits = index.search("export tables to parquet")
        assert hits and hits[0].name == "data-export"


class TestCLI:
    def test_search_cli_prints_hit(self, tmp_path, monkeypatch, capsys):
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "web-research.md").write_text(
            "---\nname: web-research\ntriggers:\n  - research and summarize\n"
            "tools_needed:\n  - shell\n---\n\n# Steps\n\n1. Research the topic well.\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("maverick.skills.SKILLS_DIR", skills_dir)
        rc = main(["research and summarize"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "web-research" in out

    def test_export_cli_writes_file(self, tmp_path, monkeypatch, capsys):
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "s.md").write_text(
            "---\nname: s\ntriggers:\n  - do s\ntools_needed:\n  - shell\n---\n\n"
            "# Steps\n\n1. Do the s thing thoroughly.\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("maverick.skills.SKILLS_DIR", skills_dir)
        out = tmp_path / "out.jsonl"
        rc = main(["--export", str(out)])
        assert rc == 0
        records = parse_jsonl(out.read_text())
        assert records and records[0]["name"] == "s"

    def test_search_no_match_returns_zero(self, tmp_path, monkeypatch, capsys):
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        monkeypatch.setattr("maverick.skills.SKILLS_DIR", skills_dir)
        rc = main(["nothing will match this"])
        assert rc == 0
        assert "no skills matched" in capsys.readouterr().out


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
