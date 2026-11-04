"""Deterministic AML/KYC/watchlist screening and four-eyes cases."""
from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick.finance import aml_screening as aml
from maverick.privacy_ops import RecordConflict


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[finance_operations]\nenable = true\n", encoding="utf-8"
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _ingest(payload=None, **overrides):
    values = {
        "list_kind": "sanctions",
        "source_name": "OFAC SDN test fixture",
        "source_ref": "https://ofac.treasury.gov/sanctions-list-service",
        "version": "2026-07-22",
        "payload": payload
        or json.dumps(
            {
                "entries": [
                    {
                        "uid": "42",
                        "name": "Aleksandr Sergeyevich Ivanov",
                        "aliases": ["Alexander Ivanov"],
                        "type": "individual",
                        "programs": ["TEST"],
                    }
                ]
            }
        ),
        "ingested_by": "list-operator",
        "published_at": "2026-07-20T12:00:00Z",
        "retrieved_at": "2026-07-20T13:00:00Z",
    }
    values.update(overrides)
    return aml.ingest_list(**values)


def _finalize_case(case, decision):
    first = aml.record_disposition(
        case["id"],
        decision=decision,
        rationale=f"First independent reviewer chose {decision}.",
        decided_by="lifecycle-reviewer-one",
        expected_revision=case["revision"],
    )
    return aml.record_disposition(
        case["id"],
        decision=decision,
        rationale=f"Second independent reviewer chose {decision}.",
        decided_by="lifecycle-reviewer-two",
        expected_revision=first["revision"],
    )


def test_enabled_is_explicit_and_fail_closed(tmp_path):
    from maverick import config

    assert aml.enabled() is True
    (tmp_path / "config.toml").write_text(
        "[finance_operations]\nenable = false\n", encoding="utf-8"
    )
    config.reset_config_cache()
    assert aml.enabled() is False


def test_ingest_preserves_citation_digest_and_is_idempotent():
    payload = '["Jane Example", "John Example"]'
    first = _ingest(payload, data_format="json")
    replay = _ingest(payload, data_format="json")

    assert replay["id"] == first["id"]
    assert first["entry_count"] == 2
    assert first["content_sha256"] == hashlib.sha256(payload.encode()).hexdigest()
    assert first["provenance"]["source_ref"].startswith("https://ofac.treasury.gov/")
    assert first["provenance"]["parser_version"] == aml.PARSER_VERSION


def test_concurrent_identical_ingests_converge_on_one_stable_record():
    payload = '["Jane Concurrent", "John Concurrent"]'

    def _run(_index):
        return _ingest(payload, data_format="json")

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(_run, range(24)))

    assert len({row["id"] for row in rows}) == 1
    assert rows[0]["id"] == f"FSL-{rows[0]['release_fingerprint'][:48]}"
    assert len(aml.list_versions()) == 1


def test_same_declared_release_cannot_be_rebound_to_different_content():
    first = _ingest('["Original Release"]', data_format="json")

    with pytest.raises(RecordConflict, match="already bound to different content"):
        _ingest('["Mutated Release"]', data_format="json")

    assert aml.get_list(first["id"])["content_sha256"] == first["content_sha256"]
    assert len(aml.list_versions()) == 1


def test_concurrent_conflicting_release_ingests_choose_one_immutable_winner():
    payloads = ['["Release Alpha"]', '["Release Bravo"]'] * 8

    def _run(payload):
        try:
            return ("ok", _ingest(payload, data_format="json"))
        except RecordConflict as exc:
            return ("conflict", str(exc))

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(_run, payloads))

    winners = [value for status, value in outcomes if status == "ok"]
    conflicts = [value for status, value in outcomes if status == "conflict"]
    assert winners
    assert conflicts
    assert len({row["id"] for row in winners}) == 1
    assert len({row["content_sha256"] for row in winners}) == 1
    assert len(aml.list_versions()) == 1


def test_ingest_rejects_missing_citation_and_digest_mismatch():
    with pytest.raises(ValueError, match="source_ref"):
        _ingest(source_ref="file:///tmp/list.txt")
    with pytest.raises(ValueError, match="URN"):
        _ingest(source_ref="urn:")
    with pytest.raises(ValueError, match="SHA-256"):
        _ingest(expected_sha256="0" * 64)


def test_normalized_list_size_is_rejected_before_governed_persistence(monkeypatch):
    monkeypatch.setattr(aml, "_MAX_NORMALIZED_LIST_JSON_BYTES", 1_024)
    payload = json.dumps([
        f"Unique screening subject {index:04d} with expanded normalized metadata"
        for index in range(100)
    ])

    with pytest.raises(ValueError, match="governed-record bound"):
        _ingest(payload, data_format="json")

    assert aml.list_versions() == []


def test_xml_ingestion_extracts_primary_alias_and_program():
    payload = """<?xml version="1.0"?>
    <sdnList><sdnEntry><uid>9</uid><firstName>Jane</firstName>
    <lastName>Example</lastName><sdnType>Individual</sdnType>
    <programList><program>TEST-PROGRAM</program></programList>
    <akaList><aka><firstName>Janet</firstName><lastName>Example</lastName></aka></akaList>
    </sdnEntry></sdnList>"""
    row = _ingest(payload, data_format="xml")
    entry = row["entries"][0]
    assert entry["name"] == "Jane Example"
    assert entry["aliases"] == ["Janet Example"]
    assert entry["programs"] == ["TEST-PROGRAM"]


def test_parse_xml_rejects_doctype():
    with pytest.raises(ValueError, match="declarations"):
        aml.parse_list("<!DOCTYPE foo><foo>Jane Example</foo>", data_format="xml")


def test_parse_xml_rejects_doctype_after_long_leading_comment():
    payload = "<!--" + ("x" * 5_000) + "--><!DOCTYPE foo><foo>Jane Example</foo>"
    with pytest.raises(ValueError, match="declarations"):
        aml.parse_list(payload, data_format="xml")


def test_parse_xml_rejects_excessive_nodes(monkeypatch):
    monkeypatch.setattr(aml, "_MAX_XML_NODES", 5)
    payload = "<root>" + "".join(f"<item>{index}</item>" for index in range(5)) + "</root>"
    with pytest.raises(ValueError, match="node limit"):
        aml.parse_list(payload, data_format="xml")


def test_parse_xml_rejects_excessive_depth(monkeypatch):
    monkeypatch.setattr(aml, "_MAX_XML_DEPTH", 3)
    with pytest.raises(ValueError, match="depth limit"):
        aml.parse_list("<root><a><b><name>Jane</name></b></a></root>", data_format="xml")


def test_parse_xml_rejects_abusive_candidate_nesting(monkeypatch):
    monkeypatch.setattr(aml, "_MAX_XML_CANDIDATE_NESTING", 2)
    payload = "<entry><entity><identity><name>Jane Example</name></identity></entity></entry>"
    with pytest.raises(ValueError, match="nested candidates"):
        aml.parse_list(payload, data_format="xml")


def test_short_watchlist_entry_does_not_prefix_match_long_subject():
    watchlist = _ingest('[{"uid":"short","name":"J"}]', data_format="json")
    result = aml.screen_subject(
        "John Smith",
        screened_by="kyc-operator",
        list_ids=[watchlist["id"]],
    )
    assert result["match"] is False
    assert result["case"] is None


def test_typo_match_opens_case_with_exact_list_provenance():
    watchlist = _ingest()
    result = aml.screen_subject(
        "Alexandr Ivanov",
        screened_by="payment-monitor",
        subject_ref="payment-100",
        list_ids=[watchlist["id"]],
    )

    assert result["match"] is True
    case = result["case"]
    assert case["status"] == "open"
    assert case["rule_version"] == aml.MATCH_RULE_VERSION
    assert case["hits"][0]["citation"] == {
        "list_id": watchlist["id"],
        "list_revision": watchlist["revision"],
        "list_kind": "sanctions",
        "source_name": "OFAC SDN test fixture",
        "source_ref": "https://ofac.treasury.gov/sanctions-list-service",
        "list_version": "2026-07-22",
        "published_at": watchlist["provenance"]["published_at"],
        "retrieved_at": watchlist["provenance"]["retrieved_at"],
        "content_sha256": watchlist["content_sha256"],
        "parser_version": aml.PARSER_VERSION,
    }
    assert "not an OFAC determination" in case["notice"]


def test_screen_clear_is_deterministic_and_does_not_open_case():
    watchlist = _ingest()
    result = aml.screen_subject(
        "Completely Different Person",
        screened_by="kyc-operator",
        list_ids=[watchlist["id"]],
    )
    assert result["match"] is False
    assert result["case"] is None
    assert result["screened_lists"][0]["content_sha256"] == watchlist["content_sha256"]
    assert result["completeness"] == {
        "complete_for_selected_scope": True,
        "all_latest_active_sources_screened": False,
        "selection_mode": "explicit_list_ids",
        "selected_list_count": 1,
        "truncated": False,
        "limits": {
            "lists": 16,
            "fuzzy_comparisons": 500,
            "hits": 100,
        },
    }


def test_auto_selection_reports_all_latest_active_sources_screened():
    _ingest()

    result = aml.screen_subject(
        "Completely Different Person",
        screened_by="kyc-operator",
    )

    assert result["match"] is False
    assert result["completeness"]["complete_for_selected_scope"] is True
    assert result["completeness"]["all_latest_active_sources_screened"] is True
    assert result["completeness"]["selection_mode"] == "latest_active_per_source"
    assert result["completeness"]["truncated"] is False


def test_auto_selection_fails_closed_instead_of_omitting_active_source(monkeypatch):
    monkeypatch.setattr(aml, "_MAX_LISTS_PER_SCREEN", 1)
    _ingest(
        '["First Authority Target"]',
        data_format="json",
        source_name="Authority one",
        source_ref="https://example.test/authority-one",
    )
    _ingest(
        '["Second Authority Target"]',
        data_format="json",
        source_name="Authority two",
        source_ref="https://example.test/authority-two",
    )

    with pytest.raises(aml.ScreeningIncompleteError, match="active list sources"):
        aml.screen_subject("Unlisted Person", screened_by="kyc-operator")


def test_auto_selection_distinguishes_same_label_sources_by_provenance_url():
    _ingest(
        '["First Authority Target"]',
        data_format="json",
        source_name="Shared operator label",
        source_ref="https://example.test/authority-one",
    )
    _ingest(
        '["Second Authority Target"]',
        data_format="json",
        source_name="Shared operator label",
        source_ref="https://example.test/authority-two",
    )

    result = aml.screen_subject("Unlisted Person", screened_by="kyc-operator")

    assert len(result["screened_lists"]) == 2
    assert result["completeness"]["all_latest_active_sources_screened"] is True


def test_auto_selection_fails_closed_when_list_version_enumeration_is_truncated(
    monkeypatch,
):
    monkeypatch.setattr(aml, "_MAX_LIST_VERSION_ENUMERATION", 2)
    monkeypatch.setattr(
        aml,
        "list_versions",
        lambda *, limit: [{"id": str(index)} for index in range(limit)],
    )

    with pytest.raises(aml.ScreeningIncompleteError, match="completeness limit"):
        aml._latest_lists()


def test_kind_filtered_list_versions_never_filter_an_incomplete_prefix(monkeypatch):
    class OversizedInventory:
        @staticmethod
        def iter_record_ids(*, start_after, limit):
            start = int(start_after or -1) + 1
            return iter(
                (str(index), f"FSL-{index}")
                for index in range(start, start + limit)
            )

    monkeypatch.setattr(aml, "_MAX_LIST_VERSION_ENUMERATION", 2)
    monkeypatch.setattr(aml, "_LISTS", OversizedInventory())

    with pytest.raises(aml.ScreeningIncompleteError, match="inventory"):
        aml.list_versions(list_kind="sanctions", limit=1)


def test_metadata_inventory_never_loads_bodies_and_latest_loads_only_heads(
    monkeypatch,
):
    _ingest(
        '[{"uid":"old","name":"Old authority target"}]',
        data_format="json",
        version="2026-07-19",
        retrieved_at="2026-07-19T13:00:00Z",
    )
    newest = _ingest(
        '[{"uid":"new","name":"New authority target"}]',
        data_format="json",
        version="2026-07-20",
        retrieved_at="2026-07-20T13:00:00Z",
    )
    other = _ingest(
        '[{"uid":"other","name":"Other authority target"}]',
        data_format="json",
        source_name="Other authority",
        source_ref="https://example.test/other-authority",
        version="2026-07-20",
        retrieved_at="2026-07-20T14:00:00Z",
    )
    original = aml._LISTS

    class CountingBodies:
        def __init__(self):
            self.loaded = []

        def iter_record_ids(self, *, start_after, limit):
            return original.iter_record_ids(start_after=start_after, limit=limit)

        def get(self, record_id):
            self.loaded.append(record_id)
            return original.get(record_id)

        @staticmethod
        def list(*, limit):
            raise AssertionError(f"full list inventory read requested with {limit=}")

    bodies = CountingBodies()
    monkeypatch.setattr(aml, "_LISTS", bodies)

    versions = aml.list_versions()
    assert len(versions) == 3
    assert all("entries" not in row for row in versions)
    assert bodies.loaded == []

    selected = aml._latest_lists()
    assert {row["id"] for row in selected} == {newest["id"], other["id"]}
    assert set(bodies.loaded) == {newest["id"], other["id"]}
    assert len(bodies.loaded) == 2


def test_legacy_metadata_recovery_makes_bounded_progress(monkeypatch):
    for index in range(aml._MAX_LEGACY_METADATA_RECOVERY + 1):
        _ingest(
            json.dumps([f"Legacy authority target {index}"]),
            data_format="json",
            source_name=f"Legacy authority {index}",
            source_ref=f"https://example.test/legacy-authority-{index}",
            version="2026-07-20",
        )
    original = aml._LISTS

    class CountingBodies:
        def __init__(self):
            self.loaded = []

        def iter_record_ids(self, *, start_after, limit):
            return original.iter_record_ids(start_after=start_after, limit=limit)

        def get(self, record_id):
            self.loaded.append(record_id)
            return original.get(record_id)

    class EmptyLegacyIndex:
        def __init__(self):
            self.rows = {}

        def list(self, *, limit):
            assert limit == aml._MAX_LIST_VERSION_ENUMERATION + 1
            return list(self.rows.values())

        def get(self, record_id):
            return self.rows.get(record_id)

        def create(self, record, *, action, actor):
            assert action == "index_screening_list"
            assert actor == "system:screening-list-metadata-backfill"
            self.rows[record["id"]] = dict(record)
            return dict(record)

    bodies = CountingBodies()
    legacy_index = EmptyLegacyIndex()
    monkeypatch.setattr(aml, "_LISTS", bodies)
    monkeypatch.setattr(aml, "_LIST_METADATA", legacy_index)

    with pytest.raises(aml.ScreeningIncompleteError, match="bounded progress"):
        aml.list_versions()
    assert len(bodies.loaded) == aml._MAX_LEGACY_METADATA_RECOVERY

    recovered = aml.list_versions()
    assert len(recovered) == aml._MAX_LEGACY_METADATA_RECOVERY + 1
    assert len(bodies.loaded) == aml._MAX_LEGACY_METADATA_RECOVERY + 1


def test_fuzzy_budget_fails_closed_instead_of_omitting_plausible_candidates(
    monkeypatch,
):
    monkeypatch.setattr(aml, "_MAX_FUZZY_CANDIDATES", 1)
    watchlist = _ingest(
        json.dumps(
            {
                "entries": [{
                    "uid": "fuzzy-budget",
                    "name": "Alisia Exampel",
                    "aliases": ["Alicha Exampl"],
                }]
            }
        ),
        data_format="json",
    )

    with pytest.raises(aml.ScreeningIncompleteError, match="fuzzy candidates"):
        aml.screen_subject(
            "Alicia Example",
            screened_by="kyc-operator",
            list_ids=[watchlist["id"]],
        )


def test_hit_limit_fails_closed_instead_of_returning_truncated_hits(monkeypatch):
    monkeypatch.setattr(aml, "_MAX_HITS", 1)
    watchlist = _ingest(
        json.dumps(
            {
                "entries": [
                    {"uid": "duplicate-1", "name": "Exact Match Target"},
                    {"uid": "duplicate-2", "name": "Exact Match Target"},
                ]
            }
        ),
        data_format="json",
    )

    with pytest.raises(aml.ScreeningIncompleteError, match="hit result limit"):
        aml.screen_subject(
            "Exact Match Target",
            screened_by="kyc-operator",
            list_ids=[watchlist["id"]],
        )


def test_case_creation_is_idempotent_for_same_subject_list_and_rule():
    watchlist = _ingest()
    first = aml.screen_subject(
        "Alexander Ivanov", screened_by="operator", list_ids=[watchlist["id"]]
    )
    second = aml.screen_subject(
        "Alexander Ivanov", screened_by="operator", list_ids=[watchlist["id"]]
    )
    assert second["case"]["id"] == first["case"]["id"]


def test_case_series_lookup_is_independent_of_global_case_list_prefix(monkeypatch):
    watchlist = _ingest()
    target = aml.screen_subject(
        "Alexander Ivanov",
        screened_by="operator",
        subject_ref="case-after-global-prefix",
        list_ids=[watchlist["id"]],
    )["case"]

    class PrefixBlindCaseStore:
        def __init__(self, record):
            self.record = record
            self.list_called = False

        def get(self, record_id):
            return self.record if record_id == self.record["id"] else None

        def list(self, *, limit):
            self.list_called = True
            # The target is conceptually after this bounded unrelated prefix.
            return [{"id": "FSC-unrelated"}] * limit

        def create(self, *_args, **_kwargs):
            raise AssertionError("existing target occurrence must be found directly")

    fake = PrefixBlindCaseStore(target)
    monkeypatch.setattr(aml, "_CASES", fake)

    repeated = aml.screen_subject(
        "Alexander Ivanov",
        screened_by="repeat-operator",
        subject_ref="case-after-global-prefix",
        list_ids=[watchlist["id"]],
    )["case"]

    assert repeated["id"] == target["id"]
    assert fake.list_called is False


def test_concurrent_identical_screens_converge_on_one_stable_case():
    watchlist = _ingest()

    def _run(_index):
        return aml.screen_subject(
            "Alexander Ivanov",
            screened_by="concurrent-operator",
            subject_ref="payment-concurrent",
            list_ids=[watchlist["id"]],
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_run, range(24)))

    cases = [result["case"] for result in results]
    assert len({case["id"] for case in cases}) == 1
    assert cases[0]["id"] == f"FSC-{cases[0]['fingerprint'][:48]}"
    assert cases[0]["generation"] == 1
    assert cases[0]["previous_case_id"] == ""
    assert len(aml.list_cases()) == 1


def test_repeat_after_cleared_opens_next_deterministic_generation():
    watchlist = _ingest()
    first = aml.screen_subject(
        "Alexander Ivanov",
        screened_by="original-operator",
        list_ids=[watchlist["id"]],
    )["case"]
    final = _finalize_case(first, "clear")

    repeated = aml.screen_subject(
        "Alexander Ivanov",
        screened_by="repeat-operator",
        list_ids=[watchlist["id"]],
    )["case"]

    assert final["status"] == "cleared"
    assert repeated["status"] == "open"
    assert repeated["id"] != final["id"]
    assert repeated["generation"] == 2
    assert repeated["previous_case_id"] == final["id"]
    assert repeated["series_fingerprint"] == final["series_fingerprint"]
    assert repeated["fingerprint"] != final["fingerprint"]
    assert repeated["id"] == f"FSC-{repeated['fingerprint'][:48]}"


def test_repeat_after_escalated_opens_next_deterministic_generation():
    watchlist = _ingest()
    first = aml.screen_subject(
        "Alexander Ivanov",
        screened_by="original-operator",
        list_ids=[watchlist["id"]],
    )["case"]
    final = _finalize_case(first, "escalate")

    repeated = aml.screen_subject(
        "Alexander Ivanov",
        screened_by="repeat-operator",
        list_ids=[watchlist["id"]],
    )["case"]

    assert final["status"] == "escalated"
    assert repeated["status"] == "open"
    assert repeated["generation"] == 2
    assert repeated["previous_case_id"] == final["id"]
    assert repeated["series_fingerprint"] == final["series_fingerprint"]


def test_concurrent_repeats_after_final_converge_on_one_next_generation():
    watchlist = _ingest()
    first = aml.screen_subject(
        "Alexander Ivanov",
        screened_by="original-operator",
        subject_ref="repeat-concurrency",
        list_ids=[watchlist["id"]],
    )["case"]
    final = _finalize_case(first, "clear")

    def _repeat(_index):
        return aml.screen_subject(
            "Alexander Ivanov",
            screened_by="repeat-operator",
            subject_ref="repeat-concurrency",
            list_ids=[watchlist["id"]],
        )["case"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        repeated = list(pool.map(_repeat, range(24)))

    assert len({case["id"] for case in repeated}) == 1
    assert {case["generation"] for case in repeated} == {2}
    assert {case["previous_case_id"] for case in repeated} == {final["id"]}
    assert len(aml.list_cases()) == 2


def test_case_identity_does_not_conflate_distinct_list_provenance():
    payload = '[{"uid":"same-entry","name":"Provenance Target"}]'
    first_list = _ingest(
        payload,
        data_format="json",
        source_ref="https://example.test/authority-one",
    )
    second_list = _ingest(
        payload,
        data_format="json",
        source_ref="https://example.test/authority-two",
    )

    first_case = aml.screen_subject(
        "Provenance Target",
        screened_by="operator",
        list_ids=[first_list["id"]],
    )["case"]
    second_case = aml.screen_subject(
        "Provenance Target",
        screened_by="operator",
        list_ids=[second_list["id"]],
    )["case"]

    assert first_case["id"] != second_case["id"]
    assert first_case["screened_lists"][0]["source_ref"] != (
        second_case["screened_lists"][0]["source_ref"]
    )


def test_latest_list_uses_retrieval_time_not_optional_publication_time():
    now = time.time()
    older = _ingest(
        '["Older Retrieval Target"]',
        data_format="json",
        version="older-retrieval",
        published_at=now - 10,
        retrieved_at=now - 200,
    )
    newer = _ingest(
        '["Newer Retrieval Target"]',
        data_format="json",
        version="newer-retrieval",
        published_at=now - 2_000,
        retrieved_at=now - 100,
    )

    result = aml.screen_subject(
        "Newer Retrieval Target",
        screened_by="kyc-operator",
    )

    assert result["match"] is True
    assert result["screened_lists"] == [
        {
            "list_id": newer["id"],
            "revision": newer["revision"],
            "content_sha256": newer["content_sha256"],
            "source_ref": newer["provenance"]["source_ref"],
            "version": newer["version"],
        }
    ]
    assert result["screened_lists"][0]["list_id"] != older["id"]


def test_configured_legacy_sdn_path_is_imported_with_governed_provenance(
    tmp_path,
    monkeypatch,
):
    from maverick import config

    source = tmp_path / "legacy-sdn.json"
    payload = '["Legacy Bridge Target"]'
    source.write_text(payload, encoding="utf-8")
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "finance_operations": {"enable": True},
            "screening": {"sdn_path": str(source)},
        },
    )

    result = aml.screen_subject(
        "Legacy Bridge Target",
        screened_by="kyc-operator",
    )

    assert result["match"] is True
    governed = aml.get_list(result["screened_lists"][0]["list_id"])
    assert governed["source_name"] == "Configured [screening] sdn_path"
    assert governed["content_sha256"] == hashlib.sha256(payload.encode()).hexdigest()
    assert governed["provenance"]["source_ref"].startswith(
        "urn:lightwork:screening:sdn-path:"
    )
    assert str(source) not in governed["provenance"]["source_ref"]


def test_four_eyes_requires_submitter_separation_and_two_matching_reviews():
    watchlist = _ingest()
    case = aml.screen_subject(
        "Alexander Ivanov", screened_by="submitter", list_ids=[watchlist["id"]]
    )["case"]
    with pytest.raises(ValueError, match="submitter"):
        aml.record_disposition(
            case["id"],
            decision="clear",
            rationale="Submitted the screening request.",
            decided_by="submitter",
            expected_revision=case["revision"],
        )
    first = aml.record_disposition(
        case["id"],
        decision="clear",
        rationale="Identifiers independently reviewed; no corroborating match.",
        decided_by="reviewer-one",
        expected_revision=case["revision"],
    )
    assert first["status"] == "pending_second_review"
    with pytest.raises(ValueError, match="only once"):
        aml.record_disposition(
            case["id"],
            decision="clear",
            rationale="Trying to approve twice.",
            decided_by="reviewer-one",
            expected_revision=first["revision"],
        )
    final = aml.record_disposition(
        case["id"],
        decision="clear",
        rationale="Second independent review reaches the same conclusion.",
        decided_by="reviewer-two",
        expected_revision=first["revision"],
    )
    assert final["status"] == "cleared"
    assert final["final_disposition"]["human_reviewed"] is True
    assert final["final_disposition"]["reviewers"] == ["reviewer-one", "reviewer-two"]


def test_disagreement_stays_open_and_stale_revision_conflicts():
    watchlist = _ingest()
    case = aml.screen_subject(
        "Alexander Ivanov", screened_by="submitter", list_ids=[watchlist["id"]]
    )["case"]
    first = aml.record_disposition(
        case["id"],
        decision="clear",
        rationale="No corroborating date of birth.",
        decided_by="reviewer-one",
        expected_revision=case["revision"],
    )
    with pytest.raises(RecordConflict):
        aml.record_disposition(
            case["id"],
            decision="escalate",
            rationale="Stale screen should not win.",
            decided_by="reviewer-two",
            expected_revision=case["revision"],
        )
    disagreed = aml.record_disposition(
        case["id"],
        decision="escalate",
        rationale="The alias and program evidence require escalation.",
        decided_by="reviewer-two",
        expected_revision=first["revision"],
    )
    assert disagreed["status"] == "review_required"
    assert "final_disposition" not in disagreed


def test_disagreement_requires_two_new_adjudicators_to_resolve():
    watchlist = _ingest()
    case = aml.screen_subject(
        "Alexander Ivanov",
        screened_by="submitter",
        list_ids=[watchlist["id"]],
    )["case"]
    first = aml.record_disposition(
        case["id"],
        decision="clear",
        rationale="No corroborating identifiers.",
        decided_by="reviewer-one",
        expected_revision=case["revision"],
    )
    second = aml.record_disposition(
        case["id"],
        decision="escalate",
        rationale="The alias warrants escalation.",
        decided_by="reviewer-two",
        expected_revision=first["revision"],
    )
    third = aml.record_disposition(
        case["id"],
        decision="clear",
        rationale="Independent adjudication found no corroborating identifiers.",
        decided_by="adjudicator-one",
        expected_revision=second["revision"],
    )

    assert third["status"] == "pending_adjudication_review"
    assert "final_disposition" not in third

    fourth = aml.record_disposition(
        case["id"],
        decision="clear",
        rationale="Second adjudicator independently reached the same conclusion.",
        decided_by="adjudicator-two",
        expected_revision=third["revision"],
    )

    assert fourth["status"] == "cleared"
    assert fourth["final_disposition"]["resolution"] == "independent_adjudication"
    assert fourth["final_disposition"]["reviewers"] == [
        "adjudicator-one",
        "adjudicator-two",
    ]
    assert fourth["final_disposition"]["initial_reviewers"] == [
        "reviewer-one",
        "reviewer-two",
    ]
