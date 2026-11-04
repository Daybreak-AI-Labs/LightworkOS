"""Versioned, cited state-licensing data packs."""
from __future__ import annotations

from dataclasses import replace

import pytest
from maverick.finance.licensing import (
    JURISDICTIONS,
    LicensingPackError,
    ingest_pack_into_regulatory_register,
    load_licensing_pack,
    validate_licensing_pack,
)
from maverick.privacy_ops import RecordConflict


@pytest.mark.parametrize("vertical", ["money_transmitter", "insurance_producer"])
def test_v1_pack_covers_exactly_fifty_states(vertical):
    pack = load_licensing_pack(vertical, version="1.0.0")
    assert pack.schema_version == 1
    assert pack.version == "1.0.0"
    assert pack.as_of == "2026-07-22"
    assert {row.jurisdiction for row in pack.requirements} == set(JURISDICTIONS)
    assert len(pack.requirements) == 50
    validate_licensing_pack(pack)


@pytest.mark.parametrize("vertical", ["money_transmitter", "insurance_producer"])
def test_every_state_has_cited_renewal_routing_and_no_fabricated_conclusion(vertical):
    pack = load_licensing_pack(vertical)
    for row in pack.requirements:
        assert row.authority_name
        assert row.renewal.rule_kind
        assert row.renewal.source_check_required is True
        assert row.determination == "source_check_required"
        assert row.legal_review_required is True
        assert row.citations
        assert all(c.url.startswith("https://") for c in row.citations)
        assert any(c.supports in {"licensing", "renewal", "both"}
                   for c in row.citations)
        assert any(c.jurisdiction_specific for c in row.citations)
        assert not any(c.primary for c in row.citations)
        assert "resolve" not in row.authority_name.lower()


@pytest.mark.parametrize("vertical", ["money_transmitter", "insurance_producer"])
def test_v1_routing_sources_cannot_promote_a_legal_conclusion(vertical):
    pack = load_licensing_pack(vertical)
    first = pack.requirements[0]
    promoted = replace(
        first,
        determination="required",
        verified_on=pack.as_of,
    )
    with pytest.raises(LicensingPackError, match="jurisdiction-specific primary citation"):
        validate_licensing_pack(
            replace(pack, requirements=(promoted,) + pack.requirements[1:])
        )


@pytest.mark.parametrize("vertical", ["money_transmitter", "insurance_producer"])
def test_every_state_routes_to_a_unique_jurisdiction_source(vertical):
    pack = load_licensing_pack(vertical)
    urls = {
        next(c.url for c in row.citations if c.jurisdiction_specific)
        for row in pack.requirements
    }
    assert len(urls) == 50


def test_money_transmitter_pack_records_only_the_supported_nmls_window():
    pack = load_licensing_pack("money_transmitter")
    alabama = pack.for_state("AL")
    assert alabama.renewal.filing_system == "NMLS"
    assert alabama.renewal.opens == "11-01"
    assert alabama.renewal.closes == "12-31"
    assert alabama.renewal.reinstatement == "state_specific"
    assert "state-specific" in alabama.renewal.note.lower()


def test_insurance_pack_preserves_state_specific_deadline_uncertainty():
    pack = load_licensing_pack("insurance_producer")
    california = pack.for_state("CA")
    assert california.renewal.filing_system == "NIPR"
    assert california.renewal.opens is None
    assert california.renewal.closes is None
    assert california.renewal.rule_kind == "state_specific_expiration"


def test_pack_projects_stable_cited_rows_for_the_obligation_register():
    pack = load_licensing_pack("money_transmitter")
    rows = pack.register_records()
    assert len(rows) == 50
    assert rows[0].record_id.startswith("licensing:money_transmitter:")
    assert {row.pack_sha256 for row in rows} == {pack.content_sha256}
    assert all(row.citation_urls for row in rows)
    assert all(row.determination == "source_check_required" for row in rows)


def test_pack_is_persisted_and_versioned_in_regulatory_register(tmp_path):
    from maverick.finance.regulatory_change import RegulatoryChangeEngine

    engine = RegulatoryChangeEngine(tmp_path / "regulatory.sqlite3")
    pack = load_licensing_pack("insurance_producer")
    first = ingest_pack_into_regulatory_register(
        engine,
        pack,
        enabled_domains={"insurance_producer"},
        fetched_at="2026-07-22T12:00:00Z",
    )
    replay = ingest_pack_into_regulatory_register(
        engine,
        pack,
        enabled_domains={"insurance_producer"},
        fetched_at="2026-07-22T13:00:00Z",
    )
    assert first.items_seen == 50
    assert first.versions_created == 50
    assert first.alerts_created == 50
    assert replay.versions_created == 0
    assert replay.alerts_created == 0
    alerts = engine.list_alerts(limit=100)
    assert len(alerts) == 50
    assert {row.source_key for row in alerts} == {
        "licensing-pack-insurance_producer"
    }
    assert {row.jurisdiction for row in alerts} == {
        f"US-{code}" for code in JURISDICTIONS
    }
    assert len({row.record_url for row in alerts}) == 50
    assert all(row.citations[0].content_sha256 for row in alerts)
    assert all(row.citations[0].acquisition == "pack_generated" for row in alerts)


def test_validator_rejects_missing_state_and_unsupported_verified_claim():
    pack = load_licensing_pack("money_transmitter")
    with pytest.raises(LicensingPackError, match="exactly the 50 states"):
        validate_licensing_pack(replace(pack, requirements=pack.requirements[:-1]))

    first = pack.requirements[0]
    unsupported = replace(
        first,
        determination="required",
        verified_on=None,
        citations=tuple(c for c in first.citations if not c.jurisdiction_specific),
    )
    bad_pack = replace(pack, requirements=(unsupported,) + pack.requirements[1:])
    with pytest.raises(LicensingPackError, match="jurisdiction-specific primary citation"):
        validate_licensing_pack(bad_pack)

    state_specific = next(c for c in first.citations if c.jurisdiction_specific)
    renewal_only = replace(state_specific, supports="renewal")
    unsupported_scope = replace(
        first,
        determination="required",
        verified_on="2026-07-22",
        citations=(renewal_only,),
    )
    with pytest.raises(LicensingPackError, match="jurisdiction-specific primary citation"):
        validate_licensing_pack(
            replace(pack, requirements=(unsupported_scope,) + pack.requirements[1:])
        )


def test_pack_version_is_immutably_bound_to_one_content_digest(tmp_path):
    from maverick.finance.regulatory_change import RegulatoryChangeEngine

    engine = RegulatoryChangeEngine(tmp_path / "regulatory.sqlite3")
    pack = load_licensing_pack("money_transmitter")
    ingest_pack_into_regulatory_register(
        engine,
        pack,
        enabled_domains={"money_transmitter"},
        fetched_at="2026-07-22T12:00:00Z",
    )
    changed_first = replace(
        pack.requirements[0],
        scope_note=pack.requirements[0].scope_note + " Changed without a version bump.",
    )
    mutated_same_version = replace(
        pack,
        requirements=(changed_first,) + pack.requirements[1:],
    )

    with pytest.raises(RecordConflict, match="already bound"):
        ingest_pack_into_regulatory_register(
            engine,
            mutated_same_version,
            enabled_domains={"money_transmitter"},
            fetched_at="2026-07-23T12:00:00Z",
        )

    assert len(engine.document_versions(
        "licensing-pack-money_transmitter",
        "licensing:money_transmitter:AL",
    )) == 1


def test_unknown_pack_and_state_fail_closed():
    with pytest.raises(KeyError):
        load_licensing_pack("lending")
    pack = load_licensing_pack("insurance_producer")
    with pytest.raises(KeyError):
        pack.for_state("DC")
