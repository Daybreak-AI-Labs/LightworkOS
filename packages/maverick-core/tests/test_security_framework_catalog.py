"""Integrity checks for the pinned security-framework practice catalogs."""

from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path

import pytest
from maverick.assessment import TEMPLATES, AssessmentSession
from maverick.security_framework_catalog import (
    CIS_V81_SAFEGUARDS,
    CMMC_L2_PRACTICES,
    FEDRAMP_CLASS_C_CONTROLS,
    NIST_800_53_MODERATE,
    NIST_CSF_2_SUBCATEGORIES,
    SECURITY_CATALOG_INDEX,
    SECURITY_CATALOG_PROVENANCE,
    SECURITY_CATALOGS,
)

CATALOGS = SECURITY_CATALOGS
EXPECTED_COUNTS = {
    "nist_csf": 106,
    "nist_800_53": 287,
    "cis_v8": 153,
    "cmmc_l2": 110,
    "fedramp_moderate": 322,
}


def test_catalogs_have_exact_counts_and_unique_references():
    assert {name: len(rows) for name, rows in CATALOGS.items()} == EXPECTED_COUNTS
    for rows in CATALOGS.values():
        references = [row[0] for row in rows]
        assert len(references) == len(set(references))


def test_catalog_indexes_preserve_every_authoritative_row_and_are_read_only():
    for name, rows in CATALOGS.items():
        index = SECURITY_CATALOG_INDEX[name]
        assert tuple(index.values()) == rows
        assert all(index[row[0]] == row for row in rows)
        with pytest.raises(TypeError):
            index["invented"] = rows[0]
    with pytest.raises(TypeError):
        SECURITY_CATALOG_INDEX["invented"] = {}


def test_generated_catalog_document_is_current():
    from scripts.generate_security_catalog_docs import OUTPUT, render

    assert OUTPUT.read_text(encoding="utf-8") == render()


@pytest.mark.parametrize(
    ("catalog", "representatives"),
    [
        (
            NIST_CSF_2_SUBCATEGORIES,
            {"GV.OC-01", "ID.AM-08", "PR.AA-03", "DE.CM-09", "RS.MI-02", "RC.RP-06"},
        ),
        (NIST_800_53_MODERATE, {"AC-2(1)", "AU-6(3)", "SC-7(8)", "SR-11(2)"}),
        (CIS_V81_SAFEGUARDS, {"1.1", "8.12", "18.5"}),
        (CMMC_L2_PRACTICES, {"3.1.1", "3.12.4", "3.14.7"}),
        (FEDRAMP_CLASS_C_CONTROLS, {"AC-02(01)", "CM-02(02)", "SA-11(02)"}),
    ],
)
def test_catalogs_include_representative_practices(catalog, representatives):
    assert representatives <= {row[0] for row in catalog}


def test_cis_minimum_ig_assignments_are_complete_and_cumulative():
    minimum_groups = Counter(row[4] for row in CIS_V81_SAFEGUARDS)
    assert minimum_groups == {1: 56, 2: 74, 3: 23}
    assert sum(count for group, count in minimum_groups.items() if group <= 1) == 56
    assert sum(count for group, count in minimum_groups.items() if group <= 2) == 130
    assert sum(count for group, count in minimum_groups.items() if group <= 3) == 153


def test_expanded_templates_have_unique_ids_and_text():
    for name, expected_count in EXPECTED_COUNTS.items():
        questions = TEMPLATES[name].questions
        assert len(questions) == expected_count
        assert len({question.id for question in questions}) == expected_count
        assert len({question.text for question in questions}) == expected_count


@pytest.mark.parametrize("name", CATALOGS)
def test_every_catalog_practice_survives_into_scored_findings(name):
    """No practice may silently lose its reference or severity in an assessment."""
    template = TEMPLATES[name]
    session = AssessmentSession(
        type=name,
        subject="Catalog contract subject",
        answers={question.id: {"answer": "no", "note": ""} for question in template.questions},
    )
    result = session.evaluate()
    assert result.total == result.answered == len(CATALOGS[name])
    assert len(result.findings) == len(CATALOGS[name])
    for (reference, section, _objective, severity, minimum_ig), question, finding in zip(
        CATALOGS[name], template.questions, result.findings, strict=True,
    ):
        assert question.risk_answer == "no"
        assert question.severity == finding.severity == severity
        assert question.id == finding.question_id
        assert finding.kind == "risk"
        assert reference in finding.question and reference in finding.recommendation
        assert finding.section.startswith(section)
        if minimum_ig is not None:
            assert f"minimum IG{minimum_ig}" in finding.section
            for group in range(1, 4):
                assert (f"IG{group}" in finding.recommendation) == (group >= minimum_ig)


def test_first_practice_in_each_legacy_group_keeps_stable_id():
    expected_ids = {
        "nist_csf": {"csf_gv_oc", "csf_id_am", "csf_pr_aa", "csf_de_cm", "csf_rs_ma", "csf_rc_rp"},
        "nist_800_53": {"n53_ac", "n53_at", "n53_sc", "n53_sr"},
        "cis_v8": {"cis_1", "cis_8", "cis_18"},
        "cmmc_l2": {"cmmc_ac", "cmmc_at", "cmmc_sc", "cmmc_si"},
        "fedramp_moderate": {"fedramp_ac", "fedramp_at", "fedramp_sc", "fedramp_sr"},
    }
    for name, stable_ids in expected_ids.items():
        assert stable_ids <= {question.id for question in TEMPLATES[name].questions}


@pytest.mark.parametrize(("template_type", "expected_count"), EXPECTED_COUNTS.items())
def test_expanded_templates_evaluate_safe_and_unknown_answers(template_type, expected_count):
    template = TEMPLATES[template_type]
    first, last = template.questions[0], template.questions[-1]
    session = AssessmentSession(type=template_type, subject="Catalog integrity subject")
    session.record(first.id, "yes" if first.risk_answer == "no" else "no")
    session.record(last.id, "unknown")

    result = session.evaluate()

    assert result.total == expected_count
    assert result.answered == 1
    assert result.risk_rating == last.severity
    assert [(finding.question_id, finding.kind) for finding in result.findings] == [
        (last.id, "unverified")
    ]


def test_catalog_provenance_pins_primary_artifacts_and_license_boundary():
    assert set(SECURITY_CATALOG_PROVENANCE) == set(EXPECTED_COUNTS)
    for source in SECURITY_CATALOG_PROVENANCE.values():
        assert source["source_url"].startswith("https://")
        assert re.fullmatch(r"[0-9a-f]{64}", source["source_sha256"])
        assert source["source_artifact"]
        assert source["selection"]

    cis = SECURITY_CATALOG_PROVENANCE["cis_v8"]
    assert "CC BY-NC-ND 4.0" in cis["license"]
    assert "commercial use requires prior CIS approval" in cis["license"]
    assert "no safeguard text or titles redistributed" in cis["selection"]
    assert all(
        objective.startswith("uses authorized CIS v8.1 source material")
        for _, _, objective, _, _ in CIS_V81_SAFEGUARDS
    )


def test_static_catalog_module_has_no_runtime_network_dependency():
    import maverick.security_framework_catalog as catalog_module

    module_path = Path(catalog_module.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    network_roots = {"httpx", "requests", "socket", "urllib"}
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported_roots.isdisjoint(network_roots)


def test_questionnaire_size_limit_remains_bounded_after_catalog_expansion():
    from maverick.assessment import _normalise_template

    payload = {
        "type": "oversized",
        "title": "Oversized",
        "framework": "Test",
        "questions": [{}] * 501,
    }
    with pytest.raises(ValueError, match=r"1-500 questions"):
        _normalise_template(payload)
