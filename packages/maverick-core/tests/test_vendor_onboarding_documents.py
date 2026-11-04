"""Supported customer documents and honest extraction boundaries; local fixtures only."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from maverick.paths import tenant_scope
from maverick.privacy_ops import _pdf_extraction
from maverick.vendor_onboarding_adapters import GOOGLE_DOC_MIME, MAX_TEXT_BYTES, EvidenceDocument
from maverick.vendor_onboarding_documents import document_diff, extract

FIXTURES = Path(__file__).resolve().parents[3] / "scripts/acceptance/fixtures/vendor-documents"
NOW = 1_800_000_000.0


def extracted(content, mime="text/plain", **extra):
    with tenant_scope(tenant="synthetic-documents"):
        return extract(EvidenceDocument("synthetic", "1", NOW - 100, content, mime, **extra),
                       source="upload", name="Synthetic policy", now=NOW, freshness_days=30)


def test_real_pdf_cites_actual_pages_including_blank_page():
    content = (FIXTURES / "northstar-policy.pdf").read_bytes()
    text, meta = _pdf_extraction(content)
    assert meta["page_count"] == 3
    assert "SYNTHETIC NORTHSTAR" in text
    result = extracted(content, "application/pdf")
    assert result["status"] == "available"
    answers = result["extracted"]["answers"]
    assert answers["aiv_provenance"]["citations"][0]["pages"] == [1]
    assert answers["aiv_retention"]["citations"][0]["pages"] == [3]
    assert answers["aiv_retention"]["answer"] == "yes"
    assert result["extraction"]["confidence"] == "untrusted"
    assert "page_spans" not in result["extraction"]
    assert "blank-page fixture" not in json.dumps(result)


def test_empty_pdf_page_contents_array_keeps_page_location():
    content = (FIXTURES / "northstar-policy.pdf").read_bytes().replace(b"/Contents 7 0 R", b"/Contents []")
    result = extracted(content, "application/pdf")
    assert result["status"] == "available"
    assert result["extracted"]["answers"]["aiv_retention"]["citations"][0]["pages"] == [3]


def test_native_doc_export_cites_paragraphs_without_fabricated_pdf_pages():
    result = extracted(b"Synthetic opening.\n\nModel provenance is documented with provider and version.",
                       GOOGLE_DOC_MIME, export_mime="text/plain")
    citation = result["extracted"]["answers"]["aiv_provenance"]["citations"][0]
    assert citation["paragraph"] == 2
    assert "pages" not in citation
    assert result["mime"] == GOOGLE_DOC_MIME


@pytest.mark.parametrize("content", [b"%PDF-1.4\nmalformed", b"", b"not a PDF"])
def test_unreadable_pdf_is_visible_failure_not_available_evidence(content):
    result = extracted(content, "application/pdf")
    assert result["status"] == "extraction_failed"
    assert result["extracted"] is None


def test_active_markup_is_inert_plain_text_and_html_media_is_unsupported():
    active = (
        b'<script>globalThis.lightworkActiveMarkupExecuted=true</script>'
        b'<img src=x onerror="globalThis.lightworkActiveMarkupExecuted=true">'
    )
    result = extracted(active)
    assert result["status"] == "available"
    assert result["extracted"]["answers"] == {}
    assert result["extracted"]["unanswered"]
    assert active.decode() not in json.dumps(result)
    with pytest.raises(ValueError, match="unsupported document format"):
        extracted(active, "text/html")


def test_upload_date_is_not_collection_date_and_plaintext_is_strictly_bounded():
    result = extracted(b"Model provenance is documented with provider and version.")
    assert result["date_basis"] == "uploader_asserted_document_date"
    assert result["fresh_until"] == NOW - 100 + 30 * 86400
    with pytest.raises(UnicodeError):
        extracted(b"\xff")
    with pytest.raises(ValueError, match="byte limit"):
        extracted(b"x" * (MAX_TEXT_BYTES + 1))
    with pytest.raises(ValueError, match="date or version"):
        with tenant_scope(tenant="synthetic-documents"):
            extract(EvidenceDocument("x", "1", NOW + 1, b"text"), source="upload", name="future",
                    now=NOW, freshness_days=30)


def test_renewal_diff_contains_both_conflicting_quotations_without_full_documents():
    before = extracted(b"Model provenance is documented with provider and version.")
    after = extracted(b"Model provenance is undisclosed.")
    after["version"] = "2"
    result = document_diff({"documents": [before]}, {"documents": [after]})
    assert result["comparison"] == "previous_review"
    change = result["documents"][0]
    assert change["change"] == "changed"
    claim = change["answer_changes"][0]
    assert (claim["before"], claim["after"]) == ("yes", "no")
    assert "documented" in claim["before_citations"][0]["quote"]
    assert "undisclosed" in claim["after_citations"][0]["quote"]
