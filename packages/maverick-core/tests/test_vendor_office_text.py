"""Synthetic authored OOXML fixtures; no Office executable or network access."""
import hashlib
import io
import zipfile
from pathlib import Path

import pytest
from maverick.paths import tenant_scope
from maverick.vendor_office_text import DOCX_MIME, XLSX_MIME, extract_office
from maverick.vendor_onboarding_adapters import EvidenceDocument
from maverick.vendor_onboarding_documents import extract

W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
S = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
POLICY = 'Model provenance is documented with provider and version.'


def package(parts):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', '<Types/>')
        for name, text in parts.items():
            archive.writestr(name, text)
    return stream.getvalue()


def word(extra=None):
    return package({'word/document.xml': f'<w:document xmlns:w="{W}"><w:body>'
                    '<w:p><w:r><w:t>Synthetic evidence</w:t></w:r></w:p>'
                    f'<w:tbl><w:tr><w:tc><w:p><w:r><w:t>{POLICY}</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
                    '</w:body></w:document>', **(extra or {})})


def workbook(extra=None):
    return package({
        'xl/workbook.xml': f'<workbook xmlns="{S}" xmlns:r="{R}"><sheets><sheet name="Policy &amp; controls" sheetId="1" r:id="rId1"/></sheets></workbook>',
        'xl/_rels/workbook.xml.rels': '<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>',
        'xl/sharedStrings.xml': f'<sst xmlns="{S}"><si><t>UNUSED SECRET SENTENCE</t></si><si><t>{POLICY}</t></si></sst>',
        'xl/worksheets/sheet1.xml': f'<worksheet xmlns="{S}"><sheetData><row r="1"><c r="B1" t="s"><v>1</v></c></row>'
                                  '<row r="2" hidden="1"><c r="B2" t="s"><v>0</v></c></row></sheetData></worksheet>',
        **(extra or {}),
    })


@pytest.mark.parametrize(('content', 'mime', 'location'), [
    (word(), DOCX_MIME, {'paragraph': 2}),
    (workbook(), XLSX_MIME, {'sheet': 'Policy & controls', 'cell': 'B1'}),
], ids=['word-table', 'excel-shared-string'])
def test_evidence_citations_bind_original_office_bytes_and_real_locations(content, mime, location):
    with tenant_scope(tenant='synthetic-office'):
        result = extract(EvidenceDocument('file', '1', 100, content, mime), source='upload',
                         name='Synthetic evidence', now=200, freshness_days=30)
    assert result['status'] == 'available'
    citation = result['extracted']['answers']['aiv_provenance']['citations'][0]
    assert citation['document_sha256'] == result['content_sha256'] == hashlib.sha256(content).hexdigest()
    assert citation['locations'] == [location]
    assert 'pages' not in citation
    assert 'UNUSED SECRET SENTENCE' not in str(result)


@pytest.mark.parametrize('parts', [
    {'word/_rels/document.xml.rels': '<Relationships><Relationship TargetMode="External" Target="https://example.test/private"/></Relationships>'},
    {'word/vbaProject.bin': b'not executed'},
    {'word/embeddings/embedded.bin': b'not executed'},
    {'../escape.xml': '<x/>'},
    {'word/other.xml': '<!DOCTYPE a [<!ENTITY x "expansion">]><a>&x;</a>'},
    {'word/large.xml': '<x>' + 'a' * 300_000 + '</x>'},
])
def test_unsafe_office_packages_fail_closed_before_any_text_is_used(parts):
    with pytest.raises(ValueError):
        extract_office(word(parts), DOCX_MIME)


def test_xlsx_does_not_treat_unused_shared_strings_or_hidden_rows_as_evidence():
    text, metadata = extract_office(workbook(), XLSX_MIME)
    assert text == POLICY
    assert metadata['location_spans'][0]['cell'] == 'B1'
    assert metadata['cached_formula_values'] is False


def test_duplicate_zip_members_and_invalid_string_indices_are_rejected():
    stream = io.BytesIO(word())
    with zipfile.ZipFile(stream, 'a') as archive:
        with pytest.warns(UserWarning):
            archive.writestr('word/document.xml', '<x/>')
    with pytest.raises(ValueError, match='ambiguous'):
        extract_office(stream.getvalue(), DOCX_MIME)
    data = workbook({'xl/worksheets/sheet1.xml': f'<worksheet xmlns="{S}"><sheetData><row><c r="A1" t="s"><v>-1</v></c></row></sheetData></worksheet>'})
    with pytest.raises(ValueError, match='shared-string'):
        extract_office(data, XLSX_MIME)


@pytest.mark.parametrize(('extension', 'mime'), [('docx', DOCX_MIME), ('xlsx', XLSX_MIME)])
def test_authored_office_library_corpus_has_visible_policy_text_and_no_hidden_claim(extension, mime):
    root = Path(__file__).resolve().parents[3] / 'scripts/acceptance/fixtures/vendor-documents'
    text, metadata = extract_office((root / ('northstar-policy.' + extension)).read_bytes(), mime)
    assert POLICY in text
    assert 'undisclosed' not in text and 'Header outside' not in text
    assert metadata['review_required'] is True


def test_cached_formula_values_are_explicit_and_never_evaluated():
    data = workbook({'xl/worksheets/sheet1.xml': f'<worksheet xmlns="{S}"><sheetData><row><c r="A1"><f>1+2</f><v>4</v></c></row></sheetData></worksheet>'})
    text, metadata = extract_office(data, XLSX_MIME)
    assert text == '4' and metadata['cached_formula_values'] is True


def test_large_text_is_rejected_without_a_complete_looking_prefix():
    text = ''.join(str(index) + ' ' + POLICY for index in range(2200))
    data = package({'word/document.xml': f'<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>'})
    with pytest.raises(ValueError, match='review limit'):
        extract_office(data, DOCX_MIME)
