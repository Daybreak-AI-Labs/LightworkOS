"""Bounded vendor evidence extraction; source bytes and full text stay transient."""
from __future__ import annotations

import hashlib
import math
import re

from . import ai_vendor_risk as risk
from .privacy_ops import _build_document_evidence, _document_text
from .vendor_office_text import MAX_OFFICE_BYTES, MAX_TEXT_CHARS, OFFICE_MIMES, extract_office
from .vendor_onboarding_adapters import GOOGLE_DOC_MIME, MAX_PDF_BYTES, MAX_TEXT_BYTES

MAX_DOCUMENTS = 8
MAX_TOTAL_BYTES = 32 * 1024 * 1024


def _read(document, mime, transcription):
    metadata = {}
    if mime in OFFICE_MIMES:
        text, metadata = extract_office(document.content, mime)
    else:
        text = _document_text(document.content, mime, _metadata=metadata)
    if transcription is not None:
        if mime != "application/pdf" or text.strip() or not document.content.startswith(b"%PDF-"):
            raise ValueError("Manual transcription is available only when the selected PDF cannot yield supported text")
        if not isinstance(transcription, str) or not transcription.strip() or len(transcription) > MAX_TEXT_CHARS:
            raise ValueError("Provide between 1 and 120,000 characters of transcription")
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", transcription):
            raise ValueError("Transcription contains unsupported control characters")
        text = transcription
        metadata = {"method": "human_transcription", "scope": "user_supplied_text",
                    "confidence": "untrusted", "review_required": True,
                    "source_extraction_method": metadata.get("method", "unsupported"),
                    "limits": ["User-supplied transcription; no OCR or source-text verification was performed.",
                               "Paragraph locations refer to the transcription, not PDF pages."]}
    return text, metadata


def _locations(result, text, metadata, mime, source, document, name):
    for answer in result["answers"].values():
        for citation in answer["citations"]:
            citation.update(source=source, document_id=document.document_id,
                            source_version=document.version, document_name=name)
            if metadata.get("method") == "human_transcription":
                citation["text_origin"] = "human_transcription"
                citation["transcription_paragraph"] = 1 + len(re.findall(r"\n\s*\n", text[:citation["start"]]))
            elif mime in OFFICE_MIMES:
                citation["locations"] = [{key: value for key, value in span.items() if key not in {"start", "end"}}
                                         for span in metadata["location_spans"]
                                         if span["end"] > citation["start"] and span["start"] < citation["end"]]
            elif mime == "application/pdf":
                pages = sorted({page for span in metadata.get("page_spans", [])
                                if span["end"] > citation["start"] and span["start"] < citation["end"]
                                for page in span["pages"]})
                if not pages:
                    raise ValueError("PDF quotation has no verified page location")
                citation["pages"] = pages
            else:
                citation["paragraph"] = 1 + len(re.findall(r"\n\s*\n", text[:citation["start"]]))


def extract(document, *, source: str, name: str, now: float, freshness_days: int,
            transcription: str | None = None, preview: dict | None = None) -> dict:
    """Retain only provenance, parser limits and bounded redacted quotations."""
    if (not document.version or not math.isfinite(document.modified_at)
            or document.modified_at <= 0 or document.modified_at > now):
        raise ValueError("document date or version is invalid")
    mime = document.export_mime or document.mime
    if document.mime == GOOGLE_DOC_MIME and mime != "text/plain":
        raise ValueError("Google Docs requires the version-bracketed text export")
    if mime not in {"text/plain", "application/pdf", *OFFICE_MIMES}:
        raise ValueError("unsupported document format")
    limit = MAX_OFFICE_BYTES if mime in OFFICE_MIMES else MAX_PDF_BYTES if mime == "application/pdf" else MAX_TEXT_BYTES
    if len(document.content) > limit:
        raise ValueError("document exceeds the supported byte limit")
    if mime == "text/plain":
        document.content.decode("utf-8", errors="strict")
    text, metadata = _read(document, mime, transcription)
    if preview is not None:
        if len(text) > MAX_TEXT_CHARS:
            raise ValueError("Extracted text exceeds the 120,000-character review limit; split the evidence file")
        preview.update(text=text, locations=metadata.get("location_spans", []),
                       can_transcribe=mime == "application/pdf" and not text.strip() and document.content.startswith(b"%PDF-"))
    result = None
    status = "empty" if not text.strip() and mime == "text/plain" else "extraction_failed"
    if text.strip():
        evidence = _build_document_evidence(data=document.content, text=text[:risk._MAX_EXTRACTED_CHARS],
            mime=mime, source=source, doc_id=document.document_id,
            ref={"version": document.version, "source_mime": document.mime}, extraction=metadata)
        result = risk._extract_document_answers(text[:risk._MAX_EXTRACTED_CHARS], evidence,
                                               truncated=len(text) > risk._MAX_EXTRACTED_CHARS)
        if result["truncated"]:
            # A complete-looking assessment must not omit the uninspected tail.
            status = "extraction_limit"
        else:
            status = "available"
        _locations(result, text, metadata, mime, source, document, name)
        risk._validate_document_result(result)
    return dict(document.identity(), source=source, name=name, export_mime=document.export_mime,
                status=status, byte_length=len(document.content), collected_at=now,
                content_sha256=hashlib.sha256(document.content).hexdigest(), extracted=result,
                fresh_until=document.modified_at + freshness_days * 86400,
                date_basis="uploader_asserted_document_date" if source == "upload" else "provider_modified_time",
                extraction={key: value for key, value in metadata.items() if key not in {"page_spans", "location_spans"}})


def document_diff(previous: dict | None, current: dict) -> dict:
    """Compare retained evidence versions and cited suggestions, never invent text."""
    def docs(evidence):
        if not evidence:
            return []
        return evidence.get("documents") or [evidence]

    old = {(item.get("source", "gdrive"), item.get("document_id")): item for item in docs(previous)}
    new = {(item.get("source", "gdrive"), item.get("document_id")): item for item in docs(current)}
    changes = []
    for key in sorted(old.keys() | new.keys()):
        before, after = old.get(key), new.get(key)
        state = "added" if before is None else "removed" if after is None else "unchanged"
        if before and after and any(before.get(field) != after.get(field) for field in ("version", "content_sha256", "status")):
            state = "changed"
        answers = []
        before_answers = ((before or {}).get("extracted") or {}).get("answers", {})
        after_answers = ((after or {}).get("extracted") or {}).get("answers", {})
        for question in sorted(before_answers.keys() | after_answers.keys()):
            left, right = before_answers.get(question, {}), after_answers.get(question, {})
            if left.get("answer") != right.get("answer") or [c["quote"] for c in left.get("citations", [])] != [c["quote"] for c in right.get("citations", [])]:
                answers.append({"question_id": question, "before": left.get("answer", "unknown"),
                                "after": right.get("answer", "unknown"),
                                "before_citations": left.get("citations", []), "after_citations": right.get("citations", [])})
        changes.append({"source": key[0], "document_id": key[1], "change": state,
                        "before_version": (before or {}).get("version"), "after_version": (after or {}).get("version"),
                        "answer_changes": answers})
    return {"comparison": "previous_review" if previous else "initial_evidence", "documents": changes,
            "review_required": True}
