---
name: extract-from-document
triggers:
  - pull data from this pdf
  - extract the table
  - ocr this
  - get the fields from this document
tools_needed:
  - read_file
  - read_pdf
  - ocr
---
# What this skill does

Extracts available document text and tables, then prepares a structured field draft with source references and an explicit could-not-read flag. The shipped tools do not promise schema extraction, bounding boxes, or calibrated per-field confidence. Distinguish tool-returned evidence from the agent's interpretation.

# Steps

1. For a PDF call `read_pdf` with `source` and `include_tables=true`; choose `pages` when known. For a scanned PDF, `ocr=true` requires the enabled offline document engine. For an image call `ocr` with `op="extract"`, `path`, and `backend="tesseract"`; this also requires the configured local engine. For plain text use `read_file` with `path`. If an optional engine/dependency is unavailable, report that prerequisite and request extracted text; do not imply extraction succeeded.
2. Map the returned text/tables to the requested fields. Cite only page/region information actually returned. Mark confidence as uncalibrated unless the tool supplied a score; never invent coordinates or scores. For tables preserve the available row/column structure and flag uncertain alignment.
3. Mark any field that is illegible, absent, or ambiguous as could_not_read rather than inventing a plausible value. Do not infer a number that is not on the page.
4. Reconcile internal consistency where the document allows it (totals equal the sum of line items, dates are ordered) and flag any failed check for human review instead of silently correcting.

# Notes

Do not fill a blank or smudged field with a guess. OCR confidence is not document confidence. Verify table totals and preserve the source excerpt. This skill drafts and reports; it does not write values into a system of record or certify deterministic field extraction.
