# Document extraction coverage

Knowledge ingestion and Office attachment companions use the versioned
`lightwork.document-extraction.v1` result. A result has a status, source format,
SHA-256 of the uploaded bytes, extractor version, normalized text blocks with
source locations and character offsets, covered and omitted regions, and warnings.
Coverage describes what was extracted. It does not verify facts in the source.

`complete` means the supported text projection completed without identified
omissions. `partial` identifies omitted regions or a reached extraction bound.
`empty`, `unsupported`, `unavailable`, `rejected`, and `failed` remain distinct.
The legacy `extract_text` convenience function returns normalized text for
complete/partial/empty results and raises for the other statuses.

| Input | Text projection and limits |
| --- | --- |
| DOCX | Body paragraphs and table-cell paragraphs in document order. Headers, footers, notes, comments, media, hidden runs, and nested tables are explicitly omitted. Fields, tracked changes, text boxes, and active/embedded content require a reviewed text copy. |
| XLSX | Visible worksheet cells in stored row/cell order, with sheet and cell references. Formula expressions are shown with their cached value or an uncalculated marker; formulas never execute. Hidden cells/sheets and unsupported visual parts are omitted. Display formatting is not interpreted. |
| PDF | Embedded text by page through optional `pypdf`. Pages without extracted text are marked unresolved: they may be blank, image-only, or unsupported. This parser never starts OCR. |
| UTF-8 text allowlist | TXT, Markdown, RST, CSV/TSV, logs, JSON/JSONL, YAML, TOML, XML, and HTML. HTML is a visible-text projection without scripts, styles, or layout. Binary signatures, invalid UTF-8, and binary control bytes are rejected. |
| Other formats | Explicit unsupported status, including PPTX, RTF, ODT, and legacy Office binaries. An extension never authorizes decoding a ZIP as text. Images use the existing explicitly configured image-describer route when ingested. |

Default input bounds remain 25 MiB per document, 200 MiB expanded Office content,
and 5,000 PDF pages. Existing `MAVERICK_KNOWLEDGE_MAX_DOC_BYTES`,
`MAVERICK_KNOWLEDGE_MAX_DOCX_UNCOMPRESSED_BYTES`, and
`MAVERICK_KNOWLEDGE_MAX_PDF_PAGES` settings still apply. Office parsing also bounds
members, individual expanded parts, compression ratios, worksheets and cells;
it refuses ambiguous paths, macros, external links and XML entity declarations.
Normalized text is capped at one million characters and 10,000 blocks. Reaching
a text/block bound marks the result partial. Location metadata is bounded and
includes its count and digest when the full list cannot be included.

Attachment companions carry the status, hashes, normalized range and locations
inside their existing character cap. A truncated companion states which text
range it includes. Unsupported documents receive an explanatory companion when
the parser package is present. Companion text remains untrusted uploaded data
and passes through the existing injection-screening path. Original attachments
and their SHA-256 values remain unchanged; extraction from different bytes is
not attached as if it described the original upload.

Knowledge chunks carry the extraction metadata alongside the existing immutable
normalized document identity and exact reconstruction offsets. Full-document
and per-chunk screening remain in force. Conflicting provenance cannot silently
replace an existing normalized document record.

Extraction covers parsing and coverage reporting. It does not qualify rendered
layout, OCR transcription, arbitrary customer documents, or native Office
compatibility.
