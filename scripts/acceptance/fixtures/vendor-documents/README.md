# Synthetic vendor documents

These internally authored fixtures contain no customer or live vendor data. The PDF has three real pages, including a blank second page, to test source-grounded page locations. The text fixture deliberately contradicts its provenance and training-data claims. They demonstrate supported parsing and unresolved review; they are not compliance evidence or live acceptance.

`northstar-policy.docx` and `northstar-policy.xlsx` are authored with python-docx and openpyxl by `make_office_fixtures.py`. They exercise Word body text and table paragraphs, Excel visible cells and a deliberately hidden contradictory row. The Word header is intentionally outside the supported scope. `northstar-scan.pdf` is a real raster-only PDF containing the same short synthetic provenance sentence; it requires the explicit human-transcription fallback, with no OCR claim. The generator's optional development libraries are not product or test-runtime dependencies.
