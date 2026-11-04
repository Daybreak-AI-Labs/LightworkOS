# Selected deliverable bundles

Enable **Selected deliverable bundles** in Settings (or the installer). The
feature is off by default. Named workspace accounts are required. Open a task,
choose **Prepare selected deliverable bundle**, name the bundle and recipient,
and select exact artifact versions, original evidence files, or the saved result.
Nothing is selected implicitly. Explain the recipient's job and unresolved checks,
then preview and explicitly confirm sharing. A bundle contains at most 30 items
and six megabytes; unavailable or altered evidence is refused before sharing.

The recipient sees only that captured copy on **Selected deliverable bundles**.
They receive no conversation, other artifacts, tool history, credentials, task
execution permission, or final task sign-off. Current workspace membership and
suite permission are rechecked on reads, responses, individual downloads and
exports. Administrators do not receive a private-content bypass. The original
owner can end future access; previously downloaded copies cannot be recalled.
Access expires after the reviewed one-hour, one-day or seven-day period.

Human acceptance is a separate explicit action by the named recipient. File
integrity checks never imply that someone approved the work. Task edits, changed
selected evidence, or newer artifact versions make acceptance stale. The prior
human comment remains in the captured record. Older versions can be shared for
comparison, but their acceptance is already stale against the current source.

The download is a ZIP with selected original files, editable Markdown, complete
table CSV where supported, an escaped HTML preview, the review record, and a
SHA-256 manifest. CSV formula-like cells are escaped, with original content also
retained in Markdown. Unrecognized evidence formats download as inert binary
files rather than executable previews. No DOCX, spreadsheet or presentation
conversion is claimed for content that was not already in that native format.

Extract the ZIP and open **verify.html** in a browser with local Web Crypto.
Select the extracted content files to compare them with the portable manifest.
This needs no network or command line. Missing, duplicated or changed files are
reported individually. The checks establish consistency with the supplied
manifest, not authenticity, factual correctness, current access or human approval.
The manifest and verifier are not signed. Freshness and acceptance are captured
as of export. Packaging verifies every ZIP entry before download; failed exports
leave the saved bundle unchanged. No export files or submits anything externally.

Copilot uses the same native source selection, exact recipient preview, operation
receipt, current membership checks, and response revision. Its artifact family
must be enabled by an administrator. The native screen remains available when
the model is unavailable. Duplicate share requests reuse the same immutable
bundle; conflicting references are refused. The UI preserves an uncertain share
request for explicit retry instead of silently repeating it with a new identity.

Implementation evidence is in `deliverable_bundles.py`,
`deliverable_bundle_export.py`, `deliverable_bundles_api.py`, and
`product_operations_bundles.py`. Native regression cases are in
`test_deliverable_bundles.py`; local, browser and PostgreSQL qualification must
not be inferred from this design document.
