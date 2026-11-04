---
name: redact-pii-before-egress
triggers:
  - redact before sending
  - scrub pii
  - safe to share
  - remove personal data
tools_needed:
  - read_file
  - redact
---
# What this skill does

Prepares text using the shipped `redact` detector and requests human review for sensitive context it cannot establish. Its clean result means no residual matches from the configured detectors, not exhaustive detection of names, health information, or every special-category field.

# Steps

1. Read the outbound payload with read_file and identify the destination and its sensitivity tier (internal vs external vs regulated third party).
2. Call `redact` with `op="redact"` and `text` containing the full extracted payload. Extract attachment text using supported document tools first; unreadable attachments remain unreviewed. Treat free-text and structured fields alike.
3. Use the returned cleaned text and its proof status. Give sensitive context stricter human review and drop unnecessary fields. Do not promise stable identifiers or category counts that the tool did not return.
4. Call `redact` with `op="verify"` and the cleaned `text`. If residuals remain, stop and report them. Report what text was checked, missing attachments, and detector limits alongside the cleaned draft; a person decides whether to release it.

# Notes

Detectors miss context-dependent identifiers (an internal employee id, a rare diagnosis, a quasi-identifier combination that re-identifies someone); when the destination is external and the data is sensitive, default to human review rather than trusting a clean scan. Masking preserves length/format only for readability — never reversibly encode the original value into the placeholder. This skill prepares a redacted copy; it does not itself send anything. Data minimization beats redaction: if a field is not needed for the purpose, drop it instead of masking it.
