---
name: redact-secrets-in-output
triggers:
  - scan for secrets
  - no credentials in logs
  - safe to commit
  - strip api keys
tools_needed:
  - read_file
  - redact
---
# What this skill does

Runs the shipped `redact` tool on text headed for a commit, log, ticket, or shared channel. It returns cleaned text and a detector-relative proof status. It does not certify that every unknown token format or contextual credential has been recognized.

# Steps

1. Read the candidate text with `read_file` using `path`, then call `redact` with `op="redact"` and the entire `text`, including code comments and configuration blocks.
2. For each hit, replace the secret value with a typed placeholder such as [REDACTED:provider-key] while leaving surrounding non-secret text intact; preserve the variable name so the code still reads sensibly.
3. Treat connection strings with inline credentials, private-key PEM blocks, and bearer values as full-block redactions — redact the whole key material, not just the prefix.
4. Call `redact` with `op="verify"` and the cleaned `text`. Report any residuals and the returned status without inventing category counts. If a secret was found, request human review and credential rotation as appropriate; this skill does not perform a commit or send.

# Notes

Redacting only a token prefix leaves the credential exposed. Contextual and unfamiliar high-entropy values require human review even after a clean detector result. A secret already pushed cannot be removed from history by redacting the local text; escalate for rotation. This skill prepares a cleaned draft; it does not perform a commit or send.
