---
name: email-security-review
triggers:
  - review our email security
  - check spf dkim dmarc
  - email spoofing and phishing posture
tools_needed:
  - knowledge_search
---
# What this skill does

Reviews a domain's email-authentication and anti-phishing posture and produces a gap report. Assesses SPF, DKIM, and DMARC configuration plus supporting controls (alignment, reporting, BIMI, MTA-STS, inbound anti-phishing), and ranks remediation by spoofability risk.

# Steps

1. Collect the real inputs: the domain(s) in scope and their published SPF/DKIM/DMARC records (provided or to be retrieved). If records are not supplied, note that they must be fetched from DNS and treat any record content as unverified until confirmed.
2. Evaluate each record against current standards via `knowledge_search`: SPF (mechanism count under the 10-lookup limit, `-all` vs `~all`), DKIM (key presence, rotation, >=2048-bit RSA), and DMARC (policy `p=none/quarantine/reject`, `pct`, `rua/ruf` reporting, and SPF/DKIM alignment). Cite the standard for each check.
3. Identify gaps that enable spoofing or phishing: `p=none` with no reporting, soft-fail SPF, missing DKIM signing, no alignment, no inbound controls (no DMARC enforcement on receive, weak link/attachment scanning, no impersonation/lookalike-domain detection).
4. Rank findings by exploitability (open spoofing > weak enforcement > hygiene), give the concrete record change for each, and report as a phased plan. State assumptions and flag that moving DMARC to `reject` risks blocking legitimate mail until all senders are aligned — a monitored rollout a human approves.

# Notes

Output is wrong if it recommends `p=reject` before SPF/DKIM alignment is confirmed across all legitimate senders — that silently drops real mail and is operationally disruptive. Treat enforcement changes as staged recommendations for an owner, not auto-applied DNS edits. Every standard claim must cite a source; never assert a record's content without confirming it (DNS is the ground truth). Not for deliverability tuning (warmup, reputation) and not for incident response on an active phishing campaign.
