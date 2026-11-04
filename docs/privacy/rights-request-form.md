# Rights request form

Let people submit privacy requests (access, deletion, correction, portability,
opt-out and the rest) from your website, without an account. Each request
lands in **Privacy → Data requests (DSAR)** with the deadline the law they
chose actually sets, once they confirm their email address.

## What it does

1. **Public form** at `/rights/<link-name>` for each website or app you set
   up, and a JSON API under `/api/v1/public/rights/<link-name>/` for embedding.
   The person picks the law that applies to them (pre-selected from your
   property settings; no geo-IP lookup), and sees only the request types that
   law grants.
2. **Email confirmation.** On submit we email a single-use link (valid for
   `verification_ttl_hours`, stored only as a SHA-256 digest). The request sits
   in the tracker as *Not yet confirmed*; opening the link moves it to *Open*
   and records `email_challenge` as the identity method **performed** (the
   other methods remain labels a person records after checking elsewhere).
   A second, long-lived link lets the requester follow progress.
3. **Deadlines per law**, from the verified table in
   `maverick/rights_deadlines.py`. Every row names its statute section or
   regulator page and the date it was checked. Business-day rules skip
   weekends; month rules use the corresponding date next month.
4. **Templated notices** — acknowledgement, verification, identity follow-up,
   extension, completion (with the secure download link) and refusal (with
   the lawful basis) — per family of laws, editable on the settings page and
   kept as numbered versions.

## Deadlines (verified 2026-09-30)

| Law | Answer within | Extension | Other clocks | Source |
|---|---|---|---|---|
| EU GDPR | 1 month | +2 months, notice within the first month | — | GDPR Art. 12(3), eur-lex.europa.eu |
| UK GDPR | 1 month from the *relevant time* | +2 months, notice within the first month | — | UK GDPR Art. 12A (DUA Act 2025 s. 76), legislation.gov.uk |
| California CCPA/CPRA | 45 days | +45 days, notice within the first 45 | confirm receipt in 10 business days; opt-out honoured in 15 business days | Civ. Code 1798.130(a)(2)(A); 11 CCR 7021(a), 7026(f)(1) |
| Virginia, Colorado, Connecticut, Utah, Texas, Oregon | 45 days | +45 days, notice within the first 45 | — | Va. 59.1-577(B)(1); C.R.S. 6-1-1306(2)(a); Conn. 42-522(b) (AG page); Utah 13-61-203; Tex. 541.052(b); ORS 646A.576(5)(a) |
| Brazil LGPD | access: 15 days (complete declaration) | none | other rights: no fixed period → internal target | Lei 13.709/2018 Art. 19 |
| Canada PIPEDA | 30 days | +30 days max, notice within the first 30 | deemed refusal if late | PIPEDA s. 8(3)–(5) |
| Australia | reasonable period; OAIC: not more than 30 days | none | — | APP 12.4; OAIC APP Guidelines ch. 12 |
| Japan APPI | "without delay" — no fixed period → internal target | none | — | APPI Art. 28(2) in the PPC's June 2020 translation (now Art. 33) |

**Not offered yet:** Quebec (Law 25, s. 32) and Singapore (PDPA s. 21 /
Regulations reg. 4). Their official sources could not be fetched from the
build environment on the verification date, so they are listed in
`rights_deadlines.UNVERIFIED` instead of being guessed. Verify them against
the source and move them into `REGIMES`.

The dates are decision support for your privacy team, not legal advice.

## Setting it up

1. Turn on **Privacy automation → Rights request form** (Settings → Modules,
   or the banner on *Privacy → Rights request form*). Config:

   ```toml
   [privacy_automation]
   enable = true

   [privacy_automation.public_rights_form]
   enable = true
   verification_ttl_hours = 24
   status_ttl_days = 90
   requests_per_ip_per_hour = 5
   requests_per_email_per_day = 3
   internal_target_days = 30
   max_message_chars = 4000
   ```

   The installer asks "Let people submit privacy requests from your website?".
2. Make sure the platform email account is configured (`[email]` /
   `EMAIL_USER` + `EMAIL_APP_PASSWORD`, the same account invites use). Without
   it, notices are recorded on the request as *not sent* with the reason.
   Set `MAVERICK_PUBLIC_BASE_URL` (or `[channels] public_base_url`) to the
   externally reachable HTTPS dashboard URL (the existing `MAVERICK_PUBLIC_URL`
   or `[dashboard] public_url` is also accepted). The form refuses submissions and
   verification when this trusted URL is missing or invalid.
3. On *Privacy → Rights request form*, add a property: link name, names,
   privacy contact, the laws to offer, the default law, the request types,
   and (optionally) other https origins allowed to embed the form. Copy the
   public link or the iframe snippet.

## Anti-abuse

No CAPTCHA vendor. The form uses a signed arithmetic challenge (single use,
15 minutes), a hidden honeypot field, per-connection and per-email sliding
limits (from config), bounded field sizes and a 32 KiB body cap. Submissions
must be JSON from the form's own page or an allowed origin, which keeps the
endpoint CSRF-safe. The verification link is consumed by a button press
(POST), so mail scanners that prefetch links do not use them up. Answers to
the public never say whether an email address is known.

## Fields the alerting reads

On every tracked request: `jurisdiction`, `due_at`, `due_basis`,
`acknowledge_by`, `acknowledged_at`, `extended_until`, `extension_reason`,
`received_at`, `source` (`dashboard`, `message`, `public_form`),
`verification.status`. `privacy_ops.dsar_clock()` computes
`effective_due_at`, `days_left`, `overdue`, `due_soon` and
`acknowledge_overdue` from them.
