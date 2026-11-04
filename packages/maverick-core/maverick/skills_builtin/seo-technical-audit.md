---
name: seo-technical-audit
triggers:
  - seo audit
  - technical seo
  - search audit
  - why is organic traffic dropping
tools_needed:
  - web_search
  - read_file
---
# What this skill does

Diagnoses the organic-search health of a specific site or set of URLs and produces a prioritized technical-SEO audit. Covers crawlability, indexation, on-page content signals, and core ranking blockers. Output is a findings list ranked by impact and effort, each with the evidence it was derived from and a concrete remediation.

# Steps

1. Confirm scope from the user: the target domain/URLs, the priority pages or keywords, and any access to crawl exports, server logs, or analytics (`read_file`). Never assume which pages matter — ask if unstated.
2. Gather signals: fetch the live pages and `robots.txt`/`sitemap.xml` via `web_search` / fetch; check indexation with `site:` queries; inspect titles, meta descriptions, H1s, canonical tags, status codes, redirect chains, hreflang, and structured data. Record the exact URL and observed value behind every finding.
3. Bucket findings into crawl (blocked paths, broken sitemap, 4xx/5xx, redirect loops), index (noindex, canonical conflicts, thin/duplicate pages, orphan pages), and content (missing/duplicate titles, weak headings, missing schema, intent mismatch). Mark anything you could not verify directly as "unverified — needs Search Console / log access".
4. Score each finding by impact (traffic at risk) and effort, then report the audit ranked highest-impact-first with a one-line fix per item. State assumptions and hand off; flag any change touching `robots.txt`, canonicals, or redirects as requiring human review before deploy.

# Notes

The output is wrong if findings rest on cached or rendered-vs-raw HTML differences you didn't check — verify against the live raw response. Without Search Console / log-file / analytics access, indexation and traffic-loss claims are inferences, not facts; label them so. Do not push any change to live `robots.txt`, sitemaps, canonical tags, or redirect rules — those are irreversible-by-impact and stage as recommendations for a human. Not for content-strategy/keyword-research planning (use a content skill) or for paid-search diagnosis.
