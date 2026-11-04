---
name: ip-clearance-search
triggers:
  - run an ip clearance on this name
  - freedom to operate check
  - trademark search before we launch
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Produces an advisory IP clearance landscape for a proposed name, mark, or product feature, mapping likely conflicts and registrations to a risk tier. Handles freedom-to-operate (patent/feature) and trademark clearance (brand/name) screening. Output is a structured landscape with cited prior references and a high/medium/low risk rating per conflict — it is NOT a legal opinion and does not authorize launch.

# Steps

1. Pin the exact subject from the request: the literal mark/name string (and obvious variants/transliterations), the goods/services classes or product domain, and the target jurisdictions. If any is missing, state the assumption (e.g. "assuming US + EU, Class 9 software") rather than guessing silently.
2. Run `knowledge_search` first for any internal prior-clearance memos, existing brand portfolio, or known competitor marks so you don't re-flag owned assets or repeat work.
3. Use `web_search` against public registers and indices appropriate to the type: trademark = USPTO TESS/TMView, EUIPO, national registries plus common-law/web use; FTO = Google Patents, Espacenet, published applications in the relevant class. Capture each hit's identifier (registration/app number, owner, filing date, status, class/claims), and cite the source URL. Mark anything you could not confirm from a primary register as "unverified".
4. Map each hit to a risk tier (high = live identical/near-identical mark in same class, or granted patent reading on the core feature; medium = similar mark/adjacent class or pending app; low = dead/abandoned, distant class, or weak similarity). Report the landscape as a table with the assumptions, gaps in coverage, and an explicit handoff line that counsel must make the go/no-go call.

# Notes

The output is wrong if it conflates "no hit found" with "clear" — absence of evidence in the registers searched is not clearance, and you must state which registers and date ranges you actually covered. Common failure modes: missing phonetic/foreign-language equivalents of a mark, skipping pending (unpublished) applications, and treating an abandoned registration as a live block. Never assert infringement or non-infringement, never tell the user they are "safe to launch", and stage the result as advisory input for a qualified attorney. Do not use this skill for validity/invalidity opinions or litigation analysis — it is a screening pass only.
