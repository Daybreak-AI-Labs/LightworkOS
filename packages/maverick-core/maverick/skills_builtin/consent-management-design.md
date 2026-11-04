---
name: consent-management-design
triggers:
  - consent management
  - cookie consent
  - preference center
---
# What this skill does

Designs how an organization captures, stores, and honors user consent and preferences across its properties (cookies/trackers, marketing, and other consent-based processing). Produces a consent-management design that ties each consent to a lawful basis, defines the preference center and capture flows, and specifies the consent record schema. Output is an implementation-ready specification, not running code.

# Steps

1. Inventory the processing activities that require consent from the request and map each to its basis: GDPR consent (freely given, specific, informed, unambiguous, withdrawable) vs. legitimate interest vs. CCPA/CPRA opt-out. Distinguish opt-in (EU cookies/marketing) from opt-out (US sale/sharing) regimes per audience.
2. Use knowledge_search to retrieve the cookie/tracker inventory, existing notice text, applicable rules (ePrivacy, GDPR, CPRA), and any current CMP configuration. Identify trackers that must be blocked until consent.
3. Design the capture surfaces — banner, granular preference center by purpose category, and global signal handling (GPC honored as opt-out) — ensuring reject is as easy as accept, no pre-ticked boxes, and a withdrawal path equal to the grant path. Define the consent record schema: subject/identifier, timestamp, purpose, basis, scope, capture context/version of notice, and proof of action.
4. Report the design as flows + schema + a basis-to-surface mapping, listing what enforcement (tag blocking) each consent state must drive, and hand off for engineering and privacy review. State assumptions about audiences and platforms.

# Notes

Wrong if consent is bundled across purposes, if withdrawal is harder than granting, if records lack proof/timestamp/notice-version (undemonstrable consent = no consent under GDPR), or if trackers fire before opt-in. Do not conflate EU opt-in with US opt-out flows in one undifferentiated banner. This is a design/recommendation deliverable — a human approves before deployment, and no live tags or user data are altered by this skill. Not for designing the underlying lawful-basis decision itself (use gdpr-lawful-basis-assessment first).
