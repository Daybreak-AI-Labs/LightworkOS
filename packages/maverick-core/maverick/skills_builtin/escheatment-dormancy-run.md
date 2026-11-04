---
name: escheatment-dormancy-run
triggers:
  - unclaimed property
  - escheatment
  - dormancy period
  - abandoned property
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Walks a multistate unclaimed-property (escheatment) cycle: run dormancy clocks by property type and jurisdiction, schedule due-diligence outreach, apply B2B exemptions, and prepare for the Delaware VDA path — surfacing credit balances and uncashed checks as the most-missed property types. The goal class is "identify and prepare unclaimed property for reporting" with dormancy timing and the often-overlooked property categories as the focus.

# Steps

1. Read the relevant ledgers (AP uncashed checks, AR credit balances, payroll, rebates, gift balances) with read_file and inventory potential unclaimed property by type and last-activity date.
2. Apply the dormancy period for each property type in each jurisdiction (it varies by state and by property class), using the holder's address rules: report to the owner's last-known-address state first, falling back to the holder's state of incorporation otherwise. Search knowledge_search for the controlling dormancy periods and priority rules.
3. Schedule statutory due-diligence outreach to owners within the required pre-report window, and apply B2B (business-to-business) exemptions where a state recognizes them so genuinely exempt balances are not over-reported.
4. Prepare the report package and, where exposure spans many years or states, evaluate the Delaware VDA (voluntary disclosure agreement) path as an alternative to audit — flagging credit balances and uncashed checks explicitly, since these are the most-missed property types.

# Notes

Credit balances and uncashed/outstanding checks are the categories holders most often miss, and they are exactly what state audits target. Dormancy periods are NOT uniform — they differ by state and by property type, so a single global clock will mis-age property. The owner-last-known-address priority rule (then state of incorporation) determines WHICH state gets the property; getting it wrong means reporting to the wrong jurisdiction. B2B exemptions are state-specific and not universal. This skill prepares the inventory, outreach plan, and report draft for the unclaimed-property team; it does not remit funds or file reports.
