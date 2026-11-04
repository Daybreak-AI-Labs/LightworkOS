---
name: eight-d-problem-solving
triggers:
  - run an 8D on this defect
  - corrective action for a recurring failure
  - this defect keeps coming back, do root cause
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Drives the 8 Disciplines (8D) method to its conclusion for a recurring or high-impact defect: a structured corrective-action investigation that produces a D1-D8 report with verified interim containment, a proven root cause, and a permanent corrective action with effectiveness evidence. Use it when the same failure has recurred or escaped to a customer and an ad hoc fix is not acceptable.

# Steps

1. D1-D2: Pull the real failure record (defect ID, dates, affected lots/units, customer impact) via knowledge_search and prior tickets; state the problem quantitatively (what, where, when, how many) and name the cross-functional team and champion. Do not proceed on a vague problem statement — quantify or flag the gap.
2. D3: Define and verify interim containment (quarantine, inspection screen, rollback) that stops escape NOW; record in a spreadsheet what is contained, the screen's effectiveness, and the date applied. Mark containment as recommended-pending-approval, not auto-executed.
3. D4-D5: Drive root cause from the data — build a 5-Whys or fishbone in the spreadsheet, test each candidate against the evidence (occurrence cause AND escape/detection cause), and verify the chosen root cause reproduces and explains the data; reject causes you cannot tie to a record.
4. D6-D8: Specify the permanent corrective action, the validation evidence that it removes the root cause, the preventive/read-across actions (controls, FMEA/control-plan updates, similar processes), and team recognition. Assemble the D1-D8 report, state assumptions and any unverified causes explicitly, and hand off to the quality owner for sign-off.

# Notes

Output is wrong if containment and corrective action are conflated, if root cause is asserted without evidence that it reproduces the defect, or if the escape (detection) cause is ignored — a fix that prevents occurrence but not escape leaves the customer exposed. Containment and permanent actions are staged as recommendations; a human owner authorizes quarantine, scrap, or process change. Do not use 8D for one-off cosmetic issues or new-design work — it is for recurring/systemic defects with a containment need.
