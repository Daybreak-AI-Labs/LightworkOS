---
name: org-design-spans-layers
triggers:
  - redesign the org structure
  - analyze our spans and layers
  - plan a reorg
tools_needed:
  - spreadsheet
---
# What this skill does

Analyzes an organization's spans of control and management layers from a real headcount roster, identifies structural problems (over-layering, narrow spans, manager-heavy ratios), and produces a redesigned structure with target spans and layers. Produces a span/layer diagnostic plus a proposed org structure and the manager-position delta it implies.

# Steps

1. Load the current roster into a `spreadsheet`: every position with its manager (reporting line), level/title, and individual-contributor vs manager flag. Validate the hierarchy — orphaned reports, circular reporting, or vacant manager seats corrupt every downstream metric, so reconcile these against the source before measuring.
2. Compute the current-state diagnostic: layers from CEO to the front line, average and distribution of span of control per manager, manager-to-IC ratio, and counts of narrow spans (e.g. managers of 1-2) and over-deep branches. Locate the specific nodes driving each problem, not just the averages.
3. Design the target state against explicit span/layer guidelines appropriate to the work type (wider spans for routine/standardized work, narrower for complex/knowledge work). Re-map reporting lines to hit the targets, and quantify the delta: layers removed, manager positions eliminated or added, and which roles change.
4. Report the current-vs-target span/layer comparison, the proposed structure, and the position delta with affected roles named generically (by role, not by person where headcount actions are implied). State the guidelines and assumptions used. Present as a design proposal; any role elimination or RIF is an irreversible action staged for human/HR/legal decision.

# Notes

The output is wrong if the reporting hierarchy is dirty — vacant-manager seats inflate span counts and dotted-line relationships double-count people; clean the roster first. Spans-and-layers targets are not universal: applying a "7-9 reports" rule to complex R&D work produces a bad design — tie targets to work type. Treat headcount/role reductions as proposals only; never present them as decided, and avoid naming individuals when the analysis implies job loss. Not for compensation, capability, or process redesign — this skill addresses structure (who reports to whom), not pay, skills, or workflow.
