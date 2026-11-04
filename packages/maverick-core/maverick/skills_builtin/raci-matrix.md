---
name: raci-matrix
triggers:
  - build a RACI matrix for this project
  - who is accountable for what
  - map responsibilities across the team
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a RACI responsibility matrix mapping each project activity to roles as Responsible, Accountable, Consulted, or Informed. Produces a structured grid (activities x roles) that surfaces gaps and overlaps in ownership before work starts.

# Steps

1. Gather the concrete list of activities/deliverables and the list of roles (titles or names) from the requester. Do not infer activities the requester did not state.
2. In `spreadsheet`, lay out activities as rows and roles as columns; populate each cell with R, A, C, or I (blank = no involvement).
3. Validate the matrix: exactly one A per activity row; at least one R per row; flag any row with zero A, multiple A, or no R as an error to resolve.
4. Hand off the grid with a short list of detected gaps/overlaps, stating the assignments are a draft for the activity owner to confirm.

# Notes

Output is wrong if any activity has two Accountable roles, none, or no Responsible role — those are the failure modes the validation step exists to catch. Over-tagging Consulted/Informed dilutes the matrix; keep them sparse. This skill recommends an allocation; the accountable lead ratifies it. Not for org-chart design or for fluid work with no discrete activities.
