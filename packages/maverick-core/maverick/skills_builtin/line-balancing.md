---
name: line-balancing
triggers:
  - line balancing
  - takt time
  - assembly balance
tools_needed:
  - spreadsheet
---
# What this skill does

Balances a production or assembly line by computing takt time, assigning tasks to workstations within takt and precedence constraints, and exposing the bottleneck and line efficiency. Produces a line-balance plan (takt, station task loads, cycle time, bottleneck, efficiency) that an industrial/process engineer reviews before changing the physical line.

# Steps

1. Load the real inputs into the spreadsheet: the task list with measured task times, the precedence graph (which tasks must precede which), available working time per period, and required output (demand) per period. Do not estimate task times if measured ones exist — flag any estimated time as unverified.
2. Compute takt time = available working time / required output. This is the pace the line must meet; confirm the time unit is consistent across takt, task times, and availability.
3. Compute the theoretical minimum stations = ceil(sum of task times / takt), then assign tasks to stations respecting precedence and keeping each station's load <= takt (a heuristic such as longest-task-time or ranked-positional-weight is acceptable — name the heuristic used). Record each station's total load.
4. Report station cycle time (max station load), identify the bottleneck station, and compute line efficiency = sum of task times / (number of stations * cycle time). Hand off the assignment table and recommend rebalancing or task splitting where a station exceeds takt; state the heuristic and any estimated task times.

# Notes

Wrong if cycle time (max station load) exceeds takt — the line cannot meet demand and must be rebalanced or have stations added; if precedence is violated the assignment is infeasible. Mismatched time units between takt and task times silently corrupt the balance. Heuristic assignment is near-optimal, not provably optimal — say so. The plan is a recommendation: physically moving tasks, retraining operators, or adding stations is disruptive and must be approved by an engineer. Do not use for mixed-model lines without first deriving a weighted task time per model.
