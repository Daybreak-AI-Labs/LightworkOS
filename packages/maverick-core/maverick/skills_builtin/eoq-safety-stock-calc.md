---
name: eoq-safety-stock-calc
triggers:
  - calculate eoq
  - set safety stock and reorder points
  - how much should we order
tools_needed:
  - spreadsheet
---
# What this skill does

Computes economic order quantity (EOQ), safety stock, and reorder points for a
set of SKUs from demand, cost, and lead-time inputs. Output is a per-SKU table
of order quantity, safety-stock buffer, and reorder point at a chosen service
level, ready for a planner to load into the replenishment system.

# Steps

1. Gather inputs per SKU into the `spreadsheet`: annual demand D, ordering/setup
   cost S, unit holding cost H (or holding rate x unit cost), average lead time
   L, demand stddev over lead time, and target service level. Flag any SKU
   missing an input — do not default silently.
2. EOQ = sqrt(2 D S / H). Compute it; note that EOQ assumes stable demand and
   fixed costs — mark SKUs where those assumptions are weak (lumpy/seasonal).
3. Safety stock = Z x sigma_LT, where Z is the service-level factor (e.g. 1.65
   for 95%, 2.33 for 99%) and sigma_LT is demand variability over lead time
   (scale period sigma by sqrt(L) if lead time spans multiple periods). State
   the Z and the service level used.
4. Reorder point = (avg demand during lead time) + safety stock. Assemble the
   per-SKU table (EOQ, safety stock, ROP) in `spreadsheet`; report it with the
   service level, units, and assumptions; hand off for a planner to validate
   against MOQ/pack-size and load.

# Notes

Wrong if D, S, and H are in mismatched units (the classic EOQ blunder), if lead
time and demand periods don't align, or if supplier MOQ/pack rounding is ignored
(round EOQ to orderable quantities and say so). Safety stock from a normal
assumption understates buffers for erratic (XYZ "Z") demand — flag those for a
different model. Numbers are recommendations; a planner reconciles them with
contracts, shelf life, and capital limits before committing orders.
