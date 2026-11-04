# Billing & collection model

Lightwork meters provider usage and produces rated invoices for the tenants an
operator hosts. The operator's own agreements with those tenants determine fees
and whether metered usage is charged separately. Collection uses the operator's
accounts-receivable process or an operator-configured processor. These billing
primitives do not enforce a particular price or contract term.

## What the product does

- **Metering.** Per-principal, per-day usage (provider dollars + tokens) is
  recorded to a tenant-scoped ledger (`maverick.quotas.UsageLedger`).
- **Rating → invoice.** `maverick billing invoice <tenant> [--since --until]`
  (or `billing.generate_invoice`) rates the ledger through a `RateCard`
  (markup or token pricing, with a minimum charge) into an `Invoice`.
- **Idempotency.** An invoice for a **closed** period (both `--since` and
  `--until` given) carries a deterministic `invoice_id` (`inv_…`, keyed on
  tenant + period + currency, **not** the amount), so re-running billing for that
  period yields the same id for downstream reconciliation. The collector also
  needs a durable receipt and immutable rated contents; the identifier alone
  cannot establish whether an external charge succeeded. An **open-ended** invoice (a missing bound — including the CLI
  default with no `--since/--until`) has an **empty `invoice_id`**: its total
  grows as usage accrues, so it is deliberately *not* a safe dedup key. Always
  bill closed periods.
- **Per-tenant spend caps.** `maverick tenant quota <id> <usd/day>` enforces a
  daily ceiling at the channel door (a tenant over its cap is refused), and
  per-tenant plans gate features (`maverick billing entitlements <id>`).
- **Operator statement (`/billing`).** The dashboard's billing view shows the
  active tenant's accrued charges for the current period, a period-over-period
  spend trend, and a one-click **itemized CSV invoice**
  (`/billing?format=csv&period=YYYY-MM`) for reconciliation against contracts.
  This is the visual statement built from priced runs; the rated, idempotent
  `Invoice` above (`maverick billing invoice`) remains the source of truth for
  AR/ERP export.
- **Quick FinOps export (`maverick spend`).** For a scriptable pull without the
  dashboard, `maverick spend` (`--json`) prints total, top-goals-by-cost, and a
  per-tag split (`--tag-field` for team/project/cost-center) — the CLI face of
  the `/spend` page, for BI and chargeback pipelines.

## How money is actually collected

Pick one:

1. **Contract + AR (default).** Invoice on your finance system's cadence. Use
   `maverick billing invoice --json` to export the rated line items (and
   `invoice_id`) into your AR/ERP.
2. **Bring your own processor.** If you want programmatic collection (e.g. usage
   billing inside a contract), push the exported invoice to your processor keyed
   on `invoice_id` for idempotency. The bundled Stripe tool
   (`maverick.tools.stripe_tool`) is **read-mostly by design** — it answers
   account questions and (env-gated) refunds, and deliberately does **not** let
   an agent create charges. Charge-creation is an operator/finance action, not an
   agent capability.

## Operator Stripe collection

The collection adapter accepts only an explicitly bounded period ending before
the current UTC day. Rating a current/open period is useful for a statement;
it is not a collectible final invoice. Repeated collection of a closed period
uses a private tenant receipt, freezes the rated content, and returns already
acknowledged item results without creating them again. Changed contents for
the same period require reconciliation rather than a second automatic charge.
A tenant-wide collection fence also rejects overlapping periods and changing
the currency to collect the same usage again. Concurrent collectors cannot
reserve conflicting periods independently.

Minimum charges appear as an explicit adjustment line, so itemized charges
reconcile with the invoice total. Currency-specific integer units and rounded
line allocations preserve that total instead of rounding every line in
isolation. Review the invoice currency and rate card before collection.

A timeout after dispatch is uncertain. The collector retains that state and
uses the same provider idempotency key only within its conservative 23-hour
retry window. Beyond that window it stops for operator reconciliation with
Stripe. Do not delete the receipt or use a new invoice identity to force a
retry. Historical collections made before these receipts existed also require
reconciliation; the collector does not retroactively discover old charges.

Subscription lookup excludes terminal subscriptions, refuses ambiguous or
unresolved current subscriptions, and preserves a pending cancellation. It
does not reactivate a subscription simply because its old price matches.
