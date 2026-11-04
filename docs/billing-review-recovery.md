# Reviewed billing and retained recovery

The billing page prepares an encrypted, ten-minute review of the normalized
workspace, period, rate inputs, plan, provider connection fingerprint and exact
rated invoice. Preview reads local state and makes no provider request. Editing
the form invalidates its review. Dispatch checks the current settings again and
uses the frozen invoice, including its original identity and native collection
guards.

Each workspace has a compare-and-swap admission record. Customer, subscription
and usage stages keep pending/confirmed/unknown receipts; each provider mutation
has a durable, audited pending receipt before dispatch. Concurrent submissions
cannot acquire the same claim. A completed submission returns its existing
receipt. Losing a response never produces a claim that nothing changed.

The page can read retained receipts after a timeout or reload. An explicit
re-review can resume the same unresolved attempt and its frozen invoice.
Confirmed stages are preserved. Provider calls retain the existing idempotency
keys and invoice-period overlap protection; changed request parameters and old
uncertain create requests outside the conservative 23-hour retry window are held.
No paid operation is automatically retried by the page.

When a provider outcome cannot be established, the receipt links to Stripe for
reconciliation and continues to show uncertainty. It does not offer a new invoice
identity as a workaround. The original account and workspace context must inspect
an unresolved attempt. An account departure requiring transfer of this financial
authority is not implemented by changing the receipt's actor.

The store uses the existing governed-record backend contract, including its
multi-replica restrictions and audit outbox. It retains up to 500 compact completed
receipts and 5,000 provider dispatch entries per current attempt, then refuses new
dispatch until governed archival is arranged. Native collection receipts remain
immutable, and recovery modifies no credentials or billing settings.

Live Stripe behavior, distributed failures and browser recovery are not
qualified.
