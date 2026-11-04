# Sample data: overdue purchase order chase list

Synthetic data for the sample company Northwind Fixtures. The suppliers,
orders and dates are made up. Today's date for this sample is 2026-09-24.
Everything produced from it is marked as sample data and never counts as
real evidence.

Files: `open_purchase_orders.csv` (five open POs with promised dates,
acknowledgement, delivery status and days of stock on hand) and
`supplier_contacts.csv` (who buys from each supplier and how to reach them).

A correct result names exactly two overdue orders and ranks them by
stockout risk: PO-2305 (Granite Ridge Fasteners, promised 2026-09-12, not
delivered, 3 days of stock left) first, then PO-2302 (Blue Harbor
Packaging, promised 2026-09-17, not delivered, 4 days of stock left). It
also notes that PO-2303 (Quickline Logistics) is not yet overdue but has
never been acknowledged and should be confirmed by phone. It does not chase
PO-2301 (delivered) or PO-2304 (in transit, not due). The chase list, with
the right buyer and contact for each, waits in Results for the buyer to
review before anything is sent.
