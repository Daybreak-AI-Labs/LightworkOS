# Sample data: accounts payable three-way match

Synthetic data for the sample company Northwind Fixtures. Nothing here is
real: the vendors, invoices, amounts and account references are made up.
Everything produced from it is marked as sample data and never counts as
real evidence.

Files: `invoices.csv` (six invoices), `purchase_orders.csv` (five POs),
`receipts.csv` (five goods receipts), `vendor_master.csv` (four approved
vendors).

A correct result flags exactly three exceptions and clears the other three
invoices: it flags INV-1043 as a duplicate of INV-1041 (same vendor, PO,
amount and description two days apart); it flags INV-1044 as a price
mismatch (invoiced 2,100.00 against PO-2203 for 1,900.00, a 200.00
difference on 20 chairs); and it flags INV-1045 from Sunrise Facility
Services as a vendor that is not on the vendor master. It does not stage,
release or pay anything; the exception list waits in Results for a person
to review.
