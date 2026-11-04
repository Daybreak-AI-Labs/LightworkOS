# Sample data: ticket insights for a support manager

Synthetic data for the sample company Northwind Fixtures. The tickets and
customers are made up. Everything produced from it is marked as sample data
and never counts as real evidence.

File: `tickets.csv` (twelve tickets from 1 to 19 September 2026 with
channel, category, product, priority, first response time and resolution).

A correct result identifies delivery as the largest driver (six of twelve
tickets, all about shelving or cartons), notes that every unresolved ticket
(T-9005, T-9007, T-9009, T-9011) is a delivery ticket that came in by
email, shows that email first response times (45 to 360 minutes) are far
slower than chat and phone (5 to 15 minutes) and are getting worse through
the month, and flags label printer issues as a smaller recurring product
theme (three tickets). The staffing signal is that email delivery tickets
need more coverage in the second half of the month. The summary waits in
Results for the support manager to review; it states each count so the
manager can check it against the file.
