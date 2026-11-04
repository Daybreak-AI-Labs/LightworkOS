# Sample data: NDA desk review against a playbook

Synthetic data for the sample company Northwind Fixtures. The
counterparties and clauses are made up. Everything produced from it is
marked as sample data and never counts as real evidence.

Files: `nda_playbook.md` (seven standard positions) and three short mutual
NDAs: `nda_a_harbor_supply.md`, `nda_b_pinecrest_labs.md`,
`nda_c_summit_retail.md`.

A correct result clears NDA A (Harbor Supply Co) as within the playbook,
flags NDA B (Pinecrest Labs) for two deviations (a 7-year confidentiality
term, outside the 2 to 5 year range, and an 18-month non-solicitation
clause, which the playbook does not accept in an NDA), and flags NDA C
(Summit Retail Group) for one deviation (a residual knowledge clause) while
accepting Delaware governing law because the counterparty is in the United
States. It routes the two flagged NDAs to counsel and leaves the review in
Results for a person to sign off.
