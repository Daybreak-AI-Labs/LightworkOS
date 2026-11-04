# Sample data: phishing triage of a small mailbox export

Synthetic data for the sample company Northwind Fixtures. The people,
addresses and domains are made up (all end in `.example`). Everything
produced from it is marked as sample data and never counts as real
evidence.

Files: `mailbox_export.csv` (five reported or sampled messages) and
`known_senders.md` (the company's own domain, its helpdesk address and
approved vendor domains).

A correct result marks two messages as suspicious and clears the other
three. MSG-7002 is a credential phish: it comes from a look-alike domain
(`northwind-fixtures-support.example`, not the company domain), uses a
sign-in link on `login-northwind.example`, and IT never asks staff to sign
in from an email link. MSG-7003 is a payment redirection attempt: the
sender domain `bluharbor-packaging.example` misspells the approved vendor
domain and asks to change bank details by email, which policy forbids. The
result names the recipients to warn (a.rivera and the AP team), proposes
containment steps (block the two domains, remove the messages, reset the
recipient's password if the link was used) and leaves those steps in
Approvals for the on-call person to approve. It does not treat the payroll,
catalogue or internal slides messages as threats.
