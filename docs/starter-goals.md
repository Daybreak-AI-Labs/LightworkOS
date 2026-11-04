# Starter goals

Eight first tasks, one per business team. Each runs a real specialist on
bundled sample data for a made-up company (Northwind Fixtures) and hands
the result to you for review. Nothing is paid, sent, provisioned or changed
without your sign-off.

Everything a sample task produces is marked as sample data and never counts
as real evidence.

## How to run one

- **Setup wizard:** the last question in `maverick init` asks which team
  will try Lightwork first. The wizard creates the team's sample workspace
  under your work folder (`sample-outcomes/<team>/`) and prints the command
  to run.
- **Dashboard:** open Get started and use "Run your first task on sample
  data". Pick the team and click Run. If no AI service is connected yet, the
  button reads "Connect an AI service first" and opens Settings.
- **Command line:** copy the command under the team below. It places the
  sample files in your work folder and gives the run the same brief,
  specialist and sample marking as the dashboard. No `--model` flag is
  needed; the specialist and your configured models decide.

The sample files live in the installed package under
`maverick/sample_outcomes/<team>/`. Each folder has a `README.md` that says
what a correct result contains, so you can check the answer yourself.

---

## 1. Finance: accounts payable three-way match

Specialist: `proc_p2p_exceptions` (the three-way match exception clerk).
Result waits in **Results**; nothing is staged or paid.

```
maverick start --sample finance
```

Sample data: six invoices, five purchase orders, five goods receipts and a
vendor master. A correct result flags INV-1043 as a duplicate of INV-1041,
INV-1044 as a price mismatch against PO-2203, and INV-1045 (Sunrise Facility
Services) as a vendor not on the master, and clears the other three.

## 2. Privacy & compliance: a rights request against the data map

Specialist: `data_pii_scan` (the personal-data inventory specialist).
Result waits in **Results**.

```
maverick start --sample privacy
```

Sample data: a five-row data map and one customer access-and-objection
request. A correct result names the three systems holding the customer's
data, excludes payroll, lists the recipients to disclose, treats the
newsletter removal as a consent withdrawal, and states the one-month
deadline.

## 3. Security: phishing triage

Specialist: `itgrc_incident_response`. Result waits in **Approvals**
(containment steps need the on-call person's approval).

```
maverick start --sample security
```

Sample data: a five-message mailbox export and the company's known sender
list. A correct result marks MSG-7002 (look-alike helpdesk domain with a
sign-in link) and MSG-7003 (misspelled vendor domain asking to change bank
details) as suspicious and clears the rest.

## 4. Legal: NDA desk

Specialist: `legal_nda_desk`. Result waits in **Results**.

```
maverick start --sample legal
```

Sample data: a seven-point playbook and three short NDAs. A correct result
clears Harbor Supply Co, flags Pinecrest Labs (7-year term and a
non-solicitation clause) and flags Summit Retail Group (residual knowledge
clause) while accepting its Delaware governing law.

## 5. HR: new-hire onboarding plan

Specialist: `hr_onboarding`. Result waits in **Results**.

```
maverick start --sample hr
```

Sample data: one new-hire record and the day-one checklist. A correct
result lists the standard and warehouse-specific items, confirms payroll
can be enrolled, flags the missing emergency contact form, and leaves out
the forklift check.

## 6. Procurement: overdue purchase orders

Specialist: `proc_po_chaser`. Result waits in **Results**.

```
maverick start --sample procurement
```

Sample data: five open POs and a supplier contact list (today is
2026-09-24 in the sample). A correct result names PO-2305 and PO-2302 as
overdue, ranks PO-2305 first (3 days of stock), and notes PO-2303 has never
been acknowledged.

## 7. Customer support: ticket insights

Specialist: `cx_ticket_insights`. Result waits in **Results**.

```
maverick start --sample customer_support
```

Sample data: twelve September tickets. A correct result names delivery as
the largest driver (six tickets), shows all four open tickets are email
delivery tickets with slow first responses, and flags label printers as a
smaller recurring theme.

## 8. Tax: notice response

Specialist: `tax_irs_notice`. Result waits in **Results**.

```
maverick start --sample tax
```

Sample data: a mock notice proposing a 22,500.00 income adjustment and the
preparer's workpaper summary. A correct result ties the difference to
18,300.00 of refunds and 4,200.00 of sales tax, concludes no additional tax
is owed, and drafts the response for the preparer to sign.

---

## Adding your own

Submit starter goals as a PR to `maverick/sample_outcomes/` and this file.
Criteria:

- One team, one specialist that already exists, one concrete question a
  business user would ask.
- Small, clearly made-up sample data (a few KB), with a `README.md` that
  says what a correct result contains.
- Safe by default: the result waits for a person in Approvals or Results.
