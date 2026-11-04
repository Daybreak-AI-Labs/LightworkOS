# Requests for comments (RFCs)

An RFC is a short design document for a significant change. It gives the
community a place to discuss a proposal before code is written, and it leaves
a record of what was decided and why.

## When an RFC is needed

Write an RFC when a change:

- adds, changes or removes a public API, such as the plugin API, the REST or
  gRPC API, the MCP tools or the CLI;
- changes configuration, data formats or storage in a way users must act on;
- adds a package or a new top-level dependency;
- changes how the project is run, released or governed.

Bug fixes, documentation, tests and small, backwards-compatible features do not
need an RFC; open an issue or a pull request instead. If you are unsure, open
an issue and ask.

## How to propose an RFC

1. Optionally, open an issue or a discussion to test the idea first.
2. Copy the outline below into a new file named `docs/rfcs/NNNN-short-title.md`,
   where `NNNN` is the next unused four-digit number.
3. Open a pull request that adds the file, with a title such as
   `docs: add RFC NNNN for <topic>`. Set the status to **Draft**.
4. Discussion happens on the pull request. Update the RFC as the design
   changes.

An RFC should cover:

- **Summary**: one paragraph.
- **Motivation**: the problem and who has it.
- **Design**: the proposed change, in enough detail to review and implement.
- **Compatibility**: what breaks, and the migration path.
- **Alternatives**: other approaches and why they were not chosen.
- **Open questions**: what is still undecided.

## Review and acceptance

The maintainers review the RFC on its pull request. When the discussion has
settled, a maintainer records the decision in the RFC's status line and merges
the pull request, so that accepted and declined RFCs both stay on record. If
the maintainers cannot reach consensus, the lead maintainer decides, as
described in [GOVERNANCE.md](../../GOVERNANCE.md).

Implementation can start once an RFC is accepted. Pull requests that implement
an RFC link to it.

## Statuses

| Status | Meaning |
| --- | --- |
| Draft | Open for discussion; the design may still change. |
| Accepted | Approved for implementation. |
| Implemented | Shipped; the design moves to [`docs/contracts/`](../contracts/README.md) as a contract document. |
| Declined | Considered and not adopted. |
| Closed | Not pursued; the RFC records why and when to reopen it. |
| Superseded | Replaced by a later RFC, which the status line names. |

Each RFC states its status at the top of the file.

## Index

No RFC is open. Implemented designs are kept as
[interface contracts](../contracts/README.md).

A new RFC takes the next unused number.
