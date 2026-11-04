# Model Risk & AI Assurance Officer standalone app

This self-contained defensive app inventories declared models, agents, tools,
datasets, and providers. Its vendored deterministic engine reports operational
risk and gaps across ownership, intended use, legal-applicability review,
evaluation and red-team freshness, change lineage, drift, incidents, and
third-party assurance. It can record local human reviews and time-bounded risk
acceptances, then generate a DGM promotion-readiness **report**.

The standalone is deliberately unsigned and local. It does not discover live
assets, scan provider accounts, change policy, promote a DGM candidate, deploy,
roll back, send messages, open tickets, file reports, or call any external
system. It imports no `maverick` module. Submitted allowlisted metadata is
stored in a private local JSON file protected by a cross-process revision CAS;
the file is neither encrypted nor tamper-evident. Do not enter secrets.

## Decision boundary

Operational risk levels are deterministic triage aids, not legal risk
classifications. EU AI Act role, scope, and applicability default to
`undetermined`. A non-default assertion requires a named human, timestamp,
rationale, and basis version. The engine never converts declared use-case
metadata into an automated legal verdict.

NIST AI RMF 1.0, ISO/IEC 42001:2023, and Regulation (EU) 2024/1689 mappings are
versioned advisory metadata only. NIST AI RMF 1.0 is under revision; ISO/IEC
42001 is an AI management-system standard; and legal implementation timing and
obligations can change. Verify current primary sources and use qualified
reviewers. This product does not perform a conformity assessment or certify
compliance with any framework.

| Capability | Standalone authority | Integrated Lightwork boundary |
| --- | --- | --- |
| Inventory and deterministic findings | Unsigned local declared metadata | Live connectors, continuous inventory, tenant authority |
| Human review and risk acceptance | Unsigned local human attestations | Governed approvals, separation of duties, signed audit |
| Evidence | User-supplied references and freshness calculations | Evidence graph, collection, cryptographic provenance |
| DGM | Readiness report only; no effect endpoint | Governed promotion, canary, rollback, evaluator and artifact lineage |
| Frameworks | Advisory versioned mapping | Governed controls and current mapping lifecycle |

## Run

```bash
python -m pip install -r requirements.txt
bash run_standalone.sh                 # http://127.0.0.1:8896
```

Configuration:

- `MODEL_RISK_OFFICER_STANDALONE=1` documents forced standalone operation.
- `MODEL_RISK_OFFICER_STORE` selects the local JSON record file.
- `MODEL_RISK_OFFICER_PORT` selects the loopback port.

Every mutation requires `application/json` and an exact non-negative
`expected_revision`. The service admits only loopback Hosts and
same-loopback-origin browser writes, streams request bodies through a 768 KiB
cap, rejects secret- and raw-content-shaped field names, disables API docs,
adds restrictive browser headers, caps the local store at 8 MiB / 5,000
records, and serializes commits across processes. Allowed text values are not
secret-scanned.

Key local endpoints:

- `POST /api/assessments` — normalize and assess one declared snapshot.
- `POST /api/assessments/{id}/review` — record a human assurance decision.
- `POST /api/assessments/{id}/risk-acceptances` — record a time-bounded human
  decision without closing the underlying finding.
- `POST /api/dgm/readiness-reports` — create a non-executing readiness report.
- `GET /api/records` and `GET /api/frameworks` — read local records and mapping
  metadata.

There are intentionally no discovery, certification, promotion, deployment,
rollback, connector, filing, policy-mutation, or provider-effect routes.
