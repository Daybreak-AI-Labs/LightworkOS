# GRC Concierge standalone demo

This reduced standalone app runs without Lightwork. It includes original-paraphrase starter
screens for SOC 2, ISO/IEC 27001:2022, and NIST CSF 2.0; deterministic scoring;
quoted evidence verdicts; accessible guided assessment, evidence, risk, and
POA&M forms; bounded vendor posture carry-forward; a local mock tenant review
queue; observed workflow timing; and a revision-checked local JSON store.
It does **not** claim a complete licensed standards catalog, tamper-evident audit,
governed approval, connector coverage, or cross-run learning. Those are platform
capabilities at `/security`.

| Runtime situation | Analysis backend | Record and governance authority |
| --- | --- | --- |
| `GRC_STANDALONE=1` | Vendored catalog and scorer; no `maverick` import | Unsigned local demo store |
| Auto mode, core absent | Vendored catalog and scorer | Unsigned local demo store |
| Auto mode, core importable | `maverick.assessment` analysis adapter | Unsigned local demo store; **not** integrated governance |

The standalone requirements intentionally do not install `maverick`. Core
analysis availability changes only questionnaire declarations and scoring; it
does not turn this demo into the governed `/security` product.

```bash
python -m pip install -r requirements.txt
bash run_standalone.sh                 # http://127.0.0.1:8891
```

The authority boundary is deliberately local-only. In auto mode, when
`maverick.assessment` is importable, the app reuses Lightwork's built-in
security questionnaires and scoring algorithm. It still does **not** call
Lightwork persistence, audit, connectors, or governed approvals. Set
`GRC_STANDALONE=1` to force the useful three-framework reduced engine,
`GRC_STORE` to choose the local JSON file, and `GRC_PORT` to change the port.
Use Lightwork's `/security` workspace for governed Security Ops records.
Mutating JSON requests require an exact non-negative `expected_revision`; the
local store serializes compare-and-swap commits across processes. The server
accepts JSON only on a loopback Host, rejects cross-origin browser writes, and
streams request bodies through a 512 KiB cap before parsing.

The guided workflow can prepare a local mock review-handoff receipt labeled for
one of three generic destinations (GRC platform A, B or C), then let a human
approve or reject it in the app's local mock tenant queue. It never contacts a
GRC product, never claims delivery, and never records a Lightwork approval. The decision is only a
local demonstration; real import and approval remain external/manual. The speed
story reports observed local elapsed seconds from source save to packet and from
packet to review, not projected savings or external-system timings. Vendor
carry-forward records field-level provenance and must never be treated as fresh
evidence. The workflow has no chat-model or voice dependency.

See the [integrated Security & GRC capability and authority matrix](../../docs/SECURITY_GRC.md)
for the platform bundle, human-approval boundary, and framework-content caveat.
