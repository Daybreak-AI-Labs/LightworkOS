# Security & GRC

Lightwork packages one defensive Security & GRC suite in five deployment
shapes: the integrated platform and four reduced standalone products. The
platform combines control-program records, evidence-backed deterministic
engines, human approval, connected telemetry, and the signed audit chain. The
standalone products keep useful local engines while making the missing platform
guarantees explicit on each product's `/about` page.

!!! important "Readiness tooling, not certification or legal advice"

    Lightwork does not certify an organization, issue an audit opinion, replace
    a qualified assessor, or determine a legal notification obligation. A
    framework score is a readiness signal over supplied answers and evidence.
    Framework names and identifiers provide mapping context; the product does
    not bundle licensed standards text. Obtain the applicable official standard
    and qualified professional advice for the engagement and jurisdiction.

## Enable the integrated suite

The installer wizard writes these conservative defaults:

```toml
[security_ops]
enable = true

[evidence_graph]
enable = false

[model_risk_assurance]
enable = false
gate_promotions = false

[evidence_gateway]
enable = false

[threat_hunt]
enable = false

[env_hunt]
enable = false
response_execution = false
poll_seconds = 300

# Optional, one explicit table per trusted startup-registered provider, named
# as the provider registered itself ("example_intel" is only an example). Also
# Settings > All settings > Security suite > Lookup services.
[env_hunt.enrichment_sources.example_intel]
enable = false

[env_hunt.connectors.cloudtrail]
enable = false
push_enable = false
pivot_enable = false
[env_hunt.connectors.guardduty]
enable = false
push_enable = false
pivot_enable = false
[env_hunt.connectors.syslog]
enable = false
push_enable = false
pivot_enable = false
[env_hunt.connectors.edr]
enable = false
push_enable = false
pivot_enable = false
[env_hunt.connectors.splunk]
enable = false
push_enable = false
pivot_enable = false
[env_hunt.connectors.elastic]
enable = false
push_enable = false
pivot_enable = false
[env_hunt.connectors.sentinel]
enable = false
push_enable = false
pivot_enable = false
[env_hunt.connectors.kubernetes_audit]
enable = false
push_enable = false
pivot_enable = false
[env_hunt.connectors.okta]
enable = false
push_enable = false
pivot_enable = false
[env_hunt.connectors.entra]
enable = false
push_enable = false
pivot_enable = false
```

Security & GRC records default on. Both hunters default off because they consume
operational telemetry. Environment response execution is a second, independent
opt-in and remains off even when environment hunting is enabled. Every named
environment connector has three independent, off-by-default knobs: ``enable``
for a trusted read transport, ``push_enable`` for caller-supplied REST batches,
and ``pivot_enable`` for bounded related-event follow-up queries. Enabling pull
access never silently enables push or pivots. A connector tool is available only
when the environment hunter, that connector's ``enable`` knob, and a trusted
startup-injected read-only transport are all present. The dashboard surfaces are:

- `/security` — Security & GRC control-program workspace
- `/security/assurance` — AI evidence gateway and Model Risk assurance cockpit
- `/security/report` — print-friendly readiness and board report
- `/security/threats` — threats inside Lightwork and its agent activity
- `/security/soc` — customer-environment findings, investigations, and response
  proposals

Dashboard access uses the existing permission model. Record bodies and the
workspace require `operate`; read summaries use `view`; configuration and other
administrative mutations use `admin`. Mutations use revision compare-and-swap,
so stale clients receive a conflict instead of silently overwriting a newer
record.

The evidence gateway's signed packet is issued by an admin-only, rate-limited
`POST` because issuance appends an attestation; it is not a state-changing
download `GET`.

The configuration endpoint itself is revision-CAS guarded. Clients read the
current ``revision`` from ``GET /api/v1/security/config`` and submit it as
``expected_revision`` on ``PUT``. Turning either hunter on starts the dashboard's
lease-coordinated scheduler; it stops only when both hunters are off. Direct
out-of-band TOML edits remain an operator action outside that dashboard CAS.

## Security & GRC program

The integrated `maverick.security_ops` data plane and the shared assessment
engine cover:

- Security questionnaires for SOC 2, ISO/IEC 27001:2022, NIST CSF 2.0,
  NIST SP 800-53 Rev. 5, CIS Controls v8, PCI DSS 4.0, the HIPAA Security Rule,
  CMMC 2.0 Level 2, and FedRAMP Rev. 5 Class C readiness (the 2026
  transition mapping for legacy Moderate authorizations). The pinned granular
  catalogs include 106 CSF subcategories, 287 NIST 800-53 Moderate controls and
  enhancements, 153 CIS safeguard identifiers with minimum IG assignments,
  110 CMMC L2 practices, and 322 current FedRAMP Class C selections.
- A control register / statement of applicability with a required nonblank owner, applicability,
  implementation status, and cross-framework mappings.
- Evidence review from supplied text and supported documents, including
  least-privilege Microsoft Graph, Slack, or Google Drive connections already
  configured through the shared document-discovery boundary. A verdict is
  deterministic (`present`, `partial`, or `missing`) and quotes the matched
  evidence. Extracted document text is untrusted input and remains review-gated.
- Risk records with likelihood × impact, treatment, residual risk, accountable
  owner, and expiring exceptions or waivers.
- Plans of action and milestones (POA&M), vendor assessments, policy lifecycle
  and attestation, security incidents with chronological containment,
  eradication, and recovery workpapers, and audit engagements.
- Aggregate program insights: framework coverage, control posture, open and
  aging POA&M work, expiring exceptions, crosswalk reuse, and readiness output.

The tenant-scoped JSON stores are `security_controls`, `security_evidence`,
`security_risks`, `security_poam`, `security_vendors`, `security_policies`,
`security_incidents`, `security_audits`, and `security_clock_packs`. Their public
record labels are `control`, `evidence`, `risk`, `poam`, `vendor`, `policy`,
`incident`, `audit_engagement`, and `regulatory_clock`. `program_report()`,
`readiness_report()`, and `render_board_report()` provide aggregate and
print-oriented output without changing source records.

Questionnaire answers use the existing `yes` / `no` / `na` / `unknown`
vocabulary and the same inherent-versus-residual risk rollup as other Lightwork
assessments. An `unknown` remains visible; it is not converted into evidence of
control effectiveness.

### Framework content boundary

The built-ins are implementation-oriented readiness questionnaires with
originally written control prompts and remediation guidance. They are not a
substitute for the official publications, licensed standard text, an auditor's
testing procedure, or a certification body. Customer-provided licensed content
can be represented through the governed template/catalog mechanisms without
changing this documentation claim.

CIS safeguard titles and text are intentionally not redistributed. The built-in
CIS catalog contains factual safeguard identifiers, minimum IG assignments, and
neutral evidence prompts only. CIS publishes its material under CC BY-NC-ND 4.0
and states that commercial use requires prior approval, so a commercial
CIS-branded assessment still requires an authorized CIS copy and legal review.
The source artifact, version, selection rule, digest, and license note for every
expanded catalog are pinned in `maverick.security_framework_catalog`.

## Platform threat hunter

`maverick.platform_hunt` defensively scans Lightwork's own normalized telemetry.
The verified Ed25519 audit chain is the production verdict source. Mutable
WorldModel approval, goal, episode, and event rows cannot become finding evidence
merely because they were supplied beside an intact chain; they are ignored by
production rule evaluation unless a future adapter proves an exact commitment to
a signed row. Budget findings use the separately HMAC-signed, hash-chained
`budget_receipts.jsonl` ledger because it commits both actual spend and cap
context; mutable `EpisodeSpend` snapshots do not contain the cap and are not
budget authority. Raw source rows remain with their owners and exist in
normalized form only for the scan.

The engine is deterministic and contains no model decision path. Rules cover
shield-bypass markers, prompt injection, novel tool use, suspicious approval or
privilege patterns, exfiltration-shaped sequences, unsanctioned
self-modification, budget/rate anomalies, operator anomalies, quorum abuse, and
goal anomalies. Behavioral baselines are deterministic per actor/tool/location;
operator-time anomalies use that operator's learned privileged-action hour
histogram rather than a universal daytime rule.
Every finding carries:

- a stable rule and finding identifier;
- severity, score, verdict, and MITRE ATT&CK technique tags;
- one or more exact event references, normalized-event SHA-256 commitments, and
  bounded evidence quotes; and
- suggested containment, which is a proposal rather than an execution method.

`verify_audit_chain()` verifies every selected day file and the directory's
cross-file anchor ledger, including anchored-day deletion. When verification
fails, the scan emits only the critical integrity finding rather than deriving
additional verdicts from untrusted rows. Safe results contain basenames, not
local absolute paths. `HuntStore` keeps findings and investigations with
revision CAS, hashed actor labels, and a durable audit outbox. The hunter does
not autonomously contain production activity. A model may later narrate a
finding, but it cannot create, suppress, or relabel the deterministic verdict.

The dashboard lifespan starts a scheduler only when a hunter is enabled and
stops it during shutdown. A private SQLite lease allows one bounded turn per
platform deployment and connector even with multiple dashboard workers. The
minimum poll interval is 30 seconds. A core-only or standalone host must invoke
its own lifecycle and may reuse the exposed connector-tool registry; importing
the detector alone does not create a background thread.

## Environment threat hunter

`maverick.env_hunt` is the customer-environment SOC surface. Read-only adapters
normalize customer telemetry; deterministic rules and imported Sigma content
produce exact-event-citing findings; investigations build a timeline and propose
defensive response playbooks. Raw telemetry stays ephemeral in the detection
path. Persisted records are derived findings, investigations, proposals, and
receipts rather than a second raw-log archive.

`ConnectorRegistry` ships read-only normalizers for `CloudTrailConnector`,
`GuardDutyConnector`, `SyslogConnector`, `EDRConnector`, `SplunkConnector`,
`ElasticConnector`, `SentinelConnector`, `KubernetesAuditConnector`,
`OktaConnector`, and `EntraConnector`. A `QueryRequest` is time- and result-
bounded and rejects non-read-only operations. Connector credentials remain in
the normal Lightwork secret/configuration boundary and must be scoped read-only
for ingestion. Connector implementations must never include the credential in
evidence, logs, findings, or error text; `credential_fingerprint()` provides an
opaque diagnostic identifier instead.

Normalized source names are `aws.cloudtrail`, `aws.guardduty`, `host.syslog`,
`edr.<vendor>`, `siem.<vendor>`, `kubernetes.audit`, `identity.okta`, and
`identity.entra`. Customer Sigma content enters through `load_sigma_texts()`;
the REST-safe import boundary accepts text rather than server paths, limits each
document to 1 MiB, caps a request at 32 rules, and rejects duplicate rule IDs.
The SOC dashboard exposes this import boundary and renders a deterministic
ATT&CK technique heatmap from stored finding counts.

### Connector extension seam

New client systems plug into the environment hunter through its adapter registry:

1. Implement a read-only adapter that yields the normalized event contract.
2. Give each source event a stable source identifier and timestamp; retain the
   original record in the customer's source system.
3. Register the adapter under a unique source name and add an explicit config
   knob and installer path for credentials or source selection.
4. Add synthetic contract fixtures that prove normalization, exact evidence
   citation, least-privilege behavior, and secret redaction.
5. Keep vendor-specific querying at the adapter edge. Detection and
   investigation logic consume only normalized events.

Integrated hosts register credential-owning pull closures with
`register_environment_connector_transport()` during trusted startup; request
bodies can select only already-registered, configured adapters. A finding may
perform one related-event pivot through the same transport only when
`pivot_enable` is true. That pivot is capped at 1,000 events, carries only
bounded cited principals/targets, and uses the reserved
`lightwork:related-events-v1` query contract. Enrichment providers are likewise
registered at trusted startup and invoked only when their name is explicitly
enabled under `[env_hunt.enrichment_sources.<name>]`. Only allowlisted scalar
fields are persisted, and each lookup must first land an accepted audit event.

Mutating response connectors use the separate `ResponseExecutorRegistry`; they
must not be registered as read-only ingestion adapters. Each implementation
must support only its declared defensive allowlist and return a proposal- and
approval-bound receipt.

The integrated REST JSON batch path additionally requires that connector's
`push_enable = true`. The Environment Hunter standalone product's generic JSON
ingestion is the
compatibility floor when a requested system does not yet have a named platform
adapter. It permits a customer-side collector or broker to push normalized
events without granting Lightwork broad access to the source.

When Shield is installed, normalized telemetry and imported Sigma content are
screened before detection. The kernel still supports deployments without Shield;
the hunter then fails open only for deterministic local detection and advertises
`reduced_autonomy`. Related-event pivots, enrichment, automatic playbook
proposals, and response execution are suppressed until Shield is available.

### Response execution is explicitly opt-in

With `[env_hunt] response_execution = false`, every response stops at a proposal.
Enabling it does not create blanket autonomy: `execute_response()` also requires
a `GovernedApproval` bound to the exact proposal ID, digest, executor, queue
approval ID, and queue decider. `response_approval_request()` must be created
*after* the queue decision with those exact values; its Ed25519 signature cannot
be replayed across a replacement approval row or changed decision identity. A
narrowly scoped `ResponseExecutor` must return a receipt bound to both the
proposal and approval. The `ResponseExecutorRegistry` is empty by default: Lightwork
ships no generic mutating executor, and a deployment must explicitly register a
client-specific implementation. Before calling that executor, the store commits
a durable one-shot claim keyed by proposal and exact authorization. Completion
commits the bounded receipt and audit outbox atomically. If the adapter or final
commit fails after the claim, the record becomes `ambiguous` and every retry is
refused pending operator reconciliation. This prevents a timed-out external
action from being performed twice. The expected production flow is:

```text
finding → investigation → response proposal → human approval → connector action → receipt
```

Approving one scoped action does not grant a reusable standing approval. Failed,
expired, missing, or mismatched authorization must fail closed. Deployments can
keep environment hunting enabled permanently while leaving response execution
disabled.

## One platform, four standalone products

| Capability | Integrated platform | GRC Concierge | Platform Hunter | Environment Hunter | Model Risk Officer |
|---|---:|---:|---:|---:|---:|
| Deterministic local analysis | Yes | Yes | Yes | Yes | Yes |
| Cited evidence | Yes | Yes | Yes | Yes | User-supplied references |
| Raw hunter telemetry retained by product | No | N/A | No | No | N/A |
| Local derived-record store | Yes | Yes, unsigned | Yes, unsigned | Yes, unsigned | Yes, unsigned |
| Full framework catalog and crosswalk | Yes | No | N/A | N/A | Advisory mapping only |
| Managed enterprise connectors | Yes | No | No | No | No |
| Signed tamper-evident audit | Yes | No | No | No | No |
| Governed platform approval | Yes | No | No | No | No |
| Cross-run learning / fleet context | When enabled | No | No | No | No |
| External effects | Approval-bound opt-ins only | None | None | Proposal-only | None; readiness report only |

Both standalone hunters are proposal-only and have no response-execution
method. Governed execution is available only in the integrated platform, where
it additionally requires explicit deployment opt-in, an exact proposal-bound
human approval, and a client-registered narrow executor. These distinctions are
product boundaries, not only UI labels.

### Run the standalone products

```bash
cd demo/grc-concierge && bash run_standalone.sh
cd demo/platform-threat-hunter && bash run_standalone.sh
cd demo/environment-threat-hunter && bash run_standalone.sh
cd demo/model-risk-ai-assurance-officer && bash run_standalone.sh
```

The launchers force `GRC_STANDALONE=1`, `PLATFORM_HUNTER_STANDALONE=1`, and
`ENV_HUNTER_STANDALONE=1`, respectively. GRC Concierge is deliberately
local-only; the two hunter backends can use a compatible installed analysis
engine but keep the standalone storage and authority boundaries. Their backend
seams bind application behavior; route handlers and templates do not silently
claim integrated-platform governance. The Model Risk standalone forces
`MODEL_RISK_OFFICER_STANDALONE=1`; it can produce a readiness report but has no
promotion, deployment, rollback, discovery, or provider-effect route. See
[`MODEL_RISK_ASSURANCE.md`](./MODEL_RISK_ASSURANCE.md) for the integrated DGM
gate and assurance boundaries.

## Regulatory clocks and jurisdiction

Security incident records may calculate operational reminders for rules such as
the SEC four-business-day material-cybersecurity disclosure window and selected
breach-notification regimes. Treat every clock as an aid, never a legal verdict:

| Built-in clock key | Operational timing | Human decision / official source |
|---|---|---|
| `gdpr_eu_72h` | 72 hours from awareness | Applicability and notification decision; [GDPR Article 33](https://eur-lex.europa.eu/eli/reg/2016/679/art_33/oj) |
| `uk_gdpr_72h` | 72 hours from awareness | Applicability and notification decision; [UK ICO breach guidance](https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/) |
| `nis2_early_24h` | 24-hour early warning | Significance and national transposition; [NIS2 Article 23](https://eur-lex.europa.eu/eli/dir/2022/2555/art_23/oj) |
| `nis2_notification_72h` | 72-hour notification | Significance and national transposition; [NIS2 Article 23](https://eur-lex.europa.eu/eli/dir/2022/2555/art_23/oj) |
| `nis2_final_1mo` | One calendar month after incident notification | Significance and national transposition; [NIS2 Article 23](https://eur-lex.europa.eu/eli/dir/2022/2555/art_23/oj) |
| `singapore_pdpa_3d` | Three calendar days after notifiable determination | Human breach assessment; [Singapore PDPC guidance](https://www.pdpc.gov.sg/report-data-breach/before-you-report-a-data-breach-3/info) |
| `australia_ndb_assess_30d` | 30-calendar-day assessment period | Suspected eligible-breach assessment; [OAIC NDB guide](https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches) |
| `australia_ndb_notice_asap` | “As soon as practicable”; deliberately no numeric deadline | Eligible-breach determination; [OAIC NDB guide](https://www.oaic.gov.au/privacy/notifiable-data-breaches/quick-reference-guide-for-responding-to-data-breaches) |
| `canada_pipeda_asap` | “As soon as feasible”; deliberately no numeric deadline | Real-risk-of-significant-harm determination; [PIPEDA breach guidance](https://www.priv.gc.ca/media/4844/pipeda_pb_form_e.pdf) |
| `sec_8k_4bd` | Four business days from materiality determination | Registrant status and materiality; holiday-calendar legal review required; [SEC rule release](https://www.sec.gov/newsroom/press-releases/2023-139) |
| `hipaa_60d` | 60-calendar-day outer limit from discovery | Covered-entity/business-associate and breach determination; [HHS guidance](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html) |

- Applicability, materiality, discovery/notification start time, business-day
  rules, regulator interpretation, contractual duties, sector rules, and
  exceptions require counsel or an authorized compliance owner.
- Global companies must configure and validate the regimes applicable to each
  affected entity, person, system, and jurisdiction. A generic or US baseline is
  not global coverage.
- A clock does not send, file, notify, or decide. The accountable human records
  the decision and rationale; external filing remains outside the engine unless
  an separately authorized, governed connector implements it.
- Regulatory content changes. Owners must review rule metadata and official
  sources on a defined cadence and record the version used for each incident.

## Evidence and approval boundary

Across the integrated platform and the standalone products, deterministic code
creates control and detection verdicts from cited inputs. A model may summarize,
triage, or draft a report; it
does not become the deciding control test, threat label, materiality decision, or
authorization. Human decisions are explicit records. Only the integrated
platform can place those records on Lightwork's signed audit chain and approval
queue.
