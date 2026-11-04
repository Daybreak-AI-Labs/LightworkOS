"""Audit event schema. Versioned, additive-only.

To add a new event kind:
  1. Add it to ``EventKind`` here.
  2. Bump ``SCHEMA_VERSION`` if the payload shape changes for an
     EXISTING kind (new kinds are additive — no bump needed).
  3. Document the payload shape in this file's module docstring.

Payload shapes (kind -> required fields, all events also carry
``ts``, ``goal_id``, ``agent``, ``kind``):

  goal_start:        title:str, description:str|None
  goal_end:          status:str (succeeded|failed|cancelled), result:str|None
  episode_start:     attempt:int, model:str
  episode_end:       outcome:str, cost_dollars:float, in_tok:int, out_tok:int
  tool_call:         name:str, call_id:str, call_commitment:str,
                     call_commitment_algorithm:str, input_summary:str (truncated);
                     records an attempted governed dispatch, not completion
  tool_result:       name:str, call_id:str, call_commitment:str,
                     call_commitment_algorithm:str, status:str, output_summary:str;
                     status=ok is the execution-completion evidence
  shield_block:      stage:str (input|tool|output), reason:str, score:float|None
  ifc_flow:          tool:str, labels:list[str], explicit:list[str], mode:str,
                     outcome:str (recorded|approved|denied|blocked); labelled data
                     reaching an external sink (maverick.ifc); never arguments
  capability_denied: tool:str, principal:str, channel:str|None, user_id:str|None
  egress_blocked:    provider:str (enterprise-mode egress lock denial)
  consent_prompt:    action:str, risk:str (low|medium|high|critical)
  consent_result:    decision:str (approve|deny|timeout)
  secret_redacted:   tool_name:str, pattern:str, count:int
  erase:             channel:str, erasure_id:str (random token, never subject-derived)
  halt:              source:str (file|signal|manual), detail:str|None
  content_update:    content:str, version:int, year:int, publisher:str
                     (signed publisher content metadata; no tax table bodies)
  federation_delegate: peer_node:str (absent when the caller was unauthenticated),
                     correlation_id:str, direction:str (sent|received),
                     accepted:bool, reason:str ("" when accepted) — one half of a
                     cross-swarm delegation; the two halves share the
                     correlation_id
  agent_trust_denied: peer:str, direction:str (inbound|outbound), rule:str,
                     reason:str, correlation_id:str — an external agent was
                     refused by the Agent Trust Plane.
  privacy_record_changed: event_id:str, occurred_at:float, actor:str, tenant:str,
                     record_type:str, action:str, record_id:str, revision:int,
                     status:str, record_sha256:str (opaque control metadata and
                     a content commitment only; never DPA text, subject ids,
                     RoPA content, or export bodies)
  security_suite_control_changed: actor:str, previous:dict, requested:dict
                     (deployment-global enablement of GRC/platform-hunt/env-hunt
                     and response execution; no connector credentials)
  security_record_changed: event_id:str, occurred_at:float, actor:str, tenant:str,
                     record_type:str, action:str, record_id:str, revision:int,
                     status:str, record_sha256:str (opaque lifecycle metadata and
                     a content commitment only; never evidence or case content)
  platform_hunt_detection: finding_id:str, rule_id:str, severity:str, score:int,
                     mitre_techniques:list[str], evidence_ids:list[str],
                     finding_sha256:str
  platform_hunt_custody_initialized: event_id:str, version:int, purpose:str,
                     occurred_at:float (insert-once witness that the hunter's
                     signed audit custody was successfully initialized)
  threat_hunt_record_changed: event_id:str, record_type:str, record_id:str,
                     revision:int, action:str, actor:str, record_sha256:str,
                     status:str, occurred_at:float
  env_hunt_record_changed: same bounded derived-record mutation shape as
                     threat_hunt_record_changed
  env_hunt_ingestion: connector:str, query_sha256:str, events_received:int,
                     events_accepted:int, events_discarded:int, raw_persisted:bool
  env_hunt_detection: same bounded shape as platform_hunt_detection
  env_hunt_enrichment: investigation_id:str, source:str,
                     indicator_sha256:str, fields_sha256:str
  env_hunt_response_proposed: proposal_id:str, proposal_sha256:str, action:str,
                     target_sha256:str, evidence_ids:list[str]
  env_hunt_response_authorized: proposal_id:str, proposal_sha256:str,
                     approval_id:str, approver:str, executor:str
  env_hunt_response_executed: proposal_id:str, proposal_sha256:str,
      approval_id:str, approver:str, executor:str, outcome:str
  env_hunt_response_ambiguous: proposal_id:str, proposal_sha256:str,
      approval_id:str, executor:str, error_kind:str
  env_hunt_response_execution_claimed: proposal_id:str, proposal_sha256:str,
      approval_id:str, executor:str, actor:str
  unified_audit_projection: projection_event_id:str, projection_type:str,
                     tenant_sha256:str, source_id:str, suite_id:str,
                     source_schema_version:int, source_authority_revision:int,
                     source_authority_sha256:str, source_sequence:int;
                     ``source_record`` rows carry only stable record digests and
                     a closed action code, while ``source_page_receipt`` rows
                     carry the page/head/watermark/completeness commitments plus
                     verifier, trust-root, key, anchor and retention commitments,
                     raw_source_payload_persisted:false (digest-only custody
                     projection of a domain-owned event; never raw source
                     payloads, actors, or resource ids)
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 2

_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CALL_ID_RE = re.compile(r"^[0-9a-f]{24}$")
TOOL_CALL_COMMITMENT_ALGORITHM = "sha256:lightwork.tool-call-id:v2"


def tool_call_commitment(
    *,
    call_id: str,
) -> str:
    """Return the v2 domain-separated commitment shared by one call/result pair.

    Only the stable random call identifier is committed here. The audit writer
    may legitimately replace an omitted goal from ambient context and may
    pseudonymize ``goal_id`` / ``principal`` before signing. Binding those
    pre-write values made an honest persisted row fail verification. The
    verifier separately compares every persisted signed identity field between
    the call and result; this digest prevents substitution of the correlation id.
    """
    if not isinstance(call_id, str) or not _CALL_ID_RE.fullmatch(call_id):
        raise ValueError("tool call_id must be exactly 24 lowercase hex characters")
    payload = {
        "domain": "lightwork.tool-call-id.v2",
        "call_id": call_id,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def is_valid_day(day: Any) -> bool:
    """True iff ``day`` is a real ``YYYY-MM-DD`` calendar date.

    An audit ``day`` becomes a filesystem path component
    (``<audit_dir>/<day>.ndjson``), so anything that isn't this exact shape
    -- ``..``, a path separator, an absolute path, a NUL -- could escape the
    audit dir. The anchored shape check is the path-safety gate; on top of it
    we require a genuine calendar date, so a typo'd ``--day`` (``2026-13-99``,
    ``2026-02-30``) is a friendly error instead of a misleading "no entries /
    OK" on a day-file that could never exist. Every code path that
    builds a day-file path from an untrusted ``day`` must gate on this first.
    (Mirrors the dashboard's own ``safe_audit_day`` HTTP-boundary guard.)
    """
    if not (isinstance(day, str) and _DAY_RE.match(day)):
        return False
    import datetime
    try:
        datetime.date.fromisoformat(day)
    except ValueError:
        return False
    return True


class EventKind:
    """Stringly-typed event kinds. Use these constants, not bare strings."""
    GOAL_START      = "goal_start"
    GOAL_END        = "goal_end"
    EPISODE_START   = "episode_start"
    EPISODE_END     = "episode_end"
    TOOL_CALL       = "tool_call"
    TOOL_RESULT     = "tool_result"
    SHIELD_BLOCK    = "shield_block"
    IFC_FLOW        = "ifc_flow"
    CAPABILITY_DENIED = "capability_denied"
    SANDBOX_DENIED = "sandbox_denied"
    # Per-call token exchange (zero-trust): one row per minted, single-tool,
    # short-lived capability token, so the Operating Record shows the scoped
    # credential each tool call actually ran under -- not just the run-long grant.
    TOKEN_EXCHANGE = "token_exchange"
    # governance_denied and tool_call rows may carry optional regulatory tags
    # (regulatory_compiler): ``obligation_id``/``regulation``/``article`` on a
    # denial the compiled rules produced, ``obligations_checked`` (ids) on a
    # call that ran while obligations covering it were active. Additive.
    GOVERNANCE_DENIED = "governance_denied"
    # A finance separation-of-duties conflict found when an action was about to
    # run ([finance.sod] mode): tool, compartment, mode, outcome, conflicts.
    FINANCE_SOD_FINDING = "finance_sod_finding"
    AUTONOMY_ESCALATED = "autonomy_escalated"
    AUTONOMY_GATED = "autonomy_gated"
    EGRESS_BLOCKED  = "egress_blocked"
    CONSENT_PROMPT  = "consent_prompt"
    CONSENT_RESULT  = "consent_result"
    SECRET_REDACTED = "secret_redacted"
    ERASE           = "erase"
    # Two-phase bearer receipt publication. PREPARED means the private staged
    # artifact existed but was not yet published; ISSUED means the same digest
    # reached its requested path. Payload: day, row_hash, committed, key_id,
    # artifact_sha256. A PREPARED row without ISSUED is explicit recovery state,
    # not a false claim that the recipient could access the artifact.
    TRUST_RECEIPT_PREPARED = "trust_receipt_prepared"
    TRUST_RECEIPT_ISSUED = "trust_receipt_issued"
    # Data-retention enforcement deleted aged audit day-files / world rows. One
    # signed row per non-dry-run purge so a gap in the day-files (or shrunken
    # episode/event tables) is provably policy-driven retention, not tampering.
    # payload: audit_files_removed:int, audit_files:list[str], audit_cutoff_day,
    # episodes_deleted:int, goal_events_deleted:int, usage_buckets_removed:int.
    RETENTION_PURGE = "retention_purge"
    HALT            = "halt"
    CONFIG_REMEDIATED = "config_remediated"
    # A tenant's billing terms changed (plan or daily spend cap). One signed row
    # per change so a plan upgrade / cap change is a provable control-plane act,
    # not a silent edit. payload: tenant, field ("plan"|"quota"), old, new.
    TENANT_PLAN_CHANGED = "tenant_plan_changed"
    TENANT_QUOTA_CHANGED = "tenant_quota_changed"
    # An administrator changed the workspace or per-person spending limits.
    # payload: actor, workspace, default, people (count of personal limits).
    SPENDING_LIMITS_CHANGED = "spending_limits_changed"
    # An administrator changed one product setting on the dashboard's All
    # settings page. One row per setting. payload: actor, section, key, old,
    # new (secrets are recorded only as "set"/"not set", never their value),
    # confirmed (True when the change weakened a protection and was confirmed).
    SETTING_CHANGED = "setting_changed"
    # The scheduled shared-threat-rules check ran ([shield] federated_updates).
    # payload: outcome ("applied" | "unchanged" | "refused"), version,
    # previous_version, added, removed (rule ids), reason (refusals).
    SHIELD_RULES_UPDATE = "shield_rules_update"
    # Voice unlock ([voice] biometric_unlock). Never the audio or the voice
    # profile itself. VOICE_PROFILE_ENROLLED payload: actor, samples.
    # VOICE_PROFILE_DELETED payload: actor. VOICE_UNLOCK_CHECKED payload:
    # actor, surface ("check" | "spoken_request"), matched, score, threshold.
    VOICE_PROFILE_ENROLLED = "voice_profile_enrolled"
    VOICE_PROFILE_DELETED = "voice_profile_deleted"
    VOICE_UNLOCK_CHECKED = "voice_unlock_checked"
    # Deployment-global tenant/workspace control-plane decisions. These are
    # deliberately separate from tenant-local work so provisioning and a
    # caller changing the active confidentiality boundary cannot disappear
    # with (or be attributed only to) the selected tenant's audit chain.
    # TENANT_CREATED payload: tenant, plan, max_daily_dollars, actor.
    # WORKSPACE_SELECTED payload: actor, previous_tenant, tenant, source.
    # TENANT_DEFAULT_REGISTERED payload: tenant, trigger ("first_workspace" |
    # "repair"), actor. The deployment's implicit default tenant was added to
    # the roster so creating the first named workspace never locks it out.
    TENANT_CREATED = "tenant_created"
    TENANT_DEFAULT_REGISTERED = "tenant_default_registered"
    WORKSPACE_SELECTED = "workspace_selected"
    # A user's dashboard access changed: privilege role (global or per-tenant),
    # department (suite) grant, or one atomic SCIM group-authority mutation.
    # One row per change makes who-granted-whom-what-when provable instead of a
    # silent JSON edit. SCIM batch rows carry a stable scim_group_event_id,
    # old/new names, and complete member-set deltas or bounded commitments.
    ACCESS_GRANT_CHANGED = "access_grant_changed"
    FEDERATION_DELEGATE = "federation_delegate"
    # A bounded learned pure operator selected a value or the original agent.
    # Payload contains only node/work/artifact digests, candidate count, status
    # and reason. Agreement is not a grounded success label; examples and raw
    # inputs/outputs are deliberately absent from this decision event.
    FLOW_LEARNED_OPERATOR_DECISION = "flow_learned_operator_decision"
    FLOW_ACTION_RECIPE_DECISION = "flow_action_recipe_decision"
    # Agent Trust Plane: an external agent was refused an inbound action or an
    # outbound dial because it is absent from the [agent_trust] registry, its
    # direction forbade the interaction, or it exceeded its tool/risk ceiling.
    # payload: peer:str, direction:str (inbound|outbound), rule:str, reason:str,
    # correlation_id:str ("" when none).
    AGENT_TRUST_DENIED = "agent_trust_denied"
    # Agent Control Plane: an operator verb (suspend / resume / contain /
    # release / attenuate / halt / clear-halt) applied to a governed principal
    # from the console or `maverick control-plane`. payload: verb:str,
    # principal:str ("*" for a fleet verb), actor:str, ok:bool (what was
    # CONFIRMED to land, not what was asked), detail:str; attenuate adds
    # ceiling:dict (the narrowed deny_tools / max_risk / caps). Dashboard HALT
    # rows additionally carry operation:str, scope:str (local|cluster),
    # result:str (succeeded|failed|partial), and a bounded reason:str.
    CONTROL_PLANE_ACTION = "control_plane_action"
    # Bring-your-own-agent gateway: enrollment lifecycle and the governed
    # traffic of agents that run on OTHER platforms (Agentforce, Bedrock, ...).
    # ENROLLED payload: external_agent, platform, department, enrolled_by.
    # CREDENTIAL_MINTED payload: external_agent, surface (never the token).
    # RUN_INGESTED payload: external_agent, outcome, cost_dollars, steps,
    # over_budget (goal_id column carries the Operating Record row).
    # ACTION_SCREENED payload: external_agent, tool, allowed, rule, reason.
    # Personal / service-account API keys (maverick_dashboard.api_keys).
    # API_KEY_CHANGED payload: action (created|rotated|revoked), key_id,
    # prefix, owner, scopes, workspace, expires_at, actor -- never the secret.
    # SERVICE_ACCOUNT_CHANGED payload: action (created|disabled), account,
    # role, actor. BREAK_GLASS_TOKEN_USED: the static dashboard token (not a
    # personal key) authenticated an API request; payload: path, client,
    # rate-limited to one row per process per hour.
    API_KEY_CHANGED = "api_key_changed"  # pragma: allowlist secret - an event name
    SERVICE_ACCOUNT_CHANGED = "service_account_changed"
    BREAK_GLASS_TOKEN_USED = "break_glass_token_used"  # pragma: allowlist secret - an event name
    EXTERNAL_AGENT_ENROLLED = "external_agent_enrolled"
    EXTERNAL_CREDENTIAL_MINTED = "external_credential_minted"
    EXTERNAL_RUN_INGESTED = "external_run_ingested"
    EXTERNAL_ACTION_SCREENED = "external_action_screened"
    # Containment lifecycle: CONTAINED fires when repeated denials inside the
    # window trip the auto-containment (payload: external_agent, denials,
    # window_hours, last_rule); RELEASED and BUDGET_RESET are the admin
    # actions that lift it / zero the meter (payload carries who did it).
    EXTERNAL_AGENT_CONTAINED = "external_agent_contained"
    EXTERNAL_AGENT_RELEASED = "external_agent_released"
    EXTERNAL_BUDGET_RESET = "external_budget_reset"
    # A LIVE external run opened (goal_id carries the row; the matching
    # close is EXTERNAL_RUN_INGESTED with live=True).
    EXTERNAL_RUN_STARTED = "external_run_started"
    # The enforcement tier above screening: Lightwork PERFORMED an outbound
    # action on an external agent's behalf through a governed connector.
    # Payload: external_agent, connector, op, outcome (executed|failed),
    # request_sha256, approved (True when it went through a parked
    # approval), goal_id when the run bound one. Never the request body or
    # the response text — those stay out of the audit row by design.
    # (Previews and parks audit as ACTION_SCREENED — no effect occurred.)
    EXTERNAL_ACTION_EXECUTED = "external_action_executed"
    # Governed code execution: one row per statement run in a session kernel.
    # Payload: session, statement_sha256, ok, exit_code, wall_seconds (never
    # the code text or its output — those live in the lineage receipt and the
    # session ledger, which redact and bound).
    REPL_EXECUTED = "repl_executed"
    # Harness self-refinement. PROPOSED carries the observed failure and the
    # proposed change's digest; APPLIED carries the snapshot id that makes it
    # reversible (and is accompanied by a LEARNING_UPDATE row, so learned-state
    # verification covers it like any other learned write).
    HARNESS_REFINEMENT_PROPOSED = "harness_refinement_proposed"
    HARNESS_REFINEMENT_APPLIED = "harness_refinement_applied"
    # A run forked from another at a specific point in its event trail, so the
    # Operating Record can hold counterfactuals side by side.
    SESSION_FORKED = "session_forked"
    # An operator rolled a goal's journaled file mutations back to their
    # pre-run state (`maverick journal revert`). Payload: journal (the goal
    # dir name), reverted/deleted/skipped/entries counts, complete (False =
    # --partial on an incomplete journal) — never file contents, which stay
    # in the archived journal directory.
    WORKSPACE_REVERT = "workspace_revert"
    # Learning governance: one row per dream cycle (what the learning system
    # wrote/retired/quarantined) so `maverick audit verify` covers learned
    # state the same way it covers tool calls.
    LEARNING_UPDATE = "learning_update"
    # Signed publisher content was applied, distinct from learned-state writes.
    CONTENT_UPDATE = "content_update"
    # A validated, shared-source provider skill was authorized for an atomic
    # write. Contains source goal ID and exact output-byte digest, but makes
    # no claim that the subsequent filesystem publication succeeded.
    SKILL_DISTILL_PREPARED = "skill_distill_prepared"
    # A per-run shared-skill attempt was skipped because its source was not
    # explicitly shared. No goal title or trajectory content is logged.
    SKILL_DISTILL_SKIPPED = "skill_distill_skipped"
    # Deployment-global operator control over learning gates. Kept distinct
    # from learned-state writes so an auditor can identify who armed DGM.
    # payload: control, enabled, actor, acknowledged, previous_requested,
    # effective, state, blockers.
    LEARNING_CONTROL_CHANGED = "learning_control_changed"
    # Cortex: the governed company memory. One row per recall across every
    # memory source (knowledge, skills, lessons, the Operating Record, fleet
    # memory) and one per deposit, so "who recalled what, from where" is
    # provable for internal and external readers alike. payload: caller,
    # tenant, sources, per_source hit counts, denied reasons, query digest.
    CORTEX_RECALL = "cortex_recall"
    CORTEX_DEPOSIT = "cortex_deposit"
    # Ekko work-discovery governance.  These events deliberately carry only
    # policy hashes, opaque ids, counts and decisions -- never window titles,
    # file names, URLs, application content, or other observed work data.
    # Background work observation is a separate authority from ordinary
    # self-learning/DGM and therefore has its own auditable lifecycle.
    EKKO_CONTROL_CHANGED = "ekko_control_changed"
    EKKO_CONSENT_CHANGED = "ekko_consent_changed"
    EKKO_SESSION = "ekko_session"
    EKKO_BATCH = "ekko_batch"
    EKKO_MINING_RUN = "ekko_mining_run"
    EKKO_CANDIDATE_REVIEW = "ekko_candidate_review"
    EKKO_EXPORT = "ekko_export"
    EKKO_ERASE = "ekko_erase"
    EKKO_RETENTION_PURGE = "ekko_retention_purge"
    EKKO_POLICY_BLOCK = "ekko_policy_block"
    EKKO_HEALTH_DEGRADED = "ekko_health_degraded"
    # Provable learning: one signed row per structured verification reward
    # (maverick.reasoning_reward), so the EVIDENCE the system learns from -- the
    # per-dimension rubric, the holistic score, and whether a facet vetoed -- is
    # tamper-evident in the chain, not just a mutable in-memory verdict. Default-on
    # ([reasoning_reward] audit_rewards); payload is to_audit_summary(): score,
    # confidence, accepts, vetoed, and per-dimension name/score/veto.
    VERIFICATION_REWARD = "verification_reward"
    # Memory governance (OWASP ASI06): a memory write was stamped/screened, or a
    # trust-aware retrieval pass filtered low-trust memory out of the brief.
    # payload: action:str (write|write_blocked|recall_filter), plus key/source/
    # trust/sensitivity/reason/markers (writes) or kept/dropped/min_trust (recall).
    MEMORY_GUARD = "memory_guard"
    # Tamper-evident before/after capture for a governed computer/browser action.
    # payload: action:str (e.g. "browser.click"), phase:str (before|after),
    # file:str (capture basename under data_dir("captures")), sha256:str (sealed
    # digest, verifiable via screenshot_seal.verify_file).
    EVIDENCE_CAPTURE = "evidence_capture"
    # Human-oversight decision on a parked approval (approve/deny). Anchors the
    # who-decided-what in the signed chain so the integrity of the decision does
    # not rest on the mutable world-model `approvals` row alone.
    # payload: approval_event_id:str (stable transactional-outbox identity),
    # approval_id:int, status:str (approved|denied), decided_by:str,
    # occurred_at:float (when the vote and outbox row committed).
    APPROVAL_DECISION = "approval_decision"
    # A vote taken from a chat channel (maverick.channel_approvals): the
    # signed APPROVAL_DECISION above stays the authority; this note says
    # WHICH channel carried the decision. payload: approval_id:int,
    # decision:str, channel:str (slack|teams|email), decided_by:str,
    # effective:bool, approval_event_id:str.
    CHANNEL_APPROVAL_DECISION = "channel_approval_decision"
    # Identity linking (maverick.channel_identities): a chat account was tied
    # to / cut from a Lightwork person. payload: channel:str,
    # external_id:str, principal:str, actor:str, method:str (admin|code).
    CHANNEL_IDENTITY_LINKED = "channel_identity_linked"
    CHANNEL_IDENTITY_UNLINKED = "channel_identity_unlinked"
    # A daily summary was sent (maverick.daily_digest). No content: only the
    # recipient, the channel and item counts. payload: recipient:str,
    # channel:str, approvals:int, results:int, questions:int, ok:bool.
    DIGEST_SENT = "digest_sent"
    # Earned Autonomy (maverick.earned_autonomy): a consequence card pinned a
    # prediction for a high-stakes action BEFORE it ran, so predicted-vs-actual
    # accuracy is provable from the chain. payload: card:str, principal:str,
    # action:str, risk:str, predicted:float, episode_id:int, reversible:bool,
    # source:str (rehearsal|simulate|declared).
    CONSEQUENCE_CARD = "consequence_card"
    # Earned Autonomy dial movement: an action type earned policy-auto-approval,
    # lost it on a missed prediction, or an operator withdrew it. payload:
    # decision:str (graduate|demote|revoke), principal:str, action:str, plus
    # streak/hits/misses ints on graduate, card:str on demote, reason:str on
    # revoke.
    AUTONOMY_GRADUATION = "autonomy_graduation"
    # Earned Autonomy "Shadow Mode" (maverick.earned_autonomy.shadow_execute):
    # a high-stakes action was previewed, gated (earned-auto or human-approved),
    # and executed under the compensating saga -- the signed sim -> approve ->
    # execute chain. payload: decision:str (denied|approved|auto), action:str,
    # auto:bool, exposure:float|None; on execution also card:str|None and
    # committed:bool.
    SHADOW_EXECUTION = "shadow_execution"
    # Continuous group-fairness monitoring (ISO/IEC 42001 A.6.2.6): the rolling
    # window breached the four-fifths rule or drifted below its baseline, so a
    # fairness regression is anchored in the signed chain instead of passing
    # silently. payload: reason:str (adverse_impact|drift|adverse_impact+drift),
    # min_impact_ratio:float, demographic_parity_diff:float,
    # equal_opportunity_diff:float|None, failing_groups:list[str], samples:int,
    # threshold:float.
    FAIRNESS_ALERT = "fairness_alert"
    # Model/data drift monitoring: bounded aggregate PSI, KL, prediction,
    # embedding-centroid, or delayed-ground-truth performance metrics crossed a
    # configured threshold. Raw feature rows, predictions, labels, and vectors
    # are not part of the event. payload: asset_id:str, baseline_id:str,
    # evidence_id:str, reasons:list[str].
    MODEL_DRIFT_ALERT = "model_drift_alert"
    # Governance assessment sign-off: a reviewer accepted (or sent back) one lens
    # of a privacy/security/AI-risk assessment. Anchoring the decision in the
    # signed chain means a "reviewed" governance record can't rest on the mutable
    # JSON register alone. payload: subject_kind:str, subject:str, lens:str,
    # decision:str (accepted|needs_work), reviewer:str, result_status:str.
    ASSESSMENT_REVIEW = "assessment_review"
    # Cross-suite audit custody. Domain stores remain authoritative; this event
    # is the signed, append-once digest projection that makes their evidence
    # visible to the tenant audit/SIEM/WORM plane. ``projection_event_id`` is a
    # stable delivery identity. Stable record rows are separate from mandatory
    # signed page receipts, including receipts for empty terminal snapshots.
    # All source identities/content are closed codes or digests.
    UNIFIED_AUDIT_PROJECTION = "unified_audit_projection"
    # A privacy record mutation. The originating record retains a durable
    # audit-outbox receipt until this event is accepted by the signed chain.
    PRIVACY_RECORD_CHANGED = "privacy_record_changed"
    SECURITY_SUITE_CONTROL_CHANGED = "security_suite_control_changed"
    SECURITY_RECORD_CHANGED = "security_record_changed"
    PLATFORM_HUNT_CUSTODY_INITIALIZED = "platform_hunt_custody_initialized"
    PLATFORM_HUNT_DETECTION = "platform_hunt_detection"
    THREAT_HUNT_RECORD_CHANGED = "threat_hunt_record_changed"
    ENV_HUNT_RECORD_CHANGED = "env_hunt_record_changed"
    ENV_HUNT_INGESTION = "env_hunt_ingestion"
    ENV_HUNT_DETECTION = "env_hunt_detection"
    ENV_HUNT_ENRICHMENT = "env_hunt_enrichment"
    ENV_HUNT_RESPONSE_PROPOSED = "env_hunt_response_proposed"
    ENV_HUNT_RESPONSE_AUTHORIZED = "env_hunt_response_authorized"
    ENV_HUNT_RESPONSE_EXECUTED = "env_hunt_response_executed"
    ENV_HUNT_RESPONSE_AMBIGUOUS = "env_hunt_response_ambiguous"
    ENV_HUNT_RESPONSE_EXECUTION_CLAIMED = "env_hunt_response_execution_claimed"


@dataclass
class AuditEvent:
    """One audit log row. ``payload`` is event-specific (see module doc)."""
    ts: float
    kind: str
    agent: str = "system"
    goal_id: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        # Strip reserved keys from payload before the spread: a payload key
        # named v/ts/kind/agent/goal_id would otherwise clobber the canonical
        # structural field, losing it and corrupting the signed-hash input.
        _reserved = {"v", "ts", "kind", "agent", "goal_id"}
        safe_payload = {k: val for k, val in self.payload.items() if k not in _reserved}
        return {
            "v": self.schema_version,
            "ts": self.ts,
            "kind": self.kind,
            "agent": self.agent,
            "goal_id": self.goal_id,
            **safe_payload,
        }
