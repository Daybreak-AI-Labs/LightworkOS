"""Backwards-compat tooling: ``maverick migrate``.

Upgrades change what config means; this is the tool that walks an existing
``~/.maverick/config.toml`` forward. Three honest pieces:

* **Advisories** — real, currently-known migration paths (e.g. the Twilio
  WhatsApp adapter → the first-party Cloud API adapter). Advisories never
  rewrite config; they tell the operator what to change and why.
* **Config lint** — unknown top-level sections (typos: ``[budgets]`` for
  ``[budget]``) flagged against the known-section table, since a misspelled
  section silently no-ops and the operator thinks the knob is on.
* **Rewrites** — mechanical key renames, applied only with ``--apply`` and
  only after a timestamped backup of the config file. The rewrite table is
  empty today — no key has been renamed yet. The writer takes a backup and
  then rewrites the file in place (not atomically, no stamp), and handles only
  shallow tables; harden it before the first rename lands.

Dry-run is the default; nothing is written without ``--apply``, and nothing
is ever written without a backup.
"""
from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

# Top-level config sections the runtime actually reads. A section outside
# this table is almost always a typo that silently no-ops.
# Every top-level section some runtime reader consumes. Enumerated from the
# load_config().get("<section>") call sites across the packages (this list
# once held 44 names while the runtime reads ~90, so `migrate`
# told users that wizard-written sections like [models] / [capabilities] /
# [security] "silently do nothing" -- advice that would delete live config).
# When adding a new config section, add it here or migrate will lint it.
KNOWN_SECTIONS = frozenset({
    "conversation_inbox",
    # [public_chat] enabled / allow_localhost_origins: the public website chat
    # widget (maverick_dashboard.public_chat_api), off by default; on All settings.
    "public_chat",
    # [chat_message_actions] enabled: alternative conversation answers
    # (maverick.chat_message_actions), changeable on All settings.
    "chat_message_actions",
    "a2a", "adaptive_compute", "agent", "agent_factory", "agent_tests", "agent_trust",
    # [alerts] enabled: operational alerts (maverick.ops_alert), changeable
    # on Settings > All settings.
    "alerts",
    # [collaboration] comments: comment threads and @mentions (maverick.comments).
    "collaboration",
    # [work_details] enable: reviewed business fields and stages on tasks and
    # security records (maverick.work_record_details), on All settings.
    "work_details",
    # [first_outcome] department / sample_workspace_created: the department
    # first task picked at setup (maverick.sample_outcomes).
    "first_outcome",
    # [practice] enable: offer practice mode (maverick.practice), written by
    # the installer's capabilities step and changeable on All settings.
    "practice",
    # [third_party_portal] routing_keyring: the vendor portal link keyring
    # rotated on the Third-Party Collaboration page (sealed).
    "third_party_portal",
    # [consent_publication_signing] keyring: the consent publication signing
    # key made on the Banner and Preference Center page (sealed).
    "consent_publication_signing",
    # [approval_challenges] enable / [instruction_capture] enable: fictional
    # approval practices and per-task instruction records (Settings > All
    # settings, Memory & learning).
    "approval_challenges", "instruction_capture",
    "analytics", "approval", "assessments", "automation_import",
    "approval_delegation", "attachments", "audit", "auth", "autonomy",
    "deployment", "device_pairing", "personalization", "copilot", "settings", "_dashboard_resets", "mobile_offline", "workflows",
    "benchmark", "billing", "budget", "cache", "calendar", "calibration",
    # Written by the installer's candidate promotion, governed knowledge and
    # agent suites steps, and changeable on Settings > All settings.
    "candidate_promotion", "knowledge_access", "suites",
    "capabilities", "catalogs", "channels", "client", "coding", "compaction",
    "compliance", "computer_use", "connections", "consent_preferences",
    "consequence", "containment", "control_plane",
    "context", "credit", "customer_sandbox_lifecycle", "data_engine", "data_use_governance",
    "dashboard", "deadline_alerts", "director", "durable", "ebpf_monitor", "effort", "egress", "ekko",
    "emergent_codec", "emergent_protocol",
    "email", "embedded", "encryption", "energy", "enterprise", "entity_graph",
    "erp", "event_triggers",
    "experience", "features", "federation", "finance", "finance_operations", "flows", "github",
    "governance", "governed_connectors", "governed_records", "grpc", "grpc_dispatch", "image_edit", "intake", "intent_value",
    "kms", "knowledge", "knowledge_sources",
    "langchain", "latency", "limits", "local_first", "local_runtime",
    "logging", "lsp", "mcp_registries", "mcp_servers", "mcp_sidecar", "memory",
    # [mcp]: the tool server's limits and switches (maverick_mcp.settings),
    # [replay]: recording run traces (replay/trace.py); both on All settings.
    "mcp", "replay",
    "model_cost_tiers", "model_proxy", "models",
    # [my_work] the personal "My work" page and daily summary (maverick.daily_digest).
    "my_work", "notifications", "oauth", "observability",
    "paper_review",
    "obsidian", "operations_scientist",
    "perf", "persona", "planning", "plugins", "privacy",
    # [profile] name: the deployment profile (standard / enterprise), read by
    # profile.py and enterprise.py.
    "profile",
    "privacy_automation", "privacy_ops", "provider_failover", "providers", "queue", "quotas",
    "spending_limits",
    "rate_limits", "reflexion",
    # [release] publisher_pubkeys: the keys whose signed update bundles
    # release_update accepts (maverick.release_manifest_signing).
    "release",
    "tech_risk_compliance", "third_party_management",
    "repl", "harness_refine", "session_tree",
    "retention", "role_assignments", "roles", "routing", "safety",
    "sandbox", "screening", "search", "security", "self_learning",
    "shield", "skill_synthesis", "skills", "security_ops",
    # [contact_centre] where a human handoff goes outside Lightwork (config.get_contact_centre).
    "contact_centre",
    # [support] the Help menu's status page and support contact (config.get_support).
    "support",
    "shoring",
    "system", "telemetry", "template_registries", "tenancy", "thinking",
    "tools", "tui", "value", "verification", "voice", "webhooks", "workforce",
    "workspace", "world_model", "threat_hunt", "env_hunt",
    "chat", "connector_limits", "query_limits",
    "immune", "swarm", "ifc", "codebase",
    "ai_inventory", "evidence_gateway", "evidence_graph",
    "model_risk_assurance", "model_improvement", "policy_packs",
    "agent_topology", "drift_monitoring", "portfolio_risk", "red_team_assurance",
    "ai_regulatory_feed", "ai_vendor_risk", "eu_ai_incidents",
    "grc_outbound_sync", "ai_literacy", "ai_business_intake", "ai_cost_roi",
    "ai_dynamic_risk",
    "ai_policy_management",
    "ai_runtime_guardrails",
    "ai_governance_loop",
    "ai_explainability",
    "ai_conformity_workflow",
    "ai_insurability",
    "ai_regulated_verticals",
    "ai_bank_mrm",
    "ai_benchmark_exchange",
    "ai_discovery_sensors",
    "ai_media_provenance",
    "governance_agents",
    "ai_evidence_analysis",
    "ai_identity_governance_connectors",
    "ai_entity_tasks",
    "assessment_evidence_autopopulation",
    "administration_document_access",
    "governed_document_vault",
    "incident_attachment_metadata",
    "governance_inventory",
    "ai_incident_reporting",
    "eu_conformity",
    "explainability",
    "content_provenance",
    "llm_gateway",
    "vendor_management",
    "vendor_onboarding",
    "consent_registry",
    "data_map",
    "breach_notification",
    "ediscovery",
    "dsar_fulfillment",
    "grc_sync",
    # Registry drift, again: these are all read by real load_config() call sites
    # AND written by the installer wizard, yet were missing here -- so an operator
    # who enabled a documented, wizard-offered feature got a false "unknown
    # config section" warning from config-lint (which sources this set), some
    # with actively-wrong suggestions ("self_harness -> did you mean
    # self_learning?", which is a *different* feature). The self-learning
    # lifecycle (self_harness/self_improvement/dreaming/fleet_memory/rehearsal/
    # memory_guard) plus actions/domains/fairness_monitor/speculative/tax.
    # Guarded against future drift by test_wizard_parity's wizard-section check.
    "actions", "domains", "dreaming", "earned_autonomy", "fairness_monitor",
    "external_agents", "fleet_memory", "memory_guard", "rehearsal",
    "self_harness", "self_improvement", "speculative", "tax",
    # Cortex, the governed company memory over every source (maverick.cortex
    # reads [cortex] enable; the wizard writes it beside [fleet_memory]).
    "cortex",
    # Commerce suite (maverick.commerce): opt-in shopper/merchant tool surface
    # with per-session caps; read by config.get_commerce and written by the
    # wizard's advanced step.
    "commerce",
    # Structured rubric verifier + JitRL test-time adaptation: read by
    # load_config (config.get_reasoning_reward / get_jit_rl) and written by the
    # wizard's advanced opt-out steps.
    "reasoning_reward", "jit_rl",
    # Governed code self-modification (maverick.self_modify): editable-surface
    # allowlist for the DGM-style code rung. Read by config.get_self_modify,
    # written by the wizard's advanced opt-in step.
    "self_modify",
    # Governed in-tenant weights adaptation (maverick.adapter_rung): LoRA
    # adapters promoted through the weights rung. Read by
    # config.get_adapter_rung, written by the wizard's advanced opt-in step.
    "adapter_rung",
    # Data-residency region pinning (maverick.residency): read by real
    # load_config() call sites and written by the wizard's regulated-posture
    # step, yet was missing here -- a false "unknown section" for [residency].
    "residency",
})


@dataclass
class Finding:
    kind: str          # "advisory" | "lint" | "rewrite"
    id: str
    message: str
    applied: bool = False


@dataclass
class MigrationReport:
    findings: list[Finding] = field(default_factory=list)
    backup_path: Path | None = None
    wrote: bool = False
    apply_requested: bool = False

    @property
    def clean(self) -> bool:
        return not self.findings


def _advisory_whatsapp_cloud(cfg: dict) -> Finding | None:
    channels = cfg.get("channels") or {}
    wa = channels.get("whatsapp") or {}
    if wa.get("enabled") and not (channels.get("whatsapp_cloud") or {}).get("enabled"):
        return Finding(
            "advisory", "whatsapp-twilio-to-cloud",
            "[channels.whatsapp] rides Twilio's Business API (per-message cost, "
            "third-party webhooks). The first-party Meta Cloud API adapter "
            "([channels.whatsapp_cloud]) has no middleman; see "
            "maverick_channels/whatsapp_cloud.py for the four credentials it "
            "needs. The Twilio adapter keeps working — migrate when ready.",
        )
    return None


def _lint_unknown_sections(cfg: dict) -> list[Finding]:
    out = []
    for section in sorted(cfg):
        if not isinstance(cfg.get(section), dict):
            continue
        if section not in KNOWN_SECTIONS:
            close = _closest(section)
            hint = f" (did you mean [{close}]?)" if close else ""
            out.append(Finding(
                "lint", f"unknown-section-{section}",
                f"[{section}] is not a section the runtime reads{hint}; "
                "it silently does nothing.",
            ))
    return out


def _closest(name: str) -> str | None:
    import difflib
    matches = difflib.get_close_matches(name, KNOWN_SECTIONS, n=1, cutoff=0.75)
    return matches[0] if matches else None


# (old_dotted_key, new_dotted_key) — mechanical renames applied by --apply.
# Empty today: no config key has been renamed yet. A 2.0 rename lands here.
REWRITES: list[tuple[str, str]] = []


def _apply_rewrites(cfg: dict) -> list[Finding]:
    findings = []
    for old, new in REWRITES:
        old_parts, new_parts = old.split("."), new.split(".")
        node = cfg
        for p in old_parts[:-1]:
            node = node.get(p) or {}
        if old_parts[-1] in node:
            value = node.pop(old_parts[-1])
            dst = cfg
            for p in new_parts[:-1]:
                dst = dst.setdefault(p, {})
            dst.setdefault(new_parts[-1], value)
            findings.append(Finding("rewrite", f"rename-{old}",
                                    f"renamed {old} -> {new}", applied=True))
    return findings


def migrate(config_path: Path | None = None, *, apply: bool = False) -> MigrationReport:
    """Inspect (and with ``apply=True``, mechanically migrate) the config.

    Never writes without a timestamped backup; advisory/lint findings are
    informational either way.
    """
    try:
        import tomllib  # 3.11+
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]

    if config_path is None:
        from .config import config_path as active_config_path
        config_path = active_config_path()
    config_path = Path(config_path)
    report = MigrationReport(apply_requested=apply)
    if not config_path.exists():
        report.findings.append(Finding(
            "lint", "no-config",
            f"no config at {config_path} — run `maverick init` first."))
        return report
    try:
        cfg = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        report.findings.append(Finding("lint", "unparseable", f"cannot parse config: {e}"))
        return report

    adv = _advisory_whatsapp_cloud(cfg)
    if adv:
        report.findings.append(adv)
    report.findings.extend(_lint_unknown_sections(cfg))

    rewrites = _apply_rewrites(cfg) if apply else []
    report.findings.extend(rewrites)
    if apply and any(f.applied for f in rewrites):  # pragma: no cover -- empty table
        backup = config_path.with_name(
            f"{config_path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(config_path, backup)
        report.backup_path = backup
        _write_toml(config_path, cfg)
        report.wrote = True
    return report


def _write_toml(path: Path, cfg: dict) -> None:  # pragma: no cover -- no rewrites yet
    """Minimal TOML writer for the rewrite path (sections of scalar/list values)."""
    lines: list[str] = []
    scalars = {k: v for k, v in cfg.items() if not isinstance(v, dict)}
    for k, v in scalars.items():
        lines.append(f"{k} = {_toml_value(v)}")
    for section, table in cfg.items():
        if not isinstance(table, dict):
            continue
        lines.append(f"\n[{section}]")
        for k, v in table.items():
            if isinstance(v, dict):
                lines.append(f"\n[{section}.{k}]")
                for kk, vv in v.items():
                    lines.append(f"{kk} = {_toml_value(vv)}")
            else:
                lines.append(f"{k} = {_toml_value(v)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _toml_value(v) -> str:  # pragma: no cover -- exercised via _write_toml
    import json
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return json.dumps(str(v))


def render(report: MigrationReport) -> str:
    if report.clean:
        return "config is current: no migrations, advisories, or lint findings."
    lines = []
    for f in report.findings:
        tag = {"advisory": "ADVISE", "lint": "LINT", "rewrite": "REWROTE" if f.applied else "RENAME"}[f.kind]
        lines.append(f"[{tag}] {f.message}")
    if report.backup_path:
        lines.append(f"backup: {report.backup_path}")
    if not report.wrote:
        # Distinguish "ran --apply but there was nothing to mechanically
        # rewrite" from a plain dry run, so an operator can tell their --apply
        # was accepted.
        if report.apply_requested:
            lines.append("(--apply: no mechanical rewrites were needed)")
        else:
            lines.append("(dry run — nothing was written; re-run with --apply to migrate)")
    return "\n".join(lines)


__all__ = ["migrate", "render", "MigrationReport", "Finding", "KNOWN_SECTIONS", "REWRITES"]
