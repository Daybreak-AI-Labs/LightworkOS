"""Role-based UI visibility: which dashboard pages each RBAC role sees.

Two deliberately distinct layers:

  * ``floor`` -- the page's hard *security* requirement, mirroring the
    permission the route itself enforces (``/audit`` requires "audit",
    ``/settings`` requires "admin", ...). Visibility overrides can NEVER
    unlock a page past its floor: a role whose permissions don't include the
    floor cannot be shown the page, so presentation policy can't outrun authz.
  * ``default`` -- the page's *presentation* default: which permission a role
    must hold to see the page out of the box. This is what keeps a viewer's
    sidebar to read-only pages and an operator's free of admin plumbing. An
    admin may override it per role (within the floor) from Settings.

Safety invariants (mirror ``maverick_dashboard.rbac``):
  * Auth OFF (role ``None``) -> everything visible, nothing enforced -- the
    local single-user operator stays omnipotent, exactly as before.
  * Admins can never lose ``/settings`` or ``/users`` (``LOCKED``): a bad
    matrix save must not be able to lock every admin out of the controls
    that would undo it.
  * The store is one GLOBAL control-plane file, never per-tenant:
    ``~/.maverick/dashboard-ui-visibility.json`` (0600), shaped
    ``{path: {role: bool}}`` and holding only differences from the defaults,
    so un-overridden cells follow default changes across releases.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from . import rbac

# One registry drives the sidebar nav, the enforcement dependency, and the
# Settings matrix -- order here IS the nav order. ``floor`` mirrors the
# route-enforced gate ("view" when the GET route has none); ``default`` is the
# permission a role must hold to see the page before any admin override.
# ``in_nav: False`` keeps a page governed (enforced + in the Settings matrix)
# but out of the sidebar -- secondary composers/detail surfaces reached from a
# primary page's own links, so the nav stays one entry per job.
# ``scope: global`` uses the installation-wide role and permission in
# request navigation and HTTP admission, never a tenant-local role grant.
# ``module`` names the in-app module switch (``api._MODULE_SWITCHES``) whose
# gate turns the page into a "...is turned off" dead end; a tuple means the page
# is a dead end only while every listed switch is off. The sidebar uses it to
# keep people away from dead ends (see ``mark_switched_off``).
# ``ready: False`` marks a page that is not ready for customers -- an operator
# workbench of record ids, verification fingerprints and raw status documents,
# or a module that ships switched off with no in-app way to turn it on. Such a
# page keeps its route and its permission gate (engineers and tests reach it
# by URL) but is offered nowhere: not in the sidebar, not in the page finder,
# not in the Settings visibility matrix. Flip it back to ready when the page
# speaks to a non-technical user.
PAGES: tuple[dict, ...] = (
    {"path": "/decision-evidence", "label": "Shared decision reviews", "group": "Operate",
     "aliases": "shared facts questions freshness decisions", "icon": "bench", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/recheck-rules", "label": "Recheck affected rules", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/distinctions", "label": "Find missing distinctions", "group": "Observe",
     "aliases": "teaching observations conflicting examples compared cases",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/private-task-computation", "label": "Private task calculations", "group": "Operate",
     "icon": "check", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/rules-together", "label": "Check local rules together", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/request-program", "label": "Prepare an answer for this request", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/applicability", "label": "Checked answer regions", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/rule-evolution", "label": "Rewrite and check local rules", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/acquisition", "label": "Plan teaching questions", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/recovery-visibility", "label": "Understand a missing reply", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/portable-rules", "label": "Share and qualify local rule structures", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/work-restructuring", "label": "Share preparation safely", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/settings/local-ai", "scope": "global", "label": "AI on this computer", "group": "Admin",
     "icon": "settings", "floor": "admin", "default": "admin", "in_nav": False},
    {"path": "/settings/security-installation", "scope": "global", "label": "Sign-in and work protection", "group": "Admin",
     "icon": "settings", "floor": "admin", "default": "admin", "in_nav": False},
    {"path": "/learning/approval-challenges", "label": "Approval challenges", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/learning/instructions", "label": "Instructions used in real work", "group": "Observe",
     "icon": "learned", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/my-data", "label": "My data", "group": "Operate",
     "icon": "settings", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/account", "label": "Your account", "group": "Operate",
     "icon": "settings", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/content-access", "label": "Content access", "aliases": "Reviewed content access", "group": "Observe",
     "icon": "check", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/preferences", "label": "Your preferences", "group": "Operate", "icon": "settings", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/today", "label": "Today", "group": "Operate", "icon": "check", "floor": "view", "default": "view", "in_nav": True},
    {"path": "/workflow-readiness", "label": "Workflow readiness", "group": "Observe",
     "icon": "check", "floor": "view", "default": "view"},
    # Software development: vaulted repositories and swarm-built change
    # proposals awaiting approval. Read-only; merges run after approval.
    {"path": "/code", "label": "Code", "group": "Operate", "icon": "tools",
     "floor": "operate", "default": "operate", "module": "codebase", "in_nav": True},
    # The personal "My work" page: my approvals, questions, results, spending,
    # chat accounts and daily summary. Every signed-in person, so view floor.
    {"path": "/me", "label": "My work", "group": "Operate", "icon": "users",
     "floor": "view", "default": "view"},
    {"path": "/outcome-pilots", "label": "Workflow pilots", "group": "Operate",
     "icon": "bench", "floor": "operate", "default": "operate", "in_nav": False},
    {"path": "/commitment-reviews", "label": "Promise reviews", "group": "Operate",
     "aliases": "orders capacity deadlines options", "icon": "bench",
     "floor": "operate", "default": "operate"},
    {"path": "/research", "ready": False, "label": "Research lab", "aliases": "experiments candidates evaluation",
     "group": "Operate", "icon": "bench", "floor": "operate", "default": "operate"},
    {"path": "/project-reviews", "label": "Project team reviews", "group": "Operate",
     "icon": "check", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/deliverable-bundles", "label": "Selected deliverable bundles", "group": "Operate",
     "icon": "check", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/task-handoffs", "label": "Task handoffs", "aliases": "Accepted task handoffs", "group": "Operate",
     "icon": "check", "floor": "view", "default": "view", "in_nav": False},
    {
        "path": "/action-center", "label": "Action Center", "group": "Operate",
        "icon": "check", "floor": "operate", "default": "operate",
    },
    # -- Operate --------------------------------------------------------------
    {
        "path": "/start",
        "label": "Get started",
        "group": "Operate",
        "icon": "check",
        "floor": "view",
        # The root route sends every unconfigured installation here.  Keep
        # the guide visible to read-only users; the page projects their
        # authority and never turns its setup links into mutation grants.
        "default": "view",
    },
    {
        "path": "/chat",
        "label": "Chat",
        "group": "Operate",
        "icon": "chat",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/companion",
        "label": "My companion",
        "aliases": "personal employee companion task status",
        "group": "Operate",
        "icon": "chat",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/goals",
        "label": "Tasks",
        "aliases": "goals work tasks",
        "group": "Operate",
        "icon": "target",
        "floor": "view",
        "default": "view",
    },
    # Alternate goal composers, linked from the Goals page toolbar.
    {"path": "/work-details", "label": "Business details", "group": "Operate",
     "aliases": "business custom fields stages task details security record details",
     "icon": "target", "floor": "operate", "default": "operate", "in_nav": False},
    {
        "path": "/goal-builder",
        "label": "Task builder",
        "aliases": "Quick Goal",
        "group": "Operate",
        "icon": "builder",
        "floor": "view",
        "default": "operate",
        "in_nav": False,
    },
    {
        "path": "/graph-editor",
        "label": "Task map",
        "aliases": "Goal Map",
        "group": "Operate",
        "icon": "graph",
        "floor": "view",
        "default": "operate",
        "in_nav": False,
    },
    {
        "path": "/projects",
        "label": "Projects",
        "group": "Operate",
        "icon": "fleets",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/deliverables",
        "label": "Results",
        "aliases": "deliverables outcomes results",
        "group": "Operate",
        "icon": "templates",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/agents",
        "label": "Agent Factory",
        "group": "Operate",
        "icon": "agents",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/roles",
        "label": "Roles",
        "group": "Operate",
        "icon": "roles",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/workforce",
        "label": "Workforce",
        "group": "Operate",
        "icon": "agents",
        "floor": "view",
        "default": "view",
    },
    # The sidebar opens saved work first; the designer stays one click away.
    {
        "path": "/workflows",
        "label": "Workflows",
        "group": "Operate",
        "icon": "workflow",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/flows/designer",
        "label": "Flow designer",
        "group": "Operate",
        "icon": "workflow",
        "floor": "view",
        "default": "operate",
        "in_nav": False,
    },
    {
        "path": "/workflow-builder",
        "label": "Workflow builder",
        "group": "Operate",
        "icon": "workflow",
        "floor": "view",
        "default": "operate",
        "in_nav": False,
    },
    {
        "path": "/automations",
        "label": "Automations",
        "group": "Operate",
        "icon": "clock",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/fleets",
        "label": "Teams",
        "group": "Operate",
        "icon": "fleets",
        "floor": "view",
        "default": "operate",
    },
    # -- Observe --------------------------------------------------------------
    {
        "path": "/overview",
        "label": "Overview",
        "group": "Observe",
        "icon": "overview",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/ekko",
        "label": "Ekko",
        "group": "Observe",
        "icon": "eye",
        "floor": "operate",
        "default": "operate",
    },
    {
        # Its route requires operate permission.
        "path": "/oversight",
        "label": "Oversight",
        "group": "Observe",
        "icon": "eye",
        "floor": "operate",
        "default": "operate",
    },
    {
        "path": "/discovery",
        "label": "Discovery",
        "group": "Observe",
        "icon": "overview",
        "floor": "view",
        "default": "view",
    },
    # Counterfactual review: forked runs and their branches under one root.
    {
        "path": "/run-tree",
        "label": "Branches",
        "aliases": "Run Tree",
        "group": "Observe",
        "icon": "eye",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/spend",
        "label": "Spend",
        "group": "Observe",
        "icon": "spend",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/work-value",
        "label": "Work value & opportunities",
        "group": "Observe",
        "icon": "spend",
        "floor": "view",
        "default": "view",
    },
    # ROI: money saved vs the client's own human-cost assumptions.
    {
        "path": "/savings",
        "label": "Savings",
        "group": "Observe",
        "icon": "spend",
        "floor": "view",
        "default": "view",
    },
    # Autonomous Shoring: a function's book of work, measured SLAs, and the
    # exception desk — the Shoring P&L (Savings) sits underneath it.
    {
        "path": "/shoring",
        "label": "Autonomous shoring",
        "aliases": "Hand a team's work to Lightwork",
        "group": "Observe",
        "icon": "fleets",
        "floor": "view",
        "default": "view",
    },
    # Reviewed team setup reached from Workforce and Agent Factory.
    {
        "path": "/starter-teams",
        "label": "Starter teams",
        "group": "Operate",
        "icon": "fleets",
        "floor": "operate",
        "default": "operate",
        "in_nav": False,
    },
    # The monthly statement behind Spend's "Billing statement" link.
    {
        "path": "/billing",
        "label": "Billing",
        "group": "Observe",
        "icon": "spend",
        "floor": "view",
        "default": "view",
        "in_nav": False,
    },
    {
        "path": "/providers",
        "label": "Providers",
        "group": "Observe",
        "icon": "providers",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/benchmarks",
        "label": "Benchmarks",
        "group": "Advanced tools",
        "icon": "bench",
        "floor": "admin",
        "default": "admin",
        "scope": "global",
    },
    # Performance reads the same installation benchmark history and runs
    # diagnostic measurements; it must not be a less-protected alternate URL.
    {
        "path": "/perf", "label": "Performance diagnostics",
        "group": "Advanced tools", "icon": "bench",
        "floor": "admin", "default": "admin", "scope": "global",
        "in_nav": False,
    },
    {
        "path": "/flows/analytics",
        "label": "Flow results",
        "aliases": "Flow Analytics",
        "group": "Observe",
        "icon": "bench",
        "floor": "view",
        "default": "view",
    },
    # The legacy multi-source Cortex console remains a governed compatibility
    # route, but Knowledge access is the single customer-facing navigation
    # destination. Its document results use the APP10 registry boundary.
    {
        "path": "/cortex",
        "label": "Cortex memory diagnostics",
        "aliases": "legacy cortex company memory diagnostics",
        "group": "Advanced tools",
        "icon": "learned",
        "floor": "view",
        "default": "view",
        "in_nav": False,
    },
    {
        "path": "/knowledge-access",
        "label": "Knowledge",
        "aliases": "cortex company source freshness corrections exclusion deletion lineage rights Find knowledge you can use now",
        "group": "Observe",
        "icon": "learned",
        "floor": "operate",
        "default": "operate",
    },
    {
        "path": "/learning",
        "label": "Learning",
        "group": "Observe",
        "icon": "learned",
        "floor": "admin",
        "default": "admin",
        "scope": "global",
    },
    # The acquired-capabilities record, linked from the Learning page.
    {
        "path": "/learned",
        "label": "Learned",
        "group": "Observe",
        "icon": "learned",
        "floor": "view",
        "default": "view",
        "in_nav": False,
    },
    # Per-user goal recordings (owner-scoped) -- an operator review surface.
    {
        "path": "/walkthroughs",
        "label": "Video walkthroughs",
        "group": "Observe",
        "icon": "walkthroughs",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/facts",
        "label": "Facts",
        "group": "Observe",
        "icon": "facts",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/plan-tree-3d",
        "label": "3D plan view",
        "group": "Observe",
        "icon": "cube",
        "floor": "view",
        "default": "view",
    },
    # -- Govern ---------------------------------------------------------------
    # The Autonomous Compliance product landing: the six compliance suites
    # presented as one product, each module carrying its shipped/preview/
    # external status. A read-only overview, so the view floor is right; it
    # heads the Govern group as the front door to the compliance surface.
    {
        "path": "/autonomous-compliance",
        "label": "Autonomous compliance",
        "group": "Govern",
        "icon": "compliance",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/approvals",
        "label": "Approvals",
        "group": "Govern",
        "icon": "check",
        "floor": "operate",
        "default": "operate",
    },
    # The Agent Control Plane: a read-side roster and forensic ledger plus
    # separately authorized operator/admin verbs.  Its route requires view;
    # each API mutation rechecks its stronger permission.  Keep it discoverable
    # to auditors and viewers rather than making the nav imply one permission
    # governs the mixed-authority surface.
    {
        "path": "/agent-control-plane",
        "label": "Agent controls",
        "aliases": "Agent Control Plane",
        "group": "Govern",
        "icon": "agents",
        "floor": "view",
        "default": "view",
    },
    # The Privacy workspace: the module view over assessment records (PIA /
    # AIRA / vendor risk / framework readiness). Operate floor — records carry
    # answer bodies and reviewer threads, a tier above viewer summaries.
    {
        "path": "/privacy",
        "label": "Privacy",
        "group": "Privacy",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
    },
    {
        "path": "/privacy/data-discovery",
        "label": "Find personal data",
        "aliases": "Privacy Data Discovery",
        "group": "Privacy",
        "icon": "eye",
        "floor": "view",
        "default": "view",
        "module": "privacy_automation.data_discovery",
        "in_nav": True,
    },
    {
        "path": "/privacy/regulatory-intelligence",
        "label": "Privacy law research",
        "aliases": "Privacy Regulatory Intelligence",
        "group": "Privacy",
        "icon": "facts",
        "floor": "operate",
        "default": "operate",
        "module": "privacy_automation.regulatory_intelligence",
        "in_nav": False,
    },
    {
        "path": "/privacy/rights-orchestration",
        "label": "Privacy requests",
        "aliases": "Privacy Rights Orchestration",
        "group": "Privacy",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "module": "privacy_automation.rights_orchestration",
        "in_nav": False,
    },
    {
        "path": "/privacy/rights-consumer-delivery",
        "label": "Send people their data",
        "aliases": "Privacy Rights Consumer Delivery",
        "group": "Privacy",
        "icon": "key",
        "floor": "operate",
        "default": "operate",
        "module": "privacy_automation.rights_consumer_delivery",
        "in_nav": False,
    },
    {
        "path": "/privacy/notice-governance",
        "label": "Privacy notices",
        "aliases": "Privacy Notice Governance",
        "group": "Privacy",
        "icon": "check",
        "floor": "operate",
        "default": "operate",
        "module": "privacy_automation.notice_governance",
        "in_nav": False,
    },
    # Consumer consent is its own operating surface: unlike the agent-action
    # approval gate it carries pseudonymous profiles, immutable receipts,
    # tracker observations, and downstream preference synchronization.
    {
        "path": "/consent",
        "label": "Consent and preferences",
        "group": "Consent",
        "icon": "check",
        "floor": "operate",
        "default": "operate",
        "module": "consent_preferences",
    },
    {
        "path": "/consent/publishing",
        "label": "Banner and preference center",
        "aliases": "Consent Publishing",
        "group": "Consent",
        "icon": "check",
        "floor": "operate",
        "default": "operate",
        "module": "consent_preferences.publishing",
        "in_nav": False,
    },
    {
        "path": "/consent/experiments",
        "label": "Banner experiments",
        "aliases": "Consent Experiments",
        "group": "Consent",
        "icon": "bench",
        "floor": "operate",
        "default": "operate",
        "module": "consent_preferences.experiments",
        "in_nav": False,
    },
    {
        "path": "/consent/delivery",
        "label": "Send choices to other systems",
        "aliases": "Consent Delivery",
        "group": "Consent",
        "icon": "check",
        "floor": "operate",
        "default": "operate",
        "module": "consent_preferences.delivery",
        "in_nav": False,
    },
    {
        "path": "/consent/public-clients",
        "label": "Website and app keys",
        "aliases": "Public Consent Clients",
        "group": "Consent",
        "icon": "key",
        "floor": "operate",
        "default": "operate",
        "module": "consent_preferences.public_api",
        "in_nav": False,
    },
    {
        "path": "/consent/native",
        "label": "Mobile app consent",
        "aliases": "Consent in Your Apps",
        "group": "Consent",
        "icon": "key",
        "floor": "view",
        "default": "audit",
        "module": "consent_preferences.native_sdk",
        "in_nav": True,
    },
    {
        "path": "/consent/profile-data",
        "label": "Preference questions",
        "aliases": "Consent Profile Data",
        "group": "Consent",
        "icon": "check",
        "floor": "operate",
        "default": "operate",
        "module": "consent_preferences.profile_data",
        "in_nav": False,
    },
    {
        "path": "/consent/custom-indexes",
        "label": "Find people by preference",
        "aliases": "Custom Consent Indexes",
        "group": "Consent",
        "icon": "search",
        "floor": "view",
        "default": "view",
        "module": "consent_preferences.profile_data.custom_index",
        "in_nav": True,
    },
    {
        "path": "/consent/bulk-jobs",
        "label": "Bulk consent changes",
        "aliases": "Consent Bulk Jobs",
        "group": "Consent",
        "icon": "clock",
        "floor": "view",
        "default": "audit",
        "module": "consent_preferences.bulk_jobs",
        "in_nav": True,
    },
    {
        "path": "/consent/publish-settings",
        "label": "Website banner settings",
        "aliases": "Consent Publish Settings",
        "group": "Consent",
        "icon": "settings",
        "floor": "view",
        "default": "audit",
        "module": "consent_preferences.publishing.web_settings",
        "in_nav": True,
    },
    {
        "path": "/consent/global-opt-out",
        "label": "Opt out everywhere",
        "aliases": "Global Opt-Out",
        "group": "Consent",
        "icon": "check",
        "floor": "view",
        "default": "audit",
        "module": "consent_preferences.global_opt_out",
        "in_nav": True,
    },
    {
        "path": "/consent/application-scans",
        "label": "App tracking checks",
        "aliases": "Application Consent Scans",
        "group": "Consent",
        "icon": "search",
        "floor": "view",
        "default": "audit",
        "module": "consent_preferences.application_scanner",
        "in_nav": True,
    },
    {
        "path": "/consent/scan-inventory",
        "label": "Tracker scans",
        "aliases": "Consent Scan Inventory",
        "group": "Consent",
        "icon": "eye",
        "floor": "operate",
        "default": "operate",
        "module": "consent_preferences.scanner",
        "in_nav": False,
    },
    {
        "path": "/consent/scan-notice-proposals",
        "label": "Disclosure suggestions",
        "aliases": "Scan Disclosure Proposals",
        "group": "Consent",
        "icon": "check",
        "floor": "operate",
        "default": "operate",
        "module": "consent_preferences.scanner.notice_proposals",
        "in_nav": False,
    },
    {
        "path": "/consent/trust-center-authority",
        "label": "Trust center access",
        "aliases": "Trust Center Authority",
        "group": "Consent",
        "icon": "key",
        "floor": "operate",
        "default": "operate",
        "module": "consent_preferences.trust_center",
        "in_nav": False,
    },
    {
        "path": "/data-use",
        "label": "Data use rules",
        "aliases": "Data Use Governance",
        "group": "Privacy",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "module": "data_use_governance",
    },
    {
        "path": "/data-use/providers",
        "label": "Snowflake and Databricks",
        "aliases": "Native Data Controls",
        "group": "Privacy",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "module": ("data_use_governance.snowflake", "data_use_governance.databricks"),
        "in_nav": False,
    },
    {
        "path": "/governance-agents",
        "label": "Governance assistants",
        "aliases": "Governance Agents",
        "group": "AI oversight",
        "icon": "agents",
        "floor": "view",
        "default": "view",
        "module": "governance_agents",
        "in_nav": True,
    },
    {
        "path": "/governance/inventory",
        "label": "Governance inventory",
        "group": "AI oversight",
        "icon": "overview",
        "floor": "view",
        "default": "view",
        "in_nav": True,
    },
    {
        "path": "/ai-evidence-analysis",
        "label": "AI evidence analysis",
        "group": "AI oversight",
        "icon": "check",
        "floor": "view",
        "default": "view",
        "module": "ai_evidence_analysis",
        "in_nav": True,
    },
    {
        "path": "/assess/evidence-autopopulation",
        "label": "Suggested assessment answers",
        "aliases": "Assessment Evidence",
        "group": "AI oversight",
        "icon": "check",
        "floor": "view",
        "default": "view",
        "module": "assessment_evidence_autopopulation",
        "in_nav": True,
    },
    {
        "path": "/ai-entity-tasks",
        "label": "AI system tasks",
        "aliases": "AI Entity Tasks",
        "group": "AI oversight",
        "icon": "check",
        "floor": "view",
        "default": "view",
        "module": "ai_entity_tasks",
        "in_nav": True,
    },
    {
        "path": "/privacy/drop",
        "label": "California DROP requests",
        "group": "Privacy",
        "icon": "shield",
        "floor": "view",
        "default": "view",
        "in_nav": True,
    },
    # Security is the department workspace. The two hunter consoles are
    # governed child surfaces linked from it, so the sidebar keeps one clear
    # entry while role visibility still protects every direct URL.
    {
        "path": "/security",
        "label": "Security & GRC",
        "group": "Govern",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
    },
    {
        "path": "/third-party/vendor-onboarding",
        "label": "AI vendor onboarding",
        "group": "Third parties",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "in_nav": True,
    },
    {
        "path": "/third-party/contracts",
        "label": "Contracts and engagements",
        "aliases": "Contracts & Engagements",
        "group": "Third parties",
        "icon": "shield",
        "floor": "view",
        "default": "view",
        "module": "third_party_management.contracts",
        "in_nav": True,
    },
    {
        "path": "/third-party/executive-reports",
        "label": "Executive vendor reports",
        "group": "Third parties",
        "icon": "shield",
        "floor": "view",
        "default": "view",
        "module": "third_party_management.executive_reports",
        "in_nav": True,
    },
    {
        "path": "/third-party/intelligence",
        "label": "Third-party intelligence",
        "group": "Third parties",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "module": "third_party_management.intelligence",
        "in_nav": False,
    },
    {
        "path": "/third-party/lifecycle",
        "label": "Third-party lifecycle",
        "group": "Third parties",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "module": "third_party_management.lifecycle",
        "in_nav": False,
    },
    {
        "path": "/third-party/collaboration",
        "label": "Third-party collaboration",
        "group": "Third parties",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "module": "third_party_management.lifecycle.portal",
        "in_nav": False,
    },
    {
        "path": "/security/threats",
        "label": "Lightwork threat check",
        "aliases": "Platform Threat Hunter",
        "group": "Govern",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "in_nav": False,
    },
    {
        "path": "/security/soc",
        "label": "Threat monitoring",
        "aliases": "Environment Threat Hunter",
        "group": "Govern",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "in_nav": False,
    },
    # Reached from Security & GRC (and Get started) in-page; governed here so
    # the visibility matrix and the page finder both know them.
    {
        "path": "/security/report",
        "label": "Security readiness report",
        "aliases": "board pack readiness print Security & GRC readiness",
        "group": "Govern",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "in_nav": False,
    },
    {
        "path": "/security/assurance",
        "label": "AI assurance",
        "aliases": "assurance cockpit evidence gateway model risk Model Risk & AI Assurance",
        "group": "Govern",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "in_nav": False,
    },
    # The governance workspace: plain-language FRIA / Annex IV / literacy /
    # Art. 73 workflows for legal, privacy, and compliance staff. Its own
    # sidebar entry -- those personas never open the technical cockpit.
    {
        "path": "/security/governance",
        "label": "AI governance",
        "aliases": "Governance workspace",
        "group": "Govern",
        "icon": "shield",
        "floor": "operate",
        "default": "operate",
        "module": ("eu_conformity", "ai_literacy", "ai_incident_reporting"),
    },
    # The Finance workspace: the same chassis over the finance assessment
    # types (SOX control / fraud risk / ITGC / credit risk / close readiness).
    # "Financial Risk", not "Finance": this workspace is the SOX / fraud /
    # ITGC / credit-risk control record, not day-to-day finance operations.
    {
        "path": "/finance",
        "label": "Financial risk",
        "aliases": "Finance",
        "group": "Govern",
        "icon": "spend",
        "floor": "operate",
        "default": "operate",
    },
    # The partner fleet console: client deployments a partner operates.
    # Operate floor -- rows carry probe endpoints; mutations are admin (API).
    {
        "path": "/partner",
        "label": "Partner fleet",
        "group": "Third parties",
        "icon": "graph",
        "floor": "operate",
        "default": "operate",
    },
    # Permissions is deployment plumbing, not day-to-day governance work --
    # it lives with the rest of administration.
    {
        "path": "/permissions",
        "label": "Permissions",
        "group": "Admin",
        "icon": "key",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/simulate",
        "label": "Test a safety rule",
        "aliases": "Simulate",
        "group": "Govern",
        "icon": "graph",
        "floor": "view",
        "default": "operate",
    },
    # Redaction check (its preview API requires operate); linked from a task's
    # Steps page (trajectory.html) rather than the sidebar.
    {
        "path": "/redact",
        "label": "Redaction check",
        "group": "Govern",
        "icon": "shield",
        "floor": "view",
        "default": "operate",
        "in_nav": False,
    },
    {
        # Its route requires audit permission.
        "path": "/safety",
        "label": "Safety",
        "group": "Govern",
        "icon": "shield",
        "floor": "audit",
        "default": "audit",
    },
    # Privacy / security / AI-risk assessments of every agent & flow: auto-drafted
    # from the declared capability surface, reviewed + signed off, re-assessed on
    # change. Reading is audit-level; drafting/reviewing is admin (mutation API).
    {
        "path": "/assessments",
        "label": "Assessments",
        "group": "Govern",
        "icon": "shield",
        "floor": "audit",
        "default": "audit",
    },
    {
        "path": "/compliance",
        "label": "Compliance",
        "group": "Govern",
        "icon": "compliance",
        "floor": "view",
        "default": "audit",
    },
    {
        "path": "/compliance/grc-studio",
        "label": "Compliance studio",
        "aliases": "workflow builder governance risk compliance studio",
        "group": "Govern",
        "icon": "compliance",
        "floor": "view",
        "default": "operate",
        "module": "tech_risk_compliance.grc_studio",
        "in_nav": True,
    },
    {
        "path": "/compliance/policy-links",
        "label": "Policy links",
        "aliases": "Policy Publication Links",
        "group": "Govern",
        "icon": "compliance",
        "floor": "operate",
        "default": "operate",
        "module": "tech_risk_compliance.policy_publication_links",
        "in_nav": False,
    },
    {
        "path": "/compliance/scoping",
        "label": "Find which controls apply",
        "aliases": "Compliance Scoping",
        "group": "Govern",
        "icon": "compliance",
        "floor": "operate",
        "default": "operate",
        "module": "tech_risk_compliance.scoping",
        "in_nav": False,
    },
    {
        "path": "/compliance/scope-actions",
        "label": "Turn scope into tasks",
        "aliases": "Compliance Scope Actions",
        "group": "Govern",
        "icon": "compliance",
        "floor": "operate",
        "default": "operate",
        "module": "tech_risk_compliance.scope_actions",
        "in_nav": False,
    },
    {
        "path": "/compliance/scope-actions/mapping",
        "label": "Build a task mapping",
        "group": "Govern",
        "icon": "compliance",
        "floor": "operate",
        "default": "operate",
        "module": ("tech_risk_compliance.scoping", "tech_risk_compliance.scope_actions"),
        "in_nav": False,
    },
    {
        "path": "/compliance/continuous-evidence",
        "label": "Continuous evidence",
        "group": "Govern",
        "icon": "compliance",
        "floor": "operate",
        "default": "operate",
        "module": "tech_risk_compliance.continuous_evidence",
        "in_nav": True,
    },
    # Compliance by construction: what the regulatory compiler turned into
    # live gates, the anti-vacuity proof, and "what happens to this action".
    # Read-only (enforcement is chosen in config), so the view floor is right.
    {
        "path": "/compliance/obligations",
        "label": "Regulations and rules",
        "aliases": "Regulatory Obligations",
        "group": "Govern",
        "icon": "compliance",
        "floor": "view",
        "default": "operate",
        "in_nav": True,
    },
    {
        "path": "/compartments",
        "label": "Compartments",
        "group": "Govern",
        "icon": "compartments",
        "floor": "view",
        "default": "view",
    },
    {
        "path": "/audit",
        "label": "Activity log",
        "aliases": "Audit",
        "group": "Govern",
        "icon": "audit",
        "floor": "audit",
        "default": "audit",
    },
    # Bearer-verifiable evidence: mint a signed receipt for one audit row and
    # verify one offline. Audit floor, like the log it draws from.
    {
        "path": "/audit/receipts",
        "label": "Trust receipts",
        "group": "Govern",
        "icon": "audit",
        "floor": "audit",
        "default": "audit",
        "in_nav": True,
    },
    # Read-only immune-layer evidence: composition risk, oversight catch rates,
    # twin replays and information-flow events. Counts and labels only.
    {
        "path": "/immune",
        "label": "Safety monitoring",
        "aliases": "Immune layer",
        "group": "Govern",
        "icon": "shield",
        "floor": "audit",
        "default": "audit",
        "in_nav": True,
    },
    # Digest-only lifecycle evidence over the durable promotion authority.
    # It is audit-gated like the source evidence, and has no product mutation.
    {
        "path": "/audit/evolution-ledger",
        "label": "Learning history",
        "aliases": "Evolution Ledger",
        "group": "Govern",
        "icon": "learned",
        "floor": "audit",
        "default": "audit",
        "in_nav": True,
    },
    {
        "path": "/replay",
        "label": "Task replay",
        "group": "Govern",
        "icon": "audit",
        "floor": "view",
        "default": "audit",
    },
    {
        "path": "/trust",
        "label": "Agent trust",
        "group": "Govern",
        "icon": "agents",
        "floor": "view",
        "default": "view",
    },
    # Bring-your-own-agent console: enroll + credential + govern agents built
    # on other platforms. Reading the roster is a governance view; every
    # mutation (enroll / mint / revoke) is admin-gated at the API.
    {
        "path": "/external-agents",
        "label": "Outside agents",
        "aliases": "External Agents",
        "group": "AI oversight",
        "icon": "agents",
        "floor": "view",
        "default": "view",
        "module": "external_agents",
    },
    # -- Extend ---------------------------------------------------------------
    {
        "path": "/skills",
        "label": "Skills",
        "group": "Extend",
        "icon": "skills",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/store",
        "label": "Skill store",
        "group": "Extend",
        "icon": "store",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/templates",
        "label": "Templates",
        "group": "Extend",
        "icon": "templates",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/tools",
        "label": "Tools",
        "group": "Extend",
        "icon": "tools",
        "floor": "view",
        "default": "operate",
    },
    # Connections hold live SaaS credentials/tokens, so managing them is admin
    # plumbing, not an everyday operator surface. Builders still *reference* an
    # existing connection by name in a flow (GET /api/v1/connections stays
    # operate-readable); only create/rotate/delete/test are admin-gated.
    {
        "path": "/connections",
        "label": "Connections",
        "group": "Admin",
        "icon": "key",
        "floor": "admin",
        "default": "admin",
        "module": "connections",
    },
    {
        # Its route requires an installation administrator.
        "path": "/plugins",
        "scope": "global",
        "label": "Plugins",
        "group": "Advanced tools",
        "icon": "plugins",
        "floor": "admin",
        "default": "admin",
    },
    # Output-style customization: mutations are operate-gated, so it lives with
    # the other operator-facing extension surfaces, not admin plumbing.
    {
        "path": "/styles",
        "label": "Response styles",
        "aliases": "Output styles",
        "group": "Extend",
        "icon": "roles",
        "floor": "view",
        "default": "operate",
    },
    {
        "path": "/mcp",
        "scope": "global",
        "label": "Tool servers",
        "group": "Advanced tools",
        "icon": "mcp",
        "floor": "admin",
        "default": "admin",
    },
    {
        "path": "/channels",
        "scope": "global",
        "label": "Channels",
        "group": "Extend",
        "icon": "channels",
        "floor": "admin",
        "default": "admin",
    },
    # -- Admin ----------------------------------------------------------------
    {
        "path": "/administration/document-vault",
        "label": "Document vault",
        "group": "Admin",
        "icon": "shield",
        "floor": "view",
        "default": "admin",
        "module": "governed_document_vault",
        "in_nav": True,
    },
    {
        "path": "/workspace/recovery",
        "scope": "global",
        "label": "Workspace recovery",
        "group": "Admin",
        "icon": "settings",
        "floor": "admin",
        "default": "admin",
    },
    {
        "path": "/settings",
        "scope": "global",
        "label": "Settings",
        "group": "Admin",
        "icon": "settings",
        "floor": "admin",
        "default": "admin",
    },
    {
        "path": "/companion/admin",
        "label": "Employee companions",
        "aliases": "enrollment companion policy retention",
        "group": "Admin",
        "icon": "agents",
        "floor": "admin",
        "default": "admin",
        "scope": "workspace",
    },
    {
        "path": "/users",
        "label": "Users",
        "aliases": "Users & roles",
        "group": "Admin",
        "icon": "users",
        "floor": "admin",
        "default": "admin",
    },
    # Everyone may see and end their own sign-in sessions; administrators
    # see everyone's. Reached from the Users page, not the rail.
    {
        "path": "/settings/sessions",
        "label": "Sessions",
        "aliases": "signed in devices sign out everywhere",
        "group": "Admin",
        "icon": "users",
        "floor": "view",
        "default": "view",
        "in_nav": False,
    },
    {
        "path": "/spending-limits",
        "label": "Spending limits",
        "group": "Admin",
        "icon": "spend",
        "floor": "admin",
        "default": "admin",
    },
    {
        "path": "/tenants",
        "scope": "global",
        "label": "Workspaces",
        "group": "Admin",
        "icon": "tenants",
        "floor": "admin",
        "default": "admin",
    },
    # The workspace picker: which tenant this dashboard works in. Reached from
    # the tenant-gate page (any tenant-scoped workbench opened unbound renders
    # it) and from the Tenants console, so it stays out of the sidebar. Floor
    # is "view" -- every signed-in user may see the current binding; changing
    # it is admin-gated at the API.
    {
        "path": "/workspace/tenant",
        "label": "Choose a workspace",
        "group": "Admin",
        "icon": "tenants",
        "floor": "view",
        "default": "view",
        "in_nav": False,
    },
    {
        "path": "/cache",
        "label": "Cache",
        "group": "Advanced tools",
        "icon": "cache",
        "floor": "view",
        "default": "admin",
    },
    {
        "path": "/embed-demo",
        "label": "Embedded analytics",
        "aliases": "Embed Analytics",
        "group": "Advanced tools",
        "icon": "embed",
        "floor": "view",
        "default": "admin",
    },
    # -- Personal, help and spending pages ------------------------------------
    # Live screens the registry did not know, so the page finder could not
    # offer them. Each floor mirrors the route's own check. Routes that also
    # need a named account (or, for employee activation, its switch) are
    # withheld per request by app._account_pages_unavailable. Reached from
    # their parent pages and the top bar, never the sidebar.
    {"path": "/help", "label": "Help and diagnostics", "group": "Operate",
     "icon": "check", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/notifications", "label": "Your notifications", "group": "Operate",
     "icon": "check", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/my-work", "label": "My background work", "group": "Operate",
     "icon": "target", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/conversations", "label": "My conversations", "group": "Operate",
     "icon": "chat", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/human-conversations", "label": "Human conversations", "group": "Operate",
     "icon": "chat", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/get-started/employee", "label": "Your first useful result", "group": "Operate",
     "icon": "check", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/project-workspaces", "label": "Project workspaces", "group": "Operate",
     "icon": "fleets", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/devices", "label": "Your paired devices", "group": "Operate",
     "icon": "settings", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/access-requests", "label": "Permission requests", "group": "Operate",
     "icon": "key", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/budget", "label": "Your budget", "group": "Observe",
     "icon": "spend", "floor": "view", "default": "view", "in_nav": False},
    {"path": "/cost-reconciliation", "label": "Compare cost records", "group": "Observe",
     "icon": "spend", "floor": "view", "default": "view", "in_nav": False},
    # Its route requires an installation administrator.
    {"path": "/provider-spending", "label": "Provider spending", "group": "Observe",
     "icon": "spend", "floor": "admin", "default": "admin", "scope": "global",
     "in_nav": False},
)

# Moderate sidebar declutter: keep a focused set of everyday destinations in the
# rail; fold the rest OUT of the sidebar (in_nav=False) while leaving them fully
# reachable in-page and by URL. One place to adjust the balance — move a path
# out of this set to bring its tab back. (Pages already in_nav=False in the
# registry above, e.g. builders reached from a parent page, are unaffected.)
_NAV_FOLD: frozenset[str] = frozenset(
    {
        # Operate — reached from Goals / Agent Factory / Workforce
        "/start",
        "/projects",
        "/roles",
        # Observe — analytical/advanced views reached from Overview & friends
        "/discovery",
        "/providers",
        "/benchmarks",
        "/flows/analytics",
        "/walkthroughs",
        "/facts",
        "/plan-tree-3d",
        # Govern — advanced governance surfaces
        "/simulate",
        "/compartments",
        "/replay",
        "/trust",
        # Extend — secondary catalogs
        "/store",
        "/templates",
        "/tools",
        "/styles",
        # Admin — rarely-touched plumbing
        "/cache",
        "/embed-demo",
    }
)
for _pg in PAGES:
    if _pg["path"] in _NAV_FOLD:
        _pg["in_nav"] = False

# Where each page lives in the job-named navigation ("areas", off by default:
# ``[dashboard] navigation``): its area and the section inside that area, kept
# beside the entries above (which other code and tests read whole). One area
# per page; "Account" and "Help" are the account and help menus, and
# "Ask" is the Ask button. Placement only -- who may open a page still comes
# from its floor and default above, never from its area.
PAGE_AREAS: dict[str, tuple[str, str]] = {
    "/my-data": ("Account", "My data"),
    "/account": ("Account", "Your account"),
    "/content-access": ("Evidence & audit", "Content access"),
    "/preferences": ("Account", "Preferences"),
    "/today": ("Home", "Home"),
    "/workflow-readiness": ("Settings", "Setup"),
    "/code": ("Work", "Code changes"),
    "/me": ("Home", "Home"),
    "/outcome-pilots": ("Work", "Workflows"),
    "/commitment-reviews": ("Work", "Promise reviews"),
    "/decision-evidence": ("Work", "Shared decision reviews"),
    "/learning/recheck-rules": ("Agents", "Learning"),
    "/learning/distinctions": ("Agents", "Learning"),
    "/learning/work-restructuring": ("Agents", "Learning"),
    "/learning/portable-rules": ("Agents", "Learning"),
    "/learning/recovery-visibility": ("Agents", "Learning"),
    "/learning/rules-together": ("Agents", "Learning"),
    "/learning/request-program": ("Agents", "Learning"),
    "/learning/applicability": ("Agents", "Learning"),
    "/learning/rule-evolution": ("Agents", "Learning"),
    "/learning/acquisition": ("Agents", "Learning"),
    "/private-task-computation": ("Work", "Tasks"),
    "/research": ("Agents", "Learning"),
    "/project-reviews": ("Work", "Projects"),
    "/deliverable-bundles": ("Work", "Results"),
    "/task-handoffs": ("Work", "Tasks"),
    "/action-center": ("Work", "Approvals"),
    "/start": ("Home", "Home"),
    "/chat": ("Ask", "Ask"),
    "/companion": ("Ask", "My companion"),
    "/goals": ("Work", "Tasks"),
    "/work-details": ("Work", "Business details"),
    "/goal-builder": ("Ask", "Ask"),
    "/graph-editor": ("Work", "Tasks"),
    "/projects": ("Work", "Projects"),
    "/deliverables": ("Work", "Results"),
    "/agents": ("Agents", "Build an agent"),
    "/roles": ("Agents", "Workforce"),
    "/workforce": ("Agents", "Workforce"),
    "/starter-teams": ("Agents", "Workforce"),
    "/workflows": ("Work", "Workflows"),
    "/flows/designer": ("Work", "Workflows"),
    "/workflow-builder": ("Work", "Workflows"),
    "/automations": ("Work", "Automations"),
    "/fleets": ("Agents", "Workforce"),
    "/overview": ("Home", "Home"),
    "/ekko": ("Agents", "Discover work to automate"),
    "/oversight": ("Rules & safety", "Overview"),
    "/discovery": ("Rules & safety", "What Lightwork can do"),
    "/run-tree": ("Evidence & audit", "Task replay"),
    "/spend": ("Costs & value", "Spend"),
    "/savings": ("Costs & value", "Savings"),
    "/work-value": ("Costs & value", "Work value & opportunities"),
    "/shoring": ("Work", "Hand over a team's work"),
    "/billing": ("Costs & value", "Billing"),
    "/providers": ("Settings", "AI providers"),
    "/settings/local-ai": ("Settings", "AI providers"),
    "/settings/security-installation": ("Settings", "Advanced"),
    "/benchmarks": ("Settings", "Advanced"),
    "/perf": ("Settings", "Advanced"),
    "/flows/analytics": ("Work", "Workflows"),
    "/cortex": ("Agents", "Knowledge"),
    "/knowledge-access": ("Agents", "Knowledge"),
    "/learning": ("Agents", "Learning"),
    "/learning/approval-challenges": ("Agents", "Learning"),
    "/learning/instructions": ("Agents", "Learning"),
    "/learned": ("Agents", "Learning"),
    "/walkthroughs": ("Evidence & audit", "Task replay"),
    "/facts": ("Agents", "Knowledge"),
    "/plan-tree-3d": ("Work", "Tasks"),
    "/autonomous-compliance": ("Risk & compliance", "Compliance"),
    "/approvals": ("Work", "Approvals"),
    "/agent-control-plane": ("Rules & safety", "Agent controls"),
    "/privacy": ("Privacy", "Overview"),
    "/privacy/data-discovery": ("Privacy", "Find personal data"),
    "/privacy/regulatory-intelligence": ("Privacy", "Law research"),
    "/privacy/rights-orchestration": ("Privacy", "Requests"),
    "/privacy/rights-consumer-delivery": ("Privacy", "Requests"),
    "/privacy/notice-governance": ("Privacy", "Notices"),
    "/consent": ("Privacy", "Consent"),
    "/consent/publishing": ("Privacy", "Consent"),
    "/consent/experiments": ("Privacy", "Consent"),
    "/consent/delivery": ("Privacy", "Consent"),
    "/consent/public-clients": ("Privacy", "Consent"),
    "/consent/native": ("Privacy", "Consent"),
    "/consent/profile-data": ("Privacy", "Consent"),
    "/consent/custom-indexes": ("Privacy", "Consent"),
    "/consent/bulk-jobs": ("Privacy", "Consent"),
    "/consent/publish-settings": ("Privacy", "Consent"),
    "/consent/global-opt-out": ("Privacy", "Consent"),
    "/consent/application-scans": ("Privacy", "Consent"),
    "/consent/scan-inventory": ("Privacy", "Consent"),
    "/consent/scan-notice-proposals": ("Privacy", "Consent"),
    "/consent/trust-center-authority": ("Privacy", "Consent"),
    "/data-use": ("Privacy", "Data use rules"),
    "/data-use/providers": ("Privacy", "Data use rules"),
    "/governance-agents": ("Risk & compliance", "AI risk"),
    "/governance/inventory": ("Risk & compliance", "AI risk"),
    "/ai-evidence-analysis": ("Risk & compliance", "Assessments"),
    "/assess/evidence-autopopulation": ("Risk & compliance", "Assessments"),
    "/ai-entity-tasks": ("Risk & compliance", "AI risk"),
    "/privacy/drop": ("Privacy", "Requests"),
    "/security": ("Risk & compliance", "Security"),
    "/third-party/vendor-onboarding": ("Risk & compliance", "Vendors"),
    "/third-party/contracts": ("Risk & compliance", "Vendors"),
    "/third-party/executive-reports": ("Risk & compliance", "Vendors"),
    "/third-party/intelligence": ("Risk & compliance", "Vendors"),
    "/third-party/lifecycle": ("Risk & compliance", "Vendors"),
    "/third-party/collaboration": ("Risk & compliance", "Vendors"),
    "/security/threats": ("Risk & compliance", "Security"),
    "/security/soc": ("Risk & compliance", "Security"),
    "/security/report": ("Risk & compliance", "Security"),
    "/security/assurance": ("Risk & compliance", "AI risk"),
    "/security/governance": ("Risk & compliance", "AI risk"),
    "/finance": ("Risk & compliance", "Financial controls"),
    "/partner": ("Settings", "Partner fleet"),
    "/permissions": ("Rules & safety", "What Lightwork can do"),
    "/simulate": ("Rules & safety", "Test a rule"),
    "/redact": ("Rules & safety", "Redaction check"),
    "/safety": ("Rules & safety", "Screening"),
    "/assessments": ("Risk & compliance", "Assessments"),
    "/compliance": ("Risk & compliance", "Compliance"),
    "/compliance/grc-studio": ("Risk & compliance", "Compliance"),
    "/compliance/policy-links": ("Risk & compliance", "Compliance"),
    "/compliance/scoping": ("Risk & compliance", "Compliance"),
    "/compliance/scope-actions": ("Risk & compliance", "Compliance"),
    "/compliance/scope-actions/mapping": ("Risk & compliance", "Compliance"),
    "/compliance/continuous-evidence": ("Risk & compliance", "Compliance"),
    "/compliance/obligations": ("Rules & safety", "Regulations and rules"),
    "/compartments": ("Rules & safety", "What Lightwork can do"),
    "/audit": ("Evidence & audit", "Activity log"),
    "/audit/receipts": ("Evidence & audit", "Trust receipts"),
    "/immune": ("Rules & safety", "Safety monitoring"),
    "/audit/evolution-ledger": ("Evidence & audit", "Learning history"),
    "/replay": ("Evidence & audit", "Task replay"),
    "/trust": ("Rules & safety", "Outside agents"),
    "/external-agents": ("Rules & safety", "Outside agents"),
    "/skills": ("Agents", "Skills"),
    "/store": ("Agents", "Skills"),
    "/templates": ("Ask", "Start from a template"),
    "/tools": ("Agents", "Tools"),
    "/connections": ("Settings", "Connections"),
    "/plugins": ("Agents", "Tools"),
    "/styles": ("Agents", "Response styles"),
    "/mcp": ("Agents", "Tools"),
    "/channels": ("Settings", "Chat apps"),
    "/administration/document-vault": ("Evidence & audit", "Document vault"),
    "/workspace/recovery": ("Settings", "Backup & recovery"),
    "/settings": ("Settings", "General"),
    "/companion/admin": ("Settings", "People & roles"),
    "/users": ("Settings", "People & roles"),
    "/settings/sessions": ("Account", "Sessions"),
    "/spending-limits": ("Costs & value", "Spending limits"),
    "/tenants": ("Settings", "Workspaces"),
    "/workspace/tenant": ("Settings", "Workspaces"),
    "/cache": ("Settings", "Advanced"),
    "/embed-demo": ("Settings", "Advanced"),
    "/help": ("Help", "Help & diagnostics"),
    "/notifications": ("Account", "Notifications"),
    "/my-work": ("Work", "Tasks"),
    "/conversations": ("Ask", "Conversations"),
    "/human-conversations": ("Ask", "Conversations"),
    "/get-started/employee": ("Home", "Home"),
    "/project-workspaces": ("Work", "Projects"),
    "/devices": ("Account", "Devices"),
    "/access-requests": ("Account", "Permission requests"),
    "/budget": ("Costs & value", "Budget"),
    "/cost-reconciliation": ("Costs & value", "Compare cost records"),
    "/provider-spending": ("Costs & value", "Provider spending"),
}
_PAGES_BY_PATH = {p["path"]: p for p in PAGES}

# What people see for each registry group. The short keys stay stable because
# they also key each browser's remembered open/closed sidebar sections.
GROUP_TITLES: dict[str, str] = {
    "Operate": "Work",
    "Observe": "Insights",
    "Govern": "Governance",
    "Admin": "Administration",
    "Extend": "Library",
}


def group_title(group: str) -> str:
    """The sidebar, finder and Settings title for a registry group."""
    return GROUP_TITLES.get(group, group)

# What the page finder (Ctrl+K) matches beyond a page's label. HEADINGS holds
# a page's own heading where it differs from the label, so typing the words a
# person reads on the page finds it. SYNONYMS holds the plain words people
# type for a job ("approve" -> Approvals). The finder ranks an exact label,
# then an exact heading, then an exact synonym first (see
# static/lightwork-navfinder.js). Neither ever changes who can see a page.
HEADINGS: dict[str, str] = {
    "/budget": "Your budget before work starts",
    "/companion": "Your companion",
    "/companion/admin": "Companion policies",
}
SYNONYMS: dict[str, tuple[str, ...]] = {
    "/approvals": ("approve", "approval", "decision", "decisions", "decide", "sign-off", "sign off"),
    # Agent controls holds the emergency stop and resume controls, and every
    # role that can find it can open it.
    "/agent-control-plane": ("pause", "stop", "emergency stop", "halt", "stop all work", "resume work"),
    "/billing": ("invoice", "invoices", "bill", "bills"),
    "/spend": ("cost", "costs", "spending"),
    "/help": ("help", "docs", "documentation", "support"),
    # The Activity log is also where activity is downloaded for auditors.
    "/audit": ("audit log", "history", "export"),
    "/privacy/rights-orchestration": (
        "dsar", "data subject request", "data subject access request", "rights request",
    ),
    "/users": ("invite", "people", "colleague", "colleagues", "add user", "members", "team members"),
    "/notifications": ("notification", "notifications", "alerts"),
    # Security & GRC keeps the incident register; Privacy keeps breaches.
    "/security": ("incident", "incidents", "security incident"),
    "/privacy": ("breach", "data breach"),
    # The sidebar's "New task" button opens Chat.
    "/chat": ("new task", "start a task", "new chat", "ask"),
    "/get-started/employee": ("get started", "first task"),
    "/conversations": ("chats", "chat history", "past chats"),
    "/access-requests": ("request access", "ask for permission"),
    "/shoring": ("hand a team's work", "hand over a team's work"),
}

# The sidebar's "Pinned pages" for someone who has not chosen any yet: a
# starting set for their role, in order. Defaults only -- the first change a
# person makes saves their own list -- and a page the person cannot open is
# never offered (see pin_preset). "approver" and "privacy-officer" are the
# names the Users page derives for those custom roles; any other custom role
# starts from the preset its name or strongest permission suggests.
PIN_PRESETS: dict[str, tuple[str, ...]] = {
    "admin": ("/settings", "/users", "/audit"),
    "operator": ("/goals", "/approvals", "/deliverables"),
    "approver": ("/approvals", "/goals", "/deliverables"),
    "privacy-officer": ("/privacy/rights-orchestration", "/privacy"),
    "auditor": ("/audit", "/audit/receipts", "/assessments"),
    "viewer": ("/deliverables", "/overview"),
}
_PRESET_BY_PERMISSION = (("admin", "admin"), ("operate", "operator"), ("audit", "auditor"), ("view", "viewer"))


def pin_preset(role: str | None, allowed) -> list[str]:
    """The starting pins for ``role``: the first preset that offers at least
    one page in ``allowed`` (the pages the person may open), keeping only
    those pages. A role's own preset comes first, then one its name suggests,
    then one for its strongest permission."""
    if not role:
        return []
    names = [role] if role in PIN_PRESETS else []
    names += [name for word, name in (("privacy", "privacy-officer"), ("approv", "approver")) if word in role]
    held = rbac.permissions_for(role)
    names += [name for permission, name in _PRESET_BY_PERMISSION if permission in held]
    for name in names:
        pages = [path for path in PIN_PRESETS[name] if path in allowed]
        if pages:
            return pages
    return []


# The job-named navigation ("areas" mode, ``[dashboard] navigation``): each
# area's title (also its sidebar entry), its hub page, and its sections in
# order. A page's area and section come from PAGE_AREAS. Ask is the Ask
# button; Account and Help are the account and help menus, not sidebar areas.
AREAS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Ask", "/chat", ("Ask", "Conversations", "Start from a template", "My companion")),
    ("Home", "/today", ("Home",)),
    ("Work", "/goals", ("Tasks", "Business details", "Approvals", "Results", "Projects", "Workflows", "Automations",
                        "Code changes", "Promise reviews", "Shared decision reviews",
                        "Hand over a team's work")),
    ("Agents", "/workforce", ("Workforce", "Build an agent", "Skills", "Tools", "Knowledge", "Learning",
                              "Discover work to automate", "Response styles")),
    ("Rules & safety", "/oversight", ("Overview", "Agent controls", "What Lightwork can do", "Screening",
                                      "Safety monitoring", "Outside agents", "Test a rule", "Redaction check",
                                      "Regulations and rules")),
    ("Privacy", "/privacy", ("Overview", "Requests", "Find personal data", "Notices", "Consent",
                             "Data use rules", "Law research")),
    ("Risk & compliance", "/compliance", ("Compliance", "Assessments", "Security", "Financial controls",
                                          "AI risk", "Vendors")),
    ("Evidence & audit", "/audit", ("Activity log", "Task replay", "Trust receipts", "Learning history",
                                    "Document vault", "Content access")),
    ("Costs & value", "/spend", ("Spend", "Work value & opportunities", "Savings", "Billing", "Budget", "Provider spending",
                                 "Compare cost records", "Spending limits")),
    ("Settings", "/settings", ("General", "Setup", "AI providers", "Connections", "Chat apps", "People & roles",
                               "Workspaces", "Backup & recovery", "Partner fleet", "Advanced")),
    ("Account", "/account", ("Your account", "Preferences", "Notifications", "Devices", "Sessions", "My data",
                             "Permission requests")),
    ("Help", "/help", ("Help & diagnostics",)),
)
SIDEBAR_AREAS: tuple[str, ...] = ("Home", "Work", "Agents", "Rules & safety", "Privacy", "Risk & compliance",
                                  "Evidence & audit", "Costs & value", "Settings")
_AREA_BY_TITLE = {title: (hub, sections) for title, hub, sections in AREAS}

# Starting layouts per role (report section 5): the order of the sidebar's
# areas, which areas start open, the start page, and sections moved to the
# front of an area, and the order of Home's views (its page tabs: Today, My
# work, Overview) -- the workforce snapshot comes before personal work for an
# administrator. Defaults only -- floors still decide what anyone sees,
# and each person can reorder, hide and pin. Areas a preset does not name
# follow in the standard order.
_HOME_PERSONAL = ("/today", "/me", "/overview")
AREA_PRESETS: dict[str, dict] = {
    "employee": {"order": ("Home", "Work", "Agents"), "open": ("Work",), "start": "/home",
                 "home": _HOME_PERSONAL},
    "approver": {"order": ("Home", "Work", "Rules & safety", "Evidence & audit"), "open": ("Work",),
                 "start": "/approvals", "first": {"Work": ("Approvals",)}, "home": _HOME_PERSONAL},
    "privacy-officer": {"order": ("Home", "Work", "Privacy", "Risk & compliance", "Evidence & audit"),
                        "open": ("Privacy",), "start": "/privacy", "home": _HOME_PERSONAL},
    "admin": {"order": SIDEBAR_AREAS, "open": ("Work", "Settings"), "start": "/home",
              "home": ("/today", "/overview", "/me")},
}
_AREA_PRESET_BY_PERMISSION = (("admin", "admin"), ("operate", "employee"), ("audit", "approver"),
                              ("view", "employee"))


def area_preset_name(role: str | None) -> str:
    """The starting layout for ``role``: its own name, one its name suggests
    ("privacy", "approv"), then its strongest permission. Auth off (the local
    owner, who sees everything) starts from the administrator's layout."""
    if role is None:
        return "admin"
    if role in AREA_PRESETS:
        return role
    for word, name in (("privacy", "privacy-officer"), ("approv", "approver")):
        if word in role:
            return name
    held = rbac.permissions_for(role) if role else set()
    for permission, name in _AREA_PRESET_BY_PERMISSION:
        if permission in held:
            return name
    return "employee"


# Pages that open their section even though their name differs from it:
# the everyday job comes before the rarer one ("Privacy requests" before
# "California DROP requests"; "AI governance" before its workbenches).
SECTION_LEADS = frozenset({"/privacy/rights-orchestration", "/security/governance"})


def section_lead(hub: str, section: str):
    """Sort key for a section's pages: the area's hub first, then a section
    lead, the page named like the section, then pages the classic sidebar
    lists."""
    def key(link: dict) -> tuple[bool, bool, bool, bool]:
        return (link["href"] != hub, link["href"] not in SECTION_LEADS,
                link["label"].casefold() != section.casefold(),
                not _PAGES_BY_PATH[link["href"]].get("in_nav", True))
    return key


def _area_sections(title: str, pages: list[dict], first: tuple[str, ...], lead: tuple[str, ...] = ()) -> list[dict]:
    hub, order = _AREA_BY_TITLE[title]
    order = (*first, *(name for name in order if name not in first))
    sections: dict[str, list[dict]] = {name: [] for name in order}
    for link in pages:
        sections.setdefault(link["section"], []).append(link)
    result = []
    for name, links in sections.items():
        if not links:
            continue
        links.sort(key=section_lead(hub, name))
        # The preset's own order for these pages comes first (Home's views).
        links.sort(key=lambda link: lead.index(link["href"]) if link["href"] in lead else len(lead))
        result.append({"title": name, "href": links[0]["href"], "links": links,
                       "off": all(link.get("off") for link in links)})
    return result


def area_nav(
    finder: list[dict], role: str | None, *, off: frozenset[str] = frozenset(), can_turn_on: bool = False,
    layout: list[str] | None = None,
) -> dict:
    """The areas navigation built from ``finder`` (``finder_pages`` after the
    request's own filtering): only pages the viewer may already open, so an
    area with nothing for them is left out. A page whose module is switched
    off is dropped, or marked ``off`` for someone who can turn it on -- the
    sidebar's rule. ``layout`` is the person's own order of sidebar areas
    (areas left out are hidden); without one, the role's preset applies."""
    preset_name = area_preset_name(role)
    preset = AREA_PRESETS[preset_name]
    by_area: dict[str, list[dict]] = {}
    for group in finder:
        for link in group["links"]:
            spot = PAGE_AREAS.get(link["href"])
            if spot is None or (link["href"] in off and not can_turn_on):
                continue
            by_area.setdefault(spot[0], []).append(
                {**link, "area": spot[0], "section": spot[1], "off": link["href"] in off})
    areas = []
    for title, hub, _sections in AREAS:
        if title not in by_area:
            continue
        sections = _area_sections(title, by_area[title], preset.get("first", {}).get(title, ()),
                                  preset["home"] if title == "Home" else ())
        hrefs = [link["href"] for section in sections for link in section["links"]]
        areas.append({"title": title, "hub": hub, "href": hub if hub in hrefs else hrefs[0],
                      "open": title in preset["open"], "sections": sections,
                      "sidebar": title in SIDEBAR_AREAS})
    order = list(layout) if layout else [*preset["order"], *SIDEBAR_AREAS]
    rank = {title: index for index, title in reversed(list(enumerate(order)))}
    sidebar = sorted((area for area in areas if area["sidebar"] and area["title"] in rank),
                     key=lambda area: rank[area["title"]])
    return {"preset": preset_name, "start": preset["start"], "sidebar": sidebar,
            "by_title": {area["title"]: area for area in areas}}


def place(path: str) -> tuple[str, str] | None:
    """The (area, section) of the registry page governing ``path``."""
    page = page_for(path)
    return PAGE_AREAS.get(page["path"]) if page else None


# Areas reached from the top bar's menus rather than the sidebar.
_TOP_BAR_AREAS = frozenset({"Account", "Help"})


def parent_candidates(path: str) -> tuple[str, ...]:
    """Sidebar pages a page kept out of the sidebar (``in_nav: False``) sits
    under, best first: sidebar pages of its own area section, its area's hub,
    other sidebar pages of its area, then of its sidebar group. Empty for a
    page that is itself in the sidebar or unregistered."""
    page = _PAGES_BY_PATH.get(path)
    if page is None or page.get("in_nav", True):
        return ()
    shown = [p for p in PAGES if p.get("in_nav", True) and p["path"] != path]
    spot = PAGE_AREAS.get(path)
    found: list[str] = []
    if spot is not None:
        found += [p["path"] for p in shown if PAGE_AREAS.get(p["path"]) == spot]
        hub = _AREA_BY_TITLE.get(spot[0], ("",))[0]
        found += [hub] if any(p["path"] == hub for p in shown) else []
        found += [p["path"] for p in shown if PAGE_AREAS.get(p["path"], ("",))[0] == spot[0]]
    found += [p["path"] for p in shown if p["group"] == page["group"]]
    return tuple(dict.fromkeys(found))


def where(path: str, groups: list[dict], finder: list[dict]) -> dict | None:
    """Where a page kept out of the sidebar sits, for the sidebar highlight and
    the breadcrumb: its first parent this person's sidebar shows, and the page
    itself, each as ``{href, label}``. None for a sidebar page."""
    page = page_for(path)
    if page is None:
        return None
    visible = {link["href"]: link for group in groups for link in group["links"]}
    pages = {link["href"]: link for group in finder for link in group["links"]}
    here = pages.get(page["path"])
    spot = PAGE_AREAS.get(page["path"])
    if spot is not None and spot[0] in _TOP_BAR_AREAS:
        # Account and Help pages sit under their menu in the top bar, not the
        # sidebar: the breadcrumb leads to the area's own first page.
        hub = _AREA_BY_TITLE[spot[0]][0]
        parent, in_sidebar = (pages.get(hub) if hub != page["path"] else None), False
    else:
        parent = next((visible[href] for href in parent_candidates(page["path"]) if href in visible), None)
        in_sidebar = True
    if parent is None or here is None:
        return None
    return {"parent": {"href": parent["href"], "label": parent["label"]}, "sidebar": in_sidebar,
            "page": {"href": here["href"], "label": here["label"]}, "exact": path == page["path"]}


# Lockout guard: the pages an admin needs to *undo* a bad matrix save. Always
# visible + reachable for the admin role, no matter what the store says.
LOCKED = frozenset({("/settings", "admin"), ("/users", "admin")})

# Serializes the store's load-modify-save in-process; cross_process_lock in
# _locked() extends it across processes (multiple dashboard workers).
_VIS_LOCK = threading.Lock()


def _locked(path: Path):
    from contextlib import ExitStack

    from maverick.file_lock import cross_process_lock

    with ExitStack() as stack:
        stack.enter_context(_VIS_LOCK)
        stack.enter_context(cross_process_lock(path))
        return stack.pop_all()


def store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-ui-visibility.json"


def overrides() -> dict[str, dict[str, bool]]:
    """Validated ``{path: {role: bool}}`` admin overrides (diffs from default).

    Re-validated on read so a hand-edited / corrupt store can't inject an
    unknown page, an unknown role, or a non-bool value.
    """
    p = store_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, dict[str, bool]] = {}
    for path, cells in data.items():
        if path not in _PAGES_BY_PATH or not isinstance(cells, dict):
            continue
        clean = {role: v for role, v in cells.items() if rbac.is_known_role(role) and isinstance(v, bool)}
        if clean:
            out[path] = clean
    return out


def _write(data: dict[str, dict[str, bool]]) -> None:
    from maverick.file_lock import atomic_write_text

    atomic_write_text(store_path(), json.dumps(data, indent=2, sort_keys=True))


def clear_overrides() -> None:
    """Reset every page to its default visibility."""
    with _locked(store_path()):
        from .settings_audit import current_write

        change = current_write()
        if change is not None:
            change.prepare(overrides(), {})
        _write({})
        if change is not None:
            change.complete()


def _permission(page: dict, kind: str) -> str:
    # Self-service opens only the page shell. Native APIs still enforce own
    # account, approved fixed scopes and admin-only application management.
    if page["path"] == "/connections":
        from maverick.connection_oauth import self_connect_profiles
        if self_connect_profiles():
            return "operate"
    return page[kind]


def eligible(page: dict, role: str) -> bool:
    """Whether ``role``'s permissions reach the page's security floor at all."""
    return _permission(page, "floor") in rbac.permissions_for(role)


def default_visible(page: dict, role: str) -> bool:
    """The page's out-of-the-box visibility for ``role`` (no overrides)."""
    return _permission(page, "default") in rbac.permissions_for(role)


def is_visible(page: dict, role: str | None) -> bool:
    """Whether ``role`` sees (and may load) ``page``.

    ``None`` = auth off = single-user local mode: always visible. Otherwise:
    locked pages are always visible to their locked role; a role that lacks
    the floor permission never sees the page; else the admin override wins,
    falling back to the default.
    """
    if role is None:
        return True
    if (page["path"], role) in LOCKED:
        return True
    if not eligible(page, role):
        return False
    cell = overrides().get(page["path"], {}).get(role)
    if cell is not None:
        return cell
    return default_visible(page, role)


def set_visibility(path: str, role: str, visible: bool) -> None:
    """Set one page x role cell (stored only when it differs from the default).

    Raises ``ValueError`` for an unknown page/role, a locked cell, or an
    attempt to show a page past the role's security floor.
    """
    page = _PAGES_BY_PATH.get(path)
    if page is None:
        raise ValueError("unknown page")
    if not rbac.is_known_role(role):
        raise ValueError("unknown role")
    if (path, role) in LOCKED:
        raise ValueError("this page is always available to admins")
    if visible and not eligible(page, role):
        raise ValueError("role permissions do not reach this page")
    with _locked(store_path()):
        data = overrides()
        if visible == default_visible(page, role):
            cells = data.get(path)
            if cells:
                cells.pop(role, None)
                if not cells:
                    data.pop(path, None)
        else:
            data.setdefault(path, {})[role] = visible
        _write(data)


def apply_selection(checked: set[str]) -> None:
    """Persist a full Settings-matrix submission in one write.

    ``checked`` holds ``"role:path"`` tokens for every ticked checkbox; every
    eligible, unlocked cell absent from it is hidden. Only differences from
    the defaults are stored, so a later release's default changes still flow
    through un-overridden cells.
    """
    data: dict[str, dict[str, bool]] = {}
    for page in PAGES:
        if not customer_ready(page):
            continue  # not in the matrix, so never "absent" from a submission
        for role in rbac.known_roles():
            if (page["path"], role) in LOCKED or not eligible(page, role):
                continue
            visible = f"{role}:{page['path']}" in checked
            if visible != default_visible(page, role):
                data.setdefault(page["path"], {})[role] = visible
    with _locked(store_path()):
        from .settings_audit import current_write

        change = current_write()
        if change is not None:
            change.prepare(overrides(), data)
        _write(data)
        if change is not None:
            change.complete()


def page_for(path: str) -> dict | None:
    """The registry page governing ``path`` (exact or longest segment-prefix
    match, so ``/goals/3/plan`` follows ``/goals``), or None if unregistered."""
    best = None
    for p in PAGES:
        root = p["path"]
        if path == root or path.startswith(root + "/"):
            if best is None or len(root) > len(best["path"]):
                best = p
    return best


def customer_ready(page: dict) -> bool:
    """False for a registered page marked ``ready: False``: governed and
    reachable by URL, but offered on no customer surface (sidebar, finder,
    Settings matrix)."""
    return page.get("ready", True) is not False


def not_ready_paths() -> frozenset[str]:
    """Registered paths held back from every customer surface."""
    return frozenset(p["path"] for p in PAGES if not customer_ready(p))


def page_modules(page: dict) -> tuple[str, ...]:
    """The in-app module switches (api._MODULE_SWITCHES keys) behind a page.

    A page with a ``module`` is a "...is turned off" dead end while its switch is
    off; a page built from several switches is one only while every switch is.
    """
    modules = page.get("module") or ()
    return (modules,) if isinstance(modules, str) else tuple(modules)


def switched_off_paths(enabled) -> frozenset[str]:
    """Registry pages whose module switch is off, given ``enabled(section)``.

    Runs on every page render, so each switch is asked about once.
    """
    known: dict[str, bool] = {}

    def on(module: str) -> bool:
        if module not in known:
            known[module] = bool(enabled(module))
        return known[module]

    return frozenset(path for path, modules in _MODULE_PAGES if not any(on(m) for m in modules))


_MODULE_PAGES: tuple[tuple[str, tuple[str, ...]], ...] = tuple(
    (page["path"], page_modules(page)) for page in PAGES if page_modules(page)
)


def mark_switched_off(groups: list[dict], off: frozenset[str], *, can_turn_on: bool) -> None:
    """Keep the sidebar free of dead ends, in place.

    Someone who can turn modules on (a global administrator) keeps each link,
    marked ``off`` so the page says what to do; everyone else, who could only
    reach a "...is turned off" page, does not get the link at all.
    """
    for group in groups:
        if can_turn_on:
            for link in group["links"]:
                link["off"] = link["href"] in off
        else:
            group["links"] = [link for link in group["links"] if link["href"] not in off]
    groups[:] = [group for group in groups if group["links"]]


def nav_groups(
    role: str | None, *, scope_roles: dict[str, str | None] | None = None,
) -> list[dict]:
    """The sidebar nav for ``role``: ``[{label, links: [{href, label, icon}]}]``.

    Pages the role doesn't see are dropped; a group with nothing left is
    dropped whole. ``role=None`` (auth off) returns the full nav. Pages marked
    ``in_nav: False`` stay governed but never render a sidebar entry.
    """
    return _grouped_links(role, include_folded=False, scope_roles=scope_roles)


def finder_pages(
    role: str | None, *, scope_roles: dict[str, str | None] | None = None,
) -> list[dict]:
    """The page finder's index for ``role``, shaped exactly like ``nav_groups``.

    Same RBAC / lockout / admin-override resolution as the sidebar, but
    ``in_nav`` is ignored: pages folded out of the rail (reached in-page or by
    URL) are still destinations the role may open, so they must be searchable.
    """
    return _grouped_links(role, include_folded=True, scope_roles=scope_roles)


def _grouped_links(
    role: str | None, *, include_folded: bool,
    scope_roles: dict[str, str | None] | None = None,
) -> list[dict]:
    ov = overrides() if role is not None or scope_roles else {}
    groups: list[dict] = []
    # Groups follow the sidebar's order; a group reached only through folded
    # pages follows them, so the finder never reorders the sidebar's groups.
    sidebar_order: dict[str, int] = {}
    for page in PAGES:
        if not customer_ready(page):
            continue
        if not include_folded and not page.get("in_nav", True):
            continue
        page_role = (scope_roles or {}).get(page.get("scope", "workspace"), role)
        if page_role is not None:
            if (page["path"], page_role) not in LOCKED:
                if not eligible(page, page_role):
                    continue
                cell = ov.get(page["path"], {}).get(page_role)
                shown = cell if cell is not None else default_visible(page, page_role)
                if not shown:
                    continue
        # Merge by group label (first-seen order), not adjacency: a page whose
        # group differs from its list neighbours (e.g. an entry re-homed to
        # Admin) must join its group, not split it into a duplicate section.
        if page.get("in_nav", True):
            sidebar_order.setdefault(page["group"], len(sidebar_order))
        for g in groups:
            if g["label"] == page["group"]:
                break
        else:
            g = {"label": page["group"], "title": group_title(page["group"]), "links": []}
            groups.append(g)
        g["links"].append(
            {
                "href": page["path"],
                "label": page["label"],
                "icon": page["icon"],
                "aliases": page.get("aliases", ""),
                "heading": HEADINGS.get(page["path"], ""),
                "synonyms": SYNONYMS.get(page["path"], ()),
            }
        )
    # Technical setup and diagnostics stay discoverable after everyday work.
    return sorted(groups, key=lambda group: (group["label"] == "Advanced tools",
                                             sidebar_order.get(group["label"], len(sidebar_order))))


def matrix() -> list[dict]:
    """The Settings-page editing matrix, grouped like the nav.

    Each page row carries one cell per role (``rbac.known_roles()`` order:
    builtins most-privileged first, then custom roles by name):
    ``eligible`` (permissions reach the floor), ``visible`` (resolved), and
    ``locked`` (lockout-guarded admin cell).
    """
    ov = overrides()
    roles = rbac.known_roles()
    groups: list[dict] = []
    for page in PAGES:
        if not customer_ready(page):
            continue
        cells = []
        for role in roles:
            locked = (page["path"], role) in LOCKED
            el = eligible(page, role)
            cell = ov.get(page["path"], {}).get(role)
            visible = (
                True
                if locked
                else (el and (cell if cell is not None else default_visible(page, role)))
            )
            cells.append({"role": role, "eligible": el, "visible": visible, "locked": locked})
        # Merge by group label like nav_groups (see comment there).
        for g in groups:
            if g["label"] == page["group"]:
                break
        else:
            g = {"label": page["group"], "title": group_title(page["group"]), "pages": []}
            groups.append(g)
        g["pages"].append(
            {
                "path": page["path"],
                "label": page["label"],
                "floor": _permission(page, "floor"),
                "in_nav": page.get("in_nav", True),
                "cells": cells,
            }
        )
    return groups


__all__ = [
    "PAGES",
    "GROUP_TITLES",
    "LOCKED",
    "store_path",
    "overrides",
    "clear_overrides",
    "eligible",
    "default_visible",
    "is_visible",
    "set_visibility",
    "apply_selection",
    "page_for",
    "page_modules",
    "group_title",
    "mark_switched_off",
    "nav_groups",
    "finder_pages",
    "matrix",
    "switched_off_paths",
    "HEADINGS",
    "SYNONYMS",
    "PIN_PRESETS",
    "pin_preset",
]
