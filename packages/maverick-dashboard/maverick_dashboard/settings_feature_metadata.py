"""Shared metadata for the native product switches and their reviewed controls."""

FEATURE_DEFAULTS = {
    "employee_content_access_requests": False,
    "personal_data_controls": False,
    "permission_access_requests": False,
    "employee_departures": False,
    "employee_companions": False,
    "workflow_readiness": True,
    "project_reviews": False,
    "deliverable_bundles": False,
    "project_workspaces": False,
    "task_handoffs": False,
    "human_conversation_handoffs": False,
    "outcome_measurement": False,
    "commitment_viability": False,
    "commitment_capability_learning": False,
    "semantic_rule_reuse": False,
    "procedure_interactions": False,
    "operational_competence_acquisition": False,
    "request_program": False,
    "commitment_economic_alternatives": False,
    "workflow_step_checks": False,
    "applicability_regions": False,
    "governed_rule_evolution": False,
    "recovery_visibility": False,
    "private_task_computation": False,
    "portable_competence": False,
    "work_restructuring": False,
    "shared_decision_evidence": False,
    "copilot_operations": False,
    "guided_onboarding": True,
    "action_center": True,
    "draft_recovery": True,
    "personal_preferences": True,
    "configuration_profiles": True,
    "employee_task_diagnostics": True,
    "employee_activation": True,
    "support_center": True,
    "record_search": True,
    "workspace_recovery": False,
    "signing_identity_transition": False,
    "skills": True,
    "world_model": True,
    "streaming": True,
    "pack_editing": True,
    "role_editing": True,
    "scheduling": True,
    "triggers": True,
}

FEATURE_INFO = {
    "personal_preferences": "Let people choose their own display, response and workflow defaults within organization policy. Locked settings and permission limits still take precedence.",
    "configuration_profiles": "Review and apply portable preference or settings profiles with a preview of each change. Profiles never transfer credentials or grant permissions.",
    "employee_content_access_requests": "Allow named administrators to request an employee task or subject export, and named operators to request an exact approval-card read. Another administrator or the content owner must approve; reads expire within one hour and are recorded. Reading a card grants no voting authority. Turning this off revokes use of existing grants. Private content remains owner-only by default.",
    "personal_data_controls": "Allow named workspace members to inspect and correct their personal memory, narrow local learning, review My data and verify channel identity links. Linking alone shares nothing; optional cross-channel preferences never grant roles or tools. Disabling stops linked recall; previously saved channel recall restrictions remain enforced.",
    "permission_access_requests": "Let named employees request review of a blocked permission or tool by its actual policy owner. Requests share the employee-provided business reason with reviewers and never grant permissions automatically; completion rechecks the effective policy.",
    "employee_departures": "Allow named installation administrators to preview employee work, revoke Lightwork access, remove reviewed local connection credentials, retire recurring definitions, cancel waiting background work they own and record retained-data handoff owners. Closure needs a fresh inventory and current named responsibility for every item and external obligation. Provider outcomes remain human-attested retained obligations; private-content access never transfers.",
    "employee_companions": (
        "Let workspace administrators enroll employees for a personal companion "
        "with own-task status and optional AI draft conversations. AI drafts "
        "require a separate grant for each employee and send messages, eligible "
        "retained history and permitted own-task titles and status to the "
        "installation's configured AI service. Administrators control access "
        "and retention, and see policy and audit metadata without private "
        "companion history. Companions cannot take actions, use connected "
        "sources or create learned memory."
    ),
    "employee_task_diagnostics": "Show bounded diagnostics and support guidance for the signed-in person's own tasks. No diagnostic control grants access to another person's work.",
    "employee_activation": "Guide each signed-in person through their allowed first task and readiness checks. Existing policy, cost limits and provider configuration stay in force.",
    "copilot_operations": "Let Copilot open controls that change things, in the action families enabled by your organization. Every change requires a fresh review and explicit confirmation. When this is off, Copilot can still open pages, focus controls and show current status, but it cannot change anything.",
    "support_center": "Allow installation administrators to prepare, review and download redacted diagnostics in Help. Reports are never sent automatically.",
    "workflow_readiness": "Show available workflows, their supported boundaries, and the live or platform validation still required. Enablement never establishes customer acceptance.",
    "project_reviews": "Share selected, fixed task results with assigned workspace reviewers. Review does not execute or sign off the live task.",
    "deliverable_bundles": "Share only selected result versions and evidence files with one named workspace recipient, with separate human acceptance and offline export.",
    "project_workspaces": "Plan project outcomes, reviewed context and live milestones. Explicit planning membership never grants private task, review, or execution access.",
    "task_handoffs": "Offer a named colleague an unstarted continuation with selected evidence and a spending ceiling; acceptance closes the original conversation to new execution.",
    "human_conversation_handoffs": "Let a person request help from a named colleague who is on duty. Review the exact conversation shared, pause AI work, reply in the same conversation and separately return future work to AI.",
    "outcome_measurement": "Plan a paired workflow pilot, record observed baseline and review effort, and compare current accepted outcomes. Unmeasured costs and unreviewed work remain explicit.",
    "commitment_viability": "Review two accepted orders against the capacity and stock your team reports. Explore expiring options and record observed contention with owner review. This pilot does not connect to a supplier or reserve stock.",
    "work_restructuring": "Check exact shared preparation across permitted original local cases, with separate complete results and deadlines.",
    "portable_competence": "Release only reviewed anonymous local rule structures. Qualify them against a target workflow and its own permitted cases before any local use.",
    "private_task_computation": "Check a bounded rule using a permitted task attachment and release only a separately approved fixed answer. Original data stays private.",
    "procedure_interactions": "Compare two owned local rules in both orders and check all supported starting values before any combined use.",
    "operational_competence_acquisition": "Plan questions from a rule's complete supported alternatives and current permitted effort reports. Teaching and publication remain separate reviews.",
    "request_program": "Check bounded arrangements of your existing taught rules against permitted original cases for one request. Nothing is published automatically.",
    "commitment_economic_alternatives": "Compare reported offer prices and full incremental costs with currently protected commitments. Results remain conditional on your stated facts.",
    "workflow_step_checks": "Check one owned taught step against ordinary entered values without running the whole workflow or any connected action.",
    "applicability_regions": "Check both local rule versions across every supported starting situation. Only current separately permitted expected answers can choose a version; unclear situations remain for review.",
    "governed_rule_evolution": "Build alternative local rules and a complete checking order from one owned published rule. Independently review every change before publication, and retain the exact previous release for restoration.",
    "recovery_visibility": "Practice with fictional sign-offs to see when identical visible status hides different original outcomes. No live approval or connected service is used.",
    "semantic_rule_reuse": "Check every supported input for a local Yes/No or bounded whole-number rule before reusing prior evidence across a rewrite. All checks count toward the reviewed work allowance.",
    "commitment_capability_learning": "Compare additional offers and reported resource additions while protecting accepted work. Record attributed trial results or check one owned published local rule. This local pilot does not verify physical availability, reserve stock or establish future revenue.",
    "shared_decision_evidence": "Review which reported information can support several choices. Share only named facts with named cases, set freshness and question limits, and keep uncertain choices visible. Reports are not independently verified and this review does not carry out a business choice.",
    "guided_onboarding": "Offer a guided path to a reviewed deliverable, privacy assessment, or accepted vendor case. Task creation alone never establishes success.",
    "action_center": "Collect approvals, results waiting for approval, assessment reviews, and uncertain external actions in one personal list, with private read and snooze preferences. Overdue items remain visible.",
    "draft_recovery": "Keep encrypted recovery copies of unfinished editor work, private to each account and workspace. Credentials and attachments are excluded; restoring never runs or publishes work.",
    "record_search": "Find accessible vendors, evidence, assessments, decisions, tasks, and reports by name or reference. Searches use current metadata and disclose unavailable or partial sources.",
    "workspace_recovery": "Let global administrators recover local work and separately restore retained installation safety settings. Workspace snapshots restore only in isolated local recovery mode with a separately kept recovery key. Settings restoration on Help requires a verified saved copy and explicit review; it never resets an unreadable policy. External stores and other shared administration are excluded.",
    "signing_identity_transition": "Permit global administrators to explicitly review a dual-signed, exact-release publisher or update-key transition in isolated recovery mode. This changes installation trust for every local workspace. It never accepts an unrelated signer or bypasses Windows signature checks.",
    "skills": "Agents can use saved procedures from the Skills library "
              "while working on a task.",
    "world_model": "The shared operating record: goals, episodes, approvals, "
                   "and memory live in one governed store. Turning this off "
                   "stops information from carrying across tasks.",
    "streaming": "Show responses as they are written in Chat and task "
                 "activity. When off, responses appear when complete.",
    "pack_editing": "Change saved specialists and department teams from the "
                    "platform. When off, their editors allow viewing only.",
    "role_editing": "Change the shared instructions, AI service and effort "
                    "choices for agent roles. When off, role setup is read-only.",
    "scheduling": "Create recurring workflow schedules in Automations. "
                  "Existing schedules are managed from that page.",
    "triggers": "Start saved workflows when a connected service sends an "
                "authenticated event. Requires a configured signing secret.",
}
