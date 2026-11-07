"""Closed, page-aware guidance for the shared dashboard Copilot.

The browser may propose a path, but it never supplies product instructions to
the model.  Only a context selected from this server-owned registry reaches the
system prompt.  The same registry also provides a deterministic guide when no
model provider is configured, so the helper remains useful on a fresh install.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from re import IGNORECASE, Pattern
from re import compile as compile_regex

from .ui_visibility import PAGES as _REGISTRY_PAGES

# The registry label is each page's one name: sidebar, heading, browser title
# and the Copilot guide all use it.
_REGISTRY_LABELS = {page["path"]: page["label"] for page in _REGISTRY_PAGES}
_READ_ONLY_BOUNDARY = (
    "This page guide is read-only. It explains controls but cannot make changes for you."
)
_ROLE_AND_READINESS_BOUNDARY = (
    "Your current access and the page's setup decide which controls you can use."
)
_MAX_BUILT_IN_REPLY_WORDS = 120
_MAX_BUILT_IN_REPLY_CHARS = 1_000
_WORDS = compile_regex(r"\b\w+\b")
_ACTION_VERBS = frozenset({
    "add", "approve", "archive", "assign", "cancel", "change", "complete",
    "configure", "connect", "copy", "create", "delete", "deny", "disable",
    "download", "edit", "enable", "export", "find", "grant", "install",
    "invite", "link", "list", "mark", "move", "pause", "print", "publish",
    "remove", "rename", "restart", "restore", "resume", "revoke", "rotate",
    "run", "save", "schedule", "search", "send", "set", "share", "show",
    "stop", "submit", "turn", "unlink", "unshare", "update", "upload",
    "withdraw",
})
_ACTION_LEADS = (
    ("can", "you"), ("could", "you"), ("would", "you"), ("will", "you"),
    ("i", "want", "to"), ("i", "need", "to"), ("i", "would", "like", "to"),
    ("i", "would", "like", "you", "to"), ("help", "me"), ("let", "s"),
)
_COMPLETED_VERB = (
    r"(?:did|done|completed?|finished|changed|updated|created|approved|"
    r"cancelled|canceled|deleted|removed|enabled|disabled|sent|shared|"
    r"published|submitted|started|stopped|saved|set|switched|applied|"
    r"scheduled|launched|ran|handled|turned\s+(?:on|off)|"
    r"configured|connected|granted|deactivated|provisioned|uploaded|"
    r"filed|generated|emailed|linked|deployed|exported|imported|"
    r"invited|restored|revoked|rotated|installed|archived|assigned|"
    r"added|moved|renamed|printed|downloaded|copied|marked|paused|"
    r"resumed|restarted|withdrawn|"
    r"(?:took|taken)\s+care\s+of)"
)
_FIRST_PERSON_COMPLETION = compile_regex(
    r"\b(?:i|we)(?:['’]ve|\s+(?:have|had))?\s+"
    r"(?:(?:already|just|now|successfully|fully)\s+){0,3}"
    r"(?:(?:went|have\s+gone)\s+ahead\s+and\s+)?"
    + _COMPLETED_VERB + r"\b(?!\s+(?:not|nothing)\b)",
    IGNORECASE,
)
_PASSIVE_COMPLETION = compile_regex(
    r"\b(?:your|the|this|that|it)\s+(?:[\w-]+\s+){0,5}"
    r"(?:has(?:\s+been)?|have(?:\s+been)?|was|were|is(?:\s+now)?|are(?:\s+now)?)\s+"
    r"(?:(?:already|just|successfully|fully)\s+){0,2}"
    + _COMPLETED_VERB + r"\b(?!\s+(?:when|if|after|once)\b)",
    IGNORECASE,
)
_CURRENT_STATE_CLAIM = compile_regex(
    r"\b(?:your|the|this)\s+(?:[\w-]+\s+){0,5}"
    r"(?:is|are)\s+(?:now\s+[\w-]+|dark|light|active|inactive|ready|live|"
    r"complete|done|approved|denied|cancelled|canceled|published|saved|sent)"
    r"\b(?!\s+(?:when|if|after|once)\b)",
    IGNORECASE,
)
_TERSE_COMPLETION = compile_regex(
    r"(?:^|[.!?]\s+)(?:(?:successfully|now)\s+)?(?:"
    + _COMPLETED_VERB + r"\s+(?:your|the|this)\b|"
    r"(?:settings|task|flow|workflow|request|approval|report|file|"
    r"document|email|notification|policy|theme|access)\s+"
    + _COMPLETED_VERB + r"(?=[.!?,;:]|$))",
    IGNORECASE,
)
_DONE_LEAD = compile_regex(
    r"^(?:(?:final|status):\s*)?(?:done|all\s+set|completed|it['’]s\s+done)\b",
    IGNORECASE,
)
_QUOTED_TEXT = compile_regex(
    r'"[^"\n]{1,200}"|“[^”\n]{1,200}”|(?<!\w)\'[^\'\n]{1,200}\'|‘[^’\n]{1,200}’'
)
_EXPLANATORY_LEAD = compile_regex(
    r"\b(?:say|read|label|phrase|example|wording|message|text)\b[^.!?]{0,60}$",
    IGNORECASE,
)
_RESPONSE_LOCAL_TEXT = compile_regex(
    r"\s+(?:a|an|the)\s+(?:short\s+)?"
    r"(?:checklist|summary|list|outline|steps|answer|explanation)\s+"
    r"(?:below|here|in\s+this\s+(?:reply|answer))\b",
    IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class CopilotPageContext:
    path: str
    title: str
    summary: str
    capabilities: tuple[str, ...]
    boundaries: tuple[str, ...]
    next_steps: tuple[str, ...]
    suggested_questions: tuple[str, ...]


def _ensure_read_only(context: CopilotPageContext) -> CopilotPageContext:
    """Make the no-action boundary explicit in every public page context."""

    missing = tuple(
        boundary
        for boundary in (_READ_ONLY_BOUNDARY, _ROLE_AND_READINESS_BOUNDARY)
        if boundary not in context.boundaries
    )
    if not missing:
        return context
    return CopilotPageContext(
        path=context.path,
        title=context.title,
        summary=context.summary,
        capabilities=context.capabilities,
        boundaries=(*missing, *context.boundaries),
        next_steps=context.next_steps,
        suggested_questions=context.suggested_questions,
    )


_GENERIC = CopilotPageContext(
    path="/",
    title="Lightwork",
    summary=(
        "Lightwork is a governed work and assurance platform. Use the sidebar to "
        "move from operating work to evidence, risk, privacy, security, and audit."
    ),
    capabilities=(
        "Create and supervise governed tasks and workflows.",
        "Inspect signed operating evidence, controls, spend, and risk.",
    ),
    boundaries=(
        _READ_ONLY_BOUNDARY,
        "A green local status is not proof of live provider, customer, or regulator acceptance.",
    ),
    next_steps=(
        "Choose the workspace that matches the outcome you need.",
        "Read its readiness and evidence boundary before running an operation.",
    ),
    suggested_questions=(
        "What can I do on this page?",
        "What should I verify before I continue?",
    ),
)


# Everyday page guidance follows the visible controls. Keep each entry short:
# what is here, what the person can do, where to start, a real limit, and two
# useful questions. The last field also supplies the panel's visible tip.
_OPERATIONAL_GUIDES = (
    # Work
    ("/today", "Today", "See in-flight tasks, changed results, decisions, upcoming schedules and pinned templates in one view.",
     "Open a task, decision or schedule from its card, and choose which templates stay pinned.",
     "Start with In-flight work; open Action Center for a decision or Tasks for the full history.",
     "Hiding a card does not pause its work; check the card's coverage note if something seems missing.",
     "What needs my attention today?", "Where are all my tasks?"),
    ("/workflow-readiness", "Workflow readiness", "See which workflow abilities are ready, turned off or need setup.",
     "Review the status of each ability and follow its Settings link when available.",
     "Open the ability you need and check its status before starting a workflow.",
     "A ready label describes setup here; a connected service is checked again when work runs.",
     "Why is a workflow ability unavailable?", "Where do I turn it on?"),
    ("/code", "Code", "Follow code projects, proposed changes and reviews in this installation.",
     "Add a code project, start a change and review proposals when your access allows it.",
     "Choose a code project, then use Start a change and review the proposal before any merge.",
     "A proposed change is not merged merely because it appears here; code work may be turned off.",
     "How do I start a code change?", "Where can I review a proposed change?"),
    ("/me", "My work", "See decisions and questions waiting for you, recent results, expiring keys and your summary choices.",
     "Open an approval or task question, link your chat account, and set daily-summary preferences.",
     "Open Waiting for your decision or Questions an agent is waiting on, then use that item's page to respond.",
     "This view shows work available to your signed-in account; other employees' private work stays private.",
     "What is waiting for me?", "How do I change my daily summary?"),
    ("/research", "Research lab", "Review research readiness, datasets, models, experiments and results awaiting review.",
     "Add a permitted dataset or model, queue a bounded experiment, and propose a finished result for approval.",
     "Check Ready to run experiments, then review approved data use and limits before Queue the run.",
     "A completed experiment is not put into use until its separate review and approval finish.",
     "How do I start an experiment?", "How does a result get approved?"),
    ("/action-center", "Action Center", "See current decisions and background work that may need attention.",
     "Refresh the decision list, open an item and review its action on the item's own page.",
     "Choose Refresh list, then open the decision or background item you need to handle.",
     "The list can change while you work; check the opened item before making a decision.",
     "What needs my decision?", "How do I refresh this list?"),
    ("/goals", "Tasks", "Find tasks by status and open each task's answer, steps, plan or problems.",
     "Filter Running, Waiting for you, Failed or Done; start new work from New task.",
     "Choose a status filter, open the task, then use Result, Steps, Plan or Problems to investigate it.",
     "A finished task is not proof that its answer is correct or approved for use.",
     "How do I find a failed task?", "Where can I see what a task did?"),
    ("/deliverables", "Results", "Find saved answers and items waiting for approval, separate from running task history.",
     "Open a result to read it; sharing, printing and downloads are on its task page.",
     "Choose Review for an item waiting for approval, or open Finished work to inspect its saved answer.",
     "An available result may still need your review or sign-off before anyone relies on it.",
     "Where are my finished results?", "How do I download an answer?"),
    ("/automations", "Automations", "Manage schedules, connected-service starts, new-item starts and recent flow runs.",
     "Create a schedule or event automation when its source, flow and required access are ready.",
     "Open the complete schedule form to choose work, repeat pattern, time and time zone, then check its next runs before choosing Create schedule. For new-item starts, choose a saved SharePoint, Salesforce, ServiceNow or Teams account, review its dated source snapshot and separately arm the selected work.",
     "Opening controls starts nothing. Months without a chosen 29th, 30th or 31st are skipped. Review the complete work and next starts before confirming creation. If its reply is interrupted, read the retained original schedule result without creating it again; this also works with scheduling turned off. A connected-source preview records its observed starting point, and saving does not confirm future delivery.",
     "How do I schedule a workflow?", "Where can I check recent runs?"),
    # Insights
    ("/overview", "Overview", "See recorded task momentum, current task states, recent work and department activity.",
     "Change the time range, open a recent task, or start a first task when the workspace is empty.",
     "Choose a time range, then open a task from Recent tasks or use Chat to start new work.",
     "These counts describe recorded work; they do not by themselves prove business value.",
     "What is happening with our tasks?", "How do I start our first task?"),
    ("/ekko", "Ekko", "Record permitted activity on the computer running Lightwork and review repeated steps it could take over.",
     "Enroll the named device, review recording permissions, then separately start or stop recording.",
     "Open activity recording controls to read this computer's availability and what Ekko records. Choose your enrolled device and confirm permission before recording allowed apps or importing an activity file.",
     "Automatic recording reads only recognized app categories on the Lightwork computer, not this browser's computer. Windows, Mac and local Linux X11 are supported; Wayland and remote or headless desktops are unavailable. Opening controls records nothing; Pause, Stop and withdrawal remain separate.",
     "What can Ekko record?", "How do I stop watching?"),
    ("/oversight", "Oversight", "See active work, waiting approvals, safety interventions and emergency-stop state.",
     "Choose a date range, open a task behind an intervention, or use emergency stop if authorized.",
     "Check Emergency stop first, then open Working now, Waiting for approval or a recent intervention.",
     "Emergency stop affects ongoing work across the installation and needs the right access.",
     "Is work stopped right now?", "Why did a safety rule step in?"),
    ("/run-tree", "Branches", "Inspect task branches and return to a saved step when the feature is on.",
     "Choose a task, create a branch, or review a saved step before going back to it.",
     "Select a task under Tasks with branches, then review Create branch or Go back to a saved step.",
     "The branch controls depend on current access and the Session tree setting.",
     "How do I try another approach?", "Can I go back to an earlier step?"),
    ("/spend", "Spend", "See recorded AI spending over time, task costs and the evidence behind each cost.",
     "Change the chart range, open an expensive task, review cost evidence or download the CSV.",
     "Choose a time range, then open Cost of each task or Download spreadsheet (CSV).",
     "Task totals can exclude subscriptions, outside-tool fees, taxes and invoice adjustments.",
     "Which tasks cost the most?", "Can I download the spending records?"),
    ("/work-value", "Work value & opportunities", "Understand business work, its audit evidence, estimated labor value and costs.",
     "Filter the period and scope, open a metric to inspect contributing work, or review an opportunity and create a workflow draft.",
     "Open a work item for its benchmark, cost coverage and correction history. Publish a reviewed draft explicitly in the workflow builder.",
     "Opportunity forecasts and benchmark-based labor value are not verified cash savings. Missing costs are not free execution.",
     "What is Lightwork delivering across our company?", "Where could we save more?"),
    ("/savings", "Savings", "Compare estimated time saved with recorded AI costs using your stated assumptions.",
     "Review completed-task estimates, change your numbers and open a workflow pilot to measure an outcome.",
     "Check Your numbers, then Save and recalculate before interpreting a savings chart.",
     "Savings depend on entered assumptions; an estimate is not a verified financial result.",
     "What assumptions drive this estimate?", "How can I measure a real outcome?"),
    ("/shoring", "Autonomous shoring", "Track business areas, service targets, estimated savings and work waiting for a person.",
     "Add a business area, set optional service targets and review its waiting items.",
     "Open Book of Work, choose Add a business area and set the targets you will measure.",
     "The savings view uses entered targets and costs; check actual results before claiming a benefit.",
     "How do I add a business area?", "What is waiting for a person?"),
    ("/knowledge-access", "Knowledge", "Search current approved sources and inspect why a result may be usable.",
     "Manage named company sources, review refresh history and permitted snapshots, attach approved sources to an unpublished specialist draft, or search current sources and request a correction.",
     "Open Saved Knowledge sources to choose an existing connected account and source. Source-use permission and independent approval are required before retrieval; saving an attachment draft does not publish it.",
     "A connected account proves access, not permission to use the source. Search results can disappear when source rights, approval or freshness change.",
     "How do I find an approved source?", "How do I correct a source?"),
    ("/human-conversations", "Human conversations", "Let an available named person handle a reviewed web conversation inside Lightwork.",
     "Declare your availability, read assigned conversations, send human replies or review a return to future AI work.",
     "Enable Human help in Chat in Settings, then ask a person to take over from the conversation. Only the exact reviewed brief, saved reply and human exchange are shared.",
     "Current AI work must settle before a person claims it. Stopping does not reverse external actions; returning to AI never automatically resumes old work or sends human replies to a model.",
     "Who can take this conversation?", "What information will they see?"),
    ("/learning/approval-challenges", "Approval challenges", "Build or receive a fictional approval practice and check this installation’s safeguards in a disposable copy.",
     "Choose a fictional request change and sign-off count, run the limited local check, review its source and limits, or import an authorized practice file for separate checking.",
     "An installation administrator can allow challenges here. Each local check and exact file export needs its own review. Copilot uses those same guarded controls.",
     "The source is a practice scenario, not a customer incident. This selected local check does not establish complete protection; no live safeguard, credentials, customer requests or AI calls are involved.",
     "What does this local result mean?", "What does a shared challenge contain?"),
    ("/decision-evidence", "Shared decision reviews", "Review whether your entered facts can support several choices.",
     "Enter possible situations and case choices, permit named sharing, review one affordable question, record its attributed answer and read original results.",
     "An administrator enables this in Settings. Start with your real decision definitions, then review source permission and the shared question limit.",
     "Reported facts remain assertions. Unsupported or stale choices remain uncertain; Lightwork does not reserve capacity or execute a business choice from this page.",
     "Which facts support this choice?", "Which single question could resolve several decisions?"),
    ("/learning/distinctions", "Find missing distinctions", "Find which available observations distinguish actions in your accepted teaching examples.",
     "Choose an owned workflow, permitted examples and the observations used today. Review the smallest supported addition, prepare its unpublished learning package and teach it through the existing reviewed controls.",
     "Only matching current example permissions and action contracts are used. Every proposed distinction must pass the existing teaching checks; identical conflicting observations stay unresolved.",
     "Selected known examples do not prove accuracy on future work. Recorded comparison cases show where a change matched, missed or remains uncertain; no workflow is published automatically.",
     "Why do these examples need a different observation?", "Where did the changed rules help or fail in the recorded comparisons?"),
    ("/private-task-computation", "Private task calculations", "Check a permitted task attachment locally and release only a separately approved fixed answer.",
     "Choose your task and its file, name the purpose, enter ordinary rule conditions, review the complete calculation, then separately approve any outward answer.",
     "Current task ownership, source rights and purpose still apply. Permission to read a file does not grant permission to share its contents.",
     "The source file and private values stay local. A lost reply must be checked in the original request, and spent uses are never reset by reopening the page.",
     "Which values can stay private?", "What exact answer will leave this installation?"),
    ("/learning/applicability", "Checked answer regions", "Find which supported starting situations have an independently expected answer from the current or proposed version.",
     "Choose the owned rule and complete comparisons with separate case reuse permission. Review every starting situation, then separately answer hypothetical questions or try checked routing.",
     "Both immutable versions run across the complete bounded domain. An independent complete comparison checks routing; current source and case permissions apply at every step.",
     "Missing or conflicting expected answers need review. Hypothetical answers are local tests, not observed customer outcomes. This publishes nothing automatically and proves no future business result.",
     "Where does each version give the expected answer?", "Which starting situation still needs my judgment?"),
    ("/learning/rule-evolution", "Rewrite and check local rules", "Build and check alternative decision routes and a complete checking order from your owned published rule.",
     "Choose the complete source, permission and bounded wrong-answer examples. Build alternatives, inspect every comparison and independently accept a change before activating it. Check the active release or restore the exact retained one.",
     "An unchanged complete-domain comparison remains outside both evolving artifacts. Every passing rule checks every declared situation, and current owner, source permission and work allowance bind each admission.",
     "Agreement with your original rule is not independent business truth. Equal or slower work remains visible. Lost replies use exact original custody; unknown effects never repeat automatically.",
     "Which alternative keeps every expected answer?", "How can I restore the previous published rule?"),
    ("/learning/acquisition", "Plan teaching questions", "Compare complete supported rule alternatives and plan questions using the effort you report.",
     "Choose your taught step, current permitted earlier reports and an independent reference if available. Review the whole plan, answer each selected question, and qualify the result before separate teaching or publication.",
     "Current source permission, reported effort, learning limits and original requests remain bound. Withdrawal stops further use of those reports.",
     "Entered effort and a modeled question plan do not prove faster future learning. A missing or interrupted original remains unknown without repeating work.",
     "Which question would distinguish the current answers?", "What evidence supports this plan and its reported effort?"),
    ("/learning/rules-together", "Check local rules together", "Find where two owned local rules can run together without changing their separate answers.",
     "Choose two rules, their permitted original cases and bounded starting values. Review both orders and all native comparisons, then use only the separately qualified arrangement.",
     "Every current source and original-case permission is checked again. Both results must agree with independently run separate rules.",
     "This bounded local check cannot authorize connected actions, publish workflows or establish future accuracy. Ambiguous orders remain unresolved.",
     "Which order keeps both answers?", "Which starting values make the rules conflict?"),
    ("/learning/request-program", "Prepare an answer for this request", "Check arrangements of your existing taught steps against permitted real cases for one request.",
     "Describe the request, choose named taught steps and current values, and supply explicit desired answers for permitted original cases. Review every proposed arrangement and the complete comparisons.",
     "The native calculation uses owned published local rules and current source permission. Unsupported or conflicting arrangements cannot produce a definite answer.",
     "A request-specific answer publishes no workflow. Read the original after a lost reply; do not repeat an unknown calculation.",
     "Which checked arrangement answers this request?", "What additional real case would separate the remaining answers?"),
    ("/learning/recovery-visibility", "Understand a missing reply", "Use fictional sign-offs to see why the same visible status can hide different original outcomes.",
     "Choose what a person can see, review the complete local practice and compare its shortest differing histories and useful additional observation.",
     "This practice uses isolated fictional requests. Open actual approvals to inspect an authorized live original; the practice changes no live work.",
     "An activity acknowledgement confirms only the stated local activity record. It does not prove remote delivery or a customer result.",
     "Can this status identify my original request?", "Which additional observation separates the outcomes?"),
    ("/learning/portable-rules", "Share and qualify local rule structures", "Review permitted anonymous source rule structures, then qualify against target-owned original evidence.",
     "Choose permitted source cases, review the complete released structure, import it with target cases, qualify and run the bounded local rule.",
     "Source and target rights are checked again. Private names and literals are excluded from the approved exported structure.",
     "No published workflow is replaced. Structural agreement does not establish customer accuracy, a new privacy algorithm or faster work.",
     "What structure is safe to share?", "Does this structure agree on every declared target input?"),
    ("/learning/work-restructuring", "Share preparation safely", "Review whether selected owned rule cases can share the same preparation while keeping each case's rights and result separate.",
     "Choose permitted retained cases, confidentiality groups, deadlines and a total local effort allowance; review the grouped plan, run its complete independent comparisons and read each original result.",
     "Only current successful local rule checks can supply the case evidence. Each case keeps its own source permission and original inputs.",
     "This bounded local check cannot move connected actions, bypass approvals or undo existing effects. Both grouped and complete comparison work count; agreement on known cases does not prove future accuracy or research superiority.",
     "Which cases can share their preparation?", "Which case must remain separate because its permission, deadline or confidentiality differs?"),
    ("/learning/recheck-rules", "Recheck affected rules", "Review which learned steps still match their original evidence after a saved rule changes.",
     "Select your owned workflow and permitted real case, retain complete component evidence, then separately review changed rules and the independent complete comparison.",
     "Use independently published taught rules and current permission to replay the selected original values. Local rechecking does not publish the changed rules.",
     "Only supported bounded rules are checked. The independent complete rerun adds work; known-case agreement does not prove accuracy on future customer work.",
     "Which checks must run again?", "What evidence was safely reused?"),
    ("/learning/instructions", "Instructions used in real work", "Record and review the instructions Lightwork supplied for one AI call on your own task.",
     "Request one capture, review or download its exact available text, withdraw it, or resolve a completed capture without repeating work.",
     "An installation administrator can allow recording here. Choose your task and consent before its next successful call starts, then refresh and select its dated record.",
     "Recording makes no extra AI call. Detectable secrets and unavailable sources are withheld; an earlier instruction record does not prove that instructions are still in use or that results improved.",
     "Why was a capture withheld?", "How do I withdraw this capture?"),
    ("/learned", "Learned", "Review current model guidance and the original requests that tested it.",
     "Read current lessons, turn selected completed work into reviewed questions, check question usefulness and answer judging, test lessons on another model and read the original request without repeating work.",
     "For a question from completed work, choose your own task, review or correct its expected answer and review the complete source-use permission before Save. For a question check, choose saved questions, review their complete text, AI use and spending limits, then confirm separately. Read every unavailable judgment; removing a question needs its own review. Review answer judging with independently labelled answers. For a lesson test, supply the receiving model's standing instructions and review every check and spending limit before confirming.",
     "Saving a question runs no AI. Source-derived questions use shared learning storage but remain bound to their original workspace and current source permissions. Checks need current administrator access and available spending allowance. Judge checks can remain insufficient; passing lesson tests starts lessons on trial and does not prove improvement on customer work.",
     "Review answer checking", "Read my selected original lesson test"),
    ("/learning", "Learning", "Review what Lightwork has learned, preview changes and inspect saved points.",
     "Turn learning parts on or off, review recent work and compare guidance for building new agents.",
     "Open Learning systems to check setup. For agent-building guidance, select a recurring tool problem, review the complete requests and limits, then inspect the comparison before separately reviewing adoption. To undo the latest guidance change, choose Restore, review the saved change and its original guidance, and confirm. Restoring an older change is blocked if guidance has changed since.",
     "Comparisons leave existing agents unchanged. Adoption affects future agent setup only; a tool-selection check does not establish answer quality or business improvement.",
     "What has Lightwork learned?", "Improve how new agents are built"),
    # Administration
    ("/permissions", "Permissions", "Review where work runs, available tools and the limits on what Lightwork may do.",
     "Filter tools, inspect their details and change an allowed tool when you have access.",
     "Check Where work runs, then use the Tools filter before changing an individual tool.",
     "An enabled tool may still need a connection and the right person's access when work starts.",
     "Why can't this tool run?", "Where do I change task limits?"),
    ("/connections", "Connections", "Set up and review the outside services Lightwork can use.",
     "Save or test a connection and preview a change to a connected system when available.",
     "Open Saved connections to review one, or Add a connection with a key and choose the named service, including supported reference-data services. Save the key privately in that form and review its separate service check. For Outlook or Microsoft 365 email, open account sign-in, review the application, sign in with Microsoft and choose that saved mail account in Channels.",
     "Opening setup changes nothing. Microsoft application consent and mailbox access are separate provider requirements. Saving or testing a connection does not authorize a later change in the outside system.",
     "How do I test a connection?", "Who can use a saved connection?"),
    ("/workspace/recovery", "Workspace recovery", "Create, inspect and test saved workspace copies before a recovery is needed.",
     "Keep a recovery key, create a snapshot and test restore safely before using Restore this workspace.",
     "Start with Recovery key, then Create snapshot and Test restore safely.",
     "Keep the key away from the copies; a real restore replaces newer work in that workspace.",
     "How do I test a saved copy?", "What would a restore replace?"),
    ("/settings", "Settings", "Find models, connections, features, access and maintenance settings in one place.",
     "Open a section tab or All settings, review its current value and save an authorized change.",
     "Choose Models for AI choices, Connections for services or Features for what Lightwork may do.",
     "A saved setting can still require setup or a service restart before it takes effect.",
     "Where do I set an AI model?", "How do I find a setting?"),
    ("/users", "Users", "Manage people's roles, invitations, workspace membership and department access.",
     "Give someone a role, create an invite link or change a member's workspace role when authorized.",
     "Open People to review a role; use Invite someone by email or Workspace members for a new person.",
     "An administrator role does not automatically open another employee's private task or chat.",
     "How do I invite someone?", "How do I change a workspace role?"),
    ("/spending-limits", "Spending limits", "Set spending ceilings for a workspace, everyone or one person.",
     "Review the current workspace limit and save a new whole-workspace or personal limit.",
     "Start with Whole workspace, then check Everyone and People for more specific limits.",
     "Whichever applicable limit is reached first stops new spending; a limit is not an invoice.",
     "Which spending limit applies first?", "How do I set a personal limit?"),
    ("/tenants", "Workspaces", "Create and manage separate workspaces, their daily limits and feature choices.",
     "Create a workspace, review its features, pause or resume one, or review erasure of a removed workspace when authorized.",
     "Use Create a workspace for a new team; open Your workspaces before changing an existing one.",
     "Pause or removal affects access and work. Erasure permanently removes reviewed local records; backups and external copies need separate care.",
     "How do I create a workspace?", "Where do I set its daily limit?"),
    # Common pages reached from those workspaces
    ("/help", "Help and diagnostics", "Prepare a support report or a reviewed draft about a task that stopped.",
     "Review the report on this page, then copy or download exactly the draft you intend to share.",
     "Choose Prepare support report, or search for a stopped task under Report a problem with a task.",
     "Nothing is sent automatically; share a reviewed download through your organization's support channel.",
     "How do I report a failed task?", "What does a support report contain?"),
    ("/account", "Your account", "Open your preferences, devices, access keys, permission requests and personal data controls.",
     "Choose a linked page to change your own settings or review who can access your content.",
     "Start with Your preferences, or choose Explain or request permissions when a control is unavailable.",
     "The pages you can open depend on your account and workspace access.",
     "How do I change my preferences?", "Where can I request permission?"),
    ("/start", "Get started", "Follow the setup checks and try a first task on sample data.",
     "Choose an outcome, review the readiness checks and run the sample task when it is available.",
     "Open Choose your first outcome, then follow the next setup step shown on the page.",
     "A ready setup check does not prove an outside service will accept a real request.",
     "What should I set up first?", "How do I try a sample task?"),
    ("/providers", "Providers", "See which AI services are configured and how each one is doing.",
     "Test a saved service or open its Settings entry to finish setup.",
     "Open Your AI services, choose Test connection, then review the result before starting work.",
     "A saved service is not proof that a live request will succeed.",
     "How do I test an AI service?", "Where can I add one?"),
    ("/billing", "Billing", "Review recorded monthly costs, statements and workspace invoices.",
     "Download a monthly spreadsheet or make an invoice for a workspace when available.",
     "Choose this month's Download button, or open Monthly statements for an older period.",
     "Recorded cost subtotals may differ from an outside provider's final invoice.",
     "How do I download this month's costs?", "Where can I make an invoice?"),
)


def _operational_context(row: tuple[str, ...]) -> CopilotPageContext:
    path, _title, summary, capability, next_step, tip, first_question, second_question = row
    return CopilotPageContext(
        path=path, title=_REGISTRY_LABELS[path], summary=summary,
        capabilities=(capability,), boundaries=(tip,), next_steps=(next_step,),
        suggested_questions=(first_question, second_question),
    )


def _registered(path: str, **fields: object) -> CopilotPageContext:
    """A hand-written guide for a registry page, titled with its registry label."""

    return CopilotPageContext(path=path, title=_REGISTRY_LABELS[path], **fields)


_CONTEXTS = tuple(
    _ensure_read_only(context)
    for context in (
        *(_operational_context(row) for row in _OPERATIONAL_GUIDES),
        CopilotPageContext(
            path="/chat", title="Chat",
            summary="Describe the work you want Lightwork to do, add files if helpful, and choose how to start it. You can return to recent chats from the menu.",
            capabilities=(
                "Start a task from your message, or draft a flow or agent when those choices are available.",
                "Attach files, review the task budget, and continue work in a saved chat.",
                "Copy, print, share or download an answer; try another answer, edit and resend, or branch from a saved answer when enabled.",
                "Copy one saved code block with its own labelled control, or download an editable Word answer with supported tables.",
            ),
            boundaries=(
                "Sending a message starts work and may use a paid AI service; spending limits and approval rules still apply.",
                "Starting or continuing work depends on your access and whether an AI service is ready.",
                "An alternative keeps the original conversation and starts separately reviewed work. Connected actions may repeat effects, so answer-only is the default.",
            ),
            next_steps=(
                "Describe the result you need, then add any useful files or details.",
                "Check the budget and the choice beside Send before starting work.",
            ),
            suggested_questions=(
                "What can I ask Lightwork to do here?",
                "How do I add files to a task?",
                "What happens when I send this message?",
            ),
        ),
        _registered(
            path="/commitment-reviews",
            summary="Review whether two accepted orders can still be delivered with the capacity and materials your team reports.",
            capabilities=(
                "Compare the reported capacity, materials, deadlines, and conditional options for two orders.",
                "See which source needs review before its decision window closes.",
                "Review and confirm a possible shared-resource link before it changes the assessment.",
                "When additional-work qualification is enabled, compare further offers and reported additions, record a scoped trial result or check one owned published local rule.",
                "Read an exact original result without repeating its qualification or changing its allowance.",
                "When financial comparison is enabled, compare complete reported incremental costs and offer prices across every jointly feasible combination while protecting accepted commitments.",
            ),
            boundaries=(
                "This is a bounded planning model based on information entered by your team; it does not verify supplier stock or reserve anything externally.",
                "Possible, uncertain, and infeasible are model assessments, not customer delivery guarantees.",
                "A source or decision that changed needs a fresh review before another action.",
                "Entered possibilities and operator trial reports are not independently verified. Local rules establish only the selected recorded calculation; they do not predict revenue.",
                "Conditional contribution uses one explicitly chosen currency and every entered expense. It does not establish customer demand, purchase availability or realized profit.",
            ),
            next_steps=(
                "Open a review, enter the source and time limits, and check the two orders together.",
                "Confirm any suggested resource link only after checking it against the actual work.",
                "An administrator enables additional-work qualification in Settings. Choose the current review before using its ordinary controls or Copilot.",
                "Enter complete financial assumptions and their use permission, then separately review the full conditional comparison.",
            ),
            suggested_questions=(
                "Which order needs attention first?",
                "What information is still uncertain?",
                "What happens if these orders share capacity?",
            ),
        ),
        _registered(
            path="/workflows",
            summary="Find your saved flows, reusable templates, and agent playbooks.",
            capabilities=(
                "Create and edit visual flows when the flow engine is on and you have operator access.",
                "Review saved flows and their results from this page.",
            ),
            boundaries=(
                "Copilot can guide you through a flow; it cannot create one for you from this page.",
            ),
            next_steps=(
                "Choose New flow to open the visual designer, add the steps, then save the flow.",
                "If flows are turned off, ask an administrator to turn them on in Learning.",
            ),
            suggested_questions=(
                "How do I create a flow?",
                "How do I review the results of a flow?",
            ),
        ),
        _registered(
            path="/agents",
            summary="Browse agents and specialists, check required actions, and review each one's guardrails and independence level.",
            capabilities=(
                "Check whether required workflow actions are present before choosing an agent or specialist.",
                "Administrators can edit the independence of an agent or specialist by risk level and keep new ones supervised.",
            ),
            boundaries=(
                "A Can start label checks registered actions; live connections, permissions and the AI service are checked when work starts.",
                "A server-configured independence policy takes priority over the editor. The server checks authority and current approval evidence before ending supervision.",
            ),
            next_steps=(
                "Use the ready-first picker and open a job card to see its current setup.",
                "If an action needs setup, follow Review setup. Administrators can review Independence in the editor.",
            ),
            suggested_questions=(
                "Why can this agent or specialist not start?",
                "What do Watch, Suggest, Ask, and Act mean?",
                "Why is this agent or specialist still supervised?",
            ),
        ),
        _registered(
            path="/workforce",
            summary="See departments, specialist setup status, and how independently agents and specialists may work.",
            capabilities=(
                "See how many specialists in each department have their required actions available.",
                "Administrators can grant independence to a candidate after a current approval-record check.",
            ),
            boundaries=(
                "Department counts check registered actions only; live connections, permissions and the AI service are checked when work starts.",
                "Independence levels must be enabled, and a candidate's current approval record and version are rechecked before a grant.",
            ),
            next_steps=(
                "Open a department to review the specialists that need setup.",
                "Review each candidate's policy before granting independence; use the editor in Agent Factory to set per-risk levels.",
            ),
            suggested_questions=(
                "Which departments need setup?",
                "How do I change how independently an agent or specialist works?",
                "What evidence is needed before an agent or specialist graduates?",
            ),
        ),
        _registered(
            path="/fleets",
            summary="See your teams, their agents and job roles, and recent tasks.",
            capabilities=(
                "Review each team's agents and whether their required actions are available.",
                "Give an available agent a task and follow the task from its link.",
            ),
            boundaries=(
                "The readiness label checks registered actions; access, connections and the AI service are checked when a task starts.",
                "Only teams available to your current account and workspace are shown.",
            ),
            next_steps=(
                "Open a team, choose an available agent, describe the work, then choose Start task.",
                "If no agent can start, follow Review setup beside the affected agent.",
            ),
            suggested_questions=(
                "How do I give this team a task?",
                "Why can this agent not start?",
                "Where can I follow a recent team task?",
            ),
        ),
        _registered(
            path="/approvals",
            summary="Review work Lightwork has paused for a person's decision.",
            capabilities=(
                "Read what a proposed step will do and what remains uncertain.",
                "Approve, reject, or send back an exact request using the page controls when your role allows it.",
            ),
            boundaries=(
                "A Hold-mode prediction never grants permission by itself.",
                "Approving a paused step lets it reach its remaining safety checks; it does not prove execution or success.",
                "Copilot can explain these decisions here, but cannot cast an approval vote.",
            ),
            next_steps=(
                "Open the paused request, read its effects and open questions, then make your decision.",
                "Check the task result after the decision; another approval or safety check may still stop it.",
            ),
            suggested_questions=(
                "Why did Lightwork pause this step?",
                "What happens if I approve it?",
                "What if nobody decides in time?",
            ),
        ),
        _registered(
            path="/facts",
            summary="Browse shared facts by name, source, tag and age, then inspect exact current details and recorded versions.",
            capabilities=("Search bounded server pages and select facts for read-only review.",
                          "Review an exact single-fact edit, tag change, historical restore or removal through native controls and authorized Copilot actions."),
            boundaries=("Shared facts are visible to workspace viewers; personal and task working notes are excluded.",
                        "An edit needs current operate permission and the reviewed version. A read grant cannot grant a write.",
                        "Removal stops new recall; retained history and minimal operation receipts are not permanent erasure."),
            next_steps=("Choose Details and history on one fact to set the current Copilot selection.",
                        "Compare the saved value with your draft if another person changed the fact."),
            suggested_questions=("Find shared business facts", "Review selected facts and history", "Edit the selected fact's tags"),
        ),
        _registered(
            path="/content-access",
            summary="Employee content stays private while administrators govern policy and audit metadata.",
            capabilities=("Request a specific task, approval-card read or exact chat-identity export for a stated purpose.",
                          "Review, deny or revoke an independently requested read and inspect its receipts."),
            boundaries=("Another administrator or the current content owner must approve; approvals expire within an hour.",
                        "A read never grants mutation, publication, whole-conversation access or companion history.",
                        "Reading an approval card does not grant a vote; current role, claim and separation-of-duties checks still apply.",
                        "Use the page controls; this guidance does not submit or approve requests."),
            next_steps=("Choose the exact record, purpose and duration, then request independent review.",
                        "Confirm the activity receipt before opening approved content."),
            suggested_questions=("Who can approve this read?", "Why did my content approval stop working?"),
        ),
        CopilotPageContext(
            path="/users/departures", title="Employee departures",
            summary="Review employee access and retained work before deactivating an exact named identity.",
            capabilities=("Preview owned work, memberships, connections and pending scheduled tasks.",
                          "Deactivate local access and record named responsibility for unresolved handoffs."),
            boundaries=("Removing local credentials does not revoke external provider consent.",
                        "Data and holds remain retained; a custodian receives no private-content access.",
                        "Running work and other module queues remain unresolved; no complete-offboarding claim is made.",
                        "Use the reviewed page controls; guidance does not deactivate accounts."),
            next_steps=("Preview a known employee and name a retained-data owner.",
                        "Review saved per-step receipts and record external handoff evidence."),
            suggested_questions=("What remains after deactivation?", "Does a handoff owner receive private task access?"),
        ),
        _registered(
            path="/companion/admin",
            summary=(
                "Workspace administrators enroll employees and set the policy "
                "for personal task status and optional AI draft conversations."
            ),
            capabilities=(
                "Enroll or disable a specific employee using the page's controls.",
                "Allow access to the employee's own task status and choose conversation retention.",
                "Separately allow an employee to request AI drafts using the installation's configured AI service.",
                "Review policy and audit metadata for companions in this workspace.",
            ),
            boundaries=(
                "Companion policy requires administrator authority in the current workspace and current employee membership.",
                "Companion administration does not grant access to private companion history.",
                "AI drafts send messages, eligible retained history and permitted own-task titles and status to the configured AI service.",
                "Retained context is checked against current source access; no-history drafts are stateless.",
                "Companions cannot execute model tools or task actions, use connected sources, or create learned memory.",
                "Copilot can explain these controls but cannot enroll employees or change companion policy.",
            ),
            next_steps=(
                "Check whether employee companions are enabled in Settings.",
                "Select an employee and review task access, AI draft permission and retention before saving.",
                "Before permitting AI drafts, confirm that the configured AI service is an approved destination for the employee's messages and allowed context.",
                "Refresh the policy after a conflict before making another change.",
            ),
            suggested_questions=(
                "What can an employee companion access?",
                "Can administrators read companion conversations?",
                "How do I change an employee's companion policy?",
            ),
        ),
        _registered(
            path="/companion",
            summary=(
                "Check your own task status and, when your administrator permits "
                "it, ask for AI drafts alongside work that is still running."
            ),
            capabilities=(
                "Read the status of your own tasks when your workspace policy allows it.",
                "Ask the companion for an AI draft when your administrator has enabled draft conversations for you.",
                "View your current companion policy and conversation retention.",
                "Clear your retained companion conversation using the page's controls.",
            ),
            boundaries=(
                "A workspace administrator must enroll you before you use a companion.",
                "AI drafts use the configured AI service, which receives your message, eligible retained history and permitted own-task titles and status.",
                "Without task-source access, drafts use your current message only; without conversation retention, drafts do not carry history forward.",
                "Retained context is rechecked against current source access before it is used.",
                "Drafts may be wrong and need your review; the companion cannot execute tools or task actions.",
                "It cannot read another employee's tasks, use connected sources or create learned memory.",
                "Companion administration exposes policy and audit metadata, not private companion history.",
                "Copilot can show the status of your own saved conversation and clear it after you review the request. It does not read or share your conversation text.",
            ),
            next_steps=(
                "Review your access, AI draft permission, destination and retention policy before sending a message.",
                "Ask about task status or request a draft, then review the reply and any task sources before using it.",
                "If access is unavailable, ask your workspace administrator to review enrollment, policy or the configured AI service.",
            ),
            suggested_questions=(
                "What can my companion do today?",
                "What does the AI service receive?",
                "How do I clear my conversation history?",
            ),
        ),
        _registered(
            path="/ai-evidence-analysis",
            summary=(
                "Extract bounded technical facts from an attested artifact and route the "
                "criteria-pinned result to a distinct human reviewer."
            ),
            capabilities=(
                "Analyze one bounded PDF, JPEG or PNG image, XLS or XLSX spreadsheet, or plain-text artifact against an enrolled criteria set.",
                "Inspect current, released, and historical analysis records.",
                "Review, revoke, verify integrity, and purge retention-due records.",
            ),
            boundaries=(
                "Results are evidence aids, not legal advice, certification, or compliance conclusions.",
                "Artifact and criteria authority are resolved independently by the server.",
                "Extracted text is not persisted, but process-memory zeroization is not guaranteed.",
            ),
            next_steps=(
                "Refresh status and confirm the workspace is enabled and configured for an operation attempt; status does not resolve artifact-specific authorities or prove them ready.",
                "Upload only an attested artifact with exact authority digests and revisions.",
                "Have a distinct authorized human review the pending result.",
            ),
            suggested_questions=(
                "What do I need before uploading evidence?",
                "What does a released analysis prove?",
                "When should I revoke an analysis?",
            ),
        ),
        _registered(
            path="/ai-entity-tasks",
            summary=(
                "Manage review and remediation tasks tied to exact AI inventory entity revisions."
            ),
            capabilities=(
                "Filter and inspect revision-pinned tasks with complete lifecycle history.",
                "Create review or remediation work for an exact inventory entity revision.",
                "Update status, priority, assignee, collaborators, and due date under CAS.",
                "Inspect audit integrity and apply authorized retention maintenance.",
            ),
            boundaries=(
                "Workspace, actor, entity authority, entity digest, retention, and quotas are server-owned.",
                "Task creation independently re-resolves the current inventory authority.",
                "Local readiness does not prove an external workflow or customer has accepted the task outcome.",
            ),
            next_steps=(
                "Confirm the task and AI inventory compositions are ready.",
                "Copy the exact inventory entity ID and revision before creating a task.",
                "Inspect the returned authority digest and history after each update.",
            ),
            suggested_questions=(
                "What must I verify before creating a task?",
                "Why did my entity revision conflict?",
                "When can a task be purged?",
            ),
        ),
        _registered(
            path="/governance-agents",
            summary=(
                "Run closed, evidence-cited workflows for breach response, privacy risk, "
                "program analysis, knowledge governance, and third-party risk."
            ),
            capabilities=(
                "Publish independently approved agent policies.",
                "Analyze server-resolved evidence and inspect cited findings.",
                "Record human review and execute separately approved idempotent actions.",
            ),
            boundaries=(
                "Agents provide decision support and never become autonomous authority.",
                "Evidence, adapters, dispatchers, credentials, and workspace identity are server-owned.",
                "Execution is default-off and requires durable token custody plus independent approval.",
            ),
            next_steps=(
                "Load status and confirm the required callable composition is configured for an operation attempt; status does not open the store or verify live authorities.",
                "Publish an approved policy before starting an analysis run.",
                "Review cited evidence before granting any execution approval.",
            ),
            suggested_questions=(
                "Which governance agent should I use?",
                "What is required before execution?",
                "How do policy and evidence revisions stay pinned?",
            ),
        ),
        _registered(
            path="/agent-control-plane",
            summary=(
                "Inspect and operate bounded controls over native principals and registered "
                "external agents, with a separately scoped deployment emergency halt."
            ),
            capabilities=(
                "Inspect status and one bounded, paginated roster page without accumulating an unbounded browser inventory.",
                "Suspend or resume a named principal, durably contain or release a named principal, and narrow an external agent's capability ceiling when the current role and runtime permit.",
                "Read a named principal's bounded ledger and request or clear the hardened local or shared-cluster halt under its exact authority gate.",
            ),
            boundaries=(
                "Roster completeness is refused when a required authority is unreadable; an unavailable response is not an empty estate.",
                "Containment from this page durably protects the named principal but does not claim a live-swarm seal or subtree revocation.",
                "Ordinary audit outages are fail-soft, while a configured audit-guarantee refusal can be reported after a control change has already landed.",
                "A local result does not prove complete estate discovery, live external-agent acceptance, or production recovery and scale.",
            ),
            next_steps=(
                "Refresh status and confirm the control-plane runtime and exact halt scope are available before selecting a mutation.",
                "Use the bounded roster page to select the exact principal and read the returned enforced state after an operation.",
                "Inspect the principal ledger separately when durable audit evidence is required, especially after an audit-related refusal.",
            ),
            suggested_questions=(
                "Which controls are available to my role right now?",
                "What does containment from this page actually protect?",
                "How should I verify state and audit evidence after a control attempt?",
            ),
        ),
        _registered(
            path="/audit/evolution-ledger",
            summary=(
                "Review recorded learning changes and restorations, and download "
                "receipts to check their recorded contents."
            ),
            capabilities=(
                "See when recorded changes were adopted or restored and whether their stored history checks match.",
                "Download a recorded receipt and choose it in Check a receipt without editing its contents.",
                "Download a checkpoint of the complete supported native history, keep the original file independently, then choose it to compare the earlier history against the current record.",
                "Copilot can check the current workspace history when learning actions are enabled and your role permits audit review.",
            ),
            boundaries=(
                "Adopting a change does not establish that it improved results. Use the recorded results and review controls for that decision.",
                "Private learned content and approval material stay out of this page and its receipt downloads.",
                "Matching fingerprints do not establish who created or approved a receipt, or detect replacement of the whole history. Confirming those claims requires separate trusted evidence.",
                "A checkpoint can detect a changed or missing earlier history only when its original file was independently retained. File contents alone do not prove external custody or that all activity was recorded. Legacy or temporary history and sources exceeding 4,096 records or 16 MB are refused rather than truncated.",
                "This history covers recorded adoptions and restorations, rather than every learning action. An empty history does not mean learning is turned off.",
            ),
            next_steps=(
                "Select Refresh to check the current stored history.",
                "Select Download receipt on a recorded change, then choose the downloaded file in Check a receipt.",
                "Use Keep a history checkpoint to download the complete supported reference. Later select that original file and Compare saved history; this comparison runs without an AI call.",
                "Open Learning or Release decisions to review or change learned work through its own controls.",
            ),
            suggested_questions=(
                "Which learning changes are recorded here?",
                "Does a matching receipt prove that someone approved the change?",
                "How do I download and check a recorded receipt?",
            ),
        ),
        _registered(
            path="/consent",
            summary=(
                "Govern version-bound consent choices, pseudonymous profiles, tracker "
                "enforcement, and privacy-bounded consent analytics."
            ),
            capabilities=(
                "Inspect the active policy and notice, then collect an immutable preference receipt.",
                "Create and inspect pseudonymous profiles and run a fail-closed enforcement check.",
                "Review tracker governance and bounded aggregate consent analytics.",
                "Inspect current identity links and immutable unlink, relink, and account-transition evidence.",
            ),
            boundaries=(
                "Every choice is bound to an exact policy and notice version.",
                "Privacy signals can deny covered purposes; they never manufacture consent.",
                "An enforcement result does not prove every tracker or destination in an estate is known.",
                "The operator page cannot unlink, relink, choose a workspace, or submit identity subjects.",
                "Receipt rows are never moved or merged; the current link is an association projection.",
                "Production IdP/JWKS operation and live multi-device acceptance remain external evidence.",
            ),
            next_steps=(
                "Refresh the page and verify the consent authority is enabled for the active workspace.",
                "Confirm the exact policy, notice, purpose, and jurisdiction before recording a choice.",
                "Run the enforcement check before activating a tracker or destination.",
                "Use a fresh public pairing and exact revisions for unlink, relink, or account transition.",
            ),
            suggested_questions=(
                "What is required before I collect a preference?",
                "What does the enforcement check prove?",
                "What evidence is required to unlink or relink a profile?",
            ),
        ),
        _registered(
            path="/consent/custom-indexes",
            summary=(
                "Create governed indexes over approved volunteered profile-data elements "
                "and run exact, privacy-minimized subject searches."
            ),
            capabilities=(
                "Create an index definition pinned to one published data element.",
                "Build or rebuild a revision-pinned HMAC index without persisting raw values.",
                "Search one ready index and inspect bounded opaque profile matches.",
                "Revoke indexes and verify workspace-local audit and integrity records.",
            ),
            boundaries=(
                "The browser cannot choose workspace identity, actors, key material, key versions, retention, or quotas.",
                "Search is exact and intentionally excludes free-text, fuzzy, inferred, or cross-tenant discovery.",
                "A ready local index does not prove customer privacy review or production-scale acceptance.",
            ),
            next_steps=(
                "Load status and confirm profile-data authority, key custody, and source schema are ready.",
                "Create an index only for an approved published data element and review its source revision.",
                "Rebuild after a source revision changes before relying on search results.",
            ),
            suggested_questions=(
                "What values can be indexed safely?",
                "Why did this index become stale?",
                "What does an index search return?",
            ),
        ),
        _registered(
            path="/consent/bulk-jobs",
            summary=(
                "Run workspace-scoped, credit-limited asynchronous receipt exports "
                "and governed consent-subject lifecycle actions."
            ),
            capabilities=(
                "Create, schedule, inspect, cancel, recover, and download bounded bulk exports.",
                "Run preference edits, subject deletion, identifier changes, receipt reactivation, and expiration clearing through their exact consent primitives.",
                "Inspect credits, progress, immutable history, retention, and integrity without exposing raw subject identifiers.",
            ),
            boundaries=(
                "Workspace, principal, actor, worker, stores, paths, and provider authority are server-derived and cannot be supplied by the browser.",
                "Each operation fails closed unless its real consent-store primitive is installed; a similarly shaped callback is not sufficient.",
                "Local completion does not prove production volume, customer acceptance, regulator delivery, or an external provider effect.",
            ),
            next_steps=(
                "Check readiness and what each kind of change can do before starting a bulk change.",
                "Confirm the credit reservation, exact profile revisions, and receipt identifiers before scheduling mutations.",
                "Review terminal history and download integrity before relying on an export or action result.",
            ),
            suggested_questions=(
                "Which bulk operations are ready for this workspace?",
                "What should I verify before scheduling a destructive action?",
                "What does a successful export prove?",
            ),
        ),
        _registered(
            path="/consent/publish-settings",
            summary=(
                "Govern immutable website runtime settings pinned to exact consent "
                "property and publication authority."
            ),
            capabilities=(
                "Version, activate, roll back, withdraw, and inspect SDK/runtime settings for an exact property publication.",
                "Control SDK version, per-geolocation reconsent, privacy-safe analytics categories, common trackers, cookie scope, SPA reload, CSP nonce requirements, and automatic refresh.",
                "Expose only the active integrity-checked SDK projection while retaining bounded history, recovery, and audit evidence.",
            ),
            boundaries=(
                "The browser cannot choose workspace, actor, authority digests, storage, retention, CSP nonce values, or signing material.",
                "A CSP nonce requirement is configuration metadata; Lightwork never stores or publishes a reusable nonce value.",
                "A locally active setting does not prove the SDK was installed on a customer property or accepted in live browsers.",
            ),
            next_steps=(
                "Verify readiness and load the exact property's current publishing authority.",
                "Create and independently review a new immutable version before activation.",
                "Validate the safe public projection and then separately test the deployed property and browser estate.",
            ),
            suggested_questions=(
                "Which publish settings are active for this property?",
                "What must be tested on the live website?",
                "How do rollback and withdrawal differ?",
            ),
        ),
        _registered(
            path="/consent/global-opt-out",
            summary=(
                "Govern a versioned mobile and email Global Opt-Out experience "
                "that submits a real profile-bound opt-out rights request."
            ),
            capabilities=(
                "Create, revise, activate, revoke, and audit an experience pinned to an exact public client, property, publication, policy, and channel authority.",
                "Serve a privacy-minimized public configuration and accept selector-free opt-out submissions through the existing public-consent trust boundary.",
                "Create a real privacy-rights opt-out case while retaining only bounded case and signed-result digests in this control plane.",
            ),
            boundaries=(
                "The browser cannot select workspace, profile, property, origin, service, publication, policy, storage, or retention authority.",
                "A successful local submission proves the governed workflow ran; it does not prove every device or service honored the request.",
                "Live mobile, email, connected-device, customer-estate, and legal acceptance require separate evidence.",
            ),
            next_steps=(
                "Confirm public consent and privacy-rights intake readiness for the active workspace.",
                "Bind the experience to the exact active public client and independently review its device and service coverage.",
                "Exercise revocation, retry, recovery, and representative live-device acceptance before relying on production coverage.",
            ),
            suggested_questions=(
                "What authority is this opt-out experience pinned to?",
                "What happens when the public client or publication changes?",
                "What still requires live-device validation?",
            ),
        ),
        _registered(
            path="/consent/application-scans",
            summary=(
                "Inspect bounded mobile and connected-app manifests and govern "
                "cited observations through independent review and retention."
            ),
            capabilities=(
                "Register exact Android, Fire OS, iOS, tvOS, Roku, Tizen, or webOS application authority.",
                "Analyze already-extracted manifests under per-file, aggregate, tree, and finding bounds.",
                "Review an exact application revision and result digest, verify integrity, and operate retention.",
            ),
            boundaries=(
                "Raw manifest bytes remain transient and SDK names remain unreviewed candidates rather than tracker or legal classifications.",
                "Binary APK AXML, executables, live devices, IDFA state, and runtime network behavior are not inspected.",
                "Local manifest analysis does not prove a native SDK, deployed-device behavior, completeness, scale, or customer acceptance.",
            ),
            next_steps=(
                "Confirm workspace composition and application authority are ready before uploading extracted manifests.",
                "Review cited completeness limits and have a different authorized person decide the exact result.",
                "Run separate device, runtime-traffic, accessibility, recovery, and scale acceptance before relying on production coverage.",
            ),
            suggested_questions=(
                "What does this manifest scan prove?",
                "Which application formats and evidence are supported?",
                "What still needs live-device testing?",
            ),
        ),
        _registered(
            path="/consent/publishing",
            summary=(
                "Enroll exact web or mobile properties and promote immutable, structured consent "
                "resources through preview, publish, rollback, and withdrawal."
            ),
            capabilities=(
                "Enroll an exact property and append versioned consent resources.",
                "Preview a pinned bundle and publish it with compare-and-swap authority.",
                "Roll back as a new auditable publication or withdraw into an immutable tombstone.",
            ),
            boundaries=(
                "Resources accept closed structured data, not arbitrary HTML, script, URLs, or CSS.",
                "Publishing and rollback require exact current revisions; history is not rewritten.",
                "Withdrawal denies public resolution but does not delete prior audit records.",
            ),
            next_steps=(
                "Confirm publishing is enabled and the property enrollment is exact.",
                "Preview the pinned resource versions before promoting the bundle.",
                "Use rollback or withdrawal only after reviewing the immutable result it creates.",
            ),
            suggested_questions=(
                "What should I verify before publishing?",
                "How do rollback and withdrawal differ?",
            ),
        ),
        _registered(
            path="/consent/experiments",
            summary=(
                "Govern immutable consent-presentation experiments, bounded assignments and outcomes, "
                "statistical review, and fail-safe rollback to control."
            ),
            capabilities=(
                "Create and independently approve a closed experiment definition.",
                "Assign variants without retaining raw identity and record bounded binary outcomes.",
                "Inspect, analyze, stop, kill, or roll an experiment back to control.",
            ),
            boundaries=(
                "The experiment creator and definition approver must be different authenticated people.",
                "Legal signals, required purposes, inaccessible rendering, or unequal choices fall back to control.",
                "A statistical winner is not legal, causal, accessibility, or customer-estate acceptance.",
            ),
            next_steps=(
                "Load current limits and confirm the feature, privacy review, and rollback authority are ready.",
                "Approve the exact immutable definition with a distinct authorized reviewer.",
                "Inspect guardrail and sample bounds before accepting or stopping a result.",
            ),
            suggested_questions=(
                "What makes an experiment eligible to run?",
                "What does a winning variant not prove?",
            ),
        ),
        _registered(
            path="/consent/delivery",
            summary=(
                "Synchronize immutable preference receipts to exact HTTPS destinations through a "
                "signed, retryable queue with explicit dispatch and recovery."
            ),
            capabilities=(
                "Enroll or revoke an exact destination and rotate its signing-key identifier.",
                "Bridge authoritative preference changes into a durable signed queue.",
                "Dispatch bounded Salesforce, Marketo, Adobe Experience Platform, and Snowflake provider contracts.",
                "Inspect adapter readiness, minimized receipts, ambiguous outcomes, integrity, audit evidence, and dead letters.",
            ),
            boundaries=(
                "Sync queues only events reconstructed from immutable receipts.",
                "Provider origins, DNS authority, signing keys, OAuth credentials, workspace identity, and destination mappings are server-controlled.",
                "Named adapters refuse redirects and remain unavailable without deployment-held credential references and independent reconciliation authority.",
                "A local acknowledgement or ready state does not prove live provider interoperability, permissions, completeness, customer acceptance, or applied state.",
            ),
            next_steps=(
                "Confirm the destination, signing custody, retry, privacy, and recovery reviews are complete.",
                "Load queue and named-adapter readiness before dispatching a bounded batch.",
                "Reconcile ambiguous provider outcomes independently before replay or acceptance.",
            ),
            suggested_questions=(
                "What must be ready before dispatch?",
                "Which named provider bindings are ready?",
                "How should I reconcile an ambiguous delivery?",
            ),
        ),
        _registered(
            path="/consent/public-clients",
            summary=(
                "Mint and revoke exact-origin browser or service clients for the active consent "
                "publication and receipt policy."
            ),
            capabilities=(
                "Mint a browser client bound to an exact property, origin, jurisdiction, and policy revision.",
                "List minimized client bindings and revoke a client or profile capability.",
                "Use the inert public SDK for structured first-party consent integration.",
            ),
            boundaries=(
                "A raw client credential is returned once and is never stored by the authority.",
                "Origins, properties, publications, and receipt policies are exact rather than inferred.",
                "The SDK does not grant authority beyond the active server-side consent configuration.",
            ),
            next_steps=(
                "Verify consent publishing and the public API are enabled and the active publication is correct.",
                "Copy the one-time credential directly into approved custody.",
                "Revoke a compromised client or profile capability using its exact revision.",
            ),
            suggested_questions=(
                "What is the one-time credential boundary?",
                "What must match before I mint a client?",
            ),
        ),
        _registered(
            path="/consent/native",
            summary=(
                "Operate application and device authority for the attested mobile and "
                "OTT/CTV consent runtime and its offline-verifiable receipt keys."
            ),
            capabilities=(
                "Register a globally unambiguous application from an exact active service client and published consent bundle.",
                "Rotate configured receipt keys, rotate freshly attested device keys, revoke devices, and inspect exact CAS results.",
                "Check fail-closed readiness and integrity and discover current and historical public receipt verification keys.",
            ),
            boundaries=(
                "Workspace, principal, publication, service-client, signer and stored device authority are server-derived; the browser supplies only safe selectors, CAS revisions and attestation evidence.",
                "Platform attestation has no permissive fallback, and configured profile, rights and GPP/TCF callbacks are required before readiness.",
                "Local and synthetic success does not prove app-store, live-device, accessibility, conformance, customer-estate or regulator acceptance.",
            ),
            next_steps=(
                "Confirm signer custody, the external platform verifier and any configured callback requirements before registration.",
                "Register the create-only application authority from its exact public service client and save the returned authority digest.",
                "Exercise enrollment, refresh, offline receipt verification, recovery and representative live-device acceptance before production reliance.",
            ),
            suggested_questions=(
                "Why is native consent not ready?",
                "What authority is an application registration pinned to?",
                "What remains to be validated on live devices?",
            ),
        ),
        _registered(
            path="/consent/profile-data",
            summary=(
                "Govern closed profile-data catalogs and journeys with revision-pinned publication, "
                "independent approval, integrity, and retention controls."
            ),
            capabilities=(
                "Create and inspect closed catalog and journey versions.",
                "Record independent approval and publish exact revisions.",
                "Verify integrity and purge only retention-eligible operational records.",
            ),
            boundaries=(
                "Workspace and actor are server-derived; the page accepts no raw profile or capability selector.",
                "Authors cannot approve their own versions and every mutation uses an exact revision.",
                "Only closed published values and trusted purposes are supported; protected traits are never inferred.",
            ),
            next_steps=(
                "Load status and confirm the catalog, journey, and approval authorities are composed.",
                "Review the closed values and trusted purpose before submitting a version.",
                "Have a distinct authorized person approve before publication.",
            ),
            suggested_questions=(
                "What profile data is allowed here?",
                "Who may approve a catalog or journey?",
            ),
        ),
        _registered(
            path="/consent/scan-inventory",
            summary=(
                "Run bounded browser scans against enrolled properties, review minimized tracker "
                "discoveries, and bridge only fresh approved mappings."
            ),
            capabilities=(
                "Add an exact website, schedule scans, and start a scan when you choose.",
                "Inspect bounded reports and record versioned classification review.",
                "Bridge fresh reviewed mappings and operate audit, recovery, and retention controls.",
            ),
            boundaries=(
                "A scan performs external browser requests only against an enrolled property.",
                "Every discovery remains unknown until reviewed; bridging is a separate governed action.",
                "A complete bounded report does not prove that no tracker exists.",
            ),
            next_steps=(
                "Confirm property authority, browser adapter, privacy review, and scan limits.",
                "Inspect completeness, truncation, and errors before classifying a discovery.",
                "Bridge only a fresh, revision-pinned reviewed mapping.",
            ),
            suggested_questions=(
                "What does scan completeness mean?",
                "When may a discovery be bridged?",
            ),
        ),
        _registered(
            path="/consent/scan-notice-proposals",
            summary=(
                "Turn independently reviewed scan evidence into content-free, revision-pinned "
                "disclosure proposals for separate approval and local acceptance."
            ),
            capabilities=(
                "Create a proposal from exact server-resolved scan and inventory evidence.",
                "Record independent approval and separate local acceptance.",
                "Inspect integrity and export a signed, content-free governance record.",
            ),
            boundaries=(
                "The browser cannot select workspace, principal, property, report, inventory revision, or revocation set.",
                "Approval and local acceptance require different authenticated people and exact source pins.",
                "Acceptance does not generate legal copy, mutate a site or app, call a provider, or publish a notice.",
            ),
            next_steps=(
                "Load status and verify the source report and reviewed inventory remain current.",
                "Use distinct authorized people for approval and local acceptance.",
                "Treat the signed export as governance evidence, not proof of publication.",
            ),
            suggested_questions=(
                "What evidence is pinned into a proposal?",
                "What does local acceptance not do?",
            ),
        ),
        _registered(
            path="/consent/trust-center-authority",
            summary=(
                "Govern digest-bound consumer capability grants and privacy-rights case authority "
                "through server-resolved identity and multi-party approval."
            ),
            capabilities=(
                "Create, inspect, approve, revoke, and verify capability grants.",
                "Authorize privacy-rights cases against exact package and consumer bindings.",
                "Inspect integrity and retention evidence without exposing raw identity material.",
                "Propose, independently review, activate, rotate, revoke, and retain bounded PNG/JPEG brand assets.",
                "Challenge and govern exact custom-domain claims through an injected DNS/TLS deployment authority.",
                "Bind an approved asset and optional verified domain to the exact enrolled client and consent publication.",
            ),
            boundaries=(
                "Workspace, operator, consumer binding, permission authority, and signing keys are server-resolved.",
                "Every grant and case authorization requires a requester plus two other distinct approvers.",
                "The surface performs no identity proof, network call, provider write, or completeness inference.",
                "Branding accepts no SVG, HTML, CSS, URL, raw storage path, caller-selected workspace, or encryption key.",
                "Live DNS/TLS/CDN issuance and accessibility, brand, and customer acceptance remain external.",
            ),
            next_steps=(
                "Confirm the identity, consumer-binding, permission, and key authorities are ready.",
                "Review the exact digest-bound grant or package before collecting approvals.",
                "Use two distinct authorized approvers other than the requester.",
                "For branding, review the raster digest and dimensions before activation, then pin it to the current publication.",
            ),
            suggested_questions=(
                "Why are three distinct people required?",
                "What identity material is excluded?",
                "What does the brand projection prove, and what remains external?",
            ),
        ),
        _registered(
            path="/data-use",
            summary=(
                "Authorize data use from catalog bindings, independently sourced decision context, "
                "reviewed labels, policy, exceptions, and provider-neutral control intent."
            ),
            capabilities=(
                "Catalog assets and fields, lineage, context, labels, and policy versions.",
                "Create a project data-use request and record a revision-pinned authorization decision.",
                "Inspect provider-neutral control IR and bounded authority records.",
            ),
            boundaries=(
                "Four independent context records must be fresh before data use can be authorized.",
                "Policy authors cannot approve their own versions and requesters cannot authorize their own use.",
                "Provider writes remain off until an approved native adapter is explicitly configured.",
            ),
            next_steps=(
                "Verify catalog, lineage, purpose, jurisdiction, and classification context are fresh.",
                "Publish an independently approved policy before evaluating a request.",
                "Inspect the compiled control intent before any native-provider operation.",
            ),
            suggested_questions=(
                "Which context records must be fresh?",
                "When can a provider write occur?",
            ),
        ),
        _registered(
            path="/data-use/providers",
            summary=(
                "Apply authorized data-use decisions to exact Snowflake and Databricks resources "
                "through server-controlled credentials and safe-deny reconciliation."
            ),
            capabilities=(
                "Enroll or permanently revoke an exact native-resource binding.",
                "Apply a freshly recompiled authorized masking, row-filter, access, or deny decision.",
                "Reconcile provider state and roll ambiguous or rejected operations toward safe deny.",
            ),
            boundaries=(
                "Binding enrollment accepts no credential or provider origin from the browser.",
                "Apply recompiles the exact authorized decision before performing an external write.",
                "Rollback converges to safe deny; it does not recreate arbitrary prior provider state.",
            ),
            next_steps=(
                "Confirm the native adapter, credential reference, target binding, and recovery plan.",
                "Re-read the data-use decision immediately before apply.",
                "Reconcile the provider after acceptance, timeout, or ambiguous acknowledgement.",
            ),
            suggested_questions=(
                "What is required before a native apply?",
                "What does rollback restore?",
            ),
        ),
        _registered(
            path="/compliance",
            summary=(
                "Triage governed compliance assessments, evidence needs, control work, and exports "
                "without turning local workflow state into a compliance conclusion."
            ),
            capabilities=(
                "Review assessment work that needs attention and filter it by governed state.",
                "Inspect evidence and control records and prepare bounded exports.",
                "Open policy publication, scoping, and scope-action workbenches.",
            ),
            boundaries=(
                "Workflow state and local evidence do not establish legal applicability or compliance.",
                "Framework text, external evidence rights, and final disposition remain separately governed.",
            ),
            next_steps=(
                "Start with items that need attention and verify their evidence revision.",
                "Choose policy publication, scoping, or scope actions for the exact task.",
                "Have the configured accountable person accept any final disposition.",
            ),
            suggested_questions=(
                "Which compliance workbench should I use?",
                "What does an assessment state prove?",
            ),
        ),
        _registered(
            path="/compliance/grc-studio",
            summary=(
                "Visually compose closed-schema GRC objects, fields, forms, rules, "
                "collector bindings, and report views under governed publication."
            ),
            capabilities=(
                "Build a draft through guided object, field, form, rule, collector-binding, and report-view controls.",
                "Submit, independently review, approve, publish, roll back, revoke, and recover an exact revision under CAS.",
                "Export and import authenticated portable packages and inspect integrity, retention, and runtime projections.",
            ),
            boundaries=(
                "Copilot is read-only and cannot create, review, approve, publish, roll back, revoke, import, or recover a studio.",
                "The studio cannot supply deployment-owned collector credentials, provider transports, or target write authority.",
                "Local studio state is not evidence of live provider interoperability, customer usability, regulator acceptance, or compliance.",
            ),
            next_steps=(
                "Confirm the active workspace, readiness state, and role before authoring a draft.",
                "Use different principals for authoring, review, and approval before publication.",
                "Validate runtime projections and recovery with the deployment-owned target before relying on them operationally.",
            ),
            suggested_questions=(
                "What can I configure without code?",
                "What must happen before publication?",
                "What does the runtime projection prove?",
            ),
        ),
        _registered(
            path="/compliance/policy-links",
            summary=(
                "Publish immutable, independently reviewed policy versions through stable links, "
                "scheduled promotion, fail-closed retrieval, and bounded evidence operations."
            ),
            capabilities=(
                "Create an immutable policy artifact and record its required independent review.",
                "Move a stable-link pointer with compare-and-swap or schedule a bounded promotion.",
                "Rotate or revoke private capabilities and inspect audit, access, retention, and integrity evidence.",
            ),
            boundaries=(
                "Only a policy version satisfying its exact review mode may be published.",
                "Private link capabilities are returned once and should replace shared administrator access.",
                "Scheduled changes require the bounded worker; expiry and revocation fail closed during retrieval.",
            ),
            next_steps=(
                "Verify storage, access, recovery, retention, and review-mode configuration.",
                "Record the required independent review before moving the stable pointer.",
                "Inspect the bounded worker and integrity evidence after a scheduled change.",
            ),
            suggested_questions=(
                "What must happen before publication?",
                "How are private links rotated safely?",
            ),
        ),
        _registered(
            path="/compliance/scoping",
            summary=(
                "Publish closed, reference-only questionnaires and compute, independently approve, "
                "sign, export, and verify exact compliance-scope revisions."
            ),
            capabilities=(
                "Create and independently publish a closed scoping questionnaire.",
                "Compute a scope result from exact answers and record independent final approval.",
                "Sign, export, inspect, and verify a revision-pinned scope record.",
            ),
            boundaries=(
                "Questionnaires contain opaque references and closed values, never licensed framework prose.",
                "A questionnaire creator cannot publish it and a scope computer cannot approve their own result.",
                "Signing accepts only an environment, vault, or secret reference, never a key value.",
            ),
            next_steps=(
                "Confirm the framework references, question schema, signing reference, and retention authority.",
                "Use a distinct publisher and a distinct final scope approver.",
                "Verify the signed export against its exact revision and evidence pins.",
            ),
            suggested_questions=(
                "Why is framework prose excluded?",
                "Who must be independent in scoping?",
            ),
        ),
        _registered(
            path="/compliance/scope-actions",
            summary=(
                "Derive a governed action plan from an independently finalized scope and approved "
                "mapping catalog, then approve, apply, reconcile, roll back, and export it."
            ),
            capabilities=(
                "Publish an opaque mapping catalog and create an exact scope-derived action plan.",
                "Independently approve, apply, reconcile, or roll back an idempotent local operation.",
                "Inspect signed exports, history, recovery state, and integrity evidence.",
            ),
            boundaries=(
                "Plans require an exact finalized scope and an independently approved mapping catalog.",
                "A separate principal must approve the plan and the server must install the idempotent callback.",
                "Callback and plan stores are not one transaction; uncertain operations reuse their deterministic reference.",
            ),
            next_steps=(
                "Verify the finalized scope, approved catalog, callback, and recovery design.",
                "Have a distinct principal approve the exact plan revision before apply.",
                "Reconcile an ambiguous callback before retrying or rolling back.",
            ),
            suggested_questions=(
                "What must be approved before apply?",
                "How do I recover an uncertain callback?",
            ),
        ),
        _registered(
            path="/compliance/continuous-evidence",
            summary=(
                "Collect evidence from approved sources, review what was checked, "
                "and follow changes to your controls."
            ),
            capabilities=(
                "Collect from configured AWS, Azure, Google Cloud, GitHub and Okta sources, plus Lightwork's own security checks.",
                "Use each source's Set up, Approve, Start collecting, Pause and Resume controls.",
                "Review recent collections and evidence changes, retry failed collections, and check retained records.",
            ),
            boundaries=(
                "A different administrator must approve a source's setup before collection starts.",
                "Checking setup does not collect from an outside service. Collection checks the current approval and access again.",
                "Evidence shows what was checked. It does not prove every system is covered, that a control works, or that the company is certified.",
            ),
            next_steps=(
                "Refresh Sources and review which connections are ready.",
                "Choose Set up, ask another administrator to Approve, then use Start collecting to choose the schedule and keep period.",
                "Use Collect evidence now for due work, then review incomplete collections and recorded changes before relying on the evidence.",
            ),
            suggested_questions=(
                "Read current evidence collection status",
                "Open evidence source setup",
                "Open complete evidence controls",
                "Why does setup need another administrator's approval?",
                "What does collected evidence tell us?",
            ),
        ),
        _registered(
            path="/privacy",
            summary=(
                "Coordinate privacy assessments, residual-risk review, vendor paper, program "
                "insights, lineage, and governed privacy records."
            ),
            capabilities=(
                "Triage privacy work and inspect assessment flow, residual risk, and framework views.",
                "Review vendor paper and supporting evidence beside the governed record.",
                "Inspect a registered vendor's current assessments, screening, contracts and open tasks together; explicitly link an existing profile or review activation after the latest assessment.",
                "Inspect program insights, lineage, and bounded privacy records.",
                "Read the selected privacy request's current response deadline, remaining work and recorded answer, then open its complete native record.",
            ),
            boundaries=(
                "Generated analysis and redlines are decision support, not legal advice or approval.",
                "Vendor submissions and local workflow state are not independently verified external facts.",
                "Vendor activation requires the latest complete evaluated assessment; linking existing identities does not create fresh screening or independent identity verification.",
                "Final applicability, risk acceptance, and disposition remain human decisions.",
                "A collected data package is separate from an answer; recorded answers do not independently confirm receipt or deletion by another service.",
            ),
            next_steps=(
                "Open the work item that needs attention and verify its current evidence revision.",
                "Use lineage to understand why a prior decision was recorded.",
                "Have the accountable privacy reviewer accept or reject the result.",
            ),
            suggested_questions=(
                "Where should I start on this privacy page?",
                "What does lineage show?",
            ),
        ),
        _registered(
            path="/channels",
            summary="Connect chat apps, choose who may use them and review their current readiness.",
            capabilities=(
                "Check each saved chat connection and its permitted people.",
                "Open the complete protected message test for Telegram, Discord, WhatsApp or Mattermost.",
                "Review a currently permitted private conversation and the fixed test sentence before sending; read its original outcome afterward.",
                "Check whether Signal or IRC replies are waiting behind an earlier reply in the same chat, and when they go out.",
            ),
            boundaries=(
                "A connection check does not prove a person received a message; a service accepting the test is a separate result.",
                "An uncertain message outcome must be read from its original before a separate new decision; it is never automatically resent.",
                "WhatsApp tests need a recent saved private conversation; the service can still refuse a reply outside its allowed window.",
            ),
            next_steps=(
                "Choose the chat app and check its current connection.",
                "Open the protected form, choose a permitted conversation and review the recipient and message.",
                "Confirm the send separately, then read its saved outcome.",
            ),
            suggested_questions=("How can I check this chat connection?", "Are any chat replies waiting?",
                                 "Can I review a test message?", "Was my earlier test accepted?"),
        ),
        _registered(
            path="/privacy/data-discovery",
            summary=(
                "Enroll exact data sources, run bounded provider scans, review minimized findings, "
                "and promote only fresh four-eyes-approved classifications."
            ),
            capabilities=(
                "Enroll, suspend, reactivate, or revoke an exact source and its schedule.",
                "Start, retry and inspect scans through stock AWS S3, Azure Blob, Google Cloud Storage, Snowflake metadata, ServiceNow CMDB, and Microsoft Entra adapters.",
                "Read recent retained scan states in Copilot, then open the same protected scan review without changing the current source selection or drafts.",
                "Propose and independently approve a classification, then operate its durable remediation outbox and digest-only governed data-map projection.",
                "Inspect or enable the bounded managed remediation scheduler for workspace-derived retry and exact local ambiguity reconciliation.",
            ),
            boundaries=(
                "Raw secrets never enter the page; credentials and adapters are server-resolved.",
                "Every report is bounded and completeness-explicit; no findings never proves absence.",
                "Only a fresh four-eyes-approved classification can enter remediation; stock adapters do not prove live provider acceptance, estate completeness, or an authorized provider write.",
                "Managed retry is a separate explicit opt-in and operates only the built-in digest-only data map; running health is not provider or completeness evidence.",
            ),
            next_steps=(
                "Verify the exact source, credential reference, provider adapter, privacy review, and scan bounds.",
                "Inspect completeness, truncation, and errors before proposing a classification.",
                "Use a distinct authorized approver, then run and reconcile the durable outbox before treating the data map as current.",
                "Confirm the workspace scheduler opt-in, bounded cycle status, recovery counter, and concurrency exclusion before relying on automatic retry.",
            ),
            suggested_questions=(
                "What does a discovery report prove?",
                "When may a classification be bridged?",
            ),
        ),
        _registered(
            path="/privacy/regulatory-intelligence",
            summary=(
                "Govern licensed regulatory sources, immutable evidence, corpus-grounded research, "
                "jurisdiction comparison, saved queries, alerts, reports, and retention."
            ),
            capabilities=(
                "Enroll a source, record independent rights review, and ingest immutable evidence.",
                "Run cited research and jurisdiction comparison over the retained approved corpus.",
                "Operate saved-query alerts, durable delivery, reports, integrity, and retention.",
            ),
            boundaries=(
                "Source license and permitted uses require independent review before enrollment.",
                "Answers are corpus-grounded and abstain when the configured evidence floor is not met.",
                "The workspace does not bundle OneTrust DataGuidance content or replace legal advice.",
            ),
            next_steps=(
                "Confirm source rights, purpose, territory, retention, and evidence custody.",
                "Review every citation and abstention before relying on a research result.",
                "Inspect retry, dead-letter, and acknowledgement ambiguity after alert delivery.",
            ),
            suggested_questions=(
                "What source rights are required?",
                "What does an abstention mean?",
            ),
        ),
        _registered(
            path="/privacy/rights-orchestration",
            summary=(
                "Open and coordinate minimized privacy-rights cases, external identity evidence, "
                "tasks, callbacks, approvals, closure, integrity, and retention."
            ),
            capabilities=(
                "Open a case from HMAC-minimized subject and external-request references.",
                "Coordinate identity-evidence status, tasks, callback intent, and response-package authority.",
                "Record independent closure approval and inspect audit, integrity, and retention state.",
            ),
            boundaries=(
                "Raw subject and external request references are HMACed and never persisted or returned.",
                "Identity status records external evidence only; Lightwork does not perform identity verification.",
                "Callbacks are local worker intent, not network transport, provider write, response delivery, or completeness proof.",
                "Manual result statements and document fingerprints remain independently unverified; open the native complete evidence review before manually attesting.",
                "A connected-system active-record lookup with no match does not prove purge from retained copies or backups. Closure and completeness describe workflow status, not deletion certification.",
            ),
            next_steps=(
                "Confirm case, HMAC, task, callback, and package authorities are composed.",
                "Review independently obtained identity evidence before advancing the case.",
                "Require a distinct authorized closure approver and verify callback outcomes separately.",
            ),
            suggested_questions=(
                "How is subject identity minimized?",
                "What does a callback record prove?",
            ),
        ),
        _registered(
            path="/privacy/rights-consumer-delivery",
            summary=(
                "Mint digest-retained consumer delivery capabilities, govern exact response packages, "
                "revoke deliveries, export evidence, and purge retention-eligible records."
            ),
            capabilities=(
                "Create and inspect a delivery bound to server-resolved consumer and package authority.",
                "Revoke a delivery and produce a bounded signed evidence export.",
                "Inspect integrity and purge only retention-due delivery records.",
                "Deliver an exact pinned package from the encrypted governed-document vault after repeated orchestration and vault authority checks.",
            ),
            boundaries=(
                "A raw consumer capability appears only in the first mint response; only its digest is retained.",
                "Public consumer binding and reauthentication are independent trusted resolvers; case or package authority is never treated as identity proof.",
                "Digest, export-signing, and package-encryption authority are pinned key references; raw key values are not configuration or status data.",
                "The operator page exposes no redeem, object bytes, credentials, provider write, or live-customer acceptance.",
            ),
            next_steps=(
                "Load composition readiness and verify independent reauthentication, consumer binding, exact package authority, key-reference custody, and retention.",
                "Move the one-time raw capability directly into approved delivery custody.",
                "Revoke with an exact revision and verify the resulting evidence independently.",
            ),
            suggested_questions=(
                "How is the consumer capability retained?",
                "Why is operator minting still fail-closed?",
                "What is excluded from this operator page?",
            ),
        ),
        _registered(
            path="/privacy/notice-governance",
            summary=(
                "Govern digest-only privacy-notice releases and the optional exact-target "
                "local bridge into tenant-private Consent Publishing authority."
            ),
            capabilities=(
                "Create a notice release from opaque content and evidence references.",
                "Record independent approval, publication intent, rollback, withdrawal, revocation, and expiry.",
                "Run one bounded workspace-derived local publication cycle through an exact server-owned target binding.",
            ),
            boundaries=(
                "Releases carry only digests and opaque references; raw notice content and key values are rejected.",
                "Workspace, target property, consent reference, rule group, resource versions, and CAS revisions are server-derived.",
                "The runtime mutates only Lightwork's local consent publication store; it has no website, provider, tag-manager, or SDK mutation path.",
                "Local completion is not proof of customer browser behavior, provider acceptance, production deployment, or legal sufficiency.",
            ),
            next_steps=(
                "Load runtime status and confirm configuration preflight is ready for the active workspace.",
                "Have an authorized person other than the author approve the exact release.",
                "Verify the release digests and exact target binding before authorizing one local cycle.",
            ),
            suggested_questions=(
                "Is the local publication runtime configured for this workspace?",
                "What does a successful local publication prove?",
                "How does rollback choose the exact prior bundle?",
            ),
        ),
        _registered(
            path="/third-party/contracts",
            summary=(
                "Govern first-class Contract and Engagement records tied to exact "
                "third-party vendor revisions."
            ),
            capabilities=(
                "Create, filter, inspect, update, archive, and tombstone Contracts and Engagements.",
                "Manage closed custom-field schemas, option codes, redaction, and deterministic formulas.",
                "Inspect immutable history, integrity, retention queues, and recovery readiness.",
            ),
            boundaries=(
                "Workspace, actor, vendor type, vendor authority, issuer, revocation, retention, and storage are server-owned.",
                "Raw contracts, licensed templates, executable formulas, provider adapters, and recovery paths are not accepted.",
                "Recovery preflight verifies readiness and integrity; actual backups remain server-configured administrator operations.",
            ),
            next_steps=(
                "Confirm the workspace composition is enabled, configured, and ready.",
                "Use the exact enrolled vendor ID and revision before creating a record.",
                "Review redaction, history, and integrity after material lifecycle changes.",
            ),
            suggested_questions=(
                "What vendor authority is pinned to this Contract?",
                "Which fields are redacted and why?",
                "When can an archived record be purged?",
            ),
        ),
        _registered(
            path="/third-party/executive-reports",
            summary=(
                "Create role-scoped, brandable PDF reports from exact revision- and "
                "digest-pinned third-party records."
            ),
            capabilities=(
                "Resolve selected lifecycle, intelligence, contract, engagement, and collaboration records without copying raw source data.",
                "Render a bounded deterministic PDF with closed branding and role-aware metrics.",
                "Issue principal-bound one-time downloads, revoke reports, purge expired records, and verify audit integrity.",
            ),
            boundaries=(
                "Unavailable sources remain explicit and never become invented portfolio facts.",
                "Branding accepts closed text and color tokens, not HTML, scripts, URLs, fonts, or arbitrary assets.",
                "A local PDF is audit evidence, not proof of live portfolio completeness, customer acceptance, or an external WORM anchor.",
            ),
            next_steps=(
                "Confirm reporting composition and each selected source authority are ready.",
                "Choose the smallest exact source set and review unavailable-source reasons before creating a report.",
                "Use the one-time grant from approved custody and verify report integrity before distribution.",
            ),
            suggested_questions=(
                "Which source records can I include?",
                "What does this PDF prove?",
                "How are download grants protected?",
            ),
        ),
        _registered(
            path="/administration/document-vault",
            summary=(
                "Custody bounded approved document bytes in workspace-private encrypted "
                "storage and deliver them only through one-time principal-bound grants."
            ),
            capabilities=(
                "Ingest approved media without accepting paths, URLs, bucket keys, or object locators.",
                "List minimized authority metadata, revoke documents under CAS, and purge only after retention.",
                "Mint short-lived access tokens, atomically redeem one-time delivery grants, recover leases, and verify integrity.",
            ),
            boundaries=(
                "The UI never exposes ciphertext locations, encryption keys, raw token digests, or storage credentials.",
                "Local encrypted custody does not prove external object-store, HSM/KMS, backup, or disaster-recovery acceptance.",
                "A successful download proves this local authority consumed one grant; relying workflow and customer acceptance remain separate.",
            ),
            next_steps=(
                "Confirm the vault and Administration Document Access readiness probes are both ready.",
                "Ingest only approved bounded media and preserve the returned exact authority revision and digest.",
                "Exercise one-time delivery, replay rejection, revocation, recovery, retention, and integrity before production use.",
            ),
            suggested_questions=(
                "What document data is stored here?",
                "How does one-time delivery work?",
                "What still needs external acceptance?",
            ),
        ),
        _registered(
            path="/third-party/intelligence",
            summary=(
                "Govern licensed vendor intelligence, screening, explainable risk, enhanced due "
                "diligence, monitoring, delivery, and a consent-bound contribution exchange."
            ),
            capabilities=(
                "Enroll approved source rights and immutable snapshots for pseudonymous vendor screening.",
                "Review findings, risk policy, overrides, rollback, and enhanced due-diligence evidence.",
                "Operate DNS-pinned, GET-only normalized reference feeds for RiskRecon, SecurityScorecard, HackNotice, SupplyWisdom, ISS Corporate Solutions, and one approved generic provider.",
                "Operate scheduled monitoring, durable alerts, retention, integrity, and consent-bound aggregate exchange.",
            ),
            boundaries=(
                "Source license, purpose, territory, and retention require independent review.",
                "Sanctions, PEP, watchlist, and adverse-media candidates require explicit human disposition.",
                "A configured reference contract or verified credential reference does not prove licensed data, vendor-native interoperability, completeness, scale, or provider acceptance.",
                "External delivery occurs only through a configured server-side destination resolver and transport.",
            ),
            next_steps=(
                "Load provider runtime status, then have an administrator verify the exact approved monitoring source credential before the scheduler makes an attempt.",
                "Verify source rights, host authority, completeness, and the exact snapshot before screening a vendor.",
                "Disposition uncertain findings and review cited evidence before accepting risk.",
                "Confirm contribution consent and privacy review before using the exchange.",
            ),
            suggested_questions=(
                "Which named provider reference contracts are ready for an attempt?",
                "What evidence rights must be approved?",
                "Which findings require human review?",
            ),
        ),
        _registered(
            path="/third-party/lifecycle",
            summary=(
                "Coordinate versioned vendor assessments, conditional workflow, evidence references, "
                "callbacks, offboarding, independent completion, audit, and retention."
            ),
            capabilities=(
                "Create and publish approved assessment templates and issue exact vendor assessments.",
                "Track answers, evidence references, conditions, callback intent, and lifecycle state.",
                "Plan offboarding, record independent completion, and inspect integrity and retention.",
            ),
            boundaries=(
                "Templates are versioned and records retain evidence references rather than raw vendor data.",
                "Offboarding, callbacks, state changes, and completion require explicit revision-bound decisions.",
                "Callbacks are local intent only; the surface proves no transport, provider write, or live acceptance.",
            ),
            next_steps=(
                "Verify the approved template, exact vendor binding, due dates, and evidence policy.",
                "Review conditions and callback results before changing lifecycle state.",
                "Use an independent authorized person to complete offboarding.",
            ),
            suggested_questions=(
                "What is retained from a vendor assessment?",
                "What does callback state prove?",
            ),
        ),
        _registered(
            path="/third-party/collaboration",
            summary=(
                "Invite consenting vendors into a scoped external portal and govern respondent "
                "attestations, document manifests, follow-up, rotation, revocation, and retention."
            ),
            capabilities=(
                "Create an invitation and disclose its one-time credential through approved custody.",
                "Inspect respondent answers and artifact manifests and record governed follow-up.",
                "Rotate, revoke, retain, purge, and verify exact invitation and response records.",
            ),
            boundaries=(
                "Invitation credentials are disclosed once and require an independently approved delivery channel.",
                "Answers and artifact manifests are respondent attestations, not verified evidence or uploaded files.",
                "The collaboration surface issues no risk score, vendor approval, or external acceptance claim.",
            ),
            next_steps=(
                "Confirm vendor consent, invitation scope, document contract, delivery custody, and retention policy.",
                "Send the one-time credential only through the approved external channel.",
                "Review attestations independently before any risk or lifecycle decision.",
            ),
            suggested_questions=(
                "What does a vendor response prove?",
                "How should an invitation credential be handled?",
            ),
        ),
        _registered(
            path="/governance/inventory",
            summary=(
                "Inspect one revision-pinned, digest-only inventory across AI Governance, "
                "Consent, Data Use, Privacy, Tech Risk, and Third-Party Management."
            ),
            capabilities=(
                "Inspect the active immutable inventory snapshot and its six source authorities.",
                "Query bounded entities and relationships without loading raw source records.",
                "Reconcile exact source revisions, verify integrity, create bounded exports, and operate authenticated recovery checkpoints when authorized.",
            ),
            boundaries=(
                "The inventory proves only captured source revisions and never infers an unavailable source from another suite.",
                "Digest matches are deterministic references rather than fuzzy identity resolution or proof of real-world identity.",
                "Local reconciliation, exports, and recovery do not establish live provider completeness or external acceptance.",
            ),
            next_steps=(
                "Refresh readiness and confirm every required source authority is available.",
                "Inspect source completeness and the active revision before using a query or export.",
                "Use exact compare-and-swap values for reconciliation and verify integrity after recovery.",
            ),
            suggested_questions=(
                "What does this inventory prove?",
                "Which source is incomplete or unavailable?",
                "How should I safely reconcile or recover a snapshot?",
            ),
        ),
        _registered(
            path="/security/governance",
            summary=(
                "Run plain-language EU AI Act and governance workflows for legal, "
                "privacy, compliance, and HR teams."
            ),
            capabilities=(
                "Prepare fundamental-rights impact assessments, Annex IV documentation checklists, and conformity-assessment routes.",
                "Track role-specific AI literacy requirements, evidence, expiry, and coverage gaps.",
                "Operate Article 73 serious-incident clocks and inspect governed GRC synchronization state.",
            ),
            boundaries=(
                "Workspace records are decision support, not legal advice, certification, or a regulatory filing.",
                "Nothing on this page transmits a record to an authority or external system without separately configured and authorized integration.",
                "Local readiness and recorded evidence do not prove legal sufficiency, provider acceptance, or regulator acceptance.",
            ),
            next_steps=(
                "Open the governance record that needs attention and confirm its current revision and evidence.",
                "Resolve missing literacy, documentation, or incident-clock evidence with the accountable reviewer.",
                "Reconcile any configured GRC writeback against the external system before accepting the outcome.",
            ),
            suggested_questions=(
                "Which governance workflow should I use?",
                "What still needs human review?",
                "What does this workspace not prove?",
            ),
        ),
        _registered(
            path="/security/assurance",
            summary=(
                "Operate the AI evidence gateway, model-risk controls, and sixteen bounded governance "
                "modules from one assurance workspace."
            ),
            capabilities=(
                "Manage AI literacy evidence, the EU AI Act Article 73 incident clock, AI business intake, and AI cost and ROI.",
                "Inspect operational AI policy, explainable dynamic AI risk, transient runtime guardrails, and governed AI explanations.",
                "Prepare independent insurance-assurance profiles, EU AI Act conformity readiness, and regulated AI evidence packages.",
                "Operate the voluntary aggregate benchmark exchange and AI discovery sensor control plane.",
                "Inspect read-only identity and data-governance connectors and C2PA media-provenance evidence.",
                "Prepare and reconcile semantic GRC writeback through enrolled outbound authority.",
                "Review an AI-use exception with named safeguards, request independent approval, close it and read its retained result.",
            ),
            boundaries=(
                "AI literacy, intake, cost, policy, risk, and guardrail records are local decision support, not legal conclusions.",
                "Article 73 records are not regulatory filings; explanations, insurance profiles, conformity readiness, and packages are not certification.",
                "Benchmark transport does not establish contribution consent, anonymity, differential privacy, or privacy-budget approval.",
                "Discovery inventory is bounded; identity connectors are read-only and do not prove estate completeness or enforced conditional access.",
                "C2PA verification records provenance evidence rather than truth, and GRC writeback requires external reconciliation.",
            ),
            next_steps=(
                "Open only the module needed and load its current readiness, authority, and evidence state.",
                "For a policy exception, choose current rules and named safeguards, review the complete request and ask a different administrator to approve it.",
                "For literacy, Article 73, intake, cost, policy, risk, guardrails, explanations, insurance, conformity, or packages, verify the exact revision and required human decision.",
                "For benchmarks and discovery sensors, verify contribution consent, privacy review, completeness limits, key custody, and recovery before operation.",
                "For identity connectors, C2PA, and GRC writeback, reconcile live external state before accepting an outcome.",
            ),
            suggested_questions=(
                "Which assurance module should I use?",
                "How do I request an AI use exception?",
                "Which modules require external reconciliation?",
                "What does this workspace not prove?",
            ),
        ),
        _registered(
            path="/privacy/drop",
            summary=(
                "Bridge an independently enrolled California DROP record into the privacy-rights "
                "workflow and track a terminal, evidence-backed outcome."
            ),
            capabilities=(
                "List workspace-local broker, record, outcome, proposal, and key-revision authority without raw subject fields or key material.",
                "Propose broker enrollment/revocation, DROP record import/revocation, independent outcomes, and key lifecycle operations.",
                "Apply every authority mutation through a different authenticated administrator with revision and idempotency checks.",
                "Create a deletion or opt-out request from an enrolled DROP record.",
                "Load the current minimized request receipt.",
                "Record an exempted, deleted, opted-out, or not-found outcome.",
                "Inspect configured-for-attempt versus locally operational readiness, authority counts, scheduler health, revisions, and integrity.",
            ),
            boundaries=(
                "The page never accepts raw subject identity, credentials, key material, or attachments; authority imports use opaque references and SHA-256 evidence.",
                "A key revision cannot be retired while retained broker, record, outcome, request, or proposal evidence still depends on it.",
                "Terminal status requires independently resolved outcome evidence.",
                "Local records do not prove live DROP interoperability or legal acceptance.",
            ),
            next_steps=(
                "Refresh status and distinguish local operation from request executability; zero active records means no DROP request can execute.",
                "For a fresh workspace, enroll a broker and import a record through two-person authority proposals before creating a request.",
                "Use the exact external DROP ID, request type, approved template, and language.",
                "Propose and independently approve outcome evidence before recording a terminal status.",
            ),
            suggested_questions=(
                "What authority must exist for a DROP request?",
                "How do I complete a fresh-tenant two-person DROP lifecycle?",
                "Which records block retiring a principal-binding key revision?",
            ),
        ),
        _registered(
            path="/assessments",
            summary=(
                "Review the declared capabilities of specialists and workflows through "
                "privacy, security and AI-risk findings."
            ),
            capabilities=(
                "Choose a specialist or workflow and draft its assessment from declared capabilities.",
                "Read each finding and add an evidence note or link.",
                "With administrator access, approve a review, mark it as needing work and choose its review frequency.",
            ),
            boundaries=(
                "Automatic findings are a review aid, not a legal conclusion or certification.",
                "Auditors may read; administrator access and the current assessment revision are required for changes.",
            ),
            next_steps=(
                "Open an assessment from Register or Needs attention and read its complete findings.",
                "Review the evidence before approving each part; re-assess when its capabilities change.",
            ),
            suggested_questions=(
                "What do privacy, security and AI-risk reviews cover?",
                "What should I review before deciding?",
            ),
        ),
        _registered(
            path="/assess/evidence-autopopulation",
            summary=(
                "Turn released evidence analyses into cited assessment-answer proposals "
                "without treating documents as attestations."
            ),
            capabilities=(
                "Generate questionnaire-bound proposals from exact released evidence analyses.",
                "Inspect confidence, eligibility, digest citations, and authority pins.",
                "Approve or reject an explicit answer subset, then invoke application separately.",
            ),
            boundaries=(
                "Proposal generation never changes an assessment answer or score.",
                "Application fills only unanswered questions under assessment CAS and never overwrites an answer.",
                "Evidence-assisted answers are not attestations, certifications, legal conclusions, or live-provider acceptance.",
            ),
            next_steps=(
                "Confirm both proposal and AI Evidence Analysis compositions are ready.",
                "Generate a proposal for an open pinned assessment and released analysis IDs.",
                "Have a different human review eligible answers before separately applying them.",
            ),
            suggested_questions=(
                "What does proposal eligibility mean?",
                "Why can this answer not be applied?",
                "Which authorities are rechecked during apply?",
            ),
        ),
    )
)
_CONTEXT_BY_PATH = {context.path: context for context in _CONTEXTS}
if len(_CONTEXT_BY_PATH) != len(_CONTEXTS):  # pragma: no cover - import invariant
    raise RuntimeError("duplicate Copilot page context path")

_DETAIL_PAGE_CONTEXTS: tuple[tuple[str, str, Pattern[str]], ...] = (
    ("/privacy/vendors/", "/privacy", compile_regex(r"VMR-[0-9a-f]{24}\Z")),
    ("/privacy/dsar/", "/privacy", compile_regex(r"DSAR-[0-9a-f]{10}\Z")),
)

_RECORD_DETAIL_ROUTES: tuple[tuple[str, Pattern[str]], ...] = (
    ("task", compile_regex(r"/goals/([1-9][0-9]{0,17})(?:/(plan|trajectory|errors))?\Z")),
    ("task_chat", compile_regex(r"/chat/goal/([1-9][0-9]{0,17})\Z")),
    ("flow_designer", compile_regex(r"/flows/designer/([A-Za-z0-9_-]{1,120})\Z")),
    ("flow_run", compile_regex(r"/flows/([A-Za-z0-9_-]{1,120})/runs/([0-9a-f]{32})\Z")),
)


def record_detail_for_page(page: object) -> tuple[str, tuple[str, ...]] | None:
    """Recognize only bounded detail URLs issued by Lightwork routes."""

    if not isinstance(page, str) or len(page) > 200:
        return None
    path = page.strip()
    if not path.startswith("/") or path.startswith("//") or any(char in path for char in "?#\\"):
        return None
    for kind, pattern in _RECORD_DETAIL_ROUTES:
        match = pattern.fullmatch(path)
        if match:
            return kind, tuple(match.groups(default=""))
    return None


def _canonical_context_path(path: str) -> str:
    """Map a valid server-issued detail route to its closed parent context."""

    for prefix, canonical_path, identifier_pattern in _DETAIL_PAGE_CONTEXTS:
        if path.startswith(prefix):
            identifier = path.removeprefix(prefix)
            if identifier_pattern.fullmatch(identifier):
                return canonical_path
            break
    return path


def _registered_page_context(path: str) -> CopilotPageContext | None:
    """Build closed, page-specific help for registry pages without bespoke copy.

    Rich hand-authored contexts continue to win.  This fallback keeps every
    newly registered dashboard module from silently inheriting the unrelated
    generic home-page guide while preserving the closed-registry boundary.
    """

    from .ui_visibility import PAGES

    page = next((item for item in PAGES if item.get("path") == path), None)
    if page is None:
        return None
    title = str(page.get("label") or "Lightwork page")
    group = str(page.get("group") or "workspace")
    floor = str(page.get("floor") or "view")
    authority = {
        "view": "Anyone who can open this page can look; some changes need more access.",
        "operate": "Making changes here needs operator access.",
        "audit": "This page is for people who review the audit record.",
        "admin": "This page is for administrators.",
    }.get(floor, "Lightwork checks your access again for every change.")
    return _ensure_read_only(
        CopilotPageContext(
            path=path,
            title=title,
            summary=(
                f"{title} is part of Lightwork's {group} workspace. It shows "
                "the records, current status and controls available here."
            ),
            capabilities=(
                f"Review the {title} records and status available to you.",
                "Use the page's labeled controls when your access and setup allow it.",
            ),
            boundaries=(
                authority,
                "A visible control or ready status does not confirm that an outside service acted or accepted a result.",
            ),
            next_steps=(
                "Read the page status before choosing a control.",
                "After a change, check the result and saved record before relying on it.",
            ),
            suggested_questions=(
                f"What can I do on {title}?",
                "Where do I start on this page?",
                "What should I check before I rely on it?",
            ),
        )
    )


def context_for_page(page: object) -> CopilotPageContext:
    """Resolve a browser-proposed path to a closed server-owned context."""

    if not isinstance(page, str) or len(page) > 200:
        return _GENERIC
    path = page.strip()
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "?" in path
        or "#" in path
        or "\\" in path
    ):
        return _GENERIC
    detail = record_detail_for_page(path)
    if detail is not None:
        from dataclasses import replace

        kind, parts = detail
        if kind in {"task", "task_chat"}:
            section = parts[1] if kind == "task" else ""
            label = "Current chat task" if kind == "task_chat" else {"plan": "Task plan", "trajectory": "Task timeline", "errors": "Task errors"}.get(section, "Task result")
            base = _CONTEXT_BY_PATH["/chat"] if kind == "task_chat" else _registered_page_context("/goals")
            assert base is not None
            return replace(
                base, path=path, title=label,
                summary=("This conversation shows the current task, its answers and any next action."
                         if kind == "task_chat" else f"This is a task's {section or 'result'} page. Check its current status before using a control."),
                next_steps=("Review this task's current status and answer.", "Use the task tabs to inspect its plan, timeline, or errors."),
                suggested_questions=("What is this task's status?", "What should I do next on this task?"),
            )
        if kind == "flow_designer":
            base = _CONTEXT_BY_PATH["/workflows"]
            return replace(
                base, path=path, title="Flow designer",
                summary="This is the visual designer for a saved flow. Review its steps and current setup before saving or running it.",
                next_steps=("Review the saved flow's steps and inputs.", "Check required access and setup before saving or running it."),
                suggested_questions=("What flow am I editing?", "What should I check before running this flow?"),
            )
        base = _CONTEXT_BY_PATH["/workflows"]
        return replace(
            base, path=path, title="Flow run",
            summary="Review this workflow run's current state, complete permitted result and step timeline. Copilot can read its owned status and open the same complete result controls.",
            next_steps=("Check this run's current status and step timeline.", "Open Information in this run or What it started with, then expand details or choose Read more to see the complete permitted value.", "If a step failed or paused, review its native details before retrying or approving."),
            suggested_questions=("What is the status of this workflow run?", "Show this complete workflow result", "What should I check before retrying this run?"),
        )
    if path == "/compliance/scope-actions/mapping":
        return CopilotPageContext(
            path=path, title="Build a task mapping",
            summary="Choose a final compliance scope and define the control and evidence tasks it needs.",
            capabilities=("Review named final scopes and their controls.", "Prepare a task mapping and request a separate person's approval."),
            boundaries=("Only an approved mapping can support a task plan.", "This page records your team's choices; it does not supply licensed framework text.", _READ_ONLY_BOUNDARY),
            next_steps=("Choose a final scope, then the work status, responsible role and evidence cadence.", "Review the exact mapping and ask another authorized person to approve it."),
            suggested_questions=("Which controls need tasks?", "How do I prepare this scope's mapping?"),
        )
    if path == "/settings/webhooks/manage":
        return CopilotPageContext(
            path=path, title="Work updates",
            summary="Choose which saved task events send updates to another approved service, and read retained delivery states.",
            capabilities=("Read current subscription and recent delivery counts.", "Open the same complete update form from Copilot while keeping entered choices."),
            boundaries=("These controls require current administrator access.", "Waiting for your answer is separate from completed work. A queued update or service acceptance does not prove arrival."),
            next_steps=("Choose the events you need, including waiting questions or completed work, then review the full destination and signing setup in the protected form.", "Read retained deliveries before deciding whether to retry an update."),
            suggested_questions=("Read current work updates", "Open the complete update controls"),
        )
    if path == "/settings/local-ai":
        return CopilotPageContext(
            path=path, title="AI on this computer",
            summary="Choose an installed model program and an existing local model, then review starting or stopping it.",
            capabilities=("Review local model setup and current service state.", "Prepare supported setup, start and stop actions with original-result readback."),
            boundaries=("A model loading on this computer may need time and memory.", "A running service or connection check does not establish answer quality.", _READ_ONLY_BOUNDARY),
            next_steps=("Choose a supported program and an existing model in the setup form.", "Review each action and read its original request if the response is interrupted."),
            suggested_questions=("Is the local AI service responding?", "How do I start the selected model?"),
        )
    if path == "/settings/security-installation":
        return CopilotPageContext(
            path=path, title="Sign-in and work protection",
            summary="Review how people sign in and how automated work is contained on this installation.",
            capabilities=("Review current sign-in and work-protection policies.", "Prepare and confirm supported policy changes through the same native controls."),
            boundaries=("Only an installation administrator may change these policies.", "A connection check does not confirm that someone successfully signed in.", _READ_ONLY_BOUNDARY),
            next_steps=("Choose sign-in or work protection, review current settings and their source.", "Review each exact change and read its original saved result after an interruption."),
            suggested_questions=("How is work protected?", "Which sign-in settings need attention?"),
        )
    if path == "/settings/all":
        return CopilotPageContext(
            path=path, title="All settings",
            summary="Browse installation settings by group, search for a setting, and review saved values and their source.",
            capabilities=("Find and review installation settings available to administrators.", "Save or reset a setting through its reviewed page controls."),
            boundaries=("Only an installation administrator may open or change these settings.", _READ_ONLY_BOUNDARY),
            next_steps=("Open a group or search for the setting you need.", "Review the saved value, its source, and any restart note before making a change."),
            suggested_questions=("How do I find a setting?", "What happens when I reset a setting?"),
        )
    canonical = _canonical_context_path(path)
    return _CONTEXT_BY_PATH.get(canonical) or _registered_page_context(canonical) or _GENERIC


# Short, page-specific tips for the panel. The full boundaries above remain in
# the server's model context; implementation details do not need to fill the
# three visible tip slots on every page.
_PANEL_TIPS = {
    **{row[0]: row[5] for row in _OPERATIONAL_GUIDES},
    "/chat": "A chat starts work when you send it. Check your budget and what Lightwork will create first.",
    "/commitment-reviews": "These estimates use your team's inputs. They do not check supplier stock or reserve capacity.",
    "/workflows": "The guide can explain a flow. Use the designer to create or change one.",
    "/agents": "A Can start label checks required actions. Connections, access and the AI service are checked when work starts.",
    "/workforce": "Department counts show required actions. Connections, access and the AI service are checked when work starts.",
    "/fleets": "Choose an available agent and describe the task. Access, connections and the AI service are checked when work starts.",
    "/approvals": "An approval lets a paused step continue to other checks; it does not confirm success.",
    "/channels": "A connection check does not prove a person received a message, and an uncertain test is never resent automatically.",
    "/facts": "Shared facts are visible to workspace viewers. Personal and task notes stay private.",
    "/content-access": "Another administrator or the content owner must approve a read, and that access ends within an hour.",
    "/users/departures": "Deactivating local access does not end access granted by outside services.",
    "/companion/admin": "You need workspace administrator access and current employee membership to change companion policy.",
    "/companion": "A workspace administrator must enroll you before you can use a companion.",
    "/ai-evidence-analysis": "Results help review evidence. They do not certify compliance or provide legal advice.",
    "/assess/evidence-autopopulation": "A proposed answer does not change an assessment or its score until applied.",
    "/administration/document-vault": "Local encrypted storage does not confirm that outside backup or recovery has been tested.",
    "/ai-entity-tasks": "Current access and setup are checked when you start a task. A ready label does not prove the result.",
    "/governance-agents": "Governance agents help people decide; they cannot approve or act on their own.",
    "/agent-control-plane": "If the agent list cannot be read completely, Lightwork reports the gap instead of showing an empty list.",
    "/audit/evolution-ledger": "You can review learning history here. This page cannot approve, change or repair learned work.",
    "/governance/inventory": "The inventory shows sources Lightwork captured. Missing sources remain unknown.",
    "/consent": "A person's choice applies to the policy and notice version shown when it was made.",
    "/consent/publishing": "Publishing uses reviewed versions. Returning to an older version does not erase history.",
    "/consent/experiments": "A different person must approve an experiment before it can run.",
    "/consent/delivery": "A ready or completed local delivery does not confirm that a connected service applied the change.",
    "/consent/public-clients": "A client secret is shown once. Save it securely when it is issued.",
    "/consent/native": "Registration needs a valid check from the device platform; local success does not prove live app acceptance.",
    "/consent/profile-data": "Authors cannot approve their own versions, and protected traits are never inferred.",
    "/consent/custom-indexes": "Search matches exact saved values. It does not search across workspaces or guess from similar data.",
    "/consent/bulk-jobs": "A completed bulk change does not confirm that an outside service acted or received the result.",
    "/consent/publish-settings": "Lightwork keeps publishing keys and protected storage under administrator control.",
    "/consent/global-opt-out": "A local opt-out request does not confirm that every device or service honored it.",
    "/consent/application-scans": "The scan reviews submitted app information. It does not inspect a live device or network activity.",
    "/consent/scan-inventory": "Scan findings need a person's review before they become part of a consent notice.",
    "/consent/scan-notice-proposals": "Accepting a proposal does not publish a notice or change an app.",
    "/consent/trust-center-authority": "Access grants need a requester and two different approvers.",
    "/data-use": "Policy authors cannot approve their own changes, and requesters cannot authorize their own use.",
    "/data-use/providers": "Before writing to a connected service, Lightwork checks the approved decision again.",
    "/compliance": "Completed local work does not establish whether a law applies or whether you comply.",
    "/compliance/grc-studio": "The guide cannot create or approve studio work. Use the reviewed controls on this page.",
    "/compliance/policy-links": "Only a reviewed policy version can be published. Share private links carefully.",
    "/compliance/scoping": "A questionnaire creator cannot publish it or approve their own scope result.",
    "/compliance/scope-actions": "A plan needs a final scope and a separately approved mapping before use.",
    "/compliance/continuous-evidence": "A ready connection does not prove that every source was collected or that a control works.",
    "/privacy": "Draft analysis helps with review; it is not legal advice or final approval.",
    "/privacy/data-discovery": "No findings in a report do not prove that no private data exists.",
    "/privacy/regulatory-intelligence": "Sources must be cleared for their intended use before they are added.",
    "/privacy/rights-orchestration": "Lightwork records identity-check evidence from another source; it does not verify identity itself. Open the native complete evidence review before manually attesting. Manual result statements remain independently unverified, and an active-record lookup with no match does not certify permanent deletion.",
    "/privacy/rights-consumer-delivery": "A case or package does not prove someone's identity. Access needs a separate check.",
    "/privacy/notice-governance": "A finished local release does not confirm browser behavior or legal sufficiency.",
    "/privacy/drop": "A finished local record does not confirm that California's DROP service accepted it.",
    "/third-party/contracts": "Contracts and templates need review before use. This page does not accept executable content.",
    "/third-party/executive-reports": "Missing source data stays marked unavailable. Reports do not fill the gap with guesses.",
    "/third-party/intelligence": "Possible sanctions and watchlist matches need a person's review.",
    "/third-party/lifecycle": "Changing a vendor's status needs an explicit decision. Saved templates keep their versions.",
    "/third-party/collaboration": "A supplier's answer is their statement, not independently checked evidence.",
    "/security/governance": "These records support a review. They do not provide legal advice or certify a result.",
    "/security/assurance": "Local AI risk records support decisions. They are not legal conclusions or certification.",
    "/assessments": "Automatic findings help a person review declared capabilities; they are not a compliance conclusion.",
}


def _panel_tip(context: CopilotPageContext) -> str:
    if context.path == "/":
        return "Ask about a page or open it to see its current status. The guide cannot make a change for you."
    return _PANEL_TIPS.get(
        context.path,
        "Check the page's current status and your access before using one of its controls.",
    )


def public_context(
    context: CopilotPageContext,
    permissions: frozenset[str] | None = None,
) -> dict[str, object]:
    """Return the bounded fields the browser can use for tips and quick prompts."""

    result: dict[str, object] = {
        "path": context.path,
        "title": context.title,
        "summary": context.summary,
        "capabilities": list(context.capabilities),
        "boundaries": [_panel_tip(context)],
        "next_steps": list(context.next_steps),
        "suggested_questions": list(context.suggested_questions),
    }
    if permissions is not None:
        order = ("view", "operate", "audit", "admin")
        result["caller_permissions"] = [item for item in order if item in permissions]
        result["authority_notice"] = _authority_notice(permissions)
        result["intro"] = intro_for(context)
        result["suggestions"] = suggestions_for(context, permissions)
    return result


_INTERNAL_COPY = compile_regex(
    r"\b(?:tenant|principal|actor|digest|cas|csp|hmac|nonce|callback|"
    r"server|composition|endpoint|schema|manifest|signer|sdk|idempotent|"
    r"attestation|revision|revisions|runtime|adapter|preflight|"
    r"authority|credential reference|key custody)\b",
    IGNORECASE,
)


def _plain_lines(lines: tuple[str, ...], fallback: str) -> str:
    """Keep useful page copy while avoiding implementation terms in replies."""
    selected = [line for line in lines if not _INTERNAL_COPY.search(line)]
    return " ".join(selected[:2]) if selected else fallback
def intro_for(context: CopilotPageContext, *, changes_enabled: bool = False) -> str:
    """One short line on what Copilot can do here, instead of a list of boundaries."""
    lead = (f"I can explain {context.title}, answer questions about it and take you to the right control."
            if context.path != "/" else
            "I can explain this page, answer questions about it and take you to the right control.")
    return lead + (" Changes always need your confirmation." if changes_enabled
                   else " I don't change anything for you.")


def suggestions_for(context: CopilotPageContext, permissions: frozenset[str]) -> list[str]:
    """Three things people come to this page to do, phrased as tasks."""
    from .copilot_tasks import tasks_for

    tasks = [task.label for task in tasks_for(context.path, permissions)]
    for question in context.suggested_questions:
        if len(tasks) >= 3:
            break
        if question not in tasks:
            tasks.append(question)
    return tasks[:3]


def built_in_reply(
    context: CopilotPageContext,
    message: str,
    permissions: frozenset[str] | None = None,
) -> str:
    """Answer common page-help questions without an external model call."""

    words = tuple(_WORDS.findall(message.casefold()))
    terms = frozenset(words)
    if _is_action_request(words):
        lead = "I can explain the steps, but I haven't changed anything. "
        body = (
            f"Open {context.title} and use its controls if the action is available. "
            "If you don't see the control, check the item's status and your access."
        )
    elif terms & {"limit", "limits", "boundary", "boundaries", "prove", "proof", "safe", "safety", "authority"}:
        lead = "Keep in mind: "
        tip = _panel_tip(context)
        body = tip if "guide" in tip.casefold() else f"{tip} {_READ_ONLY_BOUNDARY}"
    elif terms & {"start", "started", "next", "how", "ready", "readiness", "status"}:
        lead = "Start here: "
        body = _plain_lines(
            context.next_steps,
            f"Open {context.title}, check its current status and follow any setup message before using a control.",
        )
    elif terms & {"can", "could", "capability", "capabilities", "do", "feature", "features"}:
        lead = f"{context.title} can help you: "
        body = _plain_lines(
            context.capabilities,
            f"Review what is available on this page. {_panel_tip(context)}",
        )
        if "access" not in body.casefold() and "permission" not in body.casefold():
            body += f" {_authority_notice(permissions)}" if permissions is not None else (
                " Available controls depend on your access and current setup."
            )
    else:
        lead = f"{context.title}: "
        questions = " Or ask: ".join(context.suggested_questions[:2])
        body = f"{context.summary} You can ask: {questions}"
    return _bounded_reply(f"{lead}{body}")


def _is_action_request(words: tuple[str, ...]) -> bool:
    """Distinguish a request to act from a question about what a page can do."""

    if not words:
        return False
    if words[0] == "please":
        words = words[1:]
    if words and words[0] in _ACTION_VERBS:
        return True
    for lead in _ACTION_LEADS:
        if words[:len(lead)] == lead:
            return bool(_ACTION_VERBS.intersection(words[len(lead):len(lead) + 5]))
    return False


def is_action_request(message: str) -> bool:
    """Classify direct requests before untrusted model text can imply execution."""

    return _is_action_request(tuple(_WORDS.findall(message.casefold())))


def model_claims_completed_action(reply: str) -> bool:
    """Fail closed on common claims of completed work in read-only model text.

    This is a safety net for unsolicited claims and wording the action-request
    classifier misses. Neither a prompt nor a regex is an action receipt.
    """

    for pattern in (
        _FIRST_PERSON_COMPLETION, _PASSIVE_COMPLETION, _CURRENT_STATE_CLAIM,
        _TERSE_COMPLETION, _DONE_LEAD,
    ):
        for match in pattern.finditer(reply):
            # Examples, conditionals, and text composed in this reply are not
            # claims that the guide changed platform state. An isolated quoted
            # claim without an explanatory lead is still rejected.
            clause_start = max((reply.rfind(char, 0, match.start()) for char in ".!?;,"), default=-1) + 1
            clause_lead = reply[clause_start:match.start()].strip().casefold()
            if clause_lead and clause_lead.split()[0] in {"if", "when", "once", "after", "unless"}:
                continue
            if any(
                quoted.start() < match.start() and match.end() < quoted.end()
                and _EXPLANATORY_LEAD.search(reply[max(0, quoted.start() - 80):quoted.start()])
                for quoted in _QUOTED_TEXT.finditer(reply)
            ):
                continue
            if pattern is _FIRST_PERSON_COMPLETION:
                if _RESPONSE_LOCAL_TEXT.match(reply[match.end():]):
                    continue
            return True
    return False


def _authority_notice(permissions: frozenset[str]) -> str:
    """Describe caller authority without exposing identity or implying readiness."""

    if "admin" in permissions:
        access = "You can manage installation settings"
    elif "operate" in permissions:
        access = "You can start or change work in this workspace; installation settings need an administrator"
    elif "audit" in permissions:
        access = "You can review activity records but cannot change work"
    else:
        access = "You can view available records but cannot change them"
    return f"{access}. Each control checks your current access and setup when you use it."


def sanitize_model_reply(reply: object) -> str:
    """Return display-safe, contract-bounded model guidance.

    Model text remains advisory rather than authoritative.  Strip control and
    bidi-formatting characters, collapse whitespace, and enforce the same
    response budget as the deterministic guide before the browser sees it.
    """

    if not isinstance(reply, str):
        return ""
    without_controls = "".join(
        " " if unicodedata.category(character).startswith("C") else character for character in reply
    )
    normalized = " ".join(without_controls.split())
    return _bounded_reply(normalized) if normalized else ""


def _bounded_reply(reply: str) -> str:
    """Keep deterministic no-provider guidance within the model reply budget."""

    words = reply.split()
    if len(words) > _MAX_BUILT_IN_REPLY_WORDS:
        reply = " ".join(words[:_MAX_BUILT_IN_REPLY_WORDS])
    if len(reply) > _MAX_BUILT_IN_REPLY_CHARS:
        reply = reply[: _MAX_BUILT_IN_REPLY_CHARS - 1].rsplit(" ", 1)[0]
    if not reply.endswith((".", "?", "!")):
        reply = f"{reply.rstrip(' ,;:')}."
    return reply


__all__ = [
    "CopilotPageContext",
    "built_in_reply",
    "context_for_page",
    "intro_for",
    "is_action_request",
    "model_claims_completed_action",
    "public_context",
    "sanitize_model_reply",
    "suggestions_for",
]
