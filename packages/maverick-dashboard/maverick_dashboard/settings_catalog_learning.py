"""All-settings catalog rows for the learning group.

Kept apart from settings_catalog.py so each group can be extended without
editing the shared catalog. entries receives the catalog's own row and
column types (a plain import would be circular).

Learning, research and self-improvement: each learning system's own on/off
switch (the Learning page's "Turn core learning on/off" still switches them
all together), overnight learning, self-improving instructions, adopting
learned changes, workflow learning, research experiments, scoring and
sharing. Anything that lets Lightwork change its own code, instructions,
model weights or workflows stays off by default and asks for confirmation,
with a plain sentence about what it allows, before it can be turned on.
"""
from __future__ import annotations

# A server file or folder: an absolute path (or one in the service's home
# folder), with no ``..`` step out of it and no characters a path cannot hold.
_PATH = (r"(?:~|/|[A-Za-z]:[\\/])(?!.*(?:^|[\\/])\.\.(?:[\\/]|$))"
         r"[^\x00-\x1f\x7f<>\"|?*]{0,400}")
_LABEL = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
_DNS = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
# A public secure web address with nothing after the host (the benchmark
# service accepts only its bare address).
_ORIGIN = rf"https://{_DNS}(?:\.{_DNS})+(?::443)?/?"
# A secure web address, or a plain one on this computer only.
_SERVICE = (r"(?:https://[^\s\"'<>]{1,300}|http://(?:localhost|127\.0\.0\.1|\[::1\])"
            r"(?::\d{1,5})?(?:/[^\s\"'<>]{0,300})?)")

_LEARN = "Learning systems"
_NIGHT = "Learning overnight"
_HARNESS = "Self-improving instructions"
_ADOPT = "Adopting learned changes"
_FLOWS = "Learning from workflows"
_RESEARCH = "Research experiments"
_PROMOTE = "Moving research results into use"
_BENCH = "Benchmark sharing"

_EVERY = (("0 * * * *", "Every hour"), ("0 */3 * * *", "Every 3 hours"),
          ("0 */6 * * *", "Every 6 hours (default)"), ("0 */12 * * *", "Every 12 hours"),
          ("0 2 * * *", "Once a day, at 2 in the morning server time"),
          ("0 2 * * 0", "Once a week, early on Sunday server time"))
_EVERY_HALF = (("30 * * * *", "Every hour"), ("30 */3 * * *", "Every 3 hours"),
               ("30 */6 * * *", "Every 6 hours (default)"), ("30 */12 * * *", "Every 12 hours"),
               ("30 2 * * *", "Once a day, at half past 2 in the morning server time"),
               ("30 2 * * 0", "Once a week, early on Sunday server time"))


def entries(S, C, Column) -> tuple:  # noqa: ARG001 -- rows only
    return (_systems(S) + _overnight(S) + _harness(S) + _adopting(S) + _flows(S)
            + _research(S) + _promotion(S) + _benchmarks(S) + _elsewhere(S) + _intent_value(S))


def _intent_value(S) -> tuple:
    return (
        S("intent_value", "enabled", "Intent-based work value",
          "Analyze permitted work metadata and requests, group related tasks, and show audit-backed work with editable estimated labor value. Does not activate automation.",
          "toggle", "Memory & learning", True, "maverick.intent_value.settings", subgroup="Work value and opportunities"),
        S("intent_value", "recommendations", "Suggest reusable work",
          "Use repeated intent and audited actions to suggest existing capabilities or reviewable drafts. Customers choose whether to adopt them.",
          "toggle", "Memory & learning", True, "maverick.intent_value.settings", subgroup="Work value and opportunities"),
    )


def _systems(S) -> tuple:
    """Each learning system's own switch, and how the always-on ones are tuned."""
    group = "Memory & learning"
    return (
        S("self_learning", "enable", "Learn new skills from work",
          "Agents notice a skill a task needs and pick up an approved one from the catalog. "
          "Building new tools and adding outside tool servers stay separate choices.",
          "toggle", group, True, "maverick.self_learning", subgroup=_LEARN,
          env=("MAVERICK_SELF_LEARNING",)),
        S("self_learning", "preflight", "Get skills ready before a task starts",
          "Check each new task for skills it will need and add approved ones before the "
          "agents begin.", "toggle", group, True, "maverick.config", subgroup=_LEARN),
        S("self_learning", "provision_packs", "Equip newly approved agents",
          "Give a newly approved agent the catalog skills and tools its work needs. Each new "
          "tool still needs approval.", "toggle", group, True, "maverick.provision",
          subgroup=_LEARN),
        S("self_learning", "distill_local", "Suggest skills from repeated successes",
          "Prepare a reusable skill suggestion from completed work on this server, without "
          "asking an AI model. Review and add it from Skills before future tasks use it.", "toggle", group, True, "maverick.skill.distillation_local",
          subgroup=_LEARN, env=("MAVERICK_DISTILL_LOCAL",)),
        S("self_learning", "auto_distill", "Let an AI model write skills from finished tasks",
          "After each finished task, an AI model writes a new saved skill from it straight "
          "away, without the overnight checks. It cannot replace a saved or built-in skill.", "toggle", group, False,
          "maverick.orchestrator", subgroup=_LEARN, env=("MAVERICK_AUTO_DISTILL",),
          weaker=True,
          warning="An AI model will write new saved skills straight from finished tasks, and "
                  "text inside a task could plant instructions in them."),
        S("telemetry", "failure_modes", "Count the kinds of failures",
          "Keep a count of how tasks fail, such as running out of time or money, so learning "
          "can focus on the common problems. Nothing leaves this server.",
          "toggle", group, True, "maverick.failure_telemetry", subgroup=_LEARN,
          env=("MAVERICK_FAILURE_TELEMETRY",)),
        S("consequence", "enable", "Learn from real results",
          "When a connected system reports what really happened, such as an invoice paid or "
          "a ticket reopened, learn from that instead of the answer checker's guess.",
          "toggle", group, True, "maverick.consequence", subgroup=_LEARN,
          env=("MAVERICK_CONSEQUENCE",)),
        S("reflexion", "enable", "Remember lessons from mistakes",
          "After a task goes wrong, write down what happened so later tasks avoid it.",
          "toggle", group, True, "maverick.reflexion", subgroup=_LEARN,
          env=("MAVERICK_REFLEXION",)),
        S("experience", "enable", "Plan from past experience",
          "Use how similar past tasks went to decide how to plan and staff a new one.",
          "toggle", group, True, "maverick.experience", subgroup=_LEARN,
          env=("MAVERICK_EXPERIENCE_GUIDANCE",)),
        S("skill_synthesis", "enable", "Prepare guidance for each task",
          "Before a task starts, write short guidance for that task. It is paid from the "
          "task's own spending limit.", "toggle", group, True, "maverick.skill.synthesis",
          subgroup=_LEARN, env=("MAVERICK_SKILL_SYNTHESIS",)),
        S("self_improvement", "prm_guidance", "Nudge agents that stall",
          "Score each step of a task and prompt the agent to change approach when several "
          "steps in a row make no progress.", "toggle", group, True, "maverick.prm_guidance",
          subgroup=_LEARN, env=("MAVERICK_PRM_GUIDANCE",)),
        S("self_improvement", "capture", "Keep an outline of how tasks ran",
          "Save an outline of each task's steps, with secrets removed, as the material "
          "learning works from.", "toggle", group, True, "maverick.trajectory_store",
          subgroup=_LEARN, env=("MAVERICK_TRAJECTORY_CAPTURE",)),
        S("self_improvement", "causal_promotion", "Require a controlled comparison before adopting changes",
          "Only adopt a learned change automatically when a prospectively controlled "
          "comparison has enough evidence. Ordinary task history can suggest what to try, "
          "but cannot prove what caused the result.", "toggle", group, True,
          "maverick.promotion_effect", subgroup=_LEARN, env=("MAVERICK_CAUSAL_PROMOTION",),
          weaker=False,
          warning="Automatic adoption can mistake a coincidental improvement for one "
                  "caused by the change."),
        S("self_improvement", "factory_learning", "Improve how new agents are built",
          "Learn from the gaps found when new agents are set up, so the next ones start "
          "better. Needs governed improvement on.", "toggle", group, True,
          "maverick.factory_learning", subgroup=_LEARN, env=("MAVERICK_FACTORY_LEARNING",)),
        S("self_improvement", "evaluator_evolution", "Replace a drifting answer checker",
          "When the answer checker drifts, try a better one against fixed, locked examples. "
          "A swap still needs a person unless you allow it under Adopting learned changes.",
          "toggle", group, True, "maverick.evaluator_evolution", subgroup=_LEARN,
          env=("MAVERICK_EVALUATOR_EVOLUTION",)),
        S("data_engine", "enable", "Improvement flywheel",
          "Find the failures that cost the most, test a fix in a simulation first and track "
          "whether it helps in real work.", "toggle", group, True, "maverick.data_engine",
          subgroup=_LEARN, env=("MAVERICK_DATA_ENGINE",)),
        S("operations_scientist", "enable", "Look for better ways of working",
          "Suggest a better step to replace one that keeps causing harm, and test it in a "
          "simulation before any real trial.", "toggle", group, True,
          "maverick.operations_scientist", subgroup=_LEARN,
          env=("MAVERICK_OPERATIONS_SCIENTIST",)),
        S("credit", "enable", "Score each agent's part in team work",
          "In a team of agents, work out how much each one helped, to learn which agents to "
          "use. It costs extra answer checks.", "toggle", group, True, "maverick.credit",
          subgroup=_LEARN, env=("MAVERICK_CREDIT",)),
        S("credit", "min_budget_headroom", "Budget left before scoring team work",
          "Team scoring runs only while at least this share of the task's budget is left.",
          "number", group, 0.4, "maverick.config", subgroup=_LEARN, minimum=0, maximum=100,
          unit="percent", scale=0.01, weaker="lower",
          warning="Scoring team work may use more of a task's remaining budget."),
        S("reasoning_reward", "enable", "Detailed answer scoring",
          "Score final answers on several points, with a safety veto, instead of a single "
          "pass or fail.", "toggle", group, True, "maverick.reasoning_reward",
          subgroup=_LEARN, env=("MAVERICK_REASONING_REWARD",)),
        S("reasoning_reward", "audit_rewards", "Record answer scores in the activity log",
          "Sign each detailed score into the tamper-evident activity log, as proof of what "
          "learning was based on.", "toggle", group, True, "maverick.reasoning_reward",
          subgroup=_LEARN, env=("MAVERICK_REASONING_REWARD_AUDIT",), weaker=False,
          warning="Answer scores will no longer be recorded in the tamper-evident activity "
                  "log."),
        S("jit_rl", "enable", "Favour answers that worked before",
          "When agents write several candidate answers, lean toward the kind that checked out "
          "well before. Nothing changes until there is experience to use.", "toggle", group,
          True, "maverick.jit_rl", subgroup=_LEARN, env=("MAVERICK_JIT_RL",)),
        S("jit_rl", "beta", "How strongly past results steer the choice",
          "Higher values lean harder toward the kind of answer that worked before; 0 ignores "
          "past results.", "number", group, 1.0, "maverick.config", subgroup=_LEARN,
          minimum=0, maximum=10, step=0.1),
        S("self_improvement", "prm_backend", "How each step is scored",
          "What scores each step of a task for the stall nudge above.", "select", group,
          "null", "maverick.prm", subgroup=_LEARN, env=("MAVERICK_PRM",),
          choices=(("null", "Not scored (default)"), ("heuristic", "Built-in rules"),
                   ("remote", "An outside scoring service"),
                   ("learned", "A scoring model trained on this server"),
                   ("linear", "A small scoring file adopted through the approval steps")),
          weaker="change",
          warning="Each step of agents' work will be scored differently. An outside scoring "
                  "service receives the details of each step."),
        S("self_improvement", "prm_endpoint", "Outside scoring service address",
          "Used when steps are scored by an outside service. It must be a secure address, or "
          "an address on this computer.", "text", group, "", "maverick.prm",
          subgroup=_LEARN, env=("MAVERICK_PRM_ENDPOINT",), max_length=320, pattern=_SERVICE,
          weaker="change",
          warning="The details of each step will be sent to a different scoring service."),
        S("self_improvement", "prm_api_key", "Outside scoring service key",
          "The key for the outside scoring service. It is stored sealed and never shown "
          "again.", "secret", group, "", "maverick.prm", subgroup=_LEARN,
          env=("MAVERICK_PRM_API_KEY",), max_length=500),
        S("self_improvement", "prm_path", "Where the trained scoring model is kept",
          "The folder or file on the server that holds the trained scoring model.", "text",
          group, "", "maverick.prm", subgroup=_LEARN, env=("MAVERICK_PRM_PATH",),
          max_length=400, pattern=_PATH, weaker="change",
          warning="Steps will be scored by whatever model is kept in the new place."),
        S("calibration", "collect_from_coding", "Check the answer checker on coding tasks",
          "On coding tasks with tests, also ask the answer checker, so its reliability is "
          "measured against the test results. It costs one extra check per coding task.",
          "toggle", group, False, "maverick.calibration",
          env=("MAVERICK_CALIBRATION_COLLECT_CODING",)),
        S("calibration", "min_resistance", "Pause learning when the checker is easy to fool",
          "Pause learning when the answer checker catches this share fewer tricked answers "
          "than normal ones. At 0 it is only measured.", "number", group, 0.0,
          "maverick.config", minimum=0, maximum=100, unit="percent", scale=0.01,
          weaker="lower",
          warning="Learning will carry on even when the answer checker is easier to fool."),
        S("fairness_monitor", "window", "Recent decisions compared for fairness",
          "How many of the most recent decisions are compared between groups.", "number",
          group, 1000, "maverick.config", minimum=10, maximum=1000000, integer=True,
          unit="decisions"),
        S("fairness_monitor", "min_samples", "Decisions needed before comparing",
          "Groups are compared only once at least this many decisions have been made.",
          "number", group, 30, "maverick.config", minimum=1, maximum=100000, integer=True,
          unit="decisions", weaker="higher",
          warning="Unfair outcomes will be flagged later, after more decisions."),
        S("fairness_monitor", "drift_tolerance", "How far fairness may slip before a warning",
          "Warn when the fairness level falls this far below where it started.", "number",
          group, 0.1, "maverick.config", minimum=0, maximum=100, unit="percent",
          scale=0.01, weaker="higher",
          warning="Fairness can slip further before you are warned."),
    )


def _overnight(S) -> tuple:
    group = "Memory & learning"
    return (
        S("dreaming", "cron", "When overnight learning runs",
          "How often Lightwork reviews recent work to write lessons and skills.", "select",
          group, "0 */6 * * *", "maverick_dashboard.automation_queue", subgroup=_NIGHT,
          choices=_EVERY),
        S("data_engine", "cron", "When the improvement flywheel runs",
          "How often the flywheel looks for costly failures and tests fixes.", "select",
          group, "30 */6 * * *", "maverick_dashboard.automation_queue", subgroup=_NIGHT,
          choices=_EVERY_HALF),
        S("dreaming", "snapshots", "Save a restore point before learning",
          "Keep a checked copy of the covered learned information before each improvement cycle. Customer work and activity stay current.",
          "toggle", group, True, "maverick.config", subgroup=_NIGHT, weaker=False,
          warning="Scheduled and manual learning cycles will stop until restore points are turned on again."),
        S("dreaming", "benchmark_gate", "Hold back new skills while test results slip",
          "Keep newly learned skills on hold while the tracked test results are getting "
          "worse.", "toggle", group, True, "maverick.config", subgroup=_NIGHT, weaker=False,
          warning="New skills will be used even while the tracked test results are getting "
                  "worse."),
        S("dreaming", "mine_critiques", "Learn from the answer checker's comments",
          "Turn the answer checker's comments on shared work outlines into lessons.",
          "toggle", group, True, "maverick.config", subgroup=_NIGHT),
        S("dreaming", "prune", "Tidy the list of lessons",
          "Remove repeated lessons from mistakes so the list stays short and useful.",
          "toggle", group, True, "maverick.config", subgroup=_NIGHT),
        S("dreaming", "retire_skills", "Retire skills that stopped working",
          "Stop using a learned skill once it keeps failing.", "toggle", group, True,
          "maverick.config", subgroup=_NIGHT),
        S("dreaming", "promote_shared", "Share department lessons with every department",
          "Offer lessons learned in one department to agents in all departments.",
          "toggle", group, False, "maverick.config", subgroup=_NIGHT, weaker=True,
          warning="Lessons learned in one department, including its problems, will be "
                  "offered to every department."),
        S("dreaming", "prune_facts", "Remove old remembered facts",
          "During learning, delete stored facts that are old or over the limit.",
          "toggle", group, False, "maverick.config", subgroup=_NIGHT, weaker=True,
          warning="Old stored facts will be deleted during learning."),
        S("dreaming", "user_notes", "Remember people's stated preferences",
          "Keep preferences people state in a conversation, word for word, and use them in "
          "later conversations.", "toggle", group, False, "maverick.config",
          subgroup=_NIGHT, weaker=True,
          warning="Preferences people state in one conversation will be kept and used in "
                  "later ones."),
        S("dreaming", "rehearse", "Practise before keeping a lesson",
          "Run a few real practice tasks during learning to test new lessons before they "
          "are kept.", "toggle", group, False, "maverick.config", subgroup=_NIGHT,
          weaker=True, warning="Learning will run real practice tasks, which cost money."),
        S("dreaming", "trusted_insight_pubkeys", "Installations you accept lessons from",
          "Lessons from another Lightwork installation are accepted only when signed with "
          "one of these keys. Add the key file that installation gives you.", "keys", group,
          [], "maverick.insight_exchange", subgroup=_NIGHT, weaker="add",
          warning="Lessons signed with the new key will be accepted from that installation."),
    )


def _harness(S) -> tuple:
    group = "Memory & learning"
    careful = "The careful improvement profile always keeps this on."
    return (
        S("self_harness", "require_held_out", "Test improvements on unseen cases",
          "Never adopt an improvement that was only tested on the mistakes it was made "
          "from. " + careful, "toggle", group, True, "maverick.config",
          subgroup=_HARNESS, partial_default=False, weaker=False,
          warning="Improvements could be adopted after testing only on the cases they were "
                  "made from."),
        S("self_harness", "min_held_out", "Unseen cases each improvement is tested on",
          "The careful improvement profile uses at least 8.", "number", group, 8,
          "maverick.config", subgroup=_HARNESS, partial_default=0, minimum=0, maximum=10000, integer=True,
          unit="cases", weaker="lower",
          warning="Improvements will be tested on fewer unseen cases."),
        S("self_harness", "min_delta", "Smallest gain worth adopting",
          "An improvement must do at least this much better. The careful improvement "
          "profile uses at least 2 percent.", "number", group, 0.02, "maverick.config",
          subgroup=_HARNESS, partial_default=0.0, minimum=0, maximum=100, unit="percent", scale=0.01,
          weaker="lower", warning="Smaller, less certain gains will be adopted."),
        S("self_harness", "judge_samples", "Times each result is judged",
          "Ask the judge this many times and go with the majority. The careful improvement "
          "profile uses at least 3.", "number", group, 3, "maverick.config",
          subgroup=_HARNESS, partial_default=1, minimum=1, maximum=9, integer=True, unit="times",
          weaker="lower",
          warning="Each result will be judged fewer times, so one lucky verdict counts "
                  "more."),
        S("self_harness", "candidates_per_signature", "Fixes tried for each recurring mistake",
          "How many different fixes are written and tested for one recurring mistake. The "
          "careful improvement profile always tries 3.", "number", group, 3,
          "maverick.config", subgroup=_HARNESS, partial_default=1, minimum=1, maximum=10, integer=True,
          unit="fixes", weaker="higher",
          warning="More fixes will be tried, which costs more and makes a lucky result more "
                  "likely to be adopted."),
        S("self_harness", "metamorphic", "Test improvements on reworded cases",
          "Reword the test cases and require the improvement to still help. " + careful,
          "toggle", group, True, "maverick.config", subgroup=_HARNESS,
          partial_default=False, weaker=False,
          warning="Improvements that only help with the exact wording of the tests could be "
                  "adopted."),
        S("self_harness", "promote_as_canary", "Try each improvement on a small share first",
          "Put each adopted improvement on probation and keep it only if real work goes "
          "well. " + careful, "toggle", group, True, "maverick.config", subgroup=_HARNESS,
          partial_default=False, weaker=False, warning="Adopted improvements will apply fully straight away."),
        S("self_harness", "calibrate_judge", "Watch the judge for drift",
          "Feed the judge's verdicts into the check that pauses learning when the answer "
          "checker drifts. " + careful, "toggle", group, True, "maverick.config",
          subgroup=_HARNESS, partial_default=False, weaker=False,
          warning="A drifting judge will no longer pause learning."),
        S("self_harness", "efficacy_review", "Re-check adopted improvements",
          "Each night, measure whether each adopted improvement still helps and drop the "
          "ones that no longer do.", "toggle", group, False, "maverick.config",
          subgroup=_HARNESS),
        S("self_harness", "semantic_mining", "Group mistakes by meaning",
          "Group similar mistakes by what they mean rather than by matching words, when "
          "that is available.", "toggle", group, False, "maverick.config",
          subgroup=_HARNESS),
        S("self_harness", "mine_bucket_by", "Look for mistakes separately by",
          "Find recurring mistakes, and scope their fixes, separately for each choice ticked "
          "here. With none ticked, they are found across all work.", "multiselect", group,
          [], "maverick.config", subgroup=_HARNESS,
          choices=(("domain", "Department"), ("tool", "Tool used"), ("role", "Agent role"))),
        S("self_harness", "relapse_failure_share", "Put an improvement back on probation at",
          "Put an adopted improvement back on probation when this share of its recent tasks "
          "fail. 0 turns this off.", "number", group, 0.0, "maverick.config",
          subgroup=_HARNESS, minimum=0, maximum=100, unit="percent", scale=0.01),
        S("self_harness", "retire_after_days", "Retire unused improvements after",
          "Stop using an improvement that has not been used for this many days. 0 keeps "
          "them.", "number", group, 0, "maverick.config", subgroup=_HARNESS, minimum=0,
          maximum=3650, integer=True, unit="days"),
        S("self_harness", "store", "Where improvements are kept",
          "Keep what is learned on this server, or in the shared database so every server "
          "learns together.", "select", group, "files", "maverick.config",
          subgroup=_HARNESS,
          choices=(("files", "On this server (default)"),
                   ("world", "In the shared database, for every server")),
          weaker="change",
          warning="Improvements will be read from and saved to a different place. What was "
                  "learned in the old place is not moved."),
        S("self_harness", "eval_corpus", "Test cases for improvements",
          "The file, inside Lightwork's data folder, with the test cases improvements are "
          "measured against. Lightwork creates it when it first saves test cases. Without "
          "it, nightly runs only report what they would change.", "path", group, "",
          "maverick.config", subgroup=_HARNESS, max_length=400, path_kind="file",
          path_writable=True, path_new=True, path_scope="data", weaker="change",
          warning="Improvements will be judged against a different set of test cases."),
        S("self_harness", "holdout_ledger", "Record of unseen-case checks",
          "The file, inside Lightwork's data folder, that counts how often the unseen test "
          "cases have been used. Set it up once from the Learned page. The careful "
          "improvement profile needs it before it adopts anything.", "path",
          group, "", "maverick.config", subgroup=_HARNESS, max_length=400, path_kind="file",
          path_writable=True, path_new=True, path_scope="data", weaker="change",
          warning="Checks will be counted in a different record, which could let the unseen "
                  "cases be used more often than allowed."),
        S("self_harness", "holdout_container_image", "Approved checking environment",
          "The ID of the approved local environment improvements are checked in. Leave "
          "empty to use the standard one.", "text", group,
          "", "maverick.config", subgroup=_HARNESS, max_length=71,
          pattern=r"sha256:[0-9a-f]{64}", weaker="change",
          warning="Improvements will be checked in a different environment."),
        S("self_harness", "holdout_require_independent_custody",
          "Require a separate keeper for confirming results",
          "Only confirm results when the record of unseen-case checks is kept by a separate "
          "keeper, not this server.", "toggle", group, False,
          "maverick.self_improvement_runner", subgroup=_HARNESS,
          env=("MAVERICK_SELF_HARNESS_REQUIRE_INDEPENDENT_CUSTODY",), weaker=False,
          warning="Results will be confirmed with a record this server keeps itself."),
    )


def _adopting(S) -> tuple:
    group = "Memory & learning"
    return (
        S("self_improvement", "min_improvement", "Smallest gain before a change is adopted",
          "A learned change must beat how things work now by at least this much.", "number",
          group, 0.0, "maverick.config", subgroup=_ADOPT, minimum=0, maximum=100,
          unit="percent", scale=0.01, weaker="lower",
          warning="Learned changes with smaller gains will be adopted."),
        S("self_improvement", "max_auto_rung", "Changes adopted without a person",
          "Learned changes up to this kind are adopted once they pass their checks. Changes "
          "to Lightwork's own code or model weights always need a person.", "select", group,
          "policy", "maverick.config", subgroup=_ADOPT,
          choices=(("config", "Only small setting adjustments"),
                   ("prompt", "Also changes to agent instructions"),
                   ("tool", "Also changes to how tools are used"),
                   ("policy", "Also changes to working rules (default)"),
                   ("evaluator", "Also replacing the answer checker")),
          weaker=True, order=("config", "prompt", "tool", "policy", "evaluator"),
          warning="More kinds of learned changes will be adopted without a person."),
        S("self_improvement", "evaluator_eps", "How sure a new answer checker must be",
          "A new answer checker replaces the current one only with this much doubt or less. "
          "Lower is more careful.", "number", group, 0.05, "maverick.config",
          subgroup=_ADOPT, minimum=0.1, maximum=50, unit="percent", scale=0.01,
          weaker="higher",
          warning="A new answer checker could replace the current one on weaker evidence."),
    )


def _flows(S) -> tuple:
    """Learned workflow steps: every one is off by default, confirmed to turn on,
    and only matters while workflows are turned on."""
    group = "Memory & learning"

    def learn(key, label, help_text, warning):
        return S("flows", key, label, help_text, "toggle", group, False, "maverick.config",
                 subgroup=_FLOWS, weaker=True, warning=warning)

    return (
        learn("learned_operators", "Learn simple calculations from reviewed examples",
              "A reviewed calculation may stand in for an agent's answer when every "
              "calculation it learned agrees. Other cases still go to the agent.",
              "Learned calculations will replace some agent answers in workflows."),
        learn("learned_operator_questions", "Ask review questions about learned calculations",
              "Keep questions that tell learned calculations apart, and the reviewed answers. "
              "Answers only create drafts; nothing is published on its own.",
              "Review questions and their answers will be kept."),
        learn("composed_operators", "Combine learned calculations",
              "Let learned calculations be combined into bigger ones. Also needs learned "
              "calculations on.",
              "Combined learned calculations will replace some agent answers in workflows."),
        learn("action_recipes", "Learn action steps from reviewed examples",
              "Build workflow steps from reviewed examples of actions. Approvals stay in place "
              "and the workflow stops when data is unclear.",
              "Workflows will be able to run action steps learned from examples."),
        learn("action_recipe_transforms", "Learn how action details are filled in",
              "Learn how one action's details are worked out from earlier results. Also needs "
              "learned action steps on.",
              "Learned workflows will fill in action details on their own."),
        learn("action_recipe_choices", "Learn which action to take next",
              "Learn a choice between two actions after a shared step. The chosen action "
              "still needs approval. Also needs learned action details on.",
              "Learned workflows will choose between actions on their own."),
        learn("action_recipe_teaching", "Let people teach the next step",
              "At a real finished step, a person can show what should happen next. The "
              "person's choice and a separate approval are still needed.",
              "People will be able to teach workflows new next steps."),
        learn("action_workflow_learning", "Learn whole workflows from signed runs",
              "Learn the next actions, up to eight, and when a workflow is finished, from "
              "reviewed runs with signed records. Approvals stay in place.",
              "Workflows learned from past runs will be able to run."),
        learn("action_workflow_memory_learning", "Learn running totals in workflows",
              "Learn simple whole-number totals kept across a workflow's history. Also needs "
              "whole-workflow learning on.",
              "Learned workflows will keep and use running totals on their own."),
        learn("action_episode_capture", "Keep workflow examples for learning",
              "Keep copies of real workflow runs, including business data, to learn from. "
              "Each run needs enrolment, encrypted storage, an expiry and a person's review. "
              "Turning this on also requires signed evidence for learned action flows.",
              "Copies of real workflow runs will be kept. Older learned flows without signed "
              "examples may stop until rebuilt from reviewed runs allowed for learning."),
        S("flows", "action_recipe_lineage", "Sign reviewed examples",
          "Sign each reviewed example so learned steps can show where they came from. The "
          "signature confirms the review was recorded, not who reviewed it. "
          "Turning this on requires signed evidence for learned action flows.", "toggle",
          group, False, "maverick.config", subgroup=_FLOWS, weaker=True,
          warning="Older learned flows without signed examples may stop until rebuilt "
                  "from reviewed runs allowed for learning."),
        S("flows", "require_action_recipe_lineage", "Always require signed history for learned steps",
          "Refuse to save, publish or run a learned step without a signed record of its "
          "reviewed examples, even when example collection and signing are off. This is "
          "already required while either of those features is on.", "toggle", group, False,
          "maverick.config", subgroup=_FLOWS,
          weaker=False,
          warning="Unsigned learned steps remain blocked while workflow example capture or "
                  "signed examples are on. If both are off, older unsigned steps may run again."),
        S("flows", "action_evidence_issuer", "Name that signs reviewed examples",
          "A short, stable name for this installation, used when it signs reviewed examples. "
          "Letters, numbers, dots, dashes, underscores and colons only.", "text", group, "",
          "maverick.config", subgroup=_FLOWS, max_length=128,
          pattern=r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", weaker="change",
          warning="Reviewed examples will be signed under a different name, and older "
                  "signatures may no longer match it."),
        S("flows", "action_evidence_revoked_keys", "Withdrawn signing keys",
          "Signing keys that must no longer be trusted, each as its 16-character key ID.",
          "list", group, [], "maverick.config", subgroup=_FLOWS, max_items=64,
          pattern=r"[0-9a-f]{16}", item_label="Key ID", item_hint="16 characters, 0 to 9 and a to f",
          item_error="a 16-character key ID using 0 to 9 and a to f", weaker="shrink",
          warning="A withdrawn key will be trusted again."),
    )


def _research(S) -> tuple:
    group = "Memory & learning"
    return (
        S("self_modify", "editable_paths", "Files code experiments may change",
          "The only files Lightwork's own-code experiments may propose changes to, as file "
          "patterns inside its source folder. Protected files are always refused and "
          "changes are never installed.", "list", group, [], "maverick.self_modify",
          subgroup=_RESEARCH, max_items=50, max_length=200,
          pattern=r"(?![/\\])(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_./*?\[\]-]{1,200}",
          item_label="File pattern", item_hint="packages/example/*.py",
          item_error="a file pattern inside the source folder", weaker="grow",
          warning="Lightwork's own-code experiments will be allowed to propose changes to "
                  "more files."),
        S("self_modify", "eval_tests", "Tests each code experiment must pass",
          "At least two tests that show whether a proposed code change helps.", "list", group,
          [], "maverick.self_modify", subgroup=_RESEARCH, max_items=50, max_length=300,
          pattern=r"(?!-)[A-Za-z0-9_./-]{1,200}(?:::[A-Za-z0-9_.\[\]-]{1,100}){0,3}",
          item_label="Test", item_hint="tests/test_example.py::test_case",
          item_error="a test name inside the source folder", weaker="change",
          warning="Code experiments will be judged by different tests."),
        S("adapter_rung", "enable", "Train model weights from your own data",
          "Research only: train small add-ons to a local model from your own records and "
          "propose them. Each one needs a signed approval and can be rolled back.", "toggle",
          group, False, "maverick.config", subgroup=_RESEARCH, weaker=True,
          warning="Lightwork will be able to train and propose changes to a model's weights "
                  "from your data. Each change still needs a signed approval."),
        S("adapter_rung", "base_model", "Local model to train",
          "The local model the add-ons are trained for, for example ollama:llama3.", "text",
          group, "", "maverick.config", subgroup=_RESEARCH, max_length=200,
          pattern=r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}"),
        S("adapter_rung", "trainer", "How add-ons are trained",
          "A practice run makes a placeholder to test the steps; real training needs the "
          "training tools on this server.", "select", group, "stub", "maverick.config",
          subgroup=_RESEARCH,
          choices=(("stub", "Practice run, no real training (default)"),
                   ("dpo-lora", "Real training on this server"))),
        S("adapter_rung", "store_dir", "Where trained add-ons are kept",
          "The folder on the server for trained add-ons.", "text", group, "",
          "maverick.config", subgroup=_RESEARCH, max_length=400, pattern=_PATH),
        S("adapter_rung", "allow_synthetic", "Train on generated examples",
          "Allow examples that were generated rather than recorded to be used for training.",
          "toggle", group, False, "maverick.config", subgroup=_RESEARCH, weaker=True,
          warning="Generated examples will be allowed as training data."),
        S("adapter_rung", "allow_model_output", "Train on outside AI models' answers",
          "Allow answers written by outside AI models to be used for training. Their terms "
          "of use may forbid this.", "toggle", group, False, "maverick.config",
          subgroup=_RESEARCH, weaker=True,
          warning="Answers from outside AI models will be used as training data, which their "
                  "terms of use may forbid."),
        S("emergent_protocol", "enable", "Let agents use learned shorthand",
          "Agents learn short codes for text they repeat in messages to each other. Every "
          "code can be translated back exactly and is kept in the record.", "toggle", group,
          False, "maverick.emergent_protocol", subgroup=_RESEARCH,
          env=("MAVERICK_EMERGENT_PROTOCOL",), weaker=True,
          warning="Agents will write to each other in learned short codes."),
        S("emergent_codec", "enable", "Measure savings from shorter agent messages",
          "Measure how much a shorter form of agents' messages would save. It only measures; "
          "what agents see is unchanged.", "toggle", group, False, "maverick.emergent_tokens",
          subgroup=_RESEARCH, env=("MAVERICK_EMERGENT_CODEC",)),
    )


def _promotion(S) -> tuple:
    group = "AI governance"
    reader = "maverick_dashboard.candidate_promotion_composition"
    return (
        S("candidate_promotion", "allowed_targets", "Where research results may be put into use",
          "The names of the installations research results may be moved into. Emptying the "
          "list goes back to this installation only.", "list", group,
          ["installed-lightwork"], reader, subgroup=_PROMOTE, max_items=64, max_length=128,
          pattern=_LABEL, item_label="Installation name", item_hint="installed-lightwork",
          item_error="a name using letters, numbers, dots, dashes and underscores",
          empty_unset=True, weaker="grow",
          warning="Research results will be able to change more installations."),
        S("candidate_promotion", "canary_comparison", "The trial passes when the measure is",
          "Whether the measure a small trial is judged on, the error rate unless your release "
          "setup names another, must stay at or below, or at or above, the level below.",
          "select", group, "at_most", reader, subgroup=_PROMOTE,
          choices=(("at_most", "At or below the level (default)"),
                   ("at_least", "At or above the level")),
          weaker="change", warning="Trials will pass under a different rule."),
        S("candidate_promotion", "canary_threshold", "Level the measure is compared with",
          "The level a trial's measure is checked against.", "number", group, 0.05, reader,
          subgroup=_PROMOTE, minimum=-1000000, maximum=1000000, weaker="change",
          warning="Trials will pass or fail at a different level."),
    )


def _benchmarks(S) -> tuple:
    group = "AI governance"
    reader = "maverick.ai_benchmark_exchange"
    return (
        S("ai_benchmark_exchange", "enable", "Compare results with other organisations",
          "Prepare anonymous benchmark results to compare with other organisations. Each "
          "one needs consent and two people's approval before it is shared.", "toggle",
          group, False, reader, subgroup=_BENCH, weaker=True,
          warning="People will be able to prepare anonymous benchmark results for sharing."),
        S("ai_benchmark_exchange.coordinator", "enable", "Send approved results to the benchmark service",
          "Send approved, anonymous benchmark results to the outside benchmark service below.",
          "toggle", group, False, reader, subgroup=_BENCH, partial_default=False,
          weaker=True,
          warning="Approved benchmark results will be sent to the outside benchmark service."),
        S("ai_benchmark_exchange.coordinator", "origin", "Benchmark service address",
          "The secure web address of the benchmark service, with nothing after its name.",
          "text", group, "", reader, subgroup=_BENCH, max_length=260, pattern=_ORIGIN,
          weaker="change",
          warning="Benchmark results will be sent to a different outside service."),
        S("ai_benchmark_exchange.coordinator", "timeout_seconds", "Wait for the benchmark service",
          "How long to wait for the benchmark service before giving up.", "number", group,
          15.0, reader, subgroup=_BENCH, minimum=1, maximum=60, unit="seconds"),
        S("ai_benchmark_exchange.coordinator", "max_request_bytes", "Largest result sent",
          "The largest benchmark result that may be sent.", "number", group, 131072, reader,
          subgroup=_BENCH, minimum=1, maximum=256, integer=True, unit="KB", scale=1024,
          weaker="higher", warning="Larger results may be sent to the outside service."),
        S("ai_benchmark_exchange.coordinator", "max_response_bytes", "Largest reply accepted",
          "The largest reply accepted from the benchmark service.", "number", group, 131072,
          reader, subgroup=_BENCH, minimum=1, maximum=1024, integer=True, unit="KB",
          scale=1024),
    )


def _elsewhere(S) -> tuple:
    """Learning-related settings that sit with their neighbours in other groups."""
    return (
        S("rehearsal", "enable", "Observe high-impact action predictions",
          "Compare high-impact actions with past work. The mode below controls "
          "whether predictions can stop an action. Shield, permissions, and "
          "required approvals still apply.",
          "toggle", "Safety", True, "maverick.rehearsal",
          env=("MAVERICK_REHEARSAL",), weaker=False,
          warning="Lightwork will stop recording practice predictions for high-impact actions."),
        S("rehearsal", "mode", "What practice predictions do",
          "Watch only lets normal tool checks decide. Hold can stop unfamiliar or "
          "poorly predicted actions until a person reviews the exact step in Approvals. "
          "An unanswered or rejected request does not run. Other safety checks still apply.",
          "select", "Safety", "observe", "maverick.config",
          choices=(("observe", "Watch only (default)"),
                   ("hold", "Hold high-impact actions for review"))),
        S("autonomy", "escalate_verification", "Second check on uncertain answers",
          "When agents disagree about a final answer, have other AI models check it too. "
          "Needs extra checks on uncertain work on.", "toggle", "Safety", True,
          "maverick.config", weaker=False,
          warning="Final answers agents disagree about will no longer get a second check."),
        S("autonomy", "tighten_on_low_trust", "Limit risky tools when a task looks unreliable",
          "When a task looks unreliable, lower the risk level its tools may reach. Needs "
          "extra checks on uncertain work on.", "toggle", "Safety", True, "maverick.config",
          weaker=False,
          warning="Risky tools will keep their usual limits even when a task looks "
                  "unreliable."),
        S("harness_refine", "max_pending", "Instruction changes waiting at once",
          "The most suggested instruction changes that can wait for a decision at one time.",
          "number", "Safety", 20, "maverick.config", minimum=1, maximum=1000, integer=True,
          unit="changes"),
        S("telemetry", "donate_text", "Include the text when sharing work patterns",
          "Also keep the wording of tasks and drafts with shared work patterns, not only "
          "their outline.", "toggle", "Privacy", False, "maverick.donation", weaker=True,
          warning="The wording of tasks and drafts will be kept with shared work patterns."),
        S("telemetry", "donate_min_confidence", "How sure the checker must be to share a task",
          "Only share work patterns from tasks the answer checker is at least this sure "
          "about.", "number", "Privacy", 0.75, "maverick.donation", minimum=0, maximum=100,
          unit="percent", scale=0.01, weaker="lower",
          warning="Work patterns from less certain tasks will be shared too."),
        S("telemetry", "donate_min_entropy", "How much agents must disagree to share a task",
          "Only share work patterns from tasks where agents disagreed at least this much. At "
          "0, every successful task is shared.", "number", "Privacy", 0.5,
          "maverick.donation", minimum=0, maximum=10, step=0.1, weaker="lower",
          warning="Work patterns from more tasks will be shared."),
        S("paper_review", "draft_budget_dollars", "Most to spend drafting contract wording",
          "The most one contract review may spend on AI-drafted wording.", "number",
          "Privacy", 2.0, "maverick.paper_review", minimum=0.01, maximum=100,
          unit="dollars", weaker="higher",
          warning="Drafting contract wording may cost more."),
        S("paper_review", "playbook_path", "Your standard contract positions file",
          "The file on the server with your standard contract positions. Leave empty to "
          "keep it with Lightwork's other records.", "text", "Privacy", "",
          "maverick.paper_review", max_length=400, pattern=_PATH, weaker="change",
          warning="Contract reviews will use the positions in a different file."),
        S("entity_graph", "staleness_seconds", "Refresh the map of related records after",
          "How old the map of which records relate to each other may get before it is "
          "rebuilt.", "number", "Performance", 60.0, "maverick.entity_graph", minimum=1,
          maximum=86400, unit="seconds"),
    )


# ------------------------------------------------------------ cross checks
def cross_checks(effective: dict, by_id: dict, error: type) -> None:
    """Refuse learning combinations the kernel reports as a broken setup
    (mirrors config_lint's benchmark coordinator rule)."""
    send = "ai_benchmark_exchange.coordinator.enable"
    origin = "ai_benchmark_exchange.coordinator.origin"
    if effective.get(send) is True and not str(effective.get(origin) or "").strip():
        raise error(f"{by_id[send].label}: fill in “{by_id[origin].label}” first.")
