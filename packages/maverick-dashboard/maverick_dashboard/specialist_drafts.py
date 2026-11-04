"""Complete specialist drafts, bounded answer checks, and reviewed publication."""
from __future__ import annotations

import copy
import json
import math
import re
import time
from dataclasses import asdict

from fastapi import HTTPException
from maverick import agent_tests_policy, config, crypto_at_rest, domain, domain_edit
from maverick import specialist_canary as canary
from maverick.authority_effects import authority_effect_fence
from maverick.file_lock import cross_process_lock
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore

from . import agent_changelog, auth, tools_ops_api
from .agent_override_changes import PROFILE_LABELS, _readable
from .draft_api import context_for

API, PAGE = "/api/v1/specialist-drafts", "/agents#specialist-drafts"
STORE = GovernedRecordStore("specialist-drafts", "SPD", "specialist_draft")
TTL, MAX_RECORDS = 600, 10000
NOTICE = ("Saving a draft does not change the specialist people use. Preview checks its entered setup. "
          "Try and saved answer checks use the exact draft with no real tools, files, company knowledge or shared learning. "
          "Checks that test tool use get recording test stubs instead; they answer with fixed results and run nothing real. "
          "Its complete instructions and fictional requests are sent to the configured AI service for those answer checks. "
          "They do not establish that connected actions work or that an answer is correct. Publishing or restoring changes new work; work already running can retain earlier instructions.")
ACTIONS = {"save": "Saved a draft", "try": "Tried a draft answer", "check": "Checked the draft's saved questions",
           "publish": "Published a saved draft", "restore": "Restored an earlier definition",
           "promote": "Promoted a trial version", "rollback": "Rolled back a trial version"}
TRIAL_LIVE = ("A trial version of this specialist is live. Promote it or roll it back in Workforce before "
              "publishing another change. Nothing was changed.")


def authority(request, context=None, *, write=False):
    auth.require_permission(request, "admin")
    current = context_for(request)
    if context is not None and current != context:
        raise HTTPException(409, "Your account or workspace changed. Reopen this specialist.")
    if write:
        from .editor_policy import require_pack_editing as _require_pack_editing
        _require_pack_editing(request)
        tools_ops_api.same_origin(request)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current settings could not be checked. No new work was admitted.")
    return tools_ops_api.actor(request), current


def _name(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", name):
        raise HTTPException(422, "Choose a specialist or give a custom agent a short name.")
    return name


def _source(request, name):
    name = _name(name)
    profile = domain.available_domains().get(name)
    if profile is not None:
        allowed = auth.caller_suites(request)
        if allowed is not None and not domain.suites_for_domain(name, profile) <= allowed:
            raise HTTPException(403, "Your current access does not include this specialist's department.")
    elif name in domain.rejected_workspace_domains():
        raise HTTPException(409, "Its saved setup cannot be read safely. Review the damaged setup before creating a draft.")
    raw = domain_edit.read_override(name)
    base_name = str(raw.get("extends") or name)
    base = domain.available_domains().get(base_name) if base_name != name else domain.builtin_domains().get(name)
    if base is not None:
        allowed = auth.caller_suites(request)
        if allowed is not None and not domain.suites_for_domain(base_name, base) <= allowed:
            raise HTTPException(403, "Your current access does not include the inherited specialist.")
    path = domain.user_dir() / f"{name}.toml"
    value = {"profile": asdict(profile) if profile else None, "raw": raw,
             "base": asdict(base) if base else None,
             "generation": domain_edit._override_generation(name, path)}
    _bounded(value)
    return value


def _bounded(value):
    try:
        size = len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode())
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "The complete draft contains an unsupported value.") from exc
    if size > 1024 * 1024:
        raise HTTPException(413, "The complete draft exceeds its supported size. Nothing was shortened.")


def _draft(request, name, entered, source):
    if not isinstance(entered, dict) or not set(entered) <= set(PROFILE_LABELS):
        raise HTTPException(422, "This draft contains an unsupported specialist setting.")
    patch = {**copy.deepcopy(source["raw"]), **copy.deepcopy(entered), "name": name}
    try:
        profile = domain_edit.preview_override(name, patch)
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    allowed = auth.caller_suites(request)
    if allowed is not None and not domain.suites_for_domain(name, profile) <= allowed:
        raise HTTPException(403, "The entered draft belongs to a department outside your current access.")
    from .api import _agent_action_errors, _agent_autonomy_errors
    from .api_schemas import AgentOverrideIn
    body = AgentOverrideIn.model_validate(patch)
    errors = _agent_action_errors(name, body) + _agent_autonomy_errors(name, body)
    if errors:
        raise HTTPException(422, "; ".join(errors))
    _allowed_draft_models(asdict(profile), source)
    _allowed_draft_servers(asdict(profile), source)
    _bounded(patch)
    return patch, asdict(profile)


def _server_state(names=()):
    from maverick.mcp_tools import current_mcp_servers

    try:
        current = current_mcp_servers()
    except Exception as exc:
        raise HTTPException(503, "Current tool services could not be checked. Open Tool servers to review their setup; your draft has been kept.") from exc
    names = set(names)
    if len(set(current) | names) > 5000:
        raise HTTPException(409, "The complete tool-service choices exceed the supported limit. Nothing was shortened.")
    choices = []
    for name in sorted(set(current) | set(names)):
        row = current.get(name)
        available = bool(row and row["enabled"] and row["spec"] is not None)
        status = "Configured; connects for new work" if available else "Turned off" if row and row["spec"] else "Setup unavailable"
        choices.append({"value": name, "label": name.replace("_", " ").replace("-", " ") + " · " + status,
                        "available": available})
    binding = digest([(name, current[name]["revision"] if name in current else "missing") for name in sorted(set(names))])
    return {"choices": choices, "binding": binding}


def _allowed_draft_servers(profile, source):
    names = profile["mcp_servers"]
    if len(names) > 5000 or len(set(names)) != len(names) or any(not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) for name in names):
        raise HTTPException(422, "Choose distinct named tool services from the complete editor.")
    retained = set((source.get("profile") or {}).get("mcp_servers", []))
    choices = {row["value"]: row for row in _server_state(names)["choices"]}
    if any(name not in retained and not choices[name]["available"] for name in names):
        raise HTTPException(409, "A newly selected tool service is unavailable or turned off. Set it up in Tool servers, then refresh and review this draft again.")


def _allowed_draft_models(profile, source):
    from maverick.llm import ModelNotAllowedError, require_model_allowed
    before = (source.get("profile") or {}).get("models", {})
    try:
        for role, model in profile["models"].items():
            if before.get(role) != model:
                require_model_allowed(model)
    except ModelNotAllowedError as exc:
        raise HTTPException(409, "A changed AI choice is no longer permitted by the current workspace policy. Choose an allowed AI in the complete editor and review the draft again.") from exc


def _connection(name, *, models=None):
    from maverick.llm import LLM, ModelNotAllowedError, _parse_spec, model_for_role
    try:
        model = model_for_role(name, domain_models=models)
    except ModelNotAllowedError as exc:
        raise HTTPException(409, "This draft's AI choice is not permitted by the current workspace policy. Choose an allowed AI in the complete editor before reviewing it again.") from exc
    provider, _ = _parse_spec(model)
    client = LLM(model)
    connection = client._provider_client_config(provider).fingerprint
    # Only opaque digests are retained; credentials and environment values are not.
    return {"model": str(model), "connection": connection,
            "settings": digest(config.load_config())}


def _owned(request, identifier):
    actor, context = authority(request)
    if not isinstance(identifier, str) or not re.fullmatch(r"SPD-[a-f0-9]{32}", identifier):
        raise HTTPException(404, "This saved specialist record is unavailable.")
    row = STORE.get(identifier)
    if row is None or row.get("actor") != actor or row.get("context") != context:
        raise HTTPException(404, "This saved record is unavailable to this account and workspace.")
    if row.get("_audit_pending"):
        with authority_effect_fence():
            authority(request, context)
            row = STORE._flush(row)
    authority(request, context)
    return row


def _rows(request, name):
    actor, context = authority(request)
    _source(request, name)
    rows = STORE.list(limit=MAX_RECORDS + 1)
    if len(rows) > MAX_RECORDS:
        raise HTTPException(409, "The complete retained history exceeds its supported limit. No history was presented as complete.")
    return sorted((row for row in rows if row.get("actor") == actor and row.get("context") == context and row.get("name") == name),
                  key=lambda row: (row["created_at"], row["id"]), reverse=True)


def original_history(request):
    actor, context = authority(request)
    rows = STORE.list(limit=MAX_RECORDS + 1)
    if len(rows) > MAX_RECORDS:
        raise HTTPException(409, "The complete original history exceeds its supported limit. No choices were silently omitted.")
    choices = [{"value": row["id"], "label": ACTIONS[row["action"]] + " · " + time.strftime("%b %d, %Y %H:%M", time.localtime(row["created_at"]))}
               for row in sorted(rows, key=lambda item: (item["created_at"], item["id"]), reverse=True)
               if row.get("actor") == actor and row.get("context") == context]
    authority(request, context)
    return {"context": context, "originals": choices}


def unpublished_profiles(request, *, name=None) -> dict:
    """The newest confirmed saved draft, per specialist this person has not published yet.

    Saved answer checks can be kept for these before the first publication; they
    are read against the draft. ``name`` limits the answer to one specialist.
    Nothing is returned to a person without admin access or for an unreadable history.
    """
    from maverick import domain

    try:
        actor, context = authority(request)
        rows = STORE.list(limit=MAX_RECORDS + 1)
    except HTTPException:
        return {}
    if len(rows) > MAX_RECORDS:
        return {}
    published = domain.available_domains()
    found: dict = {}
    for row in sorted(rows, key=lambda item: (item["created_at"], item["id"]), reverse=True):
        if (row.get("actor") != actor or row.get("context") != context or row.get("action") != "save"
                or row.get("state") != "confirmed" or row.get("_audit_pending")):
            continue
        if row["name"] in published or row["name"] in found or (name is not None and row["name"] != name):
            continue
        found[row["name"]] = domain._coerce(row["name"], row["profile"])
    return found


def inventory(request, name):
    actor, context = authority(request)
    source = _source(request, name)
    services = _server_state((source["profile"] or {}).get("mcp_servers", []))
    rows = _rows(request, name)
    versions = [{"value": row["id"], "label": (row.get("title") or ACTIONS[row["action"]]) + " · " +
                 time.strftime("%b %d, %Y %H:%M", time.localtime(row["created_at"]))}
                for row in rows if row["action"] == "save" and row["state"] == "confirmed" and not row.get("_audit_pending")]
    earlier = [{"value": row["id"], "label": "Before " + ACTIONS[row["action"]].lower() + " · " +
                time.strftime("%b %d, %Y %H:%M", time.localtime(row["created_at"]))}
               for row in rows if row["action"] in {"publish", "restore"} and row.get("before", {}).get("profile") and row["state"] != "not_started"]
    originals = [{"value": row["id"], "label": ACTIONS[row["action"]] + " · " +
                  time.strftime("%b %d, %Y %H:%M", time.localtime(row["created_at"]))} for row in rows]
    authority(request, context)
    return {"context": context, "binding": digest(source), "name": name, "editor": source["raw"],
            "current": source["profile"], "generation": source["generation"], "drafts": versions,
            "earlier": earlier, "originals": originals, "notice": NOTICE, "actor": actor, "tool_services": services}


def trials(request) -> dict:
    """Every live trial this person may read, with each version's goal counts (no content)."""
    from ._shared import _world

    actor, context = authority(request)
    world = _world()
    found = []
    for row in canary.TRIALS.list(limit=canary.MAX_ROWS + 1):
        trial = row.get("live")
        if trial is None:
            continue
        name = row["name"]
        try:
            _source(request, name)  # the same department access as the editor
        except HTTPException:
            continue
        try:
            versions = canary.version_stats(name, world, candidate_id=trial["candidate_id"])
        except RuntimeError:
            versions = None
        found.append({"name": name, "candidate_id": trial["candidate_id"], "percent": trial["percent"],
                      "started_at": trial["started_at"], "title": trial.get("title") or "", "versions": versions,
                      "auto_rollback": agent_tests_policy.canary_auto_rollback(), "min_finished": canary.MIN_FINISHED_GOALS})
    authority(request, context)
    return {"context": context, "trials": sorted(found, key=lambda item: item["name"])}


def saved_draft(request, identifier):
    row = _owned(request, identifier)
    if row["action"] != "save" or row["state"] != "confirmed" or row.get("_audit_pending"):
        raise HTTPException(409, "This saved draft has no confirmed complete receipt. Read its original outcome.")
    source = _source(request, row["name"])
    # A new, unpublished agent can have no active source yet; its retained
    # complete department still needs the same current access check.
    _draft(request, row["name"], row["patch"], {**source, "raw": {}})
    return row


def _target(request, action, identifier, source):
    row = _owned(request, identifier)
    if action == "restore":
        if row["action"] not in {"publish", "restore"} or not row.get("before", {}).get("profile") or row["state"] == "not_started":
            raise HTTPException(409, "Choose an earlier retained definition.")
        entered = row["before"]["raw"] or row["before"]["profile"]
        patch, profile = _draft(request, row["name"], entered, {**source, "raw": {}})
        if profile != row["before"]["profile"]:
            raise HTTPException(409, "The inherited definition changed. This earlier version cannot be restored exactly; open its settings as a new draft instead.")
    else:
        row = saved_draft(request, identifier)
        patch, profile = _draft(request, row["name"], row["patch"], {**source, "raw": {}})
        if digest(source) != row["source"] or profile != row["profile"]:
            raise HTTPException(409, "The active or inherited specialist changed after this draft was saved. Reopen it as a new draft before using it.")
    return row, patch, profile


def _uncertain(request, name, *, exclude_binding=None):
    from . import specialist_test_sets as tests
    rows = _rows(request, name)
    holds = []
    for row in rows:
        if row.get("binding") == exclude_binding or row["state"] == "not_started" and not row.get("_audit_pending"):
            continue
        run = tests.run_by_id(row["run"]) if row.get("run") else None
        run = tests.public_run(run) if run else None
        if row["state"] != "confirmed" or row.get("_audit_pending") or (run and run["state"] == "unknown"):
            holds.append({"id": row["id"], "revision": row["revision"], "action": ACTIONS[row["action"]], "recorded_at": row["created_at"],
                          "answer_outcome": digest(run) if run else None})
    return holds


def prepare(request, name, action, *, entered=None, selected=None, task="", title="", reason="", context=None, acknowledge_previous=False):
    actor, current = authority(request, context, write=True)
    if action not in ACTIONS:
        raise HTTPException(422, "Choose Save draft, Try, Check saved questions, Publish or Restore.")
    source = _source(request, name)
    selected_revision = None
    trial = canary.live(name)
    candidate_id = None
    if action in {"publish", "restore"} and trial is not None:
        raise HTTPException(409, TRIAL_LIVE)
    if action == "save" or (entered is not None and action in {"try", "check"}):
        patch, profile = _draft(request, name, entered, source)
    elif action in {"promote", "rollback"}:
        if trial is None:
            raise HTTPException(409, "There is no trial version of this specialist to promote or roll back.")
        patch, profile, candidate_id = copy.deepcopy(trial["patch"]), copy.deepcopy(trial["profile"]), trial["candidate_id"]
    else:
        row, patch, profile = _target(request, action, selected, source)
        if row["name"] != name:
            raise HTTPException(409, "This retained version belongs to another specialist.")
        selected_revision = row["revision"]
    if not isinstance(task, str) or not isinstance(title, str) or len(title) > 120 or not isinstance(reason, str) or len(reason) > 300:
        raise HTTPException(422, "The complete entered request exceeds its supported field limits. Nothing was shortened.")
    if action == "try" and not 8 <= len(task.strip()) <= 4000:
        raise HTTPException(422, "Enter a fictional sample request of between 8 and 4,000 characters.")
    from . import specialist_test_sets as tests
    cases = tests.cases_for(name) if action == "check" else []
    if action == "check" and not 1 <= len(cases) <= tests.max_cases_per_specialist():
        raise HTTPException(409, "Add at least one saved answer check before checking this draft.")
    connection = _connection(name, models=profile["models"])
    if action in {"try", "check"}:
        from maverick import model_tests
        try:
            model_tests.policy()
        except PermissionError as exc:
            raise HTTPException(409, str(exc)) from exc
    uncertain = _uncertain(request, name)
    if uncertain and acknowledge_previous is not True:
        raise HTTPException(409, "An earlier decision remains unconfirmed. Read its original, then explicitly acknowledge that earlier work may already exist before reviewing a separate new intent.")
    prepared = {"name": name, "action": action, "actor": actor, "context": current, "source": digest(source),
                "before": source, "patch": patch, "profile": profile, "selected": selected,
                "selected_revision": selected_revision, "task": task, "title": title,
                "reason": reason, "cases": cases, "connection": connection, "expires": time.time() + TTL,
                "uncertain": uncertain, "acknowledge_previous": acknowledge_previous,
                "candidate_id": candidate_id, "trial_percent": agent_tests_policy.canary_percent()}
    prepared["tool_services"] = _server_state(profile["mcp_servers"])
    if action in {"publish", "restore", "promote"}:
        verdict = _publication_verdict(prepared)
        if verdict["blocked"] and verdict.get("hard"):
            raise HTTPException(409, verdict["message"])
        if verdict["blocked"] and len(reason.strip()) < 8:
            raise HTTPException(409, "This complete draft needs a finished passing check of every current saved question, or a reason of at least eight characters for proceeding without one.")
    _bounded(prepared)
    authority(request, current, write=True)
    return prepared


def changes(request, prepared):
    from . import specialist_test_sets as tests
    from .plain_labels import model_label
    _guard(request, prepared)
    from maverick.agent_tests_policy import tool_checks_enabled

    from .specialist_tool_checks import budget_questions
    limits = tests.draft_answer_limits(budget_questions(prepared["cases"], enabled=tool_checks_enabled())
                                       if prepared["action"] == "check" else 1)
    decision = ACTIONS[prepared["action"]] + (f" as a trial on {prepared['trial_percent']}% of new goals" if _starts_trial(prepared) else "")
    rows = [{"label": "Decision", "after": decision},
            {"label": "Complete draft", "after": _readable(prepared["profile"], "definition")},
            {"label": "Currently used definition", "after": _readable(prepared["before"]["profile"], "definition") if prepared["before"]["profile"] else "No active custom agent"},
            {"label": "AI used for answer checks", "after": model_label(prepared["connection"]["model"])}]
    if prepared.get("tool_services"):
        selected = set(prepared["profile"]["mcp_servers"])
        rows.append({"label": "Selected tool services", "after": [row["label"] for row in prepared["tool_services"]["choices"] if row["value"] in selected] or "None selected"})
        rows.append({"label": "Tool-service limits", "after": "Only tools discovered from these connected services can be added for new work. Server tools are high risk unless an administrator has explicitly changed an action's classification. The specialist's risk limit, blocked actions and the caller's permissions still apply. Saving or trying this draft does not connect or test a service."})
    if prepared["action"] == "try":
        rows.append({"label": "Fictional sample request", "after": prepared["task"]})
    if prepared["action"] == "check":
        rows.append({"label": "Every saved question and passing condition", "after": [{"Question": row["task"], "Must mention": row["includes"],
            "Must never say": row["excludes"], "Should refuse": "Yes" if row["refusal"] else "No", "Needs a source reference": "Yes" if row["citation"] else "No"} for row in prepared["cases"]]})
    if prepared["action"] in {"promote", "rollback"}:
        trial = canary.live(prepared["name"]) or {}
        rows.append({"label": "Trial being decided", "after": f"{trial.get('percent', 0)}% of new goals used it. "
                     + ("Promoting makes it the current version for everyone." if prepared["action"] == "promote"
                        else "Rolling back discards it; the current version stays as it is.")})
    if prepared["action"] in {"publish", "restore", "promote"}:
        rows.append({"label": "Publication tests", "after": _publication_verdict(prepared)["message"]})
        if prepared["reason"]:
            rows.append({"label": "Reason for publishing without a complete passing check", "after": prepared["reason"]})
    if prepared["uncertain"]:
        rows.append({"label": "Earlier unconfirmed decisions", "after": {
            "Earlier work may already exist": [{"Decision": item["action"], "Recorded": time.strftime("%b %d, %Y %H:%M", time.localtime(item["recorded_at"]))} for item in prepared["uncertain"]],
            "Separate new intent": "I acknowledged the earlier unknown outcomes. This new full review does not confirm or repeat those originals."}})
    rows.extend([{"label": "Limits and consequences", "after": NOTICE + (
                     f" One shared answer-check limit: ${limits['max_dollars']:.2f}, {limits['max_input_tokens']:,} input tokens, "
                     f"{limits['max_output_tokens']:,} output tokens and {limits['max_wall_seconds']:,} seconds. "
                     "A partial or stopped check is not a passing publication check." if prepared["action"] in {"try", "check"} else "")},
                 {"label": "If the response is lost", "after": "Read this original decision. An unconfirmed original is not automatically repeated, and a matching current definition does not prove its outcome."}])
    return rows


NEW_SPECIALIST_NEEDS_CHECK = ("A new specialist needs at least one saved check before it can be published. "
                              "Add a check in Workforce, run every saved check on this draft in Agent Factory, "
                              "then publish it again. A reason cannot skip this.")
NEW_SPECIALIST_NEEDS_RUN = ("A new specialist can be published only after a full run of every saved check on this "
                            "exact draft has passed. Run the checks on this draft in Agent Factory, then publish it "
                            "again. A reason cannot skip this.")


def _complete_check(prepared) -> bool:
    """Whether the latest full run of every current saved check, on exactly this complete draft, passed.

    An older passing run never counts once a newer full run on the same draft has failed or stopped.
    """
    from . import specialist_test_sets as tests
    current = {case["id"]: case["revision"] for case in tests.cases_for(prepared["name"])}
    if not current:
        return False
    full = [run for run in tests.all_runs_for(prepared["name"])  # newest first
            if run["model"] == prepared["connection"]["model"]
            and run.get("comparison", {}).get("draft_profile") == prepared["profile"]
            and run.get("comparison", {}).get("connection") == prepared["connection"]
            and {case["id"]: case["revision"] for case in run["case_revisions"]} == current]
    if not full:
        return False
    latest = full[0]
    return (latest["state"] == "done" and len(latest["results"]) == len(current)
            and all(result["passed"] for result in latest["results"]))


def _publication_verdict(prepared):
    from maverick.agent_publish_policy import require_passing_tests
    from maverick.agent_tests_policy import require_for_new_specialists

    from . import agent_publish_gate
    before = prepared["before"]["profile"] or {}
    verdict = agent_publish_gate.check(prepared["name"], model=prepared["connection"]["model"], current_instructions=before.get("persona", ""),
        new_instructions=prepared["profile"]["persona"], creating=not before, required=require_passing_tests())
    # A specialist never published before is "hard": no reason publishes it without this proof.
    new = not before and require_for_new_specialists()
    if new or (before and before != prepared["profile"] and require_passing_tests()):
        complete = _complete_check(prepared)
        if complete:
            message = "Every current saved question passed on this complete draft."
        elif new:
            from . import specialist_test_sets as tests
            message = NEW_SPECIALIST_NEEDS_RUN if tests.cases_for(prepared["name"]) else NEW_SPECIALIST_NEEDS_CHECK
        else:
            message = "This complete draft has no finished passing check of every current saved question. Publishing needs a new complete check or an explicit recorded reason."
        verdict.update(required=True, passing=complete, blocked=not complete, hard=new, message=message)
    return verdict


def _review_time(actor, prepared):
    expires = prepared.get("expires")
    now = time.time()
    if actor != prepared["actor"] or type(expires) not in {int, float} or not math.isfinite(expires) or not now < expires <= now + TTL:
        raise HTTPException(409, "This complete review expired. Review the current draft before another decision.")


def _guard(request, prepared, *, budget=None, published=None):
    actor, context = authority(request, prepared["context"], write=True)
    _review_time(actor, prepared)
    source = _source(request, prepared["name"])
    expected = published if published is not None else prepared["source"]
    if digest(source) != expected:
        raise HTTPException(409, "The active or inherited specialist changed. Review the complete current draft again.")
    if asdict(domain_edit.preview_override(prepared["name"], prepared["patch"])) != prepared["profile"]:
        raise HTTPException(409, "The draft's inherited settings changed. Review its complete current definition again.")
    _allowed_draft_models(prepared["profile"], prepared["before"])
    _allowed_draft_servers(prepared["profile"], prepared["before"])
    if prepared.get("tool_services") and _server_state(prepared["profile"]["mcp_servers"])["binding"] != prepared["tool_services"]["binding"]:
        raise HTTPException(409, "A selected tool service changed. Refresh its setup and review the complete draft again.")
    if _connection(prepared["name"], models=prepared["profile"]["models"]) != prepared["connection"]:
        raise HTTPException(409, "The AI connection or current settings changed. Review the draft again before proceeding.")
    if prepared["selected"] is not None:
        row = _owned(request, prepared["selected"])
        if row["revision"] != prepared["selected_revision"]:
            raise HTTPException(409, "The chosen retained draft changed. Choose it again.")
    if prepared["action"] == "check":
        from . import specialist_test_sets as tests
        if tests.cases_for(prepared["name"]) != prepared["cases"]:
            raise HTTPException(409, "A saved question changed. Review all questions again before checking answers.")
    if _uncertain(request, prepared["name"], exclude_binding=digest(prepared)) != prepared["uncertain"]:
        raise HTTPException(409, "An earlier original outcome changed. Read it and review this separate intent again.")
    actor, _ = authority(request, context, write=True)
    _review_time(actor, prepared)
    if budget is not None:
        budget.check()


def original(request, operation, *, prepared=None):
    identifier = "SPD-" + operation if not str(operation).startswith("SPD-") else operation
    row = _owned(request, identifier)
    if prepared is not None and row["binding"] != digest(prepared):
        raise HTTPException(409, "This original belongs to a different complete review.")
    confirmed = row["state"] == "confirmed" and not row.get("_audit_pending")
    refused = row["state"] == "not_started" and not row.get("_audit_pending")
    result = {"context": row["context"], "operation": row["id"][4:], "confirmed": confirmed,
              "action": ACTIONS[row["action"]], "message": "The original decision is confirmed. Nothing was repeated." if confirmed else
              "The original decision was refused before it changed anything. Nothing was repeated." if refused else
              "The original decision is unconfirmed. Some work may already have happened; no answer request or publication was repeated.",
              "recorded_at": row["updated_at"], "notice": NOTICE}
    try:
        source = _source(request, row["name"])
    except HTTPException:
        return result
    # A specialist not yet published has no live profile, but its own check outcome is still read here.
    if source["profile"] is None and not row.get("run"):
        return result
    result.update(name=row["name"], draft=row["id"] if row["action"] == "save" and confirmed else None)
    if row.get("run"):
        from . import specialist_test_sets as tests
        run = tests.run_by_id(row["run"])
        if run and run["actor"] == row["actor"]:
            result["run"] = tests.public_run(run)
            result["message"] = "The original answer-check admission is confirmed. Read its separate answer outcome below; no answer request was repeated." if confirmed else result["message"]
            if result["run"]["state"] == "unknown":
                result["message"] = "The original answer outcome remains unknown. An AI request may already have happened; nothing was repeated."
    return result


def apply(request, prepared, operation):
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(422, "This original decision could not be identified.")
    identifier = "SPD-" + operation
    authority(request, prepared["context"], write=True)
    if STORE.get(identifier) is not None:
        return original(request, identifier, prepared=prepared)
    began, row = [], None
    with authority_effect_fence(), cross_process_lock(domain.user_dir() / f"{prepared['name']}.toml", strict=True):
        _guard(request, prepared)
        if STORE.get(identifier) is not None:
            return original(request, identifier, prepared=prepared)
        try:
            row = STORE.create({"id": identifier, "actor": prepared["actor"], "context": prepared["context"],
                "name": prepared["name"], "action": prepared["action"], "state": "unconfirmed", "binding": digest(prepared),
                "before": prepared["before"], "patch": prepared["patch"], "profile": prepared["profile"], "source": prepared["source"],
                "title": prepared["title"], "prepared": prepared}, action="specialist_draft.started", actor=prepared["actor"],
                max_records=MAX_RECORDS, effect_guard=lambda: _guard(request, prepared))
            if row.get("_audit_pending"):
                return original(request, identifier, prepared=prepared)
            if prepared["action"] in {"try", "check"}:
                return _start_answers(request, prepared, row, began)
            if prepared["action"] in {"publish", "restore"}:
                return _publish(request, prepared, row, began)
            if prepared["action"] in {"promote", "rollback"}:
                return _settle_trial(request, prepared, row, began)
            STORE.update(row["id"], lambda current: current.update(state="confirmed"), expected_revision=row["revision"],
                action="specialist_draft.completed", actor=prepared["actor"], effect_guard=lambda: _guard(request, prepared))
        except HTTPException:
            if STORE.get(identifier) is None:
                raise
            # A refusal before any change began is the real answer, not an unknown outcome.
            if not began and _mark_not_started(prepared, row):
                raise
        except Exception as exc:
            if STORE.get(identifier) is None:
                raise HTTPException(503, "The complete draft could not be retained. Your entered work is still in the editor.") from exc
        return original(request, identifier, prepared=prepared)


def _mark_not_started(prepared, row):
    """Record that nothing began; any doubt about the record or its audit keeps it unconfirmed."""
    try:
        current = STORE.get(row["id"]) if row else None
        if current is None or current["revision"] != row["revision"] or current.get("_audit_pending"):
            return False
        saved = STORE.update(row["id"], lambda value: value.update(state="not_started"), expected_revision=row["revision"],
                             action="specialist_draft.refused", actor=prepared["actor"])
        return saved is not None and not saved.get("_audit_pending")
    except Exception:  # noqa: BLE001 - a record that cannot be marked stays unconfirmed
        return False


def _starts_trial(prepared) -> bool:
    """A changed existing specialist is published as a trial while ``canary_percent`` is above 0."""
    before = prepared["before"]["profile"]
    return (prepared["action"] in {"publish", "restore"} and prepared.get("trial_percent", 0) > 0
            and bool(before) and before != prepared["profile"])


def _payload(prepared):
    from .api_schemas import AgentOverrideIn
    return AgentOverrideIn.model_validate({**prepared["patch"], "publish_without_passing_tests": bool(prepared["reason"]),
        "override_reason": prepared["reason"], "expected_generation": prepared["before"]["generation"]})


def _publish(request, prepared, row, began):
    payload = _payload(prepared)

    second_person = _publication_admission(request, prepared, payload)
    if _starts_trial(prepared):
        return _start_trial(request, prepared, row, began, payload, second_person)

    def guard():
        _guard(request, prepared)
        _publication_current(request, prepared, payload)
        # Once a guard passes, the replacement itself may happen.
        began.append(True)

    domain_edit.write_override(prepared["name"], prepared["patch"], expected_generation=prepared["before"]["generation"], effect_guard=guard)
    published = digest(_source(request, prepared["name"]))
    STORE.update(row["id"], lambda current: current.update(state="confirmed", published=published,
        bypass_approval=(second_person or {}).get("approval")), expected_revision=row["revision"],
        action="specialist_draft.completed", actor=prepared["actor"], effect_guard=lambda: _guard(request, prepared, published=published))
    # The agent's own plain-words history (who, when, what) records every
    # published or restored definition, as the retired direct save did.
    from .api import _record_agent_change
    _record_agent_change(request, prepared["name"], prepared["before"]["profile"], prepared["profile"])
    return original(request, row["id"], prepared=prepared)


def _start_trial(request, prepared, row, began, payload, second_person):
    """Keep the current definition and make the changed one a trial on a share of new goals."""
    from .api import caller_principal

    name = prepared["name"]

    def guard():
        _guard(request, prepared)
        _publication_current(request, prepared, payload)
        began.append(True)

    try:
        trial = canary.start(name, patch=prepared["patch"], profile=prepared["profile"], percent=prepared["trial_percent"],
                             actor=prepared["actor"], title=prepared["title"], reason=prepared["reason"], effect_guard=guard)
    except canary.TrialAlreadyLive as exc:
        raise HTTPException(409, TRIAL_LIVE) from exc
    published = digest(_source(request, name))
    STORE.update(row["id"], lambda current: current.update(state="confirmed", published=published, trial=trial["candidate_id"],
        bypass_approval=(second_person or {}).get("approval")), expected_revision=row["revision"],
        action="specialist_draft.completed", actor=prepared["actor"], effect_guard=lambda: _guard(request, prepared, published=published))
    agent_changelog.record(name, [f"Started a trial of changed instructions on {trial['percent']}% of new goals; "
                                  "the current version keeps the rest"], by=caller_principal(request) or "")
    return original(request, row["id"], prepared=prepared)


def _settle_trial(request, prepared, row, began):
    """Promote the live trial to everyone, or roll it back. Both are reviewed and audited like a publication."""

    name = prepared["name"]
    before = prepared["before"]["profile"]
    live_trial = canary.live(name)
    if live_trial is None or live_trial["candidate_id"] != prepared["candidate_id"]:
        raise HTTPException(409, "The trial version changed. Review it again.")
    if prepared["action"] == "promote":
        payload = _payload(prepared)
        second_person = _publication_admission(request, prepared, payload)

        def guard():
            _guard(request, prepared)
            _publication_current(request, prepared, payload)
            began.append(True)

        domain_edit.write_override(name, prepared["patch"], expected_generation=prepared["before"]["generation"], effect_guard=guard)
        canary.finish(name, candidate_id=prepared["candidate_id"], outcome=canary.PROMOTED, actor=prepared["actor"])
        published = digest(_source(request, name))
        STORE.update(row["id"], lambda current: current.update(state="confirmed", published=published,
            bypass_approval=(second_person or {}).get("approval")), expected_revision=row["revision"],
            action="specialist_draft.completed", actor=prepared["actor"], effect_guard=lambda: _guard(request, prepared, published=published))
        from .api import _record_agent_change
        _record_agent_change(request, name, before, prepared["profile"])
    else:
        _roll_back_trial(request, prepared, row, began)
    return original(request, row["id"], prepared=prepared)


def _roll_back_trial(request, prepared, row, began):
    from .api import caller_principal

    name = prepared["name"]

    def guard():
        _guard(request, prepared)
        began.append(True)

    canary.finish(name, candidate_id=prepared["candidate_id"], outcome=canary.ROLLED_BACK, actor=prepared["actor"], effect_guard=guard)
    published = digest(_source(request, name))
    STORE.update(row["id"], lambda current: current.update(state="confirmed", published=published), expected_revision=row["revision"],
        action="specialist_draft.completed", actor=prepared["actor"], effect_guard=lambda: _guard(request, prepared, published=published))
    agent_changelog.record(name, ["Rolled back the trial version; the current instructions stay as they were"],
                           by=caller_principal(request) or "")
    return original(request, row["id"], prepared=prepared)


def _publication_current(request, prepared, payload):
    from .api import _agent_action_errors, _agent_autonomy_errors, _publish_check
    errors = _agent_action_errors(prepared["name"], payload) + _agent_autonomy_errors(prepared["name"], payload)
    if errors:
        raise HTTPException(409, "; ".join(errors))
    verdict = _publish_check(prepared["name"], payload, prepared["before"]["profile"])
    if (verdict["blocked"] or _publication_verdict(prepared)["blocked"]) and len(prepared["reason"].strip()) < 8:
        raise HTTPException(409, "Current passing tests no longer support this complete publication. Review a new check or an explicit reason.")


def bypass_used(name: str, approval_id: int) -> bool:
    """Whether a publication of this specialist already spent this second-person approval."""
    rows = STORE.list(limit=MAX_RECORDS + 1)
    return len(rows) > MAX_RECORDS or any(row.get("name") == name and row.get("bypass_approval") == approval_id for row in rows)


def _publication_admission(request, prepared, payload) -> dict | None:
    """Admit a publication. Returns the second person's approval that a reasoned bypass used, if any."""
    from maverick.agent_tests_policy import bypass_requires_second_person
    from maverick.audit import EventKind, audit_event

    from . import agent_publish_bypass
    from .api import _publish_check, _record_agent_autonomy_intent, _require_tested_instructions
    _guard(request, prepared)
    verdict = _publication_verdict(prepared)
    if verdict["blocked"] and verdict.get("hard"):
        # A brand-new specialist is refused before any reasoned bypass is considered or recorded.
        raise HTTPException(409, verdict["message"])
    _publication_current(request, prepared, payload)
    reason = " ".join((payload.override_reason or "").split())
    second_person = None
    if payload.publish_without_passing_tests and len(reason) >= 8 and bypass_requires_second_person():
        try:
            plain_blocked = _publish_check(prepared["name"], payload, prepared["before"]["profile"])["blocked"]
        except Exception as exc:
            raise HTTPException(503, "The saved test results could not be read. Nothing was changed.") from exc
        if plain_blocked or verdict["blocked"]:
            second_person = agent_publish_bypass.second_person_approval(
                request, prepared["name"], prepared["profile"], reason,
                used=lambda approval_id: bypass_used(prepared["name"], approval_id))
    _require_tested_instructions(request, prepared["name"], payload, prepared["before"]["profile"], second_person=second_person)
    if verdict["blocked"]:
        accepted = audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard", verb="agent_draft_published_without_complete_check",
            actor=prepared["actor"], specialist=prepared["name"], reason=prepared["reason"], **(second_person or {}))
        if not accepted:
            raise HTTPException(503, "The reason could not be recorded. Read the original decision before another publication intent.")
    before = (prepared["before"]["profile"] or {}).get("autonomy") or {}
    after = prepared["profile"].get("autonomy") or {}
    # A trial is only a candidate until it is promoted; its independence change is recorded then.
    if before != after and after and not _starts_trial(prepared):
        _record_agent_autonomy_intent(request, prepared["name"], before, after)
    return second_person


def _start_answers(request, prepared, row, began):
    from . import workforce_ops_api as native

    def started(job, budget):
        _guard(request, prepared, budget=budget)
        current = STORE.update(row["id"], lambda record: record.update(state="confirmed", run=row["id"][4:], job=job.id),
            expected_revision=row["revision"], action="specialist_draft.completed", actor=prepared["actor"], effect_guard=lambda: _guard(request, prepared, budget=budget))
        if current is None or current.get("_audit_pending"):
            raise HTTPException(503, "The original worker admission could not be confirmed. No answer request was admitted.")

    native._start_customer_test_job(request, prepared["name"], operation_id=row["id"][4:],
        draft=prepared, draft_guard=lambda budget=None: _guard(request, prepared, budget=budget), draft_started=started)
    # A refused admission raises above; once it returns, the worker may already be running.
    began.append(True)
    return original(request, row["id"], prepared=prepared)


def seal(prepared, operation):
    token = crypto_at_rest.seal_to_str(json.dumps({"purpose": "lightwork.specialist-draft.v1", "prepared": prepared, "operation": operation}, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "This complete review could not be retained securely. Nothing was submitted.")
    return token


def open_review(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if set(value) != {"purpose", "prepared", "operation"} or value["purpose"] != "lightwork.specialist-draft.v1":
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This complete review could not be verified. Read its original outcome or review the current draft again.") from exc
