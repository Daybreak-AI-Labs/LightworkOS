"""Reviewed native automation translation, bounded connection reads and originals."""
from __future__ import annotations

import json
import re
import time
from contextlib import ExitStack
from dataclasses import asdict
from urllib.parse import quote, urlsplit

from fastapi import HTTPException
from maverick import config, connections, crypto_at_rest, templates, workflow_versions
from maverick.authority_effects import authority_effect_fence
from maverick.automation_import import available_sources, enabled, get_importer, materialize
from maverick.automation_import.to_flow import to_flow_with_report
from maverick.budget import Budget
from maverick.file_lock import cross_process_lock
from maverick.flow import enabled as flows_enabled
from maverick.flow import store as flows
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore, RecordConflict
from maverick.paths import current_tenant_id_strict, data_dir
from pydantic import BaseModel, ConfigDict, Field

from . import auth, tools_ops_api
from .draft_api import context_for
from .plain_labels import datetime_text

PAGE = "/automations#auto-import-h"
API = "/api/v1/automation-imports"
TTL = 600
LIVE = {"n8n", "make", "workato", "uipath"}
NAMES = {"n8n": "n8n", "make": "Make", "workato": "Workato", "uipath": "UiPath", "power_automate": "Power Automate", "zapier": "Zapier", "notion": "Notion"}
NOTICE = ("Review every translated instruction and any visual flow before saving. An import creates drafts; it does not prove identical behavior in the other platform. "
          "Nothing is published, scheduled or allowed to start from another service. Activation is a separate reviewed choice after publication. "
          "If a save is interrupted, read its original record. It will never repeat automatically; earlier saved items may remain.")


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: str = Field(pattern=r"^(n8n|make|workato|uipath|power_automate|zapier|notion)$")
    mode: str = Field(pattern=r"^(file|live)$")
    file_text: str = Field(default="", max_length=512000)
    connection: str = Field(default="", max_length=64)
    organization: str = Field(default="", max_length=80)
    tenant_name: str = Field(default="", max_length=80)
    make_scope: str = Field(default="", pattern=r"^(|team|organization)$")
    make_scope_id: int | None = Field(default=None, ge=1, le=2**53 - 1)
    replace: list[str] = Field(default_factory=list, max_length=25)
    as_flows: bool = False
    budget_dollars: float = Field(default=5.0, ge=0, le=1000, allow_inf_nan=False)
    budget_wall_seconds: int = Field(default=300, ge=1, le=3600)


class Activation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    original: str = Field(pattern=r"^AIR-[a-f0-9]{32}$")
    item: int = Field(ge=0, le=24)
    params: dict[str, str] = Field(default_factory=dict, max_length=128)
    timezone: str = Field(min_length=1, max_length=80)


def records():
    return GovernedRecordStore("automation-import-requests", "AIR", "automation_imports", required_backend="local")


def authority(request, context=None, *, write=False):
    auth.require_permission(request, "operate")
    actor = auth.caller_principal(request)
    if not actor:
        raise HTTPException(403, "Sign in to an account before importing or reading original imports.")
    current = context_for(request)
    if context is not None and current != context:
        raise HTTPException(409, "Your account, workspace or access changed. Refresh before using these private imports.", headers={"X-Lightwork-Import-Context-Changed": "1"})
    if write:
        tools_ops_api.same_origin(request)
    return current_tenant_id_strict() or "", actor, current


def policy():
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current import settings are unavailable. Repair Settings before continuing.")
    if not enabled():
        raise HTTPException(409, "Automation import is off. An administrator can enable it in All settings; original history remains available.")
    return digest([config.get_automation_import(), config.get_flows(), flows_enabled(), config.get_features(), str(data_dir().resolve())])


def seal(value):
    result = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(result) or len(result) > 3_000_000:
        raise HTTPException(503, "This complete private import cannot be retained securely. Enable Encrypt stored data or choose a smaller export; nothing was saved.")
    return result


def opened(row):
    value = json.loads(crypto_at_rest.unseal_from_str(row["payload"]))
    if digest(value["prepared"]) != row["binding"]:
        raise HTTPException(409, "The original import review cannot be verified. It was not repeated.")
    return value


def owned(request, identifier):
    tenant, actor, context = authority(request)
    if re.fullmatch(r"AIR-[a-f0-9]{32}", identifier or "") is None:
        raise HTTPException(422, "Choose an original import request.")
    store = records()
    row = store.get(identifier)
    if row and (row.get("tenant"), row.get("owner")) != (tenant, actor):
        raise HTTPException(404, "This original import is unavailable to your account and workspace.")
    authority(request, context)
    if row and row.get("_audit_pending"):
        row = store._flush(row)
        authority(request, context)
    return row


def history(request):
    tenant, actor, context = authority(request)
    rows = records().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(409, "The complete import history exceeds its supported limit. No records were silently hidden.")
    result = [{"value": row["id"], "label": NAMES.get(row["source"], "Imported work") + " / " + ("Save drafts" if row["kind"] == "import" else "Activate schedule") + " / " + datetime_text(row["created_at"])}
              for row in reversed(rows) if (row.get("tenant"), row.get("owner")) == (tenant, actor)]
    authority(request, context)
    return {"context": context, "choices": result}


def catalog(request):
    from zoneinfo import available_timezones
    _tenant, actor, context = authority(request)
    saved = []
    if connections.enabled():
        for row in connections.list_connections():
            record = connections.get_connection(row["name"])
            if record and row["connector"] in LIVE and connections._may_use(record, actor):
                saved.append({"value": row["name"], "label": row["name"].replace("-", " "), "source": row["connector"], "ready": bool(row["has_token"]), "origin": row["base_url"]})
    result = {"context": context, "enabled": enabled(), "sources": [{"value": name, "label": NAMES[name], "live": name in LIVE} for name in available_sources()], "connections": saved, "timezones": sorted(available_timezones() | {"UTC"}), "notice": NOTICE}
    authority(request, context)
    return result


def _connection(request, choices):
    _tenant, actor, context = authority(request, choices["context"])
    row = connections.get_connection(choices["connection"])
    if (not connections.enabled() or not row or not connections._may_use(row, actor) or row["connector"] != choices["source"] or not row.get("token")):
        raise HTTPException(409, "Choose a current connected account for this platform in Connections, with permission to read its automations.")
    parsed = urlsplit(row["base_url"])
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.port not in (None, 443)):
        raise HTTPException(409, "This connection needs the platform's secure server address without an extra path. Reconnect it in Connections.")
    authority(request, context)
    return {"name": row["name"], "revision": row["revision"], "connector": row["connector"], "origin": "https://" + parsed.hostname.lower()}


def _bounded(raws):
    if type(raws) is not list or not 1 <= len(raws) <= 25 or any(type(row) is not dict for row in raws):
        raise HTTPException(422, "Choose an export containing one to twenty-five complete automations. Unsupported records are never silently skipped.")
    sizes = [len(json.dumps(row, ensure_ascii=False, allow_nan=False).encode("utf-8")) for row in raws]
    if max(sizes) > 64000 or sum(sizes) > 512000:
        raise HTTPException(413, "Choose a smaller export: each automation must fit within 64 KB and the complete import within 512 KB.")
    return raws


def _file(text):
    if not text or len(text.encode("utf-8")) > 512000:
        raise HTTPException(413, "Choose a platform export no larger than 512 KB.")
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate export fields")
            result[key] = value
        return result
    try:
        value = json.loads(text, object_pairs_hook=unique_fields, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError) as exc:
        raise HTTPException(422, "This is not a readable platform export. Use that platform's Export or Download choice and choose the resulting file.") from exc
    if type(value) is dict:
        collections = [key for key in ("workflows", "recipes", "scenarios", "value", "data") if type(value.get(key)) is list]
        if len(collections) > 1:
            raise HTTPException(422, "This export has more than one collection. Choose a separate platform automation export.")
        value = value[collections[0]] if collections else [value]
    return _bounded(value)


def fetch(request, choices, pin):
    """The unchanged importer controls fixed read paths; credentials refresh per send."""
    import httpx
    from maverick.tools._ssrf import safe_client
    budget = Budget(max_dollars=0, max_tool_calls=200, max_wall_seconds=30)
    source_policy = policy()
    base = pin["origin"]
    if choices["source"] == "make" and (choices["make_scope"] not in {"team", "organization"} or choices["make_scope_id"] is None):
        raise HTTPException(422, "Choose a Make team or organization and enter its account number from Make.")
    if choices["source"] == "uipath":
        if not all(re.fullmatch(r"[A-Za-z0-9_-]{1,80}", choices[name]) for name in ("organization", "tenant_name")):
            raise HTTPException(422, "Enter the UiPath organization and tenant names shown in its address.")
        base += "/" + quote(choices["organization"], safe="") + "/" + quote(choices["tenant_name"], safe="") + "/orchestrator_"
    received = 0
    def send(url, **kwargs):
        nonlocal received
        budget.check()
        authority(request, choices["context"], write=True)
        if policy() != source_policy or _connection(request, choices) != pin:
            raise HTTPException(409, "The import settings or connected account changed. No further account requests were sent.")
        path = urlsplit(url).path
        allowed = {"n8n": r"/api/v1/workflows", "make": r"/api/v2/scenarios(?:/[A-Za-z0-9_-]{1,100}/blueprint)?", "workato": r"/api/recipes", "uipath": re.escape(urlsplit(base).path) + r"/odata/(?:ProcessSchedules|Releases)"}
        if not url.startswith(base + "/") or re.fullmatch(allowed[choices["source"]], path) is None or urlsplit(url).query or urlsplit(url).fragment:
            raise HTTPException(409, "The platform returned an unsupported account request. Use a supported export instead.")
        def before_send(outgoing):
            # safe_client resolves DNS before this hook. Re-read the exact
            # authority and credential inside the fences held through I/O.
            budget.check()
            _tenant, current_actor, _context = authority(request, choices["context"], write=True)
            if policy() != source_policy or _connection(request, choices) != pin:
                raise HTTPException(409, "The import settings or connected account changed. No further account requests were sent.")
            with connections.bind_principal(current_actor):
                credential = connections.resolve_named(pin["name"], expected_revision=pin["revision"], connector=pin["connector"], origin=pin["origin"])
            token = credential["token"]
            outgoing.headers["X-N8N-API-KEY" if choices["source"] == "n8n" else "Authorization"] = token if choices["source"] == "n8n" else ("Token " if choices["source"] == "make" else "Bearer ") + token
            budget.record_tool_call()
        with safe_client(url, timeout=min(10, budget.remaining_wall()), attempt_deadline=time.monotonic() + budget.remaining_wall(), event_hooks={"request": [before_send]}) as client:
            with authority_effect_fence(), connections._mutation_lock():
                with client.stream("GET", url, headers={"Accept": "application/json"}, params=kwargs.get("params")) as response:
                    response.raise_for_status()
                    chunks = []
                    for chunk in response.iter_bytes():
                        budget.check()
                        received += len(chunk)
                        if received > 512000:
                            raise HTTPException(413, "The account export exceeds 512 KB. Choose a smaller exported collection instead.")
                        chunks.append(chunk)
                    authority(request, choices["context"])
                    result = httpx.Response(response.status_code, content=b"".join(chunks), request=httpx.Request("GET", url))
        body = result.json()
        if type(body) not in {dict, list}:
            raise HTTPException(422, "The connected platform did not return a complete supported automation collection.")
        key = {"n8n": "data", "make": "scenarios", "workato": "items", "uipath": "value"}[choices["source"]]
        collection = body if type(body) is list else body.get(key)
        if choices["source"] == "make" and path.endswith("/blueprint"):
            if type(body) is not dict:
                raise HTTPException(422, "One scenario did not return a complete blueprint. Nothing was skipped.")
        elif type(collection) is not list or len(collection) > 25 or any(type(item) is not dict for item in collection):
            raise HTTPException(422, "This account collection is too large or includes unsupported records. Choose an export of up to twenty-five complete automations; nothing was skipped.")
        elif choices["source"] == "make" and any(item.get("id") is None for item in collection):
            raise HTTPException(422, "A scenario has no current account reference. Nothing was skipped.")
        if choices["source"] == "uipath" and body.get("@odata.nextLink"):
            raise HTTPException(409, "This UiPath collection needs additional pages that this import cannot safely read. Export the selected automations instead; no partial import was saved.")
        authority(request, choices["context"])
        return result
    make_options = {"scope": choices["make_scope"], "scope_id": choices["make_scope_id"]} if choices["source"] == "make" else {}
    importer = type(get_importer(choices["source"]))(base_url=base, request=send, **make_options)
    return _bounded(importer.fetch())


def _template(name, actor):
    try:
        value = templates.load_template(name)
    except FileNotFoundError:
        return None
    if value.owner != actor:
        raise HTTPException(409, "A workflow with this import name belongs to another account or needs administrator ownership repair. It cannot be replaced here.")
    return {"generation": value.generation, "digest": digest(asdict(value) | {"path": str(value.path) if value.path else None}), "title": value.title, "body": value.body, "params": value.params, "budget_dollars": value.budget_dollars, "budget_wall_seconds": value.budget_wall_seconds}


def _translated(request, choices, raws):
    _tenant, actor, _context = authority(request, choices["context"])
    importer = get_importer(choices["source"])
    result = []
    for raw in _bounded(raws):
        try:
            automation = importer.translate(raw)
            title, body = automation.render(complete=True)
        except Exception as exc:
            raise HTTPException(422, "An automation in this export could not be translated completely. Nothing was skipped or saved; choose a supported separate export.") from exc
        if not body or len(body) > 16000:
            raise HTTPException(413, "One automation's full instructions exceed the supported review size. Choose a smaller automation export.")
        name = automation.template_name()
        prior = _template(name, actor)
        graph, fidelity = None, []
        if choices["as_flows"]:
            if not flows_enabled():
                raise HTTPException(409, "Visual workflows are off. Enable them in Settings or save instruction drafts only.")
            try:
                graph, fidelity = to_flow_with_report(automation)
            except ValueError as exc:
                # A condition the visual flow cannot run as written: say which
                # repair is needed (the message never echoes the expression)
                # and refuse the whole batch before anything is saved.
                if not str(exc).startswith("Imported condition requires repair before execution"):
                    raise
                raise HTTPException(422, str(exc) + ". Repair it in the other platform or import "
                                    "instruction drafts only; nothing was saved.") from exc
            graph.owner = actor
            if flows.load_flow(graph.id) is not None:
                raise HTTPException(409, "An imported visual workflow already exists. Review and edit it in Designer; this import never replaces a visual workflow.")
        source_zone = (raw.get("settings") or {}).get("timezone") if choices["source"] == "n8n" and type(raw.get("settings")) is dict else ""
        result.append({"name": name, "title": title, "body": body, "prior": prior, "params": templates._template_parameters(automation.payload_fields(), title, body), "trigger": asdict(automation.trigger), "source_timezone": source_zone if type(source_zone) is str and len(source_zone) <= 80 else "", "source_enabled": automation.enabled, "graph": graph.to_dict() if graph else None, "fidelity": fidelity})
    if len({item["name"] for item in result}) != len(result):
        raise HTTPException(409, "Two automations resolve to the same saved workflow. Choose separate exports; neither can silently replace the other.")
    if len(set(choices["replace"])) != len(choices["replace"]) or any(name not in [item["name"] for item in result if item["prior"]] for name in choices["replace"]):
        raise HTTPException(409, "The replacement choices no longer match the current owned workflows. Check the export again.")
    return result


def prepare(request, choices, *, checked_raws=None, checked_pin=None):
    choices = Choices.model_validate(choices).model_dump()
    tenant, actor, context = authority(request, choices["context"], write=True)
    source_policy = policy()
    # A platform without an account reader needs its export, whatever account is chosen.
    if choices["mode"] == "live" and (choices["source"] not in LIVE or choices["file_text"]):
        raise HTTPException(422, "This platform requires an exported file, or an account import must have no file selected.")
    pin = _connection(request, choices) if choices["mode"] == "live" else None
    if choices["mode"] == "live":
        if checked_raws is not None and pin != checked_pin:
            raise HTTPException(409, "The account changed after the export was read. Check the current account again.")
        raws = checked_raws if checked_raws is not None else fetch(request, choices, pin)
    else:
        if choices["connection"] or choices["organization"] or choices["tenant_name"] or choices["make_scope"] or choices["make_scope_id"] is not None:
            raise HTTPException(422, "An exported file does not use a connected account.")
        raws = _file(choices["file_text"])
    items = _translated(request, choices, raws)
    authority(request, context, write=True)
    if policy() != source_policy:
        raise HTTPException(409, "Import settings changed during review. Check the current choices again.")
    file_digest = digest(choices["file_text"]) if choices["mode"] == "file" else None
    choices["file_text"] = ""
    return {"kind": "import", "tenant": tenant, "owner": actor, "context": context, "choices": choices, "file_digest": file_digest, "raws": raws, "pin": pin, "policy": source_policy, "items": items, "expires": time.time() + TTL}


def _words(value):
    if type(value) is dict:
        return "\n".join(str(key).replace("_", " ") + ": " + _words(item) for key, item in value.items())
    if type(value) is list:
        return "\n".join(str(index + 1) + ". " + _words(item) for index, item in enumerate(value))
    if type(value) is bool:
        return "Yes" if value else "No"
    return "No value" if value is None else str(value)


def _visual_rows(graph, prefix, rows):
    names = {node["id"]: node.get("label") or "Step " + str(index + 1) for index, node in enumerate(graph["nodes"])}
    kinds = {"agent": "Follow these instructions with AI", "action": "Use a connected service", "approval": "Wait for human approval", "branch": "Choose a path", "foreach": "Repeat for each item", "while": "Repeat while the condition holds", "scope": "Keep these steps together", "parallel": "Run these groups", "setvar": "Prepare values", "noop": "Continue"}
    for node in graph["nodes"]:
        details = {"Work": kinds.get(node["kind"], "Review this supported step")}
        for key, value in node.items():
            if key in {"id", "kind", "label", "body", "branches"}:
                continue
            if key in {"next", "if_true", "if_false", "on_error"} and type(value) is str:
                details[{"next": "Following step", "if_true": "When the condition is met", "if_false": "When it is not met", "on_error": "If this step fails"}[key]] = names.get(value, "Continue in the reviewed group")
            elif type(value) is not dict or "nodes" not in value:
                details[key.replace("_", " ")] = value
        rows.append({"label": prefix + names[node["id"]], "after": _words(details)})
        for key in ("body", "if_true", "if_false"):
            if type(node.get(key)) is dict:
                _visual_rows(node[key], prefix + names[node["id"]] + " / ", rows)
        for index, child in enumerate(node.get("branches", [])):
            _visual_rows(child, prefix + names[node["id"]] + " / group " + str(index + 1) + " / ", rows)


def review_rows(value):
    rows = [{"label": "What happens", "after": NOTICE}, {"label": "Platform and source", "after": NAMES[value["choices"]["source"]] + (" / exported file" if value["pin"] is None else " / account " + value["pin"]["name"].replace("-", " ") + " / " + value["pin"]["origin"])},
            {"label": "Each future run's maximum spending", "after": "$" + str(value["choices"]["budget_dollars"])}, {"label": "Each future run's maximum time", "after": str(value["choices"]["budget_wall_seconds"]) + " seconds"}]
    if value["pin"] and value["choices"]["source"] == "make":
        rows.append({"label": "Make account collection", "after": value["choices"]["make_scope"].capitalize() + " " + str(value["choices"]["make_scope_id"])})
    for item in value["items"]:
        prefix = item["title"] + " / "
        rows.append({"label": prefix + "save choice", "after": "Create a new draft" if item["prior"] is None else "Replace your current draft" if item["name"] in value["choices"]["replace"] else "Keep the current draft unchanged"})
        if item["prior"]:
            rows.append({"label": prefix + "current instructions", "after": item["prior"]["body"]})
        trigger = {"schedule": "Scheduled work", "webhook": "A request from another service", "event": "A connected service event", "manual": "A person's request"}.get(item["trigger"]["kind"], "Source-platform start")
        if item["trigger"].get("cron"):
            trigger += " / " + _timing_pattern(item["trigger"]["cron"]) + " / timezone must be confirmed separately"
        rows.extend([{"label": prefix + "proposed instructions", "after": item["body"]}, {"label": prefix + "inputs", "after": "\n".join(item["params"]) or "No named input fields"}, {"label": prefix + "original start", "after": trigger + " / " + ("on in the source" if item["source_enabled"] else "off in the source") + " / left off in Lightwork"}])
        if item["graph"]:
            _visual_rows(item["graph"], prefix, rows)
            rows.extend({"label": prefix + "translation detail", "after": str(entry.get("step", "Step")) + ": " + str(entry.get("fidelity", "")) + " / " + str(entry.get("note", ""))} for entry in item["fidelity"])
    if len(rows) > 1000 or len(json.dumps(rows, ensure_ascii=False).encode("utf-8")) > 2_000_000:
        raise HTTPException(413, "The complete import review is too large to display safely. Choose a smaller export; no fields were hidden.")
    return rows


def _fresh(request, value, finished):
    authority(request, value["context"], write=True)
    if time.time() >= value["expires"] or policy() != value["policy"]:
        raise HTTPException(409, "This import review expired or its settings changed. Earlier saved work may remain; nothing will repeat automatically.")
    if value["pin"] is not None and _connection(request, value["choices"]) != value["pin"]:
        raise HTTPException(409, "The connected account changed or access was withdrawn. No further imported draft will be saved.")
    for item in value["items"]:
        expected = finished.get(item["name"], item["prior"])
        if _template(item["name"], value["owner"]) != expected:
            raise HTTPException(409, "A current workflow changed after review. Earlier saved work may remain; check the original import before another review.")
    if value["choices"]["as_flows"]:
        for item in value["items"]:
            current = flows.load_flow(item["name"])
            expected = finished.get("flow:" + item["name"])
            if (current.to_dict() if current else None) != expected:
                raise HTTPException(409, "A visual workflow changed after review. No further draft was saved.")


def original(request, identifier):
    row = owned(request, identifier)
    if row is None:
        return {"id": identifier, "confirmed": False, "items": [], "message": "No original admission is retained here. That does not prove whether work was saved elsewhere. Nothing was repeated."}
    value = opened(row)
    result = {"context": authority(request)[2], "id": identifier, "kind": row["kind"], "confirmed": row["state"] == "done" and not row.get("_audit_pending"), "items": [{key: item[key] for key in ("title", "template", "status", "flow") if key in item} for item in value.get("results", [])], "message": "Your original import is unconfirmed. Earlier saved items may remain. Nothing was repeated; a matching current workflow is not an original receipt."}
    if result["confirmed"]:
        result["message"] = "Your original reviewed drafts were saved. Nothing was repeated. Publish and activate separately when ready."
        if row["kind"] == "activate":
            result["message"] = "Your original schedule activation was accepted once. Future runs can spend the reviewed amount; no run was started again by reading this record."
            result["schedule"] = value["schedule"]
    if row["kind"] == "activate" and not result["confirmed"] and not row.get("_audit_pending"):
        from maverick.job_queue import JobQueue
        prepared = value["prepared"]
        job = JobQueue().admission_receipt("start_goal", prepared["payload"], idempotency_key=prepared["admission_key"])
        if job is not None:
            result.update(confirmed=True, schedule={"job_id": job, "title": prepared["payload"]["title"]}, message="The exact original future schedule was accepted once. Its final confirmation was interrupted; reading this native admission has not repeated it.")
    if row["kind"] == "import" and result["confirmed"]:
        result["activation_choices"] = [{"value": index, "label": item["title"], "params": item["params"], "source_timezone": item.get("source_timezone", "")} for index, item in enumerate(value["prepared"]["items"])
                                        if item["trigger"].get("cron") and value["results"][index]["status"] != "Kept unchanged"]
    authority(request, result["context"])
    return result


def apply(request, value, operation):
    identifier = "AIR-" + operation
    authority(request, value["context"], write=True)
    if re.fullmatch(r"[a-f0-9]{32}", operation) is None:
        raise HTTPException(422, "Review the import again.")
    with authority_effect_fence(), ExitStack() as stack:
        prior = owned(request, identifier)
        if prior:
            if prior["binding"] != digest(value):
                raise HTTPException(409, "This original import belongs to a different complete review.")
            return original(request, identifier)
        if value["pin"]:
            stack.enter_context(connections._mutation_lock())
        if value["choices"]["as_flows"]:
            stack.enter_context(flows._definitions_lock())
        for item in sorted(value["items"], key=lambda item: item["name"]):
            stack.enter_context(cross_process_lock(templates.user_templates_dir() / (item["name"] + ".md"), strict=True))
        finished, results = {}, []
        _fresh(request, value, finished)
        row = records().create({"id": identifier, "tenant": value["tenant"], "owner": value["owner"], "source": value["choices"]["source"], "kind": "import", "binding": digest(value), "state": "running", "payload": seal({"prepared": value, "results": results})}, action="import_admitted", actor=value["owner"], max_records=1000)
        if row.get("_audit_pending"):
            return original(request, identifier)
        def guard():
            _fresh(request, value, finished)
        try:
            importer = get_importer(value["choices"]["source"])
            for raw, item in zip(value["raws"], value["items"], strict=True):
                guard()
                if item["prior"] and item["name"] not in value["choices"]["replace"]:
                    results.append({"title": item["title"], "template": item["name"], "status": "Kept unchanged", "flow": ""})
                else:
                    materialize(importer.translate(raw), owner=value["owner"], queue=None, overwrite=bool(item["prior"]), expected_generation=item["prior"]["generation"] if item["prior"] else 0, effect_guard=guard,
                                budget_dollars=value["choices"]["budget_dollars"], budget_wall_seconds=value["choices"]["budget_wall_seconds"], complete=True)
                    finished[item["name"]] = _template(item["name"], value["owner"])
                    results.append({"title": item["title"], "template": item["name"], "status": "Instructions saved", "flow": "", "saved": finished[item["name"]]})
                    row = _progress(row, value, results)
                    if row.get("_audit_pending"):
                        return original(request, identifier)
                    if item["graph"]:
                        saved = flows.save_flow(flows.Flow.from_dict(item["graph"]), expected_version=0, effect_guard=guard)
                        finished["flow:" + item["name"]] = saved.to_dict()
                        results[-1]["flow"] = saved.id
                        results[-1]["status"] = "Instructions and visual draft saved"
                row = _progress(row, value, results)
                if row.get("_audit_pending"):
                    return original(request, identifier)
            def finish(current):
                guard()
                current.update(state="done", payload=seal({"prepared": value, "results": results}))
            records().update(identifier, finish, expected_revision=row["revision"], action="import_completed", actor=value["owner"])
        except Exception:
            # The durable original remains read-only and never resumes a partial import.
            return original(request, identifier)
        return original(request, identifier)


def _progress(row, value, results):
    return records().update(row["id"], lambda current: current.update(payload=seal({"prepared": value, "results": results})), expected_revision=row["revision"], action="import_item_saved", actor=value["owner"])


def _timing_pattern(expr):
    """Explain the scheduler's complete matching sets without exposing cron syntax."""
    import calendar

    from maverick.scheduler import parse_cron
    minute, hour, day, month, weekday = parse_cron(expr)
    def values(items, full, labels=None):
        if items == full:
            return "every"
        return ", ".join(labels[item] if labels else str(item) for item in sorted(items))
    clock = "At " + f"{next(iter(hour)):02d}:{next(iter(minute)):02d}" if len(hour) == len(minute) == 1 else "Hours " + values(hour, set(range(24))) + "; minutes " + values(minute, set(range(60)))
    days = values(day, set(range(1, 32)))
    weekdays = values(weekday, set(range(7)), ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"])
    if days != "every" and weekdays != "every":
        date = "days of the month " + days + " OR " + weekdays
    else:
        date = "days of the month " + days if days != "every" else weekdays + (" day" if weekdays == "every" else "")
    return clock + "; " + date + "; " + values(month, set(range(1, 13)), calendar.month_name) + " month"


def activation_material(request, body, *, require_unadmitted=False):
    from datetime import datetime
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    from maverick.job_queue import JobQueue
    from maverick.scheduler import next_run
    from maverick.template_connections import parameters
    body = Activation.model_validate(body).model_dump()
    tenant, actor, context = authority(request, body["context"], write=True)
    source_policy = policy()
    if not config.get_automation_import().get("create_schedules"):
        raise HTTPException(409, "Recreate imported schedules is off. An administrator can turn it on in All settings; "
                                 "the imported draft stays saved and can be scheduled in Automations.")
    if not config.get_features().get("scheduling") or not workflow_versions.enabled():
        raise HTTPException(409, "Scheduling and workflow version review must be on before activation. Publish the imported draft in Workflow builder first.")
    row = owned(request, body["original"])
    if row is None or row["kind"] != "import" or row["state"] != "done" or row.get("_audit_pending"):
        raise HTTPException(409, "Choose an original confirmed import. An interrupted import cannot silently activate future work.")
    retained = opened(row)
    if body["item"] >= len(retained["prepared"]["items"]):
        raise HTTPException(409, "Choose a saved automation from this original import.")
    item = retained["prepared"]["items"][body["item"]]
    result = retained["results"][body["item"]]
    if result["status"] == "Kept unchanged" or _template(item["name"], actor) != result.get("saved"):
        raise HTTPException(409, "This saved import changed. Review and activate the current workflow separately in Workflow builder or Automations.")
    cron = item["trigger"].get("cron")
    if not cron:
        raise HTTPException(409, "This source has no supported original schedule. Choose a schedule or start from another service in the ordinary Automations controls.")
    try:
        zone = ZoneInfo(body["timezone"])
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise HTTPException(422, "Choose an available timezone before reviewing this schedule. Unknown timezones never fall back silently.") from exc
    cursor, times = time.time(), []
    for _ in range(3):
        cursor = next_run(cron, after=cursor, tz=body["timezone"])
        times.append(datetime.fromtimestamp(cursor, tz=zone).strftime("%A, %d %B %Y at %H:%M %Z (%z)"))
    template, version = workflow_versions.execution_template(item["name"])
    if template.body != item["body"] or template.title != item["title"]:
        raise HTTPException(409, "Publish this exact reviewed imported draft in Workflow builder before activating its original schedule.")
    if len(json.dumps(body["params"], ensure_ascii=False)) > 32000 or set(body["params"]) != set(template.params):
        raise HTTPException(422, "Fill every named input shown for this imported schedule, without extra fields.")
    _, refs = parameters(template, actor, body["params"])
    title, text = template.render_for(actor, **body["params"])
    payload = {"text": text, "title": title[:200], "__cron__": cron, "__tz__": body["timezone"], "owner": actor, "tenant": tenant, "template_name": template.name, "template_generation": template.generation, "template_version": version, "connection_references": refs,
               "max_dollars": template.budget_dollars, "max_wall_seconds": template.budget_wall_seconds}
    allowed = auth.caller_suites(request)
    if allowed is not None:
        payload["allowed_suites"] = sorted(allowed)
    user = auth.execution_user_id_from_request(request)
    if user:
        payload.update(channel="api", user_id=user)
    admission = "import-activation:" + digest([tenant, actor, row["id"], row["binding"], body["item"], version])
    payload["schedule_id"] = digest(admission)[:32]
    if require_unadmitted and JobQueue().admission_receipt("start_goal", payload, idempotency_key=admission) is not None:
        raise HTTPException(409, "This exact imported schedule already has an original admission. Read its activation in Original import history; it was not activated again.")
    authority(request, context, write=True)
    return {"kind": "activate", "tenant": tenant, "owner": actor, "context": context, "body": body, "source": row["source"], "original_revision": row["revision"], "original_binding": row["binding"], "policy": source_policy, "template": result["saved"], "payload": payload, "timing": _timing_pattern(cron), "next_occurrences": times, "admission_key": admission, "expires": time.time() + TTL}


def activation_rows(value):
    return [{"label": "Future work", "after": "Activate one recurring schedule for the exact published imported instructions. Future AI and connected work may spend money or change other services; reading the original result never starts another run."},
            {"label": "Published instructions", "after": value["payload"]["text"]}, {"label": "Named inputs", "after": _words(value["body"]["params"]) or "No named inputs"},
            {"label": "Reviewed timing", "after": value["timing"] + "\nTimezone: " + value["body"]["timezone"] + "\nNext scheduled starts:\n" + "\n".join(value["next_occurrences"]) + "\nConfirm this is your intended timing. The original platform's full timing behavior is not guaranteed; clock changes can skip or repeat local times."}, {"label": "Maximum spending for each future run", "after": "$" + str(value["template"]["budget_dollars"])},
            {"label": "Maximum time for each future run", "after": str(value["template"]["budget_wall_seconds"]) + " seconds"}, {"label": "Interruption", "after": "This activation is admitted at most once. If its reply is lost, read the original receipt; an unconfirmed request is never submitted again automatically."}]


def activate(request, value, operation):
    from maverick.job_queue import JobQueue
    from maverick.scheduler import next_run
    identifier = "AIR-" + operation
    authority(request, value["context"], write=True)
    with authority_effect_fence(), cross_process_lock(templates.user_templates_dir() / (value["payload"]["template_name"] + ".md"), strict=True):
        prior = owned(request, identifier)
        if prior:
            if prior["binding"] != digest(value):
                raise HTTPException(409, "This original activation belongs to another review.")
            return original(request, identifier)
        def guard():
            if time.time() >= value["expires"]:
                raise HTTPException(409, "The schedule review expired. No future schedule was activated.")
            checked = activation_material(request, value["body"])
            checked["expires"] = value["expires"]
            if checked != value:
                raise HTTPException(409, "The original import, published instructions, account or settings changed. No future schedule was activated.")
        guard()
        if JobQueue().admission_receipt("start_goal", value["payload"], idempotency_key=value["admission_key"]) is not None:
            raise HTTPException(409, "This imported schedule was already activated by another reviewed request. Read that original activation; nothing was repeated.")
        row = records().create({"id": identifier, "tenant": value["tenant"], "owner": value["owner"], "source": value["source"], "kind": "activate", "binding": digest(value), "state": "running", "payload": seal({"prepared": value, "results": []})}, action="import_activation_admitted", actor=value["owner"], max_records=1000)
        if row.get("_audit_pending"):
            return original(request, identifier)
        payload = value["payload"]
        run_at = next_run(payload["__cron__"], tz=payload["__tz__"])
        queue = JobQueue()
        try:
            job = queue.enqueue_once("start_goal", payload, idempotency_key=value["admission_key"], run_at=run_at, effect_guard=guard)
            def finish(current):
                current.update(state="done", payload=seal({"prepared": value, "results": [], "schedule": {"job_id": job, "title": payload["title"], "run_at": run_at}}))
            records().update(identifier, finish, expected_revision=row["revision"], action="import_schedule_activated", actor=value["owner"])
        except Exception:
            return original(request, identifier)
        return original(request, identifier)


def native_call(function):
    try:
        return function()
    except HTTPException:
        raise
    except (ValueError, PermissionError, RecordConflict) as exc:
        raise HTTPException(409, "The current import, account or saved workflow could not be verified. Read the original record before reviewing another import.") from exc
    except Exception as exc:
        raise HTTPException(503, "Import information is unavailable. Entered work was kept; read the original record if a save was submitted. Nothing repeats automatically.") from exc
