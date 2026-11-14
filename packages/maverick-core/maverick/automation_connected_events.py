"""Named, read-only app event sources using exact saved-account authority."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import quote, urlencode, urlsplit

from . import automation_events as events
from . import connections

SOURCES = {
    "sharepoint_files": {"label": "New SharePoint files", "connector": "msgraph"},
    "salesforce_records": {"label": "New Salesforce records or newly closed opportunities", "connector": "salesforce"},
    "servicenow_tickets": {"label": "New ServiceNow tickets", "connector": "servicenow"},
    "teams_messages": {"label": "New Teams channel messages", "connector": "msgraph"},
}
OBJECTS = {"Opportunity": "Opportunities", "Lead": "Leads", "Contact": "Contacts", "Case": "Cases"}
TABLES = {"incident": "Incidents", "change_request": "Change requests", "sc_req_item": "Requested items"}
MAX_ITEMS = 5000
MAX_PAGES = 32
MAX_SEEN = 20000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.!,:@-]{0,255}")


def identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise events.EventSourceError("Select a named item from the connected system.")
    return value


def selection(source, value):
    if source not in SOURCES or not isinstance(value, dict):
        raise events.EventSourceError("Choose a supported connected-system event.")
    keys = {"sharepoint_files": {"site", "drive", "folder"}, "teams_messages": {"team", "channel"},
            "salesforce_records": {"object", "closed_only"}, "servicenow_tickets": {"table"}}[source]
    if set(value) != keys:
        raise events.EventSourceError("Choose every source detail using the current form.")
    if source == "salesforce_records":
        if value["object"] not in OBJECTS or type(value["closed_only"]) is not bool or (value["closed_only"] and value["object"] != "Opportunity"):
            raise events.EventSourceError("Closed-opportunity events require the Opportunities choice.")
    elif source == "servicenow_tickets":
        if value["table"] not in TABLES:
            raise events.EventSourceError("Choose a supported ServiceNow ticket type.")
    else:
        for item in value.values():
            identifier(item)
    return dict(value)


def origin(source, value):
    parsed = urlsplit(str(value))
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.port not in (None, 443)):
        raise events.EventSourceError("Reconnect this account with its secure service address.")
    host = parsed.hostname.lower()
    allowed = (host == "graph.microsoft.com" if source in {"sharepoint_files", "teams_messages"}
               else host.endswith((".salesforce.com", ".force.com")) if source == "salesforce_records"
               else host.endswith(".service-now.com"))
    if not allowed:
        raise events.EventSourceError("This saved account has a different service destination. Reconnect it in Connections.")
    return "https://" + host


def validate(source, config):
    if source not in SOURCES or not isinstance(config, dict):
        raise events.EventSourceError("Connected-system source settings are unavailable.")
    required = {"connection", "revision", "connector", "origin", "selection"}
    if set(config) - {"_lightwork_cursor_format", "_lightwork_authority_check", "baseline"} != required:
        raise events.EventSourceError("Use the reviewed connected-system source form; custom URLs and credentials are not accepted.")
    if config["connector"] != SOURCES[source]["connector"] or not isinstance(config["revision"], str) or not config["revision"]:
        raise events.EventSourceError("The saved account binding is unavailable. Review the source again.")
    if not isinstance(config["connection"], str) or connections.normalize_name(config["connection"]) != config["connection"]:
        raise events.EventSourceError("Choose a saved connection.")
    selected = selection(source, config["selection"])
    base = origin(source, config["origin"])
    if "baseline" in config:
        baseline = config["baseline"]
        if not isinstance(baseline, str) or len(baseline) > 400000:
            raise events.EventSourceError("The dated source baseline is unavailable. Review this source again.")
        ids = events._decode_cursor(baseline, "connected_app", 1)
        if not isinstance(ids, list) or len(ids) > MAX_ITEMS or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in ids):
            raise events.EventSourceError("The dated source baseline is unavailable. Review this source again.")
    return {**config, "origin": base, "selection": selected}


def read_json(source, config, path):
    """Resolve current permission and credentials at each physical HTTP read."""
    cfg = validate(source, config)
    check = cfg.get("_lightwork_authority_check")
    if callable(check):
        check()
    from .authority_effects import authority_effect_fence
    with authority_effect_fence(), connections._mutation_lock():
        if callable(check):
            check()
        try:
            account = connections.resolve_named(cfg["connection"], expected_revision=cfg["revision"], connector=cfg["connector"], origin=cfg["origin"])
        except (PermissionError, ValueError, connections.ConnectionVersionConflict) as exc:
            raise events.EventSourceError("This saved account or its permission changed. Review the connection before checking again.") from exc
        url = events._same_origin_url(cfg["origin"], path)
        return events._http_get_json(url, headers={"Authorization": "Bearer " + str(account["token"]), "Accept": "application/json"})


def collection(source, config, path, *, key="value", paginated=True):
    items, current, visited = [], path, set()
    for _ in range(MAX_PAGES):
        if current in visited:
            raise events.EventSourceError("The connected system repeated a result page. No event position was advanced.")
        visited.add(current)
        body = read_json(source, config, current)
        page = body.get(key) if isinstance(body, dict) else None
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            raise events.EventSourceError("The connected system did not return a complete readable item list.")
        items.extend(page)
        if len(items) > MAX_ITEMS:
            raise events.EventSourceError("This source contains more than 5,000 items. Choose a smaller folder or channel; no event position was advanced.")
        if not paginated:
            return items
        following = body.get("@odata.nextLink") or body.get("nextRecordsUrl")
        if not following:
            return items
        current = events._same_origin_url(config["origin"], str(following))
    raise events.EventSourceError("The source exceeds 32 result pages. Choose a smaller source; no event position was advanced.")


def read_items(source, config):
    cfg = validate(source, config)
    selected = cfg["selection"]
    def esc(value):
        return quote(identifier(value), safe="")
    if source == "sharepoint_files":
        folder = "root" if selected["folder"] == "root" else "items/" + esc(selected["folder"])
        rows = collection(source, cfg, "/v1.0/drives/" + esc(selected["drive"]) + "/" + folder + "/children?$top=200")
        return [row for row in rows if row.get("file") is not None and not row.get("deleted")], "id", "createdDateTime"
    if source == "teams_messages":
        rows = collection(source, cfg, "/v1.0/teams/" + esc(selected["team"]) + "/channels/" + esc(selected["channel"]) + "/messages?$top=50")
        return [row for row in rows if not row.get("deletedDateTime") and not row.get("replyToId")], "id", "createdDateTime"
    if source == "salesforce_records":
        obj = selected["object"]
        fields = "Id,Name,CreatedDate" if obj != "Case" else "Id,CaseNumber,Subject,CreatedDate"
        if obj == "Opportunity":
            fields += ",IsClosed,StageName,LastModifiedDate"
        query = "SELECT " + fields + " FROM " + obj + (" WHERE IsClosed = true" if selected["closed_only"] else "") + " ORDER BY CreatedDate DESC,Id DESC"
        return collection(source, cfg, "/services/data/v61.0/query?" + urlencode({"q": query}), key="records"), "Id", "CreatedDate"
    rows = []
    for offset in range(0, MAX_ITEMS + 1, 1000):
        page = collection(source, cfg, "/api/now/table/" + selected["table"] + "?" + urlencode({"sysparm_query": "ORDERBYDESCsys_created_on^ORDERBYDESCsys_id", "sysparm_fields": "sys_id,number,short_description,sys_created_on,state", "sysparm_limit": 1000, "sysparm_offset": offset}), key="result", paginated=False)
        rows.extend(page)
        if len(rows) > MAX_ITEMS:
            raise events.EventSourceError("This ticket source exceeds 5,000 items. No event position was advanced.")
        if len(page) < 1000:
            return rows, "sys_id", "sys_created_on"
    raise events.EventSourceError("This ticket source exceeds its supported bound. No event position was advanced.")


class ConnectedAppSource:
    def __init__(self, source):
        self.source = source

    def poll(self, config, cursor):
        items, id_field, date_field = read_items(self.source, config)
        ids = [str(row.get(id_field) or "") for row in items]
        if any(not item or len(item) > 512 for item in ids) or len(set(ids)) != len(ids):
            raise events.EventSourceError("The source returned duplicate or missing identities. No event position was advanced.")
        hashed = {hashlib.sha256(item.encode()).hexdigest() for item in ids}
        preview_baseline = not cursor and bool(config.get("baseline"))
        cursor = cursor or config.get("baseline", "")
        if not cursor:
            return events.PollResult(cursor=events._encode_cursor("connected_app", sorted(hashed)))
        if not isinstance(cursor, str) or len(cursor) > 1400000:
            raise events.EventSourceError("The source position is unavailable. No events were repeated.")
        prior = events._decode_cursor(cursor, "connected_app", 1 if preview_baseline else config.get("_lightwork_cursor_format"))
        if not isinstance(prior, list) or len(prior) > MAX_SEEN or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in prior):
            raise events.EventSourceError("The source position is unavailable. No events were repeated.")
        seen = set(prior)
        fresh = [row for row in items if hashlib.sha256(str(row[id_field]).encode()).hexdigest() not in seen]
        fresh.sort(key=lambda row: (str(row.get(date_field) or ""), str(row[id_field])))
        fresh = fresh[:events._MAX_EVENTS]
        seen.update(hashlib.sha256(str(row[id_field]).encode()).hexdigest() for row in fresh)
        if len(seen) > MAX_SEEN:
            raise events.EventSourceError("This source's retained identity limit was reached. Review a replacement source; no event position was advanced.")
        return events.PollResult(events=[events._flatten(row) for row in fresh], event_ids=[str(row[id_field]) for row in fresh], cursor=events._encode_cursor("connected_app", sorted(seen)))


def register_sources():
    for name in SOURCES:
        events.register(name, lambda name=name: ConnectedAppSource(name))
