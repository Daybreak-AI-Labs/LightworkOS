"""Fixed, read-only capability probes with exact resource receipt binding.

There is no arbitrary method/path escape hatch. No probe writes a business
record, qualifies a write capability, or automatically resumes blocked work.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from urllib.parse import quote, urlsplit

from . import connection_oauth, connections

MANIFEST = {
    "drive_file_metadata": {"connector": "gdrive", "label": "Read a Google Drive file's metadata",
        "resource_label": "File identifier", "pattern": r"[A-Za-z0-9_-]{1,200}",
        "minimum_scope": "drive.metadata.readonly (drive.readonly also admits this read)",
        "host": "www.googleapis.com", "path": "/drive/v3/files/{resource}?fields=id&supportsAllDrives=true", "identity_field": "id"},
    "storage_bucket_metadata": {"connector": "google_cloud_storage", "label": "Read Google Cloud Storage bucket metadata",
        "resource_label": "Bucket name", "pattern": r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]",
        "minimum_scope": "devstorage.read_only plus storage.buckets.get on the selected bucket",
        "host": "storage.googleapis.com", "path": "/storage/v1/b/{resource}?fields=name", "identity_field": "name"},
    "jira_issue_metadata": {"connector": "jira", "label": "Read a Jira issue's metadata",
        "resource_label": "Issue key", "pattern": r"[A-Z][A-Z0-9_]{0,30}-[0-9]{1,15}",
        "minimum_scope": "read:jira-work plus permission to browse the selected issue",
        "host": "atlassian", "path": "/rest/api/3/issue/{resource}?fields=summary", "identity_field": "key"},
    "github_repository_metadata": {"connector": "github", "label": "Read GitHub repository metadata",
        "resource_label": "Organization or owner / repository", "pattern": r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}",
        "minimum_scope": "Repository metadata read access; no repository write permission is required",
        "host": "api.github.com", "path": "/repos/{resource}", "identity_field": "full_name"},
}


def choices(connector):
    return [{"id": key, **{k: v for k, v in value.items() if k not in {"path", "pattern", "identity_field"}},
             "method": "GET", "external_writes": False, "write_access_tested": False}
            for key, value in MANIFEST.items() if value["connector"] == connector]


def probe(name, capability, resource, *, actor, expected_revision, authorize):
    """Make one bounded public-origin GET and persist only a scoped receipt."""
    from .tools import _ssrf
    from .tools.enterprise_connectors import auth_headers_for

    authorize()
    if not connections.enabled():
        raise PermissionError("Connections are disabled in Settings.")
    # The receipt write looks the record up by its stored (normalised) name.
    name = connections.normalize_name(name)
    record = connections.get_connection(name)
    selected = MANIFEST.get(capability)
    if (not record or (record.get("owner") or None) != actor or not selected
            or selected["connector"] != record.get("connector")):
        raise PermissionError("Choose a capability declared for your own connection.")
    if record["revision"] != expected_revision:
        raise connections.ConnectionVersionConflict("The connection changed. Review its current version.")
    if re.fullmatch(selected["pattern"], resource) is None:
        raise ValueError("Enter a valid " + selected["resource_label"].lower() + ".")
    if record.get("oauth"):
        record = connection_oauth.renew(record, actor=actor)
    prefix = (record.get("oauth") or {}).get("api_prefix", "")
    path = selected["path"].format(resource=quote(resource, safe="/" if capability == "github_repository_metadata" else ""))
    url = record["base_url"].rstrip("/") + prefix + path
    address = urlsplit(url)
    host = address.hostname or ""
    if (address.scheme != "https" or address.port not in (None, 443) or address.username or address.password or address.fragment
            or (host != selected["host"] and not (selected["host"] == "atlassian"
                and (host == "api.atlassian.com" or host.endswith(".atlassian.net"))))):
        raise ValueError("This capability check supports only the declared provider's public HTTPS service. Review a custom service through its dedicated setup.")
    headers = ({"Authorization": "Bearer " + record["token"]} if record.get("oauth") else
               auth_headers_for(record["connector"], record["token"], include_extra_headers_env=False))
    verified, status, outcome = False, None, "unavailable"
    try:
        started = time.monotonic()
        with _ssrf.safe_client(url, timeout=10.0) as client:
            with client.stream("GET", url, headers=headers, follow_redirects=False) as response:
                status = response.status_code
                if 200 <= status < 300:
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 65536 or time.monotonic() - started > 10:
                            raise ValueError("Capability response exceeded its bounded read.")
                    data = json.loads(raw)
                    verified = isinstance(data, dict) and str(data.get(selected["identity_field"], "")).lower() == resource.lower()
                    outcome = "verified_resource_read" if verified else "response_not_verified"
                else:
                    outcome = "permission_or_resource_unavailable" if status in {401, 403, 404} else "service_unavailable"
    except _ssrf.BlockedHost:
        outcome = "blocked_by_policy"
    except Exception:
        outcome = "unavailable"
    receipt = {"capability": capability, "label": selected["label"],
               "resource_sha256": hashlib.sha256(resource.encode()).hexdigest(),
               "revision": expected_revision, "tested_at": time.time(), "verified": verified,
               "outcome": outcome, "status": status, "external_writes": False,
               "write_access_verified": False, "historical_actions_replayed": False}
    with connections._mutation_lock():
        authorize()
        records = connections._load()
        current = records.get(name)
        if (not connections.enabled() or not current or current.get("revision") != expected_revision
                or (current.get("owner") or None) != actor):
            raise connections.ConnectionVersionConflict("Connection authority changed during the check. Review again.")
        current["capability_receipts"] = (list(current.get("capability_receipts", [])) + [receipt])[-100:]
        connections._save(records)
    return receipt
