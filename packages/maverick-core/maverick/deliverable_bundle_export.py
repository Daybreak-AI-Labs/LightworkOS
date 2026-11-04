"""Portable selected-file ZIPs with safe rendering and offline integrity checks."""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import re
import zipfile

from .deliverable_bundles import decoded_items

_STYLE = "body{font:17px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:1rem;line-height:1.5}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse;display:block;overflow:auto}th,td{border:1px solid;padding:.5rem}section{margin-block:2rem}"


def _table(text):
    """Convert a complete pipe-table artifact; never silently truncate a source."""
    from .deliverable import _is_separator, _split_row

    lines = text.strip().splitlines()
    if len(lines) < 2 or "|" not in lines[0] or not _is_separator(_split_row(lines[1])):
        return None
    rows = [_split_row(line) for line in [lines[0], *lines[2:]]]
    width = len(rows[0])
    if width > 100 or len(rows) > 2000 or any(len(row) != width for row in rows):
        return None
    return rows


def _safe_cell(value):
    # Spreadsheet applications must not execute a selected artifact's formula.
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def _render_text(text, rows=None):
    if rows:
        return "<table><thead><tr>" + "".join("<th>" + html.escape(cell) + "</th>" for cell in rows[0]) + \
            "</tr></thead><tbody>" + "".join("<tr>" + "".join("<td>" + html.escape(cell) + "</td>" for cell in row) + "</tr>" for row in rows[1:]) + "</tbody></table>"
    paragraphs = text.split("\n\n")
    return "".join("<p>" + html.escape(paragraph).replace("\n", "<br>") + "</p>" for paragraph in paragraphs)


def files_for(record):
    files, sections, file_entries = {}, [], []
    for index, (item, content) in enumerate(decoded_items(record), 1):
        extension = ".md" if item["kind"] != "evidence" else ".bin"
        if item["kind"] == "evidence":
            suffix = item["title"].rsplit(".", 1)[-1].lower()
            if suffix in {"pdf", "docx", "xlsx", "pptx", "txt", "csv", "png", "jpg", "jpeg", "webp"}:
                extension = "." + suffix
        stem = re.sub(r"[^A-Za-z0-9_-]+", "-", item["title"]).strip("-")[:50] or "selected-item"
        filename = f"{index:02d}-{stem}{extension}"
        files[filename] = content
        section = "<section><h2>" + html.escape(item["title"]) + "</h2>"
        section += '<p><a download href="' + filename + '">Download selected original</a></p>'
        if item["kind"] != "evidence":
            text = content.decode("utf-8")
            table = _table(text) if item["source"].get("kind") == "table" else None
            section += _render_text(text, table)
            if table:
                output = io.StringIO(newline="")
                csv.writer(output).writerows([[_safe_cell(cell) for cell in row] for row in table])
                csv_name = filename.removesuffix(".md") + ".csv"
                files[csv_name] = output.getvalue().encode("utf-8-sig")
                section += '<p><a download href="' + csv_name + '">Editable spreadsheet CSV</a>. Formula-like cells are escaped; the original remains in Markdown.</p>'
        else:
            section += "<p>Evidence file; open it in its native application after verification. Its factual accuracy has not been established by the checksum check.</p>"
        sections.append(section + "</section>")
        file_entries.append({"key": item["key"], "filename": filename, "title": item["title"], "source": item["source"]})
    payload = record["payload"]
    review = {"bundle": payload["name"], "recipient_job": payload["note"], "unresolved_items": payload["unresolved"],
              "source_warnings": payload.get("source_warnings", []),
              "source_version": payload["source_version"], "stale_at_export": record["stale"],
              "human_acceptance": record["acceptance"], "acceptance_current_at_export": record["acceptance_current"],
              "owner": record["owner"], "recipient": payload["recipient"], "expires_at": record["expires_at"],
              "scope": "Selected files only; no conversation, tools, credentials or task execution authority.",
              "external_submission": "Not performed", "selected_sources": file_entries}
    files["review.json"] = json.dumps(review, indent=2, ensure_ascii=False).encode("utf-8")
    manifest = {"schema": "lightwork.deliverable-bundle-manifest.v1", "algorithm": "SHA-256",
                "assurance": "Integrity against this manifest only; not authenticity, factual verification, current permission or human approval.",
                "files": [{"name": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                          for name, content in files.items()]}
    files["manifest.json"] = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    acceptance = "Accepted by the named human recipient" if record["acceptance_current"] else "No current human acceptance"
    introduction = "<h1>" + html.escape(payload["name"]) + "</h1><p>" + html.escape(payload["note"]) + "</p>"
    introduction += "<p>" + acceptance + ". Source state at export: " + ("stale" if record["stale"] else "unchanged") + ". Nothing was filed or submitted externally.</p>"
    introduction += "<h2>Unresolved items</h2><p>" + html.escape(payload["unresolved"] or "None declared by the author; this is not an independent completeness finding.") + "</p>"
    introduction += "".join("<p>" + html.escape(warning) + "</p>" for warning in payload.get("source_warnings", []))
    introduction += '<p><a href="verify.html">Verify extracted files offline</a> before opening them. Review <a download href="review.json">the review record</a> and <a download href="manifest.json">the portable manifest</a>. Revoking access cannot erase exported copies. Acceptance and source freshness are recorded as of export, not checked live.</p>'
    files["index.html"] = _document(payload["name"], introduction + "".join(sections)).encode("utf-8")
    files["verify.html"] = _verifier(manifest).encode("utf-8")
    return files


def _document(title, body):
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; script-src \'unsafe-inline\'; connect-src \'none\'"><title>' + html.escape(title) + "</title><style>" + _STYLE + "</style><body>" + body + "</body></html>"


def _verifier(manifest):
    encoded = json.dumps(manifest, ensure_ascii=True).replace("<", "\\u003c")
    body = '<h1>Verify this bundle offline</h1><p>Extract the ZIP, then choose all extracted content files, including review.json. Nothing is uploaded. This compares bytes with the captured manifest; it does not authenticate the author or establish human approval. The manifest, index and verifier are not themselves signed.</p><label for="files">Extracted files</label><input id="files" type="file" multiple><button id="verify" type="button">Check selected files</button><p id="status" role="status" aria-live="polite"></p><ul id="results"></ul><p><a href="index.html">Open bundle contents</a></p>'
    script = """<script>
const manifest=MANIFEST;
document.getElementById('verify').onclick=async()=>{
 const status=document.getElementById('status'), list=document.getElementById('results');list.replaceChildren();
 if(!globalThis.crypto?.subtle){status.textContent='This browser cannot verify local files. Open verify.html in a browser that supports local Web Crypto.';return;}
 const supplied=Array.from(document.getElementById('files').files), results=[];
 for(const expected of manifest.files){const matching=supplied.filter(f=>f.name===expected.name);let valid=false;
  if(matching.length===1&&matching[0].size===expected.bytes){const bytes=await matching[0].arrayBuffer();const hash=await crypto.subtle.digest('SHA-256',bytes);valid=Array.from(new Uint8Array(hash),x=>x.toString(16).padStart(2,'0')).join('')===expected.sha256;}
  const row=document.createElement('li');row.textContent=expected.name+': '+(valid?'Matches captured bytes':'Missing, duplicated or changed');list.append(row);results.push(valid);}
 status.textContent=results.every(Boolean)?'All manifest content files match. This does not establish source authenticity or approval.':'Verification incomplete. Do not treat missing or changed files as the captured bundle.';
};</script>""".replace("MANIFEST", encoded)
    return _document("Offline bundle verification", body + script)


def export_zip(record):
    files = files_for(record)
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    target.seek(0)
    # Round-trip every entry before exposing a completed export. No previous
    # bundle is replaced when rendering, compression or verification fails.
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != set(files):
            raise ValueError("The export could not be verified. Your saved bundle is unchanged.")
        for name, content in files.items():
            if hashlib.sha256(archive.read(name)).digest() != hashlib.sha256(content).digest():
                raise ValueError("The export content changed during packaging.")
    return target.getvalue()


def rendered_preview(record):
    """Online safe preview with working, separately authorized download links."""
    files = files_for(record)
    document = files["index.html"].decode("utf-8")
    sources = json.loads(files["review.json"])["selected_sources"]
    base = "/api/v1/deliverable-bundles/" + record["id"]
    mapping = {row["filename"]: base + "/files/" + row["key"] for row in sources}
    # Supplementary CSV/review/manifest/verifier are delivered together in the
    # verified ZIP, rather than linking to nonexistent relative HTTP routes.
    for name in files:
        destination = mapping.get(name, base + "/export")
        document = document.replace('href="' + name + '"', 'href="' + html.escape(destination, quote=True) + '"')
    return document.encode("utf-8")
