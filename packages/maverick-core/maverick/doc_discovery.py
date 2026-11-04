"""Document discovery for assessments: find the SOW/contract/DPA for them.

When someone is answering assessment questions, the documents that answer
half of them -- the statement of work, the contract, the DPA, the security
overview -- usually already exist in the company's own systems. This module
searches the CONNECTED sources (Microsoft Graph / SharePoint+OneDrive, Slack
files, Google Drive) for documents related to the assessment subject and lets
the caller pull one down and attach it as evidence, instead of making the
respondent go hunt for files.

Credentials resolve per source from a named :mod:`maverick.connections` record
or, for local/standard operator execution, the legacy environment variables:

  ==========  =========================  ==================  ============
  source      env token                  env base override   connection
  ==========  =========================  ==================  ============
  msgraph     MSGRAPH_ACCESS_TOKEN       MSGRAPH_BASE_URL    ``msgraph``
  slack       SLACK_SEARCH_TOKEN /       SLACK_BASE_URL      ``slack``
              SLACK_BOT_TOKEN
  gdrive      GDRIVE_ACCESS_TOKEN        GDRIVE_BASE_URL     ``gdrive``
  ==========  =========================  ==================  ============

The base-URL override is what makes this testable and demoable against a
simulated tenant while keeping ONE real code path. Everything is fail-open:
a source that isn't configured is skipped, a source that errors contributes
nothing (logged), and discovery never raises. Fetched bytes are capped at the
attachment limit so discovery can't smuggle in what a direct upload couldn't.
Gated by ``[assessments] doc_discovery`` (default on -- it only activates when
a source is actually configured).

Authenticated enterprise calls are different: they may use only a saved
connection that admits the bound caller principal and never borrow ambient
process credentials. Every outbound hop is held to the enterprise egress
policy and an SSRF-safe, DNS-pinned transport; redirects are revalidated and
credentials are dropped on a cross-origin redirect. Client-supplied ids/refs
are additionally hardened at the path layer.
"""
from __future__ import annotations

import logging
import os
import urllib.parse
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# The document kinds worth proactively finding for an assessment. Matched
# against filenames for ranking; folded into search queries.
DOC_KEYWORDS = (
    "sow", "statement of work", "contract", "msa", "dpa",
    "data processing", "security", "questionnaire", "privacy",
    "architecture", "agreement",
)

_TIMEOUT = 15.0


@dataclass
class DocHit:
    source: str
    doc_id: str
    name: str
    url: str = ""          # human-facing web link
    snippet: str = ""
    mime: str = ""
    size: int = 0
    score: float = 0.0
    # opaque fetch details a source needs to download content (e.g. msgraph
    # drive id, slack private download url). Round-tripped by the caller.
    ref: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"source": self.source, "doc_id": self.doc_id, "name": self.name,
                "url": self.url, "snippet": self.snippet, "mime": self.mime,
                "size": self.size, "score": round(self.score, 3),
                "ref": self.ref}


def enabled() -> bool:
    try:
        from .config import get_assessments
        return bool(get_assessments()["doc_discovery"])
    except Exception:  # pragma: no cover -- config never crashes a read
        return True


# --------------------------------------------------------------------------- #
# Credential resolution (env first, then a sealed named connection).
# --------------------------------------------------------------------------- #

_ENV_TOKENS = {
    "msgraph": ("MSGRAPH_ACCESS_TOKEN",),
    "slack": ("SLACK_SEARCH_TOKEN", "SLACK_BOT_TOKEN"),
    "gdrive": ("GDRIVE_ACCESS_TOKEN",),
}
_ENV_BASES = {
    "msgraph": "MSGRAPH_BASE_URL",
    "slack": "SLACK_BASE_URL",
    "gdrive": "GDRIVE_BASE_URL",
}
_DEFAULT_BASES = {
    "msgraph": "https://graph.microsoft.com/v1.0",
    "slack": "https://slack.com/api",
    "gdrive": "https://www.googleapis.com",
}


def _bound_principal(principal: str | None = None) -> str | None:
    """Return an explicit or dispatch-bound credential-use principal."""
    explicit = str(principal or "")
    if explicit:
        return explicit
    try:
        from . import connections

        return connections.current_principal()
    except Exception:  # pragma: no cover - optional connections layer
        return None


def _requires_scoped_connection(principal: str | None) -> bool:
    """Whether ambient process credentials are forbidden for this call."""
    # Authentication itself is the authority boundary. Configuration/profile
    # parsing must never decide whether an authenticated caller may borrow an
    # operator-global environment credential: only genuine local auth-off calls
    # (principal=None) retain that legacy behavior.
    return bool(principal)


def _creds(
    source: str,
    *,
    principal: str | None = None,
    allow_ambient_credentials: bool = False,
) -> tuple[str, str] | None:
    """Return an authorized ``(base_url, token)`` or ``None``.

    Standard/local execution retains the historical env-first precedence.
    Authenticated enterprise execution must use a saved connection whose use
    grant admits the bound principal; neither its token nor base URL may come
    from ambient process state.
    """
    caller = _bound_principal(principal)
    if caller is None and not allow_ambient_credentials:
        return None
    conn = None
    try:
        from . import connections

        conn = connections.resolve(source, principal=caller)
    except Exception:  # pragma: no cover - an unreadable store is unconfigured
        conn = None

    if _requires_scoped_connection(caller):
        if not conn or not str(conn[1]).strip():
            return None
        base = str(conn[0]).strip().rstrip("/") or _DEFAULT_BASES.get(source, "")
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return None
        return (base, str(conn[1]).strip())

    token = ""
    for var in _ENV_TOKENS.get(source, ()):
        token = os.environ.get(var, "").strip()
        if token:
            break
    base = os.environ.get(_ENV_BASES.get(source, ""), "").strip()
    if not token and conn:
        base = base or conn[0]
        token = conn[1]
    if not token:
        return None
    default = _DEFAULT_BASES.get(source, "")
    resolved_base = (base or default).rstrip("/")
    return (resolved_base, token) if resolved_base else None


def get_assessments_sources() -> list[str]:
    """The operator's ordered source allowlist ([assessments] sources)."""
    from .config import get_assessments
    return get_assessments()["sources"]


def configured_sources(
    *,
    principal: str | None = None,
    allow_ambient_credentials: bool = False,
) -> list[str]:
    """Sources that currently have credentials, in stable order."""
    return [
        s for s in get_assessments_sources()
        if _creds(
            s,
            principal=principal,
            allow_ambient_credentials=allow_ambient_credentials,
        ) is not None
    ]


def _guarded_client(url: str, **kwargs):
    """Return a policy-checked, DNS-pinned client for one exact URL."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("document source URL credentials are not permitted")
    from .enterprise import enterprise_egress_denial

    if enterprise_egress_denial(url, tool="doc_discovery"):
        raise PermissionError("document source egress is not permitted")
    from .tools._ssrf import safe_client

    return safe_client(url, **kwargs)


def _get(url: str, token: str, params: dict | None = None,
         *, auth: str = "bearer") -> tuple[int, object]:
    headers = {"Authorization": f"Bearer {token}"} if auth == "bearer" else {}
    with _guarded_client(url, timeout=_TIMEOUT) as client:
        r = client.get(url, headers=headers, params=params or {})
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(url: str, token: str, body: dict) -> tuple[int, object]:
    with _guarded_client(url, timeout=_TIMEOUT) as client:
        r = client.post(
            url,
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            json=body,
        )
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _download(url: str, token: str, max_bytes: int) -> tuple[bytes, str]:
    """Stream a document body, aborting past ``max_bytes`` -- a discovered
    file must not be able to balloon server memory before the size check.

    Each redirect target gets a fresh egress + SSRF validation. Authorization
    is retained only for a same-origin redirect; cross-origin signed download
    URLs receive no bearer credential.
    """
    current = url
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(5):
        with _guarded_client(current, timeout=_TIMEOUT) as client:
            with client.stream("GET", current, headers=headers) as r:
                if r.status_code in {301, 302, 303, 307, 308}:
                    location = str(r.headers.get("location") or "").strip()
                    if not location:
                        raise ValueError("document source returned an invalid redirect")
                    target = urllib.parse.urljoin(current, location)
                    old = urllib.parse.urlsplit(current)
                    new = urllib.parse.urlsplit(target)
                    if (
                        old.scheme.lower() == "https"
                        and new.scheme.lower() != "https"
                    ):
                        raise PermissionError(
                            "document download scheme downgrade is not permitted"
                        )
                    if (
                        old.scheme.lower(), old.hostname, old.port
                    ) != (
                        new.scheme.lower(), new.hostname, new.port
                    ):
                        headers = {}
                    current = target
                    continue
                r.raise_for_status()
                mime = r.headers.get("content-type", "application/octet-stream")
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf += chunk
                    if len(buf) > max_bytes:
                        raise ValueError(
                            f"document too large: > {max_bytes} bytes")
                return bytes(buf), mime
    raise ValueError("document source returned too many redirects")


# --------------------------------------------------------------------------- #
# Source adapters: search(query) -> [DocHit], fetch(hit) -> (name, bytes, mime)
# --------------------------------------------------------------------------- #

def _search_msgraph(base: str, token: str, query: str, limit: int) -> list[DocHit]:
    """Microsoft Search over driveItems: OneDrive + every SharePoint site the
    caller can read -- where the SOW/contract/DPA actually live."""
    status, data = _post(f"{base}/search/query", token, {
        "requests": [{
            "entityTypes": ["driveItem"],
            "query": {"queryString": query},
            "size": limit,
        }],
    })
    if status != 200 or not isinstance(data, dict):
        log.debug("doc_discovery msgraph search failed with HTTP %s", status)
        return []
    hits: list[DocHit] = []
    for value in data.get("value", []):
        for container in value.get("hitsContainers", []):
            for h in container.get("hits", []):
                res = h.get("resource", {}) or {}
                parent = res.get("parentReference", {}) or {}
                hits.append(DocHit(
                    source="msgraph",
                    doc_id=str(res.get("id", "")),
                    name=str(res.get("name", "")) or "(unnamed)",
                    url=str(res.get("webUrl", "")),
                    snippet=str(h.get("summary", ""))[:300],
                    mime=str((res.get("file") or {}).get("mimeType", "")),
                    size=int(res.get("size", 0) or 0),
                    ref={"drive_id": str(parent.get("driveId", ""))},
                ))
    return hits


def _fetch_msgraph(base: str, token: str, hit_ref: dict, doc_id: str,
                   max_bytes: int):
    # safe="": drive_id/doc_id are caller-supplied (round-tripped through the
    # client on the attach endpoints) -- an embedded "/" or "?" must never be
    # able to re-point the request at a different Graph path, which would turn
    # this into an arbitrary-GET proxy carrying the org's token.
    q = lambda s: urllib.parse.quote(s, safe="")  # noqa: E731
    drive = str(hit_ref.get("drive_id", ""))
    path = (f"/drives/{q(drive)}/items/{q(doc_id)}/content" if drive
            else f"/me/drive/items/{q(doc_id)}/content")
    return _download(f"{base}{path}", token, max_bytes)


def _search_slack(base: str, token: str, query: str, limit: int) -> list[DocHit]:
    status, data = _get(f"{base}/search.files", token,
                        {"query": query, "count": limit})
    if status != 200 or not isinstance(data, dict) or not data.get("ok"):
        log.debug("doc_discovery slack search failed with HTTP %s", status)
        return []
    hits: list[DocHit] = []
    for f in ((data.get("files") or {}).get("matches") or [])[:limit]:
        hits.append(DocHit(
            source="slack",
            doc_id=str(f.get("id", "")),
            name=str(f.get("name", "")) or "(unnamed)",
            url=str(f.get("permalink", "")),
            mime=str(f.get("mimetype", "")),
            size=int(f.get("size", 0) or 0),
            ref={"download_url": str(f.get("url_private_download")
                                     or f.get("url_private") or "")},
        ))
    return hits


def _slack_url_allowed(url: str, base: str) -> bool:
    """Only fetch download URLs that live where the configured Slack tenant
    lives. ``download_url`` round-trips through the CLIENT on the attach
    endpoints, so an unchecked value would let a caller point the server at
    an arbitrary URL (SSRF) -- with the org's Slack token in the header."""
    u = urllib.parse.urlparse(url)
    b = urllib.parse.urlparse(base)
    if u.scheme not in ("https", b.scheme) or not u.hostname:
        return False
    if u.hostname == b.hostname:
        return True
    # Default tenant: content is served from *.slack.com (files.slack.com).
    base_host = b.hostname or ""
    return (base_host.endswith("slack.com")
            and (u.hostname == "slack.com"
                 or u.hostname.endswith(".slack.com")))


def _fetch_slack(base: str, token: str, hit_ref: dict, doc_id: str,
                 max_bytes: int):
    url = str(hit_ref.get("download_url", ""))
    if not url:
        raise ValueError("slack hit carries no download url")
    if not _slack_url_allowed(url, base):
        raise ValueError("slack download url is outside the configured tenant")
    return _download(url, token, max_bytes)


def _search_gdrive(base: str, token: str, query: str, limit: int) -> list[DocHit]:
    q = " or ".join(f"name contains '{t}'" for t in query.split()[:6]
                    if t and "'" not in t)
    if not q:
        return []
    status, data = _get(f"{base}/drive/v3/files", token, {
        "q": q, "pageSize": limit,
        "fields": "files(id,name,mimeType,size,webViewLink)",
    })
    if status != 200 or not isinstance(data, dict):
        log.debug("doc_discovery gdrive search failed with HTTP %s", status)
        return []
    return [DocHit(
        source="gdrive", doc_id=str(f.get("id", "")),
        name=str(f.get("name", "")) or "(unnamed)",
        url=str(f.get("webViewLink", "")), mime=str(f.get("mimeType", "")),
        size=int(f.get("size", 0) or 0),
    ) for f in data.get("files", [])[:limit]]


def _fetch_gdrive(base: str, token: str, hit_ref: dict, doc_id: str,
                  max_bytes: int):
    # safe="" for the same reason as msgraph: doc_id is client-round-tripped.
    doc = urllib.parse.quote(doc_id, safe="")
    return _download(f"{base}/drive/v3/files/{doc}?alt=media", token,
                     max_bytes)


_SEARCHERS = {"msgraph": _search_msgraph, "slack": _search_slack,
              "gdrive": _search_gdrive}
_FETCHERS = {"msgraph": _fetch_msgraph, "slack": _fetch_slack,
             "gdrive": _fetch_gdrive}


# --------------------------------------------------------------------------- #
# Discovery + fetch
# --------------------------------------------------------------------------- #

def _rank(hit: DocHit, subject_tokens: set[str]) -> float:
    """Explainable relevance: doc-keyword hits in the filename + subject-token
    overlap. No model, no magic -- a reviewer can see why a doc surfaced."""
    name = hit.name.lower()
    score = sum(1.0 for kw in DOC_KEYWORDS if kw in name)
    score += sum(0.5 for t in subject_tokens if t and t in name)
    if hit.snippet:
        snip = hit.snippet.lower()
        score += sum(0.25 for t in subject_tokens if t and t in snip)
    return score


def discover(subject: str, *, keywords: tuple[str, ...] | None = None,
             sources: list[str] | None = None, limit: int = 8,
             principal: str | None = None,
             allow_ambient_credentials: bool = False) -> list[DocHit]:
    """Search every configured source for documents related to ``subject``.

    Returns ranked, deduped hits (best first), at most ``limit``. Never
    raises: unconfigured sources are skipped, erroring sources contribute
    nothing. An empty subject returns nothing rather than everything.
    """
    subject = (subject or "").strip()
    if not subject or not enabled():
        return []
    try:
        allowed = list(get_assessments_sources())
    except Exception:  # pragma: no cover
        allowed = list(_SEARCHERS)
    if sources is None:
        use = [
            s for s in allowed
            if _creds(
                s,
                principal=principal,
                allow_ambient_credentials=allow_ambient_credentials,
            ) is not None
        ]
    else:
        # Caller preference filters WITHIN the operator's allowlist -- a
        # request body must not be able to widen [assessments] sources.
        use = [s for s in sources if s in allowed]
    kws = keywords if keywords is not None else ("sow", "contract", "dpa",
                                                 "security", "agreement")
    subject_tokens = {t.lower() for t in subject.split() if len(t) > 2}
    seen: set[tuple[str, str]] = set()
    out: list[DocHit] = []
    for source in use:
        creds = _creds(
            source,
            principal=principal,
            allow_ambient_credentials=allow_ambient_credentials,
        )
        searcher = _SEARCHERS.get(source)
        if creds is None or searcher is None:
            continue
        base, token = creds
        # One broad query per source: subject + the doc vocabulary. Sources
        # tokenize server-side; per-keyword fan-out costs N requests for the
        # same recall on every backend tested.
        query = f"{subject} {' '.join(kws)}".strip()
        try:
            found = searcher(base, token, query, max(limit, 8))
        except Exception as e:  # noqa: BLE001 -- one source must not kill discovery
            log.warning(
                "doc_discovery: %s search failed (%s)", source, type(e).__name__,
            )
            continue
        for h in found:
            key = (h.source, h.doc_id)
            if h.doc_id and key not in seen:
                seen.add(key)
                h.score = _rank(h, subject_tokens)
                out.append(h)
    out.sort(key=lambda h: h.score, reverse=True)
    return out[:limit]


# The document types an assessment's evidence is made of. Read here rather than
# from the host's MIME database: mimetypes takes its values from the Windows
# registry on Windows, and a registry can lack the Office entries.
_DOCUMENT_MIMES = {
    ".pdf": "application/pdf",
    ".rtf": "application/rtf",
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".epub": "application/epub+zip",
}


def resolve_mime(name: str, mime: str) -> str:
    """A usable mime for a fetched document. Sources often serve Office files
    as ``application/octet-stream`` (Graph's /content does), which the
    attachment allowlist rightly rejects -- infer from the filename in that
    case so the SOW/contract the feature exists to attach is attachable. The
    magic-byte executable/archive deny still guards the actual content."""
    m = (mime or "").split(";")[0].strip().lower()
    if m and m != "application/octet-stream":
        return m
    import mimetypes
    guessed = _DOCUMENT_MIMES.get(os.path.splitext(name)[1].lower())
    guessed = guessed or mimetypes.guess_type(name)[0]
    return guessed or m or "application/octet-stream"


def fetch(source: str, doc_id: str, ref: dict | None = None,
          *, max_bytes: int | None = None,
          principal: str | None = None,
          allow_ambient_credentials: bool = False) -> tuple[bytes, str]:
    """Download one discovered document's content: ``(bytes, mime)``.

    Raises ValueError on an unknown/unconfigured source, a download URL
    outside the configured tenant, or an oversized file -- the size cap is
    enforced WHILE streaming (never after buffering), and defaults to the
    attachment limit so discovery can't smuggle in what a direct upload
    couldn't."""
    creds = _creds(
        source,
        principal=principal,
        allow_ambient_credentials=allow_ambient_credentials,
    )
    fetcher = _FETCHERS.get(source)
    if creds is None or fetcher is None:
        raise ValueError(f"source {source!r} is not configured")
    if max_bytes is None:
        from .attachments import MAX_FILE_BYTES
        max_bytes = MAX_FILE_BYTES
    base, token = creds
    return fetcher(base, token, ref or {}, doc_id, max_bytes)


__all__ = ["DocHit", "DOC_KEYWORDS", "configured_sources", "discover",
           "enabled", "fetch", "resolve_mime"]
