"""Version trusted template assets and revalidate public controller responses."""
from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path

from jinja2.ext import Extension

_ASSET = re.compile(r"/static/([A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:js|css))")
_ATTRIBUTE = re.compile(r'''\s+([\w:.-]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?''')
_JINJA_LITERAL = re.compile(r"{#.*?#}|{%[-+]?\s*raw\s*[-+]?%}.*?{%[-+]?\s*endraw\s*[-+]?%}", re.DOTALL)
_ETAGS = re.compile(r'\s*(?:W/)?"[^"\r\n]*"\s*(?:,\s*(?:W/)?"[^"\r\n]*"\s*)*')


class AssetVersions:
    """Content hashes cached against a file's identity, size and timestamps."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._versions: dict[str, tuple[tuple, str]] = {}

    def version(self, name: str) -> str:
        if not name or "/" in name or "\\" in name or name.startswith("."):
            return ""
        path = self.directory / name
        try:
            before = path.stat()
            identity = (str(path), before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
            cached = self._versions.get(name)
            if cached is not None and cached[0] == identity:
                return cached[1]
            contents = path.read_bytes()
            after = path.stat()
            if identity != (str(path), after.st_dev, after.st_ino, after.st_size,
                            after.st_mtime_ns, after.st_ctime_ns) or len(contents) != after.st_size:
                self._versions.pop(name, None)
                return ""
            version = hashlib.sha256(contents).hexdigest()[:8]
            self._versions[name] = identity, version
            return version
        except OSError:
            self._versions.pop(name, None)
            return ""


class _AssetTags(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=False)
        self.offsets, self.edits = [0], []
        for line in source.splitlines(keepends=True):
            self.offsets.append(self.offsets[-1] + len(line))

    def handle_starttag(self, tag, attrs):
        attribute = "src" if tag == "script" else "href" if tag == "link" else None
        if attribute is None or (tag == "link" and "stylesheet" not in (dict(attrs).get("rel") or "").lower().split()):
            return
        text = self.get_starttag_text()
        line, column = self.getpos()
        start = self.offsets[line - 1] + column
        for found in _ATTRIBUTE.finditer(text):
            value = found[2]
            if found[1].lower() != attribute or not value or value[0] not in "\"'":
                continue
            asset = _ASSET.fullmatch(value[1:-1])
            if asset and asset[1].endswith(".js" if tag == "script" else ".css"):
                quote = "'" if value[0] == '"' else '"'
                replacement = value[0] + "{{ static_url(" + quote + asset[1] + quote + ") }}" + value[0]
                self.edits.append((start + found.start(2), start + found.end(2), replacement))


class AssetVersionExtension(Extension):
    """Transform only actual static script/stylesheet tags in trusted templates."""
    def preprocess(self, source, name, filename=None):
        parser = _AssetTags(source)
        masked = _JINJA_LITERAL.sub(lambda found: re.sub(r"[^\n]", " ", found[0]), source)
        parser.feed(masked)
        for start, end, replacement in reversed(parser.edits):
            source = source[:start] + replacement + source[end:]
        return source


def _matches(header, etag):
    if header.strip() == "*":
        return True
    if len(header) > 16384 or not _ETAGS.fullmatch(header):
        return False
    return any(value.removeprefix("W/") == etag.removeprefix("W/")
               for value in re.findall(r'(?:W/)?"[^"\r\n]*"', header))


def cache_response(scope, message, version, immutable):
    """Conditional cache only after the native route actually admitted public200."""
    if message.get("type") != "http.response.start" or message.get("status") != 200 or not version:
        return message, False
    headers = list(message.get("headers", []))
    policy = ",".join(value.decode("latin-1").lower() for key, value in headers if key.lower() == b"cache-control")
    directives = {value.strip().split("=", 1)[0] for value in policy.split(",")}
    if "public" not in directives or directives & {"private", "no-store"}:
        return message, False
    controller = _ASSET.fullmatch(scope.get("path", "")) is not None
    if not immutable and not controller:
        return message, False
    headers = [(key, value) for key, value in headers if key.lower() != b"cache-control"]
    headers.append((b"cache-control", b"public, max-age=31536000, immutable" if immutable else b"public, no-cache"))
    if not controller:
        return {**message, "headers": headers}, False
    etag = 'W/"' + version + '"'
    headers = [(key, value) for key, value in headers if key.lower() != b"etag"] + [(b"etag", etag.encode("ascii"))]
    condition = ",".join(value.decode("latin-1") for key, value in scope.get("headers", []) if key.lower() == b"if-none-match")
    unchanged = scope.get("method") in {"GET", "HEAD"} and _matches(condition, etag)
    if unchanged:
        headers = [(key, value) for key, value in headers if key.lower() not in {b"content-length", b"content-range"}]
    return {**message, "status": 304 if unchanged else 200, "headers": headers}, unchanged


class StaticCacheMiddleware:
    """Cache public asset responses only after the route admits the request."""

    def __init__(self, app, *, version_for) -> None:
        self.app = app
        self.version_for = version_for

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or not scope.get("path", "").startswith("/static/"):
            await self.app(scope, receive, send)
            return
        name = scope["path"].rsplit("/", 1)[-1]
        query = scope.get("query_string", b"").decode("latin-1")
        unchanged = False

        async def send_cached(message) -> None:
            nonlocal unchanged
            if message.get("type") == "http.response.start":
                wanted = self.version_for(name)
                immutable = bool(wanted) and any(part == f"v={wanted}" for part in query.split("&"))
                message, unchanged = cache_response(scope, message, wanted, immutable)
            elif unchanged:
                if message.get("type") == "http.response.pathsend" or not message.get("more_body", False):
                    await send({"type": "http.response.body", "body": b""})
                return
            await send(message)

        await self.app(scope, receive, send_cached)
