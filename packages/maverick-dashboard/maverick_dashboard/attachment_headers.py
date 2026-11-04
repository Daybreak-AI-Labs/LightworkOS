"""Safe download names and RFC 6266 attachment headers."""
from __future__ import annotations

from urllib.parse import quote


def safe_filename(name: str) -> str:
    """Remove characters unsafe in a filename or HTTP response header."""
    cleaned = "".join(ch if (ch.isalnum() or ch in "-_. ") else "-" for ch in (name or ""))
    return cleaned.strip(" .-")[:120] or "document"


def attachment_content_disposition(name: str, *, filename=None) -> str:
    """Use an ASCII fallback and preserve Unicode with RFC 5987 encoding."""
    safe_name = (filename or safe_filename)(name)
    fallback = safe_name.encode("ascii", "ignore").decode("ascii").strip(" .-")
    fallback = fallback or "document"
    disposition = f'attachment; filename="{fallback}"'
    if fallback != safe_name:
        disposition += f"; filename*=UTF-8''{quote(safe_name, safe='')}"
    return disposition
