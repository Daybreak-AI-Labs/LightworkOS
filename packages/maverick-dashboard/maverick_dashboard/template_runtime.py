"""Template configuration, caching and date presentation."""
from __future__ import annotations

import logging
import os
import re

from fastapi.templating import Jinja2Templates

from . import plain_labels as _plain_labels

log = logging.getLogger("maverick_dashboard.app")


def _templates_auto_reload() -> bool:
    """Whether Jinja re-checks template files on every render.

    Off outside development: with 120+ templates the per-render stat calls
    and recompiles are pure overhead, and a deployment changes templates only
    by upgrading the package (a restart). ``MAVERICK_DEBUG=1``, the
    ``MAVERICK_TEMPLATE_AUTO_RELOAD`` environment variable or
    ``[dashboard] template_auto_reload = true`` turn it on for template work.
    """
    if os.environ.get("MAVERICK_DEBUG", "").strip():
        return True
    from maverick.env_setting import env_or_config

    raw = env_or_config("MAVERICK_TEMPLATE_AUTO_RELOAD", "dashboard",
                        "template_auto_reload", "0") or "0"
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _template_bytecode_cache():
    """Compiled-template cache under ``MAVERICK_HOME`` (fail-open: ``None``).

    Jinja compiles each template on first use; the first page after a start
    paid ~1.2 s compiling the shell, the page finder and the page itself. The
    on-disk cache is keyed on the template source checksum, so an upgraded
    template is recompiled, never served stale.
    """
    try:
        from jinja2 import FileSystemBytecodeCache
        from maverick.paths import maverick_home

        cache_dir = maverick_home() / "cache" / "templates"
        cache_dir.mkdir(parents=True, exist_ok=True)
        return FileSystemBytecodeCache(str(cache_dir))
    except Exception:  # pragma: no cover - an unwritable home just compiles per process
        log.debug("template bytecode cache unavailable", exc_info=True)
        return None


class _Templates(Jinja2Templates):
    """Page templates whose shell reads the deployment configuration once.

    The context processors (navigation, theme, help, drafts, search, ...) and
    the template each asked the configuration again: about 60 reads per page.
    One render is one ``config.single_read()``; the route's own gates ran
    before it with their own reads, and the next page reads the files again.
    """

    def TemplateResponse(self, *args, **kwargs):  # noqa: N802 -- Starlette's name
        from maverick.config import single_read

        with single_read():
            return super().TemplateResponse(*args, **kwargs)


def _format_datetime(ts, mode: str = "relative"):
    """Jinja filter: epoch seconds or ISO 8601 text -> a ``<time>`` the viewer
    reads in their zone.

    The server text is the full date, time and zone ("4 Oct 2026, 14:01 UTC"),
    so a page without JavaScript still says when; ``lightwork-ui.js``
    (``mvFormatTimes``) then rewrites it in the viewer's time zone -- relative
    with the absolute time on hover (default), absolute with
    ``mode="absolute"``, or the calendar date alone with ``mode="date"`` (a
    ``YYYY-MM-DD`` value stays that calendar day). Never a bare ``HH:MM:SS``,
    an ISO string or a raw epoch.
    """
    import datetime as _dt

    from markupsafe import Markup, escape

    if ts is None or ts == "":
        return "-"
    if mode == "date" and isinstance(ts, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", ts.strip()):
        try:
            day = _dt.date.fromisoformat(ts.strip())
        except ValueError:
            return str(ts)
        return Markup(f'<time datetime="{day.isoformat()}" data-mv-time="{day.isoformat()}"'
                      f' data-mv-time-mode="date">{_plain_labels.day_text(day)}</time>')
    try:
        if isinstance(ts, str) and not re.fullmatch(r"\s*-?\d+(?:\.\d+)?\s*", ts):
            when = _dt.datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
            when = (when if when.tzinfo else when.replace(tzinfo=_dt.timezone.utc)).astimezone(_dt.timezone.utc)
            stamp = when.timestamp()
        else:
            stamp = float(ts)
            when = _dt.datetime.fromtimestamp(stamp, tz=_dt.timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return str(ts)
    text = _plain_labels.datetime_text(stamp, date_only=mode == "date")
    return Markup(
        f'<time datetime="{when.isoformat()}" data-mv-time="{stamp:.3f}"'
        f' data-mv-time-mode="{escape(mode)}">{text}</time>'
    )
