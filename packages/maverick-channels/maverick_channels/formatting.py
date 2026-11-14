"""Map an agent's markdown reply to each chat platform's rich format.

Slack uses its own ``mrkdwn`` dialect (single-asterisk ``*bold*``,
``<url|text>`` links, no ``#`` headings); Discord renders standard markdown
natively but rejects a single message over 2000 characters. These helpers
keep the channel ``send()`` methods surgical and are pure functions, so they
unit-test without any platform SDK.
"""
from __future__ import annotations

import re

DISCORD_LIMIT = 2000

# Keep link text on one non-nested-bracket span so malformed strings with many
# candidate ``[`` characters fail locally instead of rescanning long suffixes.
_LINK_RE = re.compile(r"\[([^\[\]\r\n]+)\]\((https?://[^)\s]+)\)")
_BOLD_STAR_RE = re.compile(r"\*\*(.+?)\*\*", re.DOTALL)
_BOLD_UNDER_RE = re.compile(r"__(.+?)__", re.DOTALL)
_HEADING_RE = re.compile(r"(?m)^[ \t]{0,3}#{1,6}[ \t]+(.+?)[ \t]*$")
# An ``@`` that can start a mention: followed by a name character and not
# preceded by one, nor by ``/`` or ``=`` (``@user``, ``@user@host``,
# ``@channel``, ``@all``, ``@here``). The ``@`` inside ``bob@example.com``,
# ``https://host/@alice`` or ``?a=@b`` is left alone, as Mastodon's own
# mention pattern does not match it either. Fixed-width lookarounds keep
# this linear on long input.
_MENTION_TRIGGER_RE = re.compile(r"(?<![\w/=])@(?=\w)")
WORD_JOINER = "\u2060"


def _convert_slack_segment(seg: str) -> str:
    # Structural mrkdwn rewrites only. Control-char escaping (& < >) is done
    # unconditionally across the whole reply in to_slack_mrkdwn -- NOT here --
    # so it cannot be skipped on an unbalanced/odd code fence. Only the <...>
    # spans this function itself emits below stay live, matching the Discord
    # adapter's AllowedMentions.none() no-mention guarantee.
    seg = _LINK_RE.sub(r"<\2|\1>", seg)          # [text](url) -> <url|text>
    seg = _BOLD_STAR_RE.sub(r"*\1*", seg)        # **bold** -> *bold*
    seg = _BOLD_UNDER_RE.sub(r"*\1*", seg)       # __bold__ -> *bold*
    seg = _HEADING_RE.sub(r"*\1*", seg)          # ## Heading -> *Heading*
    return seg


def to_slack_mrkdwn(text: str) -> str:
    """Convert common markdown to Slack mrkdwn, preserving fenced code blocks.

    Slack control chars (``&`` ``<`` ``>``) are escaped across the ENTIRE
    reply first, independent of code-fence balance, so a prompt-injected
    ``<!channel>``/``<@U..>``/``<url|label>`` after an unclosed ``` fence can
    never reach Slack live (Slack honours these escapes even inside code, so
    the code body is not mangled). Structural rewrites (links/bold/headings)
    are then applied only to out-of-fence segments so code is left verbatim.
    """
    if not text:
        return text
    # Escape FIRST and unconditionally -- this is the security-critical step and
    # must not depend on fence parity. The link rewrite below re-emits its own
    # <url|text> spans from already-escaped text, which stay live by design.
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    parts = text.split("```")
    # Even-indexed parts are outside code fences; odd-indexed are inside.
    for i in range(0, len(parts), 2):
        parts[i] = _convert_slack_segment(parts[i])
    return "```".join(parts)


def neutralize_mentions(text: str) -> str:
    """Stop reply text from notifying anyone through an ``@`` mention.

    A WORD JOINER (U+2060, invisible and never a line break) goes between
    ``@`` and the following name character, so ``@user`` still reads the same
    but no longer matches the provider's mention syntax: Mastodon's mention
    pattern needs a name character right after ``@`` and Mattermost matches
    the whole ``@name`` word. Adapters add their own live mention of the
    person being answered outside this text.

    Code spans are not skipped: Mastodon statuses are plain text, so
    backticks do not stop a mention there.
    """
    return _MENTION_TRIGGER_RE.sub("@" + WORD_JOINER, text or "")


def split_utf16(text: str, limit: int) -> list[str]:
    """Split ``text`` into chunks of at most ``limit`` UTF-16 code units.

    A character outside the Basic Multilingual Plane counts as two units and
    is never split, so each chunk is within ``limit`` however the provider
    counts. Returns ``[""]`` for empty input so callers always send something.
    """
    chunks: list[str] = []
    start, units = 0, 0
    for index, char in enumerate(text or ""):
        width = 2 if ord(char) > 0xFFFF else 1
        if units + width > limit:
            chunks.append(text[start:index])
            start, units = index, 0
        units += width
    chunks.append((text or "")[start:])
    return chunks


def split_for_discord(text: str, limit: int = DISCORD_LIMIT) -> list[str]:
    """Split ``text`` into <= ``limit``-char chunks on line boundaries.

    Discord rejects messages over 2000 chars; this lets a channel send a
    long reply as multiple messages. A single line longer than the limit is
    hard-split. Returns ``[""]`` for empty input so callers always send
    something.
    """
    if not text:
        return [""]
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    cur = ""
    for line in text.splitlines(keepends=True):
        if len(cur) + len(line) > limit:
            if cur:
                chunks.append(cur)
                cur = ""
            while len(line) > limit:
                chunks.append(line[:limit])
                line = line[limit:]
        cur += line
    if cur:
        chunks.append(cur)
    return chunks
