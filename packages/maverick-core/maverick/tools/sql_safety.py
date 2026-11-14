"""Helpers for conservative SQL mutation gating."""
from __future__ import annotations

import re

_DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$")


def has_unconfirmed_statement_separator(
    sql: str, *, backslash_escapes: bool = False
) -> bool:
    """Return True when SQL contains a statement-separating semicolon.

    A single trailing semicolon is allowed for convenience, but semicolons that
    can introduce another statement require an explicit confirm gate. Semicolons
    inside string literals, quoted identifiers, or comments are ignored. By
    default single-quoted literals use SQL-standard doubled-quote escaping; set
    ``backslash_escapes`` only for dialects where backslash escapes quotes.

    Dialects disagree about two lexical forms: PostgreSQL dollar-quoted strings
    (``$tag$ ... $tag$``) and MySQL ``#`` line comments. Either can hide a
    semicolon from a scanner that reads the other way, so the text is scanned
    with each form on and off and a separator found by any reading counts.
    """
    return any(
        _scan_for_separator(sql, backslash_escapes, dollar, hash_comments)
        for dollar in (False, True)
        for hash_comments in (False, True)
    )


def _scan_for_separator(
    sql: str, backslash_escapes: bool, dollar: bool, hash_comments: bool
) -> bool:
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if ch == "'":
            i = _consume_single_quoted(sql, i, backslash_escapes=backslash_escapes)
            continue
        if ch == '"':
            i = _consume_double_quoted(sql, i)
            continue
        if ch == "`":
            i = _consume_backtick_quoted(sql, i)
            continue
        if ch == "[":
            i = _consume_bracket_quoted(sql, i)
            continue
        if (ch == "-" and nxt == "-") or (hash_comments and ch == "#"):
            i = _consume_line_comment(sql, i + 1)
            continue
        if ch == "/" and nxt == "*":
            i = _consume_block_comment(sql, i + 2)
            continue
        if dollar and ch == "$":
            i = _consume_dollar_quoted(sql, i)
            continue
        if ch == ";" and _has_non_comment_tail(sql, i + 1):
            return True
        i += 1
    return False


def _consume_dollar_quoted(sql: str, start: int) -> int:
    tag = _DOLLAR_TAG.match(sql, start)
    if tag is None:
        return start + 1
    end = sql.find(tag.group(0), tag.end())
    return len(sql) if end == -1 else end + len(tag.group(0))


def _consume_single_quoted(
    sql: str, start: int, *, backslash_escapes: bool = False
) -> int:
    i = start + 1
    while i < len(sql):
        if sql[i] == "'":
            if i + 1 < len(sql) and sql[i + 1] == "'":
                i += 2
                continue
            return i + 1
        if backslash_escapes and sql[i] == "\\":
            i += 2
            continue
        i += 1
    return i


def _consume_double_quoted(sql: str, start: int) -> int:
    i = start + 1
    while i < len(sql):
        if sql[i] == '"':
            if i + 1 < len(sql) and sql[i + 1] == '"':
                i += 2
                continue
            return i + 1
        i += 1
    return i


def _consume_backtick_quoted(sql: str, start: int) -> int:
    i = start + 1
    while i < len(sql):
        if sql[i] == "`":
            return i + 1
        i += 1
    return i


def _consume_bracket_quoted(sql: str, start: int) -> int:
    end = sql.find("]", start + 1)
    return len(sql) if end == -1 else end + 1


def _consume_line_comment(sql: str, start: int) -> int:
    end = sql.find("\n", start)
    return len(sql) if end == -1 else end + 1


def _consume_block_comment(sql: str, start: int) -> int:
    end = sql.find("*/", start)
    return len(sql) if end == -1 else end + 2


def _has_non_comment_tail(sql: str, start: int) -> bool:
    i = start
    n = len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if ch.isspace() or ch == ";":
            i += 1
            continue
        if ch == "-" and nxt == "-":
            i = _consume_line_comment(sql, i + 2)
            continue
        if ch == "/" and nxt == "*":
            i = _consume_block_comment(sql, i + 2)
            continue
        return True
    return False
