"""Where the consent stores keep their records: private files or shared Postgres.

Every consent store (preferences, delivery, publishing, experiments, profile
data, scanning and the rest under the ``consent_preferences`` data folder)
keeps its records in a private SQLite file per workspace. That remains the
default and is unchanged when ``[consent_preferences.storage]`` is not set.

With ``backend = "postgres"`` the same stores run on a shared PostgreSQL
database through the connection layer the governed-record backend uses
(:class:`maverick.postgres_transactions.PostgresTransactions`: bounded
statement, idle-transaction and client I/O timeouts, ``maverick-core[postgres]``
only when chosen). Each store file maps to its own Postgres schema, named from
the file's place under the Lightwork home (``tenants/<workspace>/consent_
preferences/<file>``), so every workspace keeps its own separate records and
several servers sharing one database reach the same records.

The stores keep their own SQL. :class:`PostgresConsentConnection` accepts the
SQLite statements they use and runs the PostgreSQL equivalent with the same
guarantees the stores rely on:

* ``BEGIN IMMEDIATE`` takes a transaction advisory lock for that store, so
  writers to one store are serialized exactly as SQLite's database write lock
  serializes them (the governed-record schema-lock convention);
* every statement inside a transaction runs under a savepoint, so a refused
  statement (a unique key, an immutable-row trigger) leaves the transaction
  usable, as it does in SQLite;
* ``RAISE(ABORT, ...)`` triggers become PL/pgSQL triggers raising an integrity
  error with the same message; column types, ``INSERT OR IGNORE``,
  ``json_extract``, ``instr``, two-argument ``max``/``min``, ``PRAGMA
  table_info`` and ``sqlite_master`` are translated; ``NULL`` ordering and
  byte-wise text ordering match SQLite;
* errors come back as the ``sqlite3`` exception the store already handles,
  without driver text (which can carry values or connection details).

The connection string never lives in plain configuration: it comes from the
environment variable named by ``dsn_secret_ref`` (``$NAME``), which wins, or
from the connection saved sealed on the All settings page. The selection is
read once per process, like the governed-record authority: a change takes
effect when Lightwork restarts, so one process never writes to both places.

Switching does not move existing records. :func:`preview_move` and
:func:`move_local_records` copy each workspace's store files into the shared
database (only into empty stores, verified row by row, originals kept).
"""
from __future__ import annotations

import contextlib
import decimal
import hashlib
import math
import os
import re
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BACKENDS = ("sqlite", "postgres")
DEFAULT_DSN_ENV = "MAVERICK_CONSENT_PG_DSN"
BACKEND_ENV = "MAVERICK_CONSENT_STORAGE_BACKEND"
# The consent stores' data folders (the public consent service keeps its
# client and application registries beside the preference center).
DATA_FOLDERS = ("consent_preferences", "consent_public_api")
_ENV_NAME_RE = re.compile(r"\$?([A-Z][A-Z0-9_]{2,63})")
# ``mvkc``: the advisory-lock class for consent stores (the governed-record
# backend uses ``mvkgrv`` for its schema lock). The second key is the store.
_LOCK_CLASS = 0x6D766B63
_SCHEMA_PREFIX = "lw_consent_"
_MAX_SQL_CACHE = 2048


class ConsentStorageError(sqlite3.OperationalError):
    """The chosen consent storage cannot be used (plain, no connection details).

    A ``sqlite3`` error, so every store's existing "records unavailable"
    handling also covers a shared database that cannot be reached or chosen.
    """


@dataclass(frozen=True)
class StorageSelection:
    backend: str
    dsn: str = field(default="", repr=False)
    dsn_env: str = DEFAULT_DSN_ENV

    @property
    def shared(self) -> bool:
        return self.backend == "postgres"


def _section(config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if config is None:
        from .config import load_global_config

        try:
            config = load_global_config() or {}
        except Exception as exc:  # noqa: BLE001 - unreadable settings fail closed
            raise ConsentStorageError("consent storage settings are unavailable") from exc
    node: object = config.get("consent_preferences") if isinstance(config, Mapping) else None
    node = node.get("storage") if isinstance(node, Mapping) else None
    if node is None:
        return {}
    if not isinstance(node, Mapping):
        raise ConsentStorageError("consent_preferences.storage must be a table")
    return node


def dsn_env_name(config: Mapping[str, Any] | None = None) -> str:
    """The environment variable that holds the connection (``dsn_secret_ref``)."""
    raw = _section(config).get("dsn_secret_ref")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return DEFAULT_DSN_ENV
    match = _ENV_NAME_RE.fullmatch(raw.strip()) if isinstance(raw, str) else None
    if match is None or "CONSENT" not in match.group(1):
        raise ConsentStorageError(
            "consent_preferences.storage.dsn_secret_ref must name an environment variable "
            "containing CONSENT")
    return match.group(1)


def storage_settings(config: Mapping[str, Any] | None = None) -> StorageSelection:
    """Read ``[consent_preferences.storage]`` (the environment wins)."""
    section = _section(config)
    raw = os.environ.get(BACKEND_ENV, "").strip() or section.get("backend", "sqlite")
    backend = raw.strip().lower() if isinstance(raw, str) else raw
    if backend not in BACKENDS:
        raise ConsentStorageError("consent storage backend must be sqlite or postgres")
    env_name = dsn_env_name(config)
    if backend == "sqlite":
        return StorageSelection("sqlite", "", env_name)
    dsn = os.environ.get(env_name, "").strip()
    if not dsn:
        saved = section.get("dsn")
        dsn = saved.strip() if isinstance(saved, str) else ""
    if not dsn:
        raise ConsentStorageError("shared consent storage needs a database connection")
    if len(dsn) > 8192:
        raise ConsentStorageError("the consent database connection is too long")
    return StorageSelection("postgres", dsn, env_name)


_PIN_LOCK = threading.Lock()
_PINNED: StorageSelection | None = None


def selection() -> StorageSelection:
    """The storage this process uses: read once, kept until restart."""
    global _PINNED
    with _PIN_LOCK:
        if _PINNED is None:
            _PINNED = storage_settings()
        return _PINNED


def shared() -> bool:
    """True when this process keeps consent records in shared Postgres."""
    return selection().shared


def _reset_for_testing() -> None:
    global _PINNED
    with _PIN_LOCK:
        _PINNED = None
    _READY.clear()


# ---------------------------------------------------------------- identity
def logical_name(path: str | os.PathLike[str]) -> str:
    """The store's place under the Lightwork home, the same on every server."""
    from .paths import maverick_home

    resolved = Path(path).expanduser().resolve()
    with contextlib.suppress(ValueError, OSError):
        return resolved.relative_to(maverick_home().expanduser().resolve()).as_posix()
    return resolved.as_posix()


def schema_name(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256(logical_name(path).encode("utf-8")).hexdigest()
    return _SCHEMA_PREFIX + digest[:32]


def _lock_key(schema: str) -> int:
    value = int.from_bytes(hashlib.sha256(schema.encode("ascii")).digest()[:4], "big")
    return value - (1 << 32) if value >= (1 << 31) else value


# ---------------------------------------------------------------- tokens
_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<comment>--[^\n]*|/\*.*?\*/)
  | (?P<str>'(?:[^']|'')*')
  | (?P<qident>"(?:[^"]|"")*")
  | (?P<param>\?\d*)
  | (?P<named>(?<![:\w]):[A-Za-z_]\w*)
  | (?P<word>[A-Za-z_][A-Za-z0-9_$]*)
  | (?P<num>\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)
  | (?P<op><=|>=|<>|!=|==|\|\||::|.)
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass
class _Tok:
    kind: str
    text: str

    @property
    def up(self) -> str:
        return self.text.upper() if self.kind == "word" else ""


def _tokens(sql: str) -> list[_Tok]:
    out: list[_Tok] = []
    for match in _TOKEN_RE.finditer(sql):
        kind = match.lastgroup or "op"
        out.append(_Tok(kind, match.group()))
    return out


def _code(tokens: Sequence[_Tok]) -> list[int]:
    """Indexes of tokens that are not whitespace or comments."""
    return [i for i, t in enumerate(tokens) if t.kind not in {"ws", "comment"}]


def split_statements(script: str) -> list[str]:
    """Split a script into statements (a trigger body stays whole)."""
    statements: list[str] = []
    current: list[str] = []
    words: list[str] = []
    depth_begin = 0
    for tok in _tokens(script):
        if tok.kind == "word":
            words.append(tok.up)
            if words[:2] == ["CREATE", "TRIGGER"] or (
                    len(words) > 2 and words[0] == "CREATE" and "TRIGGER" in words[1:3]):
                if tok.up in {"BEGIN", "CASE"}:
                    depth_begin += 1
                elif tok.up == "END" and depth_begin:
                    depth_begin -= 1
        if tok.kind == "op" and tok.text == ";" and depth_begin == 0:
            text = "".join(current).strip()
            if text:
                statements.append(text)
            current, words = [], []
            continue
        current.append(tok.text)
    text = "".join(current).strip()
    if text:
        statements.append(text)
    return statements


# ---------------------------------------------------------------- translation
_TYPES = {"INTEGER": "BIGINT", "INT": "BIGINT", "REAL": "DOUBLE PRECISION",
          "BLOB": "BYTEA", "TEXT": 'TEXT COLLATE "C"', "NUMERIC": "NUMERIC"}
_TERMINATORS = {"LIMIT", "OFFSET", "UNION", "EXCEPT", "INTERSECT", "FOR", "FETCH"}


class _Unsupported(ValueError):
    pass


@dataclass(frozen=True)
class _Plan:
    kind: str          # sql | begin | commit | rollback | pragma | noop | script
    sql: str = ""
    pragma: str = ""
    value: str = ""
    ddl: bool = False
    writes: bool = False
    statements: tuple[str, ...] = ()


def _render(tokens: Sequence[_Tok], *, bind: bool) -> str:
    parts = []
    for tok in tokens:
        if tok.kind == "param":
            if len(tok.text) > 1:
                raise _Unsupported("numbered parameters are not supported")
            parts.append("%s")
        elif tok.kind == "named":
            parts.append(f"%({tok.text[1:]})s")
        elif bind and "%" in tok.text:
            # psycopg reads every % in the text, inside literals and comments
            # too: double it so no value lands in (or breaks) the statement.
            parts.append(tok.text.replace("%", "%%"))
        elif tok.kind == "op" and tok.text == "==":
            parts.append("=")
        else:
            parts.append(tok.text)
    return "".join(parts)


def _match_paren(tokens: Sequence[_Tok], start: int) -> int:
    """Index of the ``)`` closing the ``(`` at ``start``."""
    depth = 0
    for i in range(start, len(tokens)):
        if tokens[i].kind == "op" and tokens[i].text == "(":
            depth += 1
        elif tokens[i].kind == "op" and tokens[i].text == ")":
            depth -= 1
            if depth == 0:
                return i
    raise _Unsupported("unbalanced parentheses")


def _next_code(tokens: Sequence[_Tok], i: int) -> int:
    i += 1
    while i < len(tokens) and tokens[i].kind in {"ws", "comment"}:
        i += 1
    return i


def _prev_code(tokens: Sequence[_Tok], i: int) -> int:
    i -= 1
    while i >= 0 and tokens[i].kind in {"ws", "comment"}:
        i -= 1
    return i


def _top_level_args(tokens: Sequence[_Tok], open_i: int, close_i: int) -> int:
    count, depth, seen = 1, 0, False
    for tok in tokens[open_i + 1:close_i]:
        if tok.kind == "op" and tok.text == "(":
            depth += 1
        elif tok.kind == "op" and tok.text == ")":
            depth -= 1
        elif tok.kind == "op" and tok.text == "," and depth == 0:
            count += 1
        if tok.kind not in {"ws", "comment"}:
            seen = True
    return count if seen else 0


def _json_path(literal: str) -> str:
    text = literal[1:-1].replace("''", "'")
    if not text.startswith("$"):
        raise _Unsupported("json_extract needs a $ path")
    keys = [k for k in re.split(r"\.", text[1:]) if k]
    if not all(re.fullmatch(r"[A-Za-z0-9_]+", k) for k in keys):
        raise _Unsupported("json_extract path is not supported")
    return "'{" + ",".join(keys) + "}'"


_COMPARE = {"<", ">", "<=", ">=", "=", "==", "<>", "!="}
# A JSON value ordered the way SQLite orders what json_extract returns: NULL
# for JSON null or a missing key, then numbers (true/false are 1/0), then text
# compared byte by byte. Objects and arrays come back from SQLite as compact
# JSON text that jsonb cannot reproduce, so comparing one with text fails
# loudly instead of giving a different answer.
_CLASS = ("CASE WHEN {v} IS NULL OR jsonb_typeof({v}) = 'null' THEN NULL "
          "WHEN jsonb_typeof({v}) IN ('number', 'boolean') THEN 0 ELSE 1 END")
_AS_NUMBER = ("CASE jsonb_typeof({v}) WHEN 'number' THEN ({v})::numeric "
              "WHEN 'boolean' THEN CASE WHEN ({v})::boolean THEN 1 ELSE 0 END END")
_AS_TEXT = ("CASE WHEN jsonb_typeof({v}) = 'string' THEN ({v} #>> '{{}}') COLLATE \"C\" "
            "WHEN jsonb_typeof({v}) IN ('object', 'array') THEN (('json_extract of a JSON '"
            " || jsonb_typeof({v}) || ' cannot be compared with text')::integer)::text END")


def _prev_is_comparison(tokens: Sequence[_Tok], i: int) -> bool:
    before = _prev_code(tokens, i)
    return before >= 0 and tokens[before].kind == "op" and tokens[before].text in _COMPARE


def _named_operand(tokens: Sequence[_Tok], close: int, params: Mapping) -> object:
    operand = _next_code(tokens, _next_code(tokens, close))
    if operand < len(tokens) and tokens[operand].kind == "named":
        return params.get(tokens[operand].text[1:])
    return None


def _ordered(value_sql: str, numeric: bool) -> _Tok:
    second = (_AS_NUMBER if numeric else _AS_TEXT).format(v=value_sql)
    return _Tok("word", f"ROW({_CLASS.format(v=value_sql)}, {second})")


def _json_extract(tokens: list[_Tok], open_i: int, value: object) -> tuple[list[_Tok], int, int]:
    """``json_extract(doc, '$.path')`` compared (``op operand`` or ``IN``)
    the way SQLite compares it. Returns the tokens, the next index, and how
    many bound values were used."""
    close = _match_paren(tokens, open_i)
    inner = tokens[open_i + 1:close]
    comma = max((j for j, t in enumerate(inner) if t.kind == "op" and t.text == ","), default=-1)
    path_tokens = [t for t in inner[comma + 1:] if t.kind not in {"ws", "comment"}]
    if comma < 0 or len(path_tokens) != 1 or path_tokens[0].kind != "str":
        raise _Unsupported("json_extract form is not supported")
    doc_tokens = _functions(list(inner[:comma]), ())
    if any(t.kind in {"param", "named"} for t in doc_tokens):
        raise _Unsupported("json_extract of a bound value is not supported")
    doc = _render(doc_tokens, bind=False).strip()
    json_value = f"(({doc})::jsonb #> {_json_path(path_tokens[0].text)})"
    after = _next_code(tokens, close)
    nxt = tokens[after] if after < len(tokens) else _Tok("ws", "")
    if nxt.kind == "op" and nxt.text in _COMPARE:
        operand = _next_code(tokens, after)
        target = tokens[operand] if operand < len(tokens) else _Tok("ws", "")
        if target.kind not in {"param", "named", "num", "str"}:
            raise _Unsupported("json_extract can only be compared with a value")
        used = int(target.kind in {"param", "named"})
        if used and value is None:
            # A NULL value: every comparison is NULL, as in SQLite.
            return ([_Tok("word", f"({json_value} #>> '{{}}')"), nxt, target], operand + 1, used)
        numeric = target.kind == "num" or (
            used == 1 and isinstance(value, (int, float)))  # bool binds as 0/1
        side = "0" if numeric else "1"
        return ([_ordered(json_value, numeric), nxt, _Tok("word", f"ROW({side}, "), target,
                 _Tok("op", ")")], operand + 1, used)
    words = [nxt.up]
    j = after
    if nxt.up == "NOT":
        j = _next_code(tokens, after)
        words.append(tokens[j].up if j < len(tokens) else "")
    if words[-1] == "IN":
        list_open = _next_code(tokens, j)
        if list_open >= len(tokens) or tokens[list_open].text != "(":
            raise _Unsupported("json_extract IN needs a list of text values")
        list_close = _match_paren(tokens, list_open)
        items = [t for t in tokens[list_open + 1:list_close] if t.kind not in {"ws", "comment"}]
        texts = items[0::2]
        if not texts or any(t.kind != "str" for t in texts) or any(
                t.text != "," for t in items[1::2]):
            raise _Unsupported("json_extract IN needs a list of text values")
        rows = ", ".join(f"ROW(1, {t.text})" for t in texts)
        return ([_ordered(json_value, False), *tokens[close + 1:list_open],
                 _Tok("word", f"({rows})")], list_close + 1, 0)
    raise _Unsupported("json_extract is only supported in a comparison")


def _functions(tokens: list[_Tok], params: object) -> list[_Tok]:
    """Rewrite SQLite functions to PostgreSQL ones (in place, returns tokens)."""
    positional = list(params) if isinstance(params, Sequence) and not isinstance(
        params, (str, bytes)) else []
    param_index = 0
    out: list[_Tok] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.kind == "param":
            param_index += 1
        nxt = _next_code(tokens, i)
        is_call = (tok.kind == "word" and nxt < len(tokens)
                   and tokens[nxt].kind == "op" and tokens[nxt].text == "(")
        name = tok.up
        if is_call and name == "INSTR":
            out.append(_Tok("word", "strpos"))
            i += 1
            continue
        if is_call and name == "IFNULL":
            out.append(_Tok("word", "coalesce"))
            i += 1
            continue
        if is_call and name == "LAST_INSERT_ROWID":
            close = _match_paren(tokens, nxt)
            out.append(_Tok("word", "lastval()"))
            i = close + 1
            continue
        if is_call and name in {"MAX", "MIN"}:
            close = _match_paren(tokens, nxt)
            if _top_level_args(tokens, nxt, close) >= 2:
                out.append(_Tok("word", "GREATEST" if name == "MAX" else "LEAST"))
                i += 1
                continue
        if is_call and name == "JSON_EXTRACT":
            value = positional[param_index] if param_index < len(positional) else None
            if isinstance(params, Mapping):
                value = _named_operand(tokens, _match_paren(tokens, nxt), params)
            if _prev_is_comparison(tokens, i):
                raise _Unsupported("json_extract must be on the left of a comparison")
            rewritten, i, used = _json_extract(tokens, nxt, value)
            out.extend(rewritten)
            param_index += used
            continue
        out.append(tok)
        i += 1
    return out


def _nulls_like_sqlite(tokens: list[_Tok]) -> list[_Tok]:
    """``ORDER BY`` terms sort NULLs first ascending and last descending."""
    out: list[_Tok] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        out.append(tok)
        nxt = _next_code(tokens, i)
        if tok.up == "ORDER" and nxt < len(tokens) and tokens[nxt].up == "BY":
            out.extend(tokens[i + 1:nxt + 1])
            i = nxt + 1
            depth = 0
            term: list[_Tok] = []

            def close_term(term: list[_Tok]) -> list[_Tok]:
                words = [t.up for t in term if t.kind == "word"]
                if not words and not any(t.kind not in {"ws", "comment"} for t in term):
                    return term
                if "NULLS" in words:
                    return term
                last = next((t.up for t in reversed(term) if t.kind not in {"ws", "comment"}), "")
                trailing = []
                while term and term[-1].kind in {"ws", "comment"}:
                    trailing.insert(0, term.pop())
                suffix = " NULLS LAST" if last == "DESC" else " NULLS FIRST"
                return [*term, _Tok("word", suffix), *trailing]

            while i < len(tokens):
                t = tokens[i]
                if t.kind == "op" and t.text == "(":
                    depth += 1
                elif t.kind == "op" and t.text == ")":
                    if depth == 0:
                        break
                    depth -= 1
                elif depth == 0 and (t.up in _TERMINATORS or (t.kind == "op" and t.text == ";")):
                    break
                if depth == 0 and t.kind == "op" and t.text == ",":
                    out.extend(close_term(term))
                    out.append(t)
                    term = []
                else:
                    term.append(t)
                i += 1
            out.extend(close_term(term))
            continue
        i += 1
    return out


def _column_types(tokens: list[_Tok], start: int) -> list[_Tok]:
    """Map SQLite column types after ``start`` (CREATE TABLE / ADD COLUMN)."""
    out = list(tokens[:start])
    i = start
    while i < len(tokens):
        tok = tokens[i]
        up = tok.up
        prev = _prev_code(tokens, i)
        prev_tok = tokens[prev] if prev >= 0 else None
        # A type follows a column name (a word or quoted name) directly.
        after_name = prev_tok is not None and (
            prev_tok.kind == "qident" or (prev_tok.kind == "word" and prev_tok.up != "AS"))
        if up in _TYPES and after_name:
            if up in {"INTEGER", "INT"}:
                j = _next_code(tokens, i)
                k = _next_code(tokens, j) if j < len(tokens) else j
                if j < len(tokens) and tokens[j].up == "PRIMARY" and k < len(tokens) \
                        and tokens[k].up == "KEY":
                    end = k
                    auto = _next_code(tokens, k)
                    if auto < len(tokens) and tokens[auto].up == "AUTOINCREMENT":
                        end = auto
                    out.append(_Tok("word", "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY"))
                    i = end + 1
                    continue
            out.append(_Tok("word", _TYPES[up]))
            i += 1
            continue
        if up == "AUTOINCREMENT":
            i += 1
            continue
        if up == "REFERENCES":
            # REFERENCES t(cols) [ON DELETE|UPDATE action]... -> DEFERRABLE
            j = _next_code(tokens, i)          # table
            j = _next_code(tokens, j)
            if j < len(tokens) and tokens[j].kind == "op" and tokens[j].text == "(":
                j = _match_paren(tokens, j)
            end = j
            while True:
                k = _next_code(tokens, end)
                if k < len(tokens) and tokens[k].up == "ON":
                    action = _next_code(tokens, _next_code(tokens, k))
                    end = action
                    if action < len(tokens) and tokens[action].up in {"SET", "NO"}:
                        end = _next_code(tokens, action)
                    continue
                break
            out.extend(tokens[i:end + 1])
            out.append(_Tok("word", " DEFERRABLE INITIALLY IMMEDIATE"))
            i = end + 1
            continue
        out.append(tok)
        i += 1
    return out


def _trigger(tokens: list[_Tok]) -> tuple[str, ...]:
    code = _code(tokens)
    words = [tokens[i].up for i in code]
    pos = 2
    if words[pos:pos + 3] == ["IF", "NOT", "EXISTS"]:
        pos += 3
    name_tok = tokens[code[pos]]
    name = name_tok.text.strip('"')
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", name):
        raise _Unsupported("trigger name is not supported")
    pos += 1
    timing = words[pos]
    if timing not in {"BEFORE", "AFTER"}:
        raise _Unsupported("trigger timing is not supported")
    pos += 1
    event = words[pos]
    if event not in {"INSERT", "UPDATE", "DELETE"}:
        raise _Unsupported("trigger event is not supported")
    begin_at = next(i for i in code if tokens[i].up == "BEGIN")
    end_at = max(i for i in code if tokens[i].up == "END")
    head = "".join(t.text for t in tokens[code[pos]:begin_at])
    head = re.sub(r"\bFOR\s+EACH\s+ROW\b", "", head, flags=re.IGNORECASE).strip()
    when = ""
    match = re.search(r"\bWHEN\b(.*)$", head, flags=re.IGNORECASE | re.DOTALL)
    if match:
        when = match.group(1).strip()
        head = head[:match.start()].strip()
        when_sql = _render(_functions(_tokens(when), ()), bind=False)
        when_sql = re.sub(r"\bIS\s+NOT\b(?!\s+NULL)", "IS DISTINCT FROM", when_sql, flags=re.IGNORECASE)
        when = f" WHEN ({when_sql})"
    body_src = "".join(t.text for t in tokens[begin_at + 1:end_at])
    body: list[str] = []
    for statement in split_statements(body_src):
        raised = re.fullmatch(r"SELECT\s+RAISE\s*\(\s*(ABORT|FAIL|ROLLBACK)\s*,\s*('(?:[^']|'')*')\s*\)",
                              statement.strip(), flags=re.IGNORECASE | re.DOTALL)
        if raised:
            body.append(f"RAISE EXCEPTION USING ERRCODE = '23000', MESSAGE = {raised.group(2)}")
            continue
        plan = _translate(statement, (), in_trigger=True)
        body.append(plan.sql)
    returned = "NULL" if timing == "AFTER" else ("OLD" if event == "DELETE" else "NEW")
    function = f"lw_trg_{name}"[:63]
    create_function = (
        f'CREATE OR REPLACE FUNCTION "{function}"() RETURNS trigger LANGUAGE plpgsql '
        "SET search_path FROM CURRENT AS $lw$ BEGIN " + "; ".join(body) + f"; RETURN {returned}; END $lw$"
    )
    create_trigger = (
        f'CREATE OR REPLACE TRIGGER "{name}" {timing} {head} FOR EACH ROW{when} '
        f'EXECUTE FUNCTION "{function}"()'
    )
    return create_function, create_trigger


def _drop_trigger(tokens: list[_Tok]) -> str:
    code = _code(tokens)
    words = [tokens[i].up for i in code]
    pos = 2
    if words[pos:pos + 2] == ["IF", "EXISTS"]:
        pos += 2
    name = tokens[code[pos]].text.strip('"')
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", name):
        raise _Unsupported("trigger name is not supported")
    return (
        "DO $lw$ DECLARE r record; BEGIN FOR r IN SELECT c.relname FROM pg_trigger t "
        "JOIN pg_class c ON c.oid = t.tgrelid WHERE c.relnamespace = "
        f"current_schema()::regnamespace AND t.tgname = '{name}' AND NOT t.tgisinternal "
        f"LOOP EXECUTE format('DROP TRIGGER %I ON %I', '{name}', r.relname); END LOOP; "
        "END $lw$"
    )


def _param_signature(params: object) -> tuple:
    if isinstance(params, Mapping):
        return ("map",)
    if isinstance(params, Sequence) and not isinstance(params, (str, bytes)):
        return tuple(type(p).__name__ for p in params)
    return ()


_CACHE: dict[tuple, _Plan] = {}
_CACHE_LOCK = threading.Lock()


def translate(sql: str, params: object = ()) -> _Plan:
    """The PostgreSQL plan for one SQLite statement (cached)."""
    key = (sql, _param_signature(params), bool(params))
    with _CACHE_LOCK:
        plan = _CACHE.get(key)
    if plan is None:
        plan = _translate(sql, params)
        with _CACHE_LOCK:
            if len(_CACHE) >= _MAX_SQL_CACHE:
                _CACHE.clear()
            _CACHE[key] = plan
    return plan


def _translate(sql: str, params: object, *, in_trigger: bool = False) -> _Plan:  # noqa: C901
    tokens = _tokens(sql)
    code = _code(tokens)
    while code and tokens[code[-1]].kind == "op" and tokens[code[-1]].text == ";":
        tokens = tokens[:code[-1]]
        code = code[:-1]
    if not code:
        return _Plan("noop")
    words = [tokens[i].up for i in code]
    first = words[0]
    bind = bool(params) and not in_trigger
    if first in {"BEGIN"}:
        return _Plan("begin")
    if first in {"COMMIT", "END"}:
        return _Plan("commit")
    if first == "ROLLBACK":
        if "TO" in words:
            raise _Unsupported("savepoints are not supported")
        return _Plan("rollback")
    if first == "PRAGMA":
        text = "".join(t.text for t in tokens[code[1]:]).strip()
        match = re.fullmatch(r"(\w+)\s*(?:=\s*(.+?)|\((.+?)\))?\s*", text, flags=re.DOTALL)
        if not match:
            raise _Unsupported("pragma form is not supported")
        return _Plan("pragma", pragma=match.group(1).lower(),
                     value=(match.group(2) or match.group(3) or "").strip().strip("'\""))
    if first == "CREATE" and "TRIGGER" in words[1:3]:
        return _Plan("script", statements=_trigger(tokens), ddl=True, writes=True)
    if first == "DROP" and len(words) > 1 and words[1] == "TRIGGER":
        return _Plan("sql", sql=_drop_trigger(tokens), ddl=True, writes=True)
    ddl = first in {"CREATE", "DROP", "ALTER"}
    if first == "CREATE" and ("TABLE" in words[1:3]):
        paren = next(i for i in code if tokens[i].kind == "op" and tokens[i].text == "(")
        tokens = _column_types(tokens, paren)
    elif first == "ALTER" and "ADD" in words:
        add = next(i for i in code if tokens[i].up == "ADD")
        tokens = _column_types(tokens, _next_code(tokens, _next_code(tokens, add)))
    if first == "INSERT" and len(words) > 2 and words[1] == "OR":
        mode = words[2]
        if mode != "IGNORE":
            raise _Unsupported("INSERT OR " + mode + " is not supported")
        drop = {code[1], code[2]}
        tokens = [t for i, t in enumerate(tokens) if i not in drop]
        tokens.append(_Tok("word", " ON CONFLICT DO NOTHING"))
    tokens = _functions(tokens, params)
    if not ddl:
        tokens = _nulls_like_sqlite(tokens)
    rendered = _render(tokens, bind=bind)
    writes = first in {"INSERT", "UPDATE", "DELETE", "REPLACE"} or ddl
    return _Plan("sql", sql=rendered, ddl=ddl, writes=writes)


def adapt_params(params: object) -> object:
    if params is None:
        return None
    if isinstance(params, Mapping):
        return {k: _adapt(v) for k, v in params.items()}
    return tuple(_adapt(v) for v in params)


def _adapt(value: object) -> object:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, float) and not math.isfinite(value):
        return value
    if isinstance(value, memoryview):
        return bytes(value)
    return value


def _value(value: object) -> object:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, decimal.Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, memoryview):
        return bytes(value)
    return value


# ---------------------------------------------------------------- rows and cursors
class Row:
    """A result row that reads like ``sqlite3.Row`` (by index or any-case name)."""

    __slots__ = ("_keys", "_values")

    def __init__(self, keys: tuple[str, ...], values: tuple) -> None:
        self._keys = keys
        self._values = values

    def keys(self) -> list[str]:
        return list(self._keys)

    def __getitem__(self, item: int | str | slice) -> object:
        if isinstance(item, (int, slice)):
            return self._values[item]
        wanted = str(item).lower()
        for index, key in enumerate(self._keys):
            if key.lower() == wanted:
                return self._values[index]
        raise IndexError("No item with that key")

    def __iter__(self) -> Iterator[object]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Row):
            return self._keys == other._keys and self._values == other._values
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self._keys, self._values))

    def __repr__(self) -> str:
        return f"<consent storage row with {len(self._values)} values>"


class Cursor:
    """The result of one statement: rows are read into memory at once."""

    def __init__(self, rows: list, rowcount: int = -1, description=None) -> None:
        self._rows = rows
        self._index = 0
        self.rowcount = rowcount
        self.description = description
        self.lastrowid = None

    def fetchone(self):
        if self._index >= len(self._rows):
            return None
        row = self._rows[self._index]
        self._index += 1
        return row

    def fetchall(self) -> list:
        rows = self._rows[self._index:]
        self._index = len(self._rows)
        return rows

    def fetchmany(self, size: int = 1) -> list:
        rows = self._rows[self._index:self._index + max(1, int(size))]
        self._index += len(rows)
        return rows

    def __iter__(self):
        while True:
            row = self.fetchone()
            if row is None:
                return
            yield row

    def close(self) -> None:
        self._rows = []


# ---------------------------------------------------------------- errors
def _mapped_error(exc: BaseException) -> sqlite3.Error:
    """The ``sqlite3`` error a store already handles, without driver text."""
    sqlstate = str(getattr(exc, "sqlstate", "") or "")
    diag = getattr(exc, "diag", None)
    if sqlstate.startswith("23"):
        if sqlstate == "23000":
            # Raised by a translated trigger: its message is the store's own text.
            message = str(getattr(diag, "message_primary", "") or "constraint failed")
            return sqlite3.IntegrityError(message)
        constraint = str(getattr(diag, "constraint_name", "") or "")
        kinds = {"23505": "UNIQUE", "23503": "FOREIGN KEY", "23502": "NOT NULL",
                 "23514": "CHECK"}
        text = f"{kinds.get(sqlstate, 'constraint')} constraint failed"
        return sqlite3.IntegrityError(text + (f": {constraint}" if constraint else ""))
    if sqlstate in {"55P03", "57014", "40P01"}:
        return sqlite3.OperationalError("database is locked")
    if sqlstate == "25006":
        return sqlite3.OperationalError("attempt to write a readonly database")
    if sqlstate.startswith("08") or not sqlstate:
        return sqlite3.OperationalError("the shared consent database is unavailable")
    return sqlite3.OperationalError(f"shared consent database statement failed ({sqlstate})")


# ---------------------------------------------------------------- connection
_READY: set[str] = set()
_READY_LOCK = threading.Lock()


def driver_available() -> bool:
    """Whether the PostgreSQL driver (``maverick-core[postgres]``) is installed."""
    try:
        import psycopg  # noqa: F401
    except ImportError:
        return False
    return True


def _require_driver() -> None:
    if not driver_available():
        raise ConsentStorageError("shared consent storage requires maverick-core[postgres]")


class PostgresConsentConnection:
    """A consent store's connection to its own schema in shared Postgres."""

    def __init__(self, path: str | os.PathLike[str], *, dsn: str, timeout: float = 10.0,
                 read_only: bool = False, implicit_transactions: bool = False) -> None:
        _require_driver()
        from .postgres_transactions import PostgresTransactions

        self.schema = schema_name(path)
        self.logical_name = logical_name(path)
        self._lock = _lock_key(self.schema)
        self._implicit = implicit_transactions
        self._journal = "delete"
        self.row_factory: object = None
        self.isolation_level = "" if implicit_transactions else None
        try:
            self._pg = PostgresTransactions(dsn).connect()
            self._pg.autocommit = True
            import psycopg

            self._cursor = psycopg.ClientCursor(self._pg)
            wait_ms = max(100, min(int(float(timeout) * 1000), 600_000))
            self._raw("SELECT set_config('lock_timeout', %s, false)", (f"{wait_ms}ms",))
            self._ensure_schema()
            self._raw("SELECT set_config('search_path', %s, false)", (f'"{self.schema}"',))
            if read_only:
                self._raw("SET default_transaction_read_only = on")
        except sqlite3.Error:
            self._close_quietly()
            raise
        except Exception as exc:  # noqa: BLE001 - never surface connection details
            self._close_quietly()
            raise _mapped_error(exc) from None

    # -- plumbing
    def _raw(self, sql: str, params: object = None):
        self._cursor.execute(sql, params)
        return self._cursor

    def _close_quietly(self) -> None:
        pg = getattr(self, "_pg", None)
        if pg is not None:
            with contextlib.suppress(Exception):
                pg.close()

    def _ensure_schema(self) -> None:
        with _READY_LOCK:
            if self.schema in _READY:
                return
        self._raw("BEGIN")
        try:
            self._raw("SELECT pg_advisory_xact_lock(%s, %s)", (_LOCK_CLASS, 0))
            self._raw(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
            self._raw(f'COMMENT ON SCHEMA "{self.schema}" IS %s',
                      ("Lightwork consent store " + self.logical_name[:400],))
            self._raw(
                f'CREATE TABLE IF NOT EXISTS "{self.schema}".lw_sqlite_pragma ('
                "name TEXT PRIMARY KEY, value BIGINT NOT NULL)")
            self._raw(
                f'CREATE OR REPLACE VIEW "{self.schema}".sqlite_master AS '
                "SELECT CASE c.relkind WHEN 'i' THEN 'index' WHEN 'v' THEN 'view' "
                "ELSE 'table' END::text AS type, c.relname::text AS name, "
                "COALESCE(t.relname, c.relname)::text AS tbl_name, NULL::text AS sql "
                "FROM pg_class c LEFT JOIN pg_index x ON x.indexrelid = c.oid "
                "LEFT JOIN pg_class t ON t.oid = x.indrelid "
                f"WHERE c.relnamespace = '\"{self.schema}\"'::regnamespace "
                "AND c.relkind IN ('r', 'i') AND c.relname NOT LIKE 'lw\\_sqlite\\_%' "
                "UNION ALL SELECT 'trigger', tg.tgname::text, c.relname::text, NULL "
                "FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid "
                f"WHERE c.relnamespace = '\"{self.schema}\"'::regnamespace "
                "AND NOT tg.tgisinternal")
            self._raw("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                self._raw("ROLLBACK")
            raise
        with _READY_LOCK:
            _READY.add(self.schema)

    @property
    def in_transaction(self) -> bool:
        status = getattr(getattr(self._pg, "info", None), "transaction_status", None)
        return getattr(status, "name", "IDLE") in {"INTRANS", "INERROR", "ACTIVE"}

    def _begin(self) -> None:
        if self.in_transaction:
            raise sqlite3.OperationalError("cannot start a transaction within a transaction")
        self._raw("BEGIN")
        try:
            self._raw("SELECT pg_advisory_xact_lock(%s, %s)", (_LOCK_CLASS, self._lock))
        except BaseException:
            with contextlib.suppress(Exception):
                self._raw("ROLLBACK")
            raise

    def _rows(self) -> Cursor:
        cursor = self._cursor
        if cursor.description is None:
            return Cursor([], -1 if cursor.rowcount is None else cursor.rowcount)
        names = tuple(column.name for column in cursor.description)
        raw_rows = cursor.fetchall()
        if self.row_factory is sqlite3.Row:
            rows = [Row(names, tuple(_value(v) for v in r)) for r in raw_rows]
        elif callable(self.row_factory):
            rows = [self.row_factory(self, tuple(_value(v) for v in r)) for r in raw_rows]
        else:
            rows = [tuple(_value(v) for v in r) for r in raw_rows]
        return Cursor(rows, -1, cursor.description)

    def _run(self, sql: str, params: object) -> Cursor:
        """One translated statement; inside a transaction it cannot spoil it."""
        if self.in_transaction:
            self._raw("SAVEPOINT lw_statement")
            try:
                self._raw(sql, params)
                result = self._rows()
            except BaseException:
                with contextlib.suppress(Exception):
                    self._raw("ROLLBACK TO SAVEPOINT lw_statement")
                    self._raw("RELEASE SAVEPOINT lw_statement")
                raise
            self._raw("RELEASE SAVEPOINT lw_statement")
            return result
        self._raw(sql, params)
        return self._rows()

    # -- the sqlite3 surface the stores use
    def execute(self, sql: str, params: object = ()) -> Cursor:
        try:
            plan = translate(sql, params)
            return self._execute_plan(plan, params)
        except sqlite3.Error:
            raise
        except _Unsupported as exc:
            raise sqlite3.OperationalError(f"statement not supported: {exc}") from None
        except Exception as exc:  # noqa: BLE001 - redact driver diagnostics
            raise _mapped_error(exc) from None

    def _execute_plan(self, plan: _Plan, params: object) -> Cursor:  # noqa: C901
        if plan.kind == "noop":
            return Cursor([])
        if plan.kind == "begin":
            self._begin()
            return Cursor([])
        if plan.kind == "commit":
            if not self.in_transaction:
                raise sqlite3.OperationalError("cannot commit - no transaction is active")
            self._raw("COMMIT")
            return Cursor([])
        if plan.kind == "rollback":
            if not self.in_transaction:
                raise sqlite3.OperationalError("cannot rollback - no transaction is active")
            self._raw("ROLLBACK")
            return Cursor([])
        if plan.kind == "pragma":
            return self._pragma(plan.pragma, plan.value)
        if plan.kind == "script":
            return self._atomic_ddl(plan.statements)
        if plan.ddl and not self.in_transaction:
            return self._atomic_ddl((plan.sql,))
        if plan.writes and self._implicit and not self.in_transaction:
            self._begin()
        return self._run(plan.sql, adapt_params(params) if params else None)

    def _atomic_ddl(self, statements: Iterable[str]) -> Cursor:
        """Schema changes run under the store lock so servers never race them."""
        owned = not self.in_transaction
        if owned:
            self._begin()
        try:
            for statement in statements:
                self._run(statement, None)
            if owned:
                self._raw("COMMIT")
        except BaseException:
            if owned:
                with contextlib.suppress(Exception):
                    self._raw("ROLLBACK")
            raise
        return Cursor([])

    def _pragma(self, name: str, value: str) -> Cursor:
        if name == "table_info":
            table = value.strip().strip('"')
            self._raw(
                "SELECT ordinal_position - 1 AS cid, column_name AS name, data_type AS type, "
                "CASE WHEN is_nullable = 'NO' THEN 1 ELSE 0 END AS notnull, "
                "column_default AS dflt_value, 0 AS pk FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = %s "
                "ORDER BY ordinal_position", (table,))
            return self._rows()
        if name == "journal_mode":
            if value:
                self._journal = value.lower()
            return self._single("journal_mode", self._journal)
        if name == "user_version":
            if value:
                self._run("INSERT INTO lw_sqlite_pragma (name, value) VALUES ('user_version', %s) "
                          "ON CONFLICT (name) DO UPDATE SET value = excluded.value", (int(value),))
                return Cursor([])
            self._raw("SELECT value FROM lw_sqlite_pragma WHERE name = 'user_version'")
            row = self._cursor.fetchone()
            return self._single("user_version", int(row[0]) if row else 0)
        if name in {"quick_check", "integrity_check"}:
            return self._single(name, "ok")
        if name == "query_only":
            if value.upper() in {"ON", "1", "TRUE", "YES"}:
                self._raw("SET default_transaction_read_only = on")
            return Cursor([])
        return Cursor([])

    def _single(self, name: str, value: object) -> Cursor:
        if self.row_factory is sqlite3.Row:
            return Cursor([Row((name,), (value,))])
        return Cursor([(value,)])

    def executemany(self, sql: str, seq_of_params: Iterable[object]) -> Cursor:
        total = 0
        for params in seq_of_params:
            cursor = self.execute(sql, params)
            total += max(0, cursor.rowcount)
        return Cursor([], total)

    def executescript(self, script: str) -> Cursor:
        if self.in_transaction:
            self.execute("COMMIT")
        statements = split_statements(script)
        explicit = any(re.match(r"\s*(BEGIN|COMMIT|END|ROLLBACK)\b", s, flags=re.IGNORECASE)
                       for s in statements)
        if explicit:
            for statement in statements:
                self.execute(statement)
            return Cursor([])
        self.execute("BEGIN IMMEDIATE")
        try:
            for statement in statements:
                self.execute(statement)
            self.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                if self.in_transaction:
                    self._raw("ROLLBACK")
            raise
        return Cursor([])

    def commit(self) -> None:
        if self.in_transaction:
            self.execute("COMMIT")

    def rollback(self) -> None:
        if self.in_transaction:
            self.execute("ROLLBACK")

    def close(self) -> None:
        if getattr(self, "_pg", None) is None:
            return
        with contextlib.suppress(Exception):
            if self.in_transaction:
                self._raw("ROLLBACK")
        self._close_quietly()
        self._pg = None

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()

    def __enter__(self) -> PostgresConsentConnection:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # ``with connection:`` in sqlite3 commits or rolls back; it never closes.
        if self.in_transaction:
            self.execute("ROLLBACK" if exc_type is not None else "COMMIT")


def connect(path: str | os.PathLike[str], *, timeout: float = 10.0, read_only: bool = False,
            implicit_transactions: bool = False) -> PostgresConsentConnection:
    """Open the shared-database connection for the store file ``path``."""
    chosen = selection()
    if not chosen.shared:
        raise ConsentStorageError("consent records are kept in files on this server")
    return PostgresConsentConnection(path, dsn=chosen.dsn, timeout=timeout, read_only=read_only,
                                     implicit_transactions=implicit_transactions)


@contextlib.contextmanager
def authority_connection(path, *, ensure_directory, ensure_file, foreign_keys: bool = True):
    """Open an authority's private file or shared connection under its policy."""
    from .data_use_sqlite import private_connection
    from .sqlite_authority import configure_authority_connection

    if not shared():
        with private_connection(path, ensure_directory=ensure_directory,
                                ensure_file=ensure_file, foreign_keys=foreign_keys) as connection:
            yield connection
        return
    connection = connect(path, timeout=10.0)
    try:
        configure_authority_connection(connection, foreign_keys=foreign_keys)
        yield connection
    finally:
        connection.close()


@contextlib.contextmanager
def reading(path: str | os.PathLike[str]) -> Iterator[Any]:
    """Read-only access to a store: its private file here, or its shared schema."""
    if shared():
        connection: Any = connect(path, timeout=5.0, read_only=True)
    else:
        from .file_lock import ensure_private_file

        ensure_private_file(path, 0o600)
        connection = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True,
                                     timeout=5.0)
    try:
        yield connection
    finally:
        connection.close()


def read_only_connection(path: str | os.PathLike[str]):
    """A read-only connection to a store, or None when it has no file here."""
    if shared():
        return connect(path, timeout=5.0, read_only=True)
    local = Path(path)
    if not local.is_file():
        return None
    return sqlite3.connect(f"{local.resolve().as_uri()}?mode=ro", uri=True, timeout=5.0)


def store_exists(path: str | os.PathLike[str]) -> bool:
    """Whether the store has records: its file, or its schema in shared Postgres."""
    if not shared():
        return Path(path).is_file()
    try:
        connection = connect(path, timeout=5.0, read_only=True)
    except (ConsentStorageError, sqlite3.Error):
        return False
    try:
        row = connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'").fetchone()
        return bool(row and row[0])
    finally:
        connection.close()


# ---------------------------------------------------------------- moving local records
_MOVE_BATCH = 500
_MAX_MOVE_FILES = 5000


class MoveRefused(ConsentStorageError):
    """Records could not be moved safely; the originals were kept (plain words)."""


def local_store_files() -> list[Path]:
    """Every workspace's consent store files under the Lightwork home."""
    from .paths import maverick_home

    home = maverick_home().expanduser()
    found: list[Path] = []
    folders = [home / name for name in DATA_FOLDERS]
    tenants = home / "tenants"
    if tenants.is_dir():
        folders.extend(sorted(p / name for p in tenants.iterdir() if p.is_dir()
                              for name in DATA_FOLDERS))
    for folder in folders:
        if folder.is_dir():
            found.extend(sorted(p for p in folder.glob("*.sqlite3") if p.is_file()))
        if len(found) > _MAX_MOVE_FILES:
            raise MoveRefused("There are too many consent store files to move at once.")
    return found


def _workspace(path: Path) -> str:
    parts = Path(logical_name(path)).parts
    return parts[1] if len(parts) > 3 and parts[0] == "tenants" else ""


def _source_tables(source: sqlite3.Connection) -> list[tuple[str, str]]:
    rows = source.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
        "ORDER BY rowid").fetchall()
    return [(str(name), str(sql)) for name, sql in rows if sql]


def _source_extras(source: sqlite3.Connection) -> list[str]:
    rows = source.execute(
        "SELECT sql FROM sqlite_master WHERE type IN ('index', 'trigger') AND sql IS NOT NULL "
        "ORDER BY rowid").fetchall()
    return [str(sql) for (sql,) in rows]


def _open_source(path: Path) -> sqlite3.Connection:
    source = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=30.0)
    source.execute("PRAGMA query_only = ON")
    return source


def _quoted(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", name):
        raise MoveRefused("A consent store has a table name Lightwork does not recognise.")
    return f'"{name}"'


def _if_not_exists(sql: str) -> str:
    return re.sub(r"^\s*CREATE\s+(UNIQUE\s+)?(TABLE|INDEX|TRIGGER)\s+(?!IF\s+NOT\s+EXISTS)",
                  lambda m: f"CREATE {m.group(1) or ''}{m.group(2)} IF NOT EXISTS ",
                  sql, count=1, flags=re.IGNORECASE)


def _canonical_row(values: Sequence[object]) -> tuple:
    out = []
    for value in values:
        value = _value(value)
        if isinstance(value, float) and value.is_integer() and abs(value) < 2 ** 53:
            value = int(value)
        out.append(value)
    return tuple(out)


def preview_move() -> dict[str, Any]:
    """What a move would copy: each store file, its records, and the target."""
    stores = []
    total = 0
    chosen = selection()
    for path in local_store_files():
        entry: dict[str, Any] = {"workspace": _workspace(path), "store": path.stem,
                                 "records": 0, "state": "ready"}
        try:
            source = _open_source(path)
            try:
                for table, _sql in _source_tables(source):
                    entry["records"] += int(source.execute(
                        f"SELECT count(*) FROM {_quoted(table)}").fetchone()[0])
            finally:
                source.close()
        except (sqlite3.Error, MoveRefused):
            entry["state"] = "unreadable"
        if chosen.shared and entry["state"] == "ready":
            entry["state"] = _target_state(path)
        total += entry["records"]
        stores.append(entry)
    return {"shared": chosen.shared, "stores": stores, "records": total}


def _target_state(path: Path) -> str:
    try:
        target = connect(path, timeout=10.0, read_only=True)
    except (ConsentStorageError, sqlite3.Error):
        return "unavailable"
    try:
        source = _open_source(path)
        try:
            state = "ready"
            same = True
            for table, _sql in _source_tables(source):
                exists = target.execute(
                    "SELECT 1 FROM information_schema.tables WHERE table_schema = "
                    "current_schema() AND table_name = ?", (table,)).fetchone()
                if exists is None:
                    same = False
                    continue
                count = int(target.execute(f"SELECT count(*) FROM {_quoted(table)}").fetchone()[0])
                expected = int(source.execute(
                    f"SELECT count(*) FROM {_quoted(table)}").fetchone()[0])
                if count != expected:
                    same = False
                if count and count > expected:
                    state = "has_records"
            return "moved" if same else state
        finally:
            source.close()
    except (sqlite3.Error, MoveRefused):
        return "unavailable"
    finally:
        target.close()


def _copy_table(source: sqlite3.Connection, target: PostgresConsentConnection, table: str) -> int:
    quoted = _quoted(table)
    columns = [str(row[1]) for row in source.execute(f"PRAGMA table_info({quoted})")]
    names = ", ".join(_quoted(c) for c in columns)
    existing = {
        _canonical_row(tuple(row))
        for row in target.execute(f"SELECT {names} FROM {quoted}").fetchall()
    }
    source_rows: set[tuple] = set()
    insert = (f"INSERT INTO {quoted} ({names}) VALUES ({', '.join('?' for _ in columns)})")
    copied = 0
    cursor = source.execute(f"SELECT {names} FROM {quoted}")
    while batch := cursor.fetchmany(_MOVE_BATCH):
        for row in batch:
            canonical = _canonical_row(tuple(row))
            source_rows.add(canonical)
            if canonical in existing:
                continue
            # One all-or-nothing transaction: a failure ends the whole store's copy.
            target._raw(translate(insert, tuple(row)).sql, adapt_params(tuple(row)))
            copied += 1
    if not existing <= source_rows:
        raise MoveRefused("The shared database already holds different consent records for "
                          "this workspace, so nothing was copied for it.")
    after = {
        _canonical_row(tuple(row))
        for row in target.execute(f"SELECT {names} FROM {quoted}").fetchall()
    }
    if after != source_rows:
        raise MoveRefused("The copied consent records did not match the originals, so nothing "
                          "was copied for this workspace.")
    qualified = f'"{target.schema}".{quoted}'
    for column in columns:
        sequence = target._raw("SELECT pg_get_serial_sequence(%s, %s)",
                               (qualified, column)).fetchone()
        if sequence and sequence[0]:
            highest = target._raw(f"SELECT max({_quoted(column)}) FROM {quoted}").fetchone()
            if highest and highest[0] is not None:
                target._raw("SELECT setval(%s, %s)", (sequence[0], int(highest[0])))
    return copied


def move_store(path: Path) -> dict[str, Any]:
    """Copy one store file into its schema: all or nothing, originals kept."""
    target = connect(path, timeout=60.0)
    try:
        target.row_factory = sqlite3.Row
        source = _open_source(path)
        try:
            tables = _source_tables(source)
            preference_store = {
                "consent_meta", "consent_profiles", "consent_receipts", "consent_outbox"
            } <= {table for table, _sql in tables}
            for _table, sql in tables:
                target.execute(_if_not_exists(sql))
            for sql in _source_extras(source):
                target.execute(_if_not_exists(sql))
            target.execute("BEGIN IMMEDIATE")
            copied = 0
            try:
                target._raw("SET CONSTRAINTS ALL DEFERRED")
                if preference_store:
                    # Startup may have initialized an empty shared target.
                    # Recompute this derived marker from the copied source;
                    # otherwise it is an extra row and can suppress backfill.
                    target.execute(
                        "DELETE FROM consent_meta WHERE key = 'restoration_floor_backfill_v1'"
                    )
                for table, _sql in tables:
                    target._raw(f"ALTER TABLE {_quoted(table)} DISABLE TRIGGER USER")
                for table, _sql in tables:
                    copied += _copy_table(source, target, table)
                for table, _sql in tables:
                    target._raw(f"ALTER TABLE {_quoted(table)} ENABLE TRIGGER USER")
                if preference_store:
                    from .consent_preferences import ConsentPreferenceStore

                    ConsentPreferenceStore._ensure_restoration_floor_schema(target)
                    ConsentPreferenceStore._backfill_restoration_floors(
                        target, clock=time.time
                    )
                version = int(source.execute("PRAGMA user_version").fetchone()[0])
                if version:
                    target.execute(f"PRAGMA user_version={version}")
                target.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    target._raw("ROLLBACK")
                raise
        finally:
            source.close()
    finally:
        target.close()
    return {"workspace": _workspace(path), "store": path.stem, "copied": copied}


def move_local_records() -> dict[str, Any]:
    """Copy every workspace's consent store files into the shared database.

    Each store is copied in one transaction under its store lock (live writers
    wait), only into an empty store or one that already holds exactly these
    records, and every row is compared after the copy. The files on this
    server are never changed.
    """
    if not shared():
        raise MoveRefused("Consent records are kept in files on this server. Choose the shared "
                          "database for consent records and restart Lightwork first.")
    moved: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    started = time.time()
    for path in local_store_files():
        try:
            moved.append(move_store(path))
        except MoveRefused as exc:
            refused.append({"workspace": _workspace(path), "store": path.stem,
                            "reason": str(exc)})
        except (sqlite3.Error, ConsentStorageError):
            refused.append({"workspace": _workspace(path), "store": path.stem,
                            "reason": "This store could not be copied; its file was kept."})
    return {"moved": moved, "refused": refused,
            "copied": sum(int(m["copied"]) for m in moved),
            "seconds": round(time.time() - started, 3)}


__all__ = [
    "BACKENDS", "BACKEND_ENV", "DEFAULT_DSN_ENV", "ConsentStorageError", "Cursor", "MoveRefused",
    "PostgresConsentConnection", "Row", "StorageSelection", "adapt_params", "connect",
    "driver_available", "dsn_env_name", "local_store_files", "logical_name", "move_local_records", "move_store",
    "preview_move", "read_only_connection", "reading", "schema_name", "selection", "shared", "split_statements", "storage_settings",
    "store_exists", "translate",
]
