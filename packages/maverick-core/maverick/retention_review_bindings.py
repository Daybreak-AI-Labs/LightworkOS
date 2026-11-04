"""Private candidate seals checked while native retention owns its writer lock.

Only fixed native record columns are scanned; neither rows nor their seals
belong in customer-facing activity. Large reviews refuse before any deletion.
"""
from __future__ import annotations

import hashlib
import json


class RetentionReviewChanged(RuntimeError):
    pass


_COLUMNS = {
    "episodes": "id,goal_id,started_at,ended_at,summary,outcome,cost_dollars,input_tokens,output_tokens,tool_calls,cache_read_tokens,cache_write_tokens",
    "goal_events": "id,goal_id,agent,kind,content,ts",
    "messages": "id,goal_id,role,content,ts",
}
MAX_ROWS = 100_000
MAX_BYTES = 16 * 1024 * 1024


def seal(rows):
    count, size, value = 0, 0, hashlib.sha256()
    for row in rows:
        count += 1
        if sum(len(value) for value in row if isinstance(value, str)) > MAX_BYTES:
            raise RetentionReviewChanged("This record is too large for a safe review. No deletion started.")
        encoded = json.dumps(list(row), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        size += len(encoded)
        if count > MAX_ROWS or size > MAX_BYTES:
            raise RetentionReviewChanged("This store is too large for one safe review. Choose a longer retention period, save it and preview again.")
        value.update(len(encoded).to_bytes(8, "big"))
        value.update(encoded)
    return {"count": count, "digest": value.hexdigest()}


def check(binding, current, *, dry_run):
    if dry_run:
        binding.update(current)
    elif binding != current:
        raise RetentionReviewChanged("The eligible records changed after preview. No new deletion started for this store; preview again.")


def guard_sql(connection, table, predicate, params, binding, *, dry_run, postgres=False):
    if binding is None:
        return
    columns = _COLUMNS[table]  # closed native tables, never caller SQL
    if not dry_run:
        if postgres:
            # These reservations include the owning-goal tenant predicate and
            # block phantoms/changes until the native deletion commits.
            connection.execute("SET LOCAL lock_timeout = '5s'")
            connection.execute(f"LOCK TABLE goals, {table} IN SHARE ROW EXCLUSIVE MODE")
        elif not connection.in_transaction:
            connection.execute("BEGIN IMMEDIATE")
        else:
            connection.execute(f"UPDATE {table} SET id=id WHERE 0")
    cursor = connection.execute(f"SELECT {columns} FROM {table} WHERE {predicate} ORDER BY id LIMIT {MAX_ROWS + 1}", params)
    if postgres:
        cursor = connection
    check(binding, seal(cursor), dry_run=dry_run)


def file_seal(path):
    value, size = hashlib.sha256(), 0
    with path.open("rb") as source:
        for part in iter(lambda: source.read(1024 * 1024), b""):
            size += len(part)
            if size > MAX_BYTES:
                raise RetentionReviewChanged("This activity file is too large for a safe review. No deletion started.")
            value.update(part)
    return {"bytes": size, "digest": value.hexdigest()}
