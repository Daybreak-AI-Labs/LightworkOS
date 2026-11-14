"""Indexed history for released organization receipts; no unresolved holds.

The caller holds provider_admission's strict store lock. SQLite commits history
before the hot JSON removes it; duplicates after a crash prefer the hot record.
History is retained for replay/checkpoint identity and is never TTL-expired.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager

from ..file_lock import atomic_create_text, ensure_private_file
from ..paths import data_dir


@contextmanager
def _database(tenant, *, create=False):
    path = data_dir('usage', 'provider_history.sqlite3', tenant=tenant)
    marker = path.with_suffix('.required')
    if not path.exists():
        if marker.exists():
            raise ValueError('organization provider history is missing')
        if not create:
            yield None
            return
        try:
            atomic_create_text(path, '')
        except FileExistsError:
            pass
    ensure_private_file(path)
    connection = sqlite3.connect(path, timeout=30)
    try:
        if not create and connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='calls'"
        ).fetchone() is None:
            # Created but the schema never written (a crash between the two
            # steps): it holds no history. Reading it must not block every
            # provider call; the next compact finishes the creation.
            yield None
            return
        if create:
            connection.executescript('''
                CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, scope TEXT NOT NULL, data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS runs_scope ON runs(scope);
                CREATE TABLE IF NOT EXISTS calls (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS calls_run ON calls(run_id);
                CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, data TEXT NOT NULL);
            ''')
            try:
                atomic_create_text(marker, 'organization provider history v1\n')
            except FileExistsError:
                ensure_private_file(marker)
        yield connection
    finally:
        connection.close()


def include(tenant, data, *, run_ids=(), key=None, scopes=()):
    """Load only requested history; hot records are always authoritative."""
    with _database(tenant) as db:
        if db is None:
            return
        identities = set(run_ids)
        requested_scopes = set(scopes)
        if key:
            row = db.execute('SELECT run_id FROM calls WHERE id=?', (key,)).fetchone()
            if row:
                identities.add(row[0])
        for identity in identities.copy():
            row = db.execute('SELECT scope FROM runs WHERE id=?', (identity,)).fetchone()
            if row:
                requested_scopes.add(row[0])
        for scope in requested_scopes:
            identities.update(row[0] for row in db.execute('SELECT id FROM runs WHERE scope=?', (scope,)))
            row = db.execute('SELECT data FROM plans WHERE id=?', (scope,)).fetchone()
            if row:
                data['plans'].setdefault(scope, json.loads(row[0]))
        for identity in identities:
            row = db.execute('SELECT data FROM runs WHERE id=?', (identity,)).fetchone()
            if row:
                data['runs'].setdefault(identity, json.loads(row[0]))
            for call_id, raw in db.execute('SELECT id,data FROM calls WHERE run_id=?', (identity,)):
                data['calls'].setdefault(call_id, json.loads(raw))


def compact(tenant, data):
    """Move fully acknowledged scopes out of the bounded pending-hold store."""
    pending = {data['runs'][call['run_id']]['scope'] for call in data['calls'].values()
               if not call['released']}
    scopes = {run['scope'] for run in data['runs'].values()} - pending
    identities = {identity for identity, run in data['runs'].items() if run['scope'] in scopes}
    if not identities:
        return
    calls = {key: call for key, call in data['calls'].items() if call['run_id'] in identities}
    with _database(tenant, create=True) as db, db:
        for identity in identities:
            run = data['runs'][identity]
            db.execute('INSERT OR REPLACE INTO runs VALUES(?,?,?)',
                       (identity, run['scope'], json.dumps(run, allow_nan=False)))
        for key, call in calls.items():
            db.execute('INSERT OR REPLACE INTO calls VALUES(?,?,?)',
                       (key, call['run_id'], json.dumps(call, allow_nan=False)))
        for scope in scopes:
            if scope in data['plans']:
                db.execute('INSERT OR REPLACE INTO plans VALUES(?,?)',
                           (scope, json.dumps(data['plans'][scope], allow_nan=False)))
    for identity in identities:
        del data['runs'][identity]
    for key in calls:
        del data['calls'][key]
    for scope in scopes:
        data['plans'].pop(scope, None)
