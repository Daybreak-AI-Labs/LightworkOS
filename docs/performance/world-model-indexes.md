# World-model indexes

The SQLite world model indexes the queries that run on every agent turn,
monitor refresh or recall lookup, where a full table scan is felt immediately
on a database that has accumulated goals. Schema version 8 (`MIGRATIONS[8]` in
`packages/maverick-core/maverick/world_model.py`) added the four compound
indexes below; existing databases pick them up on next open.

## Indexes for the hot queries

| Index | Columns | Read paths it serves |
|-------|---------|----------------------|
| `idx_episodes_goal_started` | `episodes(goal_id, started_at DESC)` | `WorldModel.list_episodes(goal_id=...)` |
| `idx_episodes_started` | `episodes(started_at DESC)` | `WorldModel.list_episodes()` |
| `idx_goals_status_updated` | `goals(status, updated_at DESC)` | Active-goal lookup (`WorldModel.inflight_goal`, used by `monitor._resolve_active_goal`) and recall candidates (`WorldModel.candidate_goals`, used by `tools/recall.py`) |
| `idx_goals_parent` | `goals(parent_id, created_at)` | `WorldModel.subgoals` (used by `monitor._fetch_subgoals`) |

When these indexes were added, `EXPLAIN QUERY PLAN` against a synthetic
database with 50k goals, 100k episodes and 1M goal_events showed each of these
queries moving from a full scan plus sort to an index search. The
episodes-by-goal and recall-candidate queries went from 200–400 ms cold
(30–80 ms warm) to sub-millisecond. SQLite chooses a plan from the schema, the
data and its statistics, so check the plan on your own database (below) rather
than assuming it.

## Other indexes

Earlier schema versions added these, and they remain in use:

- `idx_goals_status         ON goals(status)`
- `idx_goals_updated_at     ON goals(updated_at)`
- `idx_episodes_ended_at    ON episodes(ended_at)`
- `idx_goal_events_goal_id_id  ON goal_events(goal_id, id)`
- `idx_goal_events_ts       ON goal_events(ts)`
- `idx_conversations_last_seen  ON conversations(last_seen)`
- `idx_turns_conv_id        ON turns(conversation_id, id)`
- `idx_attachments_goal_id  ON attachments(goal_id)`

`idx_goals_status` and `idx_goals_updated_at` each cover part of the common
pattern of filtering by status and sorting by `updated_at`; the compound
`idx_goals_status_updated` covers both in a single seek and range scan when the
planner chooses it. The single-column indexes remain for queries that use just
one of the columns. `WHERE goal_id = ? AND id > ?` lookups on `goal_events` are
already served by `idx_goal_events_goal_id_id`.

## Checking a query plan

Run `EXPLAIN QUERY PLAN` against a copy of your world database. Opening it with
`WorldModel` applies any pending migrations to the copy first.

```python
import sys
from maverick.world_model import WorldModel

w = WorldModel(sys.argv[1])  # path to a copy of your world database
queries = [
    ("SELECT id FROM episodes WHERE goal_id = ? ORDER BY started_at DESC LIMIT 10", (1,)),
    ("SELECT id FROM goals WHERE parent_id = ? ORDER BY created_at ASC LIMIT 50", (1,)),
]
for sql, params in queries:
    print(sql)
    for row in w.conn.execute("EXPLAIN QUERY PLAN " + sql, params):
        print("  ", row["detail"])
```

## Migration safety

The version 8 migration only adds indexes, and `CREATE INDEX IF NOT EXISTS` is
idempotent, so a partially applied migration completes cleanly on the next
open. SQLite builds each index when the statement runs, so the first open after
upgrading a large database takes longer while the indexes are built.

## Related

- Partitioning the `goal_events` table by `goal_id` range is not implemented.
