"""DuckDB analytics over the world model.

DuckDB is the wrong tool for the agent's *live transactional* store: it is an
OLAP engine, and the world model is a concurrent OLTP write path that SQLite
(WAL) / Postgres serve correctly.
What DuckDB is genuinely great at is the **analytics** over that history:
percentiles, time-bucketed spend, ad-hoc ``GROUP BY`` across thousands of
goals — queries that are verbose and slow in hand-rolled Python.

So this is the DuckDB layer that earns its keep: load the world model's goals
and episodes into an in-memory DuckDB (no extension download, fully offline)
and run analytical SQL. Ad-hoc queries are constrained to a single
``SELECT``/``WITH`` subquery, capped at a bounded number of returned rows, and
run with DuckDB external file access disabled. Behind the ``[duckdb]`` extra.
"""

from __future__ import annotations

import threading

#: Question pieces a person picks from; every one maps to a fixed SQL fragment,
#: so :meth:`WorldAnalytics.ask` never splices caller text into a query.
METRICS = {
    "spend": "sum(e.cost)",
    "tasks": "count(DISTINCT e.goal_id)",
    "runs": "count(*)",
    "tokens": "sum(e.in_tok + e.out_tok)",
    "spend_per_task": "sum(e.cost) / nullif(count(DISTINCT e.goal_id), 0)",
}
GROUPS = {
    "none": ("'all'", False),
    "day": ("strftime(to_timestamp(e.ended_at), '%Y-%m-%d')", True),
    "week": ("strftime(date_trunc('week', to_timestamp(e.ended_at)), '%Y-%m-%d')", True),
    "month": ("strftime(to_timestamp(e.ended_at), '%Y-%m')", True),
    "status": ("coalesce(g.status, 'unknown')", False),
    "outcome": ("coalesce(e.outcome, 'unknown')", False),
    "task": ("CAST(e.goal_id AS VARCHAR) || ' ' || coalesce(g.title, '')", False),
}


class WorldAnalytics:
    """In-memory DuckDB loaded from the world model, for analytical queries."""

    def __init__(self, world, *, limit: int = 100000, query_limit: int = 10000, conn=None):
        try:
            import duckdb
        except ImportError as e:
            raise ImportError(
                "duckdb not installed. Run: python -m pip install -e './packages/maverick-core[duckdb]'"
            ) from e
        self._conn = conn or duckdb.connect(":memory:", config={"enable_external_access": "false"})
        self._query_limit = max(1, int(query_limit))
        self._disable_external_access()
        self._load(world, limit)

    def _disable_external_access(self) -> None:
        """Disable DuckDB file/network access for ad-hoc analytical SQL."""
        self._conn.execute("SET enable_external_access=false")

    def _load(self, world, limit: int) -> None:
        self._conn.execute("CREATE TABLE goals(id BIGINT, title VARCHAR, status VARCHAR)")
        self._conn.execute(
            "CREATE TABLE episodes(goal_id BIGINT, cost DOUBLE, in_tok BIGINT, "
            "out_tok BIGINT, outcome VARCHAR, ended_at DOUBLE)"
        )
        goals = list(world.list_goals(limit=limit))
        if goals:
            self._conn.executemany(
                "INSERT INTO goals VALUES (?, ?, ?)",
                [(g.id, getattr(g, "title", "") or "", getattr(g, "status", None)) for g in goals],
            )
        from .world_model import episodes_by_goal_batch

        erows = []
        batch = episodes_by_goal_batch(world, [g.id for g in goals], per_goal=limit)
        for g in goals:
            for e in (batch[g.id] if batch is not None and g.id in batch
                      else world.list_episodes(goal_id=g.id, limit=limit)):
                erows.append(
                    (
                        g.id,
                        float(getattr(e, "cost_dollars", 0.0) or 0.0),
                        int(getattr(e, "input_tokens", 0) or 0),
                        int(getattr(e, "output_tokens", 0) or 0),
                        getattr(e, "outcome", None),
                        float(getattr(e, "ended_at", 0.0) or 0.0),
                    )
                )
        if erows:
            self._conn.executemany("INSERT INTO episodes VALUES (?, ?, ?, ?, ?, ?)", erows)

    def query(self, sql: str, params: list | None = None, *,
              timeout: float | None = None) -> list[dict]:
        """Run a **read-only** analytical query; returns a list of row dicts.

        ``params`` bind ``?`` placeholders in ``sql``. ``timeout`` (seconds)
        interrupts a query still running at the deadline and raises
        ``TimeoutError`` -- the bound a shared server puts on ad-hoc SQL."""
        query_sql = (sql or "").strip().removesuffix(";").rstrip()
        s = query_sql.lstrip("(").lstrip()
        if not s.lower().startswith(("select", "with")):
            raise ValueError("only SELECT / WITH queries are allowed")
        self._require_single_select(query_sql)
        expired = threading.Event()
        timer = None
        if timeout is not None:
            def _expire() -> None:
                expired.set()
                self._conn.interrupt()
            timer = threading.Timer(max(0.01, float(timeout)), _expire)
            timer.daemon = True
            timer.start()
        try:
            cur = self._conn.execute(
                "SELECT * FROM (" + query_sql + ") AS maverick_query LIMIT ?",
                [*(params or []), self._query_limit],
            )
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
        except Exception as exc:
            if expired.is_set():
                raise TimeoutError("the query took too long and was stopped") from exc
            raise
        finally:
            if timer is not None:
                timer.cancel()
        return [dict(zip(cols, row, strict=False)) for row in rows]

    def _require_single_select(self, query_sql: str) -> None:
        """Refuse text that parses as anything but one SELECT: a ``)`` that
        closes the wrapper would otherwise smuggle further statements (writes,
        ``SET``, an unlimited last SELECT) past the prefix check."""
        import duckdb

        extract = getattr(self._conn, "extract_statements", None)
        if extract is None:  # older duckdb: no parser access, refuse any separator
            if ";" in query_sql:
                raise ValueError("only SELECT / WITH queries are allowed, one at a time")
            return
        statements = extract(query_sql)
        if len(statements) != 1 or statements[0].type != duckdb.StatementType.SELECT:
            raise ValueError("only SELECT / WITH queries are allowed, one at a time")

    def ask(self, metric: str, group: str = "none", *, since: float | None = None,
            until: float | None = None, limit: int = 100,
            timeout: float | None = None) -> list[dict]:
        """Answer one picked question: ``metric`` (a :data:`METRICS` key)
        broken down by ``group`` (a :data:`GROUPS` key) over runs that ended
        in ``[since, until)`` (Unix seconds; either end optional).

        Returns ``[{"group": label, "value": number}]`` -- time groups in date
        order, the others largest first. Unknown picks raise ``ValueError``;
        nothing the caller passes becomes SQL text."""
        if metric not in METRICS:
            raise ValueError(f"unknown metric {metric!r}")
        if group not in GROUPS:
            raise ValueError(f"unknown grouping {group!r}")
        label, by_time = GROUPS[group]
        where, params = [], []
        if by_time or since is not None or until is not None:
            where.append("e.ended_at > 0")
        if since is not None:
            where.append("e.ended_at >= ?")
            params.append(float(since))
        if until is not None:
            where.append("e.ended_at < ?")
            params.append(float(until))
        order = "grp" if by_time else "val DESC NULLS LAST, grp"
        sql = (
            f"SELECT {label} AS grp, {METRICS[metric]} AS val "
            "FROM episodes e LEFT JOIN goals g ON g.id = e.goal_id"
            + (" WHERE " + " AND ".join(where) if where else "")
            + f" GROUP BY grp ORDER BY {order} LIMIT {max(1, min(int(limit), 1000))}"
        )
        rows = self.query(sql, params, timeout=timeout)
        return [{"group": r["grp"], "value": r["val"]} for r in rows]

    def cost_percentiles(self) -> dict:
        rows = self.query(
            "WITH per_goal AS (SELECT goal_id, sum(cost) c FROM episodes "
            "GROUP BY goal_id HAVING sum(cost) > 0) "
            "SELECT count(*) AS n, "
            "  coalesce(percentile_cont(0.5) WITHIN GROUP (ORDER BY c), 0) AS p50, "
            "  coalesce(percentile_cont(0.9) WITHIN GROUP (ORDER BY c), 0) AS p90, "
            "  coalesce(percentile_cont(0.99) WITHIN GROUP (ORDER BY c), 0) AS p99, "
            "  coalesce(max(c), 0) AS max_cost FROM per_goal"
        )
        return rows[0] if rows else {}

    def top_goals(self, n: int = 10) -> list[dict]:
        return self.query(
            "SELECT g.id AS id, g.title AS title, sum(e.cost) AS total_cost, "
            "count(*) AS ep_count "
            "FROM episodes e JOIN goals g ON g.id = e.goal_id "
            "GROUP BY g.id, g.title HAVING sum(e.cost) > 0 "
            f"ORDER BY total_cost DESC LIMIT {max(1, int(n))}"
        )

    def daily_cost(self) -> list[dict]:
        return self.query(
            "SELECT strftime(to_timestamp(ended_at), '%Y-%m-%d') AS bucket, "
            "sum(cost) AS spend FROM episodes WHERE ended_at > 0 "
            "GROUP BY bucket ORDER BY bucket"
        )

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # pragma: no cover
            pass


__all__ = ["GROUPS", "METRICS", "WorldAnalytics"]
