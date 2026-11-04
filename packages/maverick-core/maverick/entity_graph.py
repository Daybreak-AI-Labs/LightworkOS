"""The entity graph -- one resolved identity per real-world thing, and typed,
time-bounded edges derived from the records the platform already governs.

The memory layers exist (episodic ``world_model``, semantic ``fleet_memory`` /
``assessment_memory``, procedural ``procedural_memory``, consolidation in
``dreaming``), but they are silos: "Acme Corp" in a DPA review, in a paper
redline, in a security vendor assessment, and in an assessment subject are four
unlinked strings. This module is the connective tissue -- the spine that says
they are ONE vendor, and the edges that say who reviewed what, what was found,
who decided, and *when each fact became true*.

Three design rules, each load-bearing:

* **The graph is an index, never a source of truth.** Every node and edge is
  derived from a governed record and carries that record's id. ``rebuild()``
  regenerates the whole graph from the stores at any time, so the graph can
  never disagree with the records -- delete it and nothing is lost. That is
  also why there is no write API: you change the graph by changing records.
* **Derived, not designed.** No ontology committee: entity kinds and edge
  types fall out of the record schemas that already exist. A missing edge is
  acceptable; a *fabricated* one is not, so linking is exact-canonical only
  (case/punctuation-insensitive), never fuzzy.
* **Time on every edge.** ``valid_from`` is the record's own timestamp and a
  superseded review's edge is closed at its successor's birth, so
  ``as_of(ts)`` reconstructs what the company knew at any past moment -- the
  question a regulator actually asks ("what did you know when you signed?").

The three acceptance queries this exists to answer:

1. :func:`why` -- walk an approval back to its evidence: decision -> reviewer
   -> reviews in force at decision time -> clause findings -> documents, every
   hop citing a record id.
2. :func:`dossier` with ``as_of`` -- the point-in-time picture of a vendor.
3. :func:`blast_radius` -- reverse reachability: this clause/document turned
   out bad; which reviews, vendors, and decisions relied on it?

SQLite (WAL) under ``data_dir("entity_graph")``, stdlib only. The episodic
plane joins on exact keys only -- episode -> goal (foreign key), goal ->
agent (``goal.domain`` names the pack) and owner -- and the procedural plane
joins through ``source_goal_ids``, the goal ids the distiller now stamps into
each learned skill's frontmatter. A goal's TITLE is prose and is never
matched against vendors or systems; a skill distilled before provenance
stamping reads as provenance-unknown rather than guessed. That closes the
memory-integrity loop: "this run turned out to be tainted -- which learned
skills depend on it?" is :func:`blast_radius` on the goal.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
import sqlite3
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

# Entity kinds the deriver emits. A record node is an entity too -- lineage is
# record -> concept, so both ends must be nodes.
CONCEPT_KINDS = ("vendor", "system", "person", "document", "clause", "agent")
RECORD_KINDS = ("assessment", "dpa_review", "paper_review",
                "security_review", "ai_system", "dsar", "incident",
                "goal", "episode", "skill")

# The inventory projection is deliberately closed.  If a future graph builder
# emits a new relationship, inventory reconciliation reports the graph as
# unavailable until this vocabulary is reviewed; it must never silently turn
# arbitrary stored text into a public relationship type.
RELATION_KINDS = (
    "answered_by",
    "approved_by",
    "assesses",
    "assigned_to",
    "clause_conflicting",
    "clause_missing",
    "clause_present",
    "clause_unclear",
    "concerns_subject",
    "covers_document",
    "decided_by",
    "distilled_from",
    "from_assessment",
    "owned_by",
    "part_of",
    "performed_by",
    "produced_redline",
    "provided_by",
    "registers",
    "rejected_by",
    "reported_by",
    "reviewed_by",
    "reviews",
    "sent_back_by",
    "supersedes",
    "supports",
)

INVENTORY_PROVENANCE_SCHEMA = "lightwork.entity-graph-inventory-provenance.v1"
INVENTORY_ENTITY_SCHEMA = "lightwork.shared-governance-inventory-entity.v1"
INVENTORY_RELATIONSHIP_SCHEMA = (
    "lightwork.shared-governance-inventory-relationship.v1"
)

_DEFAULT_STALENESS_SECONDS = 60.0
_MAX_EDGES_PER_RECORD = 64
_LOCK = threading.Lock()


# --------------------------------------------------------------------------- #
# config / storage
# --------------------------------------------------------------------------- #

def _config() -> dict:
    try:
        from .config import load_config
        return (load_config() or {}).get("entity_graph") or {}
    except Exception:  # pragma: no cover -- config read never breaks the graph
        return {}


def enabled() -> bool:
    """On by default: a read-only derived index adds capability, not risk.
    ``[entity_graph] enable = false`` switches every entry point to a no-op."""
    value = _config().get("enable", True)
    return str(value).strip().lower() not in ("0", "false", "no", "off")


def _db_path() -> Path:
    from .paths import data_dir
    return data_dir("entity_graph") / "graph.db"


def _connect(path: Path | None = None) -> sqlite3.Connection:
    target = path or _db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
    except BaseException:
        conn.close()
        raise
    return conn


_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    canonical TEXT NOT NULL,
    display TEXT NOT NULL,
    UNIQUE (kind, canonical)
);
CREATE TABLE IF NOT EXISTS aliases (
    entity_id INTEGER NOT NULL REFERENCES entities(id),
    alias TEXT NOT NULL,
    UNIQUE (entity_id, alias)
);
CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY,
    src INTEGER NOT NULL REFERENCES entities(id),
    rel TEXT NOT NULL,
    dst INTEGER NOT NULL REFERENCES entities(id),
    record_type TEXT NOT NULL,
    record_id TEXT NOT NULL,
    valid_from REAL NOT NULL,
    valid_to REAL,
    detail TEXT NOT NULL DEFAULT '',
    UNIQUE (src, rel, dst, record_type, record_id)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _canonical(name: str) -> str:
    """Case/punctuation-insensitive identity: 'Acme Corp.' == 'acme corp'.
    Exact after normalisation -- never fuzzy, because a wrong merge fabricates
    lineage."""
    return re.sub(r"[^a-z0-9]+", " ", (name or "").lower()).strip()


# --------------------------------------------------------------------------- #
# the derivation pass
# --------------------------------------------------------------------------- #

class _Builder:
    """One rebuild transaction: entity interning + edge emission."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self._ids: dict[tuple[str, str], int] = {}

    def entity(self, kind: str, name: str,
               display: str | None = None) -> int | None:
        """Intern one entity. ``display`` overrides the human label while the
        identity stays keyed on ``name`` -- used for goals, whose stable key is
        the numeric id but whose readable face is the title."""
        raw = str(name or "").strip()
        canonical = _canonical(raw)
        if not canonical:
            return None
        shown = str(display or raw).strip() or raw
        key = (kind, canonical)
        eid = self._ids.get(key)
        if eid is None:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO entities(kind, canonical, display) "
                "VALUES (?, ?, ?)", (kind, canonical, shown))
            if cur.lastrowid:
                eid = cur.lastrowid
            else:
                eid = self.conn.execute(
                    "SELECT id FROM entities WHERE kind=? AND canonical=?",
                    key).fetchone()["id"]
            self._ids[key] = eid
        self.conn.execute(
            "INSERT OR IGNORE INTO aliases(entity_id, alias) VALUES (?, ?)",
            (eid, raw))
        return eid

    def edge(self, src: int | None, rel: str, dst: int | None, *,
             record_type: str, record_id: str, valid_from: float,
             detail: str = "") -> None:
        if src is None or dst is None or not valid_from:
            return
        self.conn.execute(
            "INSERT OR IGNORE INTO edges"
            "(src, rel, dst, record_type, record_id, valid_from, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (src, rel, dst, record_type, record_id, float(valid_from),
             str(detail)[:200]))


# Assessment templates whose subject is a vendor rather than an internal
# system. Everything else stays "system" -- a wrong kind is a wrong merge.
_VENDOR_SUBJECT_TYPES = frozenset({"vendor_risk"})

_IGNORED_ACTORS = frozenset({"", "system", "local:dashboard"})


def _person(b: _Builder, actor: str) -> int | None:
    label = str(actor or "").strip()
    if label.lower() in _IGNORED_ACTORS:
        return None
    return b.entity("person", label)


def _derive_assessments(b: _Builder) -> None:
    from .assessment import list_saved, load_saved
    for row in list_saved():
        record = load_saved(str(row.get("id") or "")) or {}
        rid = str(record.get("id") or "")
        created = float(record.get("created_at") or 0)
        if not rid or not created:
            continue
        node = b.entity("assessment", rid)
        subject_kind = ("vendor" if record.get("type") in _VENDOR_SUBJECT_TYPES
                        else "system")
        b.edge(node, "assesses", b.entity(subject_kind, record.get("subject")),
               record_type="assessment", record_id=rid, valid_from=created,
               detail=str(record.get("type") or ""))
        decided = float(record.get("decided_at") or 0)
        status = str(record.get("status") or "")
        if decided and status in ("approved", "rejected"):
            b.edge(node, f"{status}_by",
                   _person(b, record.get("decided_by")),
                   record_type="assessment", record_id=rid,
                   valid_from=decided)
        assigned = float(record.get("assigned_at") or 0)
        if assigned and record.get("assignee"):
            b.edge(node, "assigned_to", _person(b, record.get("assignee")),
                   record_type="assessment", record_id=rid,
                   valid_from=assigned)
        for f in (record.get("followups") or [])[:_MAX_EDGES_PER_RECORD]:
            answered = float(f.get("answered_at") or 0)
            if answered and f.get("answered_by"):
                b.edge(node, "answered_by", _person(b, f.get("answered_by")),
                       record_type="assessment", record_id=rid,
                       valid_from=answered)


def _derive_privacy(b: _Builder) -> None:
    try:
        from . import privacy_ops
        sources = privacy_ops.graph_source_records()
    except Exception as e:  # pragma: no cover -- privacy plane optional
        log.debug("entity_graph: privacy sources unavailable: %s", e)
        return
    _derive_dpa_reviews(b, sources.get("dpa_reviews", ()))
    _derive_paper_reviews(b, sources.get("paper_reviews", ()))
    _derive_registry_and_intake(b, sources)


def _derive_dpa_reviews(b: _Builder, records) -> None:
    for record in records:
        rid = str(record.get("id") or "")
        created = float(record.get("created_at") or 0)
        if not rid or not created:
            continue
        node = b.entity("dpa_review", rid)
        b.edge(node, "reviews", b.entity("vendor", record.get("vendor")),
               record_type="dpa_review", record_id=rid, valid_from=created)
        b.edge(node, "reviewed_by", _person(b, record.get("reviewed_by")),
               record_type="dpa_review", record_id=rid, valid_from=created)
        if record.get("document_name"):
            b.edge(node, "covers_document",
                   b.entity("document", record.get("document_name")),
                   record_type="dpa_review", record_id=rid,
                   valid_from=created)
        for clause in (record.get("clauses") or [])[:_MAX_EDGES_PER_RECORD]:
            status = str(clause.get("status") or "")
            if clause.get("key") and status:
                b.edge(node, f"clause_{status}",
                       b.entity("clause", clause.get("key")),
                       record_type="dpa_review", record_id=rid,
                       valid_from=created,
                       detail=str(clause.get("severity") or ""))

def _derive_paper_reviews(b: _Builder, records) -> None:
    for record in records:
        rid = str(record.get("id") or "")
        created = float(record.get("created_at") or 0)
        if not rid or not created:
            continue
        node = b.entity("paper_review", rid)
        b.edge(node, "reviews", b.entity("vendor", record.get("vendor")),
               record_type="paper_review", record_id=rid, valid_from=created,
               detail=str(record.get("instrument") or ""))
        b.edge(node, "reviewed_by", _person(b, record.get("reviewed_by")),
               record_type="paper_review", record_id=rid, valid_from=created)
        if record.get("document_name"):
            b.edge(node, "covers_document",
                   b.entity("document", record.get("document_name")),
                   record_type="paper_review", record_id=rid,
                   valid_from=created)
        if record.get("redline_filename"):
            b.edge(node, "produced_redline",
                   b.entity("document", record.get("redline_filename")),
                   record_type="paper_review", record_id=rid,
                   valid_from=created)
        if record.get("assessment_id"):
            b.edge(node, "supports",
                   b.entity("assessment", record.get("assessment_id")),
                   record_type="paper_review", record_id=rid,
                   valid_from=created)
        for c in (record.get("concerns") or [])[:_MAX_EDGES_PER_RECORD]:
            status = str(c.get("status") or "")
            if c.get("clause_key") and status:
                b.edge(node, f"clause_{status}",
                       b.entity("clause", c.get("clause_key")),
                       record_type="paper_review", record_id=rid,
                       valid_from=created,
                       detail=str(c.get("severity") or ""))

def _derive_registry_and_intake(b: _Builder, sources: dict) -> None:
    for record in sources.get("ai_systems", ()):
        rid = str(record.get("id") or "")
        created = float(record.get("created_at") or 0)
        if not rid or not created:
            continue
        node = b.entity("ai_system", rid)
        b.edge(node, "registers", b.entity("system", record.get("name")),
               record_type="ai_system", record_id=rid, valid_from=created,
               detail=str(record.get("tier") or ""))
        if record.get("provider"):
            b.edge(node, "provided_by",
                   b.entity("vendor", record.get("provider")),
                   record_type="ai_system", record_id=rid, valid_from=created)
        b.edge(node, "owned_by", _person(b, record.get("owner")),
               record_type="ai_system", record_id=rid, valid_from=created)
        if record.get("assessment_id"):
            b.edge(node, "from_assessment",
                   b.entity("assessment", record.get("assessment_id")),
                   record_type="ai_system", record_id=rid, valid_from=created)

    for record in sources.get("dsars", ()):
        rid = str(record.get("id") or "")
        created = float(record.get("created_at") or 0)
        if not rid or not created:
            continue
        node = b.entity("dsar", rid)
        b.edge(node, "concerns_subject",
               _person(b, record.get("subject_id")),
               record_type="dsar", record_id=rid, valid_from=created,
               detail=str(record.get("kind") or ""))

    for record in sources.get("incidents", ()):
        rid = str(record.get("id") or "")
        created = float(record.get("created_at") or 0)
        if not rid or not created:
            continue
        node = b.entity("incident", rid)
        b.edge(node, "reported_by", _person(b, record.get("reported_by")),
               record_type="incident", record_id=rid, valid_from=created,
               detail=str(record.get("severity") or ""))


def _derive_security(b: _Builder) -> None:
    try:
        from .security_ops import list_vendor_assessments
        records = list_vendor_assessments()
    except Exception as e:  # pragma: no cover -- security plane optional
        log.debug("entity_graph: security sources unavailable: %s", e)
        return
    for record in records:
        rid = str(record.get("id") or "")
        created = float(record.get("created_at") or 0)
        if not rid or not created:
            continue
        node = b.entity("security_review", rid)
        b.edge(node, "reviews", b.entity("vendor", record.get("name")),
               record_type="security_review", record_id=rid,
               valid_from=created,
               detail=str(record.get("residual_risk") or ""))
        b.edge(node, "owned_by", _person(b, record.get("owner")),
               record_type="security_review", record_id=rid,
               valid_from=created)
        decision = record.get("decision") or {}
        decided = float(decision.get("decided_at") or 0)
        choice = str(decision.get("decision") or "")
        if decided and choice:
            rel = {"approved": "approved_by", "rejected": "rejected_by",
                   "needs_work": "sent_back_by"}.get(choice, "decided_by")
            b.edge(node, rel, _person(b, decision.get("decided_by")),
                   record_type="security_review", record_id=rid,
                   valid_from=decided)


def _derive_world(b: _Builder) -> None:
    """The episodic ring, on exact keys only: every episode belongs to a goal
    (foreign key), every goal names the specialist pack that ran it
    (``goal.domain``) and its owner. A goal's TITLE is prose and is never
    matched against vendors/systems -- that would fabricate lineage."""
    try:
        # Through the backend factory, never WorldModel() directly: a
        # Postgres-backed tenant's graph must read the world that tenant
        # actually runs on (the repo's factory guard enforces this).
        from .world_model import open_world
        world = open_world()
        goals = world.list_goals(limit=5000)
        episodes = world.list_episodes(limit=5000)
    except Exception as e:  # pragma: no cover -- world plane optional
        log.debug("entity_graph: world sources unavailable: %s", e)
        return
    goal_nodes: dict[int, int | None] = {}
    for g in goals:
        gid = int(getattr(g, "id", 0) or 0)
        created = float(getattr(g, "created_at", 0) or 0)
        if not gid or not created:
            continue
        title = str(getattr(g, "title", "") or "")[:120]
        node = b.entity("goal", str(gid),
                        display=f"#{gid} {title}".strip())
        goal_nodes[gid] = node
        if getattr(g, "domain", ""):
            b.edge(node, "performed_by", b.entity("agent", g.domain),
                   record_type="goal", record_id=str(gid),
                   valid_from=created,
                   detail=str(getattr(g, "status", "") or ""))
        if getattr(g, "owner", ""):
            b.edge(node, "owned_by", _person(b, g.owner),
                   record_type="goal", record_id=str(gid),
                   valid_from=created)
    for ep in episodes:
        eid = int(getattr(ep, "id", 0) or 0)
        gid = int(getattr(ep, "goal_id", 0) or 0)
        started = float(getattr(ep, "started_at", 0) or 0)
        if not eid or not started or gid not in goal_nodes:
            continue
        cost = float(getattr(ep, "cost_dollars", 0) or 0)
        outcome = str(getattr(ep, "outcome", "") or "")
        b.edge(b.entity("episode", f"ep-{eid}"), "part_of", goal_nodes[gid],
               record_type="episode", record_id=str(eid),
               valid_from=started,
               detail=f"{outcome} ${cost:.2f}".strip())


_FRONTMATTER_ID_RE = re.compile(r"^source_goal_ids:\s*([0-9 ]+)\s*$")
_FRONTMATTER_AT_RE = re.compile(r"^distilled_at:\s*(\S+)\s*$")


def _derive_skills(b: _Builder) -> None:
    """The procedural ring: learned skills, linked to the exact goals they
    were distilled from (``source_goal_ids`` in the SKILL.md frontmatter,
    stamped by the distiller). A skill written before that key existed gets a
    node but no source edges -- provenance-unknown, stated honestly rather
    than guessed. This is what makes 'this run was tainted; which learned
    skills depend on it?' a graph query."""
    import calendar
    try:
        from .paths import data_dir
        # Distillation resolves its default store through the active tenant.
        # Read the identical namespace here: forcing the legacy/shared root
        # makes a tenant's learned skills invisible to its own graph and risks
        # indexing unrelated root-level skills instead.
        store = data_dir("learned-skills")
        paths = sorted(store.glob("*.md"))
    except Exception as e:  # pragma: no cover -- skills plane optional
        log.debug("entity_graph: skill store unavailable: %s", e)
        return
    for path in paths[:2000]:
        try:
            head = path.read_text(encoding="utf-8", errors="ignore")[:4000]
        except OSError:
            continue
        gids: list[int] = []
        stamped = 0.0
        for line in head.splitlines()[:40]:
            m = _FRONTMATTER_ID_RE.match(line)
            if m:
                gids = [int(x) for x in m.group(1).split()][:16]
            m = _FRONTMATTER_AT_RE.match(line)
            if m:
                try:
                    stamped = calendar.timegm(time.strptime(
                        m.group(1), "%Y-%m-%dT%H:%M:%SZ"))
                except ValueError:
                    stamped = 0.0
        valid_from = stamped or (path.stat().st_mtime if path.exists() else 0)
        node = b.entity("skill", path.stem)
        for gid in gids:
            b.edge(node, "distilled_from", b.entity("goal", str(gid)),
                   record_type="skill", record_id=path.stem,
                   valid_from=valid_from)


def _close_superseded(conn: sqlite3.Connection) -> None:
    """A newer review of the same vendor+family closes its predecessor's
    ``reviews`` edge and gains a ``supersedes`` edge, so ``as_of`` returns the
    review that was actually current at any past instant.

    Family = instrument for paper reviews (their versioning key) and document
    name for DPA reviews (a review of a different document runs in parallel,
    not in succession)."""
    rows = conn.execute(
        "SELECT e.id AS edge_id, e.src, e.dst, e.record_type, e.record_id, "
        "       e.valid_from, e.detail "
        "FROM edges e WHERE e.rel = 'reviews' "
        "AND e.record_type IN ('paper_review', 'dpa_review') "
        "ORDER BY e.valid_from").fetchall()

    def family(row: sqlite3.Row) -> tuple:
        if row["record_type"] == "paper_review":
            return (row["record_type"], row["dst"], row["detail"])
        doc = conn.execute(
            "SELECT dst FROM edges WHERE rel='covers_document' "
            "AND record_type=? AND record_id=?",
            (row["record_type"], row["record_id"])).fetchone()
        return (row["record_type"], row["dst"], doc["dst"] if doc else None)

    chains: dict[tuple, sqlite3.Row] = {}
    for row in rows:
        key = family(row)
        prev = chains.get(key)
        if prev is not None and row["valid_from"] > prev["valid_from"]:
            conn.execute("UPDATE edges SET valid_to=? WHERE id=?",
                         (row["valid_from"], prev["edge_id"]))
            conn.execute(
                "INSERT OR IGNORE INTO edges"
                "(src, rel, dst, record_type, record_id, valid_from, detail) "
                "VALUES (?, 'supersedes', ?, ?, ?, ?, '')",
                (row["src"], prev["src"], row["record_type"],
                 row["record_id"], row["valid_from"]))
        chains[key] = row


def rebuild() -> dict:
    """Regenerate the whole graph from the governed stores. Idempotent; the
    result can only ever say what the records say."""
    if not enabled():
        return {"enabled": False, "entities": 0, "edges": 0}
    with _LOCK:
        conn = _connect()
        try:
            conn.executescript(_SCHEMA)
            with conn:
                conn.execute("DELETE FROM edges")
                conn.execute("DELETE FROM aliases")
                conn.execute("DELETE FROM entities")
                b = _Builder(conn)
                _derive_assessments(b)
                _derive_privacy(b)
                _derive_security(b)
                _derive_world(b)
                _derive_skills(b)
                _close_superseded(conn)
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) "
                    "VALUES ('rebuilt_at', ?)", (str(time.time()),))
            entities = conn.execute(
                "SELECT COUNT(*) AS n FROM entities").fetchone()["n"]
            edges = conn.execute(
                "SELECT COUNT(*) AS n FROM edges").fetchone()["n"]
            return {"enabled": True, "entities": entities, "edges": edges}
        finally:
            conn.close()


def refresh(max_age_seconds: float | None = None) -> None:
    """Rebuild when the index is older than the staleness window. Cheap by
    design: the graph is small (thousands of records), so correctness beats
    incremental cleverness."""
    if not enabled():
        return
    window = (float(_config().get("staleness_seconds",
                                  _DEFAULT_STALENESS_SECONDS))
              if max_age_seconds is None else max_age_seconds)
    conn = _connect()
    try:
        conn.executescript(_SCHEMA)
        row = conn.execute(
            "SELECT value FROM meta WHERE key='rebuilt_at'").fetchone()
    finally:
        conn.close()
    age = time.time() - float(row["value"]) if row else None
    if age is None or age > window:
        rebuild()


# --------------------------------------------------------------------------- #
# queries
# --------------------------------------------------------------------------- #

def _resolve(conn: sqlite3.Connection, kind: str, name: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM entities WHERE kind=? AND canonical=?",
        (kind, _canonical(name))).fetchone()


def _valid_clause(as_of: float | None) -> tuple[str, tuple]:
    if as_of is None:
        return "", ()
    return (" AND valid_from <= ? AND (valid_to IS NULL OR valid_to > ?)",
            (as_of, as_of))


def _edge_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    ends = {eid: conn.execute("SELECT * FROM entities WHERE id=?",
                              (eid,)).fetchone()
            for eid in (row["src"], row["dst"])}
    return {
        "src": {"kind": ends[row["src"]]["kind"],
                "name": ends[row["src"]]["display"]},
        "rel": row["rel"],
        "dst": {"kind": ends[row["dst"]]["kind"],
                "name": ends[row["dst"]]["display"]},
        "record_type": row["record_type"],
        "record_id": row["record_id"],
        "valid_from": row["valid_from"],
        "valid_to": row["valid_to"],
        "detail": row["detail"],
    }


def neighborhood(kind: str, name: str, *, depth: int = 2,
                 as_of: float | None = None) -> dict:
    """Breadth-first slice around one entity: the nodes and provenance-carrying
    edges within ``depth`` hops, optionally as the graph stood at ``as_of``."""
    if not enabled():
        return {"enabled": False, "found": False, "nodes": [], "edges": []}
    refresh()
    conn = _connect()
    try:
        start = _resolve(conn, kind, name)
        if start is None:
            return {"enabled": True, "found": False, "nodes": [], "edges": []}
        cond, params = _valid_clause(as_of)
        seen = {start["id"]}
        frontier = [start["id"]]
        edges: list[sqlite3.Row] = []
        edge_ids: set[int] = set()
        for _ in range(max(1, min(int(depth), 4))):
            if not frontier:
                break
            marks = ",".join("?" * len(frontier))
            rows = conn.execute(
                f"SELECT * FROM edges WHERE (src IN ({marks}) "
                f"OR dst IN ({marks})){cond}",
                (*frontier, *frontier, *params)).fetchall()
            frontier = []
            for row in rows:
                if row["id"] in edge_ids:
                    continue
                edge_ids.add(row["id"])
                edges.append(row)
                for eid in (row["src"], row["dst"]):
                    if eid not in seen:
                        seen.add(eid)
                        frontier.append(eid)
        marks = ",".join("?" * len(seen))
        nodes = conn.execute(
            f"SELECT * FROM entities WHERE id IN ({marks})",
            tuple(seen)).fetchall()
        return {
            "enabled": True, "found": True,
            "entity": {"kind": start["kind"], "name": start["display"]},
            "nodes": [{"kind": n["kind"], "name": n["display"]}
                      for n in nodes],
            "edges": [_edge_dict(conn, e) for e in edges],
        }
    finally:
        conn.close()


def dossier(vendor: str, *, as_of: float | None = None) -> dict:
    """Everything the graph knows about one vendor in one governed query --
    the context pack an agent (or a reviewer) opens a case with."""
    hood = neighborhood("vendor", vendor, depth=2, as_of=as_of)
    if not hood.get("found"):
        return hood
    edges = hood["edges"]
    reviews = [e for e in edges if e["rel"] == "reviews"]
    # With no historical cutoff, only open-ended review edges are in force.
    # With ``as_of``, neighborhood() has already removed every edge that was
    # not valid at that instant, including reviews superseded before it.  A
    # review that was superseded *later* is therefore current for this view
    # even though its stored ``valid_to`` is non-null today.
    in_force_reviews = [
        e for e in reviews if as_of is not None or e["valid_to"] is None
    ]
    in_force_review_keys = {
        (e["record_type"], e["record_id"]) for e in in_force_reviews
    }
    open_gaps = sorted({
        e["dst"]["name"] for e in edges
        if e["rel"] in ("clause_missing", "clause_conflicting",
                        "clause_unclear")
        and (e["record_type"], e["record_id"]) in in_force_review_keys})
    return {
        **hood,
        "summary": {
            "reviews": [{"record_type": e["record_type"],
                         "record_id": e["record_id"],
                         "current": e in in_force_reviews,
                         "since": e["valid_from"]} for e in reviews],
            "decisions": [
                {"decision": e["rel"].removesuffix("_by"),
                 "by": e["dst"]["name"], "at": e["valid_from"],
                 "record_type": e["record_type"],
                 "record_id": e["record_id"]}
                for e in edges
                if e["rel"] in ("approved_by", "rejected_by", "sent_back_by")],
            "open_clause_gaps": open_gaps,
            "documents": sorted({e["dst"]["name"] for e in edges
                                 if e["rel"] in ("covers_document",
                                                 "produced_redline")}),
            "people": sorted({e["dst"]["name"] for e in edges
                              if e["dst"]["kind"] == "person"}),
        },
    }


def why(vendor: str) -> dict:
    """The regulator's first question: *why did you approve this vendor?*

    Finds the latest decision touching the vendor and walks it back to its
    evidence: the deciding record, the reviewer, every review in force at
    decision time, each clause finding, and the documents behind them -- every
    hop citing the record id a human can pull."""
    hood = neighborhood("vendor", vendor, depth=2)
    if not hood.get("found"):
        return hood
    edges = hood["edges"]
    decisions = sorted(
        (e for e in edges
         if e["rel"] in ("approved_by", "rejected_by", "sent_back_by")),
        key=lambda e: e["valid_from"])
    if not decisions:
        return {**hood, "decision": None,
                "chain": [], "note": "no decision recorded for this vendor"}
    latest = decisions[-1]
    decided_at = latest["valid_from"]
    chain = [{
        "step": "decision",
        "what": f"{latest['rel'].removesuffix('_by')} by "
                f"{latest['dst']['name']}",
        "record_type": latest["record_type"],
        "record_id": latest["record_id"],
        "at": decided_at,
    }]
    in_force = [e for e in edges if e["rel"] == "reviews"
                and e["valid_from"] <= decided_at
                and (e["valid_to"] is None or e["valid_to"] > decided_at)]
    for review in in_force:
        chain.append({
            "step": "evidence_in_force",
            "what": f"{review['record_type']} of {review['dst']['name']}",
            "record_type": review["record_type"],
            "record_id": review["record_id"],
            "at": review["valid_from"],
        })
        for e in edges:
            if e["record_id"] != review["record_id"]:
                continue
            if e["rel"].startswith("clause_"):
                chain.append({
                    "step": "clause_finding",
                    "what": f"{e['dst']['name']}: "
                            f"{e['rel'].removeprefix('clause_')}"
                            + (f" ({e['detail']})" if e["detail"] else ""),
                    "record_type": e["record_type"],
                    "record_id": e["record_id"],
                    "at": e["valid_from"],
                })
            elif e["rel"] in ("covers_document", "produced_redline"):
                chain.append({
                    "step": "document",
                    "what": e["dst"]["name"],
                    "record_type": e["record_type"],
                    "record_id": e["record_id"],
                    "at": e["valid_from"],
                })
            elif e["rel"] == "reviewed_by":
                chain.append({
                    "step": "reviewer",
                    "what": e["dst"]["name"],
                    "record_type": e["record_type"],
                    "record_id": e["record_id"],
                    "at": e["valid_from"],
                })
    return {"enabled": True, "found": True,
            "entity": hood["entity"],
            "decision": chain[0], "chain": chain}


def blast_radius(kind: str, name: str) -> dict:
    """This thing turned out to be bad -- what relied on it?

    Reverse reachability from a clause or document: the records that touched
    it, then the vendors and decisions those records support. The compliance
    version of a product recall."""
    if not enabled():
        return {"enabled": False, "found": False}
    refresh()
    conn = _connect()
    try:
        start = _resolve(conn, kind, name)
        if start is None:
            return {"enabled": True, "found": False, "records": [],
                    "vendors": [], "decisions": []}
        touching = conn.execute(
            "SELECT * FROM edges WHERE dst=?", (start["id"],)).fetchall()
        record_keys = {(e["record_type"], e["record_id"]) for e in touching}
        records, vendors, decisions = [], set(), []
        for rtype, rid in sorted(record_keys):
            rows = conn.execute(
                "SELECT * FROM edges WHERE record_type=? AND record_id=?",
                (rtype, rid)).fetchall()
            entry = {"record_type": rtype, "record_id": rid,
                     "via": sorted({e["rel"] for e in rows
                                    if e["dst"] == start["id"]})}
            records.append(entry)
            for e in rows:
                d = _edge_dict(conn, e)
                if d["rel"] == "reviews":
                    vendors.add(d["dst"]["name"])
                    # Decisions live on records POINTING AT this vendor:
                    # assessments via `assesses`, review records via `reviews`.
                    hits = conn.execute(
                        "SELECT * FROM edges WHERE rel IN "
                        "('approved_by','rejected_by','sent_back_by') "
                        "AND src IN (SELECT src FROM edges WHERE "
                        "rel IN ('reviews','assesses') AND dst=?)",
                        (e["dst"],)).fetchall()
                    for h in hits:
                        decisions.append(_edge_dict(conn, h))
        unique_decisions = list({(d["record_type"], d["record_id"],
                                  d["rel"]): d for d in decisions}.values())
        return {"enabled": True, "found": True,
                "entity": {"kind": start["kind"], "name": start["display"]},
                "records": records,
                "vendors": sorted(vendors),
                # The memory-integrity cut: learned skills whose lineage
                # includes this entity (a tainted goal reaches the skills it
                # taught via their distilled_from edges).
                "skills": sorted({r["record_id"] for r in records
                                  if r["record_type"] == "skill"}),
                "decisions": [
                    {"decision": d["rel"].removesuffix("_by"),
                     "by": d["dst"]["name"], "at": d["valid_from"],
                     "record_type": d["record_type"],
                     "record_id": d["record_id"]} for d in unique_decisions]}
    finally:
        conn.close()


def stats() -> dict:
    """Index size + freshness, for doctor/status surfaces."""
    if not enabled():
        return {"enabled": False}
    conn = _connect()
    try:
        conn.executescript(_SCHEMA)
        row = conn.execute(
            "SELECT value FROM meta WHERE key='rebuilt_at'").fetchone()
        return {
            "enabled": True,
            "entities": conn.execute(
                "SELECT COUNT(*) AS n FROM entities").fetchone()["n"],
            "edges": conn.execute(
                "SELECT COUNT(*) AS n FROM edges").fetchone()["n"],
            "rebuilt_at": float(row["value"]) if row else None,
        }
    finally:
        conn.close()


class EntityGraphInventoryError(RuntimeError):
    """The exact, minimized inventory projection cannot be established."""


def _inventory_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise EntityGraphInventoryError(
            "entity_graph_integrity_unverified"
        ) from exc


def _inventory_ref(key: bytes, value: object) -> str:
    return hmac.new(key, _inventory_json(value), hashlib.sha256).hexdigest()


def _inventory_bound(value: object, label: str, upper: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= upper
    ):
        raise EntityGraphInventoryError(f"{label}_invalid")
    return value


def inventory_provenance_manifest(  # noqa: C901 - explicit closed projection validation
    *,
    tenant_id: str,
    reference_key: bytes,
    max_entities: int = 10_000,
    max_relationships: int = 20_000,
) -> dict[str, object]:
    """Return a bounded, digest-only projection of exact graph provenance.

    Names, aliases, record ids and relationship detail never leave the graph.
    Stable tenant-keyed HMAC references let successive inventory snapshots join
    exact identities without permitting fuzzy identity resolution or exposing
    low-entropy names through an unhashed dictionary-attack surface.

    The graph's source readers historically treat optional source failures as
    an empty plane.  Consequently this projection *never* promotes itself to
    complete: it reports ``source_completeness_unverified`` even when every
    stored graph row verifies.  The shared inventory can use the lineage while
    preserving that important limitation.
    """

    from .file_lock import ensure_private_file
    from .paths import canonical_tenant_id, data_dir, tenant_scope

    tenant = canonical_tenant_id(tenant_id)
    if not isinstance(reference_key, bytes) or len(reference_key) < 32:
        raise EntityGraphInventoryError("entity_graph_reference_key_invalid")
    entity_limit = _inventory_bound(max_entities, "max_entities", 100_000)
    relationship_limit = _inventory_bound(
        max_relationships,
        "max_relationships",
        200_000,
    )

    try:
        with tenant_scope(tenant=tenant):
            result = rebuild()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise EntityGraphInventoryError("entity_graph_unavailable") from exc
    if result.get("enabled") is not True:
        raise EntityGraphInventoryError("entity_graph_disabled")

    path = data_dir("entity_graph", "graph.db", tenant=tenant)
    try:
        ensure_private_file(path)
        conn = _connect(path)
    except (OSError, sqlite3.Error) as exc:
        raise EntityGraphInventoryError("entity_graph_unavailable") from exc

    try:
        conn.executescript(_SCHEMA)
        meta = conn.execute(
            "SELECT value FROM meta WHERE key='rebuilt_at'"
        ).fetchone()
        if meta is None:
            raise EntityGraphInventoryError("entity_graph_head_unavailable")
        try:
            rebuilt_at = float(meta["value"])
        except (TypeError, ValueError) as exc:
            raise EntityGraphInventoryError(
                "entity_graph_head_unavailable"
            ) from exc
        if not math.isfinite(rebuilt_at) or rebuilt_at <= 0:
            raise EntityGraphInventoryError("entity_graph_head_unavailable")

        entity_count = int(
            conn.execute("SELECT COUNT(*) AS n FROM entities").fetchone()["n"]
        )
        relationship_count = int(
            conn.execute("SELECT COUNT(*) AS n FROM edges").fetchone()["n"]
        )

        # Commit to the complete graph in bounded memory, including aliases
        # that influence exact identity and every private field omitted below.
        authority = hmac.new(reference_key, digestmod=hashlib.sha256)

        def commit(label: str, row: tuple[object, ...]) -> None:
            encoded = _inventory_json([label, *row])
            authority.update(len(encoded).to_bytes(8, "big"))
            authority.update(encoded)

        cursor = conn.execute(
            "SELECT id,kind,canonical,display FROM entities "
            "ORDER BY kind,canonical,id"
        )
        for row in cursor:
            if row["kind"] not in CONCEPT_KINDS + RECORD_KINDS:
                raise EntityGraphInventoryError(
                    "entity_graph_schema_unrecognized"
                )
            commit(
                "entity",
                (row["id"], row["kind"], row["canonical"], row["display"]),
            )
        cursor = conn.execute(
            "SELECT entity_id,alias FROM aliases ORDER BY entity_id,alias"
        )
        for row in cursor:
            commit("alias", (row["entity_id"], row["alias"]))
        cursor = conn.execute(
            "SELECT id,src,rel,dst,record_type,record_id,valid_from,"
            "valid_to,detail FROM edges ORDER BY id"
        )
        for row in cursor:
            if (
                row["rel"] not in RELATION_KINDS
                or row["record_type"] not in RECORD_KINDS
                or not isinstance(row["record_id"], str)
                or not row["record_id"]
            ):
                raise EntityGraphInventoryError(
                    "entity_graph_schema_unrecognized"
                )
            commit(
                "relationship",
                (
                    row["id"],
                    row["src"],
                    row["rel"],
                    row["dst"],
                    row["record_type"],
                    row["record_id"],
                    row["valid_from"],
                    row["valid_to"],
                    row["detail"],
                ),
            )
        authority_sha256 = authority.hexdigest()

        selected_rows = conn.execute(
            "SELECT id,kind,canonical FROM entities "
            "ORDER BY kind,canonical,id LIMIT ?",
            (entity_limit,),
        ).fetchall()
        refs: dict[int, str] = {}
        entities: list[dict[str, object]] = []
        tenant_sha256 = hashlib.sha256(tenant.encode("utf-8")).hexdigest()
        for row in selected_rows:
            entity_ref = _inventory_ref(
                reference_key,
                {
                    "schema": INVENTORY_ENTITY_SCHEMA,
                    "tenant_sha256": tenant_sha256,
                    "origin": "entity_graph",
                    "entity_kind": row["kind"],
                    "canonical": row["canonical"],
                },
            )
            refs[int(row["id"])] = entity_ref
            entities.append(
                {
                    "schema": INVENTORY_ENTITY_SCHEMA,
                    "entity_ref_sha256": entity_ref,
                    "entity_kind": row["kind"],
                    "origin": "entity_graph",
                }
            )

        relationships: list[dict[str, object]] = []
        if refs and relationship_limit:
            # Iterate instead of building a caller-sized SQL IN clause.  The
            # output and retained state remain bounded even for a large graph.
            cursor = conn.execute(
                "SELECT id,src,rel,dst,record_type,record_id,valid_from,"
                "valid_to,detail FROM edges ORDER BY id"
            )
            for row in cursor:
                source_ref = refs.get(int(row["src"]))
                target_ref = refs.get(int(row["dst"]))
                if source_ref is None or target_ref is None:
                    continue
                provenance_ref = _inventory_ref(
                    reference_key,
                    {
                        "schema": INVENTORY_PROVENANCE_SCHEMA,
                        "tenant_sha256": tenant_sha256,
                        "record_type": row["record_type"],
                        "record_id": row["record_id"],
                    },
                )
                material = {
                    "schema": INVENTORY_RELATIONSHIP_SCHEMA,
                    "source_entity_ref_sha256": source_ref,
                    "relation_type": row["rel"],
                    "target_entity_ref_sha256": target_ref,
                    "provenance_record_type": row["record_type"],
                    "provenance_ref_sha256": provenance_ref,
                    "valid_from": row["valid_from"],
                    "valid_to": row["valid_to"],
                    "detail_sha256": _inventory_ref(
                        reference_key,
                        {
                            "schema": INVENTORY_PROVENANCE_SCHEMA,
                            "tenant_sha256": tenant_sha256,
                            "detail": row["detail"],
                        },
                    ),
                }
                relationships.append(
                    {
                        **material,
                        "relationship_ref_sha256": _inventory_ref(
                            reference_key,
                            material,
                        ),
                        "relationship_kind": "entity_graph_edge",
                        "origin": "entity_graph",
                    }
                )
                if len(relationships) >= relationship_limit:
                    break

        limitations = {"source_completeness_unverified"}
        if entity_count > len(entities):
            limitations.add("entity_limit")
        if relationship_count > len(relationships):
            limitations.add("relationship_limit")
        return {
            "schema": INVENTORY_PROVENANCE_SCHEMA,
            "state": "partial",
            "observed_at": rebuilt_at,
            "graph_integrity_sha256": authority_sha256,
            "entity_count": entity_count,
            "relationship_count": relationship_count,
            "projected_entity_count": len(entities),
            "projected_relationship_count": len(relationships),
            "limitations": sorted(limitations),
            "entities": entities,
            "relationships": relationships,
            "raw_names_included": False,
            "raw_aliases_included": False,
            "raw_record_ids_included": False,
            "raw_relationship_detail_included": False,
            "fuzzy_identity_merging_performed": False,
        }
    except EntityGraphInventoryError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise EntityGraphInventoryError(
            "entity_graph_integrity_unverified"
        ) from exc
    finally:
        conn.close()


__all__ = [
    "CONCEPT_KINDS",
    "EntityGraphInventoryError",
    "INVENTORY_ENTITY_SCHEMA",
    "INVENTORY_PROVENANCE_SCHEMA",
    "INVENTORY_RELATIONSHIP_SCHEMA",
    "RECORD_KINDS",
    "RELATION_KINDS",
    "blast_radius",
    "dossier",
    "enabled",
    "inventory_provenance_manifest",
    "neighborhood",
    "rebuild",
    "refresh",
    "stats",
    "why",
]
