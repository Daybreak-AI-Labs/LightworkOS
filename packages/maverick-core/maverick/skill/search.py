"""Skill search engine + Hugging Face dataset publish/pull.

Lightwork already ranks skills *for the agent loop* by goal relevance
(``skills._relevant_skills_lexical``, ``skill_embeddings``). This is the
other half: a **user-facing search** over the local skill library -- "what
skills do I have for X?" -- with a transparent, zero-dependency ranking, plus
a portable manifest so a skill collection can be **published to / pulled from
a Hugging Face Hub dataset**.

Two pieces, each independently useful:

  * ``SkillSearchIndex`` -- builds a BM25-lite inverted index over each
    skill's searchable text (name + triggers + tools + an optional
    ``description:``/``tags:`` frontmatter, + body) and answers a ranked
    ``query``. BM25-lite = classic IDF * saturating TF with a length norm,
    implemented in plain Python (no rank_bm25, no numpy) so it runs anywhere
    the kernel runs. Field boosts weight a name/trigger hit over a body hit.

  * ``skills.jsonl`` export/import -- the on-disk shape of a published skill
    dataset (one JSON object per line: ``{name, description, tags, triggers,
    tools_needed, body}``). ``export_jsonl`` serializes the local library;
    ``import_records`` validates+writes pulled records back as SKILL.md files
    (reusing ``skills.validate_skill_file`` so a poisoned record can't land
    silently). The actual HF network call is injected: ``pull_dataset`` takes
    a ``fetcher`` callable, so offline tests pass a fake and CI never touches
    the network. A thin ``hf_hub_fetcher`` adapter wires the real Hub when the
    ``huggingface_hub`` package is installed.

CLI::

    python -m maverick.skill.search "research and summarize"
    python -m maverick.skill.search --export skills.jsonl
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Field weights: a query term in a skill's name/triggers is a stronger signal
# of intent than the same term buried in the body. Tunable, but kept simple.
_FIELD_BOOST = {
    "name": 4.0,
    "tags": 3.0,
    "triggers": 3.0,
    "description": 2.0,
    "tools_needed": 1.5,
    "body": 1.0,
}

# BM25 free parameters (the textbook defaults). k1 controls TF saturation,
# b controls how much document length normalizes the score.
_K1 = 1.5
_B = 0.75

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


@dataclass
class SkillDoc:
    """One indexed skill: its fields + the flattened, weighted token bag.

    ``term_counts`` already folds in the per-field boost (a term appearing in
    ``name`` contributes ``_FIELD_BOOST['name']`` to its count), so BM25 scoring
    reads a single bag while still honouring field importance.
    """

    name: str
    description: str
    tags: list[str]
    triggers: list[str]
    tools_needed: list[str]
    body: str
    path: str | None = None
    term_counts: Counter = field(default_factory=Counter)
    length: float = 0.0

    def to_record(self) -> dict[str, Any]:
        """The portable ``skills.jsonl`` record for this skill (no index state)."""
        return {
            "name": self.name,
            "description": self.description,
            "tags": list(self.tags),
            "triggers": list(self.triggers),
            "tools_needed": list(self.tools_needed),
            "body": self.body,
        }


@dataclass
class SearchHit:
    name: str
    score: float
    description: str
    tags: list[str]
    path: str | None = None


def _fields_for(name, description, tags, triggers, tools_needed, body) -> dict[str, list[str]]:
    return {
        "name": _tokenize(name),
        "tags": [t for tag in tags for t in _tokenize(tag)],
        "triggers": [t for trig in triggers for t in _tokenize(trig)],
        "description": _tokenize(description),
        "tools_needed": [t for tn in tools_needed for t in _tokenize(tn)],
        "body": _tokenize(body),
    }


def _weighted_counts(fields: dict[str, list[str]]) -> tuple[Counter, float]:
    """Fold per-field boosts into one term->weight bag; return (bag, length).

    ``length`` is the boosted token total, used by BM25's length norm so a
    long body doesn't automatically outrank a tight, on-topic skill.
    """
    counts: Counter = Counter()
    length = 0.0
    for field_name, toks in fields.items():
        boost = _FIELD_BOOST.get(field_name, 1.0)
        for tok in toks:
            counts[tok] += boost
            length += boost
    return counts, length


def make_doc(
    *,
    name: str,
    description: str = "",
    tags: Iterable[str] = (),
    triggers: Iterable[str] = (),
    tools_needed: Iterable[str] = (),
    body: str = "",
    path: str | None = None,
) -> SkillDoc:
    """Build an indexable ``SkillDoc`` from raw fields (pre-computes the bag)."""
    tags = list(tags)
    triggers = list(triggers)
    tools_needed = list(tools_needed)
    fields = _fields_for(name, description, tags, triggers, tools_needed, body)
    counts, length = _weighted_counts(fields)
    return SkillDoc(
        name=name,
        description=description,
        tags=tags,
        triggers=triggers,
        tools_needed=tools_needed,
        body=body,
        path=path,
        term_counts=counts,
        length=length,
    )


class SkillSearchIndex:
    """A BM25-lite inverted index over skill docs. Zero external deps."""

    def __init__(self, docs: list[SkillDoc]):
        self.docs = docs
        self._df: Counter = Counter()  # term -> number of docs containing it
        for doc in docs:
            for term in doc.term_counts:
                self._df[term] += 1
        n = len(docs)
        self._avg_len = (sum(d.length for d in docs) / n) if n else 0.0

    def _idf(self, term: str) -> float:
        """BM25 IDF with the +1 smoothing so it's always positive.

        A term in every doc still gets a small positive weight rather than 0
        (the classic BM25 IDF can go negative; the +1 form used here can't),
        which keeps scores monotone and easy to reason about.
        """
        n = len(self.docs)
        df = self._df.get(term, 0)
        return math.log(1.0 + (n - df + 0.5) / (df + 0.5))

    def _score(self, doc: SkillDoc, query_terms: list[str]) -> float:
        if not doc.length:
            return 0.0
        score = 0.0
        for term in query_terms:
            tf = doc.term_counts.get(term, 0.0)
            if not tf:
                continue
            idf = self._idf(term)
            denom = tf + _K1 * (1.0 - _B + _B * (doc.length / (self._avg_len or 1.0)))
            score += idf * (tf * (_K1 + 1.0)) / denom
        return score

    def search(self, query: str, *, limit: int = 5) -> list[SearchHit]:
        """Return up to ``limit`` skills ranked by BM25-lite relevance.

        Ties (and zero-score docs when the query has no index overlap) are
        broken by name so results are deterministic. Docs that score 0 are
        dropped -- an empty result is more honest than five random skills.
        """
        query_terms = _tokenize(query)
        scored = []
        for doc in self.docs:
            s = self._score(doc, query_terms)
            if s > 0:
                scored.append((s, doc))
        scored.sort(key=lambda x: (-x[0], x[1].name))
        return [
            SearchHit(
                name=doc.name,
                score=round(s, 6),
                description=doc.description,
                tags=list(doc.tags),
                path=doc.path,
            )
            for s, doc in scored[:limit]
        ]


# ---- building from the local skill library ----------------------------------

def _doc_from_skill(skill: Any) -> SkillDoc:
    """Adapt a ``maverick.skills.Skill`` (+ optional description/tags) to a doc.

    The shipped SKILL.md format carries ``triggers``/``tools_needed`` but not
    ``description``/``tags``; those are read opportunistically from the raw
    frontmatter when present so the index is forward-compatible with richer
    skills without requiring them.
    """
    description, tags = _extra_frontmatter(skill)
    return make_doc(
        name=skill.name,
        description=description,
        tags=tags,
        triggers=list(getattr(skill, "triggers", []) or []),
        tools_needed=list(getattr(skill, "tools_needed", []) or []),
        body=getattr(skill, "body", "") or "",
        path=str(skill.path) if getattr(skill, "path", None) else None,
    )


def _extra_frontmatter(skill: Any) -> tuple[str, list[str]]:
    """Pull optional ``description:`` and ``tags:`` from a skill's SKILL.md.

    Returns ("", []) on any problem -- these fields are optional, so a missing
    file or unreadable frontmatter must never break indexing.
    """
    path = getattr(skill, "path", None)
    if not path:
        return "", []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return "", []
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not m:
        return "", []
    front = m.group(1)
    description = ""
    tags: list[str] = []
    current_key = None
    for line in front.splitlines():
        stripped = line.rstrip()
        if stripped.startswith("  - ") and current_key == "tags":
            tags.append(stripped[4:].strip())
        elif ":" in stripped and not stripped.startswith(" "):
            k, _, v = stripped.partition(":")
            current_key = k.strip()
            v = v.strip()
            if current_key == "description":
                description = v
            elif current_key == "tags" and v:
                # inline list form: `tags: [a, b]` or `tags: a, b`
                tags = [t.strip().strip("[]") for t in v.split(",") if t.strip().strip("[]")]
    return description, tags


def build_index(skills_dir: Path | None = None) -> SkillSearchIndex:
    """Build an index over the installed skills (``~/.maverick/skills`` default).

    Imports ``maverick.skills`` lazily so the search engine has no import-time
    dependency on the skill loader (and tests can build an index directly from
    docs without touching disk). The default dir is resolved from
    ``skills.SKILLS_DIR`` at call time (not bound at import), so an operator
    who relocates the skills dir is honoured.
    """
    from .. import skills as skills_mod
    target = skills_dir if skills_dir is not None else skills_mod.SKILLS_DIR
    return SkillSearchIndex([_doc_from_skill(s) for s in skills_mod.load_skills(target)])


# ---- Hugging Face dataset export / import -----------------------------------

# A fetcher returns the raw bytes/str of a published ``skills.jsonl`` for a
# given HF dataset repo id. Injected so offline tests pass a fake and the real
# Hub call is isolated in ``hf_hub_fetcher``.
Fetcher = Callable[[str], str]


def export_jsonl(docs: list[SkillDoc], out_path: Path) -> int:
    """Write ``docs`` as a ``skills.jsonl`` manifest. Returns the row count.

    This is the publish shape: upload the resulting file to a HF dataset repo
    (``huggingface-cli upload <repo> skills.jsonl``) and others can pull it.
    """
    lines = [json.dumps(d.to_record(), sort_keys=True) for d in docs]
    out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


def parse_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse a ``skills.jsonl`` manifest into records. Skips blank lines.

    A malformed line is skipped (not fatal): a published dataset is untrusted
    input, and one bad row must not sink an otherwise usable pull. Each kept
    record is normalized so missing optional fields default sanely.
    """
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict) or not obj.get("name"):
            continue
        records.append(_normalize_record(obj))
    return records


def _normalize_record(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(obj.get("name", "")),
        "description": str(obj.get("description", "") or ""),
        "tags": [str(t) for t in (obj.get("tags") or [])],
        "triggers": [str(t) for t in (obj.get("triggers") or [])],
        "tools_needed": [str(t) for t in (obj.get("tools_needed") or [])],
        "body": str(obj.get("body", "") or ""),
    }


def index_from_records(records: list[dict[str, Any]]) -> SkillSearchIndex:
    """Build a searchable index directly from pulled ``skills.jsonl`` records."""
    docs = [
        make_doc(
            name=r["name"],
            description=r.get("description", ""),
            tags=r.get("tags", []),
            triggers=r.get("triggers", []),
            tools_needed=r.get("tools_needed", []),
            body=r.get("body", ""),
        )
        for r in records
    ]
    return SkillSearchIndex(docs)


def _scalar_line(value: str) -> str:
    """Collapse a scalar frontmatter value to a single safe line.

    Untrusted JSONL ``name``/``description`` are interpolated into YAML
    frontmatter, so a value carrying a newline (followed by ``---`` or
    ``tools_needed:``) could forge frontmatter. Collapse all whitespace to a
    single line -- the same single-line guarantee :func:`skills._clean_items`
    gives list entries -- which makes ``---`` and key-injection impossible
    (any embedded newline disappears)."""
    return " ".join(str(value).split()).strip()


def _record_to_skill_md(record: dict[str, Any]) -> str:
    """Render a pulled record back into SKILL.md text (frontmatter + body)."""
    lines = ["---", f"name: {_scalar_line(record['name'])}"]
    description = _scalar_line(record.get("description", ""))
    if description:
        lines.append(f"description: {description}")
    if record.get("tags"):
        lines.append("tags:")
        lines.extend(f"  - {_scalar_line(t)}" for t in record["tags"])
    triggers = [_scalar_line(t) for t in (record.get("triggers") or [])]
    triggers = [t for t in triggers if t]
    lines.append("triggers:")
    lines.extend(f"  - {t}" for t in (triggers or ["imported skill"]))
    tools = [_scalar_line(t) for t in (record.get("tools_needed") or [])]
    tools = [t for t in tools if t]
    if tools:
        lines.append("tools_needed:")
        lines.extend(f"  - {t}" for t in tools)
    lines.append("---")
    body = record.get("body") or "# Imported skill\n\nNo body provided."
    return "\n".join(lines) + "\n\n" + body + "\n"


def import_records(
    records: list[dict[str, Any]],
    dest_dir: Path,
    *,
    overwrite: bool = False,
) -> dict[str, list[str]]:
    """Write pulled records to ``dest_dir`` as validated SKILL.md files.

    Each record is rendered to SKILL.md, written to a temp file, and run
    through ``skills.validate_skill_file`` (the same publish-gate lint the CLI
    uses) BEFORE landing at its final path -- a record carrying a bad name or
    an embedded secret is rejected, not installed. Existing files are skipped
    unless ``overwrite``. Returns ``{"installed": [...], "rejected": [...],
    "skipped": [...]}`` with human-readable reasons on the rejected entries.
    """
    from .. import skills as skills_mod

    dest_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, list[str]] = {"installed": [], "rejected": [], "skipped": []}
    for record in records:
        name = record["name"]
        # The dataset is untrusted third-party input and `name` is used to build
        # filesystem paths below (target AND the .import.tmp temp file, written
        # BEFORE validate_skill_file runs). A non-kebab name such as
        # "../../../.ssh/authorized_keys" would make the temp write escape
        # dest_dir and truncate-then-delete an arbitrary writable file. Reject
        # anything that isn't a plain kebab skill id up front, before any path
        # is constructed -- the frontmatter-name check inside validate_skill_file
        # runs too late and only inspects the file body, not this stem.
        if not isinstance(name, str) or not skills_mod._KEBAB_RE.match(name):
            result["rejected"].append(
                f"{name!r}: invalid skill name (must be kebab-case: a-z, 0-9, hyphens)"
            )
            continue
        target = dest_dir / f"{name}.md"
        if target.exists() and not overwrite:
            result["skipped"].append(name)
            continue
        text = _record_to_skill_md(record)
        tmp = dest_dir / f".{name}.import.tmp"
        try:
            tmp.write_text(text, encoding="utf-8")
            validation = skills_mod.validate_skill_file(tmp)
            if not validation.ok:
                result["rejected"].append(f"{name}: {'; '.join(validation.errors)}")
                continue
            # The dataset is untrusted and a skill body is concatenated into the
            # agent's system prompt at recall (render_for_prompt). validate_skill_file
            # only lints frontmatter + scans for secrets -- it does NOT shield-scan
            # the body for prompt injection, nor enforce the [skills] signing policy.
            # Apply both here (same gates as a free-text/catalog install) so a
            # poisoned public dataset can't install a jailbreak body or land an
            # unsigned skill under require_signed.
            try:
                parsed = skills_mod.Skill.parse(text, tmp)
                skills_mod._verify_skill_signature(parsed)
                from ..catalog_trust import shield_scan
                shield_scan(parsed.body or "", label="imported skill body")
            except Exception as e:
                result["rejected"].append(f"{name}: {e}")
                continue
            tmp.replace(target)
            result["installed"].append(name)
        finally:
            if tmp.exists():
                tmp.unlink()
    return result


def pull_dataset(repo_id: str, fetcher: Fetcher) -> list[dict[str, Any]]:
    """Pull a published skill dataset via an injected ``fetcher``.

    ``fetcher(repo_id)`` returns the raw ``skills.jsonl`` text; this parses it
    into normalized records. The network is entirely behind ``fetcher`` so a
    test injects a fake and CI stays offline; ``hf_hub_fetcher`` is the real
    Hub adapter for production.
    """
    return parse_jsonl(fetcher(repo_id))


def hf_hub_fetcher(filename: str = "skills.jsonl", *, revision: str | None = None) -> Fetcher:
    """Build a ``Fetcher`` backed by ``huggingface_hub`` (optional dependency).

    Returns a callable ``fetch(repo_id)`` that downloads ``filename`` from the
    given dataset repo and returns its text. Imports ``huggingface_hub`` lazily
    and raises a clear error if it's not installed -- the package is NOT a hard
    dependency (offline tests use a fake fetcher), so we only require it when a
    real pull is actually requested.
    """
    def fetch(repo_id: str) -> str:
        try:
            from huggingface_hub import hf_hub_download
        except ImportError as e:  # pragma: no cover - exercised only with the dep absent
            raise RuntimeError(
                "huggingface_hub is required for a live dataset pull; "
                "install it or pass a custom fetcher"
            ) from e
        path = hf_hub_download(
            repo_id=repo_id, filename=filename, repo_type="dataset", revision=revision,
        )
        return Path(path).read_text(encoding="utf-8")

    return fetch


# ---- CLI --------------------------------------------------------------------

def _cmd_search(query: str, limit: int) -> int:
    index = build_index()
    hits = index.search(query, limit=limit)
    if not hits:
        print(f"no skills matched {query!r}")
        return 0
    for hit in hits:
        tag_str = f" [{', '.join(hit.tags)}]" if hit.tags else ""
        desc = f" — {hit.description}" if hit.description else ""
        print(f"{hit.score:>8.3f}  {hit.name}{tag_str}{desc}")
    return 0


def _cmd_export(out: str) -> int:
    index = build_index()
    n = export_jsonl(index.docs, Path(out))
    print(f"exported {n} skill(s) to {out}")
    return 0


def _cmd_import(repo_id: str, dest: str) -> int:
    records = pull_dataset(repo_id, hf_hub_fetcher())
    result = import_records(records, Path(dest))
    print(json.dumps(result, indent=2))
    return 0 if not result["rejected"] else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m maverick.skill.search",
        description="Search the local skill library (BM25-lite) and publish/pull HF datasets.",
    )
    ap.add_argument("query", nargs="?", help="search the local skill library for this text")
    ap.add_argument("--limit", type=int, default=5, help="max results (search mode)")
    ap.add_argument("--export", metavar="PATH", help="export the local skills to a skills.jsonl manifest")
    ap.add_argument("--import-dataset", metavar="REPO_ID", help="pull a HF dataset repo's skills.jsonl")
    ap.add_argument("--dest", metavar="DIR", help="install dir for --import-dataset (default: ~/.maverick/skills)")
    args = ap.parse_args(argv)

    if args.export:
        return _cmd_export(args.export)
    if args.import_dataset:
        from ..skills import SKILLS_DIR
        return _cmd_import(args.import_dataset, args.dest or str(SKILLS_DIR))
    if args.query:
        return _cmd_search(args.query, args.limit)
    ap.print_help()
    return 2


__all__ = [
    "SkillDoc",
    "SearchHit",
    "SkillSearchIndex",
    "Fetcher",
    "make_doc",
    "build_index",
    "export_jsonl",
    "parse_jsonl",
    "index_from_records",
    "import_records",
    "pull_dataset",
    "hf_hub_fetcher",
    "main",
]


if __name__ == "__main__":
    sys.exit(main())
