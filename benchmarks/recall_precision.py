"""Recall-precision benchmark: does relevance-gating cut injected noise?

Recalled-but-irrelevant memory hurts an agent more than a missed recall does
(precision >> recall for agent memory: hard negatives flip answers --
GSM-DC/GSM-IC; large/noisy memory degrades -- LifelongAgentBench 2505.11942; the
inverted-U of long-context RAG -- 2410.05983). This measures the relevance gate:
on a held-out query set the store never saw, what fraction of UNRELATED
queries still surface a (wrong) skill (false-positive rate), and do the right
skills still surface (Recall@1 / MRR), for the lexical recall ungated vs gated.

Deterministic + free (forces the lexical path, no fastembed/key needed), so it
runs in CI. The embedding path adds further precision at runtime (cosine gate).
"""
from __future__ import annotations

import sys
from pathlib import Path

# Repo-root import of the kernel (installed editable); benchmarks/ is flat.
from maverick.skills import Skill, _relevant_skills_lexical  # noqa: E402

# Each class = one stored skill (its triggers); queries are held-out paraphrases.
CLASSES = {
    "ledger_recon": ["reconcile the general ledger", "tie subledger to the bank"],
    "k8s_rollback": ["roll back the kubernetes deployment", "revert the bad k8s deploy"],
    "pg_index": ["add a postgres index", "speed up the slow sql query"],
    "oauth_refresh": ["refresh the oauth token", "fix the expired bearer token"],
    "csv_encoding": ["parse the csv encoding", "fix the unicode decode error"],
    "flaky_test": ["stabilize the flaky test", "fix the intermittent ci failure"],
    "s3_pagination": ["paginate the s3 bucket listing", "list all s3 objects"],
    "regex_redos": ["fix the catastrophic regex backtracking", "regex hangs the service"],
    "tz_dst": ["fix the timezone dst bug", "times shift by an hour"],
    "mem_leak": ["find the memory leak", "worker memory grows over time"],
}
POSITIVES = [
    ("ledger_recon", "reconcile the quarterly general ledger to the bank statement"),
    ("k8s_rollback", "the kubernetes deployment failed, roll it back"),
    ("pg_index", "the postgres query is slow, add an index to speed it up"),
    ("oauth_refresh", "the oauth bearer token expired, refresh it in the client"),
    ("csv_encoding", "the csv fails with a unicode decode error, fix the encoding"),
    ("flaky_test", "a test fails intermittently in ci, stabilize the flaky test"),
    ("s3_pagination", "list all objects in the s3 bucket with pagination"),
    ("regex_redos", "the regex hangs the service, fix the catastrophic backtracking"),
    ("tz_dst", "times shift by an hour, fix the timezone dst bug"),
    ("mem_leak", "the worker memory grows over time, find the memory leak"),
]
NEGATIVES = [
    "plan a birthday party menu", "best hiking trails in the alps",
    "translate this poem into french", "recommend a science fiction novel",
    "how to tune a six string guitar", "when to plant tomatoes in spring",
    "knit a winter scarf pattern", "book a flight to tokyo",
]


def _skills() -> list[Skill]:
    return [Skill(name=cls, triggers=trigs, tools_needed=[], body="", path=Path("/x"))
            for cls, trigs in CLASSES.items()]


def measure(min_score: float) -> dict:
    """Recall@1, MRR (on positives) and false-positive rate (on negatives) for
    the lexical recall at the given relevance gate."""
    skills = _skills()
    r1 = 0
    rr = 0.0
    for cls, q in POSITIVES:
        hits = _relevant_skills_lexical(q, skills, max_n=5, min_score=min_score)
        ranks = [i for i, s in enumerate(hits, 1) if s.name == cls]
        rank = ranks[0] if ranks else None
        r1 += int(rank == 1)
        rr += (1.0 / rank) if rank else 0.0
    fp = sum(1 for q in NEGATIVES
             if _relevant_skills_lexical(q, skills, max_n=5, min_score=min_score))
    n, m = len(POSITIVES), len(NEGATIVES)
    return {"recall_at_1": r1 / n, "mrr": round(rr / n, 3),
            "false_positive_rate": fp / m, "min_score": min_score}


def main() -> int:
    print("Recall-precision (lexical path, held-out queries):")
    for gate, label in ((0.0, "ungated (score>0)"), (4.0, "GATED (default)")):
        m = measure(gate)
        print(f"  {label:18}  Recall@1={m['recall_at_1']:.0%}  MRR={m['mrr']:.2f}  "
              f"false-positive-rate={m['false_positive_rate']:.0%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
