"""GAIA adapter -- the general-assistant slice.

GAIA (arxiv:2311.12983) tasks are factual questions with a single
ground-truth ``Final answer``; scoring is GAIA's official *normalized
exact match* (numbers compared as floats; strings lower-cased with
whitespace + punctuation stripped; comma/semicolon lists compared
element-wise). We reproduce that scorer here so a Lightwork GAIA run is
directly comparable to published numbers.

Dataset: a JSONL export with ``{task_id, Question, Final answer}`` rows
(the HF ``gaia-benchmark/GAIA`` validation split serialized to JSONL).
Pass ``--dataset`` to point at yours; with none, the shipped offline
fixture runs so CI exercises every scoring branch without the download.
"""
from __future__ import annotations

import importlib.util
import re
import string
import sys
from pathlib import Path


def _load_framework():
    """Load ``evals.py`` by path -- benchmarks/ is a flat dir, not a package."""
    name = "benchmarks_evals"
    if name in sys.modules:
        return sys.modules[name]
    p = Path(__file__).parent / "evals.py"
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve cls.__module__ globals.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_E = _load_framework()
EvalTask = _E.EvalTask
FIXTURES = _E.FIXTURES

# Agents are prompted to end with this marker; we score the text after it
# when present, else the whole output. Matches GAIA's prompting convention.
_FINAL_MARKER = "FINAL ANSWER:"


def _extract_final_answer(output: str) -> str:
    """Pull the agent's final answer out of a possibly-chatty completion."""
    idx = output.rfind(_FINAL_MARKER)
    if idx != -1:
        return output[idx + len(_FINAL_MARKER):].strip()
    return output.strip()


def _is_float(x: str) -> bool:
    try:
        float(x)
        return True
    except (TypeError, ValueError):
        return False


def _normalize_number(s: str) -> float:
    for ch in ("$", "%", ","):
        s = s.replace(ch, "")
    try:
        return float(s.strip())
    except ValueError:
        return float("inf")


def _normalize_str(s: str, *, remove_punct: bool = True) -> str:
    no_ws = re.sub(r"\s", "", s)
    no_ws = no_ws.lower()
    if remove_punct:
        no_ws = no_ws.translate(str.maketrans("", "", string.punctuation))
    return no_ws


def _split_list(s: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,;]", s) if p.strip()]


def question_scorer(model_answer: str, ground_truth: str) -> float:
    """GAIA's normalized exact match. Returns 1.0 (correct) or 0.0."""
    model_answer = _extract_final_answer(model_answer)
    if _is_float(ground_truth):
        return 1.0 if _normalize_number(model_answer) == float(ground_truth) else 0.0
    if any(sep in ground_truth for sep in (",", ";")):
        gt = _split_list(ground_truth)
        ma = _split_list(model_answer)
        if len(gt) != len(ma):
            return 0.0
        for g, m in zip(gt, ma, strict=False):
            if _is_float(g):
                if _normalize_number(m) != float(g):
                    return 0.0
            elif _normalize_str(m) != _normalize_str(g):
                return 0.0
        return 1.0
    return 1.0 if _normalize_str(model_answer) == _normalize_str(ground_truth) else 0.0


class GaiaBenchmark:
    name = "gaia"

    def load_tasks(self, dataset: Path | None = None, *, limit: int | None = None):
        path = dataset if dataset is not None else FIXTURES / "gaia_sample.jsonl"
        rows = _E._read_jsonl(Path(path))
        tasks = []
        for r in rows:
            tasks.append(EvalTask(
                task_id=str(r.get("task_id", r.get("id", ""))),
                prompt=str(r.get("Question", r.get("question", ""))),
                answer=str(r.get("Final answer", r.get("answer", ""))),
                metadata={"level": r.get("Level")},
            ))
        return tasks[:limit] if limit is not None else tasks

    def score(self, task, output: str) -> float:
        return question_scorer(output, str(task.answer))


__all__ = ["GaiaBenchmark", "question_scorer"]
