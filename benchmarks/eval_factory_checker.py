"""Factory checker benchmark: how many planted defects the checkers find.

The code factory (``maverick.codebase.features``) has independent checkers
look at an author's change before a person approves it. This benchmark
measures them on a fixed corpus (``factory_checker/cases``): small
repositories, each with a base commit, a change (a patch) and a ground-truth
label. A label is either ``clean`` (a correct change that may look
suspicious) or ``defect`` (one planted defect: its kind, its file, a repro
command that fails on the change and passes on the base, and why).

Each case runs the real factory path: ``features.propose`` with a stand-in
author that applies the patch, the configured checkers
(``features.default_checkers``, models from ``[codebase] checker_models`` and
the ``reviewer`` role, never named here), no repair rounds and one look. The
findings are then matched to the label:

* a planted defect counts as **found** by a checker when one of its findings
  names the defect's file and kind, or its repro command was confirmed:
  Lightwork re-ran it and it failed on the change, and it passes on the base;
* a blocker or should-fix finding on a clean case is a **false alarm**.

It reports recall, false alarms, the share of found defects confirmed by a
repro, and dollars and tokens per case, for each checker and for the panel
(any checker). Lightwork re-runs repros only when the steps run in a
container, so on a ``local`` work area the repro measure stays at zero.

Modes:
  ``python benchmarks/eval_factory_checker.py``             live run (needs a
      model key); writes ``benchmarks/results/factory-checker/run-<UTC>.json``
  ``python benchmarks/eval_factory_checker.py --self-test``  stub checkers
      (one perfect, one silent, one noisy) prove the scoring; writes nothing
  ``python benchmarks/eval_factory_checker.py --validate``   the corpus check:
      tests pass on base and change, repros fail only on the change
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import shlex
import shutil
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "factory_checker" / "cases"
RESULTS = HERE / "results" / "factory-checker"
TEST_COMMAND = "python -m pytest -q -p no:cacheprovider"
VERDICTS = ("defect", "clean")
# A finding counts as an alarm on a clean case at these severities; a minor
# note is not a claim that the change is wrong.
ALARM_SEVERITIES = ("blocker", "should-fix")
# Words that name each defect kind in a finding (lower case, substrings). The
# kind's own name, with or without dashes, always counts too.
KINDS: dict[str, tuple[str, ...]] = {
    "off-by-one": ("off by one", "off by 1", "fencepost", "one too many", "one too few",
                   "last item", "last element", "boundary", "bound"),
    "missing-error-path": ("error", "exception", "raise", "unhandled", "not handled",
                           "keyerror", "no longer check"),
    "path-traversal": ("traversal", "../", "outside", "escape", "leave the folder"),
    "shell-injection": ("injection", "inject", "shell", "unquoted", "not quoted"),
    "concurrency": ("race", "thread", "lock", "concurren", "atomic", "lost update"),
    "weakened-test": ("weaken", "loosen", "vacuous", "no longer check", "no longer assert",
                      "only checks", "hides", "masks", "assert true"),
    "regression": ("regress", "no longer", "used to", "broke", "previously", "dropped"),
    "wrong-unit": ("unit", "millisecond", "seconds", "1000"),
    "resource-leak": ("leak", "never released", "not released", "never given back",
                      "exhaust", "not closed", "never closed"),
}
# What each stub checker charges per look in the self-test, so the cost
# columns are proven too: (input tokens, output tokens, dollars).
STUB_COST = {"perfect": (1000, 100, 0.01), "silent": (0, 0, 0.0), "noisy": (500, 50, 0.005)}
NO_KEY = ("No model key is set up, so the checkers cannot run. Run `maverick init` or set "
          "your provider's API key, then try again. To check the scoring without a key, "
          "run with --self-test.")


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    description: str
    verdict: str
    path: Path
    defect: dict | None
    looks_like: str | None

    @property
    def base(self) -> Path:
        return self.path / "base"

    @property
    def patch(self) -> Path:
        return self.path / "change.patch"


def load_cases(root: Path = CORPUS, only: list[str] | None = None) -> list[Case]:
    """Every case under ``root`` (or the ``only`` ids); a malformed label raises."""
    cases = []
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        if only and folder.name not in only:
            continue
        label = json.loads((folder / "label.json").read_text(encoding="utf-8"))
        problem = _label_problem(folder, label)
        if problem:
            raise ValueError(f"{folder.name}: {problem}")
        cases.append(Case(label["id"], label["title"], label["description"], label["verdict"],
                          folder, label.get("defect"), label.get("looks_like")))
    missing = sorted(set(only or ()) - {c.id for c in cases})
    if missing:
        raise ValueError(f"no such case: {', '.join(missing)}")
    return cases


def _label_problem(folder: Path, label: dict) -> str | None:
    if label.get("id") != folder.name:
        return "its id is not its folder name"
    if label.get("verdict") not in VERDICTS or not label.get("title"):
        return "it needs a title and a verdict of defect or clean"
    if not (folder / "base").is_dir() or not (folder / "change.patch").is_file():
        return "it needs a base folder and a change.patch"
    if label["verdict"] == "clean":
        return None if label.get("looks_like") in KINDS and label.get("why") else \
            "a clean case needs looks_like (a known kind) and why"
    defect = label.get("defect") or {}
    if defect.get("kind") not in KINDS or not defect.get("why"):
        return "a defect needs a known kind and why"
    if not (folder / "base" / str(defect.get("file"))).is_file() and \
            str(defect.get("file")) not in (folder / "change.patch").read_text(encoding="utf-8"):
        return "the defect's file is in neither the base nor the change"
    if not str(defect.get("repro", "")).startswith("python ") or \
            not (folder / "repro.py").is_file():
        return "a defect needs a repro command and its repro.py"
    return None


# -- matching findings to the label ---------------------------------------------

def names_file_and_kind(finding: dict, defect: dict) -> bool:
    """Whether a finding's own words name the defect's file and kind."""
    text = " ".join(str(finding.get(k) or "") for k in ("what", "how", "repro")).lower()
    kind = defect["kind"]
    words = (kind, kind.replace("-", " "), *KINDS[kind])
    return defect["file"].lower() in text and any(w in text for w in words)


def _checker_row(case: Case, check: dict, n: int, base_passes: dict[str, bool]) -> dict:
    """Checker ``n``'s score on one case."""
    records = check.get("checkers") or []
    record = records[n - 1] if n <= len(records) else {}
    mine = [f for f in check.get("findings") or () if f.get("checker", 1) == n]
    rows, found, by_repro, as_blocker, alarms, other = [], False, False, False, 0, 0
    for f in mine:
        matched = None
        if case.defect is not None:
            if f.get("repro_state") == "confirmed" and base_passes.get(f["id"]):
                matched = "repro"
            elif names_file_and_kind(f, case.defect):
                matched = "file-and-kind"
        if matched:
            found, by_repro = True, by_repro or matched == "repro"
            as_blocker = as_blocker or f.get("severity") == "blocker"
        elif f.get("severity") in ALARM_SEVERITIES:
            alarms += case.verdict == "clean"
            other += case.verdict == "defect"
        rows.append({"id": f.get("id"), "severity": f.get("severity"),
                     "what": f.get("what"), "repro_state": f.get("repro_state"),
                     "passes_on_base": base_passes.get(f.get("id")), "matched": matched})
    return {"n": n, "model": record.get("model"), "ran": bool(record.get("commit")),
            "error": record.get("error"), "found": found, "found_by_repro": by_repro,
            "found_as_blocker": as_blocker, "alarms": alarms,
            "other_findings": other, "repros_confirmed": sum(
                f.get("repro_state") == "confirmed" for f in mine), "findings": rows}


def _ratio(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def tally(rows: list[dict]) -> dict:
    """Recall, false alarms and repro confirmation over per-case rows of one
    checker (or the panel); rows where it did not run are counted apart."""
    ran = [r for r in rows if r["ran"]]
    defect = [r for r in ran if r["verdict"] == "defect"]
    clean = [r for r in ran if r["verdict"] == "clean"]
    found = sum(r["found"] for r in defect)
    by_repro = sum(r["found_by_repro"] for r in defect)
    alarmed = sum(r["alarms"] > 0 for r in clean)
    return {"defect_cases": len(defect), "found": found, "recall": _ratio(found, len(defect)),
            "found_as_blocker": sum(r["found_as_blocker"] for r in defect),
            "confirmed_by_repro": by_repro,
            "confirmed_by_repro_rate": _ratio(by_repro, found),
            "clean_cases": len(clean), "clean_cases_with_alarm": alarmed,
            "false_alarm_rate": _ratio(alarmed, len(clean)),
            "false_alarms": sum(r["alarms"] for r in clean),
            "other_findings_on_defect_cases": sum(r["other_findings"] for r in defect),
            "repros_confirmed": sum(r["repros_confirmed"] for r in ran),
            "not_run": len(rows) - len(ran)}


def _panel(checkers: list[dict]) -> dict:
    """The panel's row for one case: a defect is found when any checker found it."""
    ran = [c for c in checkers if c["ran"]]
    return {"ran": bool(ran), "found": any(c["found"] for c in ran),
            "found_by_repro": any(c["found_by_repro"] for c in ran),
            "found_as_blocker": any(c["found_as_blocker"] for c in ran),
            "alarms": sum(c["alarms"] for c in ran),
            "other_findings": sum(c["other_findings"] for c in ran),
            "repros_confirmed": sum(c["repros_confirmed"] for c in ran)}


def summarize(results: list[dict]) -> dict:
    """Scores per checker and for the panel, plus cost per case."""
    count = max((len(r["checkers"]) for r in results), default=0)
    scores = {}
    for n in range(1, count + 1):
        scores[f"checker {n}"] = tally([
            {**r["checkers"][n - 1], "verdict": r["verdict"]} for r in results
            if len(r["checkers"]) >= n])
    scores["panel"] = tally([{**_panel(r["checkers"]), "verdict": r["verdict"]}
                             for r in results])
    kinds: dict[str, list[int]] = {}
    for r in results:
        if r["verdict"] == "defect" and any(c["ran"] for c in r["checkers"]):
            seen = kinds.setdefault(r["kind"], [0, 0])
            seen[0] += any(c["found"] for c in r["checkers"])
            seen[1] += 1
    ran = [r for r in results if not r.get("error")]
    cost = {"total_dollars": round(sum(r["dollars"] for r in results), 6),
            "dollars_per_case": _mean([r["dollars"] for r in ran]),
            "tokens_per_case": _mean([r["input_tokens"] + r["output_tokens"] for r in ran]),
            "seconds_per_case": _mean([r["seconds"] for r in ran])}
    return {"scores": scores, "panel_recall_by_kind": {
        k: {"found": v[0], "cases": v[1]} for k, v in sorted(kinds.items())},
        "cost": cost, "cases": len(results),
        "case_errors": {r["id"]: r["error"] for r in results if r.get("error")}}


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 6) if values else None


# -- running a case through the real factory path ----------------------------------

@contextlib.contextmanager
def _scoped_env(**values: str):
    """Set env vars for the run, restoring prior values exactly."""
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, old in saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


@contextlib.contextmanager
def isolated_home(config: Path | None = None):
    """A throwaway Lightwork home for the run's vault, world, proposals and
    approvals, so nothing reaches the operator's own. ``config`` is the
    settings file to read (models, budget, work area); None reads none."""
    with tempfile.TemporaryDirectory(prefix="lw-fbench-") as tmp:
        home = Path(tmp) / "home"
        with _scoped_env(MAVERICK_HOME=str(home),
                         MAVERICK_CONFIG=str(config or Path(tmp) / "no-config.toml"),
                         MAVERICK_ENCRYPT_AT_REST="0", MAVERICK_WORLD_BACKEND="sqlite"):
            yield home


def _command(command: str, python: str) -> str:
    """``command`` with a leading ``python`` replaced by the chosen interpreter."""
    return python + command[len("python"):] if command.startswith("python ") else command


def _register(case: Case, python: str) -> str:
    """Import the case's base folder into the vault as a one-commit repository."""
    from maverick.codebase import vault
    from maverick.codebase.features import _IDENTITY
    with tempfile.TemporaryDirectory(prefix="lw-fbench-src-") as tmp:
        src = Path(tmp) / case.id
        shutil.copytree(case.base, src)
        vault._git(["init", "-q", "-b", "main"], cwd=src)
        vault._git(["add", "-A"], cwd=src)
        vault._git(["commit", "-q", "-m", f"{case.id}: base"], cwd=src, env=_IDENTITY)
        vault.register(case.id, str(src), test_command=_command(TEST_COMMAND, python))
    return case.id


def _author(case: Case) -> Callable[[int, Path], None]:
    """The stand-in author: it applies the case's change, nothing else."""
    def run(_goal_id: int, work: Path) -> None:
        from maverick.codebase import vault
        vault._git(["apply", "--whitespace=nowarn", str(case.patch)], cwd=work)
    return run


def _observed(checker: Callable, seen: list, n: int) -> Callable:
    """``checker`` as is, keeping its raw output in slot ``n`` (the probe
    files a repro needs are not kept in the proposal). A failed look leaves
    its slot empty, so a later checker's output never moves into it."""
    def look(goal_id: int, copy: Path) -> object:
        seen[n - 1] = None
        out = checker(goal_id, copy)
        seen[n - 1] = out
        return out
    look.model = getattr(checker, "model", None)  # type: ignore[attr-defined]
    return look


def _raw_finding(seen: list, fid: str) -> dict | None:
    """The raw finding behind proposal finding ``fid`` (``1.3`` or ``2-1.3``)."""
    from maverick.codebase import features
    n = int(fid.split("-", 1)[0]) if "-" in fid else 1
    if n > len(seen) or seen[n - 1] is None:
        return None
    report = features._report(seen[n - 1])
    index = int(fid.rsplit(".", 1)[1]) - 1
    raw = (report or {}).get("findings") or []
    return raw[index] if 0 <= index < min(len(raw), features.MAX_FINDINGS) and \
        isinstance(raw[index], dict) else None


def _box_factory(sandbox_factory):
    """Where a repro re-runs on the base: the run's sandbox, else the factory's
    own choice (the checker image when set, else the configured backend)."""
    from maverick.codebase import features
    if sandbox_factory is not None:
        return lambda workdir: sandbox_factory(workdir=workdir)
    return features.checker_sandbox


def _passes_on_base(case: Case, finding: dict, raw: dict | None, sandbox_factory) -> bool:
    """Whether a repro Lightwork confirmed on the change passes on the base,
    in the same kind of sandbox: only then does it show the change's defect."""
    from maverick.codebase import features, vault
    probes, refused = features._probe_files((raw or {}).get("probe_files"))
    if refused:
        return False
    with vault.work_dir() as tmp:
        copy = tmp / "base"
        shutil.copytree(case.base, copy)
        if features._write_probes(copy, probes):
            return False
        if features.loop_settings()["checker_image"] and features._host_is_root():
            features._give_to_image_user(copy)
        box = _box_factory(sandbox_factory)(str(copy))
        try:
            result = box.exec(finding["repro"], timeout=features.REPRO_TIMEOUT)
        finally:
            features._close(box)
    return result.exit_code == 0 and not getattr(result, "setup_failed", False)


def run_case(world, case: Case, checkers: list[Callable], *, budget, sandbox_factory,
             python: str) -> dict:
    """One case through ``features.propose``; its per-checker scores and cost."""
    from maverick.codebase import features
    from maverick.codebase.vault import VaultError
    seen: list = [None] * len(checkers)
    started = time.monotonic()
    row = {"id": case.id, "verdict": case.verdict,
           "kind": (case.defect or {}).get("kind") or case.looks_like, "error": None}
    try:
        name = _register(case, python)
        p = features.propose(world, name, case.title, case.description, _author(case),
                             checker=[_observed(c, seen, n) for n, c in enumerate(checkers, start=1)],
                             sandbox_factory=sandbox_factory, budget=budget,
                             repair_rounds=0, check_rounds=1)
    except VaultError as exc:
        p, row["error"] = None, str(exc)[:300]
    check = (p or {}).get("check") or {}
    base_passes = {f["id"]: _passes_on_base(case, f, _raw_finding(seen, f["id"]),
                                            sandbox_factory)
                   for f in check.get("findings") or () if f.get("repro_state") == "confirmed"}
    row["checkers"] = [_checker_row(case, check, n, base_passes)
                       for n in range(1, len(checkers) + 1)]
    row.update(tests_passed=bool(((p or {}).get("tests") or {}).get("passed")),
               check_error=check.get("error"), stopped=(p or {}).get("stopped"),
               repros_skipped=bool(check.get("repros_skipped")),
               dollars=round(float(budget.dollars), 6), input_tokens=int(budget.input_tokens),
               output_tokens=int(budget.output_tokens), tool_calls=int(budget.tool_calls),
               seconds=round(time.monotonic() - started, 2))
    return row


def run_cases(cases: list[Case], make_checkers: Callable, make_budget: Callable, *,
              sandbox_factory=None, python: str = "python") -> list[dict]:
    """Every case in the current (isolated) home, each with its own budget."""
    from maverick.paths import maverick_home
    from maverick.world_model import open_world
    world = open_world()
    try:
        if maverick_home() not in Path(world.path).parents:
            raise RuntimeError("the benchmark's world is not in its own throwaway home")
        results = []
        for case in cases:
            budget = make_budget()
            results.append(run_case(world, case, make_checkers(case, budget), budget=budget,
                                    sandbox_factory=sandbox_factory, python=python))
        return results
    finally:
        world.close()


# -- the self-test: stub checkers prove the scoring ---------------------------------

class StandInContainer:
    """The local work area, marked as not sharing this computer's files, so the
    factory re-runs repros in the self-test as it would in a container. Used
    only with the stub checkers, whose commands are the corpus's own."""

    host_visible_fs = False

    def __init__(self, workdir: str) -> None:
        from maverick.sandbox import build_sandbox
        self._box = build_sandbox(workdir=workdir, backend="local")

    def exec(self, cmd: str, timeout: float | None = None):
        return self._box.exec(cmd, timeout=timeout)

    def close(self) -> None:
        close = getattr(self._box, "close", None)
        if callable(close):
            close()


def stub_checkers(case: Case, budget, python: str) -> list[Callable]:
    """Three stubs: one that reports exactly the planted defect with its repro,
    one that finds nothing, and one that reports the same noise everywhere
    (a finding about another file and a repro that fails on the base too)."""
    def charge(name: str) -> None:
        tokens_in, tokens_out, dollars = STUB_COST[name]
        if tokens_in or tokens_out:
            budget.record_tokens(tokens_in, tokens_out, cost_dollars=dollars)

    def perfect(_goal_id: int, _copy: Path) -> dict:
        charge("perfect")
        if case.defect is None:
            return {"findings": []}
        d = case.defect
        return {"findings": [{
            "severity": "blocker", "what": f"{d['file']}: {d['kind']} -- {d['why']}",
            "evidence": "ran", "how": d["repro"], "repro": _command(d["repro"], python),
            "probe_files": {"repro.py": (case.path / "repro.py").read_text(encoding="utf-8")}}]}

    def silent(_goal_id: int, _copy: Path) -> dict:
        charge("silent")
        return {"findings": []}

    def noisy(_goal_id: int, _copy: Path) -> dict:
        charge("noisy")
        return {"findings": [
            {"severity": "should-fix", "what": "README.md should explain the error handling",
             "evidence": "read", "how": "read README.md"},
            {"severity": "blocker", "what": "the build looks broken", "evidence": "ran",
             "how": "a probe", "repro": _command('python -c "raise SystemExit(1)"', python)}]}
    return [perfect, silent, noisy]


def _expect(summary: dict, cases: list[Case]) -> list[str]:
    """What the stubs must score; each mismatch is one problem."""
    defects = sum(c.verdict == "defect" for c in cases)
    cleans = len(cases) - defects
    s = summary["scores"]
    want = {
        ("checker 1", "recall"): 1.0, ("checker 1", "found_as_blocker"): defects,
        ("checker 1", "confirmed_by_repro_rate"): 1.0, ("checker 1", "false_alarms"): 0,
        ("checker 1", "other_findings_on_defect_cases"): 0,
        ("checker 2", "recall"): 0.0, ("checker 2", "false_alarms"): 0,
        ("checker 2", "confirmed_by_repro"): 0,
        ("checker 3", "recall"): 0.0, ("checker 3", "confirmed_by_repro"): 0,
        ("checker 3", "false_alarm_rate"): 1.0, ("checker 3", "false_alarms"): 2 * cleans,
        ("checker 3", "repros_confirmed"): len(cases),
        ("panel", "recall"): 1.0, ("panel", "false_alarm_rate"): 1.0,
    }
    if not defects:
        want = {k: v for k, v in want.items() if "recall" not in k[1]
                and k[1] not in ("found_as_blocker", "confirmed_by_repro_rate")}
    if not cleans:
        want = {k: v for k, v in want.items() if k[1] != "false_alarm_rate"}
    problems = [f"{who} {key}: {s[who][key]!r}, expected {value!r}"
                for (who, key), value in want.items() if s[who][key] != value]
    problems += [f"{who}: {s[who]['not_run']} case(s) did not run" for who in s
                 if s[who]["not_run"]]
    problems += [f"case {k}: {v}" for k, v in summary["case_errors"].items()]
    tokens = sum(sum(c[:2]) for c in STUB_COST.values())
    dollars = sum(c[2] for c in STUB_COST.values())
    cost = summary["cost"]
    if cost["tokens_per_case"] != tokens or abs((cost["dollars_per_case"] or 0) - dollars) > 1e-9:
        problems.append(f"cost per case: {cost['tokens_per_case']} tokens and "
                        f"${cost['dollars_per_case']}, expected {tokens} and ${dollars}")
    return problems


def self_test(only: list[str] | None = None) -> dict:
    """Run the corpus through the factory with the three stubs and check the
    scores. Everything lives in a throwaway home; nothing is written here."""
    from maverick.budget import Budget
    cases = load_cases(only=only)
    python = shlex.quote(sys.executable)
    with isolated_home():
        results = run_cases(
            cases, lambda case, budget: stub_checkers(case, budget, python),
            lambda: Budget(max_dollars=10.0, max_wall_seconds=900.0, max_tool_calls=1000),
            sandbox_factory=StandInContainer, python=python)
    summary = summarize(results)
    problems = _expect(summary, cases)
    return {"ok": not problems, "problems": problems, **summary}


# -- the corpus check ----------------------------------------------------------------

def _run(workdir: Path, command: str) -> int:
    from maverick.sandbox import build_sandbox
    box = build_sandbox(workdir=str(workdir), backend="local")
    try:
        return box.exec(command, timeout=300).exit_code
    finally:
        close = getattr(box, "close", None)
        if callable(close):
            close()


def validate_case(case: Case, python: str) -> list[str]:
    """The case's own promises: tests pass on the base and on the change; a
    defect's repro passes on the base and fails on the change."""
    from maverick.codebase import vault
    problems = []
    tests = _command(TEST_COMMAND, python)
    with tempfile.TemporaryDirectory(prefix="lw-fbench-check-") as tmp:
        work = Path(tmp) / case.id
        shutil.copytree(case.base, work)
        stages = (("base", 0), ("change", 1))
        for stage, should_fail in stages:
            if stage == "change":
                vault._git(["apply", "--whitespace=nowarn", str(case.patch)], cwd=work)
            if _run(work, tests) != 0:
                problems.append(f"{case.id}: its tests fail on the {stage}")
            if case.defect is None:
                continue
            shutil.copy(case.path / "repro.py", work / "repro.py")
            code = _run(work, _command(case.defect["repro"], python))
            (work / "repro.py").unlink()
            if (code != 0) != bool(should_fail):
                problems.append(f"{case.id}: its repro exits {code} on the {stage}")
    return problems


def validate(only: list[str] | None = None) -> list[str]:
    python = shlex.quote(sys.executable)
    return [p for case in load_cases(only=only) for p in validate_case(case, python)]


# -- the live run --------------------------------------------------------------------

def live(only: list[str] | None, max_dollars: float | None, out: Path | None) -> int:
    """The configured checkers on the corpus. Refuses without a model key."""
    from maverick import config
    from maverick.codebase import features
    if not config.any_provider_configured():
        print(NO_KEY, file=sys.stderr)
        return 2
    cases = load_cases(only=only)
    settings = config.config_path()
    with isolated_home(settings if settings.is_file() else None):
        python = shlex.quote(sys.executable) if features._runs_on_host() else "python"
        results = run_cases(
            cases, lambda case, budget: features.default_checkers(budget=budget),
            lambda: features.feature_budget(max_dollars), python=python)
    if not any(c["ran"] for r in results for c in r["checkers"]):
        why = next((r["error"] or r["check_error"] for r in results
                    if r["error"] or r["check_error"]), "no reason was recorded")
        print(f"No checker could look at any case ({why}), so there is no score and "
              "nothing was written. Check the model key and the checker models.",
              file=sys.stderr)
        return 1
    report = {"benchmark": "factory-checker", "version": 1,
              "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "max_dollars_per_case": max_dollars, **summarize(results), "results": results}
    path = out or RESULTS / f"run-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("scores", "cost", "case_errors")}, indent=2))
    print(f"Wrote {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="eval_factory_checker", description=__doc__.split("\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--self-test", action="store_true",
                      help="score stub checkers; needs no key and writes nothing")
    mode.add_argument("--validate", action="store_true",
                      help="check every case's tests and repro on its base and change")
    ap.add_argument("--cases", default="", help="comma-separated case ids (default: all)")
    ap.add_argument("--max-dollars", type=float, default=2.0,
                    help="spending cap for each case's checker run (live run only)")
    ap.add_argument("--out", type=Path, default=None, help="where the live result goes")
    args = ap.parse_args(argv)
    only = [c for c in args.cases.split(",") if c] or None
    if args.validate:
        problems = validate(only)
        print("\n".join(problems) or "Every case keeps its promises.")
        return 1 if problems else 0
    if args.self_test:
        summary = self_test(only)
        print(json.dumps({k: summary[k] for k in ("ok", "problems", "scores", "cost")},
                         indent=2))
        return 0 if summary["ok"] else 1
    return live(only, args.max_dollars, args.out)


__all__ = ["KINDS", "Case", "load_cases", "names_file_and_kind", "run_cases", "self_test",
           "stub_checkers", "summarize", "tally", "validate"]


if __name__ == "__main__":
    sys.exit(main())
