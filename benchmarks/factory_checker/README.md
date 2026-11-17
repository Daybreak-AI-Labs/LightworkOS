# Factory checker benchmark

The code factory (`maverick code feature`) asks independent checkers to look
at an author's change before a person approves it. This benchmark measures
how good those checkers are on a fixed set of planted defects.

## What it measures

The corpus in `cases/` holds 26 tiny repositories. Each case folder has:

- `base/`: the repository at its base commit, with its tests;
- `change.patch`: the change the checkers review;
- `label.json`: the ground truth;
- `repro.py` (defect cases only): a script that passes on the base and fails
  on the change.

Sixteen changes plant one defect each: off-by-one, a missing error path, path
traversal, shell injection, a concurrency bug, a test weakened instead of the
code fixed, a regression in behaviour the change did not mean to touch, a
wrong unit and a resource leak. The label names the defect's kind, its file,
the repro command and why it is wrong. Ten changes are correct but look
suspicious (an index loop that stops one early on purpose, a lock removed
from an object that became immutable, a test switched to `pytest.approx`).
In every case the repository's own tests pass on the change, so the
factory's test step cannot see the defect; only a checker can.

For each case, `benchmarks/eval_factory_checker.py` runs the real factory
path, `features.propose`, with a stand-in author that applies the patch, the
checkers your configuration sets up, no repair rounds and one look. Then it
scores each checker, and the panel (any checker), on:

- **Recall**: the share of planted defects found. A defect counts as found
  when a finding names its file and its kind, or when the finding's repro
  command was confirmed: Lightwork re-ran it and it failed on the change,
  and it passes on the base.
- **Found as a blocker**: found defects reported at blocker severity, the
  only severity that stops a merge.
- **Confirmed by repro**: the share of found defects whose finding carried a
  repro that failed only on the change.
- **False alarms**: blocker or should-fix findings on clean changes, and the
  share of clean changes with at least one.
- **Other findings on defect cases**: blocker or should-fix findings that do
  not match the planted defect. Read them: some may be real problems.
- **Cost**: dollars, tokens and seconds per case, from each case's budget.

## How to run it

You need a model key (`maverick init`, or your provider's API key). The
checker models come from your configuration: `[codebase] checkers`,
`[codebase] checker_models`, and the `reviewer` role in `[models]`.

```bash
python benchmarks/eval_factory_checker.py                    # every case
python benchmarks/eval_factory_checker.py --cases off-by-one-page,clean-pairs-index-loop
python benchmarks/eval_factory_checker.py --max-dollars 1.0  # cap per case (default 2.0)
```

The run uses a throwaway Lightwork home, so no repository, proposal or
approval reaches your own. It reads your settings file for models, budget
and work area. It writes `benchmarks/results/factory-checker/run-<UTC>.json`
with the scores, the cost and every finding. Without a key it stops with a
plain message, and if no checker could look at any case it writes nothing.

Lightwork re-runs a checker's repro command only when the steps run in a
container: set `[codebase] checker_image`, or a container work area such as
`[sandbox] backend = "docker"`. On a `local` work area the repro measure stays
at zero and only the file-and-kind rule can count a find. In a container the
image needs Python and pytest, because each case's tests run there.

Two modes need no key and write nothing:

```bash
python benchmarks/eval_factory_checker.py --self-test  # scoring proof with stubs
python benchmarks/eval_factory_checker.py --validate   # corpus check
```

The self-test runs every case through the same factory path with three stub
checkers: one reports exactly the planted defect, one reports nothing, one
reports the same noise everywhere. It fails unless they score recall 1, 0
and 0, with false alarm rates of 0, 0 and 1. The validate mode checks each
case: tests pass on the base and on the change, and each repro passes on the
base and fails on the change. `packages/maverick-core/tests/test_eval_factory_checker.py`
runs both.

## What a result means

A recall of 0.75 means the checkers found 12 of the 16 planted defects on
this corpus. A false alarm rate of 0.2 means two of the ten correct changes
drew a blocker or should-fix finding. Compare runs only when the models,
the checker count and the work area are the same; one run of a language
model is one sample, so repeat a run before trusting a small difference.

## Limits

- The corpus is small: 26 cases, one defect each, a few dozen lines of code
  per case.
- One engineer wrote every case. The defects reflect what that person
  thought of, not what goes wrong in your code.
- The cases are Python only, with no services, no framework and no history.
  Real changes are larger and mix several concerns.
- The file-and-kind rule matches words. A finding that describes the defect
  in other words, or names the code file when the label names the test
  file, does not count unless its repro was confirmed.
- The diff reviewer and the second checker for protected paths are not
  measured; only the normal checkers are.
- A checker that has seen this corpus, for example because it is public,
  may score better than it would on unseen code.
