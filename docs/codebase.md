# Software development: the code vault

Put a company's repositories in Lightwork. They are held there sealed, and
swarms add and update features on branches. Nothing reaches the main branch or
the company's git host until a person approves the change.

```bash
maverick code add payments https://git.example.com/acme/payments.git \
  --test "python -m pytest -q" --token-env ACME_GIT_TOKEN
maverick code set payments --quick-test "./scripts/quick-tests.sh {changed}" --gate "ruff check ."
maverick code feature payments "Add refund reasons" -d "Store a reason code on every refund"
maverick code proposals            # pending | approved | rejected | merged; gaps
maverick code show <id>            # what was checked, diff, test output, review
# approve codebase_merge #<n> in the dashboard's approvals queue, then:
maverick code merge --approved     # merge every approved proposal into the vault
maverick code push <id>            # push the branch to the git host for a pull request
maverick code sync payments        # bring in upstream commits
maverick code export payments ./payments   # plaintext clone for the owner
```

## Protection

- **At rest.** Each repository is one git bundle (every branch and tag). It
  is sealed with the tenant's at-rest key, bound to `codebase/<name>`, when
  encryption is on; proposals and their branch bundles are sealed the same
  way.
- **In use.** Plaintext exists only in a private (0700) working copy for as
  long as a task needs it. The copy is removed when the task ends.
- **In flight.** Every run over the code starts labelled `code:<repo>` for
  [information-flow control](ifc.md). The repository's protection mode
  (`--protect`, default `[codebase] default_protect = "block"`) is enforced
  whatever the global `[ifc]` mode. An agent that holds the code cannot send
  it through `email`, `http_fetch`, `web_search`, `mcp_*` or any other
  external tool.
- **Credentials** are never stored. A repository names an environment
  variable (`--token-env`), read at use time and handed to git through a
  short-lived askpass helper, never argv or a persisted URL. A source URL
  containing credentials is refused.
- **Git hardening.** The host never runs git in a directory an agent can
  write. The vault opens as a private, host-owned bare repository; agents get a
  separate clone. After a run, the change is committed from the working tree's
  files with host-owned plumbing (`read-tree`, `add`, `write-tree`,
  `commit-tree`, `update-ref`), so the run's own `.git` (hooks, config, a
  `gitdir:` pointer) is never read. Every host git call also disables hooks,
  external diff drivers and fsmonitor. The working copy lives in its own
  private directory, never beside the host repository, so a run cannot reach
  host git config (a planted `filter` driver in `.gitattributes` has no
  definition to run). A change that adds an embedded git repository is
  refused. With the unsandboxed `local` backend the agent already has a shell
  on the host, so use a container backend for code you do not trust.

## A feature request, end to end

1. A private working copy on a new `lightwork/<title>-<id>` branch.
2. A goal runs the governed swarm with that working copy as its sandbox
   workdir, under the run's labels. If the run fails, the goal is marked
   `failed` and nothing is proposed.
3. The host commits the working tree's files and pins the branch to that exact
   commit. It bundles the branch before any repository code (tests) runs.
   The repository's tests then run through the sandbox on a **fresh copy of
   the pinned commit** (no remote, deleted afterwards), never on the
   author's working copy, in the tiers described under
   [Test tiers](#test-tiers): the quick tier after each author round (the
   full suite when there is none). Whatever the tests write never reaches
   the author or the proposal. A test command must install what it needs:
   files the agent left untracked or ignored are not in that copy.
4. **Repair rounds.** If the tests fail, the failing output goes back to the
   author as a follow-up goal (a child of the feature goal). Once the quick
   tier passes, the full suite and the gate run on the same pinned commit;
   a failure there goes back to the author too, from the same rounds and
   budget. Every author
   round works in a fresh copy of the pinned head at a new random path,
   made after the previous step ended and removed once committed, so
   nothing a test run or a checker wrote carries over (files the author left
   untracked or ignored do not carry over either). The new files are
   committed and pinned again, and the tests run again on a fresh copy. This
   repeats up to `[codebase] repair_rounds` times (default 2). Each author
   round, test run and checker look is a contained step. On the `local`
   backend, where Linux allows user namespaces, each command of a step runs
   in its own user, PID and mount namespace (`unshare --user
   --map-root-user --pid --fork --kill-child --mount --mount-proc`): when it
   ends, the kernel stops everything it started, whatever its environment,
   and it sees an empty private temporary folder with only its own copy
   mounted in, so it cannot reach other rounds' or proposals' copies. Root
   in that namespace only sets up the mounts; the command runs in a nested
   user namespace as the real user and group (`unshare --map-user
   --map-group`), so tests behave as in the project's own CI. If the work
   area cannot be set up, the command does not run and the card says so
   instead of reporting a test result. Files elsewhere, the network and
   this computer's services are shared, and a few tools (a language server,
   a patch fallback) start host processes directly, so this is not a
   container. It costs about 15-30 ms per command. Where namespaces are unavailable (macOS,
   Windows, hosts that forbid them), each command carries a step marker and
   the step's end stops every process still carrying it (best effort, Linux
   `/proc`; a process that clears its environment escapes).
5. **The independent checker** (`[codebase] checker`, on by default). A
   separate goal with a fresh context gets the request and its own throwaway
   copy of the pinned commit, where `git diff <base> HEAD` shows the change.
   It never sees the author's goal, transcript or reasoning: its run denies
   the tools that read past goals or shared memory (`recall_past_goals`,
   `memory`, `kv_memory`, `spend_report`), recalls no prior goals and gets
   no experience guidance in its brief. Its task keeps only finding counts
   as its result, and its result is not sent in webhooks. It runs in the
   sandbox under the same `code:<repo>` label and protection mode as the
   author. Its copy has no remote, and nothing in it is read back, so it
   cannot push, merge or change the proposal. It reports findings: severity
   (`blocker`, `should-fix`, `minor`), what is wrong, and whether it ran a
   command or read the code to know. Blockers go back to the author for a
   repair round (from the same `repair_rounds` allowance), then the checker
   looks again, up to `[codebase] check_rounds` looks (default 2). Each
   finding ends `fixed` (a later look confirmed it gone), `still open` (sent
   back but not confirmed fixed) or `not attempted` (never sent back:
   should-fix and minor findings, or no rounds left). Its model is the
   `reviewer` role (`[models] reviewer`), so it can differ from the
   author's; when both share a provider family and
   `[verification] cross_family_model` is set, that model is used instead.
6. **Lightwork re-runs what a checker says it ran.** A finding may carry a
   `repro`: one command whose non-zero exit shows the problem, plus up to
   three `probe_files` (relative paths inside the copy, 20 KB each, never
   `..` or under `.git`, and never through a link in the copy). A repro is
   a command a model wrote and nobody approved, so Lightwork runs it only
   when the steps run in a container (a container backend, or the checker
   image below). Otherwise the finding says "not re-run: the steps do not
   run in a container", keeps the checker's word, and the card lists it as
   a gap. In a container, after each look Lightwork runs each repro on a
   fresh copy of the pinned commit, with the probe files written first,
   through the same sandbox, contained step and network policy as the
   tests, for at most 10 minutes. The probe files never reach the proposal.
   A non-zero exit makes the finding `confirmed`. Exit zero or a timeout
   makes it `not reproduced`, shown as read only. A refused probe file or a
   work area that could not be set up makes it `not run`, and it is not
   counted as re-run. Its severity stays either way, so a person decides.
   After each author repair every confirmed repro runs again on the new
   commit: exit zero is "fixed: its repro command passed on the repaired
   version (the author saw the command)". The author did see the command,
   so it could make the command pass without fixing the problem. The
   checker's next brief therefore lists the finding again and asks it to
   confirm the fix: with its id in `fixed` the card adds "a later look
   confirmed it"; with its id in `still_open` the finding stays open and
   the card shows both facts. Until a later look confirms it, the card has
   the gap "N blocker(s) passed their repro command after a repair, but no
   later look confirmed the fix", and the change never reads as clean.
   Findings without a confirmed repro keep the checker's word, labelled
   "fixed: the checker's word". Each re-run calls `budget.check()` first
   and counts as one tool call; at most `[codebase] max_repros` (default 5)
   run per look, and the rest say "not re-run".
7. **Several independent checkers.** `[codebase] checkers` (1-3, default 1)
   checkers look at each version. Each is its own fresh-context run on its
   own copy and its brief lists only its own earlier findings, never
   another's. Each finding records which checker found it, and a blocker
   from any checker blocks. `[codebase] checker_models` names one model per
   checker; where it is empty or short, the rule above applies. The card
   names each checker's model and whether it shares the author's provider
   family. When every checker does, it adds the gap "Every checker used the
   same kind of model as the author, so they may share its blind spots."
   Each extra checker adds one agent run per look, plus the repairs its
   blockers cause.
8. **A checker container.** With `[codebase] checker_image` set, checker
   runs and repro re-runs use that image instead of the configured work
   area, with the rest of `[sandbox]` (network, memory, user). The image
   never lowers isolation: the `local` and `docker` work areas run it on
   Docker, `gvisor` on Docker with gVisor's runtime, and `podman` on Podman.
   Any other work area (firecracker, kubernetes, ssh and the rest) cannot
   carry an image this way, so the check reads "could not run". The image
   is never pulled (`--pull never`): a missing one reads "could not run"
   with the command an administrator runs to build or pull it. Only the
   organisation sets the image, because it decides every re-run's result.
   On a root host the image runs as its ordinary user (`1000:1000`) and
   each throwaway copy is handed to that user; the copies stay inside a
   folder only root can open. The tests still run on the configured
   backend. Before the first look Lightwork runs a command that does
   nothing in the image; if that fails, the check reads "could not run"
   with the reason. It never falls back to this computer. `deploy/checker/`
   builds an image with Python 3.11 and 3.12, git, PostgreSQL 16 and
   Chromium with Playwright; see its README for the database variables
   (`MAVERICK_PG_DSN`, `DATABASE_URL`, `PGHOST` and the rest).
9. **One budget.** Every author and checker round charges one budget for the
   feature run (`--max-dollars`, else `[budget]` and the per-goal defaults).
   `budget.check()` runs before and after each round (a governed run returns
   normally when it hits its cap); when it runs out, the loop stops, a round
   that overran is not committed, and the last pinned, tested version is
   proposed. If the first round overran, nothing is proposed. The diff
   reviewer is charged to the same budget and skipped after a stop.
10. The independent reviewer reads the diff of that pinned commit. It uses a
   cross-family model where possible.
11. The sealed proposal (diff, tests, rounds, findings, review, branch bundle)
   parks a `codebase_merge` approval: a structured approval card committing
   to the repository, branch, base and approved head. The card states in
   plain words what was and was not checked: whether the tests passed on the
   exact version being approved, how many repair rounds ran, each checker
   finding and its status, and whether a finding rests on a command that was
   run. The card gives finding counts by severity and status only; the
   finding text, which can quote code, is in `maverick code show` and the
   administrator-only Code page panel. On the `local` backend it also says
   either "Commands each step ran in its work area had their own processes
   and temporary folder. They still shared this computer's other files,
   network and services, unlike a container." or, without namespaces, "These steps ran on this
   computer without a container or separate processes, so they were not
   isolated from each other." Its "unresolved assumptions" list every gap:
   tests failing or not configured, the checker turned off, unable to run or
   not looking at the final version, blockers still open, the budget running
   out or cutting the check or the diff review short, or the steps running
   on this computer rather than in a container. It never
   calls a change checked when one of these holds. It also warns when the
   diff is too large to store whole. The card can be approved in the
   dashboard's approvals queue for 7 days; after that the proposal shows
   `expired` and `maverick code renew ID` parks a fresh approval. The
   proposal is saved before its approval is parked, so a failure there
   (`unrequested`) never loses the work. A change the swarm did not make
   produces an `empty` proposal and no approval. Proposals saved before
   repair rounds and the checker existed still load; they read as not
   independently checked.
12. `merge` and `push` require that approval to be an approved `codebase_merge`
   for this repository. Both verify the branch is the approved commit. Merges
   are `--no-ff`, so each is one reviewable commit. A merge that no longer
   applies cleanly leaves the vault untouched and marks the proposal
   `conflict`.
13. `sync` fetches upstream as `upstream/*` and never overwrites vault work:
   - a branch behind upstream fast-forwards;
   - a branch ahead of upstream (approved merges not pushed yet) is kept;
   - a diverged default branch has upstream merged in, and a conflict changes
     nothing;
   - new upstream branches and tags are added.

## Test tiers

Each repository has up to four test commands. All are optional and belong
to the repository, not to `[codebase]`: set them with `maverick code add`,
change them with `maverick code set NAME --quick-test ... --test ...
--gate ... --heavy-test ...` (an empty value clears one), or with **Test
commands** on the Code page. Changing them needs the same authority as
adding the repository: the command line on the server, or an
administrator on the Code page. A workspace changes only the repositories
in its own vault, and a workspace's `config.toml` cannot set them.
Repositories added before tiers existed keep running their one test
command as before.

| Tier | Command | When it runs |
| --- | --- | --- |
| Quick | `quick_test_command` | After each author round while repairing. `{changed}` becomes the paths the change touches that exist in that version (relative, shell-quoted; deleted and renamed-away paths are left out). With more than 200, the full suite runs instead. |
| Full | `test_command` | Once the quick tier passes, on the same commit; again on the final commit if it changed since. Without a quick tier it runs after each author round. |
| Gate | `gate_command` | With the full suite: lint and other gates. The author's brief names it. |
| Heavy | `heavy_test_command` | Tests that need services (a database, a browser), on the final commit, only in `[codebase] checker_image`. Without the image it reads "not run (needs the checker image)"; it never runs on this computer. |

`{changed}` lists every changed file, not only tests: documentation,
data and source files too. So the quick command must accept any path. A
plain `pytest -q {changed}` does not: it fails when a change touches only
`app.py` or adds `NOTES.md`, and then repair rounds are spent on something
the author cannot fix. Pass the paths to a script that picks the tests
instead, as the example for this repository below does. Write `{changed}`
on its own, never inside quotes: each path is already quoted, and inside
double quotes the shell would run what a file name contains. Lightwork
refuses a quoted placeholder. Commands are one line of plain text, at most
2,000 characters: control characters (tab and newline included) and
bidirectional override characters are refused.

Every tier runs on a fresh copy of the pinned commit in a contained step,
and `budget.check()` runs before each one: a tier the spending limit
stopped reads "not run (the spending limit ran out)". After the last author
round, before the card is written, the full suite and the gate run again if
the commit changed since they last ran, then the heavy tier.

The card has one line per tier with its result on the final commit:
passed, failed, not run (with the reason) or not configured. "Tests:
PASSED" appears only when the full suite passed on that commit. A quick
pass alone never counts, and when the full suite did not run (the spending
limit, or the repair rounds ran out before the quick tier passed) the card
says so and lists it as a gap. A failing quick tier, a gate or heavy tier
that did not pass or did not run, are gaps too. `maverick code show`
prints the output of each tier that ran on the final commit; Copilot's answer about proposed code changes
names each tier's result.

### Lightwork's own repository

These commands mirror this repository's CI: a quick selected run on each
change, everything before merge. They assume the work area (for example the
checker image) has the packages installed as `.devcontainer/post-create.sh`
does. They are documentation, not built into the product.

- Quick: `scripts/select_pr_tests.py` writes the selection to a JSON file
  (its standard output is a summary), so read the paths from there:

  ```bash
  python3 scripts/select_pr_tests.py --files {changed} --output .lw-tests.json >/dev/null && python3 -m pytest -q -n 2 $(python3 -c 'import json; print(" ".join(json.load(open(".lw-tests.json"))["paths"]))')
  ```

  A change the selector maps to the full suite (or to nothing) gives no
  paths, so pytest runs every test: it errs toward running more.
- Full: `python3 -m pytest -q -n auto --dist loadfile -m "not heavy_concurrency"`
- Gate: `bash scripts/pre-push-lint.sh`
- Heavy: the live-Postgres files the CI `postgres` job runs, with
  `MAVERICK_PG_DSN` from the checker image:

  ```bash
  python3 -m pytest -q --timeout=180 $(sed -n '/POSTGRES_TEST_FILES: >-/,/^    services:/p' .github/workflows/ci.yml | grep -o 'packages/[^ ]*\.py')
  ```

## Dashboard

**Operate → Code** (`/code`, operate permission) lists vaulted repositories and
each proposal's files, test result, independent check outcome, review verdict
and approval state. It reads one summary (`GET /api/v1/code/summary`) that
never includes code, diffs or test output. **Test commands** on a
repository (administrators) sets its test tiers. Copilot has no way to set
them, as it has none for adding a repository. An administrator's review panel
opens with "What was checked", in the same words as the approval card. Ask
Copilot "What was checked on the proposed code changes?" for the same points
(administrators only, like the panel). Approve in the approvals queue; merges
run through `maverick code merge --approved`.

## Configuration

```toml
[codebase]
enable = true              # off by default: it stores your source
default_protect = "block"  # block | approve | audit for runs over vaulted code
repair_rounds = 2          # 0-5 more author runs after failing tests or blockers
checker = true             # the independent checker (one agent run per look)
check_rounds = 2           # 1-3 looks; a second look confirms blocker fixes
checkers = 1               # 1-3 independent checkers per look
checker_models = []        # one model per checker; empty: the reviewer rule
checker_image = ""         # e.g. "lightwork-checker:1" (deploy/checker)
max_repros = 5             # 0-20 findings Lightwork re-runs per look
require_container = false  # true: refuse feature runs on the local backend
```

A workspace's own `config.toml` may only tighten these: turn the checker
and `require_container` on, raise the rounds, `checkers` or `max_repros`, or
choose a stricter `default_protect`. `checker_image` and `checker_models`
are the organisation's alone: a workspace file that sets them is ignored
and reported.

At the defaults a feature run makes at most five agent runs instead of one:
the author's first run, two repair rounds and two checker looks. All of them
share one spending limit. Each extra checker adds one agent run per look (at
`checkers = 3` and two looks, four more runs), plus the repairs its
blockers cause. Repro re-runs are commands, not agent runs: at most
`max_repros` per look, each one tool call. `maverick code feature
--no-check` skips the checkers for one run.

## Limits

- Tests run through the configured sandbox backend; use a container backend
  for untrusted test suites.
- The vault keeps one bundle per repository. Very large monorepos pay the
  bundle cost on every checkout.
- `push` sends the branch; opening the pull request is left to the git host.
