# Software development: the code vault

Put a company's repositories in Lightwork. They are held there sealed, and
swarms add and update features on branches. Nothing reaches the main branch or
the company's git host until a person approves the change.

```bash
maverick code add payments https://git.example.com/acme/payments.git \
  --test "python -m pytest -q" --token-env ACME_GIT_TOKEN
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
   The repository's test command then runs through the sandbox on a **fresh
   copy of the pinned commit** (no remote, deleted afterwards), never on the
   author's working copy. Whatever the tests write never reaches the author
   or the proposal. The test command must install what it needs: files the
   agent left untracked or ignored are not in that copy.
4. **Repair rounds.** If the tests fail, the failing output goes back to the
   author as a follow-up goal (a child of the feature goal). Every author
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
   mounted in, so it cannot reach other rounds' or proposals' copies. Files
   elsewhere and the network are shared, so this is not a container. It
   costs about 30 ms per command. Where namespaces are unavailable (macOS,
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
6. **One budget.** Every author and checker round charges one budget for the
   feature run (`--max-dollars`, else `[budget]` and the per-goal defaults).
   `budget.check()` runs before and after each round (a governed run returns
   normally when it hits its cap); when it runs out, the loop stops, a round
   that overran is not committed, and the last pinned, tested version is
   proposed. If the first round overran, nothing is proposed. The diff
   reviewer is charged to the same budget and skipped after a stop.
7. The independent reviewer reads the diff of that pinned commit. It uses a
   cross-family model where possible.
8. The sealed proposal (diff, tests, rounds, findings, review, branch bundle)
   parks a `codebase_merge` approval: a structured approval card committing
   to the repository, branch, base and approved head. The card states in
   plain words what was and was not checked: whether the tests passed on the
   exact version being approved, how many repair rounds ran, each checker
   finding and its status, and whether a finding rests on a command that was
   run. The card gives finding counts by severity and status only; the
   finding text, which can quote code, is in `maverick code show` and the
   administrator-only Code page panel. On the `local` backend it also says
   either "Each step ran on this computer with its own processes and its own
   temporary folder. They still shared its other files and its network,
   unlike a container." or, without namespaces, "These steps ran on this
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
9. `merge` and `push` require that approval to be an approved `codebase_merge`
   for this repository. Both verify the branch is the approved commit. Merges
   are `--no-ff`, so each is one reviewable commit. A merge that no longer
   applies cleanly leaves the vault untouched and marks the proposal
   `conflict`.
10. `sync` fetches upstream as `upstream/*` and never overwrites vault work:
   - a branch behind upstream fast-forwards;
   - a branch ahead of upstream (approved merges not pushed yet) is kept;
   - a diverged default branch has upstream merged in, and a conflict changes
     nothing;
   - new upstream branches and tags are added.

## Dashboard

**Operate → Code** (`/code`, operate permission) lists vaulted repositories and
each proposal's files, test result, independent check outcome, review verdict
and approval state. It reads one summary (`GET /api/v1/code/summary`) that
never includes code, diffs or test output. An administrator's review panel
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
require_container = false  # true: refuse feature runs on the local backend
```

A workspace's own `config.toml` may only tighten these: turn the checker
and `require_container` on, raise the rounds, or choose a stricter
`default_protect`.

At the defaults a feature run makes at most five agent runs instead of one:
the author's first run, two repair rounds and two checker looks. All of them
share one spending limit. `maverick code feature --no-check` skips the
checker for one run.

## Limits

- Tests run through the configured sandbox backend; use a container backend
  for untrusted test suites.
- The vault keeps one bundle per repository. Very large monorepos pay the
  bundle cost on every checkout.
- `push` sends the branch; opening the pull request is left to the git host.
