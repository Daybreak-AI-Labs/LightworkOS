# Software development: the code vault

Put a company's repositories in Lightwork. They are held there sealed, and
swarms add and update features on branches. Nothing reaches the main branch or
the company's git host until a person approves the change.

```bash
maverick code add payments https://git.example.com/acme/payments.git \
  --test "python -m pytest -q" --token-env ACME_GIT_TOKEN
maverick code feature payments "Add refund reasons" -d "Store a reason code on every refund"
maverick code proposals            # pending | approved | rejected | merged
maverick code show <id>            # diff, test output, independent review
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
   commit. It bundles the branch before any repository code (tests) runs. The
   repository's test command then runs through the sandbox.
4. The independent reviewer reads the diff of that pinned commit. It uses a
   cross-family model where possible.
5. The sealed proposal (diff, tests, review, branch bundle) parks a
   `codebase_merge` approval: a structured approval card committing to the
   repository, branch, base and approved head, stating the test result, the
   review verdict and, when the diff is too large to store whole, a warning.
   It can be approved in the dashboard's approvals queue for 7 days; after
   that the proposal shows `expired` and `maverick code renew ID` parks a fresh
   approval. The proposal is saved before its approval is parked, so a failure
   there (`unrequested`) never loses the work. A change the swarm
   did not make produces an `empty` proposal and no approval.
6. `merge` and `push` require that approval to be an approved `codebase_merge`
   for this repository. Both verify the branch is the approved commit. Merges
   are `--no-ff`, so each is one reviewable commit. A merge that no longer
   applies cleanly leaves the vault untouched and marks the proposal
   `conflict`.
7. `sync` fetches upstream as `upstream/*` and never overwrites vault work:
   - a branch behind upstream fast-forwards;
   - a branch ahead of upstream (approved merges not pushed yet) is kept;
   - a diverged default branch has upstream merged in, and a conflict changes
     nothing;
   - new upstream branches and tags are added.

## Dashboard

**Operate → Code** (`/code`, operate permission) lists vaulted repositories and
each proposal's files, test result, review verdict and approval state. It
reads one summary (`GET /api/v1/code/summary`) that never includes code, diffs
or test output. Approve in the approvals queue; merges run through
`maverick code merge --approved`.

## Configuration

```toml
[codebase]
enable = true              # off by default: it stores your source
default_protect = "block"  # block | approve | audit for runs over vaulted code
```

## Limits

- Tests run through the configured sandbox backend; use a container backend
  for untrusted test suites.
- The vault keeps one bundle per repository. Very large monorepos pay the
  bundle cost on every checkout.
- `push` sends the branch; opening the pull request is left to the git host.
