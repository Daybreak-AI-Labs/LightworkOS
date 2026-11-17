# Changelog

All notable changes to Lightwork are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The setup wizard saves a search backend only when it needs no key or its key
  is present; supply the provider key before selecting a keyed backend.
- Mattermost and Threads allow-lists now use user IDs only, and the dashboard
  rejects Mattermost entries that are not 26-character IDs; replace saved
  usernames with the person's provider ID.
- Agent MCP tokens saved by `trust add` and by attenuated grants are now hashed;
  clients keep using the original bearer token, and existing raw tokens still
  authenticate.
- Dependency support now includes pypdf 7, cyclonedx-bom 8 and websockets 17,
  while simplejson must remain below 4; use the supplied dependency constraints.
- Shield's published held-out base64 evasion detection is now 83.9% (26 of 31),
  measured without a readable plaintext cue; use this result when assessing
  protection. Prompt-attack scoring now decodes one bounded layer of base64,
  so text that carries a base64-encoded instruction can be flagged where it
  was not before.
- An IMAP source's password variable must be named as a mailbox password (for
  example `IMAP_PASSWORD`), and the product's own credential variables are
  refused. The name is checked on every poll as well as on save, so an existing
  source that uses a refused name stops polling: rename its password variable.
- OpenOCD now refuses a workspace containing a `.cfg` or `.tcl` file unless
  flashing is allowed; review those files and the flashing permission before
  running hardware work.
- MongoDB now refuses `mongodb+srv://` while an egress policy is active; use an
  explicitly permitted `mongodb://` endpoint.
- The S3 tool and the attachment S3 mirror now use path-style addressing;
  ensure any custom S3 endpoint they use supports that addressing style.
- Model-written `@name` mentions in Mastodon and Mattermost replies are now
  neutralised, including inside code; e-mail addresses and URLs are left alone.
  Copy commands with care because those replies contain an invisible separator.
- `audit_days` and all other retention periods now require whole numbers and
  reject booleans; replace values such as `true` or fractional days before
  enforcing retention.
- A sidecar per-principal call limit of `0` now refuses calls; set a positive
  limit when that principal should be allowed to call.
- Re-enrolling an external agent now preserves limits that are not supplied
  and refuses changing a lifetime budget to monthly; request any intended
  limit changes explicitly.
- Serial and ROS writes now require approval; allow for an approval step in
  workflows that write to devices.
- Provider spending now uses one deployment-wide ledger. Earlier per-tenant
  ledgers are folded in once: the current period's totals and unresolved
  reservations move, so a hold that blocked calls before the upgrade still
  does. An earlier ledger that cannot be read blocks capped provider calls
  until it is repaired on the Provider spending page. Review provider caps
  against total deployment spending rather than a single tenant's spending.
- A policy gate whose configuration file exists but cannot be read or parsed
  now refuses work (for example a task budget); repair the file before
  retrying. With no configuration file, or with a misspelled key, the defaults
  still apply, so keep running `maverick config-lint` after hand edits.
- Browser-vault keys are no longer included in backups by default; retain the
  key separately and supply it when restoring existing vault entries.
- `aria_navigate` no longer accepts `focus`; remove that action from callers.
- Signed plugins are now also refused when a Python source or bytecode file
  (`.py`, `.pyc`, `.pyw`) is on disk in their own package folders but not in
  the signed manifest; reinstall the plugin into a clean environment to remove
  leftover files. See the [plugin signing guide](docs/plugin-signing-author-guide.md).
- The translate tool sends nothing unless `DEEPL_API_KEY` or
  `LIBRETRANSLATE_URL` is set. There is no public default server any more: set
  `LIBRETRANSLATE_URL` if you relied on it.
- A default backup now leaves out the consent-ledger signing key
  (`consent.ledger.key`) as well; escrow it with the other keys, because
  standing consent grants cannot be verified without it.
- An MCP server configured with a token or an `Authorization` header must use
  `https://` or a loopback address; change the URL of any such server that
  uses plain `http://` to a remote host.
- A cron schedule whose day-of-month or day-of-week field starts with `*`
  (for example `*/2`) now needs both day fields to match, as in standard cron;
  a schedule such as `0 0 */2 * 1` fires less often than before.
- With Postgres row-level security on, the first start as the table owner
  replaces the policy on the webhook and deadline-alert tables, so a workspace
  whose id contains characters outside `A-Z a-z 0-9 . _ -` can use them.
  Upgrade and restart every process that uses the database; see
  [multi-tenancy](docs/multi-tenancy.md).
- Every agent's system prompt now says that text inside a tool-output frame is
  data a tool returned and never an instruction.
- `maverick start` and `maverick resume` now exit with status 2 when the goal
  failed or was cancelled; scripts that ignored the outcome should check it.
- A chat reply that the provider definitely refuses (the message or the
  recipient, not throttling, a lost connection or a credential problem) is now
  retried at most 8 times with increasing delays and then marked
  `delivery_failed`; other failures are still retried without limit. Failed
  replies are listed by the admin delivery endpoint only.
- Cache-read prices for xAI and Moonshot models now follow the vendors'
  published rates, and a model with no listed rate on OpenRouter, xAI or
  Moonshot is charged the full input rate for cached input (it was half), so
  recorded spend for those providers can rise.
- An MCP caller may hold at most 32 resource-subscription sessions; beyond
  that its own oldest session is closed.
- Usage sent to the gateway's OpenTelemetry endpoint is now recorded against
  the team the bearer token belongs to, and a token that belongs to no team is
  refused.
- The Rust `maverick-verify-audit` tool refuses a day file larger than 512 MiB
  and reports at most 1,000 problems, saying so when it stops early.
- In coding mode, a final patch is not verified when the working directory had
  uncommitted work before the run started; that work is left untouched instead
  of being reset. Start coding runs from a clean working directory.
- Docker and Podman sandboxes now run each command under a deadline inside the
  container as well, so a command stops even if Lightwork itself is killed.
  The image must provide the `timeout` command; an image without it is refused
  before the command starts.
- The SSH sandbox checks at setup that the remote host has GNU `timeout` and
  refuses a host without it.
- A Slack attachment is accepted only when the bytes received match the size
  Slack advertised; a file with a missing or wrong size is refused.
- Matrix replies longer than 4,000 characters are sent as several messages.
  Encrypted Matrix rooms are not supported.
- The Python client raises on a success response that is not the documented
  shape (for example an empty body where an object is expected) instead of
  returning it.
- Tool names in governance deny and require-human lists are matched without
  regard to case, and deny lists from the configuration and the environment
  for agent-to-agent calls are combined instead of one replacing the other.
  `maverick doctor` notes a listed name that matches no built-in tool.
- `maverick airgap` now also checks role models, MCP servers, federation
  peers and enabled channels in the audited configuration, so a deployment
  that passed before can now report a finding.
- Malformed `[safety]` and `[sandbox]` sections are reported instead of being
  ignored.
- When a connector has several accounts and none is pinned, the caller's own
  usable account is chosen before a shared one. Reconnecting a connector under
  a different provider identity stops its sharing until it is shared again.
- Knowledge deposited into Cortex records the authenticated depositor as its
  source; a label supplied by the caller is kept after it, in quotes.
- An external agent may have at most its configured number of screening
  approvals waiting; further screening requests are refused until some are
  decided or expire.
- Earned-autonomy evidence is now tied to the signed audit log. Evidence from
  an earlier release is taken over once, on first use, if its own chain is
  intact and the audit log verifies (or audit signing is switched off). If the
  audit log does not verify, the evidence is not taken over and no new
  evidence is recorded until `maverick audit verify` passes. After the
  takeover, evidence that was shortened or rewritten is reported as broken
  and no new evidence is accepted on top of it; a demotion or revocation is
  always recorded.
- When a governed web request is redirected to a different origin, credentials
  and custom headers such as `X-Api-Key` are no longer sent on; only a short
  list of ordinary headers follows the redirect. Each redirect destination is
  checked under the same private-network setting as the first request.
- A zero-dollar budget set on a goal dispatched over gRPC is now carried as an
  explicit zero. Upgrade the dispatcher and its workers together: an older
  worker ignores the new field.
- Generating a presigned S3 link is now treated as a write and goes through
  the same approval rules as other governed writes.
- The undo window for an approval decision now starts when the decision's
  audit record has been delivered, not when the decision was entered.
- Rewinding a goal is refused while that goal is executing.
- Audit writes from federation peers that have not authenticated are
  rate-limited per network peer.
- A Vault Transit KMS address (`[kms] address` or `VAULT_ADDR`) must use
  `https://`, or `http://` on a loopback address, with no user name or
  password; otherwise encrypted data cannot be opened until it is corrected.
- A tenant's own `[kms] dek_cache_ttl` now applies to that tenant. An invalid
  value or unreadable configuration is logged and turns data-key caching off.
- Tenant egress rules compare IP addresses in canonical form: decimal, hex,
  octal, shortened, IPv4-mapped and bracketed spellings of an address match
  an allow or deny rule written for that address.
- The file-write tool writes only to regular files, not to a pipe or device,
  and refuses a write when the file or a folder on its path is replaced by a
  link leading out of the workspace while it writes.
- A Python, TypeScript or gRPC plugin tool with a built-in tool's name is
  skipped with a warning, even when that built-in is off. The Android and iOS
  simulator tools are registered only for a workspace on the same machine.
- On sandboxes other than the local one, stdin input to a program (such as a
  notebook's code) is limited to 64 KiB; larger input is refused.
- The notebook tool runs the sandbox's `python3`, or else `python`, and says
  plainly when neither is there. Whisper.cpp transcription converts non-WAV
  audio with the sandbox's own `ffmpeg`; install it in the sandbox image.
- The database tool caps MySQL and MariaDB SELECTs at its row limit through
  the session's `sql_select_limit`. The MongoDB tool uses only the database
  named by `MONGODB_DB` or the `MONGODB_URI` path, refuses any other `db`,
  and needs a non-empty filter to update or delete.
- The serial tool accepts only serial device names (`/dev/ttyS*`,
  `/dev/ttyUSB*`, `/dev/ttyACM*`, board UARTs, `/dev/serial/by-id/*`,
  `/dev/cu.*`, `COM<n>`) and caps its timeout, now also used for writes, at
  5 seconds.
- With `MAVERICK_FETCH_RESPECT_ROBOTS=1`, the HTTP fetch tool applies
  robots.txt Allow and Disallow rules with wildcards, the most specific rule
  winning, so some pages change between allowed and blocked.
- Shopify refunds are refused unless the order has exactly one successful
  sale or capture in the refund's currency; refund other orders in Shopify.
- The browser tool reports a key press that only sent key events (no click or
  form submission followed) as dispatched, and refuses combinations such as
  `Control+A`.
- The ImageMagick tool reads only PNG, JPEG, GIF, WebP, BMP, TIFF and
  PPM/PGM/PBM/PNM files, decoded as their extension says, and writes those
  formats plus ICO and PDF, under fixed memory, disk and 60-second limits.
- Hugging Face OCR now also needs `OCR_BACKEND=hf`. Discord posts and replies
  no longer notify mentioned users or roles.
- Memory writes and governed Python session statements are screened for
  instruction-injection markers across line breaks, so more ordinary text can
  be flagged (for example a `curl -X POST` whose URL is on the next line).
  With the shield installed, a goal-memory write is refused when the shield
  cannot be configured or its scan does not finish.
- A pending workspace restore review that cannot be read or verified is set
  aside as `review.json.unusable-<n>` with a warning, and its safety snapshot
  is kept. An expired, unused review is removed with its safety snapshot.
- The learning journal keeps its newest entries within 16 MiB instead of
  refusing new ones once full. The promotion ledger refuses with "promotion
  ledger journal is incomplete" when its saved view holds records the
  journal lacks.
- Recording an Ekko pilot run for a device whose enrollment was revoked
  answers 409 and asks to enroll the device again.
- Reading a published knowledge analysis needs read access to every source
  item and that each source's current admission still allows analysis.
  Evidence-graph evidence must be reviewed by someone other than whoever
  added it; evidence with no record of who added it must be submitted again.
- Further llama.cpp replicas of the local runtime keep their prompt cache in
  `llamacpp-<port>.promptcache`; replica 0 keeps `llamacpp.promptcache`.
- On Postgres, malformed or duplicate legacy provider spend receipts no
  longer stop the one-time operation-record backfill; they are logged.
- A training receipt is not issued once the receipt store holds 100,000
  receipts or would grow past 64 MiB, the limits its reader already applied;
  the refusal names the storage boundary.
- An automation opportunity is not proposed while any completed run has no
  recorded cost, and the reason shown says so.
- A document whose text reads like instructions to an assistant (for example
  "you are now ready to log in") is no longer dropped without a trace. It is
  held, and Held documents in the Knowledge library shows why. An
  administrator can include it, as quoted material only, or keep it out; a
  kept-out document uploaded again is held for a new review.
  Documents dropped before this change were never stored and cannot be
  recovered; upload them again to have them held for review.
- An outside agent that screens an action without a risk level now gets
  Lightwork's own rating of that tool. A tool nothing rates is still refused,
  as before, for an agent whose highest allowed risk is low or medium. For an
  agent allowed high risk, it now waits for a person's approval instead of
  running. Rate the tool at enrollment to avoid either.
- Two outside-agent run reports with the same idempotency key now record one
  task, even when they arrive together. The world database moves to schema
  53 on first open.
- A federation peer that the trust registry refuses (missing, revoked or
  expired) can no longer fetch this node's agent card or poll a task's
  status with its shared token. Register the peer in `[agent_trust]`.
- A federation peer that reaches its request limit is still refused, and the
  log now says how to continue. An administrator can raise the limit or start
  the count again from Agent trust > Partner request limits, or with
  `maverick trust admission-limit PEER --limit N` or `--reset`. Earlier
  requests stay on record, and each change is audited. A reset does not free
  the workspace's 250,000-request storage limit; once that is full every
  partner is refused, and an installation administrator can raise it there
  or with `--storage N` (more disk space, slightly slower checks). If the
  saved limits can't be read, new partner requests are refused until an
  installation administrator starts over (`--start-over`); the unreadable
  file is kept. Installation administrators can also show and change these
  limits through the dashboard Copilot (the Connections action family).
- Only the task that linked an outcome key, a later turn of the same chat
  or task by the same person, or an administrator can link that key to
  different work. Other runs get an error and the link stays. Links saved
  earlier keep working.
- Slack sends its bot token only to `https://files.slack.com` and follows
  no redirects for shared files. Files stored outside Slack are not opened,
  and the person is told when a shared file was not opened or fetched.
- A sealed discovery title is now signed for that purpose only and cannot
  pass as a signed eDiscovery export. `verify_export` also rejects a
  manifest that is not an export manifest. Titles and exports made by
  earlier releases still verify.
- A successful MCP tool result (no `isError`) is always treated as a
  success, even when its text starts with "REFUSED", "DRY RUN" or a warning
  sign. Such text no longer marks a high-risk action as not done, which had
  let a rerun repeat it.
- On the Local backend, `office_convert` now runs LibreOffice without network
  access (`unshare -rn`), so a document's links cannot make the host fetch
  any address. It uses the first Python that can load LibreOffice's bridge
  (`uno`), so a pip or venv install whose own Python cannot load it now
  converts; before, every such call failed. Where no such launch works
  (macOS, Windows, restricted user namespaces, most containers, no bridge),
  conversion is refused with the reason and not offered; use a Docker,
  Podman or Kubernetes sandbox backend there.
- The `compute` tool runs each SymPy operation in a separate process and
  stops it after 10 seconds with a plain error. With SymPy installed this
  includes plain `evaluate` (even `2+3*4`); each such call takes one to two
  seconds longer while the process starts.
- `maverick confidential-compute` no longer counts `/sys/firmware/tdx` as
  proof of a TDX guest; that folder appears on TDX hosts. Guests are still
  detected by `/dev/tdx_guest` or the `tdx_guest` CPU flag.
- The calendar tool checks every CalDAV request, redirects included, against
  the egress policy (`[enterprise] allowed_hosts`, tenant egress). Add your
  CalDAV server's host to the allow-list in enterprise mode.
- The setup wizard re-asks for trusted insight and tax publisher keys until
  each is 64 hexadecimal characters, and saves them in lower case.
- `dns_lookup` now obeys the network policy and egress lists: a name the
  policy blocks is not looked up. Add the host to the allow list if needed.
- `embedded_device` refuses `i2c_write` until `[embedded] allow_flash = true`,
  the same opt-in as flash and reset. Turn it on to keep writing registers.
- Hosted `image_edit` edits and every `huggingface` call need a human
  approval when governed connectors are on, like `replicate run`.
- `str_replace_editor` and `spreadsheet` writes count against
  `[limits] file_write_quota_mb`, as `write_file` writes already did.
- The `s3`, `ses` and `sns` tools appear only with
  `[tools] credential_connectors` on (`MAVERICK_ENABLE_CRED_TOOLS`), like
  `lambda` and `dynamodb`. Turn it on (the wizard now asks) to keep using
  them; a saved flow that names one says which setting to turn on.
- `vertex generate` has no built-in model: name one, and it must be on
  `[access] allowed_models` (as `vertex:<model id>`) when that list is set.
- Each `vertex` tool call is now charged to the run budget, and no call is
  sent once the budget is spent. The price is the one you set in Settings >
  Models, under Prices for the models you use, for the exact route
  (`vertex:<model id>`, or `vertex:endpoints/<endpoint id>` for `predict`),
  else a tracked price if Lightwork has one, else the safety ceiling
  ($10/$50 per million tokens); the spending-limit message and the cost line
  then say so. Set the route's price to be charged your real rate. A reply
  with no token counts (custom endpoints usually give none), an error reply
  included, is charged an estimate from the text length and marked
  estimated. The spend receipt carries the charge and how it was priced, and
  `[budget.provider_caps] vertex` is now enforced instead of refusing every
  call. Before sending, each call holds room for its longest reply: the
  per-call output allowance model calls use (`[context] max_output_tokens`,
  or `MAVERICK_AGENT_MAX_TOKENS`; by default scaled from the context window,
  at least 4096 tokens). A call that cannot fit is not sent. `generate` asks
  Vertex for at most that many tokens, or the smaller `max_output_tokens`
  you give it. `predict` cannot limit a custom endpoint's reply, so a longer
  reply is still charged in full and can pass the limit by that much. A flow
  cannot use `vertex` as a direct action step, because it has no run budget:
  saving one is refused, and an older saved flow's `vertex` step stops with
  "unsafe direct action tool 'vertex'". Call it from an agent step.
- `oracle` asks for `confirm` when a read hides a second statement in
  Oracle `q'...'` quoting, or after a `show`/`desc` line, a `/` line, a `.`
  line or a blank line. Remove blank lines inside a query to run it as a read.
- `notebook_exec` keeps `%` and `!` lines that sit inside a string, a bracket
  or a continued line; only lines that start a statement are dropped.
- Every built-in tool now has an explicit risk rating. Discovery and
  read-only tools such as `find_tools` are low, so a low or medium
  `max_risk` keeps them. Unrated plugin and MCP tools still count as high.
- The gRPC server starts again: its generated stubs now import as part of
  the package. Stubs an earlier release generated are rebuilt on next start;
  with runtime generation off, run `maverick gen-stubs` after upgrading.
- The database tool on MySQL Connector/Python now reads at most one row
  past the row limit, even when the query has its own larger LIMIT.
- The database query timeout now also applies on MySQL Connector/Python and
  MariaDB Connector/Python: the server stops the statement at the deadline
  and a timed-out query is cancelled. Before, only PyMySQL was bounded.
- Image OCR runs Tesseract with one OpenMP thread unless OMP_THREAD_LIMIT is
  set, so a busy host no longer pushes small images past the OCR timeout.
- The SSH sandbox now says "The ssh connection failed" when ssh itself
  exits 255, and no longer reports a remote command's own exit 255 as a
  connection failure.
- A restore that stopped part-way, in any workspace, is now undone when the
  dashboard, a CLI command, `maverick-mcp`, `maverick-evolve`, the gRPC
  server or the arq queue worker starts. If its record cannot be checked
  (for example the backup signing key changed), start-up stops with a
  message saying what to do. The dashboard then answers `/livez`, gives
  probes a short message, closes websockets, and shows the full steps to
  the local owner, or to an administrator who enters the dashboard token
  on its page. `--help` still works.
- On Postgres, a world read made inside an open world transaction (such as
  the check before a conversation alternative is created) now joins that
  transaction. It no longer commits it early or, with `pool_size = 1`,
  waits for a second connection until the pool times out.
- On Postgres in tenant compatibility mode, erasing a conversation no
  longer fails when a child task was later claimed by another workspace;
  that child is kept and only its link to the erased task is removed.
- A Kubernetes workspace transfer now refuses file names containing
  `< > " | ? *` (as it already refused `:`): a backup cannot hold them.
  Copies already kept in `sandbox-recovery` with such names are left out of
  backups with a warning instead of stopping every backup; rename them to
  keep them.
- `maverick start --domain D --coding-mode --best-of-n N` now applies the
  department's profile and gates to every attempt; the domain was dropped.
- `maverick share` now refuses `--db` and a run number that is not in the
  workspace's world, instead of uploading run-log events from another run
  with the same number. Share such runs from their own workspace.
- An A2A task whose start could not be saved is now marked failed, so it
  no longer holds a task slot until the server restarts.
- Fetching the public A2A agent card no longer writes an agent-trust
  denial to the audit log on every anonymous request; task requests still
  record theirs.
- The `~/.maverick/.env` loader now ignores security-authority settings
  in any letter case (such as `maverick_approver_keys`), as Windows reads
  them case-insensitively. Set those in the service environment instead.
- Approvals for protected settings now hold a file lock, so several dashboard
  workers cannot lose each other's approvals. An unreadable approval ledger is
  kept as `config_proposals.json.corrupt-<number>` and a warning names it.
- The standing-consent ledger now refuses a new grant while the space left is
  needed to revoke existing grants, so a revocation always succeeds.
- Sandbox commands now keep only the end of their output while they run. Long
  output starts with "[output truncated: showing the last 8,000 characters]".
- When a local sandbox command times out or is cancelled, processes it
  started in a new session (`setsid`) are now stopped too. After a normal
  exit they keep running, as before.
- Plugin input schemas with `pattern` or `patternProperties` are now checked
  under the regex time limit, only against the answers they apply to. If the
  check cannot finish, the form says so and nothing runs. A schema that combines
  `patternProperties` with `unevaluatedProperties` is refused.
- Kubernetes recovery folders under `sandbox-recovery/` are removed seven days
  after a failed transfer. Copy out anything you need before then.
- Turning off "Share anonymous work patterns" deletes the records still
  waiting in the outbox and says how many. Training ingest and export also
  re-check the setting and export nothing from this installation's outbox
  while it is off or the configuration cannot be read.
- `maverick trust verify` exits 1 when the decision is DENY (it exited 0).
  Scripts that read its exit code now see the refusal.
- `maverick erase` (and the dashboard's erase a person) is all or nothing:
  it refuses before deleting anything when an audit day holding the person
  cannot be rewritten, naming the day and why. Repair it and run erase again.
- `maverick erase` exits 1 with "erasure incomplete" and what remains when
  data is left or the erasure cannot be certified; it used to exit 0.
- An audit erase re-signs the day in memory and writes it once, so a missing
  signing key leaves the day unchanged instead of broken. A day with rows
  written while signing was off can be erased; erase never signs those rows
  or any row that did not verify, so the day verifies exactly as before.
- `maverick erase` also refuses a day whose tip anchor, tip ledger or
  published checkpoint already reports a break, so an erase never hides a
  truncated or edited day. Each refusal names the step to take, such as
  restoring the day or a retired key's public key. The checkpoint check
  covers the default store, the custody store and the folder chosen in the
  audit checkpoint settings; a chosen folder that cannot be read refuses.
  An install that has never had a tip ledger can still erase: the erase adds
  no anchor, and `maverick audit verify` reports what it did before.
- A rerun of `maverick erase` that finds no conversation now also clears the
  AI reply cache and retries attachment files an earlier run could not
  remove, so it finishes the job or names again what remains. The list of
  such files keeps only folders and name digests; an unusable list is kept
  aside as `pending_attachment_files.json.unusable-<n>` to check by hand.
  Two erase runs at once no longer lose each other's entries in that list.
- The privacy request page's erase button now runs the erase even when the
  person has no conversation, and shows what it actually removed.
- Erasing a person also deletes the durable-execution checkpoints of their
  goals, which kept failed or stopped goals' transcripts.
- An Ollama, vLLM or TGI model is free only when its server is on this
  machine or a private network. A server on a public address is charged a
  safety ceiling ($10/$50 per million tokens) until you set
  `[providers.<name>] price_per_mtok` to its price or `"free"`; setup asks,
  and `maverick doctor` names unpriced servers. A reply with no token counts
  is charged an estimate from its text length.
- Tailscale addresses (100.64.0.0/10) and names ending in `.ts.net`, `.home`
  or `.corp` count as private, so their self-hosted models stay free. When
  the safety ceiling priced any spend, the spending-limit message and the
  cost line say so and name the fix. An administrator can mark an Ollama,
  vLLM or TGI server free under Settings > Prices, which also shows how each
  one is charged now; a server marked free in `config.toml` must be changed
  there. The Copilot can make the same change ("Mark a self-hosted server
  free or charged"); it cannot yet set or remove a model's own price.
  The cost line counts calls whose token counts were estimated.
- Once Postgres has been used, Lightwork remembers which database it last
  used (`world_backend` in the data folder). If that was Postgres and a
  settings file cannot be read, it refuses to start and names the file and
  line instead of opening a local database. An install that has only ever
  used the local database writes no such file. Fix the file, or set `MAVERICK_WORLD_BACKEND=sqlite` to use the
  local database on purpose.
- Only `sqlite` and `postgres` are accepted for `MAVERICK_WORLD_BACKEND` and
  `[world_model] backend`; any other value now stops start-up with a plain
  message. Once Postgres was used, settings that no longer name a database
  are refused too. A deployment that switched from Postgres back to the
  local database must name `sqlite` explicitly once
  (`[world_model] backend = "sqlite"` or `MAVERICK_WORLD_BACKEND=sqlite`);
  the choice is remembered. The Helm chart now always sets the variable from
  `worldModel.backend`. The CLI and dashboard show the refusal as a plain
  message instead of an error trace.
- When the independence-levels setting cannot be read (an unreadable
  settings file, or `[workforce] levels` or `MAVERICK_WORKFORCE_LEVELS` that
  is not true or false), every agent can only watch: consequential actions
  are refused instead of the levels check switching off. `maverick doctor`
  and the Workforce and Agents pages say so. Tool grants widen only when the
  setting reads as on.
- Stop and rename now work on a running task. Its heartbeat no longer counts
  as a change since you reviewed it. The world database moves to schema 54
  on the next start, on SQLite and Postgres. Stop also works while a
  chat answer is still being written.
- A cancel that arrives after a task finished no longer replaces "done".
  The task stays finished, and the chat supervisor and the gRPC cancel say
  that it had already finished.
- With a queue or gRPC worker configured, startup recovery (`maverick
  serve`, the dashboard on SQLite and `maverick status`) no longer marks
  queued tasks as stuck; they wait for their worker. The in-process default
  still blocks them, since nothing else would start them after a crash.
- Retrying a workflow whose approved high-risk step failed now asks for a
  new approval at that step's gate, then continues the saved work. Before,
  the retry was refused. Approve or reject the new request as usual.
- The `computer` tool no longer asks to approve mouse or keyboard input it
  cannot send. It says input is not supported yet; screenshots still work.
- When "hold risky tasks for a person" is on, a resumed task skips the
  check only if a person approved its exact current words. Changed words,
  and tasks that ran while the check was off, are asked about again.
- On shared Postgres, raw world-model reads (`query`) are refused while
  tenancy is on; the boards, chat history, handoffs and reports now read
  through `tenant_query`, which adds the tenant boundary. Code that calls
  `query` directly must move to `tenant_query` or pass `system=True`.
  A task whose parent task belongs to another workspace, or to no workspace
  under strict isolation, no longer starts: its parents cannot be checked
  for a hold or a closed handoff. The message asks you to review the task map.
- A workspace's `config.toml` and a workspace agent override can only make
  governance, safety, capabilities, sandbox and security settings stricter;
  an unset organisation value counts as the product default. A looser
  value is ignored, logged, listed by `maverick doctor` and shown in Settings
  or on the agent page as "Set by your organisation"; the file still loads.
  Remove the looser values from the file to clear the warning.
- An activity-log entry written just as the day ends now goes to the new
  day's file once the finished day has its tip anchor. Before, it could be
  added after the anchor, and `maverick audit verify` then reported that
  day as changed for good. Nothing to do.
- Checking audit checkpoints against a kept receipt or `--minimum-sequence`
  now fails for any day whose checkpoint was replaced or retired after it,
  naming the day and, for a replacement, the erasures behind it. Review it,
  then keep the newest receipt; a scheduled check must do so after each
  retention purge, and `maverick audit checkpoint retire` now prints the
  sequence and digest to keep.
- Replacing a checkpoint after an erasure needs the erase record that
  `maverick erase` now stores. A day erased before this version has none:
  tick "Replace it without an erasure record" on the activity-log page, or
  publish with `--without-erase-record`. Either is written to the activity
  log first, and a check against an older receipt reports that day.
- An erase record vouches only for a checkpoint the day still matched when
  the erase ran. If you keep checkpoints in a folder given only as
  `--checkpoint-dir`, pass the same option to `maverick erase`; otherwise
  replacing them needs the step above. A person is erased either way.
- Two erasures that touch the same audit day at once now take turns, so
  each one's erase record is stored before the next rewrites the day.
  If an erase record cannot be stored, the person is still erased but
  `maverick erase` reports the erasure as incomplete and names the record.
- `maverick erase` after a signing-key rotation no longer re-signs audit
  days that do not hold the person, or the tip ledger. Before, their
  anchors and checkpoints stopped matching. This does not repair days an
  earlier erase already re-signed; they still report a change.
- `maverick import run --activate-schedules` now marks the schedule it
  creates. Importing a workflow again after it changed at the source updates
  that schedule's task text, title and timing instead of leaving the old
  text running; a paused schedule stays paused. Changes you made to the
  schedule in Lightwork are kept while the source is unchanged, and replaced
  (the time zone is reset with the time) when it changes; the import note
  and the schedule's history give the replaced time, zone and title. A
  workflow renamed at the source counts as a new one, and the note names the
  schedule still running under the old name. A workflow that has no id at
  the source cannot be told from another with the same name, so its
  schedule is created once and never changed by a later import. A schedule
  made before this release has no mark and is still left unchanged: remove
  it once, then import again.
- A flow run records a step inside a loop, a parallel lane, a try block or
  a subflow under its container, for example `loop1/n0` or `fanout/1/n0`.
  It no longer shows as, or counts towards, the top-level step with the same
  id. Inside one step id, `/` is recorded as `~s` and `~` as `~~`, so a step
  whose own id contains a slash is never read as a nested one. Outcomes
  recorded earlier keep their old ids; for a top-level id that contains `/`
  or `~`, earlier outcomes are no longer counted for that step.
- The task health check (`maverick diag health` and the task page) no longer
  scores a queued, running or paused (blocked) task as a failure (40, grade
  F). It says the task has no score yet; a paused task says it is waiting
  on a person and to look at what it needs.
- `grant_type = "authorization_code"` under `[mcp_servers.<name>.oauth]` (and
  `[mcp_sidecar.oauth]`) is now refused when the settings are read. Nothing
  could complete that sign-in, so such a server only ever failed to start.
  Use `grant_type = "client_credentials"`, or a static `auth_token`.
- Suggested instruction changes can target standing instructions only. The
  "A named procedure" and "Something it remembers" choices (`--target skill`
  and `--target memory` in `maverick refine propose`) are removed: nothing
  read those changes, so approving one changed nothing. A waiting suggestion
  of those kinds is closed when someone applies it or suggests a new change;
  one already applied is listed as changing nothing and can be undone.
- A release request on the Research page that cannot move on now shows as
  "Stuck" and says why. If an action stopped before its result was saved,
  "Retry: check what happened" reads the real state without repeating the
  action. If the approval ran out, or stopped counting because the
  reviewer's access changed, a release administrator can review it again.
  If the release rules changed, even before the first review, discard the
  request and make a new one. "Discard this request" closes a stuck or
  unwanted request that was never published. A published request that
  cannot be settled offers "Close this request" and ends as "Closed after
  publication". Both are refused while the request is the version in use;
  if its history is also full, publish another version, then close it.
  A request's history holds 128 steps: renewed reviews and repeated failed
  restores stop there, and the request can still be settled and closed.
  The Copilot offers the same retry and discard for taught workflow
  releases.
- A person's Operating Record now reads that person's approvals from the
  store directly, so older approvals no longer drop out when other people
  have thousands of newer ones. Nothing to do; totals for one person can rise.
- A HashiCorp Vault transit key that was not created with `derived=true` no
  longer wraps new workspace keys, because such a key does not keep
  workspaces apart; existing data still opens and a warning is logged. Create
  a transit key with `derived=true` and rotate to it. The check runs when a
  key is first wrapped or opened and needs encrypt and decrypt on the key.
- The AI governance page now says when its Needs attention check could not
  read every record, instead of reporting that nothing needs attention.
  Press Refresh to check again.
- The diagram tool now works in container sandboxes: the source goes to the
  renderer on standard input and the image is written in the workspace, under
  a temporary name that is moved into place when the render succeeds. A
  source over 64 KiB is refused outside the local sandbox.
- The accessibility checker's browser now connects through a local proxy that
  refuses internal addresses and applies the destination policy to every
  host a page loads, and the page itself is checked against that policy. It
  reaches public sites on ports 80 and 443 only. A container sandbox with
  network access is refused: use the local sandbox, or turn the sandbox's
  network off to check local files. `MAVERICK_FETCH_ALLOW_PRIVATE=1` keeps
  the previous behaviour for local development servers. With the proxy, a
  workspace `pa11y.json` is honoured for `standard`, `ignore`, `timeout`,
  `wait`, `hideElements`, `rootElement`, `includeNotices`, `includeWarnings`,
  `level`, `threshold`, `rules`, `viewport`, `userAgent`, the `axe` and
  `htmlcs` runners, and the browser switches `--no-sandbox`,
  `--disable-setuid-sandbox`, `--disable-dev-shm-usage` and `--disable-gpu`;
  `actions`, `headers` and other browser settings are not used.
- Outbound webhooks now read only the first 4 KiB of a receiver's reply, so
  a very large reply no longer fills memory. The delivery log still shows
  the first 200 characters. Nothing to do.
- With `[limits] file_write_quota_mb` set, a file write or edit that fails
  no longer counts against the run's quota. Nothing to do.
- `view_video` and `wasm_run` now work in container sandboxes: commands get
  workspace-relative paths, video frames are staged in a hidden folder in
  the workspace and removed afterwards, and the programs are looked for in
  the sandbox, not on the host. A WebAssembly module now sees a granted
  folder under its workspace-relative name (`data`), not its host path.
- `view_video` now refuses to run without an active run budget, as
  `view_image` does, so its vision call is always charged and capped. Code
  that builds the tool directly must pass the run's budget.
- On the Safety monitoring page the Copilot can now show where sensitive data
  went, including what to do when earlier labels for a task cannot be read.
  It needs the page's audit permission and the `reviews` control family in
  `[copilot] operation_families`; it reads the record and changes nothing.
- A GitHub comment starts a run only when `/maverick` is a word of its own.
  A path or link that contains it, such as `packages/maverick-core`, no
  longer starts one, and neither does one in a quoted reply (a line that
  starts with `>`) or a fenced code block. Indented code, HTML comments and
  quote lines without a `>` are read as before. Write `/maverick` on its
  own to start a run.
- On Postgres, the time allowed to undo an approval now starts when the
  decision reaches the signed audit log, as it already did on SQLite. It
  used to start at the vote, so a slow audit log shortened it. Nothing to do.
- A schedule is now paused when a worker stops during the last attempt of a
  run and the next run was not queued. Before, the schedule stayed active
  but never ran again. Review the paused schedule, then resume it.
- When a saved secret in the dashboard's settings cannot be opened, the
  settings made in the dashboard are on hold until the file can be opened,
  except stricter safety choices, which stay in force. Before, those were
  ignored too, which put back limits you had tightened there. A sandbox
  that was set up in the dashboard may not start until then. Health and
  `maverick doctor` say so. Save that secret again, or restore the key, to
  clear the warning.
- A workspace's `config.toml` can no longer let people approve their own
  requests (`[security] allow_self_approval`) or run sandbox work as user 0
  (`[sandbox] run_as_user`). The looser value is ignored and listed by
  `maverick doctor`, like other workspace settings that loosen policy.
- Automations that watch new Salesforce records or ServiceNow tickets now
  work on lists with more than 5,000 items: each check reads the newest
  5,000. In such a list, a record saved with an earlier creation date is
  not reported. A source that was refused for its size starts again by
  itself and reports the items it missed, if fewer than 5,000 arrived
  meanwhile; with more, it is refused with a message that asks you to review
  the source again. A source also no longer stops for good after 20,000
  remembered items; it forgets items that are gone from the source.
- Company sign-in now checks that the provider's discovery document names
  the issuer you configured, and reads that document again every hour. If
  the provider cannot be reached then, the last answer stays in use. If
  sign-in stops with "misconfigured", copy the issuer exactly as your
  provider shows it; the server log names both values.
- The dashboard Copilot can now set and remove a model's spending ceiling
  ("Set a model's spending ceiling" in the Models action family), with the
  same administrator check, confirmation and activity-log entries as the
  Settings form. Turn on Copilot actions and the Models family to use it.
- On the Activity log page the Copilot can now publish a checkpoint, publish
  one after an erasure (with or without an erasure record), retire one, and
  check the checkpoints against a receipt you kept. The same administrator
  check and activity-log entries apply. These are offered only once the
  Reviews family is in `[copilot] operation_families` (it is off by
  default); publishing and retiring also need Copilot actions turned on.
- On Postgres with at-rest encryption and strict isolation off, records
  saved before workspaces were used are shown to every workspace again, as
  they already are without encryption: facts, goals, goal events, artifacts,
  questions, episodes, sign-offs, approvals, projects and chat turns no
  longer show a "withheld" placeholder there. `maverick doctor` and
  Installation health now warn when such records exist next to a workspace.
  To stop every workspace reading them, assign them to one workspace with
  `maverick tenant backfill --tenant <id>` (preview with `--dry-run`), then
  turn on strict isolation ("Hide records with no workspace" in Settings).
- `maverick tenant backfill` now re-seals the encrypted values of the
  records it assigns, so the workspace they go to can read them; before,
  that workspace saw a "withheld" placeholder. Run it on the computer that
  runs Lightwork: it stops, changing nothing, if it cannot open a value.
  Writes to goals, facts, conversations and their events wait while it
  runs (about 4 seconds for 100,000 encrypted values), so pick a quiet
  period; if Lightwork is busy writing for more than 10 seconds it stops,
  changing nothing, and can be run again.
- `maverick tenant backfill` now stops with an explanation when row-level
  security is on and its database login cannot see records without a
  workspace; before, it reported that it assigned 0 rows. A script that
  runs it that way now gets exit code 2. Run it as a login that bypasses
  row-level security.
- A code change built with `maverick code feature` or the Code page now
  repairs itself: failing tests go back to the agent for up to two more
  tries, then a separate agent runs the change and tries to break it.
  Blocking problems it finds go back too, and it looks again. Tests and
  checks run on a fresh copy of exactly the commit you approve, so your test
  command must install anything it needs. Every round shares one spending
  limit. The approval card, `maverick code show` and the Code page list what
  was and was not checked. Set `[codebase] repair_rounds`, `checker` and
  `check_rounds` in Settings; each round or look is one more agent run.
- On the default `local` work area, a code change's tests, checker and
  agent share this computer. Each round now starts from a fresh copy. Where
  Linux allows it, each command gets its own processes and temporary
  folder, runs as your own user, and nothing it starts outlives it. The approval card says how the
  steps were kept apart, and lists it as not fully checked. To refuse such
  runs, turn on `[codebase] require_container` in Settings. A workspace can
  no longer weaken the `[codebase]` checks in its own config file.
- A code checker's finding can now carry a command that shows the problem.
  Lightwork re-runs it on a fresh copy and marks the finding confirmed, or
  not reproduced and read only. After a repair it re-runs confirmed ones to
  decide "fixed" itself. Set how many it re-runs per look with `[codebase]
  max_repros` (default 5); each re-run counts as one tool call.
- `[codebase] checkers` (1-3, default 1) sets how many independent checkers
  look at each change, and `checker_models` picks one model for each. Each
  extra checker is one more agent run per look. The approval card names
  each checker's model and flags it when all share the author's kind.
- `[codebase] checker_image` runs the checkers and their re-runs in a
  container image. `deploy/checker/` builds one with Python 3.11 and 3.12,
  PostgreSQL 16 and a Playwright browser. If the image cannot be used, the
  check says "could not run"; it never runs on this computer instead.
  Lightwork never pulls the image and never lowers your work area's
  isolation for it; only the organisation's config may set it. Re-runs
  happen only when the steps run in a container, and a fix that only
  makes the re-run pass waits for a later look to confirm it.
- A code project can now have test tiers: quick tests run after each
  repair round (`{changed}`, unquoted, lists the changed files that still
  exist, so the command must accept any path), and the full tests plus
  other checks run on the finished change; a failure goes back to the
  author. Tests that need services run only in `[codebase] checker_image`.
  Set them with `maverick code add|set --quick-test --gate --heavy-test`
  or "Test commands" on the Code page. The approval card shows one line
  per tier, and a quick pass alone never reads as the tests passing.
  Existing projects keep running their one test command as before.
- A run can now stop and ask a person to decide. It offers two to five
  options, says which it recommends and why, and waits as blocked without
  spending until someone chooses on the Approvals page, a Slack card, the
  Copilot or `maverick decisions answer`; then it continues with that choice.
  Nobody answering in time (`[approval] decision_expiry_hours`, default 72)
  stops the run without choosing. Upgrading adds world-model migration 55.
- New `[approval] decision_areas` and `decision_admin_areas` settings (wizard
  approvals step and Settings > Safety > Approvals) list where a run must ask
  and which decisions need an administrator. By default governance-control
  decisions need an administrator; the person who started the run answers
  only as `[approval] separate_approver` allows for a risky approval (someone
  else when another administrator can). A workspace file can add areas but
  cannot remove them, and an unknown area name keeps the defaults.
- `maverick resume`, the dashboard Resume button and answering a clarifying
  question no longer restart a run that is still waiting for a decision.
  Answer the decision first; `maverick resume` exits 2 until you do.
- Inside a flow step, a run cannot stop to ask for a decision yet: the step
  stops without a retry, and the flow takes the step's error route or stops
  there, showing the question.
- A run restarted after a decision begins again from the start unless durable
  checkpoints are on, so steps it already finished (including a subagent's
  side effects) may run again. Turn on `[durable] enabled` to continue where
  it stopped; the answer's confirmation says so.
- Code projects have protected paths (`maverick code set --protected-path`,
  or the test commands dialog on the Code page). A change that touches one,
  counting both sides of a rename, needs a second checker from a different
  model family (`[codebase] protected_checker_model`) and two different
  people to approve, never the person who started it. Without that checker,
  or when the change was started without a signed-in person, it cannot be
  approved. Protection is checked again at merge, push and renew: a change
  that became protected after it was built must be built again. Set the
  model and the paths you care about.
- An approval that needs two or more people now counts names with case,
  spacing and character width ignored: `user:Alice`, `user:alice` and
  `user:Ａｌｉｃｅ` are one person, and the requester spelt differently is
  still the requester.
- No agent, API key or automation can approve a code change any more, and
  Copilot cannot approve a protected one: approve those on the Approvals page.
- Feature runs on the repository the running Lightwork was installed from
  are refused. Run the factory from a separate installation pinned to a
  released version, or set `[codebase] allow_self_changes = true`; each such
  change is then protected.
- A code change whose run stops to ask a person to decide now stops at once
  with the status "decision" and is never offered for approval. Answer the
  decision, then start a new code change: the answer does not restart it.
- Paid tool calls now count against the task's spending limit, so a capped
  run can stop on tool spend. This covers search (Tavily, Brave, SerpAPI),
  Hugging Face (and its OCR), Replicate and hosted image edits, DeepL,
  LibreTranslate on a public server, OpenAI and Groq speech-to-text, OpenAI
  and ElevenLabs speech, Wolfram|Alpha, NewsAPI, BigQuery (by terabytes
  scanned when priced that way), Twilio, Amazon SES and SNS sends, and the
  pay-per-use connectors: AI, media AI, identity and background checks, and
  SMS, voice, WhatsApp and email gateways (such as `sendgrid`, `vonage`,
  `plivo`, `whatsapp_business`) on
  every request but a GET; per-lookup data services (such as `shodan`,
  `hunter`, `zoominfo`) on every request.
- Not charged: subscription services (CRM, ERP, storage, contract review
  such as `luminance` and the like), which bill by plan, not by call;
  payments, shipping labels and stock-media purchases, which move money
  under their own approval rather than spend a task's budget; and local
  engines, DuckDuckGo and servers on a private address, which are free.
  `whatsapp_business` is charged per message, though `messenger` on the
  same Meta address is free.
- A call whose price is known before it is sent is stopped if it would pass
  the limit. Speech-to-text priced per second holds what the file's size
  allows at the lowest speech bitrate (a header's stated length is never
  trusted for this) and is charged the seconds the service reports. Another
  call priced per second or per terabyte holds the smaller of what the run
  has left and `[budget] max_unmetered_hold_dollars` (default $1.00, in All
  settings and the wizard; a workspace may only raise it), so other calls
  keep running. BigQuery is told to stop at that hold. Replicate priced per
  second is always waited for, and the reply says so; it is cancelled when
  it reaches its hold, the reply gives its final state, and Replicate's
  reported seconds settle the charge even if the cancel is slow. Unpriced
  or priced per call, Replicate is never cancelled: a prediction still
  running after 90 seconds is reported as still running. A call with no
  limit can still cost more than it held, and the run stops right after
  it. If the reply does not report the seconds or terabytes used, the full
  hold is charged and the cost line says so; price such a service per
  request to be charged per call instead.
- GPU rentals (`runpod`, `vast_ai`, `lambda_labs_cloud`, `coreweave`,
  `voltage_park`, `paperspace_gradient`) start machines billed by the hour.
  The limit sees only the per-call charge, never those hours.
- Upgrading: a new install's task limit is $2, and a paid tool with no price
  set counts $0.10 per call, so 20 unpriced searches use the whole limit.
  Set prices for the services you use first, starting with search, in
  Settings > Models, under Prices for paid tool services, the Copilot, the
  setup wizard, or `[budget.tool_prices]` (for example
  `tavily = { dollars = <your price>, per = "request" }`; units are
  request, message, page, character, image, second and terabyte). Change
  the $0.10 per call in All settings (`[budget] unpriced_tool_call_dollars`); a warning and the cost
  line name the services charged it. A workspace may only raise these
  prices. While settings cannot be read, paid tool calls are refused.
- A flow's tool step charges paid tools to what is left of the flow's
  spending allowance, and adds them to the run's cost. The dashboard
  microphone, its read-aloud voice, voice-only mode, chat attachments and
  `maverick voice` are not part of a run and are not charged. With the
  default `auto` speech-to-text, a hosted service the run cannot pay for
  falls back to the local engine.
- Erasure receipts are now issued as `lightwork.erasure-receipt.v3`, which
  also counts a run's decision requests before deletion. Receipts issued as v2
  keep verifying against the stores they listed; nothing needs re-issuing.
- With Postgres row-level security on, 18 more world tables now have a row
  policy. Events and episodes carry a copy of their goal's workspace, kept in
  step by the database; artifacts, questions, turns and the other child
  tables check their parent goal, approval or conversation; the learning-store
  and approval-check tables check their workspace column. Database migration
  56 adds them when Lightwork starts as the table owner, so start once as the
  owner after upgrading. `maverick tenant backfill` now also assigns
  learning-store and approval-check records that have no workspace. Vector
  memory and knowledge-store tables in the same database are not covered yet.
  Migration 56 copies each event's and episode's workspace (about 10-13
  microseconds a row) only where RLS is on. With RLS already forced it does
  so while the tables are locked: allow about two minutes per 10 million
  rows and upgrade in a quiet window. Turning RLS on later copies them in
  short batches first.
- `maverick tenant backfill` no longer stops when a learning record exists
  both without a workspace and in the target workspace: the workspace keeps
  its own, the other is left unchanged and listed by table and key. A
  conflict it still cannot settle names the table and the key.
- A Postgres database update that the login cannot run because it does not
  own the tables now says so and changes nothing. Start Lightwork once as the
  table owner, then again with the usual login.
- `maverick tenant rls-preflight` no longer reports READY while row-level
  security hides records that have no workspace. The table owner now counts
  them with FORCE lifted in a rolled-back transaction, waiting at most 200 ms
  for a busy table; a login that cannot see them reports NOT COUNTED. Each
  report says how it counted, and lists orphaned rows (no task or approval)
  that no workspace can see; delete those before turning RLS on.
- The `database` tool now refuses an address that names Lightwork's own
  Postgres records database (same host, port and database as the world
  DSN), from `DATABASE_URL` or from an agent. Use a separate database; only
  the organisation can allow it, with `[tools] database_allow_world_database`.
- A workspace settings file (`tenants/<name>/config.toml`) may now set only
  policy keys that can be made stricter. In `[governance]`, `[safety]`,
  `[capabilities]`, `[sandbox]`, `[approval]`, `[security]`, `[codebase]`,
  `[egress]`, `[tenancy]`, `[enterprise]`, `[profile]` and `[compliance]`
  every other key is ignored, logged once and listed by `maverick doctor` and
  on Settings as set by your organisation. The file still loads. Newly ignored
  there: `[sandbox]` workdir, image, language, runtime, options, project_dir
  and the server keys below; `[safety]` receipt_key and screenshot_key;
  `[capabilities]` deferred_tools; `[approval]` check_retention_days,
  dashboard_wait_seconds, undo_grace_seconds and delegation; `[tenancy]`
  by_user; and `[tools]` deferred_loading,
  fetch_allow_private, fetch_skip_scan and database_allow_url_arg. To keep
  such a setting, move it to the organisation's `config.toml` (or Settings)
  and delete it from the workspace file. A moved value applies to every
  workspace: workspaces that each had their own `[sandbox] workdir` would
  then share one folder. For a separate folder, run that workspace's
  Lightwork process with `MAVERICK_WORKDIR` and leave `workdir` out of the
  organisation's file; a per-workspace image has no replacement yet.
  Likewise a workspace can no longer add its own `[enterprise]
  allowed_hosts` (a SaaS host) or `local_providers` (a local model server):
  moved to the organisation's file, the host or server is allowed for every
  workspace, and there is no way yet to allow one for a single workspace.
  `[tenancy.egress.<name>] allow` in the organisation's file approves hosts
  for one workspace under the allowlist network posture, but does not open
  the enterprise egress lock.
- New stricter-only workspace rules: `[sandbox] warm` and `[codebase] enable`
  may only be turned off; `[approval] record_checks` and
  `require_acknowledgement` only on; `[approval] separate_approver` only
  towards `always`. Host lists in `[sandbox.tool.<name>]`, `[egress]` and
  `[tenancy.egress.<name>]` may add denied hosts and narrow an allowed list
  the organisation set; a workspace allow list where the organisation has
  none is ignored, because under the allowlist network posture it would
  approve hosts, and a `[tenancy.egress.<name>]` table the organisation did
  not set is ignored, because it would replace `[egress]`. `[enterprise]`
  mode and require may only be turned on, allowed_hosts and local_providers
  only shortened, `[profile] name` only raised to enterprise,
  `[compliance] profiles` only extended with known profiles, and
  `[compliance] disclosure_text` replaced with other text but never emptied.
- New `[sandbox] workspace_infrastructure` and `workspace_hosts` (off and
  empty by default; wizard sandbox step for clusters and remote computers,
  and Settings > Protected work area). When on in the organisation's
  settings, a workspace file may choose a `context` and `namespace` (plain
  names) in the organisation's own cluster settings file, and a `host` that
  matches a `workspace_hosts` pattern such as `*@build.example.com` (no
  port: it comes from the organisation's ssh_args or ssh config). Its
  kubeconfig, api_key, provider, extra_kubectl_args and ssh_args are still
  ignored: a cluster settings file or ssh option can run a program on this
  computer, and a key or provider reaches another service. The backend
  cannot be weakened, and the switch counts as off while any settings file
  cannot be read.
- The ssh work area now always passes `--` before the remote computer and
  refuses a destination that starts with a dash or holds spaces or control
  characters, so a destination can never be read as an ssh option.
- Copilot on the Agent trust page can now list outside agents, check whether
  one would be let in, change an app-added agent's limits, and turn blocking
  on or off. Each runs the page's own checks. To offer them, choose Connections
  in "Actions available through Copilot".
- Adding, editing, blocking, unblocking or removing an outside agent on the
  Agent trust page (or through Copilot, which now offers all five), and
  unenrolling one on Outside agents, writes an `agent_trust_changed` audit
  record first; if it cannot be written, nothing changes. Include this event
  in any audit export filters you maintain. Enrolling and new credentials keep
  their own records, and containment keeps its control-plane record. Only
  terminal commands write no record: `maverick trust` changes, and blocking,
  restoring or unenrolling with `maverick external-agents`.
- Saving an outside agent's limits now keeps its security key on file unless
  a new key is pasted or "Remove the key on file" is ticked. Before, saving an
  edit without re-pasting the key removed it: re-add any key lost that way.
- A new benchmark, `benchmarks/eval_factory_checker.py`, measures how many
  planted defects the code factory's checkers find, how often they raise
  false alarms on correct changes, and the cost per case. Run it with a
  model key to score your configured checkers; `--self-test` needs no key.
- A code change whose round or checker asks a person to decide now stops at
  once: nothing half done is committed or offered for approval, and its
  status reads "Waiting for a person's decision". Answer it, then start a
  new code change; the answer never restarts the old step.
- An answer given in the moment before a run pauses for its decision now
  continues the run with that choice; before, the run stayed paused with
  nothing left to answer. Nothing to do.
- A run left waiting to start after its decision was answered, because
  Lightwork stopped first, now continues when Lightwork starts again, in
  every workspace. Resume, the Copilot and `maverick resume` also accept it.
- The Approvals page, its API and the Copilot now always find your own
  waiting decisions, even behind more than 200 of other people's; before,
  yours could be hidden and answering one by its number said it was gone.
- A paid tool call that fails after its request may have reached the
  service (a read timeout, a failed poll) is now charged everything it held,
  and the cost line says the provider may have billed it. It counts once
  against the organization's daily cap. A call that never connected is not
  charged. Check the provider's invoice for the real cost.
- A paid tool service priced at $0 per second or per terabyte no longer
  holds or charges anything, even when its replies do not report that unit.
  Before, it held and charged up to `max_unmetered_hold_dollars` per call. A
  $0 price for a count (message, image, page, character) makes only the
  calls counted in it free; other calls to that service are charged as
  before.
- A task an agent started inside a code change now runs only inside that
  code change. `maverick resume`, Resume, the Copilot, the queue and recovery
  refuse it and say to start a new code change.
- A workspace file can lower but no longer raise budget caps: the spending,
  time, action and word limits per task, and the caps per AI service. It
  cannot turn task limits or strict pricing off, and may only add warning
  thresholds. A value it cannot use is ignored and listed by `maverick
  doctor`; raise a cap in the organisation's config.toml instead.
- The database tool now compares where server names lead, not how they are
  spelled, before it refuses Lightwork's own records database. Another name
  for that server is refused, and the connection uses the address it checked.
  A name it cannot look up in time is refused with "could not check": retry,
  or ask your organisation to allow it.
- Copilot's form for an outside agent's limits now shows the chosen agent's
  own limits. After you choose another agent, select "Load selected agent's
  current limits" before reviewing. A review made with one agent's limits is
  refused for another agent; load that agent's limits and review again.

### Fixed

- With the optional `fastembed` package installed, the first specialist
  match no longer needs about 4.4 GB of memory. The built-in specialist texts
  are now embedded 16 at a time (about 0.5 GB), with the same results in the
  same time; conversation compaction uses the same batches.
- Resuming setup with an invalid saved advanced answer now asks the advanced
  step again, while a config-write error preserves the resume file.
- Sessionless MCP clients can cancel their in-flight requests again without
  affecting clients using distinct session IDs.
- Bluesky polling again looks beyond older indexed pages, and expired login
  tokens can be refreshed without losing the poll.
- Long SMS and WhatsApp replies are split into provider-sized messages, and
  Teams approval cards are shown only to people permitted to see the request.
- Invalid model-supplied task limits no longer increase the host's budget
  ceiling; no configuration change is needed.
- A revocation in `config.toml` now takes precedence over managed trust entries;
  clear that revocation explicitly before restoring access.
- When at-rest encryption is enabled, webhook delivery bodies are now sealed;
  run `maverick encryption migrate` (on Postgres, once per tenant) to seal
  bodies stored earlier.
- Incomplete BigQuery, Snowflake and Databricks statements are now reported as
  unfinished; check their eventual status before treating their output as final.
- Personal-data erasure checks an existing knowledge store even when knowledge
  is disabled; disabling the feature no longer hides that stored data from erase.
- pgvector searches now fall back to an exact search when the index returns too
  few rows, so configured result counts are honoured when enough matches exist.
- Benchmark cases with empty reference answers or no grading criteria no longer count as
  passes, and dry runs are labelled as dry runs; compare scores using the
  corrected evaluation reports.
- Audit verification now detects truncation of the anchor list, and write-once
  audit pushes skip unsigned days without stopping every push.

## [0.1.7] - Unreleased

The initial public release of Lightwork, licensed under the
[Apache License 2.0](LICENSE). It supports Python 3.11 and 3.12. The eight
Python distributions are versioned and released together as one cohort
(`release-cohort.toml`). Versions previously published under the MIT License
remain licensed under it.

### Runtime

- An orchestrator agent plans each goal, delegates parts of it to specialist
  sub-agents (researcher, coder, writer, verifier and others) that work in
  parallel, checks their results and answers. Each role's model is set
  independently as `provider:model-id` across 15 provider backends:
  `anthropic`, `openai`, `azure`, `bedrock`, `vertex`, `gemini`, `deepseek`,
  `xai`, `moonshot`, `openrouter`, `ollama`, `tgi`, `vllm`,
  `openai_compatible` and `codex_cli`.
- A persistent world model in SQLite with FTS5 full-text search, or in
  Postgres, keeps goals, runs, facts, conversations and approvals between runs.
  Released schema migrations are checksum-locked.
- Chat threads: follow-up messages run as goals inside the same conversation,
  so the agent sees the earlier turns.
- An optional flow engine (`[flows] enable`) runs graphs of agent steps, fixed
  actions, branches, loops, parallel steps, approvals and delays, with a
  visual designer in the dashboard.
- A cron scheduler (`lightwork schedule`) and a background worker
  (`lightwork worker`) run recurring goals and jobs; goals can also run out of
  process through a job queue and a shared world model.

### Safety and governance

- Agent Shield screens user input, every tool call and every final answer,
  including decoded variants (base64, hex, percent-encoding and look-alike
  Unicode), with profiles from `strict` to `permissive`. The built-in rule set
  ships with `maverick-shield`, and the kernel runs without the agent-shield
  SDK.
- Commands run through a configurable sandbox backend: `local`, `docker`,
  `podman`, `gvisor`, `devcontainer`, `kubernetes`, `ssh` or `modal`. Docker
  and Podman run each command in a throwaway container with all Linux
  capabilities dropped, a process limit and, by default, no network.
- Budgets cap dollars, wall-clock time, tokens and tool calls, and enforce
  every cap each time usage is recorded.
- The audit log is append-only NDJSON, hash-chained and Ed25519-signed.
  `lightwork audit verify`, `checkpoint` and `export` (JSONL or ArcSight CEF)
  verify, anchor and export it, and `rust/maverick-verify-audit` checks the
  same chain without Python.
- Connector writes to external systems wait for a person's approval on the
  dashboard's Approvals page, and an agent cannot approve its own request.
  With capability enforcement on, each sub-agent's grant is attenuated from
  its parent's; `lightwork whoami` shows a principal's effective grant and
  `lightwork halt` stops work at upcoming execution checkpoints.
- Enterprise mode (`MAVERICK_ENTERPRISE=1`) pins model calls to local or
  self-hosted providers, checks outbound requests made through the supported
  HTTP clients, turns on capability enforcement and requires a person's
  decision for consent-gated actions; `lightwork airgap` checks the
  configuration for outbound paths.
- Sensitive local stores are encrypted at rest with AES-256-GCM, and an
  optional out-of-process model proxy (Python, with a Go port in
  `go/model-proxy`) keeps provider API keys out of the agent's process.

### Interfaces

- The `lightwork` command (also installed as `maverick`), with the setup
  wizard `lightwork init` and the `lightwork doctor` and `lightwork preflight`
  checks.
- A FastAPI web dashboard with a REST API at `/api/v1`, and an in-product
  assistant panel that acts under the same authorization as the direct UI.
- An MCP server (`lightwork mcp`, over stdio or Streamable HTTP) that
  implements protocol `2025-11-25` and negotiates down to `2024-11-05`, with
  client quickstarts for TypeScript, Go, Rust, C# and Java. The kernel also
  uses external MCP servers as tools.
- A2A and gRPC interfaces, and opt-in OpenTelemetry traces and metrics.
- Messaging channels through `lightwork serve`: Telegram, Discord, Slack,
  Microsoft Teams, Mattermost, Signal, email, Matrix, Bluesky, Mastodon,
  Threads, IRC, RCS, WhatsApp, SMS, iMessage (macOS only) and voice.
- A GitHub Action (`deploy/github-action`) and a GitLab CI template, a
  TypeScript plugin SDK (`sdks/plugin-ts`), a Python REST client, editor
  extensions, a browser extension and embeddable widgets.

### Specialists, connectors and learning

- 2,031 built-in domain packs, each declaring a persona, permitted and
  forbidden tools, a maximum risk level, a compartment and a workflow.
  Invariant tests run across the whole roster.
- 2,877 write-capable REST and GraphQL connectors and 37 read-only
  public-data connectors, each using its own credentials.
- Reviewable learning: successful runs are distilled into proposed skills
  that are used only after a person admits them; `lightwork refine` proposes
  prompt, skill and memory changes that apply only once approved and can be
  reverted; code self-modification is off by default and never applies a
  patch.
- `maverick-evolve` runs configuration-only evolutionary search with an
  evaluation harness, and `maverick-knowledge` provides per-domain document
  retrieval.

### Packaging and deployment

- `scripts/install_release_cohort.py` installs the eight distributions in one
  pip transaction against the pinned constraints in `requirements/ci.txt`.
- Recipes for Docker, Helm, a VPS installer and reference architectures (ECS,
  Kubernetes, Fly.io and Railway), and a desktop bootstrap app.
- The release workflow signs its artifacts with Sigstore (cosign, keyless),
  and `deploy/verify-release.sh` verifies a downloaded artifact.
- Signed governance-frontier and harness-overhead benchmark manifests are
  verified in CI against the current sources.

### Known limitations

- Lightwork is alpha software; configuration and APIs can change between
  versions.
- No package is published to PyPI and no container image to a registry yet;
  install from source.
- With the default `local` sandbox backend, model-generated commands run
  directly on the host. Use a container backend for untrusted goals.
- By default the audit signing key lives on the same host, which detects
  unprivileged edits but not changes made by the service account. Supply the
  key from outside the host for stronger tamper evidence.
- The `firecracker` sandbox backend is an experimental scaffold, not a
  supported isolation backend.
- The full agent-shield SDK is not published; the built-in rule set is what
  ships.
- The mobile companion is a preview.
