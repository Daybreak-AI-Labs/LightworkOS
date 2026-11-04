# Real browser customer journeys

This release gate runs installed Chromium against the real FastAPI dashboard,
its controllers and private local stores. It is separate from the JSDOM unit
suite. Run it against this checkout's isolated Python environment; install all
eight workspace packages as described in `AGENTS.md` first.

From the repository root in PowerShell:

```powershell
$env:PATH = (Resolve-Path '.venv/Scripts').Path + [IO.Path]::PathSeparator + $env:PATH
Set-Location packages/maverick-dashboard/tests/browser
npm ci --ignore-scripts
npx playwright install chromium
npm test
```

On Linux, activate the isolated virtual environment, change to this directory,
and run the same npm commands (`npx playwright install --with-deps chromium`
installs browser OS dependencies on a CI runner). CI runs this suite in
`.github/workflows/ui-regressions.yml`; a failure blocks that job. Repository
administrators must separately select the job in branch protection if required.

`npm test` runs the journeys that share the default fixture server
(`playwright.config.js`), then each journey that has its own
`<journey>.config.js` and fixture server, one after another; it fails if any
run fails. Run one of those journeys alone with
`npx playwright test --config <journey>.config.js`.

The fixture binds only `127.0.0.1`, uses a new temporary home/configuration
(Playwright stops it with SIGTERM so it deletes that home), clears inherited
Lightwork configuration and provider-key environment aliases, and blocks
outbound sockets before importing the product. Browser requests are
restricted to that local origin. Explicitly synthetic named identities exercise
real current permission checks. The enterprise lifecycle fixture instead signs
its existing administrator in with a passphrase and brings the new employee and
manager in through real single-use invitations, all with signed local-session
cookies; neither fixture establishes IdP login acceptance.
Drive evidence, ticket execution and privacy reads are local test adapters.
Billing receipts are explicitly synthetic admissions. No model is run, no
provider is contacted, and no customer data is used.

The Python interpreter and all eight installed source packages must belong to
this exact checkout. Recovery deliberately removes `PYTHONPATH` from its child
process; mixing one checkout's server with another checkout's editable packages
correctly fails the application-identity check. On managed Windows hosts, use a
workspace-owned temporary/cache directory before starting Node. Tests which pin
native directory handles need an execution environment that permits those
handles; do not disable recovery's alias/race checks to accommodate a sandbox.
The full single-worker run has a bounded 30-minute budget, and CI reserves 45
minutes for dependency setup, qualification and artifact preservation. Snapshot
and restore tests await their exact successful native operation responses before
asserting the rendered receipt.

Coverage includes:

- Actual first-owner enrollment and login without injected request identity,
  traversing every rendered default sidebar destination, phone-width sign-out
  and refusal of private pages after the cookie is removed. Navigation waits
  for the shell's initialization signal; it does not equate network idle with
  workflow or provider readiness.
- A private flow recovery copy across independent browser contexts, explicit
  keyboard confirmation, and competing edits without automatic execution.
- A failed workflow recovery save, exact-operation retry, reload and restore.
- Record search through the actual API and keyboard navigation to the task.
- High contrast and dyslexia-friendly preferences at a short mobile height,
  with keyboard focus returning after closing preferences and record search.
- Authored PDF upload, evidence collection, assessment, separate human review
  and approval, one local ticket effect and explicit local acceptance.
- In-app connection creation, credential clearing/exclusion from drafts,
  generated evidence keys, bounded source-access checks, key rotation and
  deliberate source rebinding.
- Project owner membership grant, captured result preview, explicit sharing,
  colleague Action Center visibility and review without live task sign-off,
  then removal of stale private output after an injected expired-session reply.
- Held GRC delivery comparison, preserved note on a service interruption,
  cleared private comparison and inputs on an HTML expired-session reply, and
  fresh human confirmation after reload without another external write.
- Exact historical consent selection into an unsaved next version, plus actual
  server field-validation feedback that preserves the other inputs.
- Explicit preview and consent publication, real public HTTP configuration
  resolution through an API-enrolled synthetic client and policy, origin and
  credential denial, stale-revision rejection, withdrawal and immutable history.
- Recovery key download, real snapshot verification/export and temporary
  restore drill, followed by explicit historical report retrieval after reload,
  signed evidence download, interrupted retrieval and HTML permission expiry.
  Live restore remains disabled in the ordinary dashboard.
- A separately downloaded synthetic encryption-key custody copy, explicit
  upload and consent, fresh-process verification of recognized encrypted
  records, signed historical report after reload, refusal of a damaged custody
  upload, preserved previous evidence and HTML sign-in-expiry cleanup. The
  fixture uses a local at-rest key and its ordinary local tenant-KEK derivation;
  this does not establish remote KMS or complete application recovery.
- Captured recovery comparisons over more than 50 real encrypted drafts and a
  protected database change, exact report paging and signed JSON download,
  retained safe inputs on interruption and cleared private state on HTML 401.
  Comparisons never authorize restoration or reconcile the changed records.
- Four held tasks, a frozen pilot, partial observations, preserved input after
  failed save, exact admitted provider cost allocation and report export.
- Optional voice setup through the real administrator API and worker: explicit
  source/size consent, progress after reload, cancellation, failed download and
  fresh-consent retry, verified publication, service interruption and HTML
  sign-in expiry. The fixture substitutes a small synthetic catalog digest and
  `_open_model_url` byte stream; screenshots therefore show a synthetic small
  size. The real cancellation, size/hash checks and temporary-file publication
  execute locally. No speech weights are downloaded or used for inference,
  and neither microphone access nor transcription quality is tested.
- Ten new workspace surfaces at 320 and 1280 pixels with compact light
  preferences; screenshots are attached for every route and width.
- Native maintenance HTML/controller rendering with fixed synthetic Tauri IPC:
  keyboard update review, required update authorization, single operation while
  busy, failed verification, repair with unreadable recovery state, and exact
  unfinished-operation and saved-log selection. These cases do not launch the desktop shell,
  execute Windows Installer, or establish native IPC/installer acceptance.

Results are in `test-results/results.json`, the HTML `browser-report`, and the
configured browser output directory. The gate retains screenshots and traces
on failure. On Windows, an ignored `.browser-runtime` folder in the repository
holds the runner's temporary files to avoid managed-user-TEMP Chromium cleanup
failures; override it with `LIGHTWORK_BROWSER_TEMP` if needed. Temporary fixture
files are synthetic and must never be promoted into a real workspace.

Screenshot inspection is a separate release-review step. Assertions catch
horizontal clipping and uncaught JavaScript exceptions, but do not certify
visual design, screen-reader behavior, browser compatibility, live provider
acceptance, production deployment, actual invoice authenticity, or customer
outcome measurements. The recovery drill verifies local archive and SQLite
integrity; full live restore and desktop packaging have their own gates.

### Starter-team review journey

The focused starter-team smoke uses real application routes and disposable
synthetic records. Its fixture blocks outbound requests and disables application
background workers. It does not invoke a provider or qualify customer outcomes.
With the workspace Python packages and Playwright installed, run from the
repository root in two terminals:

```sh
python packages/maverick-dashboard/tests/browser/starter_teams_server.py --port 8909
node packages/maverick-dashboard/tests/browser/starter_teams_smoke.cjs
```

Set `LIGHTWORK_CHROMIUM` to an existing Chromium executable if Playwright's
browser is unavailable. `LIGHTWORK_BROWSER_URL` overrides the loopback fixture
URL, and `LIGHTWORK_SCREENSHOT_DIR` saves desktop and mobile review screenshots.
The smoke covers setup review, sample execution, a deliberately lost confirmation
response followed by exact recovery after reload, supplied CSV checks, preserved
edits, pause/resume, result links, schedule creation and pause/resume, mobile
overflow, and uncaught JavaScript errors. The expected failed confirmation request
in its console output is the injected lost response. Scheduled evidence approval
and native specialist dispatch are separately covered by focused offline tests;
this browser smoke does not run them.
