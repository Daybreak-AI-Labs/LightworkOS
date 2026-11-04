<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import { onMount, onDestroy } from 'svelte';

  type Status = 'idle' | 'installing' | 'done' | 'failed' | 'cancelled';
  type InstallFailure = { code: string; message: string };
  type Inventory = { source_ref: string; previous_source_ref?: string; phase: string; outcome: string; previous_outcome: string; review: string; updated_at: number; inventory: {name: string; state: string; detail: string}[] };
  let inventory: Inventory | null = null;
  let checkingDependencies = false, dependenciesReviewed = false;
  let inventoryMessage = '';
  async function recheckDependencies() {
    if (status === 'installing' || checkingDependencies || cleanupBlocked) return;
    checkingDependencies = true; inventory = null; dependenciesReviewed = false;
    try { inventory = await invoke<Inventory>('bootstrap_inventory'); inventoryMessage = 'Local checks complete. A response confirms launchability, not a full installation or cleanup proof. Review partial dependencies before continuing.'; }
    catch (e) { inventoryMessage = String(e); }
    finally { checkingDependencies = false; }
  }
  async function openDependencyRepair() {
    inventory = null; dependenciesReviewed = false;
    try { await invoke('open_dependency_repair'); inventoryMessage = 'OS application management opened. Complete or cancel its operations, then return and select Recheck dependencies. Lightwork will not stop those independent operations.'; }
    catch (e) { inventoryMessage = String(e); }
  }

  const MAX_LOG_LINES = 1000;
  const MAX_LOG_CHARS = 500_000;
  const LOG_BATCH_MS = 50;

  let status: Status = 'idle';
  let lines: string[] = [];
  let errorMsg = '';
  let openingLightwork = false;
  let launchError = '';
  let startupDetails = '';
  let lightworkOpened = false;
  let logEl: HTMLElement | undefined;
  let activeInstall: Promise<void> | undefined;
  let cancellationRequested = false;
  let destroyed = false;
  let listenersRegistered = false;
  let listenerRegistrationFailed = false;
  let cleanupBlocked = false;
  let resolveListenerReadiness!: (ready: boolean) => void;
  const listenerReadiness = new Promise<boolean>((resolve) => {
    resolveListenerReadiness = resolve;
  });
  let pendingLogLines: string[] = [];
  let logFlushTimer: ReturnType<typeof setTimeout> | undefined;
  // Plain progress: the bootstrap's own step lines move this forward. Log
  // events are best-effort, so the step list is a guide, never the result.
  let phase = 0;
  let copyFeedback = '';

  const STEPS = [
    'Getting this computer ready',
    'Downloading Lightwork',
    'Installing Lightwork',
  ];

  function phaseFor(line: string): number {
    if (/Installing the complete Lightwork package/i.test(line)) return 3;
    if (/Downloading a fresh Lightwork/i.test(line)) return 2;
    if (/Installing (git|Python|pipx|Git\.Git|Python\.Python)|Ensuring pipx|Using Python/i.test(line)) return 1;
    return 0;
  }

  // A plain reason and next step for a failed install. The raw output stays
  // in "Details for support".
  function failureAdvice(): string {
    const text = lines.join('\n') + '\n' + errorMsg;
    if (/Authentication failed|Repository not found|could not read Username|Permission denied \(publickey\)/i.test(text)) {
      return 'Lightwork could not be downloaded because GitHub refused the request. Check that this computer can open github.com/Daybreak-AI-Labs/LightworkOS in a browser, then select Try again.';
    }
    if (/Could not resolve host|Failed to connect|unable to access|timed out|network is unreachable/i.test(text)) {
      return 'Lightwork could not be downloaded. Check that this computer is connected to the internet, then select Try again.';
    }
    if (/No supported package manager|winget/i.test(text) && /not found|not recognized|No supported/i.test(text)) {
      return 'Setup could not add the helper programs Lightwork needs on this computer. Ask your IT contact to allow app installs, then select Try again.';
    }
    return 'Something stopped the installation. Select Try again. If it fails again, copy the details for support below and send them to your support contact.';
  }

  function supportText(): string {
    return [errorMsg, startupDetails, ...lines]
      .filter((part) => part)
      .join('\n');
  }

  async function copyDetails() {
    const text = supportText() || 'No details were recorded.';
    try {
      if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable');
      await navigator.clipboard.writeText(text);
      copyFeedback = 'Copied.';
    } catch {
      copyFeedback = "Couldn't copy. Use Save instead.";
    }
  }

  function saveDetails() {
    const url = URL.createObjectURL(new Blob([supportText() || 'No details were recorded.'], { type: 'text/plain' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'Lightwork-setup-details.txt';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    copyFeedback = 'Saved.';
  }

  const unlisteners: UnlistenFn[] = [];

  function flushLogs() {
    if (logFlushTimer !== undefined) {
      clearTimeout(logFlushTimer);
      logFlushTimer = undefined;
    }
    if (pendingLogLines.length === 0) return;

    let next = lines.concat(pendingLogLines);
    pendingLogLines = [];
    if (next.length > MAX_LOG_LINES) {
      next = next.slice(next.length - MAX_LOG_LINES);
    }
    let chars = 0;
    let first = next.length;
    while (first > 0) {
      const size = next[first - 1].length + 1;
      if (chars + size > MAX_LOG_CHARS) break;
      chars += size;
      first -= 1;
    }
    lines = first === 0 ? next : next.slice(first);
    queueMicrotask(() => { if (logEl && typeof logEl.scrollTo === "function") logEl.scrollTo(0, logEl.scrollHeight); });
  }

  function queueLog(line: string) {
    const next = phaseFor(line);
    if (next > phase) phase = next;
    pendingLogLines.push(line);
    if (pendingLogLines.length >= 50) {
      flushLogs();
    } else if (logFlushTimer === undefined) {
      logFlushTimer = setTimeout(flushLogs, LOG_BATCH_MS);
    }
  }

  function installFailure(error: unknown): InstallFailure {
    if (typeof error === 'object' && error !== null) {
      const value = error as { code?: unknown; message?: unknown };
      if (typeof value.code === 'string' && typeof value.message === 'string') {
        return { code: value.code, message: value.message };
      }
    }
    return { code: 'failed', message: String(error) };
  }

  async function registerListener<T>(
    event: string,
    handler: Parameters<typeof listen<T>>[1]
  ) {
    const unlisten = await listen<T>(event, handler);
    if (destroyed) {
      unlisten();
    } else {
      unlisteners.push(unlisten);
    }
  }

  onMount(() => {
    void Promise.all([
      registerListener<string>('install-log', (e) => {
        queueLog(e.payload);
      }),
      registerListener<void>('install-close-requested', () => {
        void confirmCancelAndClose();
      }),
      registerListener<void>('install-cleanup-failed-close-requested', () => {
        void confirmForceExit();
      }),
    ]).then(
      () => {
        listenersRegistered = true;
        resolveListenerReadiness(true);
        void recheckDependencies();
      },
      (error) => {
        listenerRegistrationFailed = true;
        errorMsg = `Could not initialize installer event listeners: ${String(error)}`;
        status = 'failed';
        resolveListenerReadiness(false);
      }
    );
  });

  onDestroy(() => {
    destroyed = true;
    if (logFlushTimer !== undefined) clearTimeout(logFlushTimer);
    unlisteners.splice(0).forEach((unlisten) => unlisten());
  });

  async function startInstall() {
    if (!(await listenerReadiness)) return;
    if (!inventory || checkingDependencies || (inventory.previous_outcome && inventory.previous_outcome !== 'completed' && !dependenciesReviewed)) { inventoryMessage = 'Recheck dependencies and review the previous partial installation before resuming.'; return; }
    status = 'installing';
    phase = 0;
    copyFeedback = '';
    lines = [];
    pendingLogLines = [];
    if (logFlushTimer !== undefined) {
      clearTimeout(logFlushTimer);
      logFlushTimer = undefined;
    }
    errorMsg = '';
    cleanupBlocked = false;
    cancellationRequested = false;
    const operation = invoke<void>('install', { review: inventory.review, confirmDependenciesReviewed: dependenciesReviewed });
    inventory = null;
    activeInstall = operation;
    try {
      await operation;
      flushLogs();
      // The command response is the authoritative terminal signal. Progress
      // events are intentionally best-effort, so a lost event must never
      // leave a completed installation stuck on this screen.
      status = 'done';
    } catch (e) {
      flushLogs();
      const failure = installFailure(e);
      if (cancellationRequested && failure.code === 'cancelled') {
        status = 'cancelled';
        errorMsg = failure.message;
      } else {
        status = 'failed';
        cleanupBlocked = failure.code === 'cleanup_failed';
        errorMsg = failure.message;
      }
    } finally {
      if (activeInstall === operation) activeInstall = undefined;
      if (!cleanupBlocked) await recheckDependencies();
    }
  }

  async function cancelInstall(): Promise<boolean> {
    if (status !== 'installing' || cancellationRequested) return false;
    cancellationRequested = true;
    const operation = activeInstall;
    try {
      await invoke('cancel_install');
    } catch (e) {
      cancellationRequested = false;
      errorMsg = `Could not cancel safely: ${installFailure(e).message}`;
      return false;
    }
    try {
      await operation;
      return false;
    } catch (error) {
      // startInstall presents the result; this return value only decides
      // whether it is safe for the close-request handler to close the window.
      return installFailure(error).code === 'cancelled';
    }
  }

  async function confirmCancelAndClose() {
    if (status !== 'installing') {
      await getCurrentWindow().close();
      return;
    }
    if (!window.confirm(
      'Lightwork is still being installed. Stop the installation and close this window?'
    )) {
      return;
    }
    if (await cancelInstall()) {
      await getCurrentWindow().close();
    }
  }

  async function confirmForceExit() {
    if (!window.confirm(
      'Some setup tasks may still be running in the background. Close the installer anyway?'
    )) {
      return;
    }
    try {
      await invoke('force_exit_after_cleanup_failure');
    } catch (error) {
      errorMsg = `Could not force the installer to exit: ${installFailure(error).message}`;
    }
  }

  async function openLightwork() {
    if (openingLightwork) return;
    openingLightwork = true;
    launchError = '';
    try {
      await invoke('open_lightwork');
      if (!destroyed) lightworkOpened = true;
    } catch (error) {
      if (!destroyed) {
        launchError = 'Lightwork did not open yet. Wait a moment, then select Open Lightwork again. If it still does not open, copy the details for support below and send them to your support contact.';
        startupDetails = String(error);
      }
    } finally {
      if (!destroyed) openingLightwork = false;
    }
  }

  async function refreshStartupDetails() {
    try {
      const details = await invoke<string>('dashboard_diagnostics');
      if (!destroyed) startupDetails = details;
    } catch (error) {
      if (!destroyed) startupDetails = String(error);
    }
  }
</script>

{#snippet supportDetails(extra = false)}
  <details class="support"><summary>Details for support</summary>
    <p class="hint">These are the technical messages from setup. Your support contact may ask for them. They can include folder names and your computer user name.</p>
    {#if extra}
      <button class="secondary" onclick={refreshStartupDetails}>Show startup messages</button>
    {/if}
    {#if errorMsg}<p class="error">{errorMsg}</p>{/if}
    {#if startupDetails}<pre class="log">{startupDetails}</pre>{/if}
    <pre bind:this={logEl} class="log">{lines.join('\n') || 'No setup messages yet.'}</pre>
    <div class="row">
      <button class="secondary" onclick={copyDetails}>Copy</button>
      <button class="secondary" onclick={saveDetails}>Save</button>
      <span class="feedback" role="status">{copyFeedback}</span>
    </div>
  </details>
{/snippet}

<main>
  <p class="sr-only" aria-live="polite">
    {status === 'installing' ? (cancellationRequested ? 'Cancelling installation' : 'Installing Lightwork') : ''}
  </p>
  <header>
    <h1>Lightwork</h1>
    <p class="sub">Engineering source setup for authorized repository users.</p>
  </header>

  {#if status !== 'installing'}
    <section aria-labelledby="dependency-title">
      <h2 id="dependency-title">Installed dependencies and safe resume</h2>
      <p role="status" aria-live="polite">{checkingDependencies ? 'Checking local Git, Python, pipx and Lightwork (no downloads)…' : inventoryMessage}</p>
      {#if inventory}
        <p>Reviewed source: <code>{inventory.source_ref}</code>. {#if inventory.previous_source_ref && inventory.previous_source_ref !== inventory.source_ref}Previous attempt used <code>{inventory.previous_source_ref}</code>; continuing explicitly installs the newly displayed revision.{/if} Last recorded phase: {inventory.phase || 'not started'}. Previous result: {inventory.previous_outcome || 'no prior attempt'}.</p>
        <ul>{#each inventory.inventory as dependency}<li><strong>{dependency.name}: {dependency.state}</strong><pre>{dependency.detail}</pre></li>{/each}</ul>
        {#if inventory.previous_outcome && inventory.previous_outcome !== 'completed'}
          <label><input type="checkbox" bind:checked={dependenciesReviewed}>I reviewed the dependencies above and confirmed that any independent package-manager or elevation operation has finished. Continue the displayed pinned bootstrap using the reviewed existing dependencies.</label>
        {/if}
      {/if}
      <button disabled={checkingDependencies || cleanupBlocked} onclick={recheckDependencies}>Recheck dependencies</button>
      <button disabled={checkingDependencies || cleanupBlocked} onclick={openDependencyRepair}>Open OS application management</button>
      <p>These checks never uninstall, kill unrelated processes, or report the computer as fully rolled back. Missing dependencies can be added by the reviewed bootstrap; partial or unconfirmed dependencies may need OS repair first.</p>
    </section>
  {/if}

  {#if status === 'idle'}
    <section>
      <p>This app installs Lightwork on this computer, then opens it so you can finish setting it up. It takes a few minutes and you can cancel at any time.</p>
      <h2>Before you start, you need</h2>
      <ul>
        <li>An internet connection. Lightwork is downloaded from its public GitHub repository; no GitHub account is needed.</li>
        <li>Permission to install apps on this computer. Setup may add helper programs Lightwork needs and may ask for your computer password.</li>
      </ul>
      <details><summary>What will be installed?</summary>
        <p>A fixed, checked version of Lightwork, plus the helper programs it needs to run (such as Python and Git) if this computer doesn't have them yet.
          Lightwork's program files are kept on this computer in a readable form.</p>
      </details>
      <button disabled={!listenersRegistered || checkingDependencies || !inventory || (!!inventory.previous_outcome && inventory.previous_outcome !== 'completed' && !dependenciesReviewed)} onclick={startInstall}>
        {listenersRegistered ? 'Install Lightwork' : 'Preparing installer…'}
      </button>
    </section>
  {:else if status === 'installing'}
    <section>
      <h2>Installing…</h2>
      <p class="sub">This usually takes a few minutes. Keep this window open.</p>
      <ol class="steps" aria-label="Installation progress">
        {#each STEPS as step, index}
          <li class={index + 1 < phase ? 'done' : index + 1 === phase || (phase === 0 && index === 0) ? 'current' : ''}
            aria-current={index + 1 === phase || (phase === 0 && index === 0) ? 'step' : undefined}>{step}</li>
        {/each}
      </ol>
      {#if errorMsg}<p class="error" role="alert">Installation could not be stopped safely. It is still running. You can try cancelling again.</p>{/if}
      {@render supportDetails()}
      <button class="cancel" disabled={cancellationRequested} onclick={cancelInstall}>
        {cancellationRequested ? 'Cancelling…' : 'Cancel installation'}
      </button>
    </section>
  {:else if status === 'done'}
    <section class="done">
      <h2>Lightwork is installed</h2>
      <p>Open Lightwork to connect your AI service and finish setup in the app.</p>
      <button disabled={openingLightwork} onclick={openLightwork}>
        {openingLightwork ? 'Opening Lightwork…' : lightworkOpened ? 'Return to Lightwork' : 'Open Lightwork'}
      </button>
      {#if lightworkOpened}<p role="status">Lightwork opened in its own app window.</p>{/if}
      {#if launchError}<p class="error" role="alert">{launchError}</p>{/if}
      {@render supportDetails(true)}
    </section>
  {:else if status === 'failed'}
    <section class="failed">
      <h2>Lightwork couldn't be installed</h2>
      <p class="error" role="alert">{cleanupBlocked
        ? 'Setup stopped, but some of its tasks may still be running in the background, so you cannot start again yet.'
        : listenerRegistrationFailed ? 'The installer could not start. Reload it and try again.'
        : failureAdvice()}</p>
      {#if cleanupBlocked}
        <p>
          Closing the installer does not stop those tasks. After it closes,
          restart your computer before you open the installer again.
        </p>
        <button class="cancel" onclick={confirmForceExit}>Close the installer</button>
      {:else if listenerRegistrationFailed}
        <button onclick={() => window.location.reload()}>Reload installer</button>
      {:else}
        <button disabled={!inventory || checkingDependencies || (!!inventory.previous_outcome && inventory.previous_outcome !== 'completed' && !dependenciesReviewed)} onclick={startInstall}>Resume reviewed bootstrap</button>
      {/if}
      {@render supportDetails()}
    </section>
  {:else}
    <section class="cancelled">
      <h2>Installation cancelled</h2>
      <p>The owned bootstrap stopped. Package-manager or elevation operations may have continued outside it, and dependencies may be partially installed. Recheck them before continuing.</p>
      <button disabled={!inventory || checkingDependencies || (!!inventory.previous_outcome && inventory.previous_outcome !== 'completed' && !dependenciesReviewed)} onclick={startInstall}>Resume reviewed bootstrap</button>
      {@render supportDetails()}
    </section>
  {/if}
</main>

<style>
  /* Same colours and buttons as the Lightwork dashboard (dark theme). */
  :global(body) {
    margin: 0;
    font-family: "Manrope", system-ui, -apple-system, "Segoe UI", sans-serif;
    background: #04050a;
    color: #eef1f7;
  }
  main { padding: 2rem 1rem; max-width: 720px; margin: 0 auto; }
  header { margin-bottom: 1.5rem; }
  h1 { font-size: 2rem; font-weight: 600; letter-spacing: -0.02em; margin: 0; }
  .sub, .hint { color: #8e97ac; }
  .hint { font-size: 0.88rem; }
  p, li { line-height: 1.6; }
  ul { padding-left: 1.25rem; color: #c3c9d6; }
  details { margin: 1rem 0; }
  details.support { border-top: 1px solid #1b2130; padding-top: 0.75rem; }
  summary { cursor: pointer; color: #eef1f7; }
  summary:focus-visible, button:focus-visible { outline: 2px solid #3d8bff; outline-offset: 3px; }
  section {
    position: relative; overflow: hidden;
    background: #0b0e15; border: 1px solid #1b2130; padding: 1.5rem; border-radius: 14px;
  }
  section::before {
    content: ""; position: absolute; left: 0; right: 0; top: 0; height: 2px;
    background: linear-gradient(90deg, #2f7cff 0%, #8b5cf6 52%, #ff8a2b 100%);
  }
  h2 { margin-top: 0; font-size: 1.2rem; font-weight: 600; }
  section > h2:not(:first-child) { margin-top: 1.25rem; font-size: 1rem; }
  button {
    background: #eef1f7; color: #04050a; border: 1px solid transparent; padding: 0.7rem 1.2rem;
    border-radius: 8px; cursor: pointer; font: inherit; font-size: 1rem; font-weight: 600;
  }
  button:hover { background: #d6dae3; }
  button:disabled { background: #2a3246; color: #8e97ac; cursor: wait; }
  button.secondary {
    background: #070910; color: #eef1f7; border-color: #2a3246; font-size: 0.9rem; padding: 0.5rem 0.9rem;
  }
  button.secondary:hover { background: #121726; }
  .row { display: flex; gap: 0.6rem; flex-wrap: wrap; align-items: center; margin-top: 0.75rem; }
  .feedback { color: #3ddc97; font-size: 0.88rem; }
  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
  }
  button.cancel { margin-top: 1rem; background: #070910; color: #ff6b6b; border-color: #ff6b6b; }
  button.cancel:hover { background: #1a0d10; }
  .steps { list-style: none; padding: 0; margin: 1rem 0; }
  .steps li { padding: 0.35rem 0 0.35rem 1.9rem; position: relative; color: #8e97ac; }
  .steps li::before {
    content: ""; position: absolute; left: 0.25rem; top: 0.72rem; width: 0.8rem; height: 0.8rem;
    border-radius: 50%; border: 2px solid #2a3246; box-sizing: border-box;
  }
  .steps li.current { color: #eef1f7; font-weight: 600; }
  .steps li.current::before { border-color: #3d8bff; border-top-color: transparent; animation: spin 1s linear infinite; }
  .steps li.done { color: #c3c9d6; }
  .steps li.done::before { background: #3ddc97; border-color: #3ddc97; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .steps li.current::before { animation: none; border-top-color: #3d8bff; } }
  .log {
    margin-top: 0.75rem; max-height: 320px; overflow: auto;
    background: #070910; border: 1px solid #1b2130; border-radius: 8px;
    padding: 0.75rem; font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.8rem; line-height: 1.4; white-space: pre-wrap; word-break: break-word;
    color: #8e97ac;
  }
  .done h2 { color: #3ddc97; }
  .failed h2 { color: #ff6b6b; }
  .cancelled h2 { color: #ffb547; }
  .error { color: #ff6b6b; }
</style>
