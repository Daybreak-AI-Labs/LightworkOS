import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import App from './App.svelte';

const tauri = vi.hoisted(() => ({
  invoke: vi.fn(),
  inventory: vi.fn(),
  listen: vi.fn(),
  unlisten: vi.fn(),
  close: vi.fn(),
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke: (command: string, ...args: unknown[]) => command === 'bootstrap_inventory' ? tauri.inventory(...args) : tauri.invoke(command, ...args) }));

const inventory = { source_ref: 'a'.repeat(40), phase: '', outcome: 'reviewed', previous_outcome: '', review: 'review-a', updated_at: 99999999999, inventory: [{name: 'Python', state: 'responded', detail: '3.13.0'}] };
async function installButton() {
  const button = await screen.findByRole('button', {name: 'Install Lightwork'}) as HTMLButtonElement;
  await waitFor(() => expect(button.disabled).toBe(false));
  return button;
}
vi.mock('@tauri-apps/api/event', () => ({ listen: tauri.listen }));
vi.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({ close: tauri.close }),
}));

describe('installer terminal state', () => {
  beforeEach(() => {
    tauri.invoke.mockReset();
    tauri.inventory.mockReset();
    tauri.inventory.mockResolvedValue(inventory);
    tauri.listen.mockReset();
    tauri.unlisten.mockReset();
    tauri.close.mockReset();
    tauri.listen.mockResolvedValue(tauri.unlisten);
    tauri.close.mockResolvedValue(undefined);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('explains in plain words what happens and what the person needs before install', async () => {
    render(App);
    const disclosure = screen.getByText(/installs Lightwork on this computer, then opens it/);
    expect(disclosure.closest('details')).toBeNull();
    const access = screen.getByText(/public GitHub repository; no GitHub account is needed/);
    expect(access.closest('details')).toBeNull();
    expect(screen.getByText(/An internet connection/)).toBeTruthy();
    expect(screen.getByText(/Permission to install apps/)).toBeTruthy();
    const page = document.body.textContent ?? '';
    for (const phrase of ['source code', 'private Lightwork repository', 'Python will be installed', 'Python source code', 'authorized access']) {
      expect(page).not.toContain(phrase);
    }
    expect((await installButton() as HTMLButtonElement).disabled).toBe(false);
    expect(tauri.invoke).not.toHaveBeenCalled();
  });

  it('shows plain progress steps and keeps raw output under details for support', async () => {
    let logHandler: ((event: { payload: string }) => void) | undefined;
    tauri.listen.mockImplementation(async (event: string, handler: (event: { payload: string }) => void) => {
      if (event === 'install-log') logHandler = handler;
      return tauri.unlisten;
    });
    tauri.invoke.mockReturnValue(new Promise<void>(() => {}));
    render(App);
    await fireEvent.click(await installButton());
    const steps = screen.getByRole('list', { name: 'Installation progress' });
    expect(steps.querySelector('[aria-current="step"]')?.textContent).toBe('Getting this computer ready');
    logHandler?.({ payload: '==> Downloading a fresh Lightwork source tree (owner/repo@abc) ...' });
    await waitFor(() => expect(steps.querySelector('[aria-current="step"]')?.textContent).toBe('Downloading Lightwork'));
    const raw = await screen.findByText(/Downloading a fresh Lightwork source tree/);
    expect(raw.closest('details')?.open).toBe(false);
    expect(raw.closest('details')?.querySelector('summary')?.textContent).toBe('Details for support');
    expect(screen.getByRole('button', { name: 'Copy' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Save' })).toBeTruthy();
  });

  it('turns a missing GitHub sign-in into a plain next step', async () => {
    let logHandler: ((event: { payload: string }) => void) | undefined;
    let failInstall!: (reason: unknown) => void;
    tauri.listen.mockImplementation(async (event: string, handler: (event: { payload: string }) => void) => {
      if (event === 'install-log') logHandler = handler;
      return tauri.unlisten;
    });
    tauri.invoke.mockReturnValue(new Promise<void>((_resolve, reject) => { failInstall = reject; }));
    render(App);
    await fireEvent.click(await installButton());
    logHandler?.({ payload: "fatal: could not read Username for 'https://github.com': terminal prompts disabled" });
    failInstall({ code: 'failed', message: 'Installer exited with status 1' });
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('GitHub refused the request');
    expect(alert.textContent).not.toContain('fatal');
    expect(screen.getByRole('button', { name: 'Resume reviewed bootstrap' })).toBeTruthy();
  });

  it('copies the support details to the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    tauri.invoke.mockRejectedValue({ code: 'failed', message: 'synthetic failure detail' });
    render(App);
    await fireEvent.click(await installButton());
    await screen.findByRole('heading', { name: "Lightwork couldn't be installed" });
    await fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expect.stringContaining('synthetic failure detail')));
    expect(await screen.findByText('Copied.')).toBeTruthy();
  });

  it('shows success when invoke resolves even if no completion event arrives', async () => {
    let completeInstall!: () => void;
    tauri.invoke.mockReturnValue(
      new Promise<void>((resolve) => {
        completeInstall = resolve;
      })
    );

    render(App);
    await fireEvent.click(
      await installButton()
    );

    expect(screen.getByRole('heading', { name: 'Installing…' })).toBeTruthy();
    expect(tauri.listen).toHaveBeenCalledWith('install-log', expect.any(Function));
    expect(tauri.listen).not.toHaveBeenCalledWith('install-done', expect.any(Function));

    completeInstall();

    expect(
      await screen.findByRole('heading', { name: /Lightwork is installed/ })
    ).toBeTruthy();
    expect(tauri.invoke).toHaveBeenCalledOnce();
    expect(tauri.invoke).toHaveBeenCalledWith('install', {review: 'review-a', confirmDependenciesReviewed: false});
  });

  it('shows the command error without depending on a failure event', async () => {
    tauri.invoke.mockRejectedValue({
      code: 'failed',
      message: 'authorization denied',
    });

    render(App);
    await fireEvent.click(
      await installButton()
    );

    expect(await screen.findByRole('heading', { name: "Lightwork couldn't be installed" })).toBeTruthy();
    expect(screen.getByText('authorization denied')).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toContain('Select Try again');
    expect(screen.getByRole('alert').textContent).not.toContain('authorization denied');
    expect(screen.getByText('authorization denied').closest('details')?.open).toBe(false);
    await waitFor(() => {
      expect(tauri.listen).not.toHaveBeenCalledWith('install-failed', expect.any(Function));
    });
  });

  it('opens the installed app for setup and prevents repeated launch requests', async () => {
    let open!: () => void;
    tauri.invoke.mockImplementation((command: string) => {
      if (command === 'install') return Promise.resolve();
      if (command === 'open_lightwork') return new Promise<void>((resolve) => { open = resolve; });
      return Promise.reject(new Error(`unexpected command: ${command}`));
    });
    render(App);
    await fireEvent.click(await installButton());
    await fireEvent.click(await screen.findByRole('button', { name: 'Open Lightwork' }));
    expect((screen.getByRole('button', { name: 'Opening Lightwork…' }) as HTMLButtonElement).disabled).toBe(true);
    expect(tauri.invoke).toHaveBeenNthCalledWith(2, 'open_lightwork');
    expect(screen.queryByText(/maverick init|Terminal or PowerShell/)).toBeNull();
    open();
    expect(await screen.findByRole('button', { name: 'Return to Lightwork' })).toBeTruthy();
    expect(screen.getByText('Lightwork opened in its own app window.')).toBeTruthy();
  });

  it('keeps launch retry and diagnostics inside the installer after startup fails', async () => {
    tauri.invoke.mockImplementation((command: string) => {
      if (command === 'install') return Promise.resolve();
      if (command === 'open_lightwork') return Promise.reject('synthetic launch error');
      if (command === 'dashboard_diagnostics') return Promise.resolve('synthetic startup output');
      return Promise.reject(new Error(`unexpected command: ${command}`));
    });
    render(App);
    await fireEvent.click(await installButton());
    await fireEvent.click(await screen.findByRole('button', { name: 'Open Lightwork' }));
    expect((await screen.findByRole('alert')).textContent).toContain('select Open Lightwork again');
    expect(screen.getByRole('alert').textContent).not.toContain('synthetic');
    expect((screen.getByRole('button', { name: 'Open Lightwork' }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByText('synthetic launch error').closest('details')?.open).toBe(false);
    await fireEvent.click(screen.getByRole('button', { name: 'Show startup messages' }));
    expect(await screen.findByText('synthetic startup output')).toBeTruthy();
  });

  it('waits for owned process teardown before reporting cancellation', async () => {
    let rejectInstall!: (reason: unknown) => void;
    const operation = new Promise<void>((_resolve, reject) => {
      rejectInstall = reject;
    });
    tauri.invoke.mockImplementation((command: string) => {
      if (command === 'install') return operation;
      if (command === 'cancel_install') {
        rejectInstall({
          code: 'cancelled',
          message: 'owned process tree terminated',
        });
        return Promise.resolve();
      }
      return Promise.reject(new Error(`unexpected command: ${command}`));
    });

    render(App);
    await fireEvent.click(
      await installButton()
    );
    await fireEvent.click(
      screen.getByRole('button', { name: 'Cancel installation' })
    );

    expect(
      await screen.findByRole('heading', { name: 'Installation cancelled' })
    ).toBeTruthy();
    expect(tauri.invoke).toHaveBeenNthCalledWith(1, 'install', {review: 'review-a', confirmDependenciesReviewed: false});
    expect(tauri.invoke).toHaveBeenNthCalledWith(2, 'cancel_install');
  });

  it('confirms close, cancels, and closes only after install cleanup', async () => {
    let closeHandler: (() => void) | undefined;
    let rejectInstall!: (reason: unknown) => void;
    const operation = new Promise<void>((_resolve, reject) => {
      rejectInstall = reject;
    });
    tauri.listen.mockImplementation(
      async (event: string, handler: () => void) => {
        if (event === 'install-close-requested') closeHandler = handler;
        return tauri.unlisten;
      }
    );
    tauri.invoke.mockImplementation((command: string) => {
      if (command === 'install') return operation;
      if (command === 'cancel_install') {
        rejectInstall({ code: 'cancelled', message: 'cancelled' });
        return Promise.resolve();
      }
      return Promise.reject(new Error(`unexpected command: ${command}`));
    });
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    render(App);
    await waitFor(() => expect(closeHandler).toBeTypeOf('function'));
    await fireEvent.click(
      await installButton()
    );
    closeHandler?.();

    await waitFor(() => expect(tauri.close).toHaveBeenCalledOnce());
    expect(tauri.invoke).toHaveBeenCalledWith('cancel_install');
  });

  it('does not close or claim cancellation when process teardown fails', async () => {
    let closeHandler: (() => void) | undefined;
    let rejectInstall!: (reason: unknown) => void;
    const operation = new Promise<void>((_resolve, reject) => {
      rejectInstall = reject;
    });
    tauri.listen.mockImplementation(
      async (event: string, handler: () => void) => {
        if (event === 'install-close-requested') closeHandler = handler;
        return tauri.unlisten;
      }
    );
    tauri.invoke.mockImplementation((command: string) => {
      if (command === 'install') return operation;
      if (command === 'cancel_install') {
        rejectInstall({
          code: 'cleanup_failed',
          message: 'installer descendants survived forced teardown',
        });
        return Promise.resolve();
      }
      return Promise.reject(new Error(`unexpected command: ${command}`));
    });
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    render(App);
    await waitFor(() => expect(closeHandler).toBeTypeOf('function'));
    await fireEvent.click(
      await installButton()
    );
    closeHandler?.();

    expect(await screen.findByRole('heading', { name: "Lightwork couldn't be installed" })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Close the installer' })).toBeTruthy();
    expect(
      screen.getByText('installer descendants survived forced teardown')
    ).toBeTruthy();
    expect(tauri.close).not.toHaveBeenCalled();
  });

  it('unregisters listeners that resolve after component destruction', async () => {
    const lateUnlisten = vi.fn();
    const resolvers: Array<(unlisten: typeof lateUnlisten) => void> = [];
    tauri.listen.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolvers.push(resolve);
        })
    );

    render(App);
    await waitFor(() => expect(resolvers).toHaveLength(3));
    cleanup();
    resolvers.forEach((resolve) => resolve(lateUnlisten));

    await waitFor(() => expect(lateUnlisten).toHaveBeenCalledTimes(3));
  });

  it('shows a cancellation request failure while the installer remains active', async () => {
    let completeInstall!: () => void;
    const operation = new Promise<void>((resolve) => {
      completeInstall = resolve;
    });
    tauri.invoke.mockImplementation((command: string) => {
      if (command === 'install') return operation;
      if (command === 'cancel_install') {
        return Promise.reject({ code: 'failed', message: 'process control unavailable' });
      }
      return Promise.reject(new Error(`unexpected command: ${command}`));
    });

    render(App);
    await fireEvent.click(
      await installButton()
    );
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel installation' }));

    expect((await screen.findByRole('alert')).textContent).toContain(
      'Installation could not be stopped safely'
    );
    expect(screen.getByText('Could not cancel safely: process control unavailable').closest('details')?.open).toBe(false);
    expect(screen.getByRole('heading', { name: 'Installing…' })).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Cancel installation' }) as HTMLButtonElement).disabled).toBe(false);
    expect(tauri.close).not.toHaveBeenCalled();
    completeInstall();
    expect(await screen.findByRole('heading', { name: /Lightwork is installed/ })).toBeTruthy();
  });
  it('requires review of partial dependencies before a resumed bootstrap', async () => {
    tauri.inventory.mockResolvedValue({...inventory, previous_outcome: 'cancelled', phase: 'installing complete package cohort'});
    tauri.invoke.mockReturnValue(new Promise<void>(() => {}));
    render(App);
    const confirm = await screen.findByRole('checkbox', {name: /I reviewed the dependencies/});
    const button = screen.getByRole('button', {name: 'Install Lightwork'}) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    await fireEvent.click(confirm);
    await waitFor(() => expect(button.disabled).toBe(false));
    await fireEvent.click(button);
    expect(tauri.invoke).toHaveBeenCalledWith('install', {review: 'review-a', confirmDependenciesReviewed: true});
  });

  it('requires fresh inventory after opening independent OS repair', async () => {
    tauri.invoke.mockResolvedValue(undefined);
    render(App);
    await installButton();
    await fireEvent.click(screen.getByRole('button', {name: 'Open OS application management'}));
    await waitFor(() => expect(tauri.invoke).toHaveBeenCalledWith('open_dependency_repair'));
    expect((screen.getByRole('button', {name: 'Install Lightwork'}) as HTMLButtonElement).disabled).toBe(true);
    await fireEvent.click(screen.getByRole('button', {name: 'Recheck dependencies'}));
    await installButton();
    expect(tauri.inventory).toHaveBeenCalledTimes(2);
  });

});
