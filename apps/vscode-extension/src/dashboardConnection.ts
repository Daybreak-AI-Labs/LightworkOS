import { createHash } from "crypto";
import * as vscode from "vscode";
import { assertDashboardTransport } from "./eventWatch";

export interface DashboardConnection { base: string; label: string; token: string; scope: string; generation: number; }

function address(value: string): string {
  const url = new URL(value);
  assertDashboardTransport(url, false);
  if (url.search || url.hash) throw new Error("Use the dashboard base address without query parameters or a fragment.");
  return url.href.replace(/\/+$/, "");
}
function key(base: string): string { return "lightwork.dashboard." + createHash("sha256").update(base).digest("hex"); }

/** Credentials are bound to the exact dashboard base and remain in SecretStorage. */
export class DashboardConnections {
  private requests = new Set<AbortController>();
  private generation = 0;
  constructor(private context: vscode.ExtensionContext, private invalidate: () => void) {}
  dispose(): void { this.generation++; for (const request of this.requests) request.abort(); this.requests.clear(); }
  isCurrent(connection: DashboardConnection): boolean { return connection.generation === this.generation; }

  async current(): Promise<DashboardConnection> {
    const config = vscode.workspace.getConfiguration("maverick");
    const base = address(config.get<string>("dashboardUrl", "http://127.0.0.1:8765"));
    let token = await this.context.secrets.get(key(base)) || "";
    const legacy = config.get<string>("dashboardToken", "");
    if (!token && legacy) {
      assertDashboardTransport(new URL(base), true);
      try {
        await this.context.secrets.store(key(base), legacy);
        if (await this.context.secrets.get(key(base)) !== legacy) throw new Error("Credential save was not confirmed");
        token = legacy;
        await config.update("dashboardToken", undefined, vscode.ConfigurationTarget.Global);
      } catch {
        // Never delete the only usable credential after a failed secure save.
        token = legacy;
        void vscode.window.showWarningMessage("The legacy access token could not be fully migrated. It remains available; use Configure dashboard to repair protected storage, then remove the legacy setting.");
      }
    }
    const selectedGeneration = this.generation;
    const selectedToken = await this.context.secrets.get(key(base)) || "";
    if (selectedToken && selectedToken !== token) throw new Error("Dashboard credentials changed while connecting. Choose the current connection again.");
    assertDashboardTransport(new URL(base), Boolean(token));
    const scope = createHash("sha256").update(base + "\0" + token).digest("hex");
    if (token && !this.context.globalState.get<boolean>("lightwork.trusted." + scope)) {
      const consent = await vscode.window.showWarningMessage(
        `Use this access token only with ${base}? Verify this named dashboard before continuing.`,
        {modal: true}, "Use this dashboard");
      if (consent !== "Use this dashboard") throw new Error("Dashboard connection was not confirmed.");
      await this.context.globalState.update("lightwork.trusted." + scope, true);
    }
    if (address(vscode.workspace.getConfiguration("maverick").get<string>("dashboardUrl", "http://127.0.0.1:8765")) !== base) throw new Error("Dashboard changed while connecting. Choose the current connection again.");
    if (selectedGeneration !== this.generation || (await this.context.secrets.get(key(base)) || "") !== selectedToken) throw new Error("Dashboard credentials changed while connecting. Choose the current connection again.");
    return {base, token, scope, generation: selectedGeneration, label: config.get<string>("dashboardName", "My dashboard")};
  }

  async configure(): Promise<void> {
    const config = vscode.workspace.getConfiguration("maverick");
    const name = await vscode.window.showInputBox({prompt: "Connection name", value: config.get("dashboardName", "My dashboard"), ignoreFocusOut: true});
    if (!name) return;
    const raw = await vscode.window.showInputBox({prompt: "Dashboard base address (HTTPS for a remote token)", value: config.get("dashboardUrl", "http://127.0.0.1:8765"), ignoreFocusOut: true});
    if (!raw) return;
    const base = address(raw.trim());
    const token = await vscode.window.showInputBox({prompt: "Access token (saved only in protected storage)", password: true, ignoreFocusOut: true});
    if (token === undefined) return;
    assertDashboardTransport(new URL(base), Boolean(token));
    if (await vscode.window.showWarningMessage(`Save ${name} at ${base}? Verify the destination before saving the token.`, {modal: true}, "Save connection") !== "Save connection") return;
    await this.context.secrets.store(key(base), token);
    if (await this.context.secrets.get(key(base)) !== token) throw new Error("Protected credential save was not confirmed; your existing connection remains active.");
    await config.update("dashboardUrl", base, vscode.ConfigurationTarget.Global);
    await config.update("dashboardName", name.trim().slice(0, 100), vscode.ConfigurationTarget.Global);
    await config.update("dashboardToken", undefined, vscode.ConfigurationTarget.Global);
    this.invalidate();
    void vscode.window.showInformationMessage("Dashboard saved. Test the connection before choosing work.");
  }

  async disconnect(): Promise<void> {
    const config = vscode.workspace.getConfiguration("maverick");
    const base = address(config.get("dashboardUrl", "http://127.0.0.1:8765"));
    if (await vscode.window.showWarningMessage(`Disconnect ${base} and remove its saved token?`, {modal: true}, "Disconnect") !== "Disconnect") return;
    await this.context.secrets.delete(key(base));
    await config.update("dashboardToken", undefined, vscode.ConfigurationTarget.Global);
    this.dispose(); this.invalidate();
    void vscode.window.showInformationMessage("Disconnected and removed the saved token for this dashboard.");
  }

  async request(connection: DashboardConnection, path: string, body?: unknown): Promise<unknown> {
    if (!this.isCurrent(connection)) throw new Error("Dashboard connection changed. Choose a task on the current connection again.");
    assertDashboardTransport(new URL(connection.base), Boolean(connection.token));
    const generation = this.generation;
    const controller = new AbortController(); this.requests.add(controller);
    let rejectAbort: (error: Error) => void = () => {};
    const aborted = new Promise<never>((_, reject) => { rejectAbort = reject; });
    const onAbort = () => rejectAbort(new Error("Dashboard request was cancelled."));
    controller.signal.addEventListener("abort", onAbort, {once: true});
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      return await Promise.race([aborted, (async () => {
      // Without a token the dashboard accepts a local write only from its own address, and Node sends no Origin unless asked.
      const response = await fetch(connection.base + path, {method: body === undefined ? "GET" : "POST", redirect: "error",
        signal: controller.signal, headers: {Accept: "application/json", "Content-Type": "application/json",
          ...(body === undefined ? {} : {Origin: new URL(connection.base).origin}),
          ...(connection.token ? {Authorization: `Bearer ${connection.token}`} : {})},
        body: body === undefined ? undefined : JSON.stringify(body)});
      if (generation !== this.generation || controller.signal.aborted) throw new Error("Dashboard connection changed; the prior response is no longer current.");
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) this.invalidate();
        await response.body?.cancel();
        throw new Error(response.status === 401 || response.status === 403 ? "Access changed. Configure or repair this dashboard connection." :
          `Dashboard request was not confirmed (HTTP ${response.status}). Review task status before any retry.`);
      }
      if (response.status === 204) return null;
      if (!response.body || Number(response.headers.get("content-length") || 0) > 1024 * 1024) { await response.body?.cancel(); throw new Error("Dashboard response exceeds the supported size."); }
      const reader = response.body.getReader(); let size = 0; const parts: Uint8Array[] = [];
      try {
        while (true) { const part = await reader.read(); if (part.done) break;
          size += part.value.byteLength; if (size > 1024 * 1024) throw new Error("Dashboard response exceeds the supported size."); parts.push(part.value); }
      } finally { await reader.cancel(); reader.releaseLock(); }
      const bytes = new Uint8Array(size); let at = 0; for (const part of parts) { bytes.set(part, at); at += part.byteLength; }
      if (generation !== this.generation || controller.signal.aborted) throw new Error("Dashboard connection changed; the prior response is no longer current.");
      return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
      })()]);
    } catch (error) {
      if (controller.signal.aborted) throw new Error("Dashboard request timed out or was cancelled; its outcome is unconfirmed. Check task status before another action.");
      throw error instanceof SyntaxError ? new Error("Dashboard response could not be verified.") : error;
    } finally { clearTimeout(timer); controller.signal.removeEventListener("abort", onAbort); this.requests.delete(controller); }
  }
}
