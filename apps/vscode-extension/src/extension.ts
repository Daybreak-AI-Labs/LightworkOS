// Local CLI tasks and explicitly configured dashboard connections.
import { ownCli, type CliOwner } from "./ownedCli";
import { DashboardConnections, type DashboardConnection } from "./dashboardConnection";
import { createHash } from "crypto";
import * as vscode from "vscode";
import { watchEvents, assertDashboardTransport } from "./eventWatch";
function getCli(): string {
  return vscode.workspace.getConfiguration("maverick").get<string>("cliPath", "maverick");
}

const TERMINAL_CONTROL_RE = /(?:\x1B\][^\x07\x1B]*(?:\x07|\x1B\\|$))|(?:\x1B\[[0-?]*[ -/]*[@-~])|(?:\x1B[@-Z\\-_])|[\x00-\x1F\x7F-\x9F]/g;
function stripTerminalControl(text: string): string {
  return text.replace(TERMINAL_CONTROL_RE, "");
}

let selectedFolder: vscode.WorkspaceFolder | undefined;
let extensionContext: vscode.ExtensionContext;
let connections: DashboardConnections;
const cliOwners = new Set<CliOwner>();
let starting = false;
let disposed = false;
function getCwd(): string | undefined {
  if (!vscode.workspace.getConfiguration("maverick").get<boolean>("workspaceCwd", true)) return undefined;
  const folders = vscode.workspace.workspaceFolders || [];
  const editor = vscode.window.activeTextEditor;
  const active = editor ? vscode.workspace.getWorkspaceFolder(editor.document.uri) : undefined;
  if (selectedFolder && folders.some(folder => folder.uri.toString() === selectedFolder!.uri.toString())) return selectedFolder.uri.fsPath;
  if (active) return active.uri.fsPath;
  if (folders.length === 1) return folders[0].uri.fsPath;
  if (folders.length > 1) throw new Error("Choose a local workspace with Lightwork: Select workspace before loading local runs.");
  return undefined;
}

async function chooseWorkspace(): Promise<boolean> {
  if (!vscode.workspace.getConfiguration("maverick").get<boolean>("workspaceCwd", true)) return true;
  const folders = vscode.workspace.workspaceFolders || [];
  if (folders.length < 2) { selectedFolder = folders[0]; return true; }
  const editor = vscode.window.activeTextEditor;
  const active = editor ? vscode.workspace.getWorkspaceFolder(editor.document.uri) : undefined;
  selectedFolder = await vscode.window.showWorkspaceFolderPick({placeHolder: active ? `Choose task workspace (active editor: ${active.name})` : "Choose the local task workspace"});
  return Boolean(selectedFolder);
}

async function runCliCapture(args: string[], cwd = getCwd()): Promise<string> {
  const owner = ownCli(getCli(), args, {cwd}); cliOwners.add(owner);
  try { return (await owner.result).stdout; } finally { cliOwners.delete(owner); }
}

async function runCliStream(args: string[], onLine: (line: string) => void, cwd: string | undefined, timeoutMs: number): Promise<number> {
  return vscode.window.withProgress({location: vscode.ProgressLocation.Notification, title: "Lightwork task: stop local supervision only", cancellable: true}, async (_progress, token) => {
    const owner = ownCli(getCli(), args, {cwd, timeoutMs, onLine}); cliOwners.add(owner);
    const cancelled = token.onCancellationRequested(owner.cancel);
    try { return (await owner.result).code; } finally { cancelled.dispose(); cliOwners.delete(owner); }
  });
}

async function checkedHaltCommand(command: "halt" | "unhalt"): Promise<void> {
  const output = await runCliCapture([command, "--json"]);
  let result;
  try { result = JSON.parse(output); }
  catch { throw new Error("Local halt-file acknowledgement was unreadable. Update the CLI and review its state."); }
  if (result.command !== command || result.acknowledged !== true || result.scope !== "local" ||
      result.halt_file_present !== (command === "halt") || result.work_stopped !== false) {
    throw new Error("Local halt-file state was not confirmed. Check the CLI before retrying.");
  }
}

// One run = one episode, as emitted by `maverick runs --json`. Keep in
// sync with the record built in maverick/cli.py::runs.
interface RunRecord {
  episode_id: number;
  goal_id: number;
  goal_title: string | null;
  goal_status: string | null;
  outcome: string | null;
  running: boolean;
  started_at: number | null;
  ended_at: number | null;
  duration_s: number | null;
  cost_dollars: number;
  input_tokens: number;
  output_tokens: number;
  tool_calls: number;
}

class RunItem extends vscode.TreeItem {
  constructor(public readonly run: RunRecord, public readonly cwd?: string) {
    const title = stripTerminalControl(run.goal_title ?? `goal ${run.goal_id}`);
    super(`#${run.episode_id} ${title}`, vscode.TreeItemCollapsibleState.None);
    const state = run.running ? "running" : run.outcome ?? "done";
    const dur = run.duration_s != null ? `${run.duration_s.toFixed(1)}s` : "—";
    this.description = `${state} · $${run.cost_dollars.toFixed(4)}`;
    const tooltip = new vscode.MarkdownString();
    tooltip.appendMarkdown(`**Run #${run.episode_id}** (goal #${run.goal_id})\n\n`);
    tooltip.appendMarkdown("Goal: ");
    tooltip.appendText(title);
    tooltip.appendMarkdown(
      `\n\nState: \`${state}\`` +
      `\n\nCost: \`$${run.cost_dollars.toFixed(4)}\`` +
      `\n\nTokens: \`${run.input_tokens} in / ${run.output_tokens} out\`` +
      `\n\nTool calls: \`${run.tool_calls}\`` +
      `\n\nDuration: \`${dur}\``,
    );
    this.tooltip = tooltip;
    this.iconPath = new vscode.ThemeIcon(
      run.running ? "sync"
      : state === "completed" || state === "succeeded" || state === "done" ? "check"
      : state === "failed" || state === "blocked" || state === "error" ? "error"
      : "circle-outline",
    );
    this.contextValue = "maverickRun";
    this.command = {command: "maverick.runActions", title: "Choose a task action", arguments: [this]};
  }
}

class RunsProvider implements vscode.TreeDataProvider<RunItem>, vscode.Disposable {
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChange.event;
  refresh() {
    this._onDidChange.fire();
  }
  dispose() {
    this._onDidChange.dispose();
  }
  getTreeItem(el: RunItem): vscode.TreeItem {
    return el;
  }
  async getChildren(): Promise<RunItem[]> {
    let out: string;
    try {
      out = await runCliCapture(["runs", "--json"]);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showFailure("Could not load your Lightwork runs. Check that Lightwork is installed on this computer.", msg);
      return [];
    }
    let rows: RunRecord[];
    try {
      rows = JSON.parse(out.trim() || "[]") as RunRecord[];
    } catch {
      showFailure("Lightwork returned an unreadable run list. Try refreshing it.", "Could not parse maverick runs --json output.");
      return [];
    }
    return rows.map((r) => new RunItem(r, getCwd()));
  }
}

function showFailure(message: string, error: unknown): void {
  if (disposed) return;
  const out = getOutput();
  out.appendLine(message);
  out.appendLine(stripTerminalControl(error instanceof Error ? error.message : String(error)));
  void vscode.window.showErrorMessage(message, "View details").then(choice => {
    if (choice === "View details") out.show(true);
  });
}

let outputChannel: vscode.OutputChannel | undefined;
function getOutput(): vscode.OutputChannel {
  if (!outputChannel) {
    outputChannel = vscode.window.createOutputChannel("Lightwork");
  }
  return outputChannel;
}

function budgetReview(value: unknown): string {
  const preview = value as {effective?: {max_dollars?: unknown; max_wall_seconds?: unknown}; available?: boolean; notice?: unknown; person?: {status?: string}};
  const dollars = preview?.effective?.max_dollars, seconds = preview?.effective?.max_wall_seconds;
  if (typeof dollars !== "number" || !Number.isFinite(dollars) || dollars < 0 || typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 1) {
    throw new Error("Effective task ceilings could not be verified. Check budget settings and update the CLI before starting paid work.");
  }
  return `Resolved task ceilings: $${dollars}, ${seconds} seconds. ` +
    (preview.available === true ? "Budget headroom is a current advisory snapshot. " : "Budget headroom or identity could not be fully established. ") +
    (typeof preview.notice === "string" ? stripTerminalControl(preview.notice).slice(0, 1000) + " " : "") +
    "This preview reserves nothing; launch rechecks current policy.";
}

async function startGoalCommand() {
  if (starting) { void vscode.window.showWarningMessage("A Lightwork start is already being prepared or supervised."); return; }
  if (!vscode.workspace.isTrusted) { void vscode.window.showErrorMessage("Trust this workspace before starting a local agent."); return; }
  starting = true;
  try {
    if (!(await chooseWorkspace())) return;
    const cwd = getCwd();
    const scope = createHash("sha256").update(getCli() + "\0" + (cwd || "local-default")).digest("hex");
    const pendingKey = "lightwork.local-start." + scope;
    const pending = extensionContext.globalState.get<{startedAt: number; goalId?: number}>(pendingKey);
    if (pending) {
      const choice = await vscode.window.showWarningMessage(`A previous local start remains unconfirmed${pending.goalId ? ` (reported task ${pending.goalId})` : ""}. Inspect recent local runs before creating more paid work.`, {modal: true}, "Review runs", "I reconciled it; start a new task");
      if (choice !== "I reconciled it; start a new task") { if (choice === "Review runs") { const runs = await runCliCapture(["runs", "--json", "--limit", "50"], cwd); const output = getOutput(); output.show(true); output.appendLine(stripTerminalControl(runs)); } return; }
    }
    const goal = await vscode.window.showInputBox({prompt: "Describe the task", ignoreFocusOut: true});
    if (!goal) return;
    const config = vscode.workspace.getConfiguration("maverick");
    const dollars = await vscode.window.showInputBox({prompt: "Requested maximum cost in USD (deployment policy may lower it)", value: String(config.get("maxDollars", 2)), validateInput: value => Number.isFinite(Number(value)) && Number(value) > 0 && Number(value) <= 100 ? null : "Enter a cost above zero and at most 100."});
    if (!dollars) return;
    const seconds = await vscode.window.showInputBox({prompt: "Requested maximum duration in seconds", value: String(config.get("maxWallSeconds", 1800)), validateInput: value => Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 86400 ? null : "Enter whole seconds from 1 to 86400."});
    if (!seconds) return;
    const preview = JSON.parse(await runCliCapture(["budget-preview", "--json", "--max-dollars", dollars, "--max-wall-seconds", seconds], cwd));
    const limits = budgetReview(preview);
    if (await vscode.window.showWarningMessage(`Start in ${cwd || "the CLI default location"}? Requested limits: $${Number(dollars)}, ${Number(seconds)} seconds. ${limits}`, {modal: true}, "Start task") !== "Start task") return;
    const saved: {startedAt: number; goalId?: number} = {startedAt: Date.now()};
    await extensionContext.globalState.update(pendingKey, saved); // Refuse dispatch if durable recovery metadata cannot be saved.
    const out = getOutput(); out.show(true); out.appendLine(`Starting local task in ${cwd || "CLI default"}; requested caps $${dollars}, ${seconds}s.`);
    let receiptSave: PromiseLike<void> = Promise.resolve();
    await runCliStream(["start", goal, "--max-dollars", dollars, "--max-wall-seconds", seconds], line => {
      const safe = stripTerminalControl(line); out.appendLine(safe);
      const match = /^goal #(\d+) created(?:\s|:)/.exec(safe);
      if (match && !saved.goalId) { saved.goalId = Number(match[1]); receiptSave = extensionContext.globalState.update(pendingKey, saved).then(undefined, () => {}); }
    }, cwd, Number(seconds) * 1000 + 30000);
    await receiptSave;
    await extensionContext.globalState.update(pendingKey, undefined);
    void vscode.window.showInformationMessage("Local Lightwork command completed. Review its task result and recent runs.");
  } catch (error) { showFailure("Lightwork start was not confirmed. Review recent local runs before starting again.", error); }
  finally { starting = false; }
}

async function statusCommand() {
  try {
    const txt = await runCliCapture(["status"]);
    const out = getOutput();
    out.show(true);
    out.append(txt);
  } catch (e: unknown) {
    showFailure("Could not load Lightwork status.", e);
  }
}

async function pickLocalRun(selected?: RunItem): Promise<RunItem | undefined> {
  if (selected instanceof RunItem) return selected;
  if (!(await chooseWorkspace())) return;
  const cwd = getCwd();
  const rows = JSON.parse(await runCliCapture(["runs", "--json"], cwd)) as RunRecord[];
  const choices = rows.map(run => ({label: stripTerminalControl(run.goal_title || `Task ${run.goal_id}`), description: `Local task ${run.goal_id} · ${run.goal_status || "unknown"}`, item: new RunItem(run, cwd)}));
  const choice = await vscode.window.showQuickPick(choices, {placeHolder: "Search recent local tasks by title or ID", matchOnDescription: true});
  return choice?.item;
}

async function exportCommand(selected?: RunItem) {
  try {
    const item = await pickLocalRun(selected); if (!item) return;
    const dest = await vscode.window.showSaveDialog({defaultUri: vscode.Uri.file(`goal-${item.run.goal_id}.json`), filters: {JSON: ["json"]}});
    if (!dest) return;
    await runCliCapture(["export", String(item.run.goal_id), "-o", dest.fsPath], item.cwd);
    void vscode.window.showInformationMessage(`Exported local task ${item.run.goal_id} to ${dest.fsPath}`);
  } catch (error) { showFailure("Could not export this local task.", error); }
}

async function pickDashboardTask(connection: DashboardConnection, selected?: RunItem): Promise<number | undefined> {
  if (selected instanceof RunItem) {
    if (await vscode.window.showWarningMessage(`The sidebar task is local (${selected.cwd || "CLI default"}). Watch task ${selected.run.goal_id} on ${connection.label} (${connection.base}) only if this is the same task database.`, {modal: true}, "Use this dashboard task") !== "Use this dashboard task") return;
    return selected.run.goal_id;
  }
  const query = await vscode.window.showInputBox({prompt: `Find an authorized task on ${connection.label} (${connection.base})`, placeHolder: "Title or content; leave empty for recent tasks"});
  if (query === undefined) return;
  const path = query.trim() ? `/api/v1/goals/search?q=${encodeURIComponent(query.trim())}&limit=100` : "/api/v1/goals?limit=100";
  const rows = await connections.request(connection, path);
  if (!Array.isArray(rows)) throw new Error("Task list could not be verified.");
  const choices = rows.filter(row => row && Number.isSafeInteger(row.id) && row.id > 0 && typeof row.title === "string").map(row => ({label: stripTerminalControl(row.title), description: `Task ${row.id} · ${row.status}`, goalId: row.id as number}));
  const picked = await vscode.window.showQuickPick(choices, {placeHolder: `Choose a task on ${connection.label}; up to 100 authorized matches`, matchOnDescription: true});
  return picked?.goalId;
}

async function controlTask(action: "cancel" | "resume"): Promise<void> {
  try {
    const connection = await connections.current();
    const id = await pickDashboardTask(connection); if (!id) return;
    const preview = action === "resume" ? budgetReview(await connections.request(connection, `/api/v1/budget/preview?goal_id=${id}`)) : "";
    const explanation = action === "cancel" ? "Cancel only this task at its next safe work boundary? Completed external effects cannot be undone." : "Resume only this task under current deployment policy? This may incur further cost.";
    if (await vscode.window.showWarningMessage(`${connection.label} · task ${id}: ${explanation} ${preview}`, {modal: true}, action === "cancel" ? "Cancel this task" : "Resume this task") !== (action === "cancel" ? "Cancel this task" : "Resume this task")) return;
    await connections.request(connection, `/api/v1/goals/${id}/${action}`, {});
    void vscode.window.showInformationMessage(action === "cancel" ? "Task cancellation was acknowledged. Work stops cooperatively; existing effects may remain." : "Task resume was acknowledged. Check its progress; acknowledgement is not completion.");
  } catch (error) { showFailure("Task control was not confirmed. Review current task status before retrying.", error); }
}

// --- live-run streaming (SSE from the local dashboard) -------------------
//
// `maverick.watchRun` tails a run's events live into an output channel via
// the dashboard's SSE endpoint (GET /api/v1/goals/{id}/events/stream). Plain
// Node http (no deps), manual SSE parse, exponential backoff reconnect, and
// a stop command. The dashboard URL/token come from machine-scoped settings.
let liveAbort: (() => void) | null = null;
let watchGeneration = 0;
const watchCursors = new Map<string, number>();
const watchOutputs: vscode.OutputChannel[] = [];
function invalidateDashboard(): void {
  liveAbort?.(); liveAbort = null; watchGeneration++;
  connections?.dispose(); watchCursors.clear();
  for (const channel of watchOutputs.splice(0)) channel.dispose();
}

async function watchRunCommand(selected?: RunItem): Promise<void> {
  const generation = ++watchGeneration;
  liveAbort?.(); liveAbort = null;
  let connection: DashboardConnection, goalId: number | undefined;
  try { connection = await connections.current(); goalId = await pickDashboardTask(connection, selected); }
  catch (error) { showFailure("Could not open an authorized dashboard watch.", error); return; }
  if (!goalId || generation !== watchGeneration || !connections.isCurrent(connection)) return;
  const url = new URL(`${connection.base}/api/v1/goals/${goalId}/events/stream`);
  const token = connection.token;
  assertDashboardTransport(url, Boolean(token));
  const channel = vscode.window.createOutputChannel(`Lightwork ${connection.label} task #${goalId}`);
  channel.show(true);
  const http = url.protocol === "https:" ? await import("https") : await import("http");
  if (generation !== watchGeneration) { channel.dispose(); return; }
  const key = createHash("sha256").update(url.href + "\0" + token).digest("hex");
  if (!watchCursors.has(key) && watchCursors.size >= 16) watchCursors.delete(watchCursors.keys().next().value!);
  watchOutputs.push(channel);
  if (watchOutputs.length > 4) watchOutputs.shift()!.dispose();
  let outputBytes = 0;
  const append = (line: string) => {
    if (generation !== watchGeneration) return;
    const safe = stripTerminalControl(line).slice(0, 262144);
    outputBytes += safe.length;
    if (outputBytes > 1000000) {
      channel.clear(); outputBytes = safe.length;
      channel.appendLine("[Earlier output cleared; open the dashboard for full history.]");
    }
    channel.appendLine(safe);
  };
  const cursor = watchCursors.get(key) || 0;
  if (cursor) append(`[Resuming after event ${cursor}; earlier output is in the previous watch or dashboard.]`);
  liveAbort = watchEvents({url, headers: token ? {Authorization: `Bearer ${token}`} : {}, cursor,
    connect: http.get, onEvent: append, onCursor: value => { if (generation === watchGeneration) watchCursors.set(key, value); },
    onNotice: line => append(`[${line}]`), onStop: reason => {
      if (/HTTP (401|403)|visibility changed/.test(reason)) {
        invalidateDashboard();
        void vscode.window.showErrorMessage("Task access changed. The private view was cleared; repair the dashboard connection before reopening it.");
      } else append(`[${reason}]`);
    }});
}

export function activate(context: vscode.ExtensionContext): void {
  disposed = false;
  extensionContext = context;
  connections = new DashboardConnections(context, invalidateDashboard);
  const runs = new RunsProvider();
  context.subscriptions.push(
    // Push the provider (disposes its EventEmitter) and the tree-view
    // registration so a reload/deactivate tears them down instead of leaking.
    runs,
    connections,
    vscode.window.registerTreeDataProvider("maverick.runs", runs),
    vscode.commands.registerCommand("maverick.start", startGoalCommand),
    vscode.commands.registerCommand("maverick.selectWorkspace", async () => { if (await chooseWorkspace()) runs.refresh(); }),
    vscode.commands.registerCommand("maverick.configureDashboard", async () => { try { await connections.configure(); } catch (error) { showFailure("Connection could not be saved; review the existing connection before retrying.", error); } }),
    vscode.commands.registerCommand("maverick.disconnectDashboard", async () => { try { await connections.disconnect(); } catch (error) { showFailure("Disconnect was not confirmed.", error); } }),
    vscode.commands.registerCommand("maverick.testDashboard", async () => { try { const connection = await connections.current(); await connections.request(connection, "/api/v1/goals?limit=1"); void vscode.window.showInformationMessage(`Authorized connection confirmed: ${connection.label} (${connection.base}).`); } catch (error) { showFailure("Dashboard access could not be verified. Configure the connection to repair it.", error); } }),
    vscode.commands.registerCommand("maverick.cancelTask", () => controlTask("cancel")),
    vscode.commands.registerCommand("maverick.resumeTask", () => controlTask("resume")),
    vscode.commands.registerCommand("maverick.runActions", async (item: RunItem) => { const action = await vscode.window.showQuickPick(["Export local task", "Watch on configured dashboard"], {placeHolder: "Choose an action for this local task"}); if (action === "Export local task") await exportCommand(item); else if (action) await watchRunCommand(item); }),
    vscode.commands.registerCommand("maverick.status", statusCommand),
    vscode.commands.registerCommand("maverick.halt", async () => {
      try {
        await checkedHaltCommand("halt");
        vscode.window.showInformationMessage("Lightwork kill switch armed. Running work stops at its next checkpoint.");
      } catch (e: unknown) {
        // A silent failure here is dangerous: the user would believe the
        // agent was halted when the CLI call actually failed.
        showFailure("Could not stop Lightwork.", e);
      }
    }),
    vscode.commands.registerCommand("maverick.unhalt", async () => {
      try {
        await checkedHaltCommand("unhalt");
        vscode.window.showInformationMessage("Lightwork kill switch cleared. This does not restart prior tasks.");
      } catch (e: unknown) {
        showFailure("Could not clear the Lightwork emergency stop.", e);
      }
    }),
    vscode.commands.registerCommand("maverick.openExport", exportCommand),
    vscode.commands.registerCommand("maverick.refreshRuns", () => runs.refresh()),
    vscode.commands.registerCommand("maverick.watchRun", watchRunCommand),
    vscode.commands.registerCommand("maverick.stopWatch", () => {
      watchGeneration++;
      if (liveAbort) {
        liveAbort();
        liveAbort = null;
      } else {
        vscode.window.showInformationMessage("No live watch running.");
      }
    }),
    vscode.workspace.onDidChangeConfiguration(event => {
      if (event.affectsConfiguration("maverick.dashboardUrl") || event.affectsConfiguration("maverick.dashboardToken")) {
        invalidateDashboard();
      }
    }),
  );
  if (context.secrets?.onDidChange) context.subscriptions.push(context.secrets.onDidChange(event => {
    if (event.key.startsWith("lightwork.dashboard.")) invalidateDashboard();
  }));
}

export function deactivate(): void {
  disposed = true;
  for (const owner of cliOwners) owner.cancel();
  cliOwners.clear();
  connections?.dispose();
  if (liveAbort) liveAbort();
  liveAbort = null; watchGeneration++;
  for (const channel of watchOutputs.splice(0)) channel.dispose();
  if (outputChannel) outputChannel.dispose();
  outputChannel = undefined;
}
