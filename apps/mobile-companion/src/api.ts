/* Bounded personal companion client for the Lightwork dashboard REST API.
 *
 * Task readers use GET endpoints in
 * packages/maverick-dashboard/maverick_dashboard/api.py:
 *
 *   GET /api/v1/goals?limit=&status=          listGoals()
 *   GET /api/v1/goals/search                 searchGoals()
 *   GET /api/v1/goals/{id}                    getGoal()
 *   GET /api/v1/goals/{id}/events?since=&limit=  getGoalEvents()
 *   GET /api/v1/oversight/active              getActive()
 *   GET /api/v1/spend                         getSpend()
 *   GET /api/v1/offline/bundle                getOfflineBundle()
 *       requires X-Lightwork-Offline-Policy: 1; otherwise the server returns 403.
 *
 * Typed POSTs handle pairing begin/poll/renewal, enrolled own-task answer/Stop,
 * and the devices/work prepare/execute service for start/approve/reject.
 * devices/work GETs provide context, original outcomes, history and approvals.
 * Writes require online review and confirmation under the device's permissions.
 */

import { connectionValidationError } from "./connectionValidation";
import { nativePlatform, nativeTransportReady, nativeRequest } from './nativeTransport';
import type {GoalOut, GoalEventOut, GoalEventsResponse as DashboardGoalEventsResponse} from "./generated/dashboard-contracts";

export type DeviceInfo = {id: string; generation: number; expires_at: number; enrollment_expires_at: number; principal: string; tenant: string | null; actions: boolean; new_tasks?: boolean; approvals?: boolean};
export type Settings = { baseUrl: string; token: string; cacheScope?: string; needsSetup?: boolean; offlineEnabled?: boolean; pairedDevice?: DeviceInfo };

export type Goal = GoalOut;

export type GoalEvent = GoalEventOut;

// Pagination requires the server's optional-default fields in actual responses;
// truncated is client-side state and is not part of the server schema.
export type GoalEventsResponse = DashboardGoalEventsResponse &
  Required<Pick<DashboardGoalEventsResponse, "has_more" | "terminal">> & {truncated?: boolean};

export type ActiveGoal = {
  id: number;
  title: string;
  status: string;
  updated_at: number;
  activity: string;
};

export type SpendTotal = {
  dollars: number;
  input_tokens: number;
  output_tokens: number;
  runs: number;
};

export type Glance = {
  as_of: number;
  active: { id: number; title: string; status: string; updated_at: number }[];
  counts: { active: number; pending_approvals: number; open_questions: number };
  spend: { dollars: number; runs: number };
};

export type BundleGoal = {
  id: number;
  title: string;
  status: string;
  created_at: number;
  updated_at: number;
  result: string | null;
};

export type OfflinePolicy = {allowed: boolean; max_age_seconds: number; max_bytes: number; revision: string; message?: string};

export type OfflineBundle = {
  cache_policy?: OfflinePolicy;
  schema: string; // "maverick-offline/1"
  as_of: number;
  glance: Glance;
  goals: BundleGoal[];
  recent_events: (GoalEvent & { goal_id: number })[];
};

// Use the same HTTPS/HTTP-loopback policy as connection setup.
export function isTokenTransportSafe(baseUrl: string): boolean {
  return connectionValidationError(baseUrl) === null;
}

// Every message below is shown to people as-is, so it stays plain: no
// addresses, status codes or code names. The status and kind stay on the
// error for program logic.
export const UNSUPPORTED_BUILD = "This version of the app cannot connect safely. Install the latest version of the app, then try again.";
export const NETWORK_TROUBLE = "Could not reach the dashboard. Check that you are on your organization's network or VPN, then try again.";

export function statusMessage(status: number): string {
  if (status === 401) return "The dashboard did not accept your access token. Check it in Settings or ask your administrator for a new one.";
  if (status === 403) return "Your access token does not allow viewing this information. Ask your administrator to check your access.";
  if (status === 404) return "This dashboard does not offer this information yet. Ask your administrator to update the dashboard.";
  if (status === 429) return "The dashboard is busy. Wait a minute, then try again.";
  if (status >= 500) return "The dashboard had a problem answering. Try again in a few minutes.";
  return "The dashboard could not answer this request. Try again, or check your settings.";
}

export class ApiError extends Error {
  constructor(message: string, public status?: number, public kind = "transient") { super(message); }
}

export function isAccessDenied(error: unknown): boolean {
  const status = (error as {status?: number})?.status;
  return status === 401 || status === 403;
}

async function boundedResponseText(res: Response, signal: AbortSignal): Promise<string> {
  const limit = 4 * 1024 * 1024;
  const oversized = () => new ApiError("The dashboard sent more information than this app can show. Open the dashboard on a computer instead.", undefined, "protocol");
  const declared = Number(res.headers?.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) throw oversized();
  if (!res.body?.getReader) {
    throw new ApiError(UNSUPPORTED_BUILD, undefined, "unsupported");
  }
  const reader = res.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  const decoder = new TextDecoder();
  let raw = "", bytes = 0;
  try {
    if (signal.aborted) throw new ApiError("Request cancelled.", undefined, "cancelled");
    while (true) {
      const {done, value} = await reader.read();
      if (signal.aborted) throw new ApiError("Request cancelled.", undefined, "cancelled");
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) { cancel(); throw oversized(); }
      raw += decoder.decode(value, {stream:true});
    }
    return raw + decoder.decode();
  } finally {
    signal.removeEventListener("abort", cancel);
    reader.releaseLock();
  }
}

async function apiRequest<T>(cfg: Settings, path: string, signal?: AbortSignal, body?: object): Promise<T> {
  return (await apiExchange<T>(cfg, path, signal, body)).data;
}

type Exchange<T> = {data: T; header: (name: string) => string | null};
async function apiExchange<T>(cfg: Settings, path: string, signal?: AbortSignal, body?: object): Promise<Exchange<T>> {
  const error = connectionValidationError(cfg.baseUrl, cfg.token);
  if (error) throw new ApiError(error, undefined, "settings");
  // Packaged phones use the native byte-cap/no-redirect bridge. Expo Go and
  // browsers without a streaming reader fail before sending a credential.
  if ((nativePlatform && !nativeTransportReady) || (!nativePlatform &&
      (typeof ReadableStream !== "function" || typeof TextDecoder !== "function" ||
       typeof Response !== "function" || !("body" in Response.prototype)))) {
    throw new ApiError(UNSUPPORTED_BUILD, undefined, "unsupported");
  }
  const base = cfg.baseUrl.trim().replace(/\/+$/, "");
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body) { headers["Content-Type"] = "application/json"; headers.Origin = new URL(base).origin; }
  if (body && cfg.pairedDevice?.tenant) headers["X-Lightwork-Expected-Tenant"] = cfg.pairedDevice.tenant;
  if (path === "/api/v1/offline/bundle") headers["X-Lightwork-Offline-Policy"] = "1";
  if (cfg.token) {
    headers.Authorization = `Bearer ${cfg.token.trim()}`;
  }
  const controller = new AbortController();
  let rejectAbort: (reason?: unknown) => void = () => {};
  const cancelled = new Promise<never>((_, reject) => { rejectAbort = reject; });
  const abort = () => { controller.abort(); rejectAbort(new ApiError("Request cancelled.", undefined, "cancelled")); };
  if (signal?.aborted) abort();
  signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => {
    controller.abort(); rejectAbort(new ApiError("The dashboard took too long to answer. Check your network, then try again."));
  }, 15_000);
  try {
    return await Promise.race([cancelled, (async () => {
      if (signal?.aborted) throw new ApiError("Request cancelled.", undefined, "cancelled");
      const res = await requestTransport(`${base}${path}`, body ? "POST" : "GET", headers,
        body ? JSON.stringify(body) : undefined, controller.signal);
      if (!res.ok) {
        const pairing = path.startsWith('/api/v1/devices/');
        const message = pairing && res.status === 401 ? 'This device connection or pairing request expired or was removed. Start device pairing again.'
          : pairing && res.status === 403 ? 'Device pairing is turned off or this account no longer has access. Check with your administrator.'
          : path.startsWith('/api/v1/devices/work/') && res.status === 409 ? 'Work, limits or access changed. Keep your draft, refresh and review again. An earlier submission must be read back before another intentional request.'
          : path.startsWith('/api/v1/devices/actions/') && res.status === 409 ? 'The task or access changed. Keep your draft, refresh the task and review again.'
          : pairing && res.status === 409 ? 'This device connection changed. Review pairing again.' : statusMessage(res.status);
        throw new ApiError(message, res.status, res.status === 401 || res.status === 403 ? "access" : "transient");
      }
      const raw = await res.read();
      if (controller.signal.aborted) throw new ApiError("Request cancelled.", undefined, "cancelled");
      let data: T;
      try {
        data = JSON.parse(raw) as T;
      } catch {
        throw new ApiError("The dashboard sent a reply this app could not read. Ask your administrator to check the dashboard address.", undefined, "protocol");
      }
      return {data, header: res.header};
    })()]);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

async function requestTransport(url: string, method: string, headers: Record<string, string>, body: string | undefined, signal: AbortSignal) {
  if (nativePlatform) {
    const response = await nativeRequest(url, method, headers, body, signal);
    // The bridges hand over only the response headers the client reads.
    const received = response.headers && typeof response.headers === 'object' ? response.headers : {};
    return {status: response.status, ok: response.status >= 200 && response.status < 300,
      read: async () => response.body,
      header: (name: string) => {
        const value = received[name.toLowerCase()];
        return typeof value === 'string' ? value : null;
      }};
  }
  const response = await fetch(url, {method, headers, body, signal, redirect: 'error', credentials: 'omit'});
  return {status: response.status, ok: response.ok, read: () => boundedResponseText(response, signal),
    header: (name: string) => response.headers?.get?.(name) ?? null};
}

function apiGet<T>(cfg: Settings, path: string, signal?: AbortSignal): Promise<T> {
  return apiRequest<T>(cfg, path, signal);
}

export type PairingRequest = {pairing_token: string; code: string; expires_at: number; interval: number};
export type PairingResult = {status: "pending" | "approved"; token?: string; device?: DeviceInfo};
export function beginPairing(baseUrl: string, label: string, signal?: AbortSignal): Promise<PairingRequest> {
  return apiRequest({baseUrl, token: ''}, '/api/v1/devices/pairing/begin', signal, {label});
}
export function pollPairing(baseUrl: string, pairingToken: string, signal?: AbortSignal): Promise<PairingResult> {
  return apiRequest({baseUrl, token: pairingToken}, '/api/v1/devices/pairing/poll', signal, {});
}
export function renewPairing(cfg: Settings, generation: number, signal?: AbortSignal): Promise<{token: string; device: DeviceInfo}> {
  return apiRequest(cfg, '/api/v1/devices/renew', signal, {generation});
}

export type DeviceActionContext = {context: string; title: string; status: string; checked_at: number;
  answer: {revision: string; blocked: string; partial: boolean; questions: {id: number; question: string}[]};
  stop: {revision: string; blocked: string; summary: string}};
export type DeviceActionReview = {token: string; expires_at: number; summary: string; action: 'answer' | 'stop'; operation_id: string;
  changes: {label?: string; field?: string; before?: unknown; after?: unknown}[]};
export type DeviceActionOutcome = {status: 'confirmed' | 'replayed' | 'queued' | 'unconfirmed'; message: string; operation_id: string};
export function deviceActionContext(cfg: Settings, goalId: number, signal?: AbortSignal): Promise<DeviceActionContext> {
  return apiGet(cfg, '/api/v1/devices/actions/context?goal_id=' + goalId, signal);
}
export function prepareDeviceAction(cfg: Settings, body: {goal_id: number; action: 'answer' | 'stop'; context: string; revision: string; arguments: object}, signal?: AbortSignal): Promise<DeviceActionReview> {
  return apiRequest(cfg, '/api/v1/devices/actions/prepare', signal, body);
}
export function executeDeviceAction(cfg: Settings, token: string, signal?: AbortSignal): Promise<DeviceActionOutcome> {
  return apiRequest(cfg, '/api/v1/devices/actions/execute', signal, {token, confirmed: true});
}

/* /api/v1/goals pages by the rows it scans, then leaves out any the reader may
 * no longer open (a copied conversation whose source access ended). A page
 * shorter than the limit is therefore not the end: Pagination-Has-More says
 * whether more remain and Pagination-Next-Before-Id where to continue. Each is
 * null when the dashboard did not send a readable value. */
export type GoalPage = {goals: Goal[]; hasMore: boolean | null; nextBeforeId: number | null};
export async function listGoals(cfg: Settings, limit = 50, signal?: AbortSignal, offset = 0, status = "", beforeId?: number): Promise<GoalPage> {
  const reply = await apiExchange<Goal[]>(cfg, `/api/v1/goals?limit=${limit}&offset=${offset}&status=${encodeURIComponent(status)}${beforeId == null ? '' : `&before_id=${beforeId}`}`, signal);
  const more = reply.header("Pagination-Has-More"), next = reply.header("Pagination-Next-Before-Id");
  const nextBeforeId = next !== null && /^[1-9][0-9]{0,15}$/.test(next) && Number.isSafeInteger(Number(next)) ? Number(next) : null;
  return {goals: reply.data, hasMore: more === "true" ? true : more === "false" ? false : null, nextBeforeId};
}

export function searchGoals(cfg: Settings, query: string, signal?: AbortSignal): Promise<Goal[]> {
  return apiGet<Goal[]>(cfg, `/api/v1/goals/search?q=${encodeURIComponent(query)}&limit=200`, signal);
}

export function getGoal(cfg: Settings, id: number, signal?: AbortSignal): Promise<Goal> {
  return apiGet<Goal>(cfg, `/api/v1/goals/${id}`, signal);
}

export function getGoalEvents(
  cfg: Settings, id: number, since = 0, limit = 200, signal?: AbortSignal,
): Promise<GoalEventsResponse> {
  return apiGet<GoalEventsResponse>(
    cfg, `/api/v1/goals/${id}/events?since=${since}&limit=${limit}`, signal,
  );
}

export function getActive(cfg: Settings, signal?: AbortSignal): Promise<{ goals: ActiveGoal[] }> {
  return apiGet<{ goals: ActiveGoal[] }>(cfg, "/api/v1/oversight/active", signal);
}

export function getSpend(cfg: Settings, signal?: AbortSignal): Promise<{ total: SpendTotal }> {
  return apiGet<{ total: SpendTotal }>(cfg, "/api/v1/spend", signal);
}

export function getOfflineBundle(cfg: Settings, signal?: AbortSignal): Promise<OfflineBundle> {
  return apiGet<OfflineBundle>(cfg, "/api/v1/offline/bundle", signal);
}
export type WorkAction = 'start' | 'approve' | 'reject';
export type WorkField = {name: string; label: string; kind: string; required?: boolean; max_length?: number; value?: unknown; choices?: {value: unknown; label: string}[]};
export type WorkContext = {context: string; revision: string; blocked: string; summary: string; fields: WorkField[]; current_details?: {label: string; value: string}[]; checked_at: number};
export type WorkReview = {token: string; operation_id: string; action: WorkAction; expires_at: number; summary: string; changes: {label?: string; field?: string; before?: unknown; after?: unknown}[]};
export type WorkOutcome = {status: 'confirmed' | 'replayed' | 'queued' | 'unconfirmed'; message: string; operation_id: string; details: Record<string, unknown>};
export type WorkHistory = {items: {operation: string; action: WorkAction; label: string; at: number}[]; complete: boolean; notice: string};
export type OwnedApprovals = {items: {id: number; task_title: string; action: string}[]; before_id: number; complete: boolean; notice: string};
export function workContext(cfg: Settings, action: WorkAction, approvalId = 0, signal?: AbortSignal): Promise<WorkContext> {
  return apiGet(cfg, `/api/v1/devices/work/context?action=${action}&approval_id=${approvalId}`, signal);
}
export function prepareWork(cfg: Settings, action: WorkAction, current: WorkContext, args: object, approvalId = 0, signal?: AbortSignal): Promise<WorkReview> {
  return apiRequest(cfg, '/api/v1/devices/work/prepare', signal, {action, approval_id: approvalId, context: current.context, revision: current.revision, arguments: args});
}
export function executeWork(cfg: Settings, review: WorkReview, signal?: AbortSignal): Promise<WorkOutcome> {
  return apiRequest(cfg, '/api/v1/devices/work/execute', signal, {token: review.token, confirmed: true});
}
export function readWorkOriginal(cfg: Settings, operation: string, signal?: AbortSignal): Promise<WorkOutcome> {
  return apiGet(cfg, '/api/v1/devices/work/original?operation=' + encodeURIComponent(operation), signal);
}
export function workHistory(cfg: Settings, signal?: AbortSignal): Promise<WorkHistory> {
  return apiGet(cfg, '/api/v1/devices/work/history', signal);
}
export function ownedApprovals(cfg: Settings, beforeId = 0, signal?: AbortSignal): Promise<OwnedApprovals> {
  return apiGet(cfg, '/api/v1/devices/work/approvals?before_id=' + beforeId, signal);
}
