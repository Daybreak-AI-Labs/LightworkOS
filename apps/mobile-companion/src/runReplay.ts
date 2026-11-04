import { ApiError, GoalEventsResponse, Settings, getGoalEvents } from "./api";

// Shown to people when the activity feed is not in a shape this app trusts.
export const UNREADABLE = "The dashboard sent task activity this app could not read. Update the app, or open the task on the dashboard.";

export function createRunReplay(settings: Settings, runId: number) {
  let state: GoalEventsResponse = {events: [], next_id: 0, status: "loading", result: null, has_more: false, terminal: false};
  let generation = 0;
  return {
    async poll(signal: AbortSignal): Promise<GoalEventsResponse> {
      const ticket = ++generation;
      for (let page = 0; page < 10; page++) {
        const data = await getGoalEvents(settings, runId, state.next_id, 200, signal);
        if (signal.aborted || ticket !== generation) throw new ApiError("Obsolete replay.", undefined, "cancelled");
        if (!Array.isArray(data.events) || data.events.length > 200 ||
            !Number.isSafeInteger(data.next_id) || data.next_id < state.next_id ||
            typeof data.has_more !== "boolean" || typeof data.terminal !== "boolean") {
          throw new ApiError(UNREADABLE, undefined, "protocol");
        }
        let cursor = state.next_id;
        for (const event of data.events) {
          if (!Number.isSafeInteger(event.id) || event.id <= cursor || event.id > data.next_id) {
            throw new ApiError(UNREADABLE, undefined, "protocol");
          }
          cursor = event.id;
        }
        if (cursor !== data.next_id || (data.has_more && cursor === state.next_id)) {
          throw new ApiError(UNREADABLE, undefined, "protocol");
        }
        const added = data.events.map(event => ({...event, content: String(event.content || "").slice(0, 16000)}));
        const events = [...state.events, ...added];
        let size = events.reduce((total, event) => total + event.content.length, 0);
        let truncated = state.truncated || String(data.result || "").length > 16000 ||
          data.events.some(event => String(event.content || "").length > 16000);
        while (events.length > 1000 || size > 1000000) { size -= events.shift()!.content.length; truncated = true; }
        state = {...data, events, truncated, terminal: data.terminal && !data.has_more,
          result: data.terminal && !data.has_more ? String(data.result || "").slice(0, 16000) : null};
        if (!data.has_more) break;
      }
      return state;
    },
  };
}

// A connection object's identity changes on settings/credential changes. Keep
// only eight bounded watches for navigation within that connection; no bearer
// or replay data is copied into device storage.
const watches = new WeakMap<Settings, Map<number, ReturnType<typeof createRunReplay>>>();
export function runReplay(settings: Settings, runId: number) {
  let runs = watches.get(settings);
  if (!runs) { runs = new Map(); watches.set(settings, runs); }
  if (!runs.has(runId)) {
    if (runs.size >= 8) runs.delete(runs.keys().next().value!);
    runs.set(runId, createRunReplay(settings, runId));
  }
  return runs.get(runId)!;
}
