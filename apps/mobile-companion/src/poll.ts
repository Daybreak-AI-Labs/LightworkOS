/* Simple polling hook: fetch now, then every `intervalMs`.
 *
 * Deliberately not SSE/websockets — plain polling is dependency-light,
 * battery-predictable, and matches the dashboard's own goal-events polling
 * model. The fetcher's failures are surfaced, not swallowed, so screens can
 * fall back to the offline cache. */
import { useCallback, useEffect, useRef, useState } from "react";
import { AppState } from "react-native";
import { NETWORK_TROUBLE, isAccessDenied } from "./api";

export type Polled<T> = {
  data: T | null;
  error: string | null;
  accessDenied: boolean;
  unsupported: boolean;
  refresh: () => void;
  updatedAt: number | null;
};

export function usePolling<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  intervalMs: number,
  continuePolling: (data: T) => boolean = keepPolling,
): Polled<T> {
  const [snapshot, setSnapshot] = useState<{
    fetcher: (signal: AbortSignal) => Promise<T>;
    data: T | null;
    error: string | null;
    accessDenied: boolean;
    unsupported: boolean;
    updatedAt: number | null;
  }>({ fetcher, data: null, error: null, accessDenied: false, unsupported: false, updatedAt: null });
  const refreshCurrent = useRef<() => void>(() => {});
  const refresh = useCallback(() => refreshCurrent.current(), []);

  useEffect(() => {
    // The flag belongs to this fetcher generation, so a later effect cannot
    // revive callbacks from the previous dashboard or from before unmount.
    let current = true;
    let latestRequest = 0;
    let pending = false;
    let stopped = false;
    let activeController: AbortController | null = null;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    setSnapshot({ fetcher, data: null, error: null, accessDenied: false, unsupported: false, updatedAt: null });
    const tick = () => {
      if (!current || AppState.currentState === "background" || AppState.currentState === "inactive") return;
      const request = ++latestRequest;
      activeController?.abort();
      clearTimeout(deadline);
      const controller = new AbortController();
      activeController = controller;
      pending = true;
      const timeout = new Promise<never>((_, reject) => {
        deadline = setTimeout(() => { controller.abort(); reject(new Error("The dashboard took too long to answer. Check your network, then try again.")); }, 20_000);
      });
      Promise.race([timeout, Promise.resolve().then(() => fetcher(controller.signal))]).then(
        (data) => {
          if (!current || request !== latestRequest) return;
          stopped = !continuePolling(data);
          setSnapshot({ fetcher, data, error: null, accessDenied: false, unsupported: false, updatedAt: Date.now() });
        },
        (e: unknown) => {
          if (!current || request !== latestRequest) return;
          const denied = isAccessDenied(e);
          const unsupported = (e as {kind?: string})?.kind === "unsupported";
          stopped = denied || unsupported;
          setSnapshot(previous => ({
            fetcher,
            data: !denied && !unsupported && previous.fetcher === fetcher ? previous.data : null,
            error: plainError(e),
            accessDenied: denied,
            unsupported,
            updatedAt: !denied && !unsupported ? previous.updatedAt : null,
          }));
        },
      ).finally(() => {
        if (request === latestRequest) { pending = false; clearTimeout(deadline); activeController = null; }
      });
    };
    const lifecycle = AppState.addEventListener('change', state => {
      if (state === 'active') { tick(); }
      else {
        latestRequest += 1; activeController?.abort(); activeController = null;
        clearTimeout(deadline); pending = false;
      }
    });
    refreshCurrent.current = tick;
    tick();
    // Slow automatic polls must be allowed to finish instead of being made
    // obsolete on every interval. Explicit refresh may still supersede one.
    const id = setInterval(() => { if (!pending && !stopped) tick(); }, intervalMs);
    return () => {
      current = false; lifecycle.remove();
      refreshCurrent.current = () => {};
      clearInterval(id);
      clearTimeout(deadline);
      activeController?.abort();
    };
  }, [fetcher, intervalMs, continuePolling]);

  // Hide the previous identity's data even in the render before effect cleanup.
  const matches = snapshot.fetcher === fetcher;
  return {
    data: matches ? snapshot.data : null,
    error: matches ? snapshot.error : null,
    accessDenied: matches ? snapshot.accessDenied : false,
    unsupported: matches ? snapshot.unsupported : false,
    refresh,
    updatedAt: matches ? snapshot.updatedAt : null,
  };
}

// Messages from this app's own client are written for people. Anything else
// (a raw network failure from the platform) gets one plain sentence.
function plainError(e: unknown): string {
  if (e instanceof Error && typeof (e as {kind?: unknown}).kind === "string" && e.message) return e.message;
  if (e instanceof Error && e.message.startsWith("The dashboard took too long")) return e.message;
  return NETWORK_TROUBLE;
}

function keepPolling<T>(_data: T): boolean { return true; }
