/* Offline cache for the maverick-offline/1 bundle.
 *
 * The app saves the last successfully fetched bundle to AsyncStorage with a
 * timestamp; when the dashboard is unreachable, screens render the cached
 * bundle behind an "as of N min ago — offline" banner instead of a blank
 * error. The bundle is built server-side by maverick.offline_bundle (bounded,
 * versioned, no credentials). Task content can still be sensitive: people may
 * disable persistence, and saved content expires after 24 hours.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { useCallback, useEffect, useState } from "react";

import { getOfflineBundle, type OfflineBundle, type Settings } from "./api";
import { usePolling } from "./poll";
import { agoText } from "./format";

const CACHE_KEY_PREFIX = "maverick.offlineBundle.v2.";
let cacheGeneration = 0;
let purgingAll = false;
const knownScopes = new Set<string>();
const retiredScopes = new Set<string>();
const cacheEpochs = new Map<string, number>();
const clearing = new Set<string>();
const mutations = new Map<string, Promise<void>>();
const listeners = new Set<(key: string | null) => void>();
const MAX_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_BYTES = 2 * 1024 * 1024;
const SCHEMA = "maverick-offline/1";

export type CachedBundle = { savedAt: number; bundle: OfflineBundle; expiresAt?: number };

function policyFor(bundle: OfflineBundle): {age: number; bytes: number} | null {
  const policy = bundle.cache_policy;
  if (!policy || policy.allowed !== true || !/^[a-f0-9]{64}$/.test(policy.revision)
      || !Number.isInteger(policy.max_age_seconds) || policy.max_age_seconds <= 0
      || !Number.isInteger(policy.max_bytes) || policy.max_bytes <= 0) return null;
  return {age: Math.min(MAX_AGE_MS, policy.max_age_seconds * 1000), bytes: Math.min(MAX_BYTES, policy.max_bytes)};
}

function changed(key: string | null): void { listeners.forEach(listener => listener(key)); }

function ordered<T>(key: string, job: () => Promise<T>): Promise<T> {
  const next = (mutations.get(key) || Promise.resolve()).then(job, job);
  const tail = next.then(() => {}, () => {});
  mutations.set(key, tail);
  void tail.then(() => { if (mutations.get(key) === tail) { mutations.delete(key); changed(key); } });
  return next;
}

// Invalidate in-memory readers immediately; serialize physical removal after
// admitted writes so an old completion cannot delete or replace a newer copy.
export async function clearBundle(scope?: string): Promise<void> {
  const key = cacheKey(scope);
  if (!key) return;
  const epoch = (cacheEpochs.get(key) || 0) + 1;
  cacheEpochs.set(key, epoch);
  clearing.add(key);
  changed(key);
  await ordered(key, async () => { await AsyncStorage.removeItem(key); });
  if (epoch === cacheEpochs.get(key)) clearing.delete(key);
  changed(key);
}

// This opaque scope is committed with the connection in SecureStore and rotates
// on every save, including token changes on the same host. Neither a bearer
// token nor a token-derived key is written to AsyncStorage. Legacy URL-only
// caches cannot establish credential identity and are deliberately not read.
function cacheKey(scope?: string): string | null {
  if (!scope || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(scope)) return null;
  const key = CACHE_KEY_PREFIX + scope;
  knownScopes.add(key);
  return key;
}

export async function saveBundle(bundle: OfflineBundle, baseUrl: string, scope?: string): Promise<boolean> {
  if (bundle.schema !== SCHEMA) { await clearBundle(scope); return false; }
  const key = cacheKey(scope);
  if (!key || retiredScopes.has(key) || purgingAll) return false;
  const policy = policyFor(bundle);
  if (!policy) { await clearBundle(scope); return false; }
  const generation = cacheGeneration;
  const epoch = (cacheEpochs.get(key) || 0) + 1;
  cacheEpochs.set(key, epoch);
  const savedAt = Date.now();
  if (!Number.isFinite(bundle.as_of)) { await clearBundle(scope); return false; }
  const expiresAt = Math.min(savedAt + policy.age, bundle.as_of * 1000 + policy.age);
  if (expiresAt <= savedAt) { await clearBundle(scope); return false; }
  const entry: CachedBundle = { savedAt, expiresAt, bundle };
  const serialized = JSON.stringify({ ...entry, baseUrl });
  if (serialized.length * 2 > policy.bytes) { await clearBundle(scope); return false; }
  const saving = ordered(key, async () => {
    if (retiredScopes.has(key) || generation !== cacheGeneration || epoch !== (cacheEpochs.get(key) || 0)) return false;
    await AsyncStorage.setItem(key, serialized);
    if (retiredScopes.has(key) || generation !== cacheGeneration || epoch !== (cacheEpochs.get(key) || 0)) {
      await AsyncStorage.removeItem(key); return false;
    }
    clearing.delete(key);
    return true;
  });
  changed(key);
  return saving;
}

export async function loadBundle(baseUrl: string, scope?: string): Promise<CachedBundle | null> {
  const key = cacheKey(scope);
  if (!key || retiredScopes.has(key) || purgingAll || clearing.has(key) || mutations.has(key)) return null;
  const epoch = cacheEpochs.get(key) || 0, generation = cacheGeneration;
  try {
    const raw = await AsyncStorage.getItem(key);
    if (retiredScopes.has(key) || clearing.has(key) || mutations.has(key)
        || epoch !== (cacheEpochs.get(key) || 0) || generation !== cacheGeneration) return null;
    if (!raw) return null;
    if (raw.length * 2 > MAX_BYTES) { await clearBundle(scope); return null; }
    const entry = JSON.parse(raw) as CachedBundle & { baseUrl?: string };
    if (!entry?.bundle || entry.bundle.schema !== SCHEMA || entry.baseUrl !== baseUrl) { await clearBundle(scope); return null; }
    const policy = policyFor(entry.bundle);
    const expiresAt = policy ? Math.min(entry.savedAt + policy.age, entry.bundle.as_of * 1000 + policy.age) : 0;
    if (!policy || raw.length * 2 > policy.bytes || !Number.isFinite(entry.savedAt) || !Number.isFinite(expiresAt)
        || expiresAt <= Date.now() || entry.savedAt > Date.now()) { await clearBundle(scope); return null; }
    if (retiredScopes.has(key) || epoch !== (cacheEpochs.get(key) || 0) || generation !== cacheGeneration) return null;
    return {...entry, expiresAt};
  } catch {
    try { await clearBundle(scope); } catch { /* Keep unavailable storage fail-closed. */ }
    return null; // corrupt cache reads as "no cache"
  }
}

export function useCachedBundle(settings: Settings, enabled: boolean): CachedBundle | null {
  const [cached, setCached] = useState<{ settings: Settings; entry: CachedBundle | null } | null>(null);
  useEffect(() => {
    let current = true;
    let expiration: ReturnType<typeof setTimeout> | undefined;
    setCached(null);
    function load() {
      clearTimeout(expiration);
      setCached(null);
      if (!enabled || settings.offlineEnabled === false) return;
      loadBundle(settings.baseUrl, settings.cacheScope).then(entry => {
        if (current) {
          setCached({ settings, entry });
          if (entry?.expiresAt) expiration = setTimeout(() => { setCached(null); void clearBundle(settings.cacheScope); }, Math.max(1, entry.expiresAt - Date.now()));
        }
      });
    }
    const listener = (key: string | null) => { if (key === null || key === cacheKey(settings.cacheScope)) load(); };
    listeners.add(listener); load();
    return () => { current = false; listeners.delete(listener); clearTimeout(expiration); };
  }, [enabled, settings.baseUrl, settings.token, settings.cacheScope, settings.offlineEnabled]);
  return enabled && cached?.settings.baseUrl === settings.baseUrl
    && cached.settings.token === settings.token && cached.settings.cacheScope === settings.cacheScope
    && (cached.entry?.expiresAt || 0) > Date.now()
    ? cached.entry : null;
}

export function ageMinutes(entry: CachedBundle, now: number = Date.now()): number {
  return Math.max(0, Math.round((now - entry.savedAt) / 60000));
}

export function offlineBanner(entry: CachedBundle): string {
  return `You're offline. Showing what was saved ${agoText(ageMinutes(entry))}.`;
}

export async function purgeBundle(scope?: string): Promise<void> {
  const key = cacheKey(scope);
  if (key) { retiredScopes.add(key); await clearBundle(scope); }
}

export async function purgeAppBundles(): Promise<void> {
  purgingAll = true;
  cacheGeneration += 1;
  for (const key of knownScopes) retiredScopes.add(key);
  for (const key of mutations.keys()) retiredScopes.add(key);
  changed(null);
  await Promise.all(Array.from(mutations.values()));
  const keys = await AsyncStorage.getAllKeys();
  const owned = keys.filter(key => key.startsWith('maverick.offlineBundle.'));
  for (const key of owned) retiredScopes.add(key);
  if (owned.length) await AsyncStorage.multiRemove(owned);
  purgingAll = false;
  changed(null);
}

// Owned by the connection, so opening Tasks first also prepares offline data.
export function useConnectionCache(settings: Settings | null) {
  cacheKey(settings?.cacheScope); // Register the active identity before a first network response.
  const fetcher = useCallback((signal: AbortSignal) => settings && !settings.needsSetup
    ? getOfflineBundle(settings, signal) : Promise.resolve(null), [settings]);
  const state = usePolling<OfflineBundle | null>(fetcher, 60_000);
  const [saved, setSaved] = useState<{scope?: string; at: number} | null>(null);
  useEffect(() => {
    let current = true;
    if (!settings) return;
    if (state.accessDenied || state.unsupported || settings.offlineEnabled === false) {
      setSaved(null); void purgeBundle(settings.cacheScope);
    } else if (state.data) {
      void saveBundle(state.data, settings.baseUrl, settings.cacheScope).then(saved => {
        if (!saved) { if (current) setSaved(null); return; }
        if (current && settings.cacheScope) setSaved({scope: settings.cacheScope, at: Date.now()});
      }, () => { if (current) setSaved(null); });
    }
    return () => { current = false; };
  }, [state.data, state.accessDenied, state.unsupported, settings]);
  const policyMessage = state.data && !policyFor(state.data)
    ? state.data.cache_policy?.message || 'Offline saving is unavailable until this dashboard provides an organization retention policy.' : null;
  return {...state, policyMessage, savedAt: saved?.scope === settings?.cacheScope ? saved?.at : null};
}
