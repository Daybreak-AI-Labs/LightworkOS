/* Dashboard connection settings, stored in the device keychain via
 * expo-secure-store (the token never touches AsyncStorage or logs). */
import * as SecureStore from "expo-secure-store";

import type { Settings } from "./api";
import { purgeBundle, purgeAppBundles } from "./offlineCache";
import { connectionValidationError } from "./connectionValidation";

const BASE_URL_KEY = "maverick.baseUrl";
const TOKEN_KEY = "maverick.token";
const CONNECTION_KEY = "maverick.connection.v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function newCacheScope(): string | undefined {
  // Expo SDK 52's core UUID helper uses this native binding. Browser builds
  // can use Web Crypto. Without either, keep connection settings usable but
  // disable offline persistence instead of inventing a weak credential key.
  const runtime = globalThis as typeof globalThis & {
    expo?: { uuidv4?: () => string };
    crypto?: { randomUUID?: () => string };
  };
  try {
    const scope = runtime.expo?.uuidv4?.() ?? runtime.crypto?.randomUUID?.();
    return typeof scope === "string" && UUID.test(scope) ? scope : undefined;
  } catch {
    return undefined;
  }
}

// Serialize this app's reads and writes, including across Settings remounts.
// A rejected keychain operation must not prevent a later retry from running.
let pending: Promise<void> = Promise.resolve();
function inOrder<T>(operation: () => Promise<T>): Promise<T> {
  const result = pending.then(operation);
  pending = result.then(() => undefined, () => undefined);
  return result;
}

export const DEFAULT_BASE_URL = "http://127.0.0.1:8765";

export class InvalidSavedConnection extends Error {}

export function resetSettings(): Promise<void> {
  return inOrder(async () => {
    // A failed/locked read refuses reset; only an explicit confirmation reaches
    // this path and only this app's named records are removed.
    await SecureStore.getItemAsync(CONNECTION_KEY);
    await SecureStore.getItemAsync(PROFILES_KEY);
    await SecureStore.deleteItemAsync(PROFILES_KEY);
    await SecureStore.deleteItemAsync(CONNECTION_KEY);
    await SecureStore.deleteItemAsync(BASE_URL_KEY);
    await SecureStore.deleteItemAsync(TOKEN_KEY);
    await purgeAppBundles();
  });
}

export function loadSettings(): Promise<Settings> {
  return inOrder(async () => {
    const profilesRaw = await SecureStore.getItemAsync(PROFILES_KEY);
    if (profilesRaw !== null) {
      const store = parseProfiles(profilesRaw);
      const selected = store.profiles.find(profile => profile.id === store.active);
      return selected ? {...selected} : {baseUrl: DEFAULT_BASE_URL, token: '', needsSetup: true};
    }
    const record = await SecureStore.getItemAsync(CONNECTION_KEY);
    if (record !== null) {
      let value: unknown;
      try {
        value = JSON.parse(record);
      } catch {
        throw new InvalidSavedConnection("Saved connection settings are invalid. Reset this app’s saved connection to set it up again.");
      }
      if (typeof value !== "object" || value === null
          || !("baseUrl" in value) || typeof value.baseUrl !== "string"
          || !("token" in value) || typeof value.token !== "string") {
        throw new InvalidSavedConnection("Saved connection settings are invalid. Reset this app’s saved connection to set it up again.");
      }
      const cacheScope = "cacheScope" in value && typeof value.cacheScope === "string"
        && UUID.test(value.cacheScope) ? value.cacheScope : undefined;
      return { baseUrl: value.baseUrl, token: value.token, cacheScope, offlineEnabled: !("offlineEnabled" in value) || value.offlineEnabled !== false,
        pairedDevice: "pairedDevice" in value ? value.pairedDevice as Settings['pairedDevice'] : undefined };
    }
    // Legacy installs are read without a migration write. The next successful
    // save creates the atomic record; failure leaves the old pair untouched.
    const savedUrl = await SecureStore.getItemAsync(BASE_URL_KEY);
    const savedToken = await SecureStore.getItemAsync(TOKEN_KEY);
    const baseUrl = savedUrl ?? DEFAULT_BASE_URL;
    const token = savedToken ?? "";
    // Nothing saved at all: the app shows its first-run connection setup.
    if (savedUrl === null && savedToken === null) return { baseUrl, token, needsSetup: true };
    return { baseUrl, token };
  });
}

export function saveSettings(s: Settings): Promise<void> {
  // One keychain write commits the URL and bearer token together. Never leave
  // a new dashboard URL paired with credentials from the previous dashboard.
  const connection = { baseUrl: s.baseUrl.trim(), token: s.token.trim() };
  return inOrder(async () => {
    const error = connectionValidationError(connection.baseUrl, connection.token);
    if (error) throw new Error(error);
    const previous = await SecureStore.getItemAsync(CONNECTION_KEY);
    let oldScope: string | undefined;
    try { oldScope = previous ? JSON.parse(previous).cacheScope : undefined; } catch { /* invalid record is replaced only by explicit save */ }
    await purgeBundle(oldScope);
    await SecureStore.setItemAsync(CONNECTION_KEY, JSON.stringify({
      ...connection,
      cacheScope: newCacheScope(),
      offlineEnabled: s.offlineEnabled !== false,
      pairedDevice: s.pairedDevice,
    }));
  });
}


export type ConnectionProfile = {id: string; name: string};
const PROFILES_KEY = "maverick.profiles.v1";
type StoredProfile = Settings & ConnectionProfile;
type ProfileStore = {active: string; profiles: StoredProfile[]};

function parseProfiles(raw: string | null): ProfileStore {
  if (!raw) return {active: '', profiles: []};
  let value: ProfileStore;
  try { value = JSON.parse(raw); } catch { throw new InvalidSavedConnection('Saved connection profiles are invalid. Reset saved connections to recover.'); }
  if (!value || !Array.isArray(value.profiles) || typeof value.active !== 'string'
      || value.profiles.some(profile => !profile || typeof profile.id !== 'string' || typeof profile.name !== 'string'
        || typeof profile.baseUrl !== 'string' || typeof profile.token !== 'string')) {
    throw new InvalidSavedConnection('Saved connection profiles are invalid. Reset saved connections to recover.');
  }
  return value;
}

export function listProfiles(): Promise<{active: string; profiles: ConnectionProfile[]}> {
  return inOrder(async () => {
    const store = parseProfiles(await SecureStore.getItemAsync(PROFILES_KEY));
    return {active: store.active, profiles: store.profiles.map(({id, name}) => ({id, name}))};
  });
}

export function saveProfile(name: string, settings: Settings, existingId?: string): Promise<void> {
  return inOrder(async () => {
    const title = name.trim();
    if (!title || title.length > 80) throw new Error('Enter a connection name of up to 80 characters.');
    const error = connectionValidationError(settings.baseUrl, settings.token);
    if (error) throw new Error(error);
    const profilesRaw = await SecureStore.getItemAsync(PROFILES_KEY);
    const store = parseProfiles(profilesRaw);
    // Only the first profile of an older install imports the older record. Once the
    // list exists, removing a connection must stay final.
    if (profilesRaw === null) {
      const raw = await SecureStore.getItemAsync(CONNECTION_KEY);
      if (raw) {
        let legacy: Settings;
        try { legacy = JSON.parse(raw); } catch { throw new InvalidSavedConnection('The previous saved connection is unreadable. Reset it before creating profiles.'); }
        if (!legacy || typeof legacy.baseUrl !== 'string' || typeof legacy.token !== 'string') throw new InvalidSavedConnection('The previous saved connection is invalid.');
        if (legacy.baseUrl !== settings.baseUrl || legacy.token !== settings.token) {
          const legacyId = newCacheScope();
          if (!legacyId) throw new Error('Secure device identity is unavailable.');
          store.profiles.push({...legacy, id: legacyId, name: 'Previous connection'});
        }
      }
    }
    const old = store.profiles.find(profile => profile.id === existingId);
    if (!existingId && store.profiles.length >= 20) throw new Error("Remove an unused connection before adding another. Up to 20 are supported.");
    const id = existingId || newCacheScope();
    if (!id) throw new Error('Secure device identity is unavailable. Update the app to save named profiles.');
    const profile: StoredProfile = {...settings, id, name: title, cacheScope: newCacheScope()};
    const profiles = [...store.profiles.filter(entry => entry.id !== id), profile];
    // Active profile and credentials are committed together in this one secure
    // record. The legacy single-connection record remains unchanged until reset.
    await purgeBundle(old?.cacheScope);
    const previousActive = store.profiles.find(entry => entry.id === store.active);
    if (previousActive?.id !== id) await purgeBundle(previousActive?.cacheScope);
    await SecureStore.setItemAsync(PROFILES_KEY, JSON.stringify({active: id, profiles}));
  });
}

export function activateProfile(id: string): Promise<void> {
  return inOrder(async () => {
    const store = parseProfiles(await SecureStore.getItemAsync(PROFILES_KEY));
    const next = store.profiles.find(profile => profile.id === id);
    if (!next) throw new Error('This saved connection is no longer available.');
    const previous = store.profiles.find(profile => profile.id === store.active);
    const cacheScope = newCacheScope();
    const profiles = store.profiles.map(profile => profile.id === id ? {...profile, cacheScope} : profile);
    await purgeBundle(previous?.cacheScope);
    await purgeBundle(next.cacheScope);
    await SecureStore.setItemAsync(PROFILES_KEY, JSON.stringify({active: id, profiles}));
  });
}

export function removeProfile(id: string): Promise<void> {
  return inOrder(async () => {
    const store = parseProfiles(await SecureStore.getItemAsync(PROFILES_KEY));
    const removed = store.profiles.find(profile => profile.id === id);
    const profiles = store.profiles.filter(profile => profile.id !== id);
    const active = store.active === id ? '' : store.active;
    await purgeBundle(removed?.cacheScope);
    if (removed) {
      // The imported copy of an older single-connection record goes with its profile, or its token would stay on the device.
      const raw = await SecureStore.getItemAsync(CONNECTION_KEY);
      let older: Partial<Settings> | null = null;
      try { older = raw ? JSON.parse(raw) : null; } catch { /* an unreadable record is left for an explicit reset */ }
      if (older && older.baseUrl === removed.baseUrl && older.token === removed.token) await SecureStore.deleteItemAsync(CONNECTION_KEY);
    }
    await SecureStore.setItemAsync(PROFILES_KEY, JSON.stringify({active, profiles}));
  });
}
