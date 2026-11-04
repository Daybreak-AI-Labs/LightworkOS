import { useEffect, useState } from "react";
import { useColorScheme } from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";
/* One set of colors and text styles for every screen. */
export const theme = {
  background: "#ffffff",
  onAccent: "#ffffff",
  result: "#ddf4ff",
  text: "#1f2328",
  muted: "#57606a",
  border: "#d0d7de",
  accent: "#0969da",
  success: "#1a7f37",
  danger: "#cf222e",
  dangerBg: "#ffebe9",
  warnBg: "#fff8c5",
  warnText: "#4d2d00",
  surface: "#f6f8fa",
};

export type Palette = typeof theme;
const dark: Palette = {
  background: '#111820', onAccent: '#111820', result: '#17334a',
  text: '#f0f4f8', muted: '#b7c5d3', border: '#657789', accent: '#8cc8ff',
  success: '#79dda0', danger: '#ff9b9b', dangerBg: '#3a1922',
  warnBg: '#382d0f', warnText: '#ffe49c', surface: '#202b37',
};
export type AppearanceChoice = 'system' | 'light' | 'dark';
const APPEARANCE_KEY = 'maverick.display.appearance.v1';
let appearance: AppearanceChoice = 'system', appearanceError = '', loaded = false;
let loading: Promise<void> | null = null, writing: Promise<void> = Promise.resolve();
const listeners = new Set<() => void>();
function changed(): void { listeners.forEach(listener => listener()); }
function choice(value: unknown): value is AppearanceChoice { return value === 'system' || value === 'light' || value === 'dark'; }
function loadAppearance(): Promise<void> {
  if (loaded) return Promise.resolve();
  if (!loading) loading = AsyncStorage.getItem(APPEARANCE_KEY).then(value => {
    if (value !== null && !choice(value)) throw new Error('Invalid appearance');
    appearance = value === null ? 'system' : value;
    appearanceError = '';
  }).catch(() => {
    appearanceError = 'Saved appearance could not be read. Following device appearance until you choose again.';
  }).finally(() => { loaded = true; loading = null; changed(); });
  return loading;
}
export function saveAppearance(value: AppearanceChoice): Promise<void> {
  if (!choice(value)) return Promise.reject(new Error('Choose a supported appearance.'));
  const operation = writing.then(async () => {
    await loadAppearance();
    await AsyncStorage.setItem(APPEARANCE_KEY, value);
    appearance = value; appearanceError = ''; changed();
  });
  writing = operation.catch(() => undefined);
  return operation;
}
export function useAppearance(): {value: AppearanceChoice; error: string} {
  const [, render] = useState(0);
  useEffect(() => {
    const listener = () => render(previous => previous + 1);
    listeners.add(listener); void loadAppearance();
    return () => { listeners.delete(listener); };
  }, []);
  return {value: appearance, error: appearanceError};
}
export function useTheme(): Palette {
  const device = useColorScheme(), selected = useAppearance().value;
  return (selected === 'system' ? device : selected) === 'dark' ? dark : theme;
}
