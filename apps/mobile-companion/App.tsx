import {msg, messageLanguage, useLanguage, formattedTime} from "./src/language";
/* Lightwork mobile companion — oversight and separately enrolled work.
 *
 * Tasks, Overview, Approvals and Settings plus task-detail and new-task forms,
 * a first-run connection setup when nothing is saved yet. Plain
 * state-based navigation: no navigation library, so the dependency surface
 * stays react/react-native/expo only. All data comes from the dashboard's
 * bounded REST readers and explicitly enrolled action service (see src/api.ts).
 */
import { StatusBar } from "expo-status-bar";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { Alert, BackHandler, Pressable, SafeAreaView, StyleSheet, Text, View } from "react-native";

import { useTheme, type Palette } from "./src/theme";
import type { Settings } from "./src/api";
import { InvalidSavedConnection, loadSettings, resetSettings } from "./src/settings";
import { useConnectionCache } from "./src/offlineCache";
import { GlanceScreen } from "./src/screens/GlanceScreen";
import { RunDetailScreen } from "./src/screens/RunDetailScreen";
import { NewTaskScreen } from "./src/screens/NewTaskScreen";
import { ApprovalsScreen } from "./src/screens/ApprovalsScreen";
import { RunsListScreen } from "./src/screens/RunsListScreen";
import { SettingsScreen } from "./src/screens/SettingsScreen";

type Tab = "runs" | "glance" | "approvals" | "settings";
const TABS: { id: Tab; label: string }[] = [
  { id: "runs", label: "Tasks" },
  { id: "glance", label: "Overview" },
  { id: "approvals", label: "Approvals" },
  { id: "settings", label: "Settings" },
];

export default function App(): React.JSX.Element {
  useLanguage();
  const theme = useTheme(), styles = stylesFor(theme);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [corrupt, setCorrupt] = useState(false);
  const [settingsError, setSettingsError] = useState("");
  const [tab, setTab] = useState<Tab>("runs");
  const [newTask, setNewTask] = useState(false);
  const [run, setRun] = useState<{ id: number; title?: string } | null>(null);
  const cache = useConnectionCache(settings);
  const mounted = useRef(false);
  const settingsRequest = useRef(0);

  const reloadSettings = useCallback(() => {
    if (!mounted.current) return;
    const request = ++settingsRequest.current;
    setSettingsError(""); setCorrupt(false);
    loadSettings().then((loaded) => {
      if (!mounted.current || request !== settingsRequest.current) return;
      setRun(null); setNewTask(false); setSettings(loaded);
    }, (error: unknown) => {
      if (!mounted.current || request !== settingsRequest.current) return;
      if (error instanceof InvalidSavedConnection) { setCorrupt(true); setSettingsError(error.message); return; }
      setSettingsError("Could not open your connection settings. Unlock your device, then try again.");
    });
  }, []);
  useEffect(() => {
    mounted.current = true;
    reloadSettings();
    return () => {
      mounted.current = false;
      settingsRequest.current += 1;
    };
  }, [reloadSettings]);

  useEffect(() => {
    const handler = BackHandler.addEventListener('hardwareBackPress', () => {
      if (newTask) {setNewTask(false); return true;}
      if (run) { setRun(null); setTab('runs'); return true; }
      if (tab !== 'runs') { setTab('runs'); return true; }
      return false;
    });
    return () => handler.remove();
  }, [run, tab, newTask]);
  function resetCorrupt(): void {
    Alert.alert('Reset saved connection?', 'Only this app’s saved connection and offline tasks will be removed.', [
      {text: 'Cancel', style: 'cancel'}, {text: 'Reset connection', style: 'destructive', onPress: () => {
        void resetSettings().then(reloadSettings, () => setSettingsError('Could not reset secure storage. Unlock the device and retry.'));
      }},
    ]);
  }
  const openSettings = useCallback(() => { setTab("settings"); setRun(null); setNewTask(false); }, []);
  const firstRun = Boolean(settings?.needsSetup);

  let body: React.JSX.Element;
  if (!settings || settingsError) {
    body = settingsError ? (
      <View style={styles.center}>
        <Text style={styles.error} accessibilityRole="alert">{settingsError}</Text>
        {corrupt ? <Pressable style={styles.retry} accessibilityRole="button" onPress={resetCorrupt}><Text style={styles.retryText} accessibilityLanguage="en">Reset saved connection</Text></Pressable> : null}
        <Pressable style={styles.retry} accessibilityRole="button" onPress={reloadSettings}>
          <Text style={styles.retryText} accessibilityLanguage={messageLanguage("Retry loading settings")}>{msg("Retry loading settings")}</Text>
        </Pressable>
      </View>
    ) : <Text style={styles.loading} accessibilityLiveRegion="polite" accessibilityLanguage="en">Loading…</Text>;
  } else if (firstRun) {
    body = <SettingsScreen firstRun onSaved={reloadSettings} />;
  } else if (tab === "runs" && newTask) {
    body = <NewTaskScreen settings={settings} onBack={() => setNewTask(false)} />;
  } else if (tab === "approvals") {
    body = <ApprovalsScreen settings={settings} />;
  } else if (tab === "runs" && run !== null) {
    body = (
      <RunDetailScreen
        settings={settings}
        runId={run.id}
        title={run.title}
        onBack={() => setRun(null)}
        onOpenSettings={openSettings}
      />
    );
  } else if (tab === "runs") {
    body = <RunsListScreen settings={settings} onOpenRun={(id, title) => setRun({ id, title })} onOpenSettings={openSettings} onNewTask={() => setNewTask(true)} />;
  } else if (tab === "glance") {
    body = <GlanceScreen settings={settings} liveBundle={cache.data} onOpenRun={(id, title) => { setRun({id, title}); setTab("runs"); }} onOpenSettings={openSettings} />;
  } else {
    body = <SettingsScreen onSaved={reloadSettings} />;
  }

  return (
    <SafeAreaView style={styles.fill}>
      <StatusBar style="auto" />
      <View style={styles.fill}>{body}</View>
      {settings && !settings.needsSetup && tab !== 'settings' ? <Text style={styles.cacheStatus}>
        {settings.offlineEnabled === false ? 'Offline saving is off' : cache.policyMessage || (cache.savedAt ? `Offline copy saved ${formattedTime(cache.savedAt)}` : 'Offline copy not ready')}
      </Text> : null}
      {settings && !settingsError && !firstRun ? (
        <View style={styles.tabbar} accessibilityRole="tablist">
          {TABS.map((t) => (
            <Pressable
              key={t.id}
              style={styles.tab}
              accessibilityRole="tab"
              accessibilityState={{ selected: tab === t.id }}
              onPress={() => {
                setTab(t.id);
                setRun(null); setNewTask(false);
              }}
            >
              <Text style={[styles.tabText, tab === t.id && styles.tabActive]} accessibilityLanguage={messageLanguage(t.label)}>{msg(t.label)}</Text>
            </Pressable>
          ))}
        </View>
      ) : null}
    </SafeAreaView>
  );
}

const stylesFor = (theme: Palette) => StyleSheet.create({
  fill: { flex: 1, backgroundColor: theme.background },
  center: { padding: 24, alignItems: "center" },
  cacheStatus: {padding: 6, textAlign: "center", color: theme.muted},
  loading: { padding: 24, textAlign: "center", color: theme.muted },
  error: { textAlign: "center", color: theme.danger, fontSize: 15 },
  retry: { marginTop: 16, backgroundColor: theme.accent, borderRadius: 6, paddingVertical: 10, paddingHorizontal: 16 },
  retryText: { color: theme.onAccent, fontSize: 15, fontWeight: "600" },
  tabbar: {
    flexDirection: "row",
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: theme.border,
  },
  tab: { minHeight: 48, flex: 1, alignItems: "center", paddingVertical: 12 },
  tabText: { fontSize: 14, color: theme.muted },
  tabActive: { color: theme.accent, fontWeight: "700" },
});
