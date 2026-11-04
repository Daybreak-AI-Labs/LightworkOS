import {msg, messageLanguage, useLanguage, formattedTime} from "../language";
/* Task detail — status header + activity timeline.
 * GET /api/v1/goals/{id}/events?since=0&limit=200, polled every 5s.
 * Paired devices may explicitly review an answer or Stop under current policy. */
import React, { useCallback, useMemo, useState } from "react";
import { FlatList, Linking, Pressable, StyleSheet, Text, View } from "react-native";

import { GoalEvent, GoalEventsResponse, Settings } from "../api";
import { ConnectionNotice } from "../components/ConnectionNotice";
import { TaskActions } from "../components/TaskActions";
import { Banner, Button, EmptyState, Loading, StatusPill } from "../components/ui";
import { humanize, taskTitle } from "../format";
import { offlineBanner, useCachedBundle } from "../offlineCache";
import { usePolling } from "../poll";
import { runReplay } from "../runReplay";
import { useTheme, type Palette } from "../theme";

const continueReplay = (data: GoalEventsResponse) => !data.terminal;

function clock(ts: number): string {
  return formattedTime(ts * 1000);
}

export function RunDetailScreen(props: {
  settings: Settings;
  runId: number;
  title?: string;
  onBack: () => void;
  onOpenSettings?: () => void;
}): React.JSX.Element {
  useLanguage();
  const theme = useTheme(), styles = stylesFor(theme);
  const { settings, runId, title, onBack, onOpenSettings } = props;
  const replay = useMemo(() => runReplay(settings, runId), [settings, runId]);
  const fetcher = useCallback((signal: AbortSignal) => replay.poll(signal), [replay]);
  const { data, error, accessDenied, unsupported, refresh } = usePolling<GoalEventsResponse>(fetcher, 5_000, continueReplay);

  const cached = useCachedBundle(settings, Boolean(error && !data && !accessDenied && !unsupported));
  const savedGoal = cached?.bundle.goals.find(goal => goal.id === runId);
  const display = data || (savedGoal && cached ? {
    status: savedGoal.status, result: savedGoal.result, events: cached.bundle.recent_events.filter(event => event.goal_id === runId),
    has_more: false, truncated: true,
  } : null);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const [linkError, setLinkError] = useState("");
  function openDashboard(): void {
    // Credentials are never put in a URL; the browser must authenticate itself.
    const url = settings.baseUrl.replace(/\/+$/, '') + '/chat/goal/' + encodeURIComponent(runId);
    void Linking.openURL(url).catch(() => setLinkError("Could not open the browser. Open your dashboard from a browser to review the full task."));
  }

  const header = <>
      <View style={styles.header}>
        <Pressable style={{minHeight: 48, justifyContent: "center"}} onPress={onBack} hitSlop={12} accessibilityRole="button" accessibilityLabel="Back to tasks">
          <Text style={styles.back} accessibilityLanguage="en">‹ Tasks</Text>
        </Pressable>
      </View>
      <View style={styles.titleBlock}>
        <Text style={styles.headline} accessibilityRole="header">{title ? taskTitle(title) : "Task details"}</Text>
        {display ? <StatusPill status={display.status} /> : null}
      </View>
      {display?.result ? (
        <View style={styles.result}>
          <Text style={styles.resultLabel} accessibilityLanguage={messageLanguage("Outcome")}>{msg("Outcome")}</Text>
          <Text selectable style={styles.resultText}>{display.result}</Text>
        </View>
      ) : null}
      {display?.has_more ? <Banner text="Loading earlier activity…" /> : null}
      {display?.truncated ? <Banner text="Showing recent activity only. Open the task on the dashboard to see its full history." /> : null}
      {error ? (
        <ConnectionNotice message={error} accessDenied={accessDenied} unsupported={unsupported}
          onRetry={refresh} onOpenSettings={accessDenied ? onOpenSettings : undefined} />
      ) : null}
      <Text style={styles.section} accessibilityRole="header" accessibilityLanguage={messageLanguage("Activity")}>{msg("Activity")}</Text>
      {cached && !data ? <Banner text={offlineBanner(cached)} /> : null}
      {linkError ? <Banner text={linkError} /> : null}
      <Button label={msg("Open full task on dashboard")} language={messageLanguage("Open full task on dashboard")} kind="secondary" onPress={openDashboard} />
      {settings.pairedDevice?.actions && !accessDenied ? <TaskActions key={settings.pairedDevice.id + ':' + settings.pairedDevice.generation + ':' + runId}
        settings={settings} goalId={runId} online={Boolean(data && !error && !unsupported)} onApplied={refresh} /> : null}
    </>;
  return (
    <View style={styles.fill}>
      <FlatList
        ListHeaderComponent={header}
        data={display ? [...display.events].reverse() : []}
        keyExtractor={(e: GoalEvent) => String(e.id)}
        ListEmptyComponent={!data && !error ? <Loading text="Loading activity…" /> : (
          <EmptyState title="No activity yet" body="Steps appear here as the work moves along. This page refreshes on its own." />
        )}
        renderItem={({ item }: { item: GoalEvent }) => (
          <View style={styles.event}>
            <View style={styles.spine} />
            <View style={styles.fill}>
              <Text style={styles.meta}>
                {clock(item.ts)} · {humanize(item.agent) || "Lightwork"} · {humanize(item.kind)}
              </Text>
              <Text selectable style={styles.content} numberOfLines={expanded[item.id] ? undefined : 6}>
                {item.content}
              </Text>
              <Button label={expanded[item.id] ? 'Collapse activity' : 'Read full activity'} kind="secondary" onPress={() => setExpanded(previous => ({...previous, [item.id]: !previous[item.id]}))} />
            </View>
          </View>
        )}
      />
    </View>
  );
}

const stylesFor = (theme: Palette) => StyleSheet.create({
  fill: { flex: 1, backgroundColor: theme.background },
  header: {
    paddingHorizontal: 16, paddingTop: 12,
  },
  back: { fontSize: 16, color: theme.accent },
  titleBlock: {
    paddingHorizontal: 16, paddingVertical: 10,
    borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: theme.border,
  },
  headline: { fontSize: 20, fontWeight: "700", color: theme.text },
  result: { margin: 12, padding: 12, borderRadius: 8, backgroundColor: theme.result },
  resultLabel: { fontSize: 13, fontWeight: "700", color: theme.text },
  resultText: { fontSize: 14, color: theme.text, marginTop: 4 },
  section: { fontSize: 15, fontWeight: "700", color: theme.text, paddingHorizontal: 16, paddingTop: 12, paddingBottom: 4 },
  event: { flexDirection: "row", paddingHorizontal: 14, paddingVertical: 8 },
  spine: {
    width: 3, borderRadius: 2, backgroundColor: theme.border, marginRight: 10,
  },
  meta: { fontSize: 12, color: theme.muted },
  content: { fontSize: 14, marginTop: 2, color: theme.text },
});
