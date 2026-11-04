import {msg, messageLanguage, useLanguage, formattedNumber, formattedDateTime} from "../language";
/* Overview (was "Glance") — the at-a-glance summary, polled every 15s.
 *
 * Online path composes two real read-only endpoints:
 *   GET /api/v1/oversight/active  (active runs + latest activity)
 *   GET /api/v1/spend             (total spend)
 * It also opportunistically refreshes the offline cache from
 * GET /api/v1/offline/bundle when the dashboard serves it (404 on older
 * dashboards is fine — the cache just isn't refreshed). When everything is
 * unreachable, renders the cached bundle with an offline banner. */
import React, { useCallback } from "react";
import { Linking, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";

import {
  ActiveGoal,
  Glance,
  Settings,
  SpendTotal,
  getActive,
  OfflineBundle,
  getSpend,
  isAccessDenied,
} from "../api";
import { offlineBanner, useCachedBundle } from "../offlineCache";
import { ConnectionNotice } from "../components/ConnectionNotice";
import { Banner, Button, EmptyState } from "../components/ui";
import { activityText, money, plural, taskTitle } from "../format";
import { usePolling } from "../poll";
import { useTheme, type Palette } from "../theme";

type GlanceData = { active: ActiveGoal[]; spend: SpendTotal | null };

export function GlanceScreen(props: { settings: Settings; liveBundle?: OfflineBundle | null; onOpenRun?: (id: number, title?: string) => void; onOpenSettings?: () => void }): React.JSX.Element {
  useLanguage();
  const theme = useTheme(), styles = stylesFor(theme);
  const { settings, onOpenSettings } = props;

  const fetcher = useCallback(async (signal: AbortSignal): Promise<GlanceData> => {
    const [activeRes, spendRes] = await Promise.all([
      getActive(settings, signal),
      getSpend(settings, signal).catch(error => { if (isAccessDenied(error)) throw error; return null; }),
    ]);
    return { active: activeRes.goals, spend: spendRes ? spendRes.total : null };
  }, [settings]);

  const { data, error, accessDenied, unsupported, refresh } = usePolling<GlanceData>(fetcher, 15_000);
  const cached = useCachedBundle(settings, Boolean(error && !data && !accessDenied && !unsupported));

  if (!data && cached) {
    const g = cached.bundle.glance;
    return (
      <ScrollView style={styles.fill}>
        <Text style={styles.heading} accessibilityRole="header" accessibilityLanguage={messageLanguage("Overview")}>{msg("Overview")}</Text>
        <Banner text={offlineBanner(cached)} />
        <View style={styles.stats}>
          <Stat label="Tasks in progress" value={formattedNumber(g.counts.active)} />
          <Stat label="Waiting for approval" value={formattedNumber(g.counts.pending_approvals)} />
          <Stat label="Questions for you" value={formattedNumber(g.counts.open_questions)} />
          <Stat label="Total spend" value={money(g.spend.dollars)} />
        </View>
        <Text style={styles.section} accessibilityRole="header" accessibilityLanguage="en">In progress (saved)</Text>
        {g.active.length === 0 ? <Text style={styles.row} accessibilityLanguage="en">Nothing was running.</Text> : null}
        {g.active.map((a: Glance["active"][number]) => (
          <Pressable key={a.id} style={styles.row} accessibilityRole="button" onPress={() => props.onOpenRun?.(a.id, a.title)}><Text>{taskTitle(a.title)}</Text></Pressable>
        ))}
        <Text style={styles.note} accessibilityLanguage="en">Approvals and questions are answered on the dashboard.</Text>
      </ScrollView>
    );
  }

  return (
    <ScrollView style={styles.fill}>
      <Text style={styles.heading} accessibilityRole="header" accessibilityLanguage={messageLanguage("Overview")}>{msg("Overview")}</Text>
      {error ? (
        <ConnectionNotice message={error} accessDenied={accessDenied} unsupported={unsupported}
          onRetry={refresh} onOpenSettings={accessDenied ? onOpenSettings : undefined} />
      ) : null}
      {error && data ? <Banner text="These numbers may be out of date." /> : null}
      <View style={styles.stats}>
        <Stat label="Tasks in progress" value={data ? formattedNumber(data.active.length) : "…"} />
        <Stat label="Waiting for approval" value={props.liveBundle ? formattedNumber(props.liveBundle.glance.counts.pending_approvals) : "Unavailable"} />
        <Stat label="Questions for you" value={props.liveBundle ? formattedNumber(props.liveBundle.glance.counts.open_questions) : "Unavailable"} />
        <Stat
          label="Total spend"
          value={data?.spend ? money(data.spend.dollars) : "…"}
          detail={data?.spend ? `Across ${plural(data.spend.runs, "task", "tasks")}` : undefined}
        />
      </View>
      <Button label="Review approvals and questions on dashboard" kind="secondary" onPress={() => { void Linking.openURL(settings.baseUrl.replace(/\/+$/, '') + '/action-center'); }} />
      {props.liveBundle ? <Text style={styles.note}>Attention counts as of {formattedDateTime(props.liveBundle.as_of * 1000)}. Approvals and questions are answered on the dashboard.</Text> : null}
      <Text style={styles.section} accessibilityRole="header" accessibilityLanguage="en">In progress now</Text>
      {data && data.active.length === 0 ? (
        <EmptyState
          title="Nothing is running"
          body="When a task starts on the dashboard, you'll see it here with its latest step."
          actionLabel={msg("Refresh now")}
          onAction={refresh}
        />
      ) : null}
      {(data ? data.active : []).map((a) => (
        <Pressable key={a.id} style={styles.card} accessibilityRole="button" accessibilityLabel={`Open ${taskTitle(a.title)}`} onPress={() => props.onOpenRun?.(a.id, a.title)}>
          <Text style={styles.cardTitle} numberOfLines={2}>{taskTitle(a.title)}</Text>
          {a.activity ? (
            <Text style={styles.cardSub} numberOfLines={2}>Latest step: {activityText(a.activity)}</Text>
          ) : null}
        </Pressable>
      ))}
    </ScrollView>
  );
}

function Stat(props: { label: string; value: string; detail?: string }): React.JSX.Element {
  const theme = useTheme(), styles = stylesFor(theme);
  return (
    <View style={styles.stat} accessible accessibilityLabel={`${props.label}: ${props.value}${props.detail ? `, ${props.detail}` : ""}`}>
      <Text style={styles.statValue}>{props.value}</Text>
      <Text style={styles.statLabel}>{props.label}</Text>
      {props.detail ? <Text style={styles.statLabel}>{props.detail}</Text> : null}
    </View>
  );
}

const stylesFor = (theme: Palette) => StyleSheet.create({
  fill: { flex: 1, backgroundColor: theme.background },
  heading: { fontSize: 22, fontWeight: "700", color: theme.text, paddingHorizontal: 16, paddingTop: 12, paddingBottom: 4 },
  stats: { flexDirection: "row", flexWrap: "wrap", paddingHorizontal: 8 },
  stat: {
    width: "46%", margin: "2%", padding: 12, borderRadius: 8,
    backgroundColor: theme.surface, borderWidth: StyleSheet.hairlineWidth, borderColor: theme.border,
  },
  statValue: { fontSize: 22, fontWeight: "700", color: theme.text },
  statLabel: { fontSize: 13, color: theme.muted },
  section: {
    fontSize: 15, fontWeight: "700", color: theme.text,
    paddingHorizontal: 16, paddingTop: 16, paddingBottom: 4,
  },
  row: { paddingHorizontal: 16, paddingVertical: 6, fontSize: 14, color: theme.text },
  note: { paddingHorizontal: 16, paddingVertical: 12, fontSize: 13, color: theme.muted },
  card: {
    marginHorizontal: 14, marginVertical: 6, padding: 12,
    borderRadius: 8, borderWidth: StyleSheet.hairlineWidth,
    borderColor: theme.border,
  },
  cardTitle: { fontSize: 15, fontWeight: "600", color: theme.text },
  cardSub: { fontSize: 13, color: theme.muted, marginTop: 4 },
});
