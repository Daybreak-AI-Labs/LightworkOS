/* Small shared building blocks so every screen looks and reads the same. */
import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";

import { statusLabel, statusLanguage, statusTone } from "../format";
import { useTheme, type Palette } from "../theme";

export function Button(props: {
  label: string;
  onPress: () => void;
  kind?: "primary" | "secondary";
  disabled?: boolean;
  busy?: boolean;
  hint?: string;
  language?: string;
}): React.JSX.Element {
  const theme = useTheme(), styles = stylesFor(theme);
  const primary = (props.kind ?? "primary") === "primary";
  return (
    <Pressable
      style={[styles.button, primary ? styles.primary : styles.secondary, props.disabled && styles.disabled]}
      accessibilityRole="button"
      accessibilityHint={props.hint}
      accessibilityState={{ disabled: Boolean(props.disabled), busy: Boolean(props.busy) }}
      disabled={props.disabled}
      onPress={props.onPress}
    >
      <Text style={primary ? styles.primaryText : styles.secondaryText} accessibilityLanguage={props.language}>{props.label}</Text>
    </Pressable>
  );
}

export function EmptyState(props: {
  title: string;
  body: string;
  actionLabel?: string;
  onAction?: () => void;
}): React.JSX.Element {
  const theme = useTheme(), styles = stylesFor(theme);
  return (
    <View style={styles.empty}>
      <Text style={styles.emptyTitle} accessibilityRole="header">{props.title}</Text>
      <Text style={styles.emptyBody}>{props.body}</Text>
      {props.actionLabel && props.onAction ? (
        <Button label={props.actionLabel} kind="secondary" onPress={props.onAction} />
      ) : null}
    </View>
  );
}

export function StatusPill(props: { status: string }): React.JSX.Element {
  const theme = useTheme(), styles = stylesFor(theme);
  const baseTone = statusTone(props.status);
  const tone = ({"#1a7f37": theme.success, "#9a6700": theme.text, "#cf222e": theme.danger} as Record<string, string>)[baseTone] || theme.muted;
  return (
    <View style={[styles.pill, { borderColor: tone }]}>
      <Text style={[styles.pillText, { color: tone }]} accessibilityLanguage={statusLanguage(props.status)}>{statusLabel(props.status)}</Text>
    </View>
  );
}

export function Banner(props: { text: string }): React.JSX.Element {
  const theme = useTheme(), styles = stylesFor(theme);
  return <Text style={styles.banner} accessibilityRole="text" accessibilityLiveRegion="polite">{props.text}</Text>;
}

export function Loading(props: { text?: string }): React.JSX.Element {
  const theme = useTheme(), styles = stylesFor(theme);
  return <Text style={styles.loading} accessibilityLiveRegion="polite">{props.text ?? "Loading…"}</Text>;
}

const stylesFor = (theme: Palette) => StyleSheet.create({
  button: { minHeight: 48, justifyContent: "center", marginTop: 12, borderRadius: 6, paddingVertical: 10, paddingHorizontal: 16, alignItems: "center" },
  primary: { minHeight: 48, justifyContent: "center", backgroundColor: theme.accent },
  secondary: { borderWidth: 1, borderColor: theme.border, backgroundColor: theme.background },
  disabled: { opacity: 0.55 },
  primaryText: { color: theme.onAccent, fontSize: 15, fontWeight: "600" },
  secondaryText: { color: theme.accent, fontSize: 15, fontWeight: "600" },
  empty: { padding: 24, alignItems: "center" },
  emptyTitle: { fontSize: 16, fontWeight: "700", color: theme.text, textAlign: "center" },
  emptyBody: { fontSize: 14, color: theme.muted, marginTop: 6, textAlign: "center", lineHeight: 20 },
  pill: { alignSelf: "flex-start", borderWidth: 1, borderRadius: 10, paddingHorizontal: 8, paddingVertical: 2, marginTop: 4 },
  pillText: { fontSize: 12, fontWeight: "600" },
  banner: { backgroundColor: theme.warnBg, color: theme.warnText, padding: 8, textAlign: "center", fontSize: 13 },
  loading: { padding: 24, textAlign: "center", color: theme.muted },
});
