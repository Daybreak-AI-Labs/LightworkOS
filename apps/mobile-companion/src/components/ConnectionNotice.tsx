import {msg, messageLanguage, useLanguage} from "../language";
/* A plain explanation of why the latest information is missing, with the
 * next step as a button. Messages come from src/api.ts and are written for
 * people; no addresses, status codes or code names reach this component. */
import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";

import { useTheme, type Palette } from "../theme";

export function ConnectionNotice({ message, accessDenied = false, unsupported = false, onRetry, onOpenSettings }: {
  message: string;
  accessDenied?: boolean;
  unsupported?: boolean;
  onRetry?: () => void;
  onOpenSettings?: () => void;
}): React.JSX.Element {
  useLanguage();
  const theme = useTheme(), styles = stylesFor(theme);
  const headline = unsupported ? "Update needed"
    : accessDenied ? "Access problem"
      : "Can't get the latest information";
  return (
    <View style={styles.notice} accessibilityRole="alert">
      <Text style={styles.headline}>{headline}</Text>
      <Text style={styles.body}>{message}</Text>
      {accessDenied ? <Text style={styles.body} accessibilityLanguage="en">Saved information is hidden until your access is fixed.</Text> : null}
      <View style={styles.actions}>
        {onRetry && !unsupported ? (
          <Pressable style={styles.primary} accessibilityRole="button" onPress={onRetry}>
            <Text style={styles.primaryText} accessibilityLanguage={messageLanguage("Try again")}>{msg("Try again")}</Text>
          </Pressable>
        ) : null}
        {onOpenSettings ? (
          <Pressable style={styles.secondary} accessibilityRole="button" onPress={onOpenSettings}>
            <Text style={styles.secondaryText} accessibilityLanguage={messageLanguage("Check settings")}>{msg("Check settings")}</Text>
          </Pressable>
        ) : null}
      </View>
    </View>
  );
}

const stylesFor = (theme: Palette) => StyleSheet.create({
  notice: {
    margin: 12, padding: 12, borderRadius: 8,
    backgroundColor: theme.dangerBg, borderWidth: StyleSheet.hairlineWidth, borderColor: theme.danger,
  },
  headline: { color: theme.danger, fontSize: 15, fontWeight: "700" },
  body: { color: theme.text, fontSize: 14, marginTop: 4, lineHeight: 20 },
  actions: { flexDirection: "row", flexWrap: "wrap", gap: 10, marginTop: 10 },
  primary: { minHeight: 48, justifyContent: "center", backgroundColor: theme.accent, borderRadius: 6, paddingVertical: 8, paddingHorizontal: 14 },
  primaryText: { color: theme.onAccent, fontSize: 14, fontWeight: "600" },
  secondary: { minHeight: 48, justifyContent: "center", borderRadius: 6, paddingVertical: 8, paddingHorizontal: 14, borderWidth: 1, borderColor: theme.border },
  secondaryText: { color: theme.accent, fontSize: 14, fontWeight: "600" },
});
