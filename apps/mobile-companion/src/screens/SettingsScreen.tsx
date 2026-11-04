/* Connection credentials and pairing metadata are committed together to secure
 * storage. Pairing/renewal POSTs change only this device connection. */
import React, { useEffect, useRef, useState } from "react";
import { Alert, Switch, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";

import { getActive, renewPairing, type DeviceInfo } from "../api";
import { Button } from "../components/ui";
import { PairingPanel } from "../components/PairingPanel";
import { activateProfile, listProfiles, loadSettings, removeProfile, resetSettings, saveProfile, saveSettings, type ConnectionProfile } from "../settings";
import { connectionValidationError } from "../connectionValidation";
import { useTheme, useAppearance, saveAppearance, type AppearanceChoice, type Palette } from "../theme";
import {LANGUAGE_CHOICES, saveLanguage, useLanguage, msg, messageLanguage, formattedDateTime, type LanguageChoice} from '../language';

// People often type "lightwork.example.com"; assume the secure scheme.
export function withScheme(address: string): string {
  const trimmed = address.trim();
  return trimmed && !/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? `https://${trimmed}` : trimmed;
}

export function SettingsScreen(props: {
  onSaved: () => void;
  firstRun?: boolean;
}): React.JSX.Element {
  const theme = useTheme(), styles = stylesFor(theme);
  const appearance = useAppearance();
  const language = useLanguage();
  const [languageBusy, setLanguageBusy] = useState(false), [languageNote, setLanguageNote] = useState('');
  const [appearanceBusy, setAppearanceBusy] = useState(false), [appearanceNote, setAppearanceNote] = useState('');
  const { firstRun = false } = props;
  const [profiles, setProfiles] = useState<ConnectionProfile[]>([]), [profileId, setProfileId] = useState<string | undefined>();
  const [profileName, setProfileName] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [token, setToken] = useState("");
  const [pairedDevice, setPairedDevice] = useState<DeviceInfo | undefined>();
  const [showToken, setShowToken] = useState(false);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const saveInFlight = useRef(false);
  const mounted = useRef(true), generation = useRef(0), testController = useRef<AbortController | null>(null);
  const [offlineEnabled, setOfflineEnabled] = useState(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current += 1; testController.current?.abort(); }; }, []);
  function edited(update: () => void): void {
    generation.current += 1; testController.current?.abort(); setTesting(false); setNote(""); setError(""); update();
  }
  function disconnect(): void {
    Alert.alert("Remove saved connection?", "This removes this app’s saved access token and offline task data. It does not change the dashboard.", [
      {text: "Cancel", style: "cancel"},
      {text: "Remove connection", style: "destructive", onPress: () => {
        edited(() => {});
        void resetSettings().then(props.onSaved, () => setError("Could not remove saved data. Unlock your device and try again."));
      }},
    ]);
  }

  useEffect(() => {
    let current = true;
    setLoading(true);
    setLoadFailed(false);
    setError("");
    loadSettings().then((s) => {
      if (!current) return;
      // A fresh install has nothing saved: leave the address empty so the
      // example shows instead of a placeholder address.
      setBaseUrl(s.needsSetup ? "" : s.baseUrl);
      setToken(s.token);
      setPairedDevice(s.pairedDevice);
      setOfflineEnabled(s.offlineEnabled !== false);
      void listProfiles().then(store => {
        if (!current) return;
        setProfiles(store.profiles); setProfileId(store.active || undefined);
        setProfileName(store.profiles.find(profile => profile.id === store.active)?.name || '');
      }, () => { if (current) setError('Could not read saved connections. Unlock your device and retry.'); });
    }, () => {
      if (!current) return;
      setLoadFailed(true);
      setError("Could not open your saved settings. Unlock your device, then try again.");
    }).finally(() => {
      if (current) setLoading(false);
    });
    return () => { current = false; };
  }, [loadAttempt]);

  function switchProfile(id: string): void {
    Alert.alert('Switch saved connection?', 'Unsaved connection edits will be discarded and the previous offline cache removed.', [
      {text: 'Cancel', style: 'cancel'}, {text: 'Switch', onPress: () => {
        edited(() => {});
        void activateProfile(id).then(() => {setLoadAttempt(value => value + 1); props.onSaved();}, () => setError('Could not switch the connection. Unlock the device and retry.'));
      }},
    ]);
  }
  function removeSelected(): void {
    if (!profileId) return;
    Alert.alert('Remove this saved connection?', 'Only this connection and its cached task data will be removed.', [
      {text: 'Cancel', style: 'cancel'}, {text: 'Remove', style: 'destructive', onPress: () => {
        void removeProfile(profileId).then(() => {setLoadAttempt(value => value + 1); props.onSaved();}, () => setError('Could not remove this connection. Unlock the device and retry.'));
      }},
    ]);
  }
  function checked(): string | null {
    const address = withScheme(baseUrl);
    if (address !== baseUrl) setBaseUrl(address);
    const validation = address ? connectionValidationError(address, token) : "Enter your dashboard address.";
    if (validation) {
      setError(validation);
      setNote("");
      return null;
    }
    return address;
  }

  async function save(): Promise<void> {
    if (loading || loadFailed || testing || saveInFlight.current) return;
    const address = checked();
    if (address === null) return;
    saveInFlight.current = true;
    setSaving(true);
    setError("");
    setNote("");
    try {
      if (profileName.trim()) await saveProfile(profileName, {baseUrl: address, token, offlineEnabled, pairedDevice}, profileId);
      else if (profiles.length) { setError('Enter a name for this connection.'); return; }
      else await saveSettings({ baseUrl: address, token, offlineEnabled, pairedDevice });
      setNote("Saved. The app now uses this connection.");
      props.onSaved();
    } catch {
      setError("Could not save your settings. Check that your device has free space, then try again.");
    } finally {
      saveInFlight.current = false;
      setSaving(false);
    }
  }

  async function paired(nextToken: string, device: DeviceInfo): Promise<void> {
    if (saveInFlight.current) throw new Error('Wait for the current save to finish.');
    saveInFlight.current = true; setSaving(true);
    const settings = {baseUrl: withScheme(baseUrl), token: nextToken, offlineEnabled, pairedDevice: device};
    try {
      if (profileName.trim()) await saveProfile(profileName, settings, profileId);
      else if (profiles.length) throw new Error('Enter a connection name before pairing.');
      else await saveSettings(settings);
      if (mounted.current) {setToken(nextToken); setPairedDevice(device); props.onSaved();}
    } finally {saveInFlight.current = false; if (mounted.current) setSaving(false);}
  }

  async function renew(): Promise<void> {
    if (!pairedDevice || saving || testing) return;
    const revision = ++generation.current, controller = new AbortController();
    testController.current = controller; setTesting(true); setError('');
    try {
      const reply = await renewPairing({baseUrl: withScheme(baseUrl), token}, pairedDevice.generation, controller.signal);
      if (mounted.current && revision === generation.current) {await paired(reply.token, reply.device); setNote('Device connection renewed and stored securely.');}
    } catch {if (mounted.current && revision === generation.current) setError('Renewal could not be saved. Retry within one minute; if the connection expired, pair again.');}
    finally {if (mounted.current && revision === generation.current) setTesting(false);}
  }

  async function testConnection(): Promise<void> {
    if (loading || loadFailed || saving || testing) return;
    const address = checked();
    if (address === null) return;
    const request = ++generation.current;
    const controller = new AbortController(); testController.current = controller;
    setTesting(true);
    setError("");
    setNote("");
    try {
      await getActive({ baseUrl: address, token }, controller.signal);
      if (!mounted.current || request !== generation.current) return;
      setNote("Connected. Save to start using this connection.");
    } catch (e) {
      if (!mounted.current || request !== generation.current) return;
      const known = e instanceof Error && typeof (e as { kind?: unknown }).kind === "string";
      setError(known ? (e as Error).message
        : "Could not reach the dashboard. Check the address and that you are on your organization's network or VPN.");
    } finally {
      if (mounted.current && request === generation.current) { setTesting(false); testController.current = null; }
    }
  }

  const disabled = loading || loadFailed || saving;

  async function chooseAppearance(value: AppearanceChoice): Promise<void> {
    if (appearanceBusy) return;
    setAppearanceBusy(true); setAppearanceNote('');
    try {
      await saveAppearance(value);
      if (mounted.current) setAppearanceNote('Appearance saved on this device.');
    } catch {
      if (mounted.current) setAppearanceNote('Appearance could not be saved. Your previous choice is still active. Try again.');
    } finally {
      if (mounted.current) setAppearanceBusy(false);
    }
  }

  async function chooseLanguage(value: LanguageChoice): Promise<void> {
    if (languageBusy) return;
    setLanguageBusy(true); setLanguageNote('');
    try {await saveLanguage(value); if (mounted.current) setLanguageNote('Language and regional formats saved on this device.');}
    catch {if (mounted.current) setLanguageNote('Language could not be saved. Your previous choice is still active. Try again.');}
    finally {if (mounted.current) setLanguageBusy(false);}
  }

  return (
    <ScrollView contentContainerStyle={styles.fill} keyboardShouldPersistTaps="handled">
      <Text style={styles.heading} accessibilityRole="header">{firstRun ? msg("Connect to Lightwork") : msg("Settings")}</Text>
      <Text style={styles.help}>
        {firstRun
          ? "Enter your dashboard address, then pair with your signed-in account."
          : "The dashboard this app shows information from."}
      </Text>
      {error ? <Text style={styles.error} accessibilityRole="alert">{error}</Text> : null}
      {loadFailed ? (
        <Button label={msg("Retry loading settings")} language={messageLanguage("Retry loading settings")} onPress={() => setLoadAttempt(loadAttempt + 1)} />
      ) : null}
      <Text style={styles.label} accessibilityRole="header" accessibilityLanguage={messageLanguage("Appearance on this device")}>{msg("Appearance on this device")}</Text>
      <View accessibilityRole="radiogroup">
        {(['system', 'light', 'dark'] as AppearanceChoice[]).map(value => (
          <Pressable key={value} accessibilityRole="radio" accessibilityState={{checked: appearance.value === value, disabled: appearanceBusy}}
            disabled={appearanceBusy} style={styles.show} onPress={() => void chooseAppearance(value)}>
            <Text style={styles.showText}>{appearance.value === value ? 'Selected: ' : ''}{value === 'system' ? msg('Follow device') : value === 'light' ? msg('Light') : msg('Dark')}</Text>
          </Pressable>
        ))}
      </View>
      <Text style={styles.fieldHelp} accessibilityLanguage="en">Device display preferences apply to every saved connection. Text follows device accessibility size. Task content stays as written.</Text>
      {appearance.error ? <Text style={styles.error} accessibilityRole="alert">{appearance.error}</Text> : null}
      {appearanceNote ? <Text style={styles.help} accessibilityLiveRegion="polite">{appearanceNote}</Text> : null}
      <Text style={styles.label} accessibilityRole="header" accessibilityLanguage={messageLanguage('Language and regional formats')}>{msg('Language and regional formats')}</Text>
      <View accessibilityRole="radiogroup">
        {LANGUAGE_CHOICES.map(choice => <Pressable key={choice.value} accessibilityRole="radio"
          accessibilityState={{checked: language.value === choice.value, disabled: languageBusy}}
          disabled={languageBusy} style={styles.show} onPress={() => void chooseLanguage(choice.value)}>
          <Text style={styles.showText} accessibilityLanguage={choice.value === 'system' ? messageLanguage('Follow device') : choice.value}>
            {choice.value === 'system' ? msg(choice.label) : choice.label}
          </Text>
        </Pressable>)}
      </View>
      <Text style={styles.fieldHelp} accessibilityLanguage="en">Translations are a partial preview. Some controls are translated; other guidance and action consequences are still in English. Arabic awaits community translation. Numbers, dates and USD costs follow your selected regional format. This does not change document output language or workspace policy.</Text>
      {language.error || languageNote ? <Text style={styles.help} accessibilityLanguage="en" accessibilityLiveRegion="polite">{language.error || languageNote}</Text> : null}
      {profiles.length ? <Text style={styles.label} accessibilityLanguage={messageLanguage("Saved connections")}>{msg("Saved connections")}</Text> : null}
      {profiles.map(profile => <Button key={profile.id} label={(profileId === profile.id ? 'Current: ' : 'Switch to ') + profile.name} kind="secondary" disabled={disabled || testing || profileId === profile.id} onPress={() => switchProfile(profile.id)} />)}
      {profileId ? <Button label={msg("Remove this saved connection")} language={messageLanguage("Remove this saved connection")} kind="secondary" disabled={disabled || testing} onPress={removeSelected} /> : null}
      <Button label={msg("Add another connection")} language={messageLanguage("Add another connection")} kind="secondary" disabled={disabled || testing} onPress={() => edited(() => {setProfileId(undefined); setProfileName(''); setBaseUrl(''); setToken(''); setPairedDevice(undefined);})} />
      <Text style={styles.label} accessibilityLanguage="en">Connection name (optional for a single connection)</Text>
      <TextInput style={styles.input} accessibilityLabel={msg("Connection name")} maxLength={80} editable={!disabled} value={profileName} onChangeText={setProfileName} />
      <Text style={styles.fieldHelp} accessibilityLanguage="en">Choose a name to keep this connection securely alongside your other deployments.</Text>
      <Text style={styles.label} nativeID="address-label" accessibilityLanguage={messageLanguage("Dashboard address")}>{msg("Dashboard address")}</Text>
      <TextInput
        style={styles.input}
        accessibilityLabel={msg("Dashboard address")}
        accessibilityHint="The web address you use to open Lightwork on a computer"
        editable={!disabled}
        value={baseUrl}
        onChangeText={value => edited(() => {setBaseUrl(value); setPairedDevice(undefined);})}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="url"
        placeholder="https://lightwork.yourcompany.com"
      />
      <Text style={styles.fieldHelp} accessibilityLanguage="en">The web address you use to open Lightwork on a computer.</Text>
      <PairingPanel address={withScheme(baseUrl)} label={profileName} disabled={disabled || testing} onPaired={paired} />
      {pairedDevice ? <>
        <Text style={styles.fieldHelp}>Paired to {pairedDevice.principal} in {pairedDevice.tenant || 'the default workspace'}. Credential expires {formattedDateTime(pairedDevice.expires_at * 1000)}.</Text>
        <Button label={msg("Renew paired connection")} language={messageLanguage("Renew paired connection")} disabled={disabled || testing} onPress={() => void renew()} />
      </> : null}
      <Text style={styles.label} accessibilityLanguage="en">Advanced administrative token connection</Text>
      <View style={styles.tokenRow}>
        <TextInput
          style={[styles.input, styles.tokenInput]}
          accessibilityLabel="Access token"
          accessibilityHint="A private code from your administrator"
          editable={!disabled}
          value={token}
          onChangeText={value => edited(() => {setToken(value); setPairedDevice(undefined);})}
          autoCapitalize="none"
          autoCorrect={false}
          secureTextEntry={!showToken}
          placeholder="Paste the code from your administrator"
        />
        <Pressable style={styles.show} accessibilityRole="button"
          accessibilityLabel={showToken ? "Hide access token" : "Show access token"}
          onPress={() => setShowToken(!showToken)}>
          <Text style={styles.showText}>{showToken ? "Hide" : "Show"}</Text>
        </Pressable>
      </View>
      <Text style={styles.fieldHelp} accessibilityLanguage="en">A private code from your administrator. Leave it empty only if your administrator says sign-in is not needed.</Text>
      <Text style={styles.label} accessibilityLanguage="en">Save offline task data on this device</Text>
      <Switch accessibilityLabel="Save offline task data for up to 24 hours" value={offlineEnabled} disabled={disabled} onValueChange={setOfflineEnabled} />
      <Text style={styles.fieldHelp} accessibilityLanguage="en">Saved task content can be sensitive. Your organization can disable offline saving or set a shorter limit. Copies never exceed 2 MB or 24 hours; turn this off and save to remove the previous cache.</Text>
      {!firstRun ? <Button label="Disconnect and remove saved data" kind="secondary" disabled={disabled || testing} onPress={disconnect} /> : null}
      <Button label={saving ? "Saving…" : loading ? "Loading…" : firstRun ? "Save and connect" : "Save"}
        disabled={disabled || testing} busy={saving} onPress={save} />
      <Button label={testing ? "Testing…" : "Test connection"} kind="secondary"
        disabled={disabled || testing} busy={testing} onPress={testConnection}
        hint="Checks the address and token without saving them" />
      {note ? <Text style={styles.note} accessibilityLiveRegion="polite">{note}</Text> : null}
      <Text style={styles.sectionHelp} accessibilityLanguage="en">Good to know</Text>
      <Text style={styles.help} accessibilityLanguage="en">
        This app reads your work by default. If your administrator allows actions
        and you explicitly approve them when pairing, you can review an answer or
        Stop request on your own task. Approvals and other decisions open the full
        dashboard. Offline copies cannot send actions. If your organization
        requires a VPN, connect first. Credentials stay in device secure storage.
      </Text>
    </ScrollView>
  );
}

const stylesFor = (theme: Palette) => StyleSheet.create({
  fill: { flexGrow: 1, padding: 16 },
  heading: { fontSize: 22, fontWeight: "700", color: theme.text },
  label: { fontSize: 14, fontWeight: "600", color: theme.text, marginTop: 16, marginBottom: 4 },
  fieldHelp: { fontSize: 12, color: theme.muted, marginTop: 4, lineHeight: 17 },
  input: {
    borderWidth: 1, borderColor: theme.border, borderRadius: 6,
    paddingHorizontal: 10, paddingVertical: 8, fontSize: 15, color: theme.text,
  },
  tokenRow: { flexDirection: "row", alignItems: "center", gap: 8 },
  tokenInput: { flex: 1 },
  show: { minHeight: 48, minWidth: 48, paddingHorizontal: 10, paddingVertical: 8 },
  showText: { color: theme.accent, fontSize: 14, fontWeight: "600" },
  note: { marginTop: 10, color: theme.success },
  error: { marginTop: 10, color: theme.danger },
  sectionHelp: { marginTop: 24, fontSize: 14, fontWeight: "600", color: theme.text },
  help: { marginTop: 6, fontSize: 13, color: theme.muted, lineHeight: 19 },
});
