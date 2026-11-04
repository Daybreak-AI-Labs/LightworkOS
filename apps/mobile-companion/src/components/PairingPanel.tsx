import {msg, messageLanguage, useLanguage} from "../language";
import React, {useEffect, useRef, useState} from 'react';
import {AppState, Linking, Text, View} from 'react-native';
import {beginPairing, pollPairing, type DeviceInfo, type PairingRequest} from '../api';
import {connectionValidationError} from '../connectionValidation';
import {useTheme} from '../theme';
import {Button} from './ui';

export function PairingPanel(props: {address: string; label: string; disabled: boolean; onPaired: (token: string, device: DeviceInfo) => Promise<void>}): React.JSX.Element {
  useLanguage();
  const theme = useTheme();
  const [pending, setPending] = useState<PairingRequest | null>(null), [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(''), [error, setError] = useState('');
  const epoch = useRef(0), controller = useRef<AbortController | null>(null), mounted = useRef(true), lastPoll = useRef(0);
  function cancel(): void {epoch.current += 1; controller.current?.abort(); setPending(null); setBusy(false);}
  useEffect(() => {cancel();}, [props.address]);
  useEffect(() => {
    mounted.current = true;
    const listener = AppState.addEventListener('change', state => {if (state !== 'active') {epoch.current += 1; controller.current?.abort(); setBusy(false);}});
    return () => {mounted.current = false; epoch.current += 1; controller.current?.abort(); listener.remove();};
  }, []);
  async function run(action: (signal: AbortSignal, current: () => boolean) => Promise<void>): Promise<void> {
    if (busy || props.disabled) return;
    const revision = ++epoch.current;
    controller.current = new AbortController(); setBusy(true); setError(''); setMessage('');
    const current = () => mounted.current && revision === epoch.current;
    try {await action(controller.current.signal, current);}
    catch (failure) {if (current()) setError(failure instanceof Error ? failure.message : 'Pairing could not be confirmed. Try again.');}
    finally {if (current()) setBusy(false);}
  }
  function start(): void {void run(async (signal, current) => {
    const error = connectionValidationError(props.address);
    if (error) throw new Error(error);
    const value = await beginPairing(props.address, props.label.trim() || 'My mobile companion', signal);
    if (current()) {setPending(value); setMessage('Compare this code on your signed-in dashboard, then return here.');}
  });}
  function check(): void {void run(async (signal, current) => {
    if (!pending) return;
    if (Date.now() >= pending.expires_at * 1000) {setPending(null); throw new Error('This pairing code expired. Start again.');}
    if (Date.now() - lastPoll.current < 5000) throw new Error('Wait five seconds before checking approval again.');
    lastPoll.current = Date.now();
    const result = await pollPairing(props.address, pending.pairing_token, signal);
    if (!current()) return;
    if (result.status === 'approved' && result.token && result.device) {
      await props.onPaired(result.token, result.device);
      if (current()) {setPending(null); setMessage('Device paired and connection saved securely.');}
    } else setMessage('Waiting for explicit approval on your signed-in dashboard.');
  });}
  return <View>
    <Text accessibilityRole="header" style={{color: theme.text, fontSize: 18, marginTop: 16}} accessibilityLanguage="en">Pair with your account</Text>
    <Text style={{color: theme.muted}} accessibilityLanguage="en">Approve a short-lived code in your signed-in dashboard. No access-token copying is needed. The connection is limited to your own work in the chosen workspace. On the dashboard, separately choose whether this device may answer or stop tasks, start new tasks, or decide requests belonging to your tasks. Existing devices gain none of these new permissions automatically.</Text>
    {!pending ? <Button label={msg("Start device pairing")} language={messageLanguage("Start device pairing")} disabled={props.disabled || busy} onPress={start} /> : <>
      <Text selectable accessibilityLabel={'Pairing code ' + pending.code.split('').join(' ')} style={{color: theme.text, fontSize: 24}}>{pending.code}</Text>
      <Button label="Open pairing page" disabled={busy} onPress={() => {void Linking.openURL(props.address.replace(/\/+$/, '') + '/devices?code=' + encodeURIComponent(pending.code)).catch(() => setError('Open your dashboard on a computer, choose Your account, then Your paired devices, and enter this code.'));}} />
      <Button label="Check pairing approval" disabled={busy || props.disabled} onPress={check} />
      <Button label="Cancel device pairing" kind="secondary" onPress={cancel} />
    </>}
    {message ? <Text accessibilityLiveRegion="polite" style={{color: theme.muted}}>{message}</Text> : null}
    {error ? <Text accessibilityRole="alert" style={{color: theme.danger}}>{error}</Text> : null}
  </View>;
}
