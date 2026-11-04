import {msg, messageLanguage, useLanguage} from "../language";
import React, {useEffect, useRef, useState} from 'react';
import {AppState, Text, TextInput, View} from 'react-native';
import {deviceActionContext, prepareDeviceAction, executeDeviceAction, isAccessDenied,
  type Settings, type DeviceActionContext, type DeviceActionReview} from '../api';
import {Button} from './ui';
import {useTheme} from '../theme';

export function TaskActions(props: {settings: Settings; goalId: number; online: boolean; onApplied: () => void}): React.JSX.Element {
  useLanguage();
  const theme = useTheme();
  const [context, setContext] = useState<DeviceActionContext | null>(null);
  const [question, setQuestion] = useState(''), [answer, setAnswer] = useState('');
  const [review, setReview] = useState<DeviceActionReview | null>(null), [uncertain, setUncertain] = useState(false);
  const [busy, setBusy] = useState(false), [message, setMessage] = useState(''), [error, setError] = useState('');
  const epoch = useRef(0), mounted = useRef(true), controller = useRef<AbortController | null>(null);
  const online = useRef(props.online); online.current = props.online;
  function invalidate(): void {epoch.current++; controller.current?.abort(); setBusy(false); setContext(null); setReview(null);}
  useEffect(() => {if (!props.online) invalidate();}, [props.online]);
  useEffect(() => {
    mounted.current = true;
    const listener = AppState.addEventListener('change', state => {if (state !== 'active') invalidate();});
    return () => {mounted.current = false; epoch.current++; controller.current?.abort(); listener.remove();};
  }, []);
  async function run(operation: (signal: AbortSignal, current: () => boolean) => Promise<void>): Promise<void> {
    if (busy || !online.current) return;
    const generation = ++epoch.current;
    controller.current = new AbortController(); setBusy(true); setError('');
    const current = () => mounted.current && generation === epoch.current && online.current;
    try {await operation(controller.current.signal, current);}
    catch (failure) {
      if (current()) {
        if (isAccessDenied(failure)) {setContext(null); setReview(null); setAnswer(''); setQuestion('');}
        setError(failure instanceof Error ? failure.message : 'The action could not be confirmed. Keep your draft and refresh task status.');
      }
    } finally {if (current()) setBusy(false);}
  }
  function load(): void {void run(async (signal, current) => {
    const value = await deviceActionContext(props.settings, props.goalId, signal);
    if (current()) {setContext(value); setReview(null); setUncertain(false); setMessage('Current task state loaded. Choose an action to review.');
      if (!value.answer.questions.some(row => String(row.id) === question)) setQuestion('');}
  });}
  function prepare(action: 'answer' | 'stop'): void {void run(async (signal, current) => {
    if (!context) return;
    const value = await prepareDeviceAction(props.settings, {goal_id: props.goalId, action,
      context: context.context, revision: context[action].revision,
      arguments: action === 'answer' ? {question, answer} : {}}, signal);
    if (current()) {setReview(value); setUncertain(false); setMessage('Review the complete change below, then explicitly confirm.');}
  });}
  function confirm(): void {void run(async (signal, current) => {
    if (!review) return;
    if (Date.now() >= review.expires_at * 1000) throw new Error('This review expired. Your draft is kept. Refresh and review the task again.');
    try {
      const outcome = await executeDeviceAction(props.settings, review.token, signal);
      if (current()) {
        setMessage(outcome.message);
        if (outcome.status !== 'unconfirmed') {
          if (review.action === 'answer') {setAnswer(''); setQuestion('');}
          setReview(null); setContext(null); setUncertain(false); props.onApplied();
        } else setUncertain(true);
      }
    } catch (failure) {if (current()) setUncertain(true); throw failure;}
  });}
  const disabled = busy || !props.online;
  const text = (value: unknown) => typeof value === 'string' ? value : JSON.stringify(value);
  return <View style={{padding: 16, gap: 8}}>
    <Text accessibilityRole="header" style={{color: theme.text, fontSize: 18}} accessibilityLanguage={messageLanguage("Reviewed task actions")}>{msg("Reviewed task actions")}</Text>
    <Text style={{color: theme.muted}} accessibilityLanguage="en">Answer one current question or request Stop. Other decisions and file evidence stay on the full dashboard. Offline copies cannot authorize an action; nothing is queued to send later.</Text>
    {!props.online ? <Text accessibilityRole="alert" style={{color: theme.warnText}} accessibilityLanguage="en">Actions are unavailable until the task refreshes online.</Text> : null}
    <Button label={msg("Load current task actions")} language={messageLanguage("Load current task actions")} disabled={disabled} kind="secondary" onPress={load} />
    {context && !review ? <>
      <Text style={{color: theme.text}}>{context.title}</Text>
      {context.answer.blocked ? <Text style={{color: theme.muted}}>{context.answer.blocked}</Text> : <>
        {context.answer.questions.map(row => <Button key={row.id} label={(question === String(row.id) ? 'Selected: ' : 'Answer: ') + row.question}
          kind="secondary" disabled={disabled} onPress={() => setQuestion(String(row.id))} />)}
        {context.answer.partial ? <Text style={{color: theme.muted}} accessibilityLanguage="en">Showing the first 20 questions. Open the full task for the rest.</Text> : null}
        <TextInput accessibilityLabel="Answer to the selected task question" multiline maxLength={12000} value={answer} editable={!disabled}
          onChangeText={setAnswer} style={{minHeight: 120, padding: 12, color: theme.text, borderColor: theme.border, borderWidth: 1}} />
        <Button label={msg("Review answer")} language={messageLanguage("Review answer")} disabled={disabled || !question || !answer.trim()} onPress={() => prepare('answer')} />
      </>}
      {context.stop.blocked ? <Text style={{color: theme.muted}}>{context.stop.blocked}</Text>
        : <Button label={msg("Review Stop request")} language={messageLanguage("Review Stop request")} kind="secondary" disabled={disabled} onPress={() => prepare('stop')} />}
    </> : null}
    {review ? <>
      <Text accessibilityRole="header" style={{color: theme.text, fontSize: 18}} accessibilityLanguage={messageLanguage("Review before confirming")}>{msg("Review before confirming")}</Text>
      <Text selectable style={{color: theme.text}}>{review.summary}</Text>
      {review.changes.map((change, index) => <Text key={index} selectable style={{color: theme.text}}>{change.label || change.field}: {text(change.after)}</Text>)}
      {uncertain ? <Text accessibilityRole="alert" style={{color: theme.warnText}} accessibilityLanguage="en">A reply was not confirmed. Checking or retrying uses this same reviewed request and its receipt; accepted work is not repeated.</Text> : null}
      <Button label={uncertain ? 'Check or retry reviewed action' : review.action === 'answer' ? 'Confirm answer' : 'Confirm Stop request'} disabled={disabled} onPress={confirm} />
      <Button label={msg("Return to draft")} language={messageLanguage("Return to draft")} kind="secondary" disabled={disabled} onPress={() => {setReview(null); setUncertain(false);}} />
    </> : null}
    {message ? <Text accessibilityLiveRegion="polite" style={{color: theme.muted}}>{message}</Text> : null}
    {error ? <Text accessibilityRole="alert" style={{color: theme.danger}}>{error}</Text> : null}
  </View>;
}
