/* Online reviewed work only. Submitting once changes this card to original-read
 * mode even when transport fails; durable attempt history lives on the dashboard. */
import React, {useCallback, useEffect, useRef, useState} from 'react';
import {AppState, Linking, Switch, Text, View} from 'react-native';
import {executeWork, isAccessDenied, readWorkOriginal, workHistory, type Settings, type WorkHistory as History, type WorkOutcome, type WorkReview as Review} from '../api';
import {useTheme} from '../theme';
import {Button} from './ui';

const names: Record<string, string> = {goal_id: 'Task number', status: 'Task state recorded with this reply', label: 'Next step', state: 'Setting', request_schema: 'Request format', request_sha256: 'Recorded request fingerprint', schema: 'Record format', binding_sha256: 'Recorded evidence fingerprint'};
function readable(value: unknown): string {
  let remaining = 8192;
  function visit(part: unknown, depth: number): string {
    if (--remaining < 0 || depth > 12) throw new Error('This complete review is too large for this phone. Open its protected dashboard review; nothing can be confirmed here.');
    if (part === null) return 'None';
    if (typeof part === 'string') return ({resolved_again_at_execution: 'Checked again when work starts', governed_again_at_execution: 'Current spending controls apply when work starts', pending: 'Waiting to start', draft: 'Retained; admission not confirmed', active: 'In progress', done: 'Complete', failed: 'Failed', cancelled: 'Stopped'} as Record<string, string>)[part] || part;
    if (typeof part === 'boolean') return part ? 'Yes' : 'No';
    if (typeof part === 'number' && Number.isFinite(part)) return String(part);
    if (Array.isArray(part)) return part.length ? part.map(item => visit(item, depth + 1)).join('\n') : 'None';
    if (part && typeof part === 'object') return Object.entries(part).filter(([label]) => label !== 'href' && !['schema', 'request_schema', 'request_sha256', 'binding_sha256'].includes(label)).map(([label, item]) => `${names[label] || label.replaceAll('_', ' ')}: ${visit(item, depth + 1)}`).join('\n') || 'None';
    throw new Error('The complete review could not be displayed. Open the protected dashboard review instead.');
  }
  return visit(value, 0);
}

export function useWorkRequest(settings: Settings, onAccess?: () => void, onInactive?: () => void) {
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const epoch = useRef(0), pending = useRef(false), mounted = useRef(true), controller = useRef<AbortController | null>(null);
  const access = useRef(onAccess); access.current = onAccess;
  const inactive = useRef(onInactive); inactive.current = onInactive;
  const clear = useCallback(() => {epoch.current += 1; controller.current?.abort(); pending.current = false; setBusy(false); setError('');}, []);
  useEffect(() => {clear();}, [settings.baseUrl, settings.token, settings.cacheScope, clear]);
  useEffect(() => {
    mounted.current = true;
    const subscription = AppState.addEventListener('change', state => {if (state !== 'active') {clear(); inactive.current?.();}});
    return () => {mounted.current = false; epoch.current += 1; controller.current?.abort(); subscription.remove();};
  }, [clear]);
  async function run<T>(request: (signal: AbortSignal) => Promise<T>, apply: (value: T) => void): Promise<void> {
    if (pending.current) return;
    pending.current = true; setBusy(true); setError('');
    const generation = ++epoch.current, aborter = new AbortController(); controller.current = aborter;
    const current = () => mounted.current && epoch.current === generation && !aborter.signal.aborted;
    try {const value = await request(aborter.signal); if (current()) apply(value);}
    catch (failure) {if (current()) {if (isAccessDenied(failure)) access.current?.(); setError(failure instanceof Error ? failure.message : 'The dashboard could not confirm this request.');}}
    finally {if (current()) {pending.current = false; setBusy(false);}}
  }
  return {busy, error, run, clear};
}

export function ReviewCard(props: {settings: Settings; review: Review; onAccess: () => void; onInvalidate: () => void; onSubmitted?: () => void}): React.JSX.Element {
  const theme = useTheme(), [accepted, setAccepted] = useState(false), [submitted, setSubmitted] = useState(false);
  const [expired, setExpired] = useState(false), [outcome, setOutcome] = useState<WorkOutcome | null>(null);
  const request = useWorkRequest(props.settings, props.onAccess, props.onInvalidate);
  useEffect(() => {
    setAccepted(false); setSubmitted(false); setOutcome(null); request.clear();
    function tick() {setExpired(Date.now() >= props.review.expires_at * 1000);}
    tick(); const timer = setInterval(tick, 1000); return () => clearInterval(timer);
  }, [props.review.token]);
  let rows: {label: string; text: string; verification: boolean}[] = [], refusal = '';
  const [detailsOpen, setDetailsOpen] = useState(false);
  try {
    if (!Array.isArray(props.review.changes) || props.review.changes.length > 2048) throw new Error('This full review cannot be shown here. Use the dashboard instead.');
    rows = props.review.changes.map(row => {
      const label = row.label || row.field;
      if (!label || Object.keys(row).some(key => !['label', 'field', 'before', 'after'].includes(key))) throw new Error('This full review has changed. Refresh it before confirming.');
      return {label, verification: label === "Recorded connection versions", text: 'before' in row && 'after' in row ? `Current: ${readable(row.before)}\nProposed: ${readable(row.after)}` : readable('after' in row ? row.after : row.before)};
    });
  } catch (error) {refusal = error instanceof Error ? error.message : 'The full review is unavailable.';}
  function submit(): void {
    if (!accepted || submitted || expired || request.busy || refusal) return;
    setSubmitted(true); setAccepted(false); props.onSubmitted?.();
    void request.run(signal => executeWork(props.settings, props.review, signal), setOutcome);
  }
  return <View style={{padding: 16, borderWidth: 1, borderColor: theme.border, marginVertical: 16}}>
    <Text style={{color: theme.text, fontSize: 18}} accessibilityRole="header">Review the complete request</Text>
    <Text style={{color: theme.text}}>{props.review.summary}</Text>
    {rows.filter(row => !row.verification || detailsOpen).map((row, index) => <View key={index} style={{marginTop: 12}}><Text style={{color: theme.text, fontWeight: '700'}}>{row.label}</Text><Text selectable style={{color: theme.text}}>{row.text}</Text></View>)}
    {rows.some(row => row.verification) ? <Button label={detailsOpen ? "Hide recorded verification details" : "Show recorded verification details"} kind="secondary" onPress={() => setDetailsOpen(!detailsOpen)} /> : null}
    {refusal ? <Text accessibilityRole="alert" style={{color: theme.danger}}>{refusal}</Text> : null}
    {!submitted ? <><Text style={{color: theme.muted}}>Decide before {new Date(props.review.expires_at * 1000).toLocaleString()}. Approval is permission, not proof that an action ran.</Text>
      <View style={{flexDirection: 'row', alignItems: 'center'}}><Switch accessibilityLabel="I have read the complete request and confirm this choice" value={accepted} disabled={request.busy || expired || !!refusal} onValueChange={setAccepted} /><Text style={{color: theme.text, flex: 1}}>I have read the complete request and confirm this choice</Text></View>
      <Button label={props.review.action === 'start' ? 'Start this task' : props.review.action === 'approve' ? 'Record my approval' : 'Record my rejection'} disabled={!accepted || request.busy || expired || !!refusal} onPress={submit} />
      {expired ? <Text style={{color: theme.danger}}>This review expired. Refresh and prepare a new complete review.</Text> : null}</> : <>
      <Text style={{color: theme.muted}}>This original was submitted once. If its reply is missing, read the original; this button never starts another task or vote.</Text>
      <Button label="Read original result" kind="secondary" disabled={request.busy} onPress={() => {void request.run(signal => readWorkOriginal(props.settings, props.review.operation_id, signal), setOutcome);}} />
    </>}
    {request.error ? <Text style={{color: theme.danger}} accessibilityRole="alert">{request.error}{submitted ? ' The effect may already exist. Read the original result; do not submit this again.' : ''}</Text> : null}
    {outcome ? <OutcomeView settings={props.settings} outcome={outcome} /> : null}
  </View>;
}

function OutcomeView(props: {settings: Settings; outcome: WorkOutcome}): React.JSX.Element {
  const theme = useTheme();
  const [showReference, setShowReference] = useState(false);
  const details = Object.fromEntries(Object.entries(props.outcome.details).filter(([key]) => key !== 'task' && (showReference || key !== 'Decision reference')));
  let text = ''; try {text = readable(details);} catch {text = 'Open the protected dashboard for the complete original details.';}
  const task = props.outcome.details.task as {href?: string} | undefined;
  return <View><Text accessibilityLiveRegion="polite" style={{color: theme.text}}>{props.outcome.message}</Text><Text selectable style={{color: theme.text}}>{text}</Text>
    {"Decision reference" in props.outcome.details ? <Button label={showReference ? "Hide original verification reference" : "Show original verification reference"} kind="secondary" onPress={() => setShowReference(!showReference)} /> : null}
    {task?.href && /^\/chat\/goal\/[1-9][0-9]*$/.test(task.href) ? <DashboardLink settings={props.settings} path={task.href} label="Open task progress" /> : null}</View>;
}

export function DashboardLink(props: {settings: Settings; path: string; label: string}): React.JSX.Element {
  const theme = useTheme(), request = useWorkRequest(props.settings);
  function open() {
    void request.run(async () => {
      try {await Linking.openURL(props.settings.baseUrl.replace(/\/+$/, '') + props.path);}
      catch {throw new Error('The dashboard page could not be opened. Use the button to try again.');}
    }, () => {});
  }
  return <View><Button label={request.error ? 'Try opening this dashboard page again' : props.label} kind="secondary" disabled={request.busy} onPress={open} />
    {request.error ? <Text accessibilityRole="alert" style={{color: theme.danger}}>{request.error}</Text> : null}</View>;
}

export function WorkHistory(props: {settings: Settings}): React.JSX.Element {
  const theme = useTheme(), [history, setHistory] = useState<History | null>(null), [result, setResult] = useState<WorkOutcome | null>(null);
  const request = useWorkRequest(props.settings, () => {setHistory(null); setResult(null);}, () => {setHistory(null); setResult(null);});
  useEffect(() => {setHistory(null); setResult(null);}, [props.settings]);
  return <View style={{marginTop: 24}}><Text style={{color: theme.text, fontSize: 18}} accessibilityRole="header">Earlier submitted requests</Text>
    <Text style={{color: theme.muted}}>Available online after reopening this app. Unknown outcomes remain unknown and are never repeated by reading them.</Text>
    <Button label="Load earlier requests" kind="secondary" disabled={request.busy} onPress={() => {setResult(null); void request.run(signal => workHistory(props.settings, signal), setHistory);}} />
    {history ? <><Text style={{color: theme.muted}}>{history.notice}</Text>{history.items.map(row => <Button key={row.operation} label={`${row.label} · ${new Date(row.at * 1000).toLocaleString()}`} kind="secondary" disabled={request.busy} onPress={() => {setResult(null); void request.run(signal => readWorkOriginal(props.settings, row.operation, signal), setResult);}} />)}{history.items.length === 0 ? <Text style={{color: theme.muted}}>No earlier requests were retained for this device.</Text> : null}</> : null}
    {request.error ? <Text accessibilityRole="alert" style={{color: theme.danger}}>{request.error}</Text> : null}
    {result ? <OutcomeView settings={props.settings} outcome={result} /> : null}
  </View>;
}
