import React, {useEffect, useState} from 'react';
import {ScrollView, Switch, Text, TextInput, View} from 'react-native';
import {ownedApprovals, prepareWork, workContext, type OwnedApprovals, type Settings, type WorkAction, type WorkContext, type WorkReview} from '../api';
import {useTheme} from '../theme';
import {Button} from '../components/ui';
import {DashboardLink, ReviewCard, WorkHistory, useWorkRequest} from '../components/WorkReview';

export function ApprovalsScreen(props: {settings: Settings}): React.JSX.Element {
  const theme = useTheme(), [list, setList] = useState<OwnedApprovals | null>(null), [selected, setSelected] = useState<number | null>(null);
  const [action, setAction] = useState<WorkAction>('approve'), [current, setCurrent] = useState<WorkContext | null>(null), [review, setReview] = useState<WorkReview | null>(null);
  const [acknowledged, setAcknowledged] = useState(false), [confirmation, setConfirmation] = useState(''), [reason, setReason] = useState('');
  function clearAccess() {setList(null); setSelected(null); setCurrent(null); setReview(null); setAcknowledged(false); setConfirmation(''); setReason('');}
  const request = useWorkRequest(props.settings, clearAccess, () => {setList(null); setSelected(null); setCurrent(null); setReview(null); setAcknowledged(false); setConfirmation('');});
  useEffect(() => {clearAccess();}, [props.settings]);
  function refresh(before = 0) {setReview(null); setCurrent(null); setSelected(null); setAcknowledged(false); setConfirmation(''); void request.run(signal => ownedApprovals(props.settings, before, signal), value => {setList(value);});}
  function choose(identifier: number, nextAction: WorkAction) {
    setReview(null); setCurrent(null); setSelected(identifier); setAction(nextAction); setAcknowledged(false); setConfirmation('');
    void request.run(signal => workContext(props.settings, nextAction, identifier, signal), setCurrent);
  }
  function prepare() {
    if (!current || !selected || current.blocked || request.busy) return;
    setReview(null);
    const args = action === 'approve' ? {acknowledged, confirmation} : {reason};
    void request.run(signal => prepareWork(props.settings, action, current, args, selected, signal), setReview);
  }
  const typed = current?.fields.some(field => field.name === 'confirmation');
  return <ScrollView contentContainerStyle={{padding: 16}} keyboardShouldPersistTaps="handled">
    <Text style={{color: theme.text, fontSize: 22}} accessibilityRole="header">Your task requests</Text>
    <Text style={{color: theme.muted}}>Online only, with a separate device permission. Review every detail before recording approval or rejection. These are decisions about permission; they do not prove execution.</Text>
    <Button label="Load current task requests" kind="secondary" disabled={request.busy} onPress={() => refresh()} />
    {list ? <><Text style={{color: theme.muted}}>{list.notice}</Text>{list.items.map(row => <View key={row.id} style={{marginTop: 16, borderBottomWidth: 1, borderColor: theme.border}}>
      <Text style={{color: theme.text, fontWeight: '700'}}>{row.task_title}</Text><Text style={{color: theme.text}}>{row.action}</Text>
      <Button label="Review approval" disabled={request.busy} onPress={() => choose(row.id, 'approve')} /><Button label="Review rejection" kind="secondary" disabled={request.busy} onPress={() => choose(row.id, 'reject')} />
    </View>)}{!list.items.length ? <Text style={{color: theme.muted}}>{list.complete ? 'There are no currently visible requests in this part of your task list.' : 'No visible requests in this part. Older requests remain unchecked.'}</Text> : null}
      {!list.complete ? <Button label="Read older task requests" kind="secondary" disabled={request.busy} onPress={() => refresh(list.before_id)} /> : <Text style={{color: theme.muted}}>Reached the end of your current retained task requests.</Text>}
    </> : null}
    {current ? <View style={{marginTop: 16}}><Text style={{color: theme.text}}>{current.summary}</Text>{current.blocked ? <Text style={{color: theme.danger}}>{current.blocked}</Text> : null}
      {action === 'approve' ? <><View style={{flexDirection: 'row', alignItems: 'center'}}><Switch accessibilityLabel="I will review the complete request and its consequences" value={acknowledged} disabled={request.busy} onValueChange={value => {setReview(null); setAcknowledged(value);}} /><Text style={{color: theme.text, flex: 1}}>I will review the complete request and its consequences</Text></View>
        {typed ? <><Text style={{color: theme.text}}>This is a critical action. Type APPROVE to confirm.</Text><TextInput accessibilityLabel="Critical approval confirmation" value={confirmation} editable={!request.busy} onChangeText={value => {setReview(null); setConfirmation(value);}} style={{padding: 12, color: theme.text, borderWidth: 1, borderColor: theme.border}} /></> : null}
      </> : <><Text style={{color: theme.text}}>Why are you rejecting it? (optional)</Text><TextInput accessibilityLabel="Rejection reason" multiline value={reason} editable={!request.busy} onChangeText={value => {setReview(null); setReason(value);}} style={{minHeight: 100, padding: 12, color: theme.text, borderWidth: 1, borderColor: theme.border}} /></>}
      <Button label="Prepare complete review" disabled={request.busy || !!current.blocked || (action === 'approve' && (!acknowledged || (!!typed && confirmation.trim().toLowerCase() !== 'approve'))) || (action === 'reject' && reason.length > 2000)} onPress={prepare} />
      {action === 'reject' && reason.length > 2000 ? <Text style={{color: theme.danger}}>Use a reason of at most 2,000 characters. Nothing will be shortened.</Text> : null}
    </View> : null}
    {request.error ? <Text accessibilityRole="alert" style={{color: theme.danger}}>{request.error}</Text> : null}
    {review ? <ReviewCard key={review.operation_id} settings={props.settings} review={review} onAccess={clearAccess} onInvalidate={() => {setList(null); setSelected(null); setCurrent(null); setReview(null); setAcknowledged(false); setConfirmation('');}} /> : null}
    <DashboardLink settings={props.settings} path="/approvals" label="Open other approvals on the dashboard" />
    <Text style={{color: theme.muted}}>Copied conversations and approval types outside your own tasks need their complete protected dashboard review.</Text>
    <WorkHistory settings={props.settings} />
  </ScrollView>;
}
