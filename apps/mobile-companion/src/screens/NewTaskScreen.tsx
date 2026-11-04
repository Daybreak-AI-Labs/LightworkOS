import React, {useEffect, useState} from 'react';
import {ScrollView, StyleSheet, Text, TextInput, View} from 'react-native';
import {prepareWork, workContext, type Settings, type WorkContext, type WorkReview} from '../api';
import {useTheme} from '../theme';
import {Button} from '../components/ui';
import {ReviewCard, WorkHistory, useWorkRequest} from '../components/WorkReview';

export function NewTaskScreen(props: {settings: Settings; onBack: () => void}): React.JSX.Element {
  const theme = useTheme(), styles = StyleSheet.create({label: {color: theme.text, marginTop: 16}, input: {color: theme.text, padding: 12, borderWidth: 1, borderColor: theme.border, minHeight: 48}});
  const [current, setCurrent] = useState<WorkContext | null>(null), [review, setReview] = useState<WorkReview | null>(null);
  const [title, setTitle] = useState(''), [description, setDescription] = useState(''), [dollars, setDollars] = useState(''), [seconds, setSeconds] = useState(''), [depth, setDepth] = useState<number | null>(null), [validation, setValidation] = useState('');
  function clearAccess() {setCurrent(null); setReview(null); setTitle(''); setDescription(''); setDollars(''); setSeconds(''); setDepth(null); setValidation('');}
  const request = useWorkRequest(props.settings, clearAccess, () => {setCurrent(null); setReview(null);});
  useEffect(() => {clearAccess();}, [props.settings]);
  function refresh() {setReview(null); void request.run(signal => workContext(props.settings, 'start', 0, signal), setCurrent);}
  function number(text: string, label: string): number | null {
    if (!text.trim()) return null;
    if (!/^\d+(?:\.\d+)?$/.test(text.trim())) throw new Error(`Enter a nonnegative amount for ${label}, or leave it blank to use the workspace limit.`);
    const value = Number(text); if (!Number.isFinite(value)) throw new Error(`The ${label} amount is too large.`); return value;
  }
  function prepare() {
    if (!current || request.busy || current.blocked) return;
    setReview(null); setValidation('');
    try {
      const args = {title, description, max_dollars: number(dollars, 'maximum dollars'), max_wall_seconds: number(seconds, 'maximum seconds'), max_depth: depth};
      if (!title.trim() || title.length > 200 || description.length > 12000) throw new Error('Enter a task of at most 200 characters and instructions of at most 12,000 characters. Nothing will be shortened.');
      void request.run(signal => prepareWork(props.settings, 'start', current, args, 0, signal), setReview);
    } catch (failure) {setValidation(failure instanceof Error ? failure.message : 'Check the task and its limits.');}
  }
  function edit(change: () => void) {setReview(null); setValidation(''); change();}
  const choices = current?.fields.find(field => field.name === 'max_depth')?.choices || [];
  return <ScrollView contentContainerStyle={{padding: 16}} keyboardShouldPersistTaps="handled">
    <Button label="Back to tasks" kind="secondary" onPress={props.onBack} />
    <Text style={{color: theme.text, fontSize: 22}} accessibilityRole="header">Start a new task</Text>
    <Text style={{color: theme.muted}}>Online only. This device needs the separate permission to start your tasks. Current workspace limits and approvals still apply; there is no offline sending queue.</Text>
    <Button label="Check current access and limits" kind="secondary" disabled={request.busy} onPress={refresh} />
    {current ? <><Text style={{color: theme.text}}>{current.summary}</Text>{current.current_details?.map(row => <View key={row.label} style={{marginTop: 8}}><Text style={{color: theme.text, fontWeight: '700'}}>{row.label}</Text><Text style={{color: theme.text}}>{row.value}</Text></View>)}{current.blocked ? <Text accessibilityRole="alert" style={{color: theme.danger}}>{current.blocked}</Text> : null}
      <Text style={styles.label}>Task</Text><TextInput accessibilityLabel="Task" style={styles.input} value={title} editable={!request.busy} onChangeText={value => edit(() => setTitle(value))} />
      <Text style={styles.label}>Instructions (optional)</Text><TextInput accessibilityLabel="Instructions" style={[styles.input, {minHeight: 120}]} multiline value={description} editable={!request.busy} onChangeText={value => edit(() => setDescription(value))} />
      <Text style={styles.label}>Maximum dollars (blank uses workspace limit)</Text><TextInput accessibilityLabel="Maximum dollars" style={styles.input} keyboardType="decimal-pad" value={dollars} editable={!request.busy} onChangeText={value => edit(() => setDollars(value))} />
      <Text style={styles.label}>Maximum seconds (blank uses workspace limit)</Text><TextInput accessibilityLabel="Maximum seconds" style={styles.input} keyboardType="decimal-pad" value={seconds} editable={!request.busy} onChangeText={value => edit(() => setSeconds(value))} />
      <Text style={styles.label}>Levels of helpers</Text><View>{choices.map((choice, index) => <Button key={index} label={(depth === choice.value ? 'Selected: ' : '') + choice.label} kind="secondary" disabled={request.busy} onPress={() => edit(() => setDepth(choice.value as number | null))} />)}</View>
      <Button label="Review this task and its limits" disabled={request.busy || !!current.blocked} onPress={prepare} />
    </> : null}
    {request.error || validation ? <Text accessibilityRole="alert" style={{color: theme.danger}}>{request.error || validation}</Text> : null}
    {review ? <ReviewCard key={review.operation_id} settings={props.settings} review={review} onAccess={clearAccess} onInvalidate={() => {setCurrent(null); setReview(null);}} /> : null}
    <WorkHistory settings={props.settings} />
  </ScrollView>;
}
