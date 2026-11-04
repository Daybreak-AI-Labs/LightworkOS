import {msg, messageLanguage, useLanguage, formattedTime} from "../language";
/* Tasks list — GET /api/v1/goals (newest first), polled every 10s.
 * Falls back to the cached offline bundle when the dashboard is unreachable. */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FlatList, Pressable, StyleSheet, Text, TextInput, View } from "react-native";

import { ApiError, BundleGoal, Goal, Settings, isAccessDenied, listGoals, searchGoals } from "../api";
import { ConnectionNotice } from "../components/ConnectionNotice";
import { Banner, Button, EmptyState, Loading, StatusPill } from "../components/ui";
import { statusLabel, taskTitle } from "../format";
import { offlineBanner, useCachedBundle } from "../offlineCache";
import { usePolling } from "../poll";
import { useTheme, type Palette } from "../theme";

const UNREADABLE = 'The task list changed in a way this app could not read. Refresh, or ask your administrator to update the dashboard.';

// Re-read the visible ID window so removed or newly inaccessible older rows do
// not survive in an append-only cache. Every cursor page is scoped by the server
// again; usePolling publishes a complete window only for its current generation.
// The server may leave scanned rows out of a page, so whether more remain and
// where to continue come from its continuation, not from the page's length.
async function readTaskWindow(settings: Settings, signal: AbortSignal, status: string,
  floor: number | null, extend: boolean): Promise<{rows: Goal[]; hasMore: boolean}> {
  const rows: Goal[] = [];
  let before: number | undefined, addedBelow = 0;
  while (true) {
    if (signal.aborted) throw new ApiError('Request cancelled.', undefined, 'cancelled');
    const reply = await listGoals(settings, 50, signal, 0, status, before);
    if (signal.aborted) throw new ApiError('Request cancelled.', undefined, 'cancelled');
    const page = reply?.goals;
    if (!Array.isArray(page) || page.length > 50) throw new ApiError(UNREADABLE, undefined, 'protocol');
    let previous = before ?? Infinity;
    for (const row of page) {
      if (!Number.isSafeInteger(row.id) || row.id <= 0 || row.id >= previous) throw new ApiError(UNREADABLE, undefined, 'protocol');
      previous = row.id;
    }
    for (const row of page) {
      const below = floor !== null && row.id < floor;
      if (rows.length >= 50 && (floor === null || below) && (!extend || addedBelow >= 50)) {
        return {rows, hasMore: true};
      }
      rows.push(row);
      if (below) addedBelow++;
    }
    // A dashboard from before ID cursors sends no Pagination-Next-Before-Id (it
    // may still send Has-More and Next-Offset, or nothing at all): a full page
    // then means more, continuing below the last row read. An empty page gives
    // that cursor nothing to stand on, so a continuation is truly missing.
    const more = reply.hasMore ?? page.length >= 50;
    if (!more) return {rows, hasMore: false};
    const cursor = reply.nextBeforeId ?? (page.length ? previous : null);
    if (cursor === null || !Number.isSafeInteger(cursor) || cursor <= 0 || cursor > previous || cursor >= (before ?? Infinity)) {
      throw new ApiError(UNREADABLE, undefined, 'protocol');
    }
    if (floor === null ? rows.length >= 50 : (extend ? addedBelow >= 50 : cursor <= floor)) return {rows, hasMore: true};
    before = cursor;
  }
}

export function RunsListScreen(props: {
  settings: Settings;
  onOpenRun: (id: number, title?: string) => void;
  onOpenSettings?: () => void;
  onNewTask?: () => void;
}): React.JSX.Element {
  useLanguage();
  const theme = useTheme(), styles = stylesFor(theme);
  const { settings, onOpenRun, onOpenSettings } = props;
  const [query, setQuery] = useState(''), [search, setSearch] = useState(''), [status, setStatus] = useState('');
  const window = useMemo(() => ({floor: null as number | null, expanding: false, busy: false, sequence: 0}), [settings, search, status]);
  const activeWindow = useRef<typeof window | null>(window); activeWindow.current = window;
  useEffect(() => {
    activeWindow.current = window;
    return () => { if (activeWindow.current === window) activeWindow.current = null; };
  }, [window]);
  const [pageState, setPageState] = useState({owner: window, loading: false, hasMore: true});
  const loadingMore = pageState.owner === window && pageState.loading;
  const hasMore = pageState.owner !== window || pageState.hasMore;
  const fetcher = useCallback(async (signal: AbortSignal): Promise<Goal[]> => {
    if (signal.aborted || activeWindow.current !== window) throw new ApiError('Request cancelled.', undefined, 'cancelled');
    if (search) return searchGoals(settings, search, signal);
    const sequence = ++window.sequence;
    window.busy = window.expanding;
    setPageState(previous => ({owner: window, loading: window.expanding, hasMore: previous.owner !== window || previous.hasMore}));
    try {
      const result = await readTaskWindow(settings, signal, status, window.floor, window.expanding);
      if (!signal.aborted && activeWindow.current === window && window.sequence === sequence) {
        window.floor = result.rows.at(-1)?.id ?? null;
        window.expanding = false;
        setPageState({owner: window, loading: false, hasMore: result.hasMore});
      }
      return result.rows;
    } catch (failure) {
      if (activeWindow.current === window && window.sequence === sequence
          && (isAccessDenied(failure) || (failure as {kind?: string})?.kind === 'unsupported')) {
        window.floor = null; window.expanding = false;
      }
      throw failure;
    } finally {
      if (activeWindow.current === window && window.sequence === sequence) {
        window.busy = false;
        setPageState(previous => ({owner: window, loading: false, hasMore: previous.owner !== window || previous.hasMore}));
      }
    }
  }, [settings, search, status, window]);
  const { data, error, accessDenied, unsupported, refresh, updatedAt } = usePolling<Goal[]>(fetcher, 10_000);
  useEffect(() => {
    if (error) {
      window.busy = false;
      setPageState(previous => ({owner: window, loading: false, hasMore: previous.owner !== window || previous.hasMore}));
    }
  }, [error, window]);
  function loadMore(): void {
    if (activeWindow.current !== window || window.busy || loadingMore || search || !data || !hasMore || accessDenied || unsupported) return;
    window.expanding = true; window.busy = true;
    setPageState({owner: window, loading: true, hasMore});
    refresh();
  }
  const cached = useCachedBundle(settings, Boolean(error && !data && !accessDenied && !unsupported));

  const offline = !data && cached;
  const rows: Goal[] = data
    ? data
    : cached
      ? cached.bundle.goals.map((g: BundleGoal) => ({
          id: g.id, status: g.status, title: g.title, result: g.result,
        }))
      : [];

  let empty: React.JSX.Element | null = null;
  if (!data && !error) empty = <Loading text="Loading tasks…" />;
  else if (data || offline) {
    empty = (
      <EmptyState
        title={search || status ? "No matching tasks" : "No tasks yet"}
        body={search || status ? "Try another search or status. Matching tasks may be outside the saved offline copy." : "Start a task here with its separately approved device permission, or on your dashboard. This list refreshes on its own."}
        actionLabel={msg("Refresh now")}
        onAction={refresh}
      />
    );
  }

  const header = <>
      {props.onNewTask ? <Button label="Start a new task" onPress={props.onNewTask} /> : null}
      <Text style={styles.heading} accessibilityRole="header" accessibilityLanguage={messageLanguage("Tasks")}>{msg("Tasks")}</Text>
      <TextInput style={styles.search} accessibilityLabel={msg("Search tasks")} placeholder="Search all task titles and results" value={query} onChangeText={setQuery} onSubmitEditing={() => setSearch(query.trim())} />
      <View style={styles.filters}>
        <Button label={msg("Search")} language={messageLanguage("Search")} onPress={() => setSearch(query.trim())} />
        <Button label={msg("Clear search")} language={messageLanguage("Clear search")} kind="secondary" onPress={() => {setQuery(''); setSearch('');}} />
        {['', 'active', 'blocked', 'done'].map(value => <Button key={value} label={(status === value ? 'Selected: ' : '') + (value ? statusLabel(value) : 'All statuses')} kind="secondary" onPress={() => setStatus(value)} />)}
      </View>
      {updatedAt ? <Text style={styles.sub}>Updated {formattedTime(updatedAt)}</Text> : null}
      {search ? <Banner text="Search shows up to 200 matches. Refine your search to find a specific task." /> : null}
      {offline && cached ? <Banner text={offlineBanner(cached)} /> : null}
      {error ? (
        <ConnectionNotice message={error} accessDenied={accessDenied} unsupported={unsupported}
          onRetry={refresh} onOpenSettings={accessDenied ? onOpenSettings : undefined} />
      ) : null}
      {error && data ? <Banner text="The list below may be out of date." /> : null}
    </>;
  return (
    <View style={styles.fill}>
      <FlatList
        maintainVisibleContentPosition={{minIndexForVisible: 0}}
        ListHeaderComponent={header}
        data={rows.filter(row => (!status || row.status === status) && (!offline || !search || `${row.title} ${row.result || ''}`.toLowerCase().includes(search.toLowerCase())))}
        keyExtractor={(g: Goal) => String(g.id)}
        ListEmptyComponent={empty}
        ListFooterComponent={!search && data && data.length > 0 && hasMore ? <Button label={loadingMore ? 'Loading older tasks…' : 'Load older tasks'} disabled={loadingMore} onPress={loadMore} /> : null}
        renderItem={({ item }: { item: Goal }) => (
          <Pressable
            style={styles.row}
            accessibilityRole="button"
            accessibilityLabel={`${taskTitle(item.title)}, ${statusLabel(item.status)}`}
            accessibilityHint="Opens this task's activity"
            onPress={() => onOpenRun(item.id, item.title)}
          >
            <View style={styles.fill}>
              <Text style={styles.title} numberOfLines={2}>{taskTitle(item.title)}</Text>
              <StatusPill status={item.status} />
              {item.result ? <Text style={styles.sub} numberOfLines={1}>{item.result}</Text> : null}
            </View>
            <Text style={styles.chevron} accessibilityElementsHidden importantForAccessibility="no">›</Text>
          </Pressable>
        )}
      />
    </View>
  );
}

const stylesFor = (theme: Palette) => StyleSheet.create({
  fill: { flex: 1, backgroundColor: theme.background },
  filters: {flexDirection: "row", flexWrap: "wrap", gap: 8, paddingHorizontal: 16},
  search: {margin: 12, padding: 12, borderWidth: 1, borderColor: theme.border, color: theme.text, minHeight: 48},
  heading: { fontSize: 22, fontWeight: "700", color: theme.text, paddingHorizontal: 16, paddingTop: 12, paddingBottom: 4 },
  row: {
    flexDirection: "row", alignItems: "center", gap: 10,
    paddingHorizontal: 16, paddingVertical: 12,
    borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: theme.border,
  },
  title: { fontSize: 15, fontWeight: "600", color: theme.text },
  sub: { fontSize: 13, color: theme.muted, marginTop: 4 },
  chevron: { fontSize: 22, color: theme.muted },
});
