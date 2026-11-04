/** Device UI preference only. Task text, output language and authority are unchanged. */
import {useEffect, useState} from 'react';
import {AppState} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

export type Language = 'en' | 'fr' | 'de' | 'ja' | 'zh' | 'ar';
export type LanguageChoice = 'system' | Language;
export const LANGUAGE_CHOICES: {value: LanguageChoice; label: string}[] = [
  {value: 'system', label: 'Follow device'}, {value: 'en', label: 'English'},
  {value: 'fr', label: 'Français'}, {value: 'de', label: 'Deutsch'},
  {value: 'ja', label: '日本語'}, {value: 'zh', label: '中文'}, {value: 'ar', label: 'العربية'},
];
// Draft native control catalogs. English fallback is explicit; no language is
// advertised as a fully reviewed native journey. Arabic remains community-only.
const CATALOG: Record<string, Partial<Record<Language, string>>> = {
  'Tasks': {fr:'Tâches',de:'Aufgaben',ja:'タスク',zh:'任务'},
  'Overview': {fr:'Vue d’ensemble',de:'Übersicht',ja:'概要',zh:'概览'},
  'Settings': {fr:'Paramètres',de:'Einstellungen',ja:'設定',zh:'设置'},
  'Connect to Lightwork': {fr:'Se connecter à Lightwork',de:'Mit Lightwork verbinden',ja:'Lightwork に接続',zh:'连接 Lightwork'},
  'Loading.': {fr:'Chargement.',de:'Wird geladen.',ja:'読み込み中。',zh:'正在加载。'},
  'Search': {fr:'Rechercher',de:'Suchen',ja:'検索',zh:'搜索'},
  'Search tasks': {fr:'Rechercher des tâches',de:'Aufgaben suchen',ja:'タスクを検索',zh:'搜索任务'},
  'Clear search': {fr:'Effacer la recherche',de:'Suche löschen',ja:'検索をクリア',zh:'清除搜索'},
  'Refresh now': {fr:'Actualiser',de:'Jetzt aktualisieren',ja:'今すぐ更新',zh:'立即刷新'},
  'Try again': {fr:'Réessayer',de:'Erneut versuchen',ja:'再試行',zh:'重试'},
  'Check settings': {fr:'Vérifier les paramètres',de:'Einstellungen prüfen',ja:'設定を確認',zh:'检查设置'},
  'Retry loading settings': {fr:'Recharger les paramètres',de:'Einstellungen erneut laden',ja:'設定を再読み込み',zh:'重新加载设置'},
  'In progress': {fr:'En cours',de:'In Bearbeitung',ja:'進行中',zh:'进行中'},
  'Waiting to start': {fr:'En attente de démarrage',de:'Wartet auf Start',ja:'開始待ち',zh:'等待开始'},
  'Needs attention': {fr:'À vérifier',de:'Benötigt Aufmerksamkeit',ja:'対応が必要',zh:'需要处理'},
  'Finished': {fr:'Terminée',de:'Abgeschlossen',ja:'完了',zh:'已完成'},
  'Did not finish': {fr:'Non terminée',de:'Nicht abgeschlossen',ja:'未完了',zh:'未完成'},
  'Stopped': {fr:'Arrêtée',de:'Gestoppt',ja:'停止済み',zh:'已停止'},
  'All statuses': {fr:'Tous les états',de:'Alle Status',ja:'すべての状態',zh:'所有状态'},
  'No tasks yet': {fr:'Aucune tâche pour le moment',de:'Noch keine Aufgaben',ja:'タスクはまだありません',zh:'暂无任务'},
  'No matching tasks': {fr:'Aucune tâche correspondante',de:'Keine passenden Aufgaben',ja:'該当するタスクはありません',zh:'没有匹配的任务'},
  'Load older tasks': {fr:'Charger les tâches précédentes',de:'Ältere Aufgaben laden',ja:'以前のタスクを読み込む',zh:'加载更早的任务'},
  'Task details': {fr:'Détails de la tâche',de:'Aufgabendetails',ja:'タスクの詳細',zh:'任务详情'},
  'Activity': {fr:'Activité',de:'Aktivität',ja:'アクティビティ',zh:'活动'},
  'Outcome': {fr:'Résultat',de:'Ergebnis',ja:'結果',zh:'结果'},
  'Open full task on dashboard': {fr:'Ouvrir la tâche dans le tableau de bord',de:'Aufgabe im Dashboard öffnen',ja:'ダッシュボードでタスクを開く',zh:'在仪表板打开完整任务'},
  'Saved connections': {fr:'Connexions enregistrées',de:'Gespeicherte Verbindungen',ja:'保存された接続',zh:'已保存的连接'},
  'Dashboard address': {fr:'Adresse du tableau de bord',de:'Dashboard-Adresse',ja:'ダッシュボードのアドレス',zh:'仪表板地址'},
  'Connection name': {fr:'Nom de la connexion',de:'Verbindungsname',ja:'接続名',zh:'连接名称'},
  'Add another connection': {fr:'Ajouter une connexion',de:'Weitere Verbindung hinzufügen',ja:'接続を追加',zh:'添加其他连接'},
  'Remove this saved connection': {fr:'Supprimer cette connexion enregistrée',de:'Gespeicherte Verbindung entfernen',ja:'この保存済み接続を削除',zh:'移除此已保存连接'},
  'Appearance on this device': {fr:'Apparence sur cet appareil',de:'Darstellung auf diesem Gerät',ja:'この端末の表示',zh:'此设备的外观'},
  'Follow device': {fr:'Suivre l’appareil',de:'Geräteeinstellung verwenden',ja:'端末の設定に従う',zh:'跟随设备'},
  'Light': {fr:'Clair',de:'Hell',ja:'ライト',zh:'浅色'},
  'Dark': {fr:'Sombre',de:'Dunkel',ja:'ダーク',zh:'深色'},
  'Language and regional formats': {fr:'Langue et formats régionaux',de:'Sprache und regionale Formate',ja:'言語と地域の表示形式',zh:'语言和区域格式'},
  'Save connection': {fr:'Enregistrer la connexion',de:'Verbindung speichern',ja:'接続を保存',zh:'保存连接'},
  'Test connection': {fr:'Tester la connexion',de:'Verbindung testen',ja:'接続をテスト',zh:'测试连接'},
  'Start device pairing': {fr:'Associer cet appareil',de:'Gerät koppeln',ja:'端末のペアリングを開始',zh:'开始设备配对'},
  'Check approval': {fr:'Vérifier l’approbation',de:'Freigabe prüfen',ja:'承認を確認',zh:'检查批准状态'},
  'Renew paired connection': {fr:'Renouveler la connexion associée',de:'Gekoppelte Verbindung erneuern',ja:'ペアリング済み接続を更新',zh:'续期已配对连接'},
  'Cancel': {fr:'Annuler',de:'Abbrechen',ja:'キャンセル',zh:'取消'},
  'Reviewed task actions': {fr:'Actions de tâche à confirmer',de:'Geprüfte Aufgabenaktionen',ja:'確認付きタスク操作',zh:'需确认的任务操作'},
  'Load current task actions': {fr:'Charger les actions actuelles',de:'Aktuelle Aufgabenaktionen laden',ja:'現在のタスク操作を読み込む',zh:'加载当前任务操作'},
  'Review answer': {fr:'Vérifier la réponse',de:'Antwort prüfen',ja:'回答を確認',zh:'检查回答'},
  'Review Stop request': {fr:'Vérifier la demande d’arrêt',de:'Stopp-Anfrage prüfen',ja:'停止リクエストを確認',zh:'检查停止请求'},
  'Review before confirming': {fr:'Vérifier avant de confirmer',de:'Vor dem Bestätigen prüfen',ja:'確定する前に確認',zh:'确认前请检查'},
  'Confirm answer': {fr:'Confirmer la réponse',de:'Antwort bestätigen',ja:'回答を確定',zh:'确认回答'},
  'Confirm Stop request': {fr:'Confirmer la demande d’arrêt',de:'Stopp-Anfrage bestätigen',ja:'停止リクエストを確定',zh:'确认停止请求'},
  'Return to draft': {fr:'Revenir au brouillon',de:'Zum Entwurf zurückkehren',ja:'下書きに戻る',zh:'返回草稿'},
};
const KEY = 'lightwork.display.language.v1';
let selected: LanguageChoice = 'system', loaded = false, error = '';
let loading: Promise<void> | null = null, writing: Promise<void> = Promise.resolve();
const listeners = new Set<() => void>();
let lifecycle: {remove: () => void} | null = null;
const valid = (value: unknown): value is LanguageChoice => LANGUAGE_CHOICES.some(row => row.value === value);
function changed(): void {listeners.forEach(listener => listener());}
export function currentLanguage(): Language {
  if (selected !== 'system') return selected;
  const device = Intl.DateTimeFormat().resolvedOptions().locale.split(/[-_]/)[0].toLowerCase();
  return valid(device) && device !== 'system' ? device : 'en';
}
export function formatLocale(): string {
  return selected === 'system' ? Intl.DateTimeFormat().resolvedOptions().locale : selected;
}
export function messageLanguage(source: string): Language {
  const locale = currentLanguage();
  return CATALOG[source]?.[locale] ? locale : 'en';
}
export function msg(source: string): string {return CATALOG[source]?.[currentLanguage()] || source;}
async function load(): Promise<void> {
  if (loaded) return;
  if (!loading) loading = AsyncStorage.getItem(KEY).then(value => {
    if (value !== null && !valid(value)) throw Error('Invalid language');
    selected = value === null ? 'system' : value; error = '';
  }).catch(() => {error = 'Saved language could not be read. Following device formats until you choose again.';})
    .finally(() => {loaded = true; loading = null; changed();});
  await loading;
}
export function saveLanguage(value: LanguageChoice): Promise<void> {
  if (!valid(value)) return Promise.reject(Error('Choose an available language.'));
  const operation = writing.then(async () => {await load(); await AsyncStorage.setItem(KEY, value); selected = value; error = ''; changed();});
  writing = operation.catch(() => undefined); return operation;
}
export function useLanguage(): {value: LanguageChoice; language: Language; error: string} {
  const [, render] = useState(0);
  useEffect(() => {const listener = () => render(value => value + 1); listeners.add(listener); void load();
    if (!lifecycle) lifecycle = AppState.addEventListener('change', state => {if (state === 'active' && selected === 'system') changed();});
    return () => {listeners.delete(listener); if (!listeners.size) {lifecycle?.remove(); lifecycle = null;}};}, []);
  return {value: selected, language: currentLanguage(), error};
}
export function formattedTime(value: number): string {
  return new Intl.DateTimeFormat(formatLocale(), {hour: 'numeric', minute: '2-digit'}).format(value);
}
export function formattedDateTime(value: number): string {
  return new Intl.DateTimeFormat(formatLocale(), {dateStyle: 'medium', timeStyle: 'short'}).format(value);
}
export function formattedNumber(value: number): string {return new Intl.NumberFormat(formatLocale()).format(value);}
