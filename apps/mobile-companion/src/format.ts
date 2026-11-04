/* Plain-language labels for values the dashboard stores in code form.
 * Screens show these instead of raw status words, event kinds or ids. */
import {msg, messageLanguage, formatLocale} from './language';

const STATUS_LABELS: Record<string, string> = {
  active: "In progress",
  running: "In progress",
  pending: "Waiting to start",
  queued: "Waiting to start",
  blocked: "Needs attention",
  done: "Finished",
  completed: "Finished",
  failed: "Did not finish",
  error: "Did not finish",
  cancelled: "Stopped",
  canceled: "Stopped",
  loading: "Loading…",
};

const STATUS_TONES: Record<string, string> = {
  active: "#1a7f37",
  running: "#1a7f37",
  pending: "#9a6700",
  queued: "#9a6700",
  blocked: "#9a6700",
  done: "#57606a",
  completed: "#57606a",
  failed: "#cf222e",
  error: "#cf222e",
  cancelled: "#57606a",
  canceled: "#57606a",
};

const WORD_LABELS: Record<string, string> = {
  tool_call: "Used a tool",
  tool_result: "Tool result",
  llm: "Thinking",
  plan: "Plan",
  step: "Step",
  observation: "Noticed",
  error: "Problem",
  result: "Result",
  sla: "Deadline check",
  supervisor: "Supervisor",
  system: "Lightwork",
  probe: "Health check",
};

/** Turn a stored code word such as `tool_call` into "Tool call". */
export function humanize(value: string | null | undefined): string {
  const raw = String(value ?? "").trim();
  if (!raw) return "";
  const known = WORD_LABELS[raw.toLowerCase()];
  if (known) return known;
  const words = raw.replace(/[_\-.]+/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2").trim().toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function statusLabel(status: string | null | undefined): string {
  const key = String(status ?? "").toLowerCase();
  return STATUS_LABELS[key] ? msg(STATUS_LABELS[key]) : (humanize(key) || "Unknown");
}

export function statusLanguage(status: string): string {return messageLanguage(STATUS_LABELS[status.toLowerCase()] || '');}

export function statusTone(status: string | null | undefined): string {
  return STATUS_TONES[String(status ?? "").toLowerCase()] ?? "#57606a";
}

/** A task title for display; never falls back to a raw number. */
export function taskTitle(title: string | null | undefined): string {
  const text = String(title ?? "").trim();
  return text || "Untitled task";
}

export function money(dollars: number | null | undefined): string {
  const value = typeof dollars === "number" && Number.isFinite(dollars) ? dollars : 0;
  return new Intl.NumberFormat(formatLocale(), {style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 2}).format(value);
}

export function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** "just now", "5 minutes ago", "2 hours ago", "3 days ago". */
export function agoText(minutes: number): string {
  const m = Math.max(0, Math.round(minutes));
  if (m < 1) return "just now";
  if (m < 60) return `${plural(m, "minute", "minutes")} ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${plural(h, "hour", "hours")} ago`;
  return `${plural(Math.round(h / 24), "day", "days")} ago`;
}

/** The dashboard sends the latest step as "kind: text"; label the kind
 * plainly and keep the text as written. */
export function activityText(activity: string | null | undefined): string {
  const raw = String(activity ?? "").trim();
  const match = /^([a-z][a-z0-9_]*): ([\s\S]*)$/.exec(raw);
  if (match) return `${humanize(match[1])}: ${match[2]}`;
  return /^[a-z][a-z0-9_]*$/.test(raw) ? humanize(raw) : raw;
}
