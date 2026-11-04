/** Thin external-agent client: bounded owned deadlines, safe errors, no retries. */
export type RecoveryKind = "authentication" | "permission" | "rate_limit" | "stale" | "unavailable" | "unknown_effect" | "invalid_response";
export class LightworkRequestError extends Error {
  constructor(public readonly kind: RecoveryKind, public readonly status: number | null,
              public readonly retryAfterSeconds: number | null = null,
              public readonly requestId: string | null = null) {
    super(kind === "unknown_effect" ? "The request was not confirmed. Reconcile it before any new write." :
      `Lightwork request failed (${kind}); review access or retry guidance.`);
    this.name = "LightworkRequestError";
  }
}

export class Lightwork {
  private base: string;
  private headers: Record<string, string>;
  private owners = new Set<AbortController>();
  private disposed = false;

  constructor(baseUrl: string, token: string, private timeoutMs = 15000,
              private fetcher: typeof fetch = (input, init) => fetch(input, init)) {
    const url = new URL(baseUrl);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname.toLowerCase());
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
        (token && url.protocol !== "https:" && !local)) throw new Error("Use HTTPS for a remote authenticated dashboard.");
    if (!Number.isFinite(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) throw new Error("Request deadline must be between 100 and 120000 milliseconds.");
    this.base = url.href.replace(/\/+$/, "") + "/api/v1/external";
    this.headers = {Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json"};
  }

  dispose(): void {
    this.disposed = true;
    for (const owner of this.owners) owner.abort();
    this.owners.clear();
  }

  private async request(path: string, body?: unknown): Promise<Record<string, any>> {
    const write = body !== undefined;
    if (this.disposed) throw new LightworkRequestError("unavailable", null);
    const controller = new AbortController(); this.owners.add(controller);
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetcher(this.base + path, {method: write ? "POST" : "GET",
        headers: this.headers, body: write ? JSON.stringify(body) : undefined,
        signal: controller.signal, redirect: "error", cache: "no-store"});
      const rawId = response.headers.get("x-request-id");
      const requestId = rawId && /^[A-Za-z0-9_.:-]{1,128}$/.test(rawId) ? rawId : null;
      const retry = response.headers.get("retry-after");
      const seconds = retry && /^\d{1,6}$/.test(retry) ? Number(retry) : null;
      if (!response.ok) {
        const kind: RecoveryKind = response.status === 401 ? "authentication" : response.status === 403 ? "permission" :
          response.status === 429 ? "rate_limit" : response.status === 409 ? "stale" :
          write && response.status >= 500 ? "unknown_effect" : "unavailable";
        await response.body?.cancel();
        throw new LightworkRequestError(kind, response.status, seconds, requestId);
      }
      if (!response.body || Number(response.headers.get("content-length") || 0) > 1024 * 1024) {
        await response.body?.cancel();
        throw new LightworkRequestError(write ? "unknown_effect" : "invalid_response", response.status);
      }
      const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
      try {
        while (true) {
          const part = await reader.read(); if (part.done) break;
          size += part.value.byteLength;
          if (size > 1024 * 1024) throw new LightworkRequestError(write ? "unknown_effect" : "invalid_response", response.status);
          chunks.push(part.value);
        }
      } finally { await reader.cancel(); reader.releaseLock(); }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      const data: unknown = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
      if (!data || typeof data !== "object" || Array.isArray(data)) throw new LightworkRequestError(write ? "unknown_effect" : "invalid_response", response.status);
      return data as Record<string, any>;
    } catch (error) {
      if (error instanceof LightworkRequestError) throw error;
      // Never echo fetch errors, URLs, response bodies, arguments or credentials.
      throw new LightworkRequestError(write ? "unknown_effect" : "unavailable", null);
    } finally { clearTimeout(timer); this.owners.delete(controller); }
  }

  screen(tool: string, detail = "", risk = "low") { return this.request("/screen", {tool, detail, risk}); }
  report(title: string, outcome: "success" | "failure", fields: Record<string, unknown> = {}) {
    return this.request("/runs", {...fields, title, outcome});
  }
  start(title: string, fields: Record<string, unknown> = {}) { return this.request("/runs/start", {...fields, title}); }
  async heartbeat(goalId: number): Promise<boolean> { return (await this.request(`/runs/${goalId}/heartbeat`, {})).continue === true; }
  finish(goalId: number, outcome: "success" | "failure", fields: Record<string, unknown> = {}) {
    return this.request(`/runs/${goalId}/finish`, {...fields, outcome});
  }
  memoryIngest(kind: "success" | "failure" | "lesson", goalText: string, fields: Record<string, unknown> = {}) {
    return this.request("/memory/ingest", {...fields, kind, goal_text: goalText});
  }
  memoryRecall(query: string, domain = "") { return this.request("/memory/recall", {query, domain}); }
  approval(approvalId: number, bindingSha256: string) {
    return this.request(`/approvals/${approvalId}?` + new URLSearchParams({binding_sha256: bindingSha256}));
  }
}
