import type { ClientRequest, IncomingMessage } from "http";
import { StringDecoder } from "string_decoder";
import type { GoalEventsResponse } from "./generated/dashboard-contracts";

type Options = {
  url: URL;
  headers: Record<string, string>;
  cursor: number;
  connect: typeof import("http").get;
  onEvent: (data: string) => void;
  onCursor: (cursor: number) => void;
  onNotice: (message: string) => void;
  onStop: (reason: string, terminal: boolean) => void;
};

/** Consent cannot override the authenticated HTTPS-or-loopback boundary. */
export function assertDashboardTransport(url: URL, authenticated: boolean): void {
  const local = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname.toLowerCase());
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password ||
      (authenticated && url.protocol !== "https:" && !local)) {
    throw new Error("Use HTTPS for a remote dashboard with an access token, or an HTTP loopback address for this computer. Address consent cannot override this rule.");
  }
}

/** One owner for connection, retry and idle deadlines, including disposal. */
export function watchEvents(options: Options): () => void {
  let stopped = false, ticket = 0, cursor = options.cursor, backoff = 1000;
  let request: ClientRequest | null = null, response: IncomingMessage | null = null;
  let connecting: ReturnType<typeof setTimeout> | undefined;
  let idle: ReturnType<typeof setTimeout> | undefined;
  let retry: ReturnType<typeof setTimeout> | undefined;

  function closeConnection() {
    ticket++;
    clearTimeout(connecting); clearTimeout(idle);
    const req = request, res = response;
    request = null; response = null;
    res?.destroy(); req?.destroy();
  }
  function stop(reason: string, terminal = false) {
    if (stopped) return;
    stopped = true;
    clearTimeout(retry); retry = undefined;
    closeConnection();
    options.onStop(reason, terminal);
  }
  function reconnect(reason: string) {
    if (stopped || retry !== undefined) return;
    closeConnection();
    options.onNotice(`${reason}; reconnecting from event ${cursor} in ${backoff / 1000}s`);
    retry = setTimeout(() => { retry = undefined; connect(); }, backoff);
    backoff = Math.min(backoff * 2, 30000);
  }
  function connect() {
    if (stopped) return;
    try { assertDashboardTransport(options.url, Object.entries(options.headers).some(([name, value]) => name.toLowerCase() === "authorization" && Boolean(value))); }
    catch (error) { stop(error instanceof Error ? error.message : "Dashboard transport is not permitted."); return; }
    const mine = ++ticket;
    const url = new URL(options.url);
    url.searchParams.set("since", String(cursor));
    const headers = {...options.headers, Accept: "text/event-stream", "Last-Event-ID": String(cursor)};
    connecting = setTimeout(() => { if (mine === ticket) reconnect("connection timed out"); }, 10000);
    const armIdle = () => {
      clearTimeout(idle);
      idle = setTimeout(() => { if (mine === ticket) reconnect("stream heartbeat timed out"); }, 45000);
    };
    try { request = options.connect(url, {headers}, res => {
      if (stopped || mine !== ticket) { res.destroy(); return; }
      response = res;
      clearTimeout(connecting);
      const status = res.statusCode ?? 0;
      if (status !== 200) {
        res.resume();
        if (status === 429 || status >= 500) reconnect(`HTTP ${status}`);
        else stop(`Stream refused: HTTP ${status}. Check the run, sign-in and permissions.`);
        return;
      }
      if (!String(res.headers["content-type"] || "").toLowerCase().startsWith("text/event-stream")) {
        stop("Dashboard returned an unsupported stream response."); return;
      }
      let buffer = "";
      const decoder = new StringDecoder("utf8");
      armIdle();
      res.on("data", (chunk: Buffer) => {
        if (stopped || mine !== ticket) return;
        armIdle();
        buffer = (buffer + decoder.write(chunk)).replace(/\r\n/g, "\n");
        let end;
        while ((end = buffer.indexOf("\n\n")) >= 0) {
          const frame = buffer.slice(0, end); buffer = buffer.slice(end + 2);
          if (frame.length > 262144) { stop("Stream event exceeds the client bound."); return; }
          let event = "message", id = "";
          const data: string[] = [];
          for (const line of frame.split("\n")) {
            if (line.startsWith("event:")) event = line.slice(6).trim();
            else if (line.startsWith("id:")) id = line.slice(3).trim();
            else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
          }
          if (!data.length) continue; // heartbeat comments refresh idle only
          if (event === "timeout") { reconnect("stream lifetime reached"); return; }
          if (event === "error" && !id) { stop("Run visibility changed or its stream is unavailable."); return; }
          let value: Partial<Pick<GoalEventsResponse, "next_id" | "terminal" | "status">>;
          try { value = JSON.parse(data.join("\n")); }
          catch { stop("Stream event is unreadable."); return; }
          if (event === "end") {
            if (value.terminal !== true || value.next_id !== cursor) {
              stop("Terminal acknowledgement does not match the replay cursor."); return;
            }
            stop(`Run ${value.status || "complete"}.`, true); return;
          }
          const next = Number(id);
          if (!/^\d+$/.test(id) || !Number.isSafeInteger(next) || next <= 0) {
            stop("Stream event has no valid replay id."); return;
          }
          if (next <= cursor) continue;
          options.onEvent(data.join("\n"));
          cursor = next;
          options.onCursor(cursor);
          backoff = 1000;
        }
        if (buffer.length > 262144) stop("Stream buffer exceeds the client bound.");
      });
      res.on("end", () => { if (mine === ticket) reconnect("stream disconnected"); });
      res.on("error", () => { if (mine === ticket) reconnect("stream transport failed"); });
    });
    request.on("error", () => { if (mine === ticket) reconnect("connection failed"); });
    } catch { stop("Dashboard connection could not be opened. Check its URL and transport settings."); }
  }
  connect();
  return () => stop("Live watch stopped.");
}
