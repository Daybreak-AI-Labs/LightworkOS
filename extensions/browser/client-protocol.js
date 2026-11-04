/* Bounded event replay contract, shared by the popup and its local tests. */
(function (root) {
  "use strict";
  function page(state, data) {
    if (!data || !Array.isArray(data.events) || data.events.length > 200 ||
        !Number.isSafeInteger(data.next_id) || data.next_id < state.cursor ||
        typeof data.has_more !== "boolean" || typeof data.terminal !== "boolean") {
      throw new Error("Unsupported event page; update the dashboard or client.");
    }
    let cursor = state.cursor;
    const added = [];
    for (const event of data.events) {
      if (!Number.isSafeInteger(event.id) || event.id <= cursor || event.id > data.next_id) {
        throw new Error("Event page has an invalid replay cursor.");
      }
      cursor = event.id;
      added.push({ id: event.id, agent: String(event.agent || "agent").slice(0, 200),
        content: String(event.content || "").slice(0, 16000) });
    }
    if (data.next_id !== cursor || (data.has_more && cursor === state.cursor)) {
      throw new Error("Event page made no valid progress.");
    }
    let rows = [...(state.events || []), ...added];
    let size = rows.reduce((n, row) => n + row.content.length, 0);
    let trimmed = Boolean(state.trimmed) || data.events.some(e => String(e.content || "").length > 16000);
    while (rows.length > 1000 || size > 1000000) {
      size -= rows.shift().content.length;
      trimmed = true;
    }
    return { ...state, cursor, events: rows, trimmed, status: String(data.status || "unknown"),
      complete: data.terminal && !data.has_more, hasMore: data.has_more,
      result: data.terminal && !data.has_more ? String(data.result || "").slice(0, 16000) : "" };
  }
  const api = { page };
  if (typeof module !== "undefined") module.exports = api;
  root.LightworkClientProtocol = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
