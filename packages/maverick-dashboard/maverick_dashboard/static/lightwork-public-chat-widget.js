/*
 * Lightwork public website chat widget.
 *
 * The host page adds one tag (the key is a publishable value, not a secret):
 *   <script src="https://<lightwork-host>/public/chat/v1/widget.js"
 *           data-key="lwpk_..." async></script>
 *
 * Every message is shown with text nodes only. The panel lives in a closed shadow
 * root: the host page's styles cannot reach it, and its scripts cannot read it
 * through host.shadowRoot. Closed mode is not a security boundary: a script on
 * the host page shares the page's trust boundary and can still reach the chat.
 * The widget sends no cookies and keeps the visitor session in memory only.
 */
(function () {
  "use strict";

  var script = document.currentScript || document.querySelector("script[data-key]");
  var key = script ? script.getAttribute("data-key") || "" : "";
  if (!script || key.indexOf("lwpk_") !== 0) {
    return;
  }
  var api = new URL(script.src, document.baseURI).origin + "/public/chat/v1";
  var sessionToken = "";
  var greeted = false;
  var busy = false;

  var host = document.createElement("div");
  host.setAttribute("data-lightwork-chat", "");
  var root = host.attachShadow({ mode: "closed" });
  // An async tag in <head> can run before <body> exists, so mount when the document is ready.
  if (document.body) {
    document.body.appendChild(host);
  } else {
    document.addEventListener("DOMContentLoaded", function () {
      document.body.appendChild(host);
    });
  }

  var style = document.createElement("style");
  style.textContent = [
    ":host { all: initial; font-family: system-ui, sans-serif; }",
    ".launcher { position: fixed; right: 16px; bottom: 16px; border: 0; border-radius: 999px;",
    "  padding: 12px 18px; background: #1f4e79; color: #fff; font-size: 15px; cursor: pointer; }",
    ".panel { position: fixed; right: 16px; bottom: 72px; width: min(360px, calc(100vw - 32px));",
    "  max-height: 70vh; display: flex; flex-direction: column; background: #fff; color: #1b1b1b;",
    "  border: 1px solid #c9d3de; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,.18); }",
    ".panel[hidden] { display: none; }",
    ".log { flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 8px; }",
    ".msg { padding: 8px 10px; border-radius: 8px; white-space: pre-wrap; overflow-wrap: anywhere; }",
    ".msg.visitor { align-self: flex-end; background: #dfe9f5; }",
    ".msg.assistant { align-self: flex-start; background: #f2f2f2; }",
    "form { display: flex; gap: 8px; padding: 10px; border-top: 1px solid #e3e8ee; }",
    "textarea { flex: 1; resize: none; min-height: 40px; font: inherit; padding: 6px; }",
    "button.send { border: 0; border-radius: 8px; padding: 0 14px; background: #1f4e79; color: #fff; cursor: pointer; }",
    "button:disabled { opacity: .6; cursor: default; }"
  ].join("\n");
  root.appendChild(style);

  var launcher = document.createElement("button");
  launcher.className = "launcher";
  launcher.type = "button";
  launcher.textContent = "Chat with us";
  launcher.setAttribute("aria-expanded", "false");
  root.appendChild(launcher);

  var panel = document.createElement("div");
  panel.className = "panel";
  panel.hidden = true;
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-label", "Website chat");
  root.appendChild(panel);

  var log = document.createElement("div");
  log.className = "log";
  log.setAttribute("role", "log");
  log.setAttribute("aria-live", "polite");
  panel.appendChild(log);

  var form = document.createElement("form");
  var input = document.createElement("textarea");
  input.maxLength = 1000;
  input.rows = 2;
  input.placeholder = "Type your question";
  input.setAttribute("aria-label", "Your question");
  var send = document.createElement("button");
  send.className = "send";
  send.type = "submit";
  send.textContent = "Send";
  form.appendChild(input);
  form.appendChild(send);
  panel.appendChild(form);

  function addMessage(who, text) {
    var item = document.createElement("div");
    item.className = "msg " + who;
    item.textContent = text;
    log.appendChild(item);
    log.scrollTop = log.scrollHeight;
    return item;
  }

  function post(path, headers, body) {
    return fetch(api + path, {
      method: "POST",
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      headers: headers,
      body: body
    }).then(function (response) {
      return response.json().catch(function () {
        return {};
      }).then(function (data) {
        return { ok: response.ok, status: response.status, data: data };
      });
    });
  }

  function startSession() {
    if (sessionToken) {
      return Promise.resolve();
    }
    return post("/sessions", { "Authorization": "PublicChatKey " + key,
      "Content-Type": "application/json" }, "{}").then(function (result) {
      if (!result.ok || typeof result.data.session_token !== "string") {
        throw new Error("session");
      }
      sessionToken = result.data.session_token;
      if (!greeted && typeof result.data.greeting === "string" && result.data.greeting) {
        greeted = true;
        addMessage("assistant", result.data.greeting);
      }
    });
  }

  function refusalText(status) {
    if (status === 429) {
      return "Please wait a moment before sending another message.";
    }
    if (status === 401) {
      sessionToken = "";
      return "Your chat session ended. Send your message again to continue.";
    }
    return "This chat is not available right now. Try again later.";
  }

  launcher.addEventListener("click", function () {
    var open = panel.hidden;
    panel.hidden = !open;
    launcher.setAttribute("aria-expanded", String(open));
    if (open) {
      startSession().catch(function () {
        addMessage("assistant", "This chat is not available right now. Try again later.");
      });
      input.focus();
    }
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var text = input.value.trim();
    if (!text || busy) {
      return;
    }
    busy = true;
    send.disabled = true;
    input.value = "";
    addMessage("visitor", text);
    var pending = addMessage("assistant", "Thinking...");
    startSession().then(function () {
      return post("/messages", { "Authorization": "PublicChatSession " + sessionToken,
        "Content-Type": "application/json" }, JSON.stringify({ message: text }));
    }).then(function (result) {
      if (result.ok && typeof result.data.answer === "string") {
        pending.textContent = result.data.answer;
      } else {
        pending.textContent = refusalText(result.status);
      }
    }).catch(function () {
      pending.textContent = "This chat is not available right now. Try again later.";
    }).then(function () {
      busy = false;
      send.disabled = false;
      input.focus();
    });
  });
})();
