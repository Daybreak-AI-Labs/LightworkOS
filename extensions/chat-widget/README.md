# Embeddable widget

A dependency-free floating chat button that drops onto any page and talks to a
Lightwork dashboard's chat endpoint. Self-hostable: it posts to **your**
dashboard origin, not a hosted service.

The dashboard does not serve `/widget/` automatically. Host the script on the
same origin using a reverse-proxy static alias before adding this tag.

```html
<script src="/widget/maverick-chat-widget.js"
        data-maverick-url="https://your-dashboard.example.com"
        data-maverick-title="Ask Lightwork"></script>
```

- `data-maverick-url` — base URL of your dashboard (where `/chat/send` lives); it
  must be the origin the page itself is served from.
- `data-maverick-title` — header/button label.

The widget `fetch`es `POST {base}/chat/send` with `credentials: include`, so the
widget must run on the dashboard's own origin; it refuses a cross-origin base.
Unconfirmed starts retain their request key and original draft in this origin's
local storage through reload. **Check start status** reads the original receipt.
If it says the admitted draft was not dispatched, the widget replays the saved
inputs with the same key; an unknown outcome stays held. Acceptance or a definite
initial refusal removes the saved draft. Older key-only entries need dashboard
review if their draft was never dispatched. No build step or dependencies.

For example, add this exact static alias to the same HTTPS server that proxies
your dashboard (replace the filesystem path with your checkout location):

```nginx
location = /widget/maverick-chat-widget.js {
    alias /opt/maverick/extensions/chat-widget/maverick-chat-widget.js;
}
```

Keep the dashboard's authentication and same-origin controls on the surrounding
page and proxied routes; the static alias only serves the widget file.

See the [client request and acknowledgement contract](../../docs/client-request-lifecycle.md) for replay, deadlines, access errors, and platform qualification limits.
