# Embeddable widget

A dependency-free floating chat button that drops onto any page and talks to a
Lightwork dashboard's chat endpoint. Self-hostable: it posts to **your**
dashboard origin, not a hosted service.

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
Unconfirmed starts retain their request key through reload. **Check start status**
reads the original receipt without submitting another goal. No build step, no dependencies —
one `<script>` tag.

See the [client request and acknowledgement contract](../../docs/client-request-lifecycle.md) for replay, deadlines, access errors, and platform qualification limits.
