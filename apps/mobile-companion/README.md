# Lightwork mobile companion (preview)

**Preview source; native transport, packaging and installed-device behavior
remain unqualified.**

Settings offers **Follow device**, **Light**, and **Dark** appearance, saved on
this device across connection profiles. Text respects device accessibility size.
Language and regional formats are a separate device preference. Available
control translations are a partial preview in French, German, Japanese and
Chinese; English fallback is identified to assistive technology. Arabic remains
community-only and uses English product fallback. Dates/numbers/USD costs follow
the selected format. Task/result text and document output language are unchanged.
Failed display-preference writes retain the previous saved choice.

Watch your Lightwork swarm from a phone: runs list, run detail with a live
event timeline, and an at-a-glance fleet summary — with an offline cache so
losing the network shows "as of 12 min ago" instead of a blank screen.

**Task browsing is read-only by default.** A device explicitly enrolled for actions,
under the administrator's separately enabled policy, can review and confirm one
answer or request Stop on its own task. An answer can resume that task through the
dashboard's existing budget admission service. Approvals, attachments and other
sensitive decisions open the authenticated full dashboard. Offline copies never
authorize or queue writes. Separately typed POSTs pair and renew the connection. See
[device pairing](../../docs/device-pairing.md) for the exact scope and limits.

## Endpoints used (all existing dashboard routes)

From `packages/maverick-dashboard/maverick_dashboard/api.py`:

| Screen      | Endpoint |
|-------------|----------|
| Tasks       | `GET /api/v1/goals?limit=50` |
| Run detail  | `GET /api/v1/goals/{id}/events?since=0&limit=200` |
| Overview    | `GET /api/v1/oversight/active` + `GET /api/v1/spend` |
| Offline     | `GET /api/v1/offline/bundle` with `X-Lightwork-Offline-Policy: 1` (optional; older dashboards still support online views, but snapshots without current retention policy are not saved) |
| Reviewed actions | `GET /api/v1/devices/actions/context`, `POST /api/v1/devices/actions/prepare`, `POST /api/v1/devices/actions/execute`; exact own-task answer/Stop allowlist only |

Organization controls in **All settings → Data retention** can disable mobile
offline copies or narrow their retention/size. Workspace policy cannot exceed
the installation ceiling; people can opt out but cannot relax it. The installer
offers the same offline-copy enablement choice. No copy exceeds 24 hours or
2 MB, and the age is based on the source snapshot rather than download time.

Missing/invalid policy, disablement, expiration and credential reset remove
the eligible app cache and invalidate in-memory offline readers. Serialized
cache mutation prevents delayed writes from resurrecting removed snapshots.
The server refuses the bundle request from clients that do not declare support
for the policy protocol. Upgrade older companion builds; no retroactive promise
is made about copies already retained by unqualified old builds. A disconnected
device cannot learn a new server policy until it reconnects, so the last accepted
expiry remains the offline bound. Native timing/storage qualification needs
native hosts; the local mocked regression suite covers the logic.

Updates are plain polling (5–15s per screen) — dependency-light and
battery-predictable; no SSE/websocket client to maintain.

## Building a local preview

The tracked npm lock and local native module generate both phone projects:

```bash
cd apps/mobile-companion
npm ci --ignore-scripts
npm run build:android:local  # JDK 17 + Android SDK; produces a debug APK
npm run build:ios:local      # macOS + Xcode + CocoaPods; unsigned simulator app
```

To generate a native project without building it, run `npm run prebuild:android`
or `npm run prebuild:ios`.

Expo Go does not contain the Lightwork transport module. The app fails closed
before sending a credential there. Use the locally built preview; its native
bridge caps response bytes before crossing into JavaScript and refuses redirects.
These commands do not upload or provision signing. See the
[native release and support matrix](../../docs/native-companion-release.md).

Requirements:

- **Network**: the phone must reach the dashboard (`maverick dashboard`,
  default port 8765) — same Wi-Fi, VPN, or a tunnel. Set the base URL in the
  Settings tab (e.g. `https://lightwork.example.com`).
- **Pairing**: choose **Start device pairing** in Settings, approve the displayed
  code from **Your account → Your paired devices** on the signed-in dashboard,
  then return and check approval. The administrator must enable device pairing.
  Named members receive an own-work credential for one workspace. Renew before
  its displayed expiry or pair again. Removing the device denies its next request.
- **Advanced token setup**: administrators may still paste a bearer in Settings.
  It is stored in the device keychain via `expo-secure-store`, never in
  plain storage. With auth off (local trusted networks only), leave it empty.
  **Security:** connection setup and requests require HTTPS for a remote
  dashboard. Plain HTTP is allowed only for loopback development on the same
  device. Invalid addresses or tokens never replace the saved connection;
  Settings preserves the entered values and explains how to correct them.
- **Offline cache**: the last good `/api/v1/offline/bundle` payload is kept
  in `AsyncStorage` (`@react-native-async-storage/async-storage`) and
  rendered with an "as of N min ago — offline" banner when fetches fail.
  Each saved connection has an opaque cache scope stored with its URL and
  token in one keychain record. Saving settings starts a new cache scope,
  including when switching tokens on the same dashboard. Reconnect and open
  Glance to refresh that connection's cache. Older URL-only caches are ignored;
  existing URL/token settings remain readable and migrate on the next save.
  If the runtime cannot generate a secure UUID, online settings still work,
  but offline caching stays disabled. Tokens are never stored in cache keys.

## Building store binaries

Release signing and publication require the release owner's existing platform
configuration and explicit authorization. The checked-in project provides local
build inputs; no signed download is published. Follow the installed-host
checks in the native release matrix before changing a preview's support status.

## Type checking

`npm run typecheck` (tsc) requires a local `npm install` first; the repo does
not vendor `node_modules`, so CI here only guarantees the sources are
syntactically valid TypeScript. Imports are limited to `react`,
`react-native`, `expo-status-bar`, `expo-secure-store`, and
`@react-native-async-storage/async-storage`.

## Local regression tests

These tests execute the actual TypeScript/React settings, polling, cache, and
screen code with synthetic storage and controlled promises. They do not call
providers, the OS keychain, or a native simulator. Their small, separate package
pins React and its matching renderer; installing Expo is unnecessary:

```bash
cd apps/mobile-companion
npm ci --prefix tests --ignore-scripts
npm test
```

Coverage includes failed/legacy keychain writes, concurrent reads and saves,
out-of-order responses, slow polling, unmounts, save feedback, and cached data
isolation when the dashboard or token changes. Native iOS/Android layout and
keychain acceptance still require a device build.

See the [client request and acknowledgement contract](../../docs/client-request-lifecycle.md) for replay, deadlines, access errors, and platform qualification limits.

Offline task data is optional in Settings, is limited to 2 MB and 24 hours, and
is removed on connection replacement or explicit disconnect. A phone's
127.0.0.1 address refers to the phone itself: use the organization's reachable
HTTPS dashboard address (including its configured proxy port), not the desktop's
loopback address. Native streaming and accessibility qualification need
installed devices; this source is not a signed device release.

Named connections can be added, switched and removed in Settings; their tokens
remain in the same device secure store. Switching clears the previous offline
copy and resets the visible task. The initial connection screen is also the
mobile setup flow for the offline-saving choice. Native screens follow the
system light/dark preference and system text size. Product copy is currently
English; selecting other languages must wait for reviewed translations.
