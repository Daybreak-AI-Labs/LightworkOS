# Native companion preview and release evidence

The companion surfaces are **previews**. Each becomes supported only when its
exact packaged build passes the installed-host checks below. Mock tests and
TypeScript checks do not qualify Keychain, Android Keystore, VoiceOver/TalkBack
or native networking.
These build paths create no store listing, signed download, distribution
certificate or platform account.

| Client | Reproducible project input | Build host / minimum deployment target | Qualification required before support |
| --- | --- | --- | --- |
| iOS phone/tablet | `apps/mobile-companion/package-lock.json`, Expo 52.0.49, local LightworkTransport module, `build-native.cjs` | macOS + Xcode; iOS 15.1 | Installed-host Keychain, VoiceOver and native networking checks |
| Android phone/tablet | Same locked Expo project and native transport | JDK 17 + Android SDK; SDK versions from pinned Expo generation | Android SDK build; installed-host Keystore, TalkBack and native networking checks |
| JetBrains | Gradle 8.13 wrapper/checksum, pinned SDK 2024.3.6, Kotlin 2.1.20, `apps/jetbrains-plugin/build.py` | JDK 21; compile target IntelliJ Community 243 only | Installed IDE, PasswordSafe and accessibility checks |
| Zed | Rust 1.97.1, exact API 0.7.0, Cargo.lock, `apps/zed-extension/build.py` | wasm32-wasip2; selected host must support API 0.7.0 | Installed-host, MCP and accessibility checks |

For editor integrations, use [JetBrains build instructions](../apps/jetbrains-plugin/BUILDING.md)
and [Zed build instructions](../apps/zed-extension/BUILDING.md). The installable
JetBrains ZIP and Zed engineering bundle do not promote either editor to supported
installed status. The Zed development install rebuilds its bundled sources.

## Local builds

In `apps/mobile-companion`, run `npm ci --ignore-scripts`, then
`npm run build:android:local` or `npm run build:ios:local`. These generate native
projects from locked sources and build an Android **debug APK** or an **unsigned
iOS simulator app**, respectively. They do not upload. `npm run prebuild:android`
and `npm run prebuild:ios` only generate the project (no build). Inspect generated
manifests before producing a distributable artifact. The native transport is a
local Expo module; Expo Go cannot load it and fails closed before a request.

The bridge applies the 4 MiB cap before data reaches JavaScript, rejects
redirects, has no shared cookie jar or disk cache, owns cancellation/timeouts,
limits concurrent requests, and never logs request bodies or credentials.
Android automatic connection retries are disabled. Native TLS validation is
unchanged. JavaScript also rejects non-loopback cleartext addresses.

## Release-owner gate

A release owner must select the distribution channel, confirm bundle ownership,
review privacy/export declarations and provide the existing signing configuration
through the platform build system. Archive the reviewed source SHA, dependency
locks, Xcode/SDK/JDK versions, unsigned-build logs, signed artifact SHA-256 and
installed test evidence together. Do not mark a preview supported based solely
on a successful archive. Do not distribute the developer debug APK as a supported
release. Platform signing makes byte-identical signed rebuilds an inappropriate
claim; compare the reviewed source/input manifest and unsigned build evidence.

Before releasing each platform, install the resulting artifact on the minimum
and supported current OS; pair a synthetic account; exercise denial, revocation,
expiry/renewal, TLS redirect refusal, 4 MiB response overflow, network loss,
background cancellation, two-profile/cache isolation, protected-store failure,
largest text, screen-reader navigation and RTL. For mobile actions also test
stale review, duplicate confirmation, lost response and preserved partial result
on Stop. Record actual results and defects, not
unchecked acceptance claims. These checks use mock accounts/endpoints and never
require a production provider invocation.
