# JetBrains preview build

This plugin remains a **preview** until its exact archive passes installed-IDE
connection, PasswordSafe and accessibility checks. The checked-in Gradle project
removes manual source/SDK assembly. It does not publish, sign, install the plugin
or start an IDE automatically.

## Pinned inputs

- JDK 21; IntelliJ Community SDK **2024.3.6**, compatibility build **243** only.
- Gradle **8.13** with wrapper distribution SHA256 verification.
- IntelliJ Platform Gradle plugin **2.5.0**, Kotlin **2.1.20**, Gson **2.11.0**.

The build follows the [JetBrains Gradle plugin
documentation](https://plugins.jetbrains.com/docs/intellij/tools-intellij-platform-gradle-plugin.html),
using the API available in the pinned 2.5.0 version. Other IDE families or build
series are not claimed compatible until qualified and added deliberately.

Set `JAVA_HOME` to a JDK21 installation. From this directory run:

```sh
python build.py
```

Python3.11+ invokes the checked-in wrapper JAR directly (including on Windows),
runs `check buildPlugin`, verifies the archive exists and emits a SHA256/input
manifest. The initial build downloads public Gradle, Kotlin and IntelliJ SDK
dependencies. `check` includes the standalone synthetic-loopback SSE fixtures;
it never calls a dashboard or provider. Archives use sorted entries and stable
timestamps. No signing identity or publishing token is read.

The installable unsigned preview ZIP appears under `build/distributions/`.
For installed qualification in a test IDE, use **Settings → Plugins → Install
Plugin from Disk**, select that exact ZIP, and follow
[connection-qualification.md](tests/connection-qualification.md). End users of a
released archive do not need Gradle or a compiler. The release owner must still
approve distribution and signing, record the artifact checksum and qualify the
declared IDE/OS/accessibility matrix before promoting it to supported release.

For deliberate IDE development, `gradlew runIde` launches a sandbox IDE. This is
separate from the packaging command and is never started by `check buildPlugin`.
