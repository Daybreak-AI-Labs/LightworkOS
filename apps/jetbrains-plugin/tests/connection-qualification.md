# Installed-IDE connection qualification checklist

Run these checks before distribution. Build the plugin with `python build.py`
(see [BUILDING.md](../BUILDING.md)) and install the resulting ZIP in an IDE with
PasswordSafe enabled. Use only a loopback fixture dashboard.

1. Save a named HTTPS connection and protected token through Settings. Read it
   back through PasswordSafe without printing it. Reopen Settings, rotate it and
   use Test connection without restarting the IDE. Ordinary persisted properties
   must contain only the connection name/address and migration state.
2. Make PasswordSafe reject a write/readback. The address must remain unchanged,
   the save must report failure and the old private view must close. With legacy
   environment configuration, that fallback remains until a successful save.
3. Switch from host A/token A to host B. Host B receives no token A. While an A
   credential read, task search and SSE frame are pending, save host B; no late A
   result may update B's picker/output/cursor. Remove the current protected token
   and confirm an old bearer is not silently recovered from the legacy environment.
4. A remote HTTP bearer is rejected before any network request. HTTPS and exact
   loopback HTTP are accepted. A redirect never carries credentials onward.
5. Find tasks by title/content, including a match older than the latest 100 runs.
   The picker contains only authorized matches with title and ID. Selecting a
   task watches its actual ID; invalid manual IDs show a positive-ID/picker remedy.
6. With the platform screen reader, verify the task search, match picker, optional
   ID and connection fields announce their purpose. Invalid selection and status
   updates announce the remedy; keyboard focus remains on the relevant control.
7. Stall headers/body and exceed the 1-MiB search response bound. The UI remains
   responsive and produces one bounded failure; Stop/disposal owns cleanup. A late
   response does not replace a newer task selection. No automatic write occurs.
8. Return 401/403 during replay after private events have displayed. The old output,
   task selection and cursor clear; the displayed remedy points to Settings.

The existing standalone `RunEventStreamTest.kt` checks remain applicable to the
transport core, but do not qualify Settings, PasswordSafe or installed UI behavior.
