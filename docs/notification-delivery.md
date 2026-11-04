# Notification delivery history

Settings → Notification delivery shows organization alert attempts and sends an
explicit content-free test to the saved channel. Installation administrators
can inspect receipts; tenant-local administration does not grant this control.
The same service checks current authority before sending. A successful queue
submission means **queued**, not delivered. A successful backend response means
**accepted by the service**, not read by the person.

`[notifications] delivery_receipts` controls the content-free history. The
installer asks about it and All settings provides the same toggle. The bounded
tenant-scoped file retains up to 1,000 receipts for seven days. It stores no
message body/title, destination URL/topic, token or provider exception text.
Provider errors use fixed, sanitized descriptions. Historical success may refer
to earlier channel settings; a fresh test checks the current configuration.

An explicit test request is deduplicated by its request reference and backend.
Only a test that was definitively refused before acceptance is retryable, up to
three attempts total. Accepted, in-flight and uncertain outcomes cannot be
retried through this control. Interrupted in-flight attempts become unknown
when viewed after two minutes; no background process guesses that they failed.
Transport timeouts and server errors are uncertain because a destination may
already have accepted a message. Ordinary alert content is never stored for
replay. Repeated event producers can supply `delivery_key` to deduplicate a
transition within the receipt retention window.

These operations are available in the direct UI and API; Copilot does not
expose delivery status, test or retry. Recipient preferences and digests are
not supported, and end-to-end delivery to each provider is not qualified.
