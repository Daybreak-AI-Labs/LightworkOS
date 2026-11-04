# Employee task diagnostics

Open **Review safe task diagnostics** from a stopped task. Prepare the local document, inspect its exact JSON preview and acknowledge review before downloading. It contains only status, a correlation reference, the latest 20 event identities/kinds/times and this task's provider receipt metadata. Task content, attachments, configuration, credentials and raw errors are excluded by construction, rather than copied and then guessed safe.

The immutable encrypted document is bound to its owner, task, account/workspace context and SHA-256. Its download link expires in 15 minutes, rechecks current ownership/feature permission, verifies the reviewed bytes and requires an acknowledged audit event before returning them. Expiry removes link access; it does not claim deletion of retained audit evidence. File sharing with a support recipient remains an explicit user action outside this page. No automatic task retry, provider call or external upload occurs.

`features.employee_task_diagnostics` controls availability independently from task authority. Authenticated browser use, revocation, storage and shared-backend behavior are not qualified.
