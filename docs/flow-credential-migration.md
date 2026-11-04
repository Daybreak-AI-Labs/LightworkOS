# Review older flow credentials

Flow parameters cannot read deployment environment variables or the server
secret vault. An action-parameter `secret(...)` expression stops a run before its actions
start, including resumed runs and nested or saved subflows. Saved definitions,
history and permissions are preserved. There is no automatic credential-name
mapping, credential copy, grant expansion or deployment configuration change.

The check reviews the complete saved graph before business effects, including
subflows behind branches or a scope's error handler. If a saved subflow cannot
be read, the run reports a structured failure before dispatch; scope recovery
cannot execute against that unreviewable graph. This is an intentional
conservative compatibility boundary, not an indeterminate external execution.
The legacy detector also flags a secret call inside an unknown function wrapper
for explicit review, even when today's expression evaluator leaves that unknown
wrapper inert. Quoted ordinary text is not mistaken for a callable expression.

In Flow designer, review each affected step and open **Connections**. Select or
connect the intended account under the current workspace policy, then use the
service's authorized native connector action and review a new flow version.
The connector's credential contract must bind its account name, current owner
or explicit grant, workspace, service, exact origin and reviewed generation.
If that service does not support the required scoped account binding, leave
the step blocked; a similarly named server secret is not an account grant.

Credentials are resolved inside the authorized connector. They never belong
in an arbitrary action argument, an agent prompt, flow data, or a reusable
template. Normal data expressions, such as `upper(customer_name)`, retain
their existing behavior. Quoted examples remain ordinary text. Deployment
model/provider configuration and the deployment secret-provider API remain
unchanged.

Review a replacement before starting it. The blocked run is not an instruction
to replay earlier business effects, and migrating a flow does not prove any
previously uncertain external outcome.
