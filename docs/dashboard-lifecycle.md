# Dashboard shutdown and restart

Shared PostgreSQL pools close in a final resource phase after scheduler, goal
and HTTP request drain, using the same remaining shutdown budget. A live or
cancelled request may still own a synchronous writer, so its pools and process
ownership remain retained until process exit. Startup reopens pool admission
only after the previous cleanup has finished.

The dashboard owns one shutdown supervisor for its main background components
and composed scheduler lifespans. Shutdown closes goal admission, marks the
dashboard as stopping, and signals every component before joining any of them.
The remaining time is shared across joins, goal drain and cleanup. An already
accepted goal can finish during that window; a background task that has not yet
won admission is refused before provider or sandbox execution.

The dashboard CLI starts that same deadline before Uvicorn drains connections.
Short responses have up to one second within the budget to finish; long streams
are cancelled so their cleanup can release stream slots. Scheduler/goal drain
already runs concurrently. The subsequent lifespan cleanup uses the original
deadline. Uvicorn's small socket-close delay and final process teardown consume
the deployment's exit allowance. An operator embedding the ASGI app in a
different server must also bound that server's connection-drain phase; the
application lifespan alone cannot control an external server's pre-shutdown wait.

`MAVERICK_SHUTDOWN_TIMEOUT` configures the total budget in seconds. If absent,
the existing `MAVERICK_DRAIN_TIMEOUT` is its fallback. If both are absent, the
default is 20 seconds. Values must be finite numbers from 0 through 300; an
invalid explicit value refuses startup. The Helm chart defaults to 30 seconds
of termination grace, including its 5-second preStop delay and a 5-second exit
allowance. Set `env.MAVERICK_SHUTDOWN_TIMEOUT` through the existing Helm env map
when changing the budget, and increase termination grace to cover the whole sum.

The supervisor records starting, running, stopping, stopped or degraded state,
and logs component names that remain active or fail cleanup. New HTTP work and
readiness are refused during stopping/degraded state; liveness remains available.
Goal admission stays closed until the next safe startup. A timed-out scheduler
retains its worker handle and cannot start an overlapping replacement. A partial
automation pool start retains and stops every thread that already started.

Clean embedded-app shutdown releases the control-plane lease acquired by that
lifespan. The CLI retains its process lease until OS exit because cancellation of
an ASGI task cannot prove that its synchronous worker stopped writing. If the
server had to cancel a request, an in-process restart is refused conservatively.
If workers, goals or cleanup remain active, ownership is retained, and an in-process
restart is refused until their exit is observed. A cleanup callback that ignores
its timeout cannot extend the async lifespan deadline: it continues as an owned
background cleanup task. This does not kill an OS thread or authorize replay of
uncertain external effects. The process manager remains responsible for final
termination when the deployment grace expires.

Partial startup failures and exceptional lifespan exits use the same cleanup.

The desktop owns a private stdin control pipe for each child it spawns. On
exit, recovery switch or maintenance it sends one versioned drain request.
The CLI consumes the child-only launch marker, starts the existing supervisor
deadline and exits normally after cleanup. Losing the owning pipe also requests
shutdown. No HTTP route or browser bearer token authorizes this operation.
Native and Python use the same validated timeout (20 seconds by default).
Forced termination and socket quiescence share an additional five-second
allowance; taskkill itself is bounded. Failed termination retains the owned
handle and refuses maintenance/recovery. An independent listener is never
stopped. Older runtimes that do not implement the pipe protocol reach the
finite force-stop fallback.

The splash uses a 2.5-second deadline per probe and displays recovery controls
after six elapsed seconds even if fetch never settles. Retry and navigation
cancel obsolete probes. An opaque no-CORS health response still admits usable
onboarding when provider configuration makes healthz return 503.

Mandatory installation-recovery, enterprise, residency and authentication gates
still refuse startup. An installed native build, frozen bootloader descendants,
a signed MSI update, real WebView behavior, Kubernetes rolling restarts and
live providers are not qualified.
