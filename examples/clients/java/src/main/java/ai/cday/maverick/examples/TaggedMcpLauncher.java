package ai.cday.maverick.examples;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Gives the stdio transport process an exact, phased ownership registry.
 *
 * <p>The MCP SDK does not expose its private {@link Process}. Running the real
 * server below this tiny tagged launcher lets {@link McpClientCleanup} identify
 * the exact transport subtree without treating every newly started Java child
 * as owned. The child also arms a platform parent-death guard before server
 * initialization, closing the window before the active registry can be written.
 */
public final class TaggedMcpLauncher {

    static final String TOKEN_PREFIX = "maverick-mcp-owner-";
    private static final String PARENT_PID_ENV = "MAVERICK_MCP_PARENT_PID";
    private static final String PARENT_STARTED_ENV =
            "MAVERICK_MCP_PARENT_STARTED_EPOCH_MILLIS";
    private static final String PARENT_TOKEN_ENV = "MAVERICK_MCP_PARENT_TOKEN";
    private static final String PARENT_READY_ENV = "MAVERICK_MCP_PARENT_READY_FILE";
    private static final String PARENT_RELEASE_ENV = "MAVERICK_MCP_PARENT_RELEASE_FILE";

    public static void main(String[] args) throws Exception {
        if ((args.length != 2 && args.length != 4)
                || !args[0].startsWith(TOKEN_PREFIX)) {
            throw new IllegalArgumentException(
                    "expected an MCP ownership token, process registry, "
                            + "and optional controlled-pause paths");
        }
        String token = args[0];
        Path registry = Path.of(args[1]).toAbsolutePath();
        ProcessHandle launcher = ProcessHandle.current();
        Instant launcherStarted = launcher.info().startInstant()
                .orElseThrow(() -> new IllegalStateException(
                        "tagged launcher start time is unavailable"));
        McpProcessOwnership.registerStarting(registry, token, launcher);

        ProcessBuilder serverBuilder = new ProcessBuilder("maverick", "mcp")
                .inheritIO();
        serverBuilder.environment().put(PARENT_PID_ENV, Long.toString(launcher.pid()));
        serverBuilder.environment().put(
                PARENT_STARTED_ENV,
                Long.toString(launcherStarted.toEpochMilli()));
        serverBuilder.environment().put(PARENT_TOKEN_ENV, token);
        boolean controlledPause = args.length == 4;
        Path ready = null;
        Path release = null;
        if (controlledPause) {
            if (!token.contains("parent-death-acceptance-")) {
                throw new IllegalArgumentException("controlled pause is acceptance-only");
            }
            ready = Path.of(args[2]).toAbsolutePath();
            release = Path.of(args[3]).toAbsolutePath();
            serverBuilder.environment().put(PARENT_READY_ENV, ready.toString());
            serverBuilder.environment().put(PARENT_RELEASE_ENV, release.toString());
        }

        AtomicReference<Process> serverRef = new AtomicReference<>();
        Thread shutdown = Thread.ofPlatform()
                .name("maverick-mcp-launcher-shutdown")
                .unstarted(() -> terminate(serverRef.get()));
        Runtime.getRuntime().addShutdownHook(shutdown);

        Process server = serverBuilder.start();
        serverRef.set(server);
        try {
            if (controlledPause) {
                awaitControlFile(ready, server, Duration.ofSeconds(15));
                awaitControlFile(release, server, Duration.ofMinutes(2));
            }
            McpProcessOwnership.registerActive(
                    registry, token, launcher, server.toHandle());
        } catch (Exception failure) {
            terminate(server);
            throw failure;
        }

        int exitCode = server.waitFor();
        try {
            Runtime.getRuntime().removeShutdownHook(shutdown);
        } catch (IllegalStateException ignored) {
            // The VM is already shutting down and the hook owns termination.
        }
        System.exit(exitCode);
    }

    private static void awaitControlFile(
            Path signal,
            Process server,
            Duration timeout) throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!Files.exists(signal)) {
            if (!server.isAlive()) {
                throw new IllegalStateException(
                        "MCP server exited before controlled launch signal " + signal);
            }
            if (System.nanoTime() >= deadline) {
                throw new IllegalStateException(
                        "timed out waiting for controlled launch signal " + signal);
            }
            Thread.sleep(20);
        }
    }

    private static void terminate(Process server) {
        if (server == null || !server.isAlive()) {
            return;
        }
        server.destroy();
        try {
            if (!server.waitFor(500, TimeUnit.MILLISECONDS)) {
                server.destroyForcibly();
                server.waitFor(1, TimeUnit.SECONDS);
            }
        } catch (InterruptedException failure) {
            server.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }

    private TaggedMcpLauncher() {
    }
}
