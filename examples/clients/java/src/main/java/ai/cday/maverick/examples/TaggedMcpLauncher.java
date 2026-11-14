package ai.cday.maverick.examples;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
                .redirectInput(ProcessBuilder.Redirect.INHERIT);
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

        // Bound each line before the SDK's otherwise unbounded line readers.
        AtomicReference<IOException> stderrFailure = new AtomicReference<>();
        Thread stderr = Thread.ofPlatform().daemon(true).name("maverick-mcp-stderr")
                .start(() -> {
                    try {
                        forwardLines(server.getErrorStream(), System.err, 64 * 1024, "stderr");
                    } catch (IOException failure) {
                        stderrFailure.set(failure);
                        terminate(server);
                    }
                });
        int exitCode;
        try {
            forwardLines(server.getInputStream(), System.out, 16 * 1024 * 1024, "stdout");
            exitCode = server.waitFor();
            stderr.join(2000);
            if (stderr.isAlive()) {
                throw new IOException("MCP stderr did not close after the server exited");
            }
            if (stderrFailure.get() != null) {
                throw stderrFailure.get();
            }
        } finally {
            terminate(server);
            server.getInputStream().close();
            server.getErrorStream().close();
            stderr.interrupt();
        }
        try {
            Runtime.getRuntime().removeShutdownHook(shutdown);
        } catch (IllegalStateException ignored) {
            // The VM is already shutting down and the hook owns termination.
        }
        System.exit(exitCode);
    }

    private static void forwardLines(
            InputStream input, OutputStream output, int limit, String stream) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int count;
        while ((count = input.read(chunk)) != -1) {
            int start = 0;
            for (int i = 0; i < count; i++) {
                if (chunk[i] == '\n') {
                    appendLine(line, chunk, start, i + 1 - start, limit, stream);
                    line.writeTo(output);
                    output.flush();
                    line.reset();
                    start = i + 1;
                }
            }
            appendLine(line, chunk, start, count - start, limit, stream);
        }
        // Preserve the SDK's handling of a final unterminated, bounded line.
        line.writeTo(output);
        output.flush();
    }

    private static void appendLine(
            ByteArrayOutputStream line, byte[] chunk, int start, int count,
            int limit, String stream) throws IOException {
        if (count > limit - line.size()) {
            throw new IOException("MCP " + stream + " line exceeds the transport size limit");
        }
        line.write(chunk, start, count);
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
        // Capture before terminating the root: otherwise its children can be
        // re-parented before the outer client's ownership sweep sees them.
        long deadline = System.nanoTime() + Duration.ofMillis(1500).toNanos();
        Set<ProcessHandle> owned = new LinkedHashSet<>();
        owned.add(server.toHandle());
        collectDescendants(owned);
        for (ProcessHandle process : owned) {
            if (process.isAlive()) process.destroy();
        }
        try {
            server.waitFor(500, TimeUnit.MILLISECONDS);
            collectDescendants(owned);
            for (ProcessHandle process : owned) {
                if (process.isAlive()) process.destroyForcibly();
            }
            server.waitFor(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            while (owned.stream().anyMatch(ProcessHandle::isAlive)
                    && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
        } catch (InterruptedException failure) {
            for (ProcessHandle process : owned) {
                if (process.isAlive()) process.destroyForcibly();
            }
            Thread.currentThread().interrupt();
        }
    }

    private static void collectDescendants(Set<ProcessHandle> owned) {
        for (ProcessHandle root : List.copyOf(owned)) {
            try (var descendants = root.descendants()) {
                owned.addAll(descendants.toList());
            }
        }
    }

    private TaggedMcpLauncher() {
    }
}
