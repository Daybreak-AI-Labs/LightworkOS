package ai.cday.maverick.examples;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.McpJsonMapperSupplier;
import io.modelcontextprotocol.spec.McpSchema.Implementation;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.Stream;

/**
 * Dependency-free acceptance test for bounded MCP child-process cleanup.
 *
 * <p>Run with Maven's test classpath:
 *
 * <pre>
 * mvn test-compile exec:java@cleanup-acceptance
 * </pre>
 */
public final class CleanupAcceptance {

    private static final Duration ACCEPTANCE_WALL_TIME = Duration.ofSeconds(5);

    public static void main(String[] args) throws Exception {
        verifySuccessfulClose();
        verifyUnrelatedPostManageChildSurvives();
        verifyParentDeathLaunchWindow();
        verifySdkInitializationFailure();
        verifyInitializationAndCloseFailure();
        verifyCorruptRegistryFailsClosed();
        verifyDeletedRegistryFailsClosed();
        verifyOversizedRegistryFailsClosed();
        System.out.println("OK: Java MCP cleanup is bounded, fail-closed, and orphan-free");
    }

    private static void verifySuccessfulClose() throws Exception {
        String token = TaggedMcpLauncher.TOKEN_PREFIX + "success-" + UUID.randomUUID();
        AtomicReference<Process> childRef = new AtomicReference<>();
        McpProcessOwnership ownership = McpProcessOwnership.createForAcceptance(token);
        McpClientCleanup cleanup = McpClientCleanup.forAcceptance(
                () -> terminateCooperatively(childRef.get()),
                () -> {
                },
                Duration.ofSeconds(1),
                Duration.ofSeconds(1),
                Duration.ofSeconds(2),
                ownership);

        Process child = startChild(token, ownership);
        childRef.set(child);
        long started = System.nanoTime();
        cleanup.close();

        assertBounded(started, "successful close");
        assertNoOrphan(child, token);
        System.out.println("OK: successful close stayed bounded and left no maverick child");
    }

    private static void verifyUnrelatedPostManageChildSurvives() throws Exception {
        String ownedToken = TaggedMcpLauncher.TOKEN_PREFIX
                + "ownership-" + UUID.randomUUID();
        String unrelatedToken = "unrelated-java-child-" + UUID.randomUUID();
        McpProcessOwnership ownership = McpProcessOwnership.createForAcceptance(ownedToken);
        McpClientCleanup cleanup = McpClientCleanup.forAcceptance(
                () -> false,
                () -> {
                },
                Duration.ofSeconds(1),
                Duration.ofSeconds(1),
                Duration.ofSeconds(2),
                ownership);

        // Both children begin after the guard is created. Cleanup must force
        // down only the exactly tagged transport process, never infer
        // ownership from creation time.
        Process owned = startChild(ownedToken, ownership);
        Process unrelated = startChild(unrelatedToken);
        long started = System.nanoTime();
        try {
            cleanup.close();
            assertBounded(started, "session-specific ownership cleanup");
            assertNoOrphan(owned, ownedToken);
            if (!unrelated.isAlive()) {
                throw new AssertionError(
                        "cleanup terminated an unrelated child created after manage()");
            }
        } finally {
            terminateForTest(unrelated);
        }

        assertNoOrphan(unrelated, unrelatedToken);
        System.out.println(
                "OK: forced cleanup preserved an unrelated post-manage Java child");
    }

    private static void verifySdkInitializationFailure() throws Exception {
        String token = TaggedMcpLauncher.TOKEN_PREFIX
                + "sdk-init-" + UUID.randomUUID();
        Path pidFile = Files.createTempFile("maverick-cleanup-sdk-", ".pid");
        Files.delete(pidFile);
        McpProcessOwnership ownership = McpProcessOwnership.createForAcceptance(token);

        ServerParameters server = ServerParameters.builder(javaExecutable())
                .args(
                        "-cp",
                        childClasspath(),
                        MaverickChild.class.getName(),
                        MaverickChild.CHILD_MODE,
                        token,
                        pidFile.toString(),
                        ownership.registry().toString())
                .build();
        StdioClientTransport transport = new StdioClientTransport(server, jsonMapper());
        McpSyncClient client = McpClient.sync(transport)
                .clientInfo(new Implementation("maverick-cleanup-acceptance", "0.1.0"))
                .requestTimeout(Duration.ofSeconds(1))
                .initializationTimeout(Duration.ofSeconds(1))
                .build();

        long started = System.nanoTime();
        RuntimeException initializationFailure = null;
        try (ownership;
                McpClientCleanup cleanup = McpClientCleanup.manage(client, ownership)) {
            client.initialize();
        } catch (RuntimeException failure) {
            initializationFailure = failure;
        }
        if (initializationFailure == null) {
            throw new AssertionError("unresponsive MCP child unexpectedly initialized");
        }
        if (!Files.exists(pidFile)) {
            throw new AssertionError("unresponsive MCP child never recorded its PID");
        }

        long pid = Long.parseLong(Files.readString(pidFile).trim());
        assertBounded(started, "SDK initialization failure");
        assertNoOrphan(pid, token);
        Files.deleteIfExists(pidFile);
        System.out.println(
                "OK: SDK initialization failure stayed bounded and left no maverick child");
    }

    private static void verifyParentDeathLaunchWindow() throws Exception {
        String token = TaggedMcpLauncher.TOKEN_PREFIX
                + "parent-death-acceptance-" + UUID.randomUUID();
        McpProcessOwnership ownership = McpProcessOwnership.create(token);
        Path ready = newAbsentTempPath("maverick-parent-guard-", ".ready");
        Path release = newAbsentTempPath("maverick-parent-guard-", ".release");
        Process launcher = new ProcessBuilder(
                javaExecutable(),
                "-cp",
                codeLocation(TaggedMcpLauncher.class),
                TaggedMcpLauncher.class.getName(),
                token,
                ownership.registry().toString(),
                ready.toString(),
                release.toString())
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        long serverPid = -1;
        long started = System.nanoTime();
        try {
            awaitControlFile(ready, launcher);
            serverPid = Long.parseLong(Files.readString(ready).trim());
            if (!ProcessHandle.of(serverPid).map(ProcessHandle::isAlive).orElse(false)) {
                throw new AssertionError("guarded MCP server exited before launcher kill");
            }
            McpProcessOwnership.Snapshot starting = ownership.snapshot();
            if (starting.state() != McpProcessOwnership.RegistryState.STARTING) {
                throw new AssertionError(
                        "controlled launch window unexpectedly reached "
                                + starting.state());
            }

            launcher.destroyForcibly();
            if (!launcher.waitFor(1, TimeUnit.SECONDS)) {
                throw new AssertionError("could not kill controlled tagged launcher");
            }
            awaitProcessExit(serverPid, Duration.ofSeconds(3));

            assertRegistryFailure(
                    failingCleanup(ownership),
                    ownership,
                    McpProcessOwnership.RegistryState.STARTING);
            assertBounded(started, "parent-death launch window");
        } finally {
            terminateForTest(launcher);
            terminateProcessForTest(serverPid);
            deleteRecoveryEvidence(ownership);
            Files.deleteIfExists(ready);
            Files.deleteIfExists(release);
        }

        assertNoOrphan(serverPid, token);
        System.out.println(
                "OK: parent-death guard reaped the server in the pre-registry launch window");
    }

    private static void verifyInitializationAndCloseFailure() throws Exception {
        String token = TaggedMcpLauncher.TOKEN_PREFIX
                + "failure-" + UUID.randomUUID();
        McpProcessOwnership ownership = McpProcessOwnership.createForAcceptance(token);
        McpClientCleanup cleanup = McpClientCleanup.forAcceptance(
                () -> {
                    // Model an SDK graceful-close operation that does not finish
                    // before the caller's budget. Cancellation interrupts this
                    // park, proving the wrapper does not inherit the SDK's 10s wait.
                    LockSupport.parkNanos(Duration.ofSeconds(5).toNanos());
                    return false;
                },
                () -> {
                    // The fallback is independently bounded as well. It must
                    // not inherit an unbounded SDK close implementation, even
                    // if that implementation ignores cancellation.
                    blockIgnoringInterrupts(Duration.ofSeconds(5));
                },
                Duration.ofMillis(250),
                Duration.ofMillis(250),
                Duration.ofSeconds(2),
                ownership);

        Process child = startChild(token, ownership);
        long started = System.nanoTime();
        IllegalStateException initializationFailure =
                new IllegalStateException("induced initialization failure");

        try (cleanup) {
            throw initializationFailure;
        } catch (IllegalStateException failure) {
            if (failure != initializationFailure) {
                throw new AssertionError("cleanup masked the initialization failure", failure);
            }
            if (failure.getSuppressed().length != 1
                    || !failure.getSuppressed()[0].getMessage().contains("fallback close")) {
                throw new AssertionError(
                        "cleanup failure was not preserved as a suppressed exception",
                        failure);
            }
        }

        assertBounded(started, "induced initialization/close failure");
        assertNoOrphan(child, token);
        System.out.println(
                "OK: induced initialization/close failure stayed bounded and left no maverick child");
    }

    private static void verifyCorruptRegistryFailsClosed() throws Exception {
        String token = TaggedMcpLauncher.TOKEN_PREFIX
                + "corrupt-registry-" + UUID.randomUUID();
        McpProcessOwnership ownership = McpProcessOwnership.createForAcceptance(token);
        McpClientCleanup cleanup = failingCleanup(ownership);
        Process child = startChild(token, ownership);
        String corruptEvidence = "corrupt ownership evidence\n";
        Files.writeString(ownership.registry(), corruptEvidence);

        long started = System.nanoTime();
        try {
            assertRegistryFailure(
                    cleanup,
                    ownership,
                    McpProcessOwnership.RegistryState.MALFORMED);
            assertBounded(started, "corrupt ownership registry");
            if (!child.isAlive()) {
                throw new AssertionError(
                        "cleanup terminated a process without valid ownership evidence");
            }
            if (!Files.readString(ownership.registry()).equals(corruptEvidence)) {
                throw new AssertionError("cleanup did not preserve the corrupt registry");
            }
        } finally {
            terminateForTest(child);
            deleteRecoveryEvidence(ownership);
        }

        assertNoOrphan(child, token);
        System.out.println(
                "OK: corrupt ownership registry failed closed and retained recovery evidence");
    }

    private static void verifyDeletedRegistryFailsClosed() throws Exception {
        String token = TaggedMcpLauncher.TOKEN_PREFIX
                + "deleted-registry-" + UUID.randomUUID();
        McpProcessOwnership ownership = McpProcessOwnership.createForAcceptance(token);
        McpClientCleanup cleanup = failingCleanup(ownership);
        Process child = startChild(token, ownership);
        Files.delete(ownership.registry());

        long started = System.nanoTime();
        try {
            assertRegistryFailure(
                    cleanup,
                    ownership,
                    McpProcessOwnership.RegistryState.MISSING);
            assertBounded(started, "deleted ownership registry");
            if (!child.isAlive()) {
                throw new AssertionError(
                        "cleanup terminated a process without valid ownership evidence");
            }
            if (Files.exists(ownership.registry())) {
                throw new AssertionError("cleanup recreated the deleted ownership registry");
            }
        } finally {
            terminateForTest(child);
            deleteRecoveryEvidence(ownership);
        }

        assertNoOrphan(child, token);
        System.out.println(
                "OK: deleted ownership registry failed closed and retained recovery evidence");
    }

    private static void verifyOversizedRegistryFailsClosed() throws Exception {
        String token = TaggedMcpLauncher.TOKEN_PREFIX
                + "oversized-registry-" + UUID.randomUUID();
        McpProcessOwnership ownership = McpProcessOwnership.createForAcceptance(token);
        McpClientCleanup cleanup = failingCleanup(ownership);
        Process child = startChild(token, ownership);
        Files.writeString(ownership.registry(), "x".repeat(4097));

        long started = System.nanoTime();
        try {
            assertRegistryFailure(
                    cleanup,
                    ownership,
                    McpProcessOwnership.RegistryState.OVERSIZED);
            assertBounded(started, "oversized ownership registry");
            if (!child.isAlive()) {
                throw new AssertionError(
                        "cleanup terminated a process without bounded ownership evidence");
            }
            if (Files.size(ownership.registry()) != 4097) {
                throw new AssertionError("cleanup did not preserve oversized evidence");
            }
        } finally {
            terminateForTest(child);
            deleteRecoveryEvidence(ownership);
        }

        assertNoOrphan(child, token);
        System.out.println(
                "OK: oversized ownership registry failed closed without unbounded parsing");
    }

    private static McpClientCleanup failingCleanup(McpProcessOwnership ownership) {
        return McpClientCleanup.forAcceptance(
                () -> false,
                () -> {
                },
                Duration.ofMillis(250),
                Duration.ofMillis(250),
                Duration.ofSeconds(1),
                ownership);
    }

    private static void assertRegistryFailure(
            McpClientCleanup cleanup,
            McpProcessOwnership ownership,
            McpProcessOwnership.RegistryState expectedState) throws Exception {
        IllegalStateException cleanupFailure = null;
        try {
            cleanup.close();
        } catch (IllegalStateException failure) {
            cleanupFailure = failure;
        }
        if (cleanupFailure == null
                || !cleanupFailure.getMessage().contains(
                        "could not verify process teardown")) {
            throw new AssertionError(
                    "invalid ownership registry did not produce an explicit cleanup failure",
                    cleanupFailure);
        }
        if (cleanupFailure.getMessage().contains("teardown completed")) {
            throw new AssertionError("cleanup falsely claimed process teardown", cleanupFailure);
        }
        if (!Files.exists(ownership.recoveryEvidence())) {
            throw new AssertionError("cleanup did not retain recovery evidence");
        }
        String recovery = Files.readString(ownership.recoveryEvidence());
        if (!recovery.contains("state=" + expectedState)) {
            throw new AssertionError(
                    "recovery evidence did not record " + expectedState + ": " + recovery);
        }
    }

    private static void deleteRecoveryEvidence(
            McpProcessOwnership ownership) throws Exception {
        Files.deleteIfExists(ownership.registry());
        Files.deleteIfExists(ownership.recoveryEvidence());
    }

    private static boolean terminateCooperatively(Process child) {
        if (child == null) {
            return true;
        }
        child.destroy();
        try {
            return child.waitFor(1, TimeUnit.SECONDS);
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static void blockIgnoringInterrupts(Duration duration) {
        long deadline = System.nanoTime() + duration.toNanos();
        while (System.nanoTime() < deadline) {
            LockSupport.parkNanos(deadline - System.nanoTime());
            Thread.interrupted();
        }
    }

    private static void terminateForTest(Process child) throws InterruptedException {
        if (child == null || !child.isAlive()) {
            return;
        }
        child.destroy();
        if (!child.waitFor(500, TimeUnit.MILLISECONDS)) {
            child.destroyForcibly();
            if (!child.waitFor(1, TimeUnit.SECONDS)) {
                throw new AssertionError(
                        "acceptance test could not terminate unrelated child PID " + child.pid());
            }
        }
    }

    private static void terminateProcessForTest(long pid) throws InterruptedException {
        if (pid <= 0) {
            return;
        }
        ProcessHandle.of(pid).filter(ProcessHandle::isAlive).ifPresent(process -> {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        });
        awaitProcessExit(pid, Duration.ofSeconds(1));
    }

    private static void awaitProcessExit(
            long pid,
            Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) {
            if (System.nanoTime() >= deadline) {
                throw new AssertionError("process PID " + pid + " is still alive");
            }
            Thread.sleep(20);
        }
    }

    private static Path newAbsentTempPath(String prefix, String suffix) throws Exception {
        Path path = Files.createTempFile(prefix, suffix).toAbsolutePath();
        Files.delete(path);
        return path;
    }

    private static void awaitControlFile(
            Path signal,
            Process launcher) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (!Files.exists(signal)) {
            if (!launcher.isAlive()) {
                throw new AssertionError(
                        "tagged launcher exited before parent guard signalled readiness");
            }
            if (System.nanoTime() >= deadline) {
                throw new AssertionError("parent guard did not signal readiness");
            }
            Thread.sleep(20);
        }
    }

    private static Process startChild(String token) throws Exception {
        return startChild(token, null);
    }

    private static Process startChild(
            String token,
            McpProcessOwnership ownership) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(
                javaExecutable(),
                "-cp",
                childClasspath(),
                MaverickChild.class.getName(),
                MaverickChild.CHILD_MODE,
                token);
        if (ownership != null) {
            builder.command().add("");
            builder.command().add(ownership.registry().toString());
        }
        Process child = builder
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        if (!child.isAlive()) {
            throw new AssertionError("maverick acceptance child exited before cleanup");
        }
        if (ownership != null) {
            awaitOwnershipRegistration(child, ownership);
        }
        return child;
    }

    private static void awaitOwnershipRegistration(
            Process child,
            McpProcessOwnership ownership) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(1).toNanos();
        do {
            McpProcessOwnership.Snapshot snapshot = ownership.snapshot();
            if (snapshot.valid()
                    && snapshot.roots().stream()
                            .anyMatch(process -> process.pid() == child.pid())) {
                return;
            }
            if (!child.isAlive()) {
                throw new AssertionError(
                        "maverick acceptance child exited before registering ownership");
            }
            Thread.sleep(20);
        } while (System.nanoTime() < deadline);
        terminateForTest(child);
        throw new AssertionError(
                "maverick acceptance child did not register ownership within one second");
    }

    private static String javaExecutable() {
        return Path.of(
                System.getProperty("java.home"),
                "bin",
                isWindows() ? "java.exe" : "java").toString();
    }

    private static String childClasspath() throws URISyntaxException {
        return codeLocation(MaverickChild.class)
                + File.pathSeparator
                + codeLocation(McpClientCleanup.class);
    }

    private static String codeLocation(Class<?> type) throws URISyntaxException {
        return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
    }

    private static void assertBounded(long started, String scenario) {
        Duration elapsed = Duration.ofNanos(System.nanoTime() - started);
        if (elapsed.compareTo(ACCEPTANCE_WALL_TIME) >= 0) {
            throw new AssertionError(
                    scenario + " exceeded " + ACCEPTANCE_WALL_TIME + ": " + elapsed);
        }
    }

    private static void assertNoOrphan(Process child, String token) throws InterruptedException {
        child.waitFor(1, TimeUnit.SECONDS);
        assertNoOrphan(child.pid(), token);
    }

    private static void assertNoOrphan(long pid, String token) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(1).toNanos();
        boolean orphan;
        do {
            orphan = ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)
                    || processWithTokenIsAlive(token);
            if (!orphan) {
                return;
            }
            Thread.sleep(20);
        } while (System.nanoTime() < deadline);
        throw new AssertionError("maverick child PID " + pid + " is still alive");
    }

    private static boolean processWithTokenIsAlive(String token) {
        try (Stream<ProcessHandle> processes = ProcessHandle.allProcesses()) {
            return processes
                    .filter(ProcessHandle::isAlive)
                    .anyMatch(process -> hasArgument(process, token));
        }
    }

    private static boolean hasArgument(ProcessHandle process, String token) {
        return process.info().arguments()
                .map(arguments -> Arrays.asList(arguments).contains(token))
                .orElse(false);
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows");
    }

    private static McpJsonMapper jsonMapper() {
        return ServiceLoader.load(McpJsonMapperSupplier.class)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No McpJsonMapper on test classpath"))
                .get();
    }

    private CleanupAcceptance() {
    }
}
