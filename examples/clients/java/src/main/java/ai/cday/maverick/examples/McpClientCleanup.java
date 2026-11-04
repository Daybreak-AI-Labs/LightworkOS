package ai.cday.maverick.examples;

import io.modelcontextprotocol.client.McpSyncClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Bounded, process-aware cleanup for the SDK's stdio client.
 *
 * <p>{@link McpSyncClient#closeGracefully()} waits up to ten seconds and returns
 * {@code false} when it cannot finish. A runnable example must not ignore that
 * result: an uncooperative stdio server would otherwise survive the Java
 * process. This guard caps the graceful attempt, invokes the SDK's fallback
 * close under a separate cap, and terminates only the MCP launcher/server roots
 * in the session registry and their captured descendants.
 */
final class McpClientCleanup implements AutoCloseable {

    static final Duration DEFAULT_GRACEFUL_TIMEOUT = Duration.ofSeconds(2);
    static final Duration DEFAULT_FALLBACK_TIMEOUT = Duration.ofMillis(500);
    static final Duration DEFAULT_PROCESS_TIMEOUT = Duration.ofSeconds(2);

    private final BooleanSupplier gracefulClose;
    private final Runnable fallbackClose;
    private final Duration gracefulTimeout;
    private final Duration fallbackTimeout;
    private final Duration processTimeout;
    private final McpProcessOwnership ownership;
    private boolean closed;

    static McpClientCleanup manage(McpSyncClient client, McpProcessOwnership ownership) {
        Objects.requireNonNull(client, "client");
        return new McpClientCleanup(
                client::closeGracefully,
                client::close,
                DEFAULT_GRACEFUL_TIMEOUT,
                DEFAULT_FALLBACK_TIMEOUT,
                DEFAULT_PROCESS_TIMEOUT,
                ownership);
    }

    static McpClientCleanup forAcceptance(
            BooleanSupplier gracefulClose,
            Runnable fallbackClose,
            Duration gracefulTimeout,
            Duration fallbackTimeout,
            Duration processTimeout,
            McpProcessOwnership ownership) {
        return new McpClientCleanup(
                gracefulClose,
                fallbackClose,
                gracefulTimeout,
                fallbackTimeout,
                processTimeout,
                ownership);
    }

    private McpClientCleanup(
            BooleanSupplier gracefulClose,
            Runnable fallbackClose,
            Duration gracefulTimeout,
            Duration fallbackTimeout,
            Duration processTimeout,
            McpProcessOwnership ownership) {
        this.gracefulClose = Objects.requireNonNull(gracefulClose, "gracefulClose");
        this.fallbackClose = Objects.requireNonNull(fallbackClose, "fallbackClose");
        this.gracefulTimeout = requirePositive(gracefulTimeout, "gracefulTimeout");
        this.fallbackTimeout = requirePositive(fallbackTimeout, "fallbackTimeout");
        this.processTimeout = requirePositive(processTimeout, "processTimeout");
        this.ownership = Objects.requireNonNull(ownership, "ownership");
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;

        McpProcessOwnership.Snapshot invalidOwnership = null;
        boolean survivors = false;
        try {
            // Capture the registered transport roots and their descendants
            // before graceful close can terminate and re-parent them.
            Set<ProcessHandle> owned = new LinkedHashSet<>();
            invalidOwnership = collectOwnedProcesses(owned, invalidOwnership);
            CloseAttempt attempt = runGracefulClose();
            invalidOwnership = collectOwnedProcesses(owned, invalidOwnership);
            if (invalidOwnership == null
                    && attempt.graceful()
                    && awaitExit(owned, Duration.ofMillis(100))) {
                return;
            }

            BoundedAttempt<Void> fallback = runBounded(
                    () -> {
                        fallbackClose.run();
                        return null;
                    },
                    fallbackTimeout,
                    "maverick-mcp-fallback-close");
            invalidOwnership = collectOwnedProcesses(owned, invalidOwnership);
            boolean allExited = terminate(owned);
            survivors = !allExited;
            boolean teardownVerified = invalidOwnership == null && allExited;
            System.err.printf(
                    "WARNING: MCP graceful close %s; fallback close %s; forced process teardown %s%n",
                    attempt.detail(),
                    fallback.detail(),
                    invalidOwnership != null
                            ? "unverified because " + invalidOwnership.detail()
                            : allExited ? "completed" : "left survivors");

            if (!teardownVerified || !fallback.completed()) {
                String message = invalidOwnership != null
                        ? "MCP cleanup could not verify process teardown because "
                                + invalidOwnership.detail()
                                + "; recovery evidence retained at "
                                + ownership.recoveryEvidence()
                        : !allExited
                                ? "MCP cleanup left child process(es) alive after forced termination"
                                : "MCP fallback close " + fallback.detail();
                Throwable cause = invalidOwnership != null
                        ? invalidOwnership.failure()
                        : fallback.failure();
                IllegalStateException failure = new IllegalStateException(message, cause);
                if (fallback.failure() != null && fallback.failure() != cause) {
                    failure.addSuppressed(fallback.failure());
                }
                if (attempt.failure() != null
                        && attempt.failure() != cause
                        && attempt.failure() != fallback.failure()) {
                    failure.addSuppressed(attempt.failure());
                }
                throw failure;
            }
        } finally {
            if (invalidOwnership != null) {
                String detail = invalidOwnership.detail();
                if (survivors) {
                    detail += "; one or more verified process handles survived termination";
                }
                ownership.retainForRecovery(invalidOwnership.state().toString(), detail);
            } else if (survivors) {
                ownership.retainForRecovery(
                        "SURVIVORS",
                        "one or more verified process handles survived termination");
            }
            ownership.close();
        }
    }

    private CloseAttempt runGracefulClose() {
        BoundedAttempt<Boolean> attempt = runBounded(
                gracefulClose::getAsBoolean,
                gracefulTimeout,
                "maverick-mcp-graceful-close");
        boolean graceful = attempt.completed() && Boolean.TRUE.equals(attempt.value());
        String detail = graceful
                ? "completed"
                : attempt.completed() ? "returned false" : attempt.detail();
        return new CloseAttempt(graceful, detail, attempt.failure());
    }

    private static <T> BoundedAttempt<T> runBounded(
            Callable<T> operation,
            Duration timeout,
            String threadName) {
        FutureTask<T> task = new FutureTask<>(operation);
        Thread worker = Thread.ofPlatform()
                .daemon(true)
                .name(threadName)
                .unstarted(task);
        worker.start();

        try {
            T value = task.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
            return new BoundedAttempt<>(true, value, "completed", null);
        } catch (TimeoutException failure) {
            task.cancel(true);
            return new BoundedAttempt<>(
                    false, null, "timed out after " + timeout, failure);
        } catch (InterruptedException failure) {
            task.cancel(true);
            Thread.currentThread().interrupt();
            return new BoundedAttempt<>(false, null, "was interrupted", failure);
        } catch (ExecutionException failure) {
            Throwable cause = failure.getCause() == null ? failure : failure.getCause();
            return new BoundedAttempt<>(
                    false, null, "raised " + cause.getClass().getSimpleName(), cause);
        }
    }

    private boolean terminate(Set<ProcessHandle> owned) {
        expandDescendants(owned);
        destroy(owned, false);
        if (awaitExit(owned, processTimeout.dividedBy(2))) {
            return true;
        }

        expandDescendants(owned);
        destroy(owned, true);
        return awaitExit(owned, processTimeout.dividedBy(2));
    }

    private static void destroy(Collection<ProcessHandle> processes, boolean forcibly) {
        List<ProcessHandle> alive = processes.stream()
                .filter(ProcessHandle::isAlive)
                .collect(Collectors.toCollection(ArrayList::new));
        // Every handle was snapshotted before termination, so a child remains
        // addressable even if terminating its parent causes it to be re-parented.
        for (ProcessHandle process : alive) {
            try {
                if (forcibly) {
                    process.destroyForcibly();
                } else {
                    process.destroy();
                }
            } catch (RuntimeException ignored) {
                // Continue through the whole owned tree. The bounded liveness
                // check below is authoritative and reports any survivor.
            }
        }
    }

    private static void expandDescendants(Set<ProcessHandle> processes) {
        List<ProcessHandle> roots = List.copyOf(processes);
        for (ProcessHandle root : roots) {
            try (Stream<ProcessHandle> descendants = root.descendants()) {
                processes.addAll(descendants.toList());
            }
        }
    }

    private McpProcessOwnership.Snapshot collectOwnedProcesses(
            Set<ProcessHandle> owned,
            McpProcessOwnership.Snapshot previousInvalid) {
        McpProcessOwnership.Snapshot snapshot = ownership.snapshot();
        owned.addAll(snapshot.roots());
        expandDescendants(owned);
        if (!snapshot.valid()) {
            return previousInvalid == null ? snapshot : previousInvalid;
        }
        return previousInvalid;
    }

    private static boolean awaitExit(Collection<ProcessHandle> processes, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        boolean interrupted = false;
        try {
            while (processes.stream().anyMatch(ProcessHandle::isAlive)) {
                if (System.nanoTime() >= deadline) {
                    return false;
                }
                try {
                    Thread.sleep(20);
                } catch (InterruptedException failure) {
                    interrupted = true;
                }
            }
            return true;
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static Duration requirePositive(Duration value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return value;
    }

    private record BoundedAttempt<T>(
            boolean completed,
            T value,
            String detail,
            Throwable failure) {
    }

    private record CloseAttempt(boolean graceful, String detail, Throwable failure) {
    }
}
