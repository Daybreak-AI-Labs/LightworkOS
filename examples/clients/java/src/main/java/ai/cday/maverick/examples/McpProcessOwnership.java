package ai.cday.maverick.examples;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Session-specific process ownership recorded outside the MCP SDK.
 *
 * <p>The SDK does not expose its stdio {@link Process}. A unique registry
 * records both PID and process start time for the tagged launcher and real MCP
 * server, so cleanup can recover exact handles without relying on process-list
 * timing or optional command-line metadata. Start time prevents a stale PID
 * from becoming authority over a later, unrelated process.
 */
final class McpProcessOwnership implements AutoCloseable {

    private static final String REGISTRY_MAGIC = "maverick-mcp-process-registry-v1";
    private static final String RECOVERY_MAGIC = "maverick-mcp-cleanup-recovery-v1";
    private static final int MAX_REGISTRY_BYTES = 4096;
    private static final int MAX_REGISTRY_LINES = 20;
    private static final int MAX_PROCESS_RECORDS = 16;

    private final String token;
    private final Path registry;
    private final int minimumActiveRecords;
    private boolean closed;
    private boolean retainEvidence;

    static McpProcessOwnership create(String token) throws IOException {
        return create(token, 2);
    }

    static McpProcessOwnership createForAcceptance(String token) throws IOException {
        return create(token, 1);
    }

    private static McpProcessOwnership create(
            String token,
            int minimumActiveRecords) throws IOException {
        requireToken(token);
        Path registry = Files.createTempFile(
                TaggedMcpLauncher.TOKEN_PREFIX, ".processes").toAbsolutePath();
        return new McpProcessOwnership(token, registry, minimumActiveRecords);
    }

    private McpProcessOwnership(
            String token,
            Path registry,
            int minimumActiveRecords) {
        this.token = token;
        this.registry = registry;
        this.minimumActiveRecords = minimumActiveRecords;
    }

    Path registry() {
        return registry;
    }

    Path recoveryEvidence() {
        return registry.resolveSibling(registry.getFileName() + ".cleanup-failure");
    }

    Snapshot snapshot() {
        byte[] encoded;
        try {
            try (InputStream input = Files.newInputStream(registry)) {
                encoded = input.readNBytes(MAX_REGISTRY_BYTES + 1);
            }
        } catch (NoSuchFileException failure) {
            return Snapshot.invalid(
                    RegistryState.MISSING,
                    "ownership registry is missing",
                    failure);
        } catch (IOException failure) {
            return Snapshot.invalid(
                    RegistryState.UNREADABLE,
                    "ownership registry could not be read",
                    failure);
        } catch (SecurityException failure) {
            return Snapshot.invalid(
                    RegistryState.UNREADABLE,
                    "access to the ownership registry was denied",
                    failure);
        }
        if (encoded.length > MAX_REGISTRY_BYTES) {
            return Snapshot.invalid(
                    RegistryState.OVERSIZED,
                    "ownership registry exceeds " + MAX_REGISTRY_BYTES + " bytes",
                    null);
        }

        String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded))
                    .toString();
        } catch (CharacterCodingException failure) {
            return Snapshot.invalid(
                    RegistryState.MALFORMED,
                    "ownership registry is not valid UTF-8",
                    failure);
        }
        List<String> lines = decoded.lines().toList();
        if (lines.size() > MAX_REGISTRY_LINES) {
            return Snapshot.invalid(
                    RegistryState.OVERSIZED,
                    "ownership registry exceeds " + MAX_REGISTRY_LINES + " lines",
                    null);
        }
        if (lines.isEmpty()) {
            return Snapshot.invalid(
                    RegistryState.UNREGISTERED,
                    "transport never registered process ownership",
                    null);
        }
        if (!REGISTRY_MAGIC.equals(lines.getFirst())) {
            return Snapshot.invalid(
                    RegistryState.MALFORMED,
                    "ownership registry has an invalid header",
                    null);
        }
        if (lines.size() < 4) {
            return Snapshot.invalid(
                    RegistryState.MALFORMED,
                    "ownership registry has no complete process record",
                    null);
        }
        if (!token.equals(lines.get(1))) {
            return Snapshot.invalid(
                    RegistryState.TOKEN_MISMATCH,
                    "ownership registry token does not match this MCP session",
                    null);
        }

        RegistryPhase phase;
        try {
            phase = RegistryPhase.valueOf(lines.get(2));
        } catch (IllegalArgumentException failure) {
            return Snapshot.invalid(
                    RegistryState.MALFORMED,
                    "ownership registry has an invalid lifecycle phase",
                    failure);
        }
        int recordCount = lines.size() - 3;
        if (recordCount > MAX_PROCESS_RECORDS) {
            return Snapshot.invalid(
                    RegistryState.OVERSIZED,
                    "ownership registry exceeds "
                            + MAX_PROCESS_RECORDS
                            + " process records",
                    null);
        }
        if (phase == RegistryPhase.ACTIVE && recordCount < minimumActiveRecords) {
            return Snapshot.invalid(
                    RegistryState.INCOMPLETE,
                    "active ownership registry contains only "
                            + recordCount
                            + " process record(s); expected at least "
                            + minimumActiveRecords,
                    null);
        }

        Set<ProcessHandle> owned = new LinkedHashSet<>();
        Set<Long> recordedPids = new LinkedHashSet<>();
        for (String line : lines.subList(3, lines.size())) {
            String[] fields = line.split(",", -1);
            if (fields.length != 2) {
                return Snapshot.invalid(
                        RegistryState.MALFORMED,
                        "ownership registry contains a malformed process record",
                        null);
            }
            try {
                long pid = Long.parseLong(fields[0]);
                long startedEpochMillis = Long.parseLong(fields[1]);
                if (pid <= 0 || startedEpochMillis <= 0 || !recordedPids.add(pid)) {
                    return Snapshot.invalid(
                            RegistryState.MALFORMED,
                            "ownership registry contains an invalid process identity",
                            null);
                }
                Optional<ProcessHandle> candidate = ProcessHandle.of(pid);
                if (candidate.isEmpty()) {
                    continue;
                }
                ProcessHandle process = candidate.get();
                if (process.pid() == ProcessHandle.current().pid()) {
                    return Snapshot.invalid(
                            RegistryState.UNVERIFIABLE,
                            "ownership registry unexpectedly identifies the client process",
                            null);
                }
                Optional<Instant> actualStart = process.info().startInstant();
                if (actualStart.isEmpty()) {
                    return Snapshot.invalid(
                            RegistryState.UNVERIFIABLE,
                            "process start time is unavailable for PID " + pid,
                            null);
                }
                if (actualStart.get().toEpochMilli() == startedEpochMillis) {
                    owned.add(process);
                }
            } catch (NumberFormatException failure) {
                return Snapshot.invalid(
                        RegistryState.MALFORMED,
                        "ownership registry contains a non-numeric process identity",
                        failure);
            } catch (SecurityException failure) {
                return Snapshot.invalid(
                        RegistryState.UNVERIFIABLE,
                        "ownership identity could not be verified",
                        failure);
            }
        }
        if (phase == RegistryPhase.STARTING) {
            return Snapshot.invalid(
                    RegistryState.STARTING,
                    owned,
                    "transport ownership registry never reached ACTIVE",
                    null);
        }
        return Snapshot.valid(owned, recordedPids.size());
    }

    static void registerStarting(
            Path registry,
            String token,
            ProcessHandle launcher) throws IOException {
        register(registry, token, RegistryPhase.STARTING, launcher);
    }

    static void registerActive(
            Path registry,
            String token,
            ProcessHandle... processes) throws IOException {
        register(registry, token, RegistryPhase.ACTIVE, processes);
    }

    private static void register(
            Path registry,
            String token,
            RegistryPhase phase,
            ProcessHandle... processes) throws IOException {
        Objects.requireNonNull(registry, "registry");
        requireToken(token);
        Objects.requireNonNull(phase, "phase");
        if (processes.length == 0 || processes.length > MAX_PROCESS_RECORDS) {
            throw new IllegalArgumentException(
                    "owned process count must be between 1 and " + MAX_PROCESS_RECORDS);
        }

        StringBuilder contents = new StringBuilder(REGISTRY_MAGIC)
                .append('\n')
                .append(token)
                .append('\n')
                .append(phase)
                .append('\n');
        for (ProcessHandle process : processes) {
            Objects.requireNonNull(process, "process");
            Instant started = process.info().startInstant()
                    .orElseThrow(() -> new IOException(
                            "process start time unavailable for PID " + process.pid()));
            contents.append(process.pid())
                    .append(',')
                    .append(started.toEpochMilli())
                    .append('\n');
        }

        replaceAtomically(registry, contents);
    }

    synchronized void retainForRecovery(
            String state,
            String detail) {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(detail, "detail");
        retainEvidence = true;
        StringBuilder contents = new StringBuilder(RECOVERY_MAGIC)
                .append('\n')
                .append("token=")
                .append(token)
                .append('\n')
                .append("registry=")
                .append(singleLine(registry.toString()))
                .append('\n')
                .append("state=")
                .append(singleLine(state))
                .append('\n')
                .append("detail=")
                .append(singleLine(detail))
                .append('\n')
                .append("observed=")
                .append(Instant.now())
                .append('\n');
        try {
            replaceAtomically(recoveryEvidence(), contents);
        } catch (IOException | SecurityException failure) {
            System.err.printf(
                    "WARNING: could not write MCP cleanup recovery evidence %s: %s%n",
                    recoveryEvidence(),
                    failure.getMessage());
        }
    }

    private static void replaceAtomically(
            Path destination,
            CharSequence contents) throws IOException {
        Path absolute = destination.toAbsolutePath();
        Path temporary = Files.createTempFile(
                absolute.getParent(), absolute.getFileName().toString(), ".tmp");
        try {
            Files.writeString(
                    temporary,
                    contents,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            try {
                Files.move(
                        temporary,
                        absolute,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException failure) {
                Files.move(temporary, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static String singleLine(String value) {
        return value.replace('\r', ' ').replace('\n', ' ');
    }

    private static void requireToken(String token) {
        Objects.requireNonNull(token, "ownershipToken");
        if (!token.startsWith(TaggedMcpLauncher.TOKEN_PREFIX)
                || token.length() > 200
                || token.indexOf('\n') >= 0
                || token.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("invalid MCP ownership token");
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        if (retainEvidence) {
            System.err.printf(
                    "WARNING: retained MCP cleanup recovery evidence at %s%n",
                    recoveryEvidence());
            return;
        }
        try {
            Files.deleteIfExists(registry);
            Files.deleteIfExists(recoveryEvidence());
        } catch (IOException | SecurityException failure) {
            System.err.printf(
                    "WARNING: could not remove MCP process registry %s: %s%n",
                    registry,
                    failure.getMessage());
        }
    }

    enum RegistryState {
        VALID,
        UNREGISTERED,
        MISSING,
        UNREADABLE,
        MALFORMED,
        TOKEN_MISMATCH,
        UNVERIFIABLE,
        OVERSIZED,
        INCOMPLETE,
        STARTING
    }

    record Snapshot(
            RegistryState state,
            Set<ProcessHandle> roots,
            String detail,
            Throwable failure) {

        Snapshot {
            Objects.requireNonNull(state, "state");
            roots = Set.copyOf(roots);
            Objects.requireNonNull(detail, "detail");
        }

        static Snapshot valid(Set<ProcessHandle> roots, int recordCount) {
            return new Snapshot(
                    RegistryState.VALID,
                    roots,
                    "valid ownership registry with " + recordCount + " process record(s)",
                    null);
        }

        static Snapshot invalid(
                RegistryState state,
                String detail,
                Throwable failure) {
            return invalid(state, Set.of(), detail, failure);
        }

        static Snapshot invalid(
                RegistryState state,
                Set<ProcessHandle> roots,
                String detail,
                Throwable failure) {
            if (state == RegistryState.VALID) {
                throw new IllegalArgumentException("invalid snapshot cannot use VALID state");
            }
            return new Snapshot(state, roots, detail, failure);
        }

        boolean valid() {
            return state == RegistryState.VALID;
        }
    }

    private enum RegistryPhase {
        STARTING,
        ACTIVE
    }
}
