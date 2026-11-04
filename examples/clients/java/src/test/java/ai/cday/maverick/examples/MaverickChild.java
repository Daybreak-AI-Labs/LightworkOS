package ai.cday.maverick.examples;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * An intentionally unresponsive process used by {@link CleanupAcceptance}.
 */
public final class MaverickChild {

    static final String CHILD_MODE = "--maverick-child";

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || !CHILD_MODE.equals(args[0])) {
            throw new IllegalArgumentException("expected " + CHILD_MODE);
        }
        if (args.length >= 4) {
            McpProcessOwnership.registerActive(
                    Path.of(args[3]), args[1], ProcessHandle.current());
        }
        if (args.length >= 3 && !args[2].isBlank()) {
            Files.writeString(Path.of(args[2]), Long.toString(ProcessHandle.current().pid()));
        }
        Thread.sleep(Duration.ofMinutes(2));
    }

    private MaverickChild() {
    }
}
