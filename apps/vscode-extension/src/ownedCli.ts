import { spawn, type ChildProcessWithoutNullStreams } from "child_process";
import { StringDecoder } from "string_decoder";

export interface CliOwner {
  result: Promise<{stdout: string; code: number}>;
  cancel: () => void;
}

/** Bounded direct child ownership. Stopping supervision never proves effects stopped. */
export function ownCli(cli: string, args: string[], options: {
  cwd?: string; timeoutMs?: number; maxBytes?: number; onLine?: (line: string) => void;
} = {}): CliOwner {
  let child: ChildProcessWithoutNullStreams | undefined;
  let settle: (reason: string) => void = () => {};
  const result = new Promise<{stdout: string; code: number}>((resolve, reject) => {
    let finished = false, stdout = "", line = "", bytes = 0;
    const stdoutDecoder = new StringDecoder("utf8"), stderrDecoder = new StringDecoder("utf8");
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error?: string, code = 0) => {
      if (finished) return; finished = true; clearTimeout(timer);
      if (error) {
        child?.kill("SIGKILL");
        reject(new Error(error + " The effect outcome is unconfirmed. Inspect recent runs before starting again; stopping this local process does not undo external work."));
      } else resolve({stdout, code});
    };
    settle = reason => finish(reason);
    try { child = spawn(cli, args, {cwd: options.cwd, shell: false, windowsHide: true}); }
    catch { finish("The local command could not be launched."); return; }
    timer = setTimeout(() => finish("The local command exceeded its deadline."), options.timeoutMs ?? 30000);
    const consume = (data: Buffer, isStdout: boolean) => {
      if (finished) return;
      bytes += data.byteLength;
      // A streamed run keeps no output, so only a total the caller chose or one endless line is bounded.
      const limit = options.maxBytes ?? 1024 * 1024;
      if (bytes > limit && (!options.onLine || options.maxBytes !== undefined)) { finish("The local command exceeded its output limit."); return; }
      const text = (isStdout ? stdoutDecoder : stderrDecoder).write(data);
      if (isStdout && !options.onLine) stdout += text;
      if (options.onLine) {
        line += text;
        let at: number;
        while ((at = line.indexOf("\n")) >= 0) {
          options.onLine(line.slice(0, at)); line = line.slice(at + 1);
        }
        if (line.length > limit) { finish("The local command exceeded its output limit."); return; }
      }
    };
    child.stdout.on("data", (data: Buffer) => consume(data, true));
    child.stderr.on("data", (data: Buffer) => consume(data, false));
    child.on("error", () => finish("The local command could not be started or supervised."));
    child.on("close", (code, signal) => {
      if (finished) return;
      if (options.onLine && line) options.onLine(line);
      if (code !== 0 || signal) finish(`The local command was not acknowledged (exit ${code}, signal ${signal}).`);
      else finish(undefined, code);
    });
  });
  return {result, cancel: () => settle("Local supervision was cancelled.")};
}
