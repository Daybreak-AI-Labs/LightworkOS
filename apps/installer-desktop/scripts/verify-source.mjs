#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const CANONICAL_REPOSITORY = "Daybreak-AI-Labs/LightworkOS";
const CANONICAL_REMOTE_URLS = new Set([
  "https://github.com/Daybreak-AI-Labs/LightworkOS",
  "https://github.com/Daybreak-AI-Labs/LightworkOS.git",
  "git@github.com:Daybreak-AI-Labs/LightworkOS.git",
  "ssh://git@github.com/Daybreak-AI-Labs/LightworkOS.git",
]);
const VERIFIED_ROOTS = ["apps/installer-desktop", "apps/desktop-runtime"];
const VERIFIED_FILES = [
  "deploy/desktop/install.sh",
  "deploy/desktop/install.ps1",
];
const GENERATED_DIRECTORIES = [
  "apps/installer-desktop/coverage",
  "apps/installer-desktop/dist",
  "apps/installer-desktop/node_modules",
  "apps/installer-desktop/provenance",
  "apps/installer-desktop/src-tauri/gen",
  "apps/installer-desktop/src-tauri/target",
  "apps/desktop-runtime/target",
];

function fail(message) {
  throw new Error(`desktop source verification failed: ${message}`);
}

function sanitizedGitEnvironment() {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_")) {
      environment[key] = value;
    }
  }
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_TERMINAL_PROMPT = "0";
  return environment;
}

function gitResult(repositoryRoot, args) {
  return spawnSync("git", ["--no-replace-objects", ...args], {
    cwd: repositoryRoot,
    encoding: null,
    env: sanitizedGitEnvironment(),
    windowsHide: true,
  });
}

function git(repositoryRoot, args) {
  const result = gitResult(repositoryRoot, args);
  if (result.error) {
    fail(`git ${args.join(" ")} could not start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const stderr = Buffer.from(result.stderr ?? Buffer.alloc(0))
      .toString("utf8")
      .trim();
    fail(`git ${args.join(" ")} failed${stderr ? `: ${stderr}` : ""}`);
  }
  return Buffer.from(result.stdout ?? Buffer.alloc(0));
}

function utf8(buffer, description) {
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  if (decoded.includes("\0")) {
    fail(`${description} contained an unexpected NUL byte`);
  }
  return decoded.trim();
}

function validateCommit(value, description) {
  const commit = value.trim();
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    fail(`${description} must be a lowercase, full 40-character commit SHA`);
  }
  return commit;
}

function normalizeRepositoryPath(path) {
  return path.split(sep).join("/");
}

function isGeneratedPath(repositoryPath) {
  return (
    repositoryPath.endsWith(".tsbuildinfo") ||
    GENERATED_DIRECTORIES.some(
      (directory) =>
        repositoryPath === directory ||
        repositoryPath.startsWith(`${directory}/`),
    )
  );
}

function parseTrackedBlobs(repositoryRoot, installRef) {
  const output = git(repositoryRoot, [
    "ls-tree",
    "-r",
    "-z",
    "--full-tree",
    installRef,
    "--",
    ...VERIFIED_ROOTS,
    ...VERIFIED_FILES,
  ]);
  const tracked = new Map();
  const records = new TextDecoder("utf-8", { fatal: true }).decode(output);
  for (const rawRecord of records.split("\0")) {
    if (!rawRecord) continue;
    const separator = rawRecord.indexOf("\t");
    if (separator < 0) {
      fail("git ls-tree emitted a malformed record");
    }
    const [mode, type, objectId] = rawRecord
      .slice(0, separator)
      .split(" ");
    const repositoryPath = rawRecord.slice(separator + 1);
    if (
      !/^[0-9a-f]{40,64}$/.test(objectId ?? "") ||
      !/^[0-7]{6}$/.test(mode ?? "")
    ) {
      fail(`git ls-tree emitted malformed metadata for ${repositoryPath}`);
    }
    if (type !== "blob" || mode === "120000") {
      fail(
        `tracked installer source must be a regular blob, not ${mode} ${type}: ${repositoryPath}`,
      );
    }
    if (
      repositoryPath.startsWith("/") ||
      repositoryPath.includes("\\") ||
      repositoryPath
        .split("/")
        .some((component) => ["", ".", ".."].includes(component)) ||
      !(
        VERIFIED_ROOTS.some((root) => repositoryPath.startsWith(`${root}/`)) ||
        VERIFIED_FILES.includes(repositoryPath)
      )
    ) {
      fail(`git ls-tree escaped the verified source scope: ${repositoryPath}`);
    }
    if (isGeneratedPath(repositoryPath)) {
      fail(`generated build output must not be tracked: ${repositoryPath}`);
    }
    tracked.set(repositoryPath, objectId);
  }
  for (const required of VERIFIED_FILES) {
    if (!tracked.has(required)) {
      fail(`required bootstrap is absent from ${installRef}: ${required}`);
    }
  }
  return tracked;
}

function collectWorktreeFiles(repositoryRoot) {
  const actual = new Set();

  function visit(absoluteDirectory) {
    const entries = readdirSync(absoluteDirectory, { withFileTypes: true }).sort(
      (left, right) => left.name.localeCompare(right.name),
    );
    for (const entry of entries) {
      const absolutePath = join(absoluteDirectory, entry.name);
      const repositoryPath = normalizeRepositoryPath(
        relative(repositoryRoot, absolutePath),
      );
      if (isGeneratedPath(repositoryPath)) continue;
      const metadata = lstatSync(absolutePath);
      if (metadata.isSymbolicLink()) {
        fail(`symbolic links are not allowed in verified source: ${repositoryPath}`);
      }
      if (metadata.isDirectory()) {
        visit(absolutePath);
      } else if (metadata.isFile()) {
        actual.add(repositoryPath);
      } else {
        fail(`unsupported filesystem entry in verified source: ${repositoryPath}`);
      }
    }
  }

  for (const root of VERIFIED_ROOTS) visit(join(repositoryRoot, ...root.split("/")));
  for (const repositoryPath of VERIFIED_FILES) {
    const absolutePath = join(repositoryRoot, ...repositoryPath.split("/"));
    const metadata = lstatSync(absolutePath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      fail(`required bootstrap is not a regular file: ${repositoryPath}`);
    }
    actual.add(repositoryPath);
  }
  return actual;
}

function verifyRawSnapshot(repositoryRoot, installRef) {
  const tracked = parseTrackedBlobs(repositoryRoot, installRef);
  const actual = collectWorktreeFiles(repositoryRoot);
  const missing = [...tracked.keys()].filter((path) => !actual.has(path)).sort();
  const unexpected = [...actual].filter((path) => !tracked.has(path)).sort();
  if (missing.length || unexpected.length) {
    const details = [
      missing.length ? `missing: ${missing.join(", ")}` : "",
      unexpected.length ? `untracked: ${unexpected.join(", ")}` : "",
    ]
      .filter(Boolean)
      .join("; ");
    fail(`worktree file set differs from ${installRef} (${details})`);
  }

  for (const [repositoryPath, objectId] of [...tracked.entries()].sort()) {
    const committed = git(repositoryRoot, ["cat-file", "blob", objectId]);
    const worktree = readFileSync(
      join(repositoryRoot, ...repositoryPath.split("/")),
    );
    if (!committed.equals(worktree)) {
      fail(`raw bytes differ from ${installRef}: ${repositoryPath}`);
    }
  }
  return tracked.size;
}

function verifyCanonicalRepository(repositoryRoot) {
  const remote = utf8(
    git(repositoryRoot, [
      "config",
      "--local",
      "--no-includes",
      "--get",
      "remote.origin.url",
    ]),
    "remote.origin.url",
  );
  if (!CANONICAL_REMOTE_URLS.has(remote)) {
    fail(
      `origin must be the canonical ${CANONICAL_REPOSITORY} repository, not ${remote}`,
    );
  }
}

function verifyRef(repositoryRoot, installRef, requireHead) {
  const head = validateCommit(
    utf8(git(repositoryRoot, ["rev-parse", "HEAD"]), "git HEAD"),
    "git HEAD",
  );
  const resolved = validateCommit(
    utf8(
      git(repositoryRoot, [
        "rev-parse",
        "--verify",
        `${installRef}^{commit}`,
      ]),
      "resolved install ref",
    ),
    "resolved install ref",
  );
  if (resolved !== installRef) {
    fail("install ref did not resolve to the exact requested commit");
  }
  const ancestor = gitResult(repositoryRoot, [
    "merge-base",
    "--is-ancestor",
    installRef,
    head,
  ]);
  if (ancestor.error) {
    fail(`git merge-base could not start: ${ancestor.error.message}`);
  }
  if (ancestor.status === 1) {
    fail(`install ref ${installRef} is not an ancestor of HEAD ${head}`);
  }
  if (ancestor.status !== 0) {
    const stderr = Buffer.from(ancestor.stderr ?? Buffer.alloc(0))
      .toString("utf8")
      .trim();
    fail(`git merge-base failed${stderr ? `: ${stderr}` : ""}`);
  }
  if (requireHead && installRef !== head) {
    fail("release-grade verification requires the install ref to equal HEAD");
  }
  return head;
}

function parseArguments(argv) {
  let repositoryRoot;
  let installRef;
  let requireHead = false;
  let canonicalizeCheckout = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--repo") {
      repositoryRoot = argv[++index];
    } else if (argument === "--ref") {
      installRef = argv[++index];
    } else if (argument === "--require-head") {
      requireHead = true;
    } else if (argument === "--canonicalize-checkout") {
      canonicalizeCheckout = true;
    } else {
      fail(`unknown argument: ${argument}`);
    }
  }
  if (!repositoryRoot || !installRef) {
    fail(
      "usage: verify-source.mjs --repo <path> --ref <sha> [--require-head] [--canonicalize-checkout]",
    );
  }
  const resolvedRoot = resolve(repositoryRoot);
  if (!isAbsolute(resolvedRoot)) {
    fail("repository root must resolve to an absolute path");
  }
  return {
    repositoryRoot: resolvedRoot,
    installRef: validateCommit(installRef, "install ref"),
    requireHead,
    canonicalizeCheckout,
  };
}

export function verifyDesktopSource({
  repositoryRoot,
  installRef,
  requireHead = false,
  canonicalizeCheckout = false,
}) {
  const root = resolve(repositoryRoot);
  verifyCanonicalRepository(root);
  let head = verifyRef(root, installRef, requireHead);
  if (canonicalizeCheckout) {
    if (!requireHead) {
      fail("checkout canonicalization is allowed only with --require-head");
    }
    git(root, ["config", "--local", "core.autocrlf", "false"]);
    git(root, ["config", "--local", "core.eol", "lf"]);
    // A checkout made with autocrlf on leaves CRLF files that the index
    // records as clean, so `reset --hard` alone rewrites none of them. Empty
    // the index first so every tracked file is written again from its blob.
    git(root, ["read-tree", "--empty"]);
    git(root, ["reset", "--hard", installRef]);
    head = verifyRef(root, installRef, true);
  }
  const files = verifyRawSnapshot(root, installRef);
  return { files, head, installRef };
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const result = verifyDesktopSource(parseArguments(process.argv.slice(2)));
    process.stdout.write(
      `Verified ${result.files} desktop source files at ${result.installRef}.\n`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}
