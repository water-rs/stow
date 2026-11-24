import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readdirSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

function resolveHomeDir() {
  const key = process.platform === "win32" ? "USERPROFILE" : "HOME";
  const fromEnv = (process.env[key] ?? "").trim();
  return fromEnv !== "" ? fromEnv : os.homedir();
}

function resolveStowCacheDir(homeDir) {
  const override = (process.env.STOW_CACHE_DIR ?? "").trim();
  return override !== "" ? override : path.join(homeDir, ".stow");
}

function resolveCargoHome(homeDir) {
  const override = (process.env.CARGO_HOME ?? "").trim();
  return override !== "" ? override : path.join(homeDir, ".cargo");
}

function computeRustcHash() {
  try {
    const out = execFileSync("rustc", ["-vV"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).replace(/\r\n/g, "\n");
    return createHash("sha256").update(out).digest("hex").slice(0, 16);
  } catch {
    return "no-rustc";
  }
}

function collectLockfiles(rootDir, maxDepth = 3) {
  const found = [];
  function walk(dir, depth) {
    if (!existsSync(dir)) return;
    const direct = path.join(dir, "Cargo.lock");
    if (existsSync(direct)) {
      found.push(direct);
    }
    if (depth >= maxDepth) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (
        entry.name === ".git" ||
        entry.name === "target" ||
        entry.name === "node_modules" ||
        entry.name.startsWith(".")
      ) {
        continue;
      }
      walk(path.join(dir, entry.name), depth + 1);
    }
  }
  walk(rootDir, 0);
  return found;
}

function computeLockHash(workspacesRaw) {
  const cwd = process.cwd();
  const roots = workspacesRaw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
  const effectiveRoots = roots.length > 0 ? roots : ["."];

  const allFiles = new Set();
  for (const rawRoot of effectiveRoots) {
    const resolved = path.resolve(cwd, rawRoot);
    const direct = path.join(resolved, "Cargo.lock");
    if (existsSync(direct)) {
      allFiles.add(direct);
    } else {
      for (const file of collectLockfiles(resolved)) {
        allFiles.add(file);
      }
    }
  }

  const sorted = [...allFiles].sort();
  if (sorted.length === 0) {
    return "unlocked";
  }

  const hash = createHash("sha256");
  for (const file of sorted) {
    const rel = path.relative(cwd, file).split(path.sep).join("/");
    const content = readFileSync(file, "utf8").replace(/\r\n/g, "\n");
    hash.update(rel);
    hash.update("\0");
    hash.update(content);
    hash.update("\0");
  }
  return hash.digest("hex").slice(0, 16);
}

function sanitizeSegment(raw) {
  return (
    raw
      .trim()
      .replace(/[^A-Za-z0-9_.-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 80) || "default"
  );
}

function writeOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath) {
    throw new Error("GITHUB_OUTPUT is not set");
  }
  if (value.includes("\n")) {
    const delimiter = "STOW_EOF_9f6b4e2a";
    appendFileSync(
      outputPath,
      `${name}<<${delimiter}\n${value}\n${delimiter}\n`,
      "utf8",
    );
  } else {
    appendFileSync(outputPath, `${name}=${value}\n`, "utf8");
  }
}

const homeDir = resolveHomeDir();
const stowCacheDir = resolveStowCacheDir(homeDir);
const cargoHome = resolveCargoHome(homeDir);
const runnerOs = sanitizeSegment(process.env.RUNNER_OS ?? process.platform);
const runnerArch = sanitizeSegment(process.env.RUNNER_ARCH ?? process.arch);
const rustcHash = computeRustcHash();
const sharedKey = (process.env.STOW_SHARED_KEY ?? "").trim();
const extraKey = (process.env.STOW_EXTRA_KEY ?? "").trim();
const jobScope = sanitizeSegment(
  sharedKey !== "" ? sharedKey : (process.env.GITHUB_JOB ?? "job"),
);
const scopeSlug =
  extraKey !== "" ? `${jobScope}-${sanitizeSegment(extraKey)}` : jobScope;
const lockHash = computeLockHash(process.env.STOW_WORKSPACES ?? ".");

const localPaths = [
  path.join(stowCacheDir, "local"),
  path.join(cargoHome, "git", "db"),
  path.join(cargoHome, "git", "checkouts"),
].join("\n");
const localCratesIoPath = path.join(stowCacheDir, "local-crates-io");

const localPrefix = `stow-v1-local-${runnerOs}-${runnerArch}-${rustcHash}`;
const localScopedPrefix = `${localPrefix}-${scopeSlug}-`;
const localCratesIoPrefix = `stow-v1-local-crates-io-${runnerOs}-${runnerArch}-${rustcHash}`;
const localCratesIoScopedPrefix = `${localCratesIoPrefix}-${scopeSlug}-`;

writeOutput("local-paths", localPaths);
writeOutput("local-crates-io-path", localCratesIoPath);
writeOutput("local-key", `${localScopedPrefix}${lockHash}`);
writeOutput("local-restore-keys", `${localScopedPrefix}\n${localPrefix}-`);
writeOutput("local-crates-io-key", `${localCratesIoScopedPrefix}${lockHash}`);
writeOutput(
  "local-crates-io-restore-keys",
  `${localCratesIoScopedPrefix}\n${localCratesIoPrefix}-`,
);
