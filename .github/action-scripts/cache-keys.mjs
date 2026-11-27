import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

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

function isRegularFile(filePath) {
  try {
    return statSync(filePath).isFile();
  } catch {
    return false;
  }
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

function scanTomlLine(line, state) {
  let out = "";
  let i = 0;
  let singleQuote = null;
  let delta = 0;
  const len = line.length;

  while (i < len) {
    if (state.multilineQuote === '"""') {
      if (line[i] === "\\" && i + 1 < len) {
        out += line[i] + line[i + 1];
        i += 2;
        continue;
      }
      if (line.startsWith('"""', i)) {
        let extra = 0;
        while (extra < 2 && line[i + 3 + extra] === '"') extra++;
        const count = 3 + extra;
        out += line.slice(i, i + count);
        i += count;
        state.multilineQuote = null;
        continue;
      }
      out += line[i];
      i++;
      continue;
    }

    if (state.multilineQuote === "'''") {
      if (line.startsWith("'''", i)) {
        let extra = 0;
        while (extra < 2 && line[i + 3 + extra] === "'") extra++;
        const count = 3 + extra;
        out += line.slice(i, i + count);
        i += count;
        state.multilineQuote = null;
        continue;
      }
      out += line[i];
      i++;
      continue;
    }

    if (singleQuote === '"') {
      if (line[i] === "\\" && i + 1 < len) {
        out += line[i] + line[i + 1];
        i += 2;
        continue;
      }
      if (line[i] === '"') {
        singleQuote = null;
      }
      out += line[i];
      i++;
      continue;
    }

    if (singleQuote === "'") {
      if (line[i] === "'") {
        singleQuote = null;
      }
      out += line[i];
      i++;
      continue;
    }

    const ch = line[i];
    if (ch === "#") {
      break;
    }
    if (line.startsWith('"""', i)) {
      out += '"""';
      i += 3;
      state.multilineQuote = '"""';
      continue;
    }
    if (line.startsWith("'''", i)) {
      out += "'''";
      i += 3;
      state.multilineQuote = "'''";
      continue;
    }
    if (ch === '"' || ch === "'") {
      singleQuote = ch;
      out += ch;
      i++;
      continue;
    }
    if (ch === "[" || ch === "{") {
      delta++;
    } else if (ch === "]" || ch === "}") {
      delta--;
    }
    out += ch;
    i++;
  }

  return { text: out, delta };
}

function parseTomlKeyPathWithRest(raw) {
  const segments = [];
  let i = 0;
  const len = raw.length;

  while (i < len) {
    while (i < len && (raw[i] === " " || raw[i] === "\t")) i++;
    if (i >= len) return null;

    let seg = "";
    if (raw[i] === '"') {
      i++;
      let closed = false;
      while (i < len) {
        if (raw[i] === "\\" && i + 1 < len) {
          seg += raw[i + 1];
          i += 2;
          continue;
        }
        if (raw[i] === '"') {
          i++;
          closed = true;
          break;
        }
        seg += raw[i];
        i++;
      }
      if (!closed) return null;
    } else if (raw[i] === "'") {
      i++;
      let closed = false;
      while (i < len) {
        if (raw[i] === "'") {
          i++;
          closed = true;
          break;
        }
        seg += raw[i];
        i++;
      }
      if (!closed) return null;
    } else {
      const start = i;
      while (
        i < len &&
        raw[i] !== "." &&
        raw[i] !== " " &&
        raw[i] !== "\t" &&
        raw[i] !== "="
      ) {
        i++;
      }
      if (i === start) return null;
      seg = raw.slice(start, i);
    }
    segments.push(seg);

    while (i < len && (raw[i] === " " || raw[i] === "\t")) i++;
    if (i < len && raw[i] === ".") {
      i++;
    } else {
      return { segments, restIndex: i };
    }
  }

  return null;
}

function parseTableHeader(trimmed) {
  let inner;
  if (trimmed.startsWith("[[") && trimmed.endsWith("]]")) {
    inner = trimmed.slice(2, -2);
  } else if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    inner = trimmed.slice(1, -1);
  } else {
    return null;
  }
  const parsed = parseTomlKeyPathWithRest(inner);
  if (parsed === null || parsed.restIndex !== inner.length) {
    return null;
  }
  return parsed.segments;
}

export function stripTomlCommentsAndBlanks(content) {
  const normalized = content.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
  const state = { multilineQuote: null };
  const out = [];

  for (const line of normalized.split("\n")) {
    const wasInMultiline = state.multilineQuote !== null;
    const { text } = scanTomlLine(line, state);
    if (!wasInMultiline && state.multilineQuote === null) {
      const trimmed = text.trim();
      if (trimmed !== "") {
        out.push(trimmed);
      }
    } else if (!wasInMultiline && state.multilineQuote !== null) {
      out.push(text.trimStart());
    } else if (wasInMultiline && state.multilineQuote === null) {
      out.push(text.trimEnd());
    } else {
      out.push(text);
    }
  }

  return out.join("\n");
}

export function extractProfileSections(content) {
  const normalized = content.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
  const state = { multilineQuote: null };
  let nestedDepth = 0;
  let section = "root";
  let capturingRootProfile = false;
  const out = [];

  for (const line of normalized.split("\n")) {
    const wasInMultiline = state.multilineQuote !== null;
    const wasInNested = nestedDepth > 0;
    const { text, delta } = scanTomlLine(line, state);

    if (wasInMultiline) {
      const formatted = state.multilineQuote === null ? text.trimEnd() : text;
      if (section === "profile" || capturingRootProfile) {
        out.push(formatted);
      }
      nestedDepth = Math.max(0, nestedDepth + delta);
      if (state.multilineQuote === null && nestedDepth === 0) {
        capturingRootProfile = false;
      }
      continue;
    }

    if (state.multilineQuote !== null) {
      const formatted = text.trimStart();
      if (!wasInNested && section === "root") {
        const parsed = parseTomlKeyPathWithRest(formatted);
        if (
          parsed !== null &&
          parsed.segments[0] === "profile" &&
          formatted[parsed.restIndex] === "="
        ) {
          capturingRootProfile = true;
        }
      }
      if (section === "profile" || capturingRootProfile) {
        out.push(formatted);
      }
      nestedDepth = Math.max(0, nestedDepth + delta);
      continue;
    }

    const trimmed = text.trim();
    if (trimmed === "") {
      continue;
    }

    if (wasInNested) {
      if (section === "profile" || capturingRootProfile) {
        out.push(trimmed);
      }
      nestedDepth = Math.max(0, nestedDepth + delta);
      if (nestedDepth === 0) {
        capturingRootProfile = false;
      }
      continue;
    }

    const header = parseTableHeader(trimmed);
    if (header !== null) {
      section = header[0] === "profile" ? "profile" : "other";
      capturingRootProfile = false;
      if (section === "profile") {
        out.push(trimmed);
      }
      continue;
    }

    nestedDepth = Math.max(0, nestedDepth + delta);
    if (section === "profile") {
      out.push(trimmed);
    } else if (section === "root") {
      const parsed = parseTomlKeyPathWithRest(trimmed);
      if (
        parsed !== null &&
        parsed.segments[0] === "profile" &&
        trimmed[parsed.restIndex] === "="
      ) {
        out.push(trimmed);
        if (nestedDepth > 0) {
          capturingRootProfile = true;
        }
      }
    }
  }

  return out.join("\n");
}

function collectLockfiles(rootDir, maxDepth = 3) {
  const found = [];
  function walk(dir, depth) {
    if (!existsSync(dir)) return;
    const direct = path.join(dir, "Cargo.lock");
    if (isRegularFile(direct)) {
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

function collectCargoConfigFiles(cwd, workspaceDirs) {
  const resolvedCwd = path.resolve(cwd);
  const candidateDirs = new Set([resolvedCwd]);

  for (const dir of workspaceDirs) {
    const resolvedDir = path.resolve(dir);
    candidateDirs.add(resolvedDir);

    const rel = path.relative(resolvedCwd, resolvedDir);
    if (rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel)) {
      let cur = path.dirname(resolvedDir);
      while (cur !== resolvedCwd) {
        candidateDirs.add(cur);
        const next = path.dirname(cur);
        if (next === cur) break;
        cur = next;
      }
    }
  }

  const found = new Set();
  for (const dir of candidateDirs) {
    for (const name of ["config.toml", "config"]) {
      const candidate = path.join(dir, ".cargo", name);
      if (isRegularFile(candidate)) {
        found.add(candidate);
      }
    }
  }
  return [...found];
}

function toRelPosix(cwd, file) {
  return path.relative(cwd, file).split(path.sep).join("/");
}

function compareStrings(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function computeLockHash(workspacesRaw, cwd = process.cwd()) {
  const resolvedCwd = path.resolve(cwd);
  const roots = workspacesRaw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
  const effectiveRoots = roots.length > 0 ? roots : ["."];

  const lockfiles = new Set();
  const manifestDirs = new Set();
  for (const rawRoot of effectiveRoots) {
    const resolved = path.resolve(resolvedCwd, rawRoot);
    manifestDirs.add(resolved);
    const direct = path.join(resolved, "Cargo.lock");
    if (isRegularFile(direct)) {
      lockfiles.add(direct);
    } else {
      for (const file of collectLockfiles(resolved)) {
        lockfiles.add(file);
      }
    }
  }

  for (const lockfile of lockfiles) {
    manifestDirs.add(path.dirname(lockfile));
  }

  const sortedLockfiles = [...lockfiles]
    .map((file) => ({ file, rel: toRelPosix(resolvedCwd, file) }))
    .sort((a, b) => compareStrings(a.rel, b.rel));

  const profileEntries = [];
  for (const dir of manifestDirs) {
    const manifest = path.join(dir, "Cargo.toml");
    if (!isRegularFile(manifest)) continue;
    const profiles = extractProfileSections(readFileSync(manifest, "utf8"));
    if (profiles !== "") {
      profileEntries.push({
        rel: toRelPosix(resolvedCwd, manifest),
        content: profiles,
      });
    }
  }
  profileEntries.sort((a, b) => compareStrings(a.rel, b.rel));

  const cargoConfigEntries = [];
  for (const file of collectCargoConfigFiles(resolvedCwd, manifestDirs)) {
    const normalized = stripTomlCommentsAndBlanks(readFileSync(file, "utf8"));
    if (normalized !== "") {
      cargoConfigEntries.push({
        rel: toRelPosix(resolvedCwd, file),
        content: normalized,
      });
    }
  }
  cargoConfigEntries.sort((a, b) => compareStrings(a.rel, b.rel));

  if (
    sortedLockfiles.length === 0 &&
    profileEntries.length === 0 &&
    cargoConfigEntries.length === 0
  ) {
    return "unlocked";
  }

  const hash = createHash("sha256");
  if (sortedLockfiles.length === 0) {
    hash.update("unlocked\0");
  } else {
    for (const { file, rel } of sortedLockfiles) {
      const content = readFileSync(file, "utf8").replace(/\r\n/g, "\n");
      hash.update(rel);
      hash.update("\0");
      hash.update(content);
      hash.update("\0");
    }
  }

  for (const { rel, content } of profileEntries) {
    hash.update("profile\0");
    hash.update(rel);
    hash.update("\0");
    hash.update(content);
    hash.update("\0");
  }

  for (const { rel, content } of cargoConfigEntries) {
    hash.update("cargo-config\0");
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

function main() {
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
}

function isEntrypoint() {
  if (!process.argv[1]) return false;
  try {
    return (
      realpathSync(process.argv[1]) ===
      realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
  }
}

if (isEntrypoint()) {
  main();
}
