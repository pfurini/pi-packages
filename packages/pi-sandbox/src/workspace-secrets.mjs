import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";

// Plain ESM (not TypeScript) so the external worker launcher, which runs as a
// bare `node` script and cannot import `.ts`, shares one implementation with
// `policy.ts` instead of duplicating the deny list. `policy.ts` re-exports
// everything here; `workspace-secrets.d.mts` carries the types.

/** Common secret basenames always denied at the workspace root (even if missing). */
export const WORKSPACE_SECRET_DENY_WRITE_BASENAMES = [
  ".env",
  ".env.local",
  ".env.development",
  ".env.development.local",
  ".env.test",
  ".env.test.local",
  ".env.production",
  ".env.production.local",
  ".env.staging",
  ".env.staging.local",
  ".env.ci",
];

/** Secret-like directories denied at the workspace root (even if missing). */
export const WORKSPACE_SECRET_DENY_WRITE_DIRECTORIES = ["secrets", ".secrets"];

/** Private-key / certificate extensions denied when discovered under the workspace. */
export const WORKSPACE_SECRET_DENY_WRITE_EXTENSIONS = [
  ".pem",
  ".key",
  ".p12",
  ".pfx",
];

/**
 * Template / sample env files that agents may legitimately create or edit.
 * These are excluded from secret write denials.
 */
export const WORKSPACE_SECRET_TEMPLATE_BASENAMES = new Set([
  ".env.example",
  ".env.sample",
  ".env.template",
  ".env.dist",
]);

const WALK_SKIP_DIRECTORIES = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  ".cache",
  "target",
  "vendor",
]);

/** Bounded workspace walk used to discover nested secrets on every platform. */
const WORKSPACE_SECRET_SCAN_MAX_DEPTH = 4;

/**
 * macOS Seatbelt supports git-style globs; Linux bubblewrap silently drops them.
 * Keep these as an extra nested-create defense on Darwin only.
 */
const DARWIN_SECRET_DENY_WRITE_GLOBS = [
  "**/.env",
  "**/.env.local",
  "**/.env.development",
  "**/.env.development.local",
  "**/.env.test",
  "**/.env.test.local",
  "**/.env.production",
  "**/.env.production.local",
  "**/.env.staging",
  "**/.env.staging.local",
  "**/.env.ci",
  "**/secrets",
  "**/secrets/**",
  "**/.secrets",
  "**/.secrets/**",
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.pfx",
];

export function isSecretDenyWriteBasename(name) {
  if (WORKSPACE_SECRET_TEMPLATE_BASENAMES.has(name)) {
    return false;
  }
  if (WORKSPACE_SECRET_DENY_WRITE_BASENAMES.includes(name)) {
    return true;
  }
  // Catch less common variants such as `.env.preview` while sparing templates.
  if (name.startsWith(".env.")) {
    return true;
  }
  const lower = name.toLowerCase();
  return WORKSPACE_SECRET_DENY_WRITE_EXTENSIONS.some((extension) =>
    lower.endsWith(extension),
  );
}

function collectNestedSecretDenyWritePaths(
  workspace,
  maxDepth = WORKSPACE_SECRET_SCAN_MAX_DEPTH,
) {
  const discovered = [];

  const visit = (directory, depth) => {
    if (depth > maxDepth) {
      return;
    }
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name === "." || entry.name === "..") {
        continue;
      }
      const fullPath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (WALK_SKIP_DIRECTORIES.has(entry.name)) {
          continue;
        }
        if (WORKSPACE_SECRET_DENY_WRITE_DIRECTORIES.includes(entry.name)) {
          discovered.push(fullPath);
          continue;
        }
        visit(fullPath, depth + 1);
        continue;
      }
      if (entry.isFile() && isSecretDenyWriteBasename(entry.name)) {
        discovered.push(fullPath);
      }
    }
  };

  visit(workspace, 0);
  return discovered;
}

/**
 * Build workspace secret write denials.
 *
 * - Always includes root-level secret basenames/directories as absolute paths so
 *   Linux can block both existing files and first-time creation.
 * - Scans a shallow workspace tree for nested secrets that already exist.
 * - Adds Darwin-only globs so nested creates are also blocked on macOS.
 */
export function createWorkspaceSecretDenyWritePaths(
  workspace,
  platform = process.platform,
) {
  const root = resolve(workspace);
  const paths = new Set();

  for (const name of WORKSPACE_SECRET_DENY_WRITE_BASENAMES) {
    paths.add(join(root, name));
  }
  for (const name of WORKSPACE_SECRET_DENY_WRITE_DIRECTORIES) {
    paths.add(join(root, name));
  }
  for (const discovered of collectNestedSecretDenyWritePaths(root)) {
    paths.add(discovered);
  }
  if (platform === "darwin") {
    for (const pattern of DARWIN_SECRET_DENY_WRITE_GLOBS) {
      paths.add(pattern);
    }
  }

  return [...paths];
}
