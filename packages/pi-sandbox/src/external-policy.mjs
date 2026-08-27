import { statSync } from "node:fs";
import { isAbsolute, join, parse, relative, resolve } from "node:path";
import { createWorkspaceSecretDenyWritePaths } from "./workspace-secrets.mjs";

// Plain ESM so the external worker launcher, which runs as a bare `node`
// script, can share this with the TypeScript side. Kept separate from the
// launcher itself purely so the policy is testable without spawning a worker.

function isWithin(parent, child) {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/**
 * Filter `PI_SANDBOX_EXTERNAL_ALLOW_READ` down to paths the launcher is willing
 * to expose.
 *
 * The launcher builds the sandbox boundary, so it must not treat its own
 * environment as trusted: those variables are visible inside every sandbox
 * (see H2). Entries must be absolute and contained by the workspace or the
 * agent directory; anything else is dropped rather than failing the whole
 * worker, since a stale entry should not be fatal.
 */
export function sanitizeExternalReadPaths(raw, { cwd, agentDir }) {
  const allowed = [];
  for (const entry of String(raw ?? "").split(":")) {
    const candidate = containedPath(entry, { cwd, agentDir });
    if (candidate && !allowed.includes(candidate)) allowed.push(candidate);
  }
  return allowed;
}

/**
 * Resolve `value` and return it only when it is absolute and contained by the
 * workspace or the agent directory. Shared by every environment-sourced path,
 * read or write: `PI_CODING_AGENT_SESSION_DIR` reaches the launcher on exactly
 * the same footing as `PI_SANDBOX_EXTERNAL_ALLOW_READ`, and it lands in
 * `allowWrite`, so an absolute-path check alone would hand the sandbox an
 * arbitrary writable location.
 */
export function containedPath(value, { cwd, agentDir }) {
  if (!value || typeof value !== "string" || !isAbsolute(value)) return undefined;
  const candidate = resolve(value);
  const roots = [resolve(cwd), resolve(agentDir)];
  return roots.some((root) => isWithin(root, candidate)) ? candidate : undefined;
}

/**
 * Validate `PI_SANDBOX_EXTERNAL_REAL_PI_BINARY` before the wrapper execs it.
 *
 * Scope, stated honestly: this rejects a relative path, a missing path, and a
 * non-file, but it does NOT prove the binary is Pi's own runtime. The injecting
 * side sets this to the *parent's* `process.execPath`, while the launcher runs
 * under `#!/usr/bin/env node`, so the two legitimately differ whenever Pi runs
 * on a different Node than the one on PATH (nvm, volta, a bundled runtime).
 * Requiring equality would fail those installs closed at worker startup, which
 * is a worse outcome than the residual risk: anything able to set this
 * wrapper's environment already controls the Pi process that spawns it.
 */
export function usableRealPiBinary(value) {
  if (!value || typeof value !== "string" || !isAbsolute(value)) return undefined;
  try {
    return statSync(value).isFile() ? value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Build the outer Sandbox Runtime policy for a pi-subagents external worker.
 *
 * `denyWrite` is kept a superset of `createDefaultPolicy`'s: the launcher
 * previously hand-rolled this config and omitted every workspace secret
 * denial, the agent log directory, and the legacy config path, so an external
 * worker was less protected than an ordinary sandboxed command.
 */
export function createExternalWorkerPolicy({
  cwd,
  agentDir,
  home,
  packageRoot,
  nodeRoot,
  runtimeRoot,
  sessionDir,
  workerTempDir,
  nodeBinDir,
  extraRead = [],
  gitReadPaths = [],
  existingGitConfig = [],
  network = { allowedDomains: [], deniedDomains: [] },
  platform = process.platform,
}) {
  const workspace = resolve(cwd);
  const agent = resolve(agentDir);
  const containedSessionDir = containedPath(sessionDir, { cwd, agentDir });
  const resolvedHome = resolve(home);

  // On Linux Sandbox Runtime masks the first missing component of a deny path.
  // Denying a not-yet-created `.pi/settings.json` would therefore mask `.pi`
  // itself and prevent Pi from creating its ordinary project state directory,
  // which is why the launcher seeds placeholders before building this policy.
  // Existing security files remain outer-sandbox protected; creation attempts
  // are still gated by permission-system and pi-auto-review.
  const workspaceSecurityFiles = [
    join(workspace, ".pi", "settings.json"),
    join(workspace, ".pi", "sandbox.json"),
    join(workspace, ".pi", "pi-auto-review.json"),
  ];
  // Mirrors createDefaultPolicy's agent-directory deny set, including the
  // audit log directory and the legacy config path the launcher had dropped.
  const agentSecurityPaths = [
    join(agent, "settings.json"),
    join(agent, "permissions.json"),
    join(agent, "sandbox.json"),
    join(agent, "pi-sandbox.json"),
    join(agent, "logs"),
    join(agent, "extensions"),
    join(agent, "extensions", "pi-sandbox", "config.json"),
  ];

  return {
    filesystem: {
      denyRead: resolvedHome === parse(resolvedHome).root ? [] : [resolvedHome],
      allowRead: [
        workspace,
        nodeRoot,
        runtimeRoot,
        ...existingGitConfig,
        "/dev/null",
        ...gitReadPaths,
        ...extraRead,
      ],
      allowWrite: [
        workspace,
        "/dev/null",
        ...(workerTempDir ? [workerTempDir] : []),
        ...(containedSessionDir ? [containedSessionDir] : []),
        // H1: the agent directory is still writable here. Narrowing it needs
        // the set of paths Pi legitimately creates at startup, which is not
        // yet established; the deny entries below are the defense in depth.
        agent,
      ],
      denyWrite: [
        ...workspaceSecurityFiles,
        ...agentSecurityPaths,
        packageRoot,
        nodeBinDir,
        ...createWorkspaceSecretDenyWritePaths(workspace, platform),
      ],
      allowGitConfig: true,
    },
    network: {
      allowedDomains: [...network.allowedDomains],
      deniedDomains: [...network.deniedDomains],
      allowAllUnixSockets: false,
      allowUnixSockets: [],
      allowLocalBinding: false,
    },
  };
}
