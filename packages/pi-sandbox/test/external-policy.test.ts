import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createDefaultPolicy } from "../src/policy.ts";
import {
  createExternalWorkerPolicy,
  sanitizeExternalReadPaths,
  usableRealPiBinary,
} from "../src/external-policy.mjs";

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), "pi-sandbox-external-policy-"));
  mkdirSync(join(dir, "nested"), { recursive: true });
  writeFileSync(join(dir, ".env"), "SECRET=1\n");
  writeFileSync(join(dir, "nested", "server.key"), "key\n");
  return dir;
}

function policyFor(cwd: string, agentDir: string) {
  return createExternalWorkerPolicy({
    cwd,
    agentDir,
    home: join(agentDir, "..", ".."),
    packageRoot: PACKAGE_ROOT,
    nodeBinDir: dirname(process.execPath),
    nodeRoot: "/usr/local",
    runtimeRoot: "/opt/srt",
    platform: "darwin",
    network: { allowedDomains: [], deniedDomains: [] },
  });
}

test("external worker denyWrite is a superset of the default policy's", () => {
  const cwd = workspace();
  try {
    // The launcher used to hand-roll its runtimeConfig and silently omitted
    // every workspace secret denial plus the agent log/legacy-config entries.
    const agentDir = join(process.env.HOME ?? "/root", ".pi", "agent");
    const external = new Set(policyFor(cwd, agentDir).filesystem.denyWrite);
    for (const path of createDefaultPolicy(cwd).filesystem.denyWrite) {
      assert.ok(
        external.has(path),
        `external policy is missing default-policy denyWrite entry: ${path}`,
      );
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("external worker denyWrite covers workspace secrets and agent audit data", () => {
  const cwd = workspace();
  const agentDir = join(cwd, "fake-agent");
  try {
    const denyWrite = policyFor(cwd, agentDir).filesystem.denyWrite;
    for (const expected of [
      join(cwd, ".env"),
      join(cwd, "nested", "server.key"),
      join(agentDir, "logs"),
      join(agentDir, "pi-sandbox.json"),
      join(agentDir, "extensions"),
    ]) {
      assert.ok(
        denyWrite.includes(expected),
        `expected denyWrite to include ${expected}`,
      );
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("extra read paths must be absolute and inside the workspace or agent dir", () => {
  const cwd = "/work/project";
  const agentDir = "/home/u/.pi/agent";
  assert.deepEqual(
    sanitizeExternalReadPaths(
      [
        "/work/project/vendor",
        "/home/u/.pi/agent/npm",
        "relative/path",
        "/etc/shadow",
        "/home/u/.ssh",
        "",
        "/work/project/vendor",
      ].join(":"),
      { cwd, agentDir },
    ),
    ["/work/project/vendor", "/home/u/.pi/agent/npm"],
  );
});

test("extra read paths reject traversal that escapes the workspace", () => {
  assert.deepEqual(
    sanitizeExternalReadPaths("/work/project/../../etc", {
      cwd: "/work/project",
      agentDir: "/home/u/.pi/agent",
    }),
    [],
  );
});

test("an out-of-scope sessionDir never becomes a writable sandbox path", () => {
  // PI_CODING_AGENT_SESSION_DIR is read from the launcher's environment on the
  // same trust footing as PI_SANDBOX_EXTERNAL_ALLOW_READ, but lands in
  // allowWrite. An absolute-path check alone would grant an arbitrary writable
  // path inside the sandbox.
  const cwd = workspace();
  const agentDir = join(cwd, "fake-agent");
  try {
    for (const hostile of ["/etc", "/", "/home/other/.ssh", `${cwd}/../escape`]) {
      const allowWrite = createExternalWorkerPolicy({
        cwd,
        agentDir,
        home: join(agentDir, "..", ".."),
        packageRoot: PACKAGE_ROOT,
        nodeBinDir: dirname(process.execPath),
        nodeRoot: "/usr/local",
        runtimeRoot: "/opt/srt",
        platform: "linux",
        sessionDir: hostile,
        network: { allowedDomains: [], deniedDomains: [] },
      }).filesystem.allowWrite;
      assert.ok(
        !allowWrite.includes(hostile),
        `sessionDir ${hostile} must not be writable`,
      );
    }
    // A legitimate session dir under the agent directory is still honored.
    const legit = join(agentDir, "sessions");
    assert.ok(
      createExternalWorkerPolicy({
        cwd,
        agentDir,
        home: join(agentDir, "..", ".."),
        packageRoot: PACKAGE_ROOT,
        nodeBinDir: dirname(process.execPath),
        nodeRoot: "/usr/local",
        runtimeRoot: "/opt/srt",
        platform: "linux",
        sessionDir: legit,
        network: { allowedDomains: [], deniedDomains: [] },
      }).filesystem.allowWrite.includes(legit),
      "a session dir under the agent directory must stay writable",
    );
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("the real Pi binary must be an absolute path to an existing file", () => {
  // Deliberately not an identity check against process.execPath: the launcher
  // runs under `#!/usr/bin/env node` while the parent injects its own
  // execPath, so those differ on nvm/volta/bundled-runtime installs and
  // equality would fail worker startup closed. See usableRealPiBinary.
  assert.equal(usableRealPiBinary(process.execPath), process.execPath);
  assert.equal(usableRealPiBinary("/tmp/does-not-exist-pi-binary"), undefined);
  assert.equal(usableRealPiBinary("node"), undefined);
  assert.equal(usableRealPiBinary("../../bin/node"), undefined);
  assert.equal(usableRealPiBinary(tmpdir()), undefined, "a directory is not a binary");
  assert.equal(usableRealPiBinary(undefined), undefined);
  assert.equal(usableRealPiBinary(""), undefined);
});
