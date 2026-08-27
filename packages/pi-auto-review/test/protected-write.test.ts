import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { protectedWriteHardDeny } from "../src/index.ts";

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

function workspace(): string {
  return mkdtempSync(join(tmpdir(), "pi-auto-review-protected-"));
}

test("a workspace symlink pointing at security extension code is hard-denied", () => {
  const cwd = workspace();
  try {
    const link = join(cwd, "innocent.ts");
    symlinkSync(join(PACKAGE_ROOT, "src", "index.ts"), link);
    const deny = protectedWriteHardDeny(
      {
        id: "r1",
        source: "permission-system",
        surface: "filesystem-write",
        operation: "write",
        cwd,
        resolvedPath: link,
      },
      cwd,
    );
    assert.equal(deny?.rule, "security-control-tampering");
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("a symlinked directory below a protected root is hard-denied", () => {
  const cwd = workspace();
  try {
    const link = join(cwd, "srcdir");
    symlinkSync(join(PACKAGE_ROOT, "src"), link);
    const deny = protectedWriteHardDeny(
      {
        id: "r2",
        source: "permission-system",
        surface: "filesystem-write",
        operation: "write",
        cwd,
        resolvedPath: join(link, "policy.ts"),
      },
      cwd,
    );
    assert.equal(deny?.rule, "security-control-tampering");
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("workspace protections follow the trusted cwd, not the request's claimed cwd", () => {
  const trusted = workspace();
  const attacker = workspace();
  try {
    mkdirSync(join(trusted, ".pi"), { recursive: true });
    writeFileSync(join(trusted, ".pi", "settings.json"), "{}\n");
    const deny = protectedWriteHardDeny(
      {
        id: "r3",
        source: "sandbox-runtime",
        surface: "filesystem-write",
        operation: "write",
        // A sandboxed process controls this value (trap.process.cwd).
        cwd: attacker,
        resolvedPath: join(trusted, ".pi", "settings.json"),
      },
      trusted,
    );
    assert.equal(deny?.rule, "security-control-tampering");
  } finally {
    rmSync(trusted, { recursive: true, force: true });
    rmSync(attacker, { recursive: true, force: true });
  }
});

test("ordinary workspace writes stay allowed", () => {
  const cwd = workspace();
  try {
    for (const target of ["src/app.ts", "README.md", ".pi/notes.json"]) {
      assert.equal(
        protectedWriteHardDeny(
          {
            id: "r4",
            source: "permission-system",
            surface: "filesystem-write",
            operation: "write",
            cwd,
            resolvedPath: join(cwd, target),
          },
          cwd,
        ),
        undefined,
        `expected ${target} to be allowed`,
      );
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});
