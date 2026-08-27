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

test("a DANGLING symlink into protected space is hard-denied", () => {
  // realpathSync throws ENOENT on a dangling link, so a naive canonicalize
  // stops at the link's parent and hands back the link's own path -- never
  // following it. Writing through a dangling link CREATES its target, so this
  // is a live tampering path, not a theoretical one.
  const cwd = workspace();
  try {
    const link = join(cwd, "innocent.ts");
    symlinkSync(join(PACKAGE_ROOT, "src", "__does_not_exist__.ts"), link);
    assert.equal(
      protectedWriteHardDeny(
        { id: "d1", source: "permission-system", surface: "filesystem-write", operation: "write", cwd, resolvedPath: link },
        cwd,
      )?.rule,
      "security-control-tampering",
    );
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("a dangling symlink with a deeper missing tail is hard-denied", () => {
  const cwd = workspace();
  try {
    const link = join(cwd, "srcdir");
    symlinkSync(join(PACKAGE_ROOT, "src", "__missing_dir__"), link);
    assert.equal(
      protectedWriteHardDeny(
        { id: "d2", source: "permission-system", surface: "filesystem-write", operation: "write", cwd, resolvedPath: join(link, "nested", "evil.ts") },
        cwd,
      )?.rule,
      "security-control-tampering",
    );
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("a symlink cycle terminates and fails closed", () => {
  const cwd = workspace();
  try {
    symlinkSync(join(cwd, "b"), join(cwd, "a"));
    symlinkSync(join(cwd, "a"), join(cwd, "b"));
    // Must terminate rather than loop, and must deny: a cycle is unresolvable,
    // so we cannot show the target stays outside protected paths.
    assert.equal(
      protectedWriteHardDeny(
        { id: "d3", source: "permission-system", surface: "filesystem-write", operation: "write", cwd, resolvedPath: join(cwd, "a") },
        cwd,
      )?.rule,
      "unresolvable-symlink-chain",
    );
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("a symlink chain longer than the hop budget fails CLOSED", () => {
  // The hop bound stops runaway recursion, but returning the lexical path at
  // exhaustion fails OPEN: the kernel still follows the whole chain on write,
  // so a 13-deep chain reached protected space unblocked.
  const cwd = workspace();
  try {
    const depth = 40;
    for (let i = 0; i < depth; i++) {
      symlinkSync(
        i === depth - 1
          ? join(PACKAGE_ROOT, "src", "__missing__.ts")
          : join(cwd, `l${i + 1}`),
        join(cwd, `l${i}`),
      );
    }
    assert.ok(
      protectedWriteHardDeny(
        { id: "h1", source: "permission-system", surface: "filesystem-write", operation: "write", cwd, resolvedPath: join(cwd, "l0") },
        cwd,
      ),
      "a chain past the hop budget must be denied, not allowed",
    );
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("an unavailable trusted cwd does not fall back to the request's cwd", () => {
  // The old `context?.cwd ?? request.cwd` fallback reinstated the exact
  // weakness this function exists to close. Home-derived protections must
  // still apply when no trusted cwd is available.
  const attacker = workspace();
  try {
    assert.equal(
      protectedWriteHardDeny(
        { id: "u1", source: "sandbox-runtime", surface: "filesystem-write", operation: "write", cwd: attacker, resolvedPath: join(attacker, ".pi", "settings.json") },
        undefined,
      ),
      undefined,
      "an attacker-claimed cwd must not define the protected set",
    );
    assert.equal(
      protectedWriteHardDeny(
        { id: "u2", source: "sandbox-runtime", surface: "filesystem-write", operation: "write", cwd: attacker, resolvedPath: join(PACKAGE_ROOT, "src", "index.ts") },
        undefined,
      )?.rule,
      "security-control-tampering",
      "home-derived protections must still apply without a trusted cwd",
    );
  } finally {
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
