import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { parse } from "yaml";

const REPO_ROOT = dirname(
  dirname(dirname(dirname(fileURLToPath(import.meta.url)))),
);
const WORKFLOW = join(REPO_ROOT, ".github", "workflows", "compat-latest.yml");

type Step = { uses?: string; env?: Record<string, unknown>; run?: string };
type Job = { env?: Record<string, unknown>; steps?: Step[] };

function workflow(): { jobs: Record<string, Job> } {
  return parse(readFileSync(WORKFLOW, "utf8")) as { jobs: Record<string, Job> };
}

const mentionsSecret = (env: Record<string, unknown> | undefined): boolean =>
  Object.values(env ?? {}).some((value) => String(value).includes("secrets."));

test("no job exposes repository secrets to every step", () => {
  // A job-level `env:` block puts secrets in the environment of *all* steps,
  // including `npm ci` and unpinned `@latest` installs, whose lifecycle scripts
  // would then run with the full provider credential set.
  for (const [name, job] of Object.entries(workflow().jobs)) {
    assert.equal(
      mentionsSecret(job.env),
      false,
      `job "${name}" declares secrets at job level; scope them to the step that needs them`,
    );
  }
});

test("steps that receive secrets never run an unpinned package install", () => {
  for (const [name, job] of Object.entries(workflow().jobs)) {
    for (const step of job.steps ?? []) {
      if (!mentionsSecret(step.env)) continue;
      assert.doesNotMatch(
        step.run ?? "",
        /@latest\b/,
        `job "${name}" installs an unpinned dependency in a step holding secrets`,
      );
    }
  }
});

test("every third-party action is pinned to a full commit SHA", () => {
  for (const [name, job] of Object.entries(workflow().jobs)) {
    for (const step of job.steps ?? []) {
      if (!step.uses) continue;
      assert.match(
        step.uses,
        /@[0-9a-f]{40}$/,
        `job "${name}" uses "${step.uses}"; pin it to a full commit SHA`,
      );
    }
  }
});
