// Hand-written declarations for `workspace-secrets.mjs`. tsc does not check the
// `.mjs`, so these must be kept in step with it by hand. The literal tuples
// below are load-bearing: consumers use `typeof X[number]` to derive unions,
// which a widened `readonly string[]` would silently destroy.

export declare const WORKSPACE_SECRET_DENY_WRITE_BASENAMES: readonly [
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

export declare const WORKSPACE_SECRET_DENY_WRITE_DIRECTORIES: readonly [
  "secrets",
  ".secrets",
];

export declare const WORKSPACE_SECRET_DENY_WRITE_EXTENSIONS: readonly [
  ".pem",
  ".key",
  ".p12",
  ".pfx",
];

export declare const WORKSPACE_SECRET_TEMPLATE_BASENAMES: ReadonlySet<string>;

export declare function isSecretDenyWriteBasename(name: string): boolean;

export declare function createWorkspaceSecretDenyWritePaths(
  workspace: string,
  platform?: NodeJS.Platform,
): string[];
