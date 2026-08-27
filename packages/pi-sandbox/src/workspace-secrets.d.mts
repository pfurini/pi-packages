export declare const WORKSPACE_SECRET_DENY_WRITE_BASENAMES: readonly string[];
export declare const WORKSPACE_SECRET_DENY_WRITE_DIRECTORIES: readonly string[];
export declare const WORKSPACE_SECRET_DENY_WRITE_EXTENSIONS: readonly string[];
export declare const WORKSPACE_SECRET_TEMPLATE_BASENAMES: ReadonlySet<string>;

export declare function isSecretDenyWriteBasename(name: string): boolean;

export declare function createWorkspaceSecretDenyWritePaths(
  workspace: string,
  platform?: NodeJS.Platform,
): string[];
