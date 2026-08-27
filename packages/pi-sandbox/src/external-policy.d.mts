import type { SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";

export declare function sanitizeExternalReadPaths(
  raw: string | undefined,
  roots: { cwd: string; agentDir: string },
): string[];

export declare function containedPath(
  value: string | undefined,
  roots: { cwd: string; agentDir: string },
): string | undefined;

export declare function usableRealPiBinary(
  value: string | undefined,
): string | undefined;

export declare function createExternalWorkerPolicy(options: {
  cwd: string;
  agentDir: string;
  home: string;
  packageRoot: string;
  nodeRoot: string;
  runtimeRoot: string;
  sessionDir?: string;
  workerTempDir?: string;
  nodeBinDir: string;
  extraRead?: readonly string[];
  gitReadPaths?: readonly string[];
  existingGitConfig?: readonly string[];
  network?: {
    allowedDomains: readonly string[];
    deniedDomains: readonly string[];
  };
  platform?: NodeJS.Platform;
}): SandboxRuntimeConfig;
