/**
 * Browser ↔ Polaron Client Evidence Agent (runs on the examiner's own computer).
 *
 * The agent lists this computer's drives/folders and publishes one selected
 * folder as a read-only, token-protected share. The forensic server then reads
 * the evidence in place over the LAN — nothing is uploaded from the browser.
 *
 * Only loopback addresses are used here (http://127.0.0.1 / http://localhost),
 * which browsers allow from an HTTPS console page.
 */

import { resolveApiUrl } from "./api";
import { inferApiService } from "./apiRouting";

export const CLIENT_AGENT_PORT = 9877;

const CONFIGURED_BASE = (import.meta.env.VITE_CLIENT_EVIDENCE_AGENT_URL as string | undefined)?.replace(/\/$/, "");
const AGENT_BASES = CONFIGURED_BASE
  ? [CONFIGURED_BASE]
  : [`http://127.0.0.1:${CLIENT_AGENT_PORT}`, `http://localhost:${CLIENT_AGENT_PORT}`];

/** Same evidence-file pattern as the server drive browser. */
export const EVIDENCE_FILE_RE =
  /\.(?:E(?:\d{2}|(?!xe|wf)[A-Za-z]{2})|001|002|003|004|005|006|007|008|009|dd|raw|aff|aff4|vmdk|vhdx|pas(?:\d+)?|ufd|ufdt|ufdx|zip)$/i;

export const HIDDEN_CLIENT_DIR_RE = /^(?:\$recycle\.bin|system volume information|recovery|config\.msi)$/i;

export type ClientAgentState = "online" | "unpaired" | "offline";

export type ClientAgentHealth = {
  ok: boolean;
  service?: string;
  version?: string;
  origin_allowed?: boolean;
  hostname?: string;
  addresses?: string[];
  port?: number;
  lan_bound?: boolean;
  share_count?: number;
  pairing_hint?: string;
  /** Agent 1.1+: can connect out to the server (works outside the office network). */
  relay_supported?: boolean;
};

export type ClientAgentStatus = {
  state: ClientAgentState;
  health: ClientAgentHealth | null;
};

export type ClientDriveVolume = {
  letter: string;
  root: string;
  label?: string;
  drive_type: "fixed" | "removable" | "network" | "cdrom" | "unknown";
  size_bytes?: number;
  free_bytes?: number;
  ready: boolean;
};

export type ClientDirEntry = {
  name: string;
  kind: "dir" | "file";
  size_bytes?: number | null;
  mtime_ms?: number;
  hidden?: boolean;
  link?: boolean;
};

export type ClientDirListing = {
  ok: boolean;
  path: string;
  parent: string | null;
  entries: ClientDirEntry[];
  count: number;
  truncated: boolean;
};

export type ClientShare = {
  ok: boolean;
  share_id: string;
  token: string;
  root: string;
  hostname: string;
  addresses: string[];
  port: number;
  lan_bound: boolean;
  file_count: number;
  dir_count: number;
  total_bytes: number;
  manifest_sha256: string;
  truncated: boolean;
  skipped: number;
  expires_utc: string;
  agent_version: string;
  files_preview: Array<{ path: string; size: number }>;
  /** The agent accepted the outbound target and keeps a connection to this server for the share. */
  relay_enabled?: boolean;
  relay_supported?: boolean;
};

export class ClientAgentError extends Error {
  code: string;
  constructor(message: string, code = "agent_error") {
    super(message);
    this.name = "ClientAgentError";
    this.code = code;
  }
}

let preferredBase: string | null = null;

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal, cache: "no-store", credentials: "omit" });
  } finally {
    window.clearTimeout(timer);
  }
}

/** Try the last working loopback address first, then the others. */
async function agentFetch(path: string, init: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const bases = preferredBase ? [preferredBase, ...AGENT_BASES.filter((b) => b !== preferredBase)] : AGENT_BASES;
  let lastError: unknown = null;
  for (const base of bases) {
    try {
      const resp = await fetchWithTimeout(`${base}${path}`, init, timeoutMs);
      preferredBase = base;
      return resp;
    } catch (err) {
      lastError = err;
    }
  }
  throw new ClientAgentError(
    lastError instanceof Error && lastError.name === "AbortError"
      ? "The Client Evidence Agent on this computer did not answer in time."
      : "The Client Evidence Agent is not running on this computer.",
    "agent_offline",
  );
}

async function agentJson<T>(path: string, init: RequestInit = {}, timeoutMs = 8000): Promise<T> {
  const resp = await agentFetch(path, init, timeoutMs);
  let body: Record<string, unknown> = {};
  try {
    body = (await resp.json()) as Record<string, unknown>;
  } catch {
    /* non-JSON error */
  }
  if (!resp.ok || body.ok === false) {
    const code = typeof body.code === "string" ? body.code : `http_${resp.status}`;
    const message = typeof body.error === "string" ? body.error : `The agent answered HTTP ${resp.status}.`;
    throw new ClientAgentError(message, code);
  }
  return body as T;
}

export async function clientAgentStatus(timeoutMs = 1500): Promise<ClientAgentStatus> {
  try {
    const health = await agentJson<ClientAgentHealth>("/health", {}, timeoutMs);
    if (!health.ok) return { state: "offline", health: null };
    return { state: health.origin_allowed === false ? "unpaired" : "online", health };
  } catch {
    return { state: "offline", health: null };
  }
}

export async function listClientDrives(): Promise<ClientDriveVolume[]> {
  const res = await agentJson<{ drives: ClientDriveVolume[] }>("/drives", {}, 12_000);
  return (res.drives || []).filter((d) => d.drive_type !== "cdrom");
}

export async function listClientDirectory(path: string): Promise<ClientDirListing> {
  return agentJson<ClientDirListing>(
    "/list-dir",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ path }) },
    20_000,
  );
}

/**
 * Publish one folder as a read-only share. Building the manifest walks the folder
 * (size + modified time only, no hashing), so large trees can take a while.
 */
export async function createClientShare(opts: {
  path: string;
  jobId: string;
  label?: string;
  relay?: ClientRelayTarget;
}): Promise<ClientShare> {
  return agentJson<ClientShare>(
    "/shares",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path: opts.path,
        job_id: opts.jobId,
        label: opts.label || "",
        relay_url: opts.relay?.url || "",
        relay_service: opts.relay?.service || "",
      }),
    },
    6 * 60_000,
  );
}

/** Where the agent connects out to: this console's own address and the job's product stack. */
export type ClientRelayTarget = { url: string; service: string };

export function clientRelayTarget(jobId: string): ClientRelayTarget {
  const path = resolveApiUrl("/api/client-agent/relay");
  const url = /^https?:\/\//i.test(path) ? path : `${consoleOrigin()}${path}`;
  return { url, service: inferApiService(`/api/jobs/${jobId}/evidence/client-source`) };
}

export async function revokeClientShare(shareId: string): Promise<void> {
  try {
    await agentJson(`/shares/${encodeURIComponent(shareId)}`, { method: "DELETE" }, 5000);
  } catch {
    /* already gone or agent offline */
  }
}

const DOWNLOAD_DIR = "/downloads/client-evidence-agent";

export function clientAgentDownloadUrls(): { script: string; installer: string } {
  return {
    script: `${DOWNLOAD_DIR}/polaron-client-evidence-agent.ps1`,
    installer: `${DOWNLOAD_DIR}/Install-PolaronClientEvidenceAgent.cmd`,
  };
}

export function consoleOrigin(): string {
  return typeof window === "undefined" ? "" : window.location.origin;
}

/** One line to paste into Windows PowerShell on the examiner computer. */
export function clientAgentInstallCommand(origin = consoleOrigin()): string {
  const url = `${origin}${DOWNLOAD_DIR}/polaron-client-evidence-agent.ps1`;
  return (
    `$o='${origin}'; $f="$env:TEMP\\polaron-client-evidence-agent.ps1"; ` +
    `Invoke-WebRequest -UseBasicParsing '${url}' -OutFile $f; ` +
    `powershell -NoProfile -ExecutionPolicy Bypass -File $f -Install -ConsoleOrigin $o`
  );
}

export function formatClientBytes(bytes: number | null | undefined): string {
  if (bytes == null || Number.isNaN(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  if (bytes < 1024 ** 4) return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
  return `${(bytes / 1024 ** 4).toFixed(2)} TB`;
}

export function joinClientPath(base: string, name: string): string {
  const sep = base.includes("\\") || /^[A-Za-z]:/.test(base) ? "\\" : "/";
  return base.endsWith(sep) ? `${base}${name}` : `${base}${sep}${name}`;
}

export function clientPathLeaf(path: string): string {
  const trimmed = path.replace(/[\\/]+$/, "");
  return trimmed.split(/[\\/]/).pop() || trimmed || path;
}
