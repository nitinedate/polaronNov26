import type { ExtractionLog } from "./types/forensic";

export const LOG_FINISHED_STATUSES = new Set([
  "completed",
  "failed",
  "ready",
  "report_ready",
  "cancelled",
  "canceled",
  "stopped",
]);

export interface LogCount {
  label: string;
  value: string;
}

export interface ProcessLogRow {
  id: string;
  timestamp: string;
  stage: string;
  level: string;
  process: string;
  counts: LogCount[];
}

// Only suppress benign chatter. Never hide errors, deadlocks, failed SQL or
// dependency failures: the examiner needs those for an auditable disposition.
const HIDDEN_LOG = /extraction liveness|extraction step timings|unzip directories|progressagent inspected|progressAgent:\s*(Useful work|Delivery is within)|adaptive resource slot unavailable/i;
const IMPORTANT_LOG = /exception|failed|failure|error|deadlock|unavailable|denied|missing key|decrypt|unsupported|timed out|corrupt|canceling statement/i;
const PROCESS_LOG = /stage started|stage complete|serial stage|items|files|records|count|processed|extracted|parsing|OCR|media.review|graph|chunk|progress|writing|retry|complete|skipped|throughput|MiB\/s|ETA|validation|decrypt/i;

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return String(value);
  if (value < 1024) return `${Math.round(value)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = value;
  let idx = -1;
  do {
    scaled /= 1024;
    idx += 1;
  } while (scaled >= 1024 && idx < units.length - 1);
  const digits = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(digits)} ${units[idx]}`;
}

function liveCountKey(message: string): string | null {
  const text = message.trim();
  if (/^(Extracting|Packing) files\b/i.test(text)) return "extract";
  if (/^Native forensic parsing\b/i.test(text)) return "parse";
  if (/^Parse streaming shard\b/i.test(text)) return "parse-shard";
  if (/^DECRYPTING\b/i.test(text)) return "decrypt";
  return null;
}

function parseProcess(message: string): { process: string; counts: LogCount[] } {
  const parts = message.split(" · ").map((part) => part.trim()).filter(Boolean);
  if (parts.length <= 1) return { process: message.trim(), counts: [] };

  const counts: LogCount[] = [];
  let process = parts[0];
  const split = process.match(/^(.*?)\s+[—–-]\s+(.+)$/);
  if (split) {
    process = split[1].trim();
    counts.push({ label: "Files", value: split[2].trim() });
  }

  for (const part of parts.slice(1)) {
    if (/\bbytes(?:\s+packed)?$/i.test(part)) {
      const n = Number(part.replace(/,/g, "").replace(/\b(?:source\s+)?bytes(?:\s+packed)?\b/i, "").trim());
      counts.push({ label: "Packed locally", value: Number.isFinite(n) ? formatBytes(n) : part });
    } else if (/MiB\/s/i.test(part)) {
      counts.push({ label: "Rate", value: part });
    } else if (/^SLA\b/i.test(part)) {
      counts.push({ label: "SLA", value: part.replace(/^SLA\s*/i, "") });
    } else if (/^ETA\b/i.test(part)) {
      counts.push({ label: "ETA", value: part.replace(/^ETA\s*/i, "") });
    } else if (/pre-filtered/i.test(part)) {
      counts.push({ label: "Pre-filtered", value: part.replace(/\s*pre-filtered/i, "") });
    } else if (/unreadable/i.test(part)) {
      counts.push({ label: "Unreadable", value: part.replace(/\s*unreadable/i, "") });
    } else {
      counts.push({ label: "Detail", value: part });
    }
  }

  return { process, counts };
}

function toRow(log: ExtractionLog): ProcessLogRow {
  const parsed = parseProcess(log.message);
  return {
    id: log.id,
    timestamp: log.timestamp,
    stage: log.stage,
    level: log.level,
    process: parsed.process,
    counts: parsed.counts,
  };
}

/** Heartbeats and repeated progress ticks are omitted. The latest count line of each kind is kept. */
export function selectProcessLogs(logs: ExtractionLog[]): ProcessLogRow[] {
  const visible = logs.filter((log) => {
    if (log.metadata && log.metadata.heartbeat === true) return false;
    if (log.level === "debug") return false;
    const critical = ["error", "warn", "warning"].includes(String(log.level).toLowerCase()) || IMPORTANT_LOG.test(log.message);
    if (!critical && HIDDEN_LOG.test(log.message)) return false;
    return critical || PROCESS_LOG.test(log.message);
  });
  const latestByKey = new Map<string, ExtractionLog>();
  const steps: ExtractionLog[] = [];
  for (const log of visible) {
    const key = liveCountKey(log.message);
    if (key) latestByKey.set(key, log);
    else steps.push(log);
  }
  const chosen = [...steps, ...latestByKey.values()];
  chosen.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  return chosen.slice(-300).map(toRow);
}
