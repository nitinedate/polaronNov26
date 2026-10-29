import { useEffect, useState } from "react";
import { Laptop } from "lucide-react";

import { Card } from "../ui";
import { forensicApi, type ClientEvidenceSourceStatus } from "../../lib/forensicApi";
import { formatClientBytes } from "../../lib/clientEvidenceAgent";

/**
 * Shown on a job whose evidence stays on the examiner's computer. While the
 * pipeline runs it re-checks every 30 s whether the server can still reach that
 * computer, so a sleeping laptop is visible before extraction stalls.
 */
export function ClientEvidenceSourceCard({
  jobId,
  fallback,
  active,
}: {
  jobId: string;
  fallback?: { hostname?: string; client_root?: string; file_count?: number; total_bytes?: number } | null;
  active: boolean;
}) {
  const [status, setStatus] = useState<ClientEvidenceSourceStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const next = await forensicApi.getClientEvidenceSource(jobId, true);
        if (!cancelled) setStatus(next);
      } catch {
        /* keep the last known state */
      }
    };
    void load();
    if (!active) return () => {
      cancelled = true;
    };
    const id = window.setInterval(() => void load(), 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [jobId, active]);

  const host = status?.hostname || fallback?.hostname || "client computer";
  const root = status?.client_root || fallback?.client_root || "";
  const files = status?.file_count ?? fallback?.file_count;
  const bytes = status?.total_bytes ?? fallback?.total_bytes;
  const reader = status?.reader;
  const transfer = status?.transfer;
  const offline = status?.agent_online === false;
  const failed = reader?.state === "failed";
  const waiting = reader?.state === "waiting";

  const tone = failed
    ? "border-red-200 bg-red-50 text-red-950"
    : offline || waiting
      ? "border-amber-200 bg-amber-50 text-amber-950"
      : "border-emerald-200 bg-emerald-50 text-emerald-950";

  return (
    <Card className={`mb-4 p-4 text-sm ${tone}`}>
      <p className="flex items-center gap-1.5 font-semibold">
        <Laptop className="h-4 w-4" />
        Evidence directory ready on {host}
      </p>
      <p className="mt-1 text-xs opacity-90">
        The image stays on that computer. The forensic server reads it in place over the network through the Client
        Evidence Agent and stores no copy of it. Keep that computer on, awake and connected until extraction finishes.
      </p>
      {root ? <p className="mt-2 break-all font-mono text-xs">{root}</p> : null}
      {files != null ? (
        <p className="mt-1 text-xs opacity-80">
          {files.toLocaleString()} file(s){bytes ? `, ${formatClientBytes(bytes)}` : ""}
          {status?.truncated ? " (folder listing was capped; choose a narrower folder if evidence is missing)" : ""}
        </p>
      ) : null}
      {transfer && transfer.logical_bytes > 0 ? (
        <p className="mt-2 text-xs" data-testid="client-transfer">
          Read from {host} so far: <span className="font-semibold">{formatClientBytes(transfer.logical_bytes)}</span>
          {bytes ? ` of the ${formatClientBytes(bytes)} evidence` : ""}
          {transfer.wire_bytes < transfer.logical_bytes
            ? `, ${formatClientBytes(transfer.wire_bytes)} sent over the network (empty space skipped and data compressed)`
            : ""}
          .
        </p>
      ) : null}
      {status ? (
        <p className="mt-2 text-xs font-medium" role="status">
          {failed
            ? reader?.detail || "Reading from the client computer stopped."
            : waiting
              ? reader?.detail || `Waiting for ${host} to come back on the network…`
              : offline
                ? `${host} is not answering. Extraction pauses until it is back; then use Resume if needed.`
                : status.agent_online
                  ? status.transport === "relay"
                    ? `Connected to ${host} through its outbound connection to this server. Speed depends on its upload.`
                    : `Connected to ${host}${status.agent_url ? ` (${status.agent_url})` : ""}.`
                  : null}
        </p>
      ) : null}
    </Card>
  );
}
