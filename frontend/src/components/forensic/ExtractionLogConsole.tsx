import { useCallback, useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { Pause, Play, Terminal } from "lucide-react";
import { Button, Spinner } from "../ui";
import { ApiError, refreshAccessToken } from "../../lib/api";
import { forensicApi } from "../../lib/forensicApi";
import { formatLogLineTimestamp } from "../../lib/formatDateTime";
import type { ExtractionLog } from "../../lib/types/forensic";
import { sanitizePipelineLabel, stripAxiomBranding } from "../../lib/displayText";
import { selectProcessLogs, type ProcessLogRow } from "../../lib/extractionLogView";

const LEVEL_TONE: Record<string, string> = {
  error: "text-red-400",
  warn: "text-amber-400",
  warning: "text-amber-400",
  info: "text-emerald-400",
  debug: "text-ink-500",
};

const STAGE_TONE: Record<string, string> = {
  artifact_capture: "text-sky-300",
  artifact_inventory: "text-fuchsia-300",
  pipeline: "text-indigo-300",
  virtual_disk: "text-violet-300",
  extract: "text-emerald-300",
  rag_index: "text-amber-300",
  evidence_register: "text-cyan-300",
};

interface ExtractionLogConsoleProps {
  jobId: string;
  autoRefresh?: boolean;
  pollIntervalMs?: number;
  /** Parent-provided logs — disables internal polling when set */
  controlledLogs?: ExtractionLog[];
  controlledLoading?: boolean;
  registering?: boolean;
  onManualRefresh?: () => void;
  /** When the job has finished, polling stops and the panel shows the process summary. */
  finished?: boolean;
}

function LogRows({ rows }: { rows: ProcessLogRow[] }) {
  return (
    <>
      {rows.map((row) => {
        const stageTone = STAGE_TONE[row.stage] ?? "text-ink-500";
        const levelTone = LEVEL_TONE[row.level] ?? "text-ink-400";
        const alert =
          row.level === "error"
            ? "bg-red-950/50"
            : row.level === "warn" || row.level === "warning"
              ? "bg-amber-950/40"
              : "";
        return (
          <div key={row.id} className={clsx("border-b border-ink-800/80 py-2 last:border-b-0", alert)}>
            <div className="text-ink-500">{formatLogLineTimestamp(row.timestamp)}</div>
            <div className={clsx("uppercase", stageTone)}>
              {row.stage}
              <span className={clsx("ml-2 normal-case", levelTone)}>{row.level}</span>
            </div>
            <div className="mt-1 whitespace-pre-wrap break-words text-ink-100">
              {sanitizePipelineLabel(stripAxiomBranding(row.process))}
            </div>
            {row.counts.length > 0 ? (
              <dl className="mt-1 space-y-0.5">
                {row.counts.map((count) => (
                  <div key={`${row.id}-${count.label}`} className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3">
                    <dt className="text-ink-500">{count.label}</dt>
                    <dd className="text-ink-100">{count.value}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </div>
        );
      })}
    </>
  );
}

export function ExtractionLogConsole({
  jobId,
  autoRefresh = true,
  pollIntervalMs = 5000,
  controlledLogs,
  controlledLoading,
  registering = false,
  onManualRefresh,
  finished = false,
}: ExtractionLogConsoleProps) {
  const isControlled = controlledLogs !== undefined;
  const [logs, setLogs] = useState<ExtractionLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [paused, setPaused] = useState(false);
  const [pollStopped, setPollStopped] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const lastTsRef = useRef<string | undefined>();
  const pollBackoffMs = useRef(pollIntervalMs);
  const pollFailures = useRef(0);
  const pollStoppedRef = useRef(pollStopped);
  const pausedRef = useRef(paused);
  const finishedRef = useRef(finished);
  const onManualRefreshRef = useRef(onManualRefresh);
  pollStoppedRef.current = pollStopped;
  pausedRef.current = paused;
  finishedRef.current = finished;
  onManualRefreshRef.current = onManualRefresh;

  const displayLogs = isControlled ? controlledLogs : logs;
  const displayLoading = isControlled ? (controlledLoading ?? false) : loading;
  const rows = selectProcessLogs(displayLogs);
  const finalCounts = [...rows].reverse().find((row) => row.counts.length > 0) ?? null;

  const load = useCallback(async () => {
    if (isControlled) {
      onManualRefreshRef.current?.();
      return;
    }
    try {
      const res = await forensicApi.listLogs(jobId, {
        from: lastTsRef.current,
        limit: 200,
      });
      pollFailures.current = 0;
      pollBackoffMs.current = pollIntervalMs;
      setPollStopped(false);
      if (res.items.length > 0) {
        setLogs((prev) => {
          const ids = new Set(prev.map((l) => l.id));
          const merged = [...prev, ...res.items.filter((l) => !ids.has(l.id))];
          return merged.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
        });
        const newest = res.items.reduce(
          (max, item) => (item.timestamp > max ? item.timestamp : max),
          res.items[0].timestamp,
        );
        lastTsRef.current = newest;
      }
    } catch (e: unknown) {
      const isUnauthorized = e instanceof ApiError && e.status === 401;
      const isNotFound = e instanceof ApiError && e.status === 404;
      const isBadGateway = e instanceof ApiError && e.status === 502;
      const isRateLimited = e instanceof ApiError && e.status === 429;
      if (isNotFound) {
        setPollStopped(true);
        return;
      }
      if (isUnauthorized && (await refreshAccessToken())) {
        try {
          const res = await forensicApi.listLogs(jobId, {
            from: lastTsRef.current,
            limit: 200,
          });
          pollFailures.current = 0;
          setPollStopped(false);
          if (res.items.length > 0) {
            setLogs((prev) => {
              const ids = new Set(prev.map((l) => l.id));
              const merged = [...prev, ...res.items.filter((l) => !ids.has(l.id))];
              return merged.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
            });
            const newest = res.items.reduce(
              (max, item) => (item.timestamp > max ? item.timestamp : max),
              res.items[0].timestamp,
            );
            lastTsRef.current = newest;
          }
          return;
        } catch {
          /* fall through */
        }
      }
      if (isUnauthorized) {
        setPollStopped(true);
        return;
      }
      pollFailures.current += 1;
      if (isBadGateway || isRateLimited) {
        pollBackoffMs.current = Math.min(pollBackoffMs.current * 2, 60_000);
      }
      if (pollFailures.current >= 5) setPollStopped(true);
    } finally {
      setLoading(false);
    }
  }, [jobId, pollIntervalMs, isControlled]);

  useEffect(() => {
    if (isControlled) return;
    setLogs([]);
    lastTsRef.current = undefined;
    setPollStopped(false);
    setLoading(true);
    load();
  }, [jobId, load, isControlled]);

  useEffect(() => {
    if (isControlled || !autoRefresh || paused || pollStopped || finished) return;
    let timer: ReturnType<typeof setTimeout>;
    const schedule = () => {
      timer = setTimeout(async () => {
        await load();
        if (!pausedRef.current && !pollStoppedRef.current && !finishedRef.current) schedule();
      }, pollBackoffMs.current);
    };
    schedule();
    return () => clearTimeout(timer);
  }, [autoRefresh, paused, pollStopped, load, isControlled, finished]);

  useEffect(() => {
    if (!finished || isControlled) return;
    void load();
  }, [finished, isControlled, load]);

  useEffect(() => {
    if (paused || finished || !scrollRef.current) return;
    scrollRef.current.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [rows, paused, finished]);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden rounded-xl border border-ink-800 bg-ink-950">
      <div className="flex items-center justify-between border-b border-ink-800 px-4 py-2">
        <div className="flex items-center gap-2 text-ink-300">
          <Terminal className="h-4 w-4" />
          <span className="text-xs font-semibold uppercase tracking-wider">
            {finished ? "Process details" : "Extraction log"}
          </span>
          <span className="text-xs text-ink-500">{rows.length} steps</span>
        </div>
        {finished ? (
          <span className="text-[10px] uppercase tracking-wide text-ink-500">Log stopped</span>
        ) : (
          <div className="flex gap-1">
            <Button
              variant="ghost"
              className="!px-2 !py-1 text-ink-400 hover:text-ink-200"
              onClick={() => setPaused((p) => !p)}
            >
              {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            </Button>
            <Button
              variant="ghost"
              className="!px-2 !py-1 text-xs text-ink-400 hover:text-ink-200"
              onClick={load}
            >
              Refresh
            </Button>
          </div>
        )}
      </div>
      <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto px-3 py-2 font-mono text-xs leading-relaxed">
        {displayLoading && rows.length === 0 ? (
          <Spinner className="py-8" />
        ) : rows.length === 0 ? (
          <p className="text-ink-500">
            {registering
              ? "Registering segments… live log output will appear here."
              : "No log entries yet. Register evidence or start processing to see output."}
          </p>
        ) : (
          <>
            {finished && finalCounts ? (
              <div className="mb-3 border-b border-ink-700 pb-3">
                <div className="text-ink-100">{finalCounts.process}</div>
                <dl className="mt-1 space-y-0.5">
                  {finalCounts.counts.map((count) => (
                    <div key={`final-${count.label}`} className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3">
                      <dt className="text-ink-500">{count.label}</dt>
                      <dd className="text-emerald-200">{count.value}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            ) : null}
            <LogRows rows={rows} />
          </>
        )}
      </div>
    </div>
  );
}
