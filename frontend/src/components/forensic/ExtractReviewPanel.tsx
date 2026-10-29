import { useMemo, useState } from "react";
import { FolderTree, ShieldCheck } from "lucide-react";

import { Button, Card } from "../ui";
import { forensicApi, type ExtractReviewState } from "../../lib/forensicApi";
import { formatClientBytes } from "../../lib/clientEvidenceAgent";
import { useToast } from "../../lib/toast";

type Row = { path: string; bytes: number; files?: number; depth: number; kind: "folder" | "file" };

const lower = (p: string) => p.replace(/\\/g, "/").replace(/^\/+|\/+$/g, "").toLowerCase();

/**
 * Shown when extraction paused after listing the file system. The examiner unticks
 * folders or very large files that are not evidence; nothing has been read yet.
 */
export function ExtractReviewPanel({
  jobId,
  review,
  sourceLabel,
  onSubmitted,
}: {
  jobId: string;
  review: ExtractReviewState;
  sourceLabel?: string;
  onSubmitted?: () => void;
}) {
  const toast = useToast();
  const summary = review.summary;
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const rows: Row[] = useMemo(() => {
    const folders: Row[] = (summary?.folders || []).map((f) => ({ ...f, kind: "folder" as const }));
    const files: Row[] = (summary?.big_files || []).map((f) => ({
      path: f.path, bytes: f.bytes, depth: f.path.split("/").length, kind: "file" as const,
    }));
    return [...folders, ...files].sort((a, b) => a.path.localeCompare(b.path));
  }, [summary]);

  const ancestorExcluded = (p: string) => {
    const key = lower(p);
    for (const e of excluded) if (key !== e && key.startsWith(`${e}/`)) return true;
    return false;
  };

  const excludedBytes = useMemo(
    () => rows.filter((r) => excluded.has(lower(r.path)) && !ancestorExcluded(r.path)).reduce((s, r) => s + r.bytes, 0),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [rows, excluded],
  );

  if (!summary) return null;
  const total = summary.total_bytes || 0;
  const auto = summary.auto_excluded || { files: 0 };

  function toggle(path: string) {
    const key = lower(path);
    setExcluded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  async function submit() {
    setBusy(true);
    try {
      const chosen = rows.filter((r) => excluded.has(lower(r.path)) && !ancestorExcluded(r.path)).map((r) => r.path);
      await forensicApi.submitExtractReview(jobId, chosen);
      toast.success(
        chosen.length
          ? `Extraction continues without ${chosen.length} item(s), about ${formatClientBytes(excludedBytes)}.`
          : "Extraction continues with everything listed.",
      );
      onSubmitted?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not continue the extraction");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mb-4 border-brand-300 bg-brand-50/40 p-4 text-sm" data-testid="extract-review">
      <p className="flex items-center gap-1.5 font-semibold text-ink-900">
        <FolderTree className="h-4 w-4 text-brand-600" />
        Review folders before extraction
      </p>
      <p className="mt-1 text-xs text-ink-700">
        The file system has been listed; no file content has been read yet.{" "}
        <span className="font-semibold">{summary.total_files.toLocaleString()} files ({formatClientBytes(total)})</span>{" "}
        would be read{sourceLabel ? ` from ${sourceLabel}` : ""}. Already left out automatically:{" "}
        {auto.files.toLocaleString()} files{auto.bytes ? ` (${formatClientBytes(auto.bytes)})` : ""}: Windows and
        program files, caches and game libraries.
      </p>
      <p className="mt-1 flex items-start gap-1.5 text-xs text-emerald-800">
        <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        Untick what is not evidence. Registry hives, event logs, browser history and other named artifacts inside an
        unticked folder are still extracted, and every choice is recorded in the job log.
      </p>
      <ul className="mt-3 max-h-80 divide-y divide-ink-100 overflow-y-auto rounded-md border border-ink-200 bg-white" aria-label="Folders and large files to read">
        {rows.map((r) => {
          const inherited = ancestorExcluded(r.path);
          const included = !inherited && !excluded.has(lower(r.path));
          const share = total ? Math.max(1, Math.round((r.bytes / total) * 100)) : 0;
          return (
            <li key={`${r.kind}:${r.path}`} className="flex items-center gap-2 px-2 py-1 text-xs">
              <input
                type="checkbox"
                className="h-3.5 w-3.5 accent-brand-600"
                checked={included}
                disabled={inherited || busy}
                onChange={() => toggle(r.path)}
                aria-label={`Read ${r.path}`}
              />
              <span className="min-w-0 flex-1 truncate font-mono" style={{ paddingLeft: `${(r.depth - 1) * 12}px` }} title={r.path}>
                {r.kind === "file" ? "📄 " : ""}
                {r.path.split("/").pop() || r.path}
                {inherited ? <span className="ml-1 font-sans text-ink-400">(in a left-out folder)</span> : null}
              </span>
              <span className={`shrink-0 tabular-nums ${included ? "text-ink-700" : "text-ink-400 line-through"}`}>
                {formatClientBytes(r.bytes)}
              </span>
              <span className="w-9 shrink-0 text-right tabular-nums text-ink-400">{share}%</span>
            </li>
          );
        })}
      </ul>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-ink-700" role="status">
          Leaving out <span className="font-semibold">{formatClientBytes(excludedBytes)}</span>;{" "}
          {formatClientBytes(Math.max(0, total - excludedBytes))} will be read.
        </p>
        <Button variant="brand" loading={busy} onClick={() => void submit()}>
          Continue extraction
        </Button>
      </div>
    </Card>
  );
}
