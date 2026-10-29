import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Download, FileText, Play } from "lucide-react";
import { Button, Card, PageHeader } from "../../components/ui";
import {
  ReportCaseExhibitProvider,
  ReportEvidencePages,
  ReportEvidenceTocContext,
  ReportDocumentFlow,
  reportPagePlan,
} from "../../components/forensic/ReportDocumentPreview";
import { forensicApi } from "../../lib/forensicApi";
import type { ReportSection } from "../../lib/types/forensic";
import { mobilePlatformService, mobileUiBasePath } from "../../lib/serviceMode";
import { useToast } from "../../lib/toast";

function displayStatus(raw: string | undefined | null): string {
  const s = (raw || "none").trim();
  if (s === "Report generated" || s === "completed") return "Report generated";
  if (["generating", "running", "queued", "waiting", "already_generating", "report_generating"].includes(s)) {
    return "generating";
  }
  if (s === "none" || s === "not_started" || s === "unknown") return "none";
  return s;
}

function withNarrative(section: ReportSection): ReportSection {
  const extra = section as ReportSection & { content_md?: string | null };
  if (section.narrative_content?.trim()) return section;
  if (extra.content_md?.trim()) return { ...section, narrative_content: extra.content_md };
  return section;
}

function MobileReportSheets({
  jobId,
  sections,
  onUpdated,
}: {
  jobId: string;
  sections: ReportSection[];
  onUpdated: (updated: ReportSection) => void;
}) {
  const { evidencePageStart } = reportPagePlan(sections);
  return (
    <ReportEvidenceTocContext.Provider value={{ page: evidencePageStart }}>
      <ReportCaseExhibitProvider jobId={jobId}>
      <div className="space-y-3">
        <div className="flex flex-col items-center rounded-xl bg-slate-100 p-4">
          <ReportDocumentFlow sections={sections} jobId={jobId} onUpdated={onUpdated} />
        </div>
        <Card className="p-5">
          <h3 className="font-bold text-ink-900">Evidences</h3>
          <p className="mt-1 text-sm text-ink-500">
            Documents and images in which an offer letter was found, with the file path and date.
          </p>
          <div className="mt-4 flex flex-col items-center rounded-xl bg-slate-100 p-4">
            <ReportEvidencePages jobId={jobId} pageStart={evidencePageStart} />
          </div>
        </Card>
      </div>
      </ReportCaseExhibitProvider>
    </ReportEvidenceTocContext.Provider>
  );
}

export function MobileReportPage() {
  const { jobId = "" } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const platform = mobilePlatformService() ?? "android";
  const label = platform === "ios" ? "iOS" : "Android";
  const base = mobileUiBasePath(platform);
  const [sections, setSections] = useState<ReportSection[]>([]);
  const [status, setStatus] = useState("none");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);

  const load = useCallback(async () => {
    if (!jobId) return;
    try {
      const [st, sec] = await Promise.all([
        forensicApi.getReportStatus(jobId),
        forensicApi.listReportSections(jobId).catch(() => []),
      ]);
      setStatus(displayStatus(st.status));
      setSections(sec);
      if (typeof st.sections_completed === "number" && typeof st.sections_total === "number") {
        setProgress({ done: st.sections_completed, total: st.sections_total });
      }
    } catch {
      /* report may not exist yet */
    }
  }, [jobId]);

  useEffect(() => {
    void load();
    const generating = status === "generating";
    const t = window.setInterval(() => void load(), generating ? 2500 : 5000);
    return () => window.clearInterval(t);
  }, [load, status]);

  async function start() {
    if (!jobId) return;
    setBusy(true);
    setStatus("generating");
    setSections([]);
    setProgress(null);
    try {
      // Every Generate rebuilds the mobile report from scratch.
      const res = await forensicApi.startReport(jobId, {
        report_type: "mobile_forensic",
        recreate: true,
      });
      setStatus(displayStatus(res.status || "generating"));
      toast.success(res.message || `${label} report generation started`);
      await load();
    } catch (e) {
      setStatus("none");
      toast.error(e instanceof Error ? e.message : "Report failed");
    } finally {
      setBusy(false);
    }
  }

  async function exportFmt(format: "pdf" | "docx") {
    setBusy(true);
    try {
      const ex = await forensicApi.exportReport(jobId, { format, template: "mobile_compact" });
      await forensicApi.downloadReportExport(ex.id);
      toast.success(`${format.toUpperCase()} exported`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    } finally {
      setBusy(false);
    }
  }

  const canExport = !busy && status === "Report generated" && sections.length > 0;

  return (
    <div>
      <PageHeader
        title={`${label} forensic report`}
        subtitle="Generated only from this mobile backend's evidence and RAG index."
        actions={
          <Button variant="ghost" onClick={() => navigate(`${base}/jobs/${jobId}`)}>
            <ArrowLeft className="h-4 w-4" /> Job
          </Button>
        }
      />
      <Card className="mb-4 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="mr-3 text-sm text-ink-600">
            Status: <b>{status}</b>
            {status === "generating" && progress ? (
              <span className="ml-2 text-ink-500">
                ({progress.done}/{progress.total} sections)
              </span>
            ) : null}
          </span>
          <Button variant="brand" loading={busy || status === "generating"} onClick={() => void start()}>
            <Play className="h-4 w-4" /> Generate
          </Button>
          <Button variant="outline" disabled={!canExport} onClick={() => void exportFmt("pdf")}>
            <Download className="h-4 w-4" /> PDF
          </Button>
          <Button variant="outline" disabled={!canExport} onClick={() => void exportFmt("docx")}>
            <Download className="h-4 w-4" /> DOCX
          </Button>
        </div>
      </Card>
      <div className="space-y-3">
        {sections.length === 0 ? (
          <Card className="p-8 text-center text-sm text-ink-400">
            <FileText className="mx-auto mb-2 h-7 w-7" />
            {status === "generating"
              ? "Generating mobile report sections…"
              : "No mobile report sections yet."}
          </Card>
        ) : (
          <MobileReportSheets
            jobId={jobId}
            sections={sections.map(withNarrative)}
            onUpdated={(updated) => {
              setSections((current) =>
                current.map((section) => (section.id === updated.id ? updated : section)),
              );
            }}
          />
        )}
      </div>
    </div>
  );
}
