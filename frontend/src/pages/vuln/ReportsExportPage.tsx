import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Download, FileOutput, FileText, Upload } from "lucide-react";
import clsx from "clsx";
import { Badge, Button, Card, Field, Input, PageHeader, Select, Spinner } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import type { Case } from "../../lib/types/forensic";
import type { GapMergeJobCandidate } from "../../lib/vulnApi";
import type { ScanJob } from "../../lib/types/vuln";

/** V1.10.3: "" in the job selector means every job of the case. */
const ALL_JOBS = "";

/**
 * The IP counts a V1.10.2+ server adds to each job. Declared here on purpose so
 * this page compiles whether or not the V1.10.2 `ScanJob.ip_summary` type is
 * installed; an older server simply omits the field and the label falls back
 * to the target count.
 */
type JobIpCounts = { total?: number; assessed?: number };

function jobIpCounts(job: ScanJob): JobIpCounts | null {
  const raw = (job as ScanJob & { ip_summary?: JobIpCounts | null }).ip_summary;
  return raw && typeof raw === "object" ? raw : null;
}

function jobOptionLabel(job: ScanJob): string {
  const when = job.started_at || job.created_at;
  const date = when
    ? new Date(when).toLocaleString(undefined, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })
    : "not started";
  const s = jobIpCounts(job);
  const ips = s?.total
    ? `${s.assessed ?? 0} of ${s.total} IPs assessed`
    : `${job.targets?.length ?? 0} target${(job.targets?.length ?? 0) === 1 ? "" : "s"}`;
  return `${date} — ${job.status} — ${ips} (${job.id.slice(0, 8)})`;
}

type GapFirewall = {
  make_model?: string;
  policies_logs?: string;
};

type GapInternet = {
  type?: string;
  vendors?: string;
  vpn_sdwans?: string;
  ids_ips?: string;
  dns_security?: string;
};

type GapOperatingSystems = {
  windows?: string;
  linux?: string;
  mac?: string;
};

export type GapIntake = {
  client_name?: string;
  branch_locations?: string;
  contact_person?: string;
  date_of_visit?: string;
  geographic_locations?: string;
  num_offices?: string;
  num_endpoints?: string;
  operating_systems?: GapOperatingSystems;
  data_centers?: string;
  critical_servers?: string;
  critical_devices?: string;
  web_apps?: string;
  mobile_apps?: string;
  firewall?: GapFirewall;
  internet?: GapInternet;
  nac?: string;
  antivirus?: string;
  backup_storage?: string;
  author?: string;
  document_version?: string;
  has_saved_intake?: boolean;
};

function hasStoredIntake(data: GapIntake): boolean {
  return Boolean(data.has_saved_intake);
}

/** "2026-10-15" -> "15 Oct 2026" for messages (the date inputs show the browser's own format). */
function displayYmd(ymd: string): string {
  const [y, m, d] = ymd.split("-").map(Number);
  if (!y || !m || !d) return ymd;
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  });
}

function kolkataYmd(offsetDays = 0): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date());
  const year = Number(parts.find((p) => p.type === "year")?.value);
  const month = Number(parts.find((p) => p.type === "month")?.value);
  const day = Number(parts.find((p) => p.type === "day")?.value);
  const dt = new Date(Date.UTC(year, month - 1, day + offsetDays));
  return dt.toISOString().slice(0, 10);
}

function mergeDayBadge(label: string): { text: string; tone: "green" | "neutral" | "indigo" } {
  if (label === "today") return { text: "Today", tone: "green" };
  if (label === "yesterday") return { text: "Yesterday", tone: "neutral" };
  return { text: label, tone: "indigo" };
}

function SectionHeading({ children }: { children: ReactNode }) {
  return (
    <h4 className="border-b border-ink-200 pb-2 text-sm font-bold uppercase tracking-wide text-ink-700">{children}</h4>
  );
}

function FieldGroupPanel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={clsx(
        "rounded-xl border border-ink-200 bg-gradient-to-b from-white to-ink-50/80 p-4 shadow-sm ring-1 ring-ink-100/80 sm:p-5",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function ReportsExportPage() {
  const toast = useToast();
  const [cases, setCases] = useState<Case[]>([]);
  // V1.10.6: the merge picks scan jobs (one case can hold several), not cases.
  const [mergeCandidates, setMergeCandidates] = useState<GapMergeJobCandidate[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [selectedJobId, setSelectedJobId] = useState<string>(ALL_JOBS);
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null);
  const [gapIntake, setGapIntake] = useState<GapIntake>({});
  const [intakeLoaded, setIntakeLoaded] = useState(false);
  const [intakeHasData, setIntakeHasData] = useState(false);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [gapExporting, setGapExporting] = useState<"pdf" | "docx" | "merged" | null>(null);
  const [savingIntake, setSavingIntake] = useState(false);
  const [pipeline, setPipeline] = useState<Array<{ engine: string; role: string }>>([]);
  const [mergeJobIds, setMergeJobIds] = useState<string[]>([]);
  // V1.10.4: both dates are optional and editable. No dates = the latest 20 reports.
  const [mergeFromDate, setMergeFromDate] = useState("");
  const [mergeToDate, setMergeToDate] = useState("");
  const [mergeMeta, setMergeMeta] = useState<{ totalMatching: number; hasMore: boolean; limit: number; filtered: boolean }>(
    { totalMatching: 0, hasMore: false, limit: 20, filtered: false },
  );
  const [mergeLoading, setMergeLoading] = useState(false);
  const mergeRequest = useRef(0);
  const todayYmd = kolkataYmd(0);
  const fileRef = useRef<HTMLInputElement>(null);

  const patchIntake = useCallback((patch: Partial<GapIntake>) => {
    setGapIntake((prev) => ({ ...prev, ...patch }));
  }, []);

  const patchNested = useCallback(
    <K extends "operating_systems" | "firewall" | "internet">(
      key: K,
      patch: GapIntake[K] extends object | undefined ? Partial<NonNullable<GapIntake[K]>> : never,
    ) => {
      setGapIntake((prev) => ({
        ...prev,
        [key]: { ...(prev[key] as object), ...patch },
      }));
    },
    [],
  );

  const loadMergeCandidates = useCallback(async () => {
    const seq = ++mergeRequest.current;
    setMergeLoading(true);
    try {
      const query: { from_date?: string; to_date?: string } = {};
      if (mergeFromDate) query.from_date = mergeFromDate;
      if (mergeToDate) query.to_date = mergeToDate;
      const mergeRes = await vulnApi.listGapMergeJobCandidates(query);
      if (seq !== mergeRequest.current) return; // a newer date choice is already loading
      const items = mergeRes.items || [];
      setMergeCandidates(items);
      setMergeMeta({
        totalMatching: mergeRes.total_matching ?? items.length,
        hasMore: Boolean(mergeRes.has_more),
        limit: mergeRes.limit ?? 20,
        filtered: Boolean(mergeRes.filtered ?? (mergeFromDate || mergeToDate)),
      });
      setMergeJobIds((prev) => prev.filter((id) => items.some((c) => c.job_id === id)));
    } catch {
      if (seq === mergeRequest.current) setMergeCandidates([]);
    } finally {
      if (seq === mergeRequest.current) setMergeLoading(false);
    }
  }, [mergeFromDate, mergeToDate]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [caseRes, pipe] = await Promise.all([
        vulnApi.listCases({ page: 1, page_size: 50 }),
        vulnApi.getOrchestratorPipeline(),
      ]);
      setCases(caseRes.items);
      setPipeline(pipe.pipeline);
      if (caseRes.items.length > 0) setSelectedCaseId(caseRes.items[0].id);
      else if (caseRes.items.length === 0) setSelectedCaseId("00000000-0000-4000-8000-000000000001");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load report data");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  // V1.10.3: the jobs of the selected case; the newest job is selected by default.
  useEffect(() => {
    let cancelled = false;
    setJobs([]);
    setSelectedJobId(ALL_JOBS);
    if (!selectedCaseId) {
      setJobsLoading(false);
      return;
    }
    setJobsLoading(true);
    vulnApi
      .listScanJobs(selectedCaseId)
      .then((items) => {
        if (cancelled) return;
        const list = Array.isArray(items) ? items : [];
        setJobs(list);
        setSelectedJobId(list[0]?.id ?? ALL_JOBS);
      })
      .catch(() => {
        if (!cancelled) setJobs([]);
      })
      .finally(() => {
        if (!cancelled) setJobsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedCaseId]);

  const selectedJob = jobs.find((j) => j.id === selectedJobId) ?? null;
  const scopeLabel = selectedJob ? `job ${selectedJob.id.slice(0, 8)}` : "whole case";

  // Only the newest request may set the summary: switching job/case quickly must
  // never leave the counts of the previously selected scope on screen.
  const summaryRequest = useRef(0);
  const loadSummary = useCallback(async () => {
    const seq = ++summaryRequest.current;
    if (!selectedCaseId || jobsLoading) {
      setSummary(null);
      return;
    }
    try {
      const data = await vulnApi.getVulnReportSummary(selectedCaseId, selectedJobId || null);
      if (seq === summaryRequest.current) setSummary(data);
    } catch {
      if (seq === summaryRequest.current) setSummary(null);
    }
  }, [selectedCaseId, selectedJobId, jobsLoading]);

  const loadGapIntake = useCallback(async () => {
    if (!selectedCaseId) return;
    setIntakeLoaded(false);
    try {
      const data = (await vulnApi.getGapIntake(selectedCaseId)) as GapIntake;
      setGapIntake(data);
      setIntakeHasData(hasStoredIntake(data));
      setIntakeLoaded(true);
    } catch {
      setGapIntake({});
      setIntakeHasData(false);
      setIntakeLoaded(true);
    }
  }, [selectedCaseId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    void loadMergeCandidates();
  }, [loadMergeCandidates]);

  useEffect(() => {
    loadSummary();
    loadGapIntake();
  }, [loadSummary, loadGapIntake]);

  async function exportCsv() {
    if (!selectedCaseId) return;
    setExporting(true);
    try {
      await vulnApi.exportVulnReportCsv(selectedCaseId, selectedJobId || null);
      toast.success(`Solution-set CSV downloaded (${scopeLabel})`);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  async function exportXlsx() {
    if (!selectedCaseId) return;
    setExporting(true);
    try {
      await vulnApi.exportVulnReportXlsx(selectedCaseId, selectedJobId || null);
      toast.success(`Solution Set Excel downloaded (${scopeLabel})`);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  async function exportCoverage() {
    if (!selectedCaseId) return;
    setExporting(true);
    try {
      await vulnApi.exportServiceCoverageCsv(selectedCaseId, selectedJobId || null);
      toast.success(`Service coverage CSV downloaded (${scopeLabel})`);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Coverage export failed");
    } finally {
      setExporting(false);
    }
  }

  async function importCsvFile(file: File) {
    if (!selectedCaseId) return;
    setImporting(true);
    try {
      const text = await file.text();
      const result = await vulnApi.importVulnReportCsv(selectedCaseId, text);
      toast.success(`Imported ${result.imported} findings`);
      loadSummary();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Import failed");
    } finally {
      setImporting(false);
    }
  }

  async function saveGapIntake() {
    if (!selectedCaseId) return;
    setSavingIntake(true);
    try {
      const { has_saved_intake: _ignored, ...payload } = gapIntake;
      const saved = (await vulnApi.saveGapIntake(selectedCaseId, payload)) as GapIntake;
      setGapIntake(saved);
      setIntakeHasData(hasStoredIntake(saved));
      try {
        await loadMergeCandidates();
      } catch {
        /* non-fatal */
      }
      toast.success(intakeHasData ? "Site overview updated" : "Site overview saved");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSavingIntake(false);
    }
  }

  async function exportGap(fmt: "pdf" | "docx") {
    if (!selectedCaseId) return;
    setGapExporting(fmt);
    try {
      const { has_saved_intake: _ignored, ...payload } = gapIntake;
      await vulnApi.saveGapIntake(selectedCaseId, payload);
      const scanJobId = selectedJobId || null;
      // V1.27.0: "All jobs in this case" with 2+ jobs downloads one ZIP holding each
      // job's report + Solution Set and the merged report + combined Solution Set.
      // (One download, because browsers block a second programmatic one.) A case with
      // 0 or 1 job keeps the single-file path below — there is nothing to merge.
      if (!scanJobId && jobs.length >= 2) {
        await vulnApi.exportGapReportBundle(selectedCaseId, fmt, jobs.length);
        toast.success(
          `Per-job and merged Gap Assessment Reports + Solution Sets downloaded as a ZIP (${jobs.length} scan jobs, ${fmt.toUpperCase()})`,
        );
        return;
      }
      if (fmt === "pdf") await vulnApi.exportGapReportPdf(selectedCaseId, { scanJobId });
      else await vulnApi.exportGapReportDocx(selectedCaseId, { scanJobId });
      await vulnApi.exportVulnReportXlsx(selectedCaseId, scanJobId);
      toast.success(`Gap Assessment Report (${fmt.toUpperCase()}) and Solution Set Excel downloaded (${scopeLabel})`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Gap report export failed";
      toast.error(msg.includes("timeout") ? "Report generation timed out — try again or disable LLM enrichment." : msg);
    } finally {
      setGapExporting(null);
    }
  }

  function toggleMergeJob(jobId: string) {
    setMergeJobIds((prev) =>
      prev.includes(jobId) ? prev.filter((id) => id !== jobId) : [...prev, jobId],
    );
  }

  async function exportMergedGap() {
    const ids = Array.from(new Set(mergeJobIds));
    if (ids.length < 2) {
      toast.error("Select at least two scan jobs to merge");
      return;
    }
    setGapExporting("merged");
    try {
      await vulnApi.exportMergedJobsGapReportPdf(ids);
      await vulnApi.exportMergedJobsGapReportXlsx(ids);
      toast.success(`Merged Gap Assessment Report and Solution Set Excel downloaded (${ids.length} scan jobs)`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Merged gap report export failed";
      toast.error(msg.includes("timeout") ? "Merge timed out — try again or disable LLM enrichment." : msg);
    } finally {
      setGapExporting(null);
    }
  }

  const os = gapIntake.operating_systems ?? {};
  const fw = gapIntake.firewall ?? {};
  const inet = gapIntake.internet ?? {};

  return (
    <div>
      <PageHeader
        title="Reports & export"
        subtitle="Export vulnerability findings as a Solution Set Excel (Risk, Host, Protocol, Port, Name) or Polaron Gap Assessment Report (PDF/DOCX) for one scan job or the whole case. Creating a gap report also downloads the Excel. Merging scan jobs downloads one PDF and one combined Solution Set Excel."
      />

      {loading ? (
        <Spinner />
      ) : (
        <>
          <Card className="mb-6 p-4">
            <div className="grid gap-4 md:grid-cols-2">
              <Field label="Case" hint="The site overview for the gap report is saved per case.">
                <Select value={selectedCaseId} onChange={(e) => setSelectedCaseId(e.target.value)}>
                  <option value="">Select case…</option>
                  {cases.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.title || c.number || c.id.slice(0, 8)}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field
                label="Scan job"
                hint={
                  jobsLoading
                    ? "Loading the scan jobs of this case…"
                    : jobs.length === 0
                      ? "This case has no scan jobs yet; exports cover the whole case."
                      : selectedJob
                        ? "Excel, CSV, coverage and the gap report use only this job's findings."
                        : "Exports combine the open findings of every job in this case."
                }
              >
                <Select
                  value={selectedJobId}
                  onChange={(e) => setSelectedJobId(e.target.value)}
                  disabled={!selectedCaseId || jobsLoading}
                >
                  {jobs.map((j) => (
                    <option key={j.id} value={j.id}>
                      {jobOptionLabel(j)}
                    </option>
                  ))}
                  <option value={ALL_JOBS}>All jobs in this case</option>
                </Select>
              </Field>
            </div>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="p-6">
              <div className="mb-4 flex items-center gap-2">
                <FileOutput className="h-5 w-5 text-brand-600" />
                <h3 className="font-bold text-ink-900">Solution-set Excel</h3>
              </div>
              <div className="space-y-4">
                <div className="rounded-lg border border-ink-200 bg-ink-50 p-3 text-xs text-ink-600">
                  <p className="mb-2 font-semibold text-ink-800">Scan orchestrator pipeline</p>
                  <div className="flex flex-wrap gap-1">
                    {pipeline.map((s) => (
                      <Badge key={s.engine} tone="indigo">
                        {s.engine}
                      </Badge>
                    ))}
                  </div>
                </div>
                <Button variant="brand" loading={exporting} onClick={exportXlsx} disabled={!selectedCaseId || jobsLoading}>
                  <Download className="h-4 w-4" /> Export solution-set Excel
                </Button>
                <Button variant="ghost" loading={exporting} onClick={exportCsv} disabled={!selectedCaseId || jobsLoading}>
                  <Download className="h-4 w-4" /> Export solution-set CSV
                </Button>
                <Button variant="ghost" loading={exporting} onClick={exportCoverage} disabled={!selectedCaseId || jobsLoading}>
                  <Download className="h-4 w-4" /> Service coverage CSV
                </Button>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".csv,text/csv"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) importCsvFile(f);
                    e.target.value = "";
                  }}
                />
                <Button
                  variant="ghost"
                  loading={importing}
                  disabled={!selectedCaseId}
                  onClick={() => fileRef.current?.click()}
                  title="Imported findings belong to the case, not to a scan job. They appear when All jobs in this case is selected."
                >
                  <Upload className="h-4 w-4" /> Import CSV into case
                </Button>
              </div>
            </Card>

            <Card className="p-6">
              <h3 className="font-bold text-ink-900">Finding summary</h3>
              {selectedCaseId ? (
                <p className="mt-1 text-xs text-ink-500">
                  {selectedJob ? `Scan job ${selectedJob.id.slice(0, 8)} (${selectedJob.status})` : "All jobs in this case"}
                </p>
              ) : null}
              {!summary ? (
                <p className="mt-4 text-sm text-ink-400">Select a case to view finding counts.</p>
              ) : (
                <dl className="mt-4 space-y-3 text-sm">
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">Polaron — Findings by severity</dt>
                    <dd className="mt-1 flex flex-wrap gap-1">
                      {Object.entries((summary.findings_by_severity as Record<string, number>) || {}).map(
                        ([sev, count]) => (
                          <Badge key={sev} tone="neutral">
                            {sev}: {count}
                          </Badge>
                        ),
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">Findings by engine</dt>
                    <dd className="mt-1 flex flex-wrap gap-1">
                      {Object.entries((summary.findings_by_engine as Record<string, number>) || {}).map(
                        ([eng, count]) => (
                          <Badge key={eng} tone="indigo">
                            {eng}: {count}
                          </Badge>
                        ),
                      )}
                    </dd>
                  </div>
                </dl>
              )}
            </Card>
          </div>

          <Card className="mt-6 p-6">
            <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="mb-2 flex items-center gap-2">
                  <FileText className="h-5 w-5 text-brand-600" />
                  <h3 className="font-bold text-ink-900">Gap Assessment Report</h3>
                </div>
                <p className="max-w-3xl text-sm text-ink-600">
                  Enter site overview and infrastructure details for the PDF. Data is saved per case and auto-loaded
                  when you switch cases. Findings, endpoint count and scan verification come from the scan job
                  selected at the top.
                </p>
                {selectedCaseId ? (
                  <p className="mt-2 text-sm font-medium text-ink-800">
                    Report scope: {selectedJob ? `scan job ${selectedJob.id.slice(0, 8)} (${selectedJob.status})` : "all jobs in this case"}
                  </p>
                ) : null}
                {selectedCaseId && !selectedJob && jobs.length >= 2 ? (
                  <p className="mt-1 text-xs text-ink-500">
                    Download PDF/DOCX returns one ZIP: each of the {jobs.length} scan jobs' own report and
                    Solution Set, plus the merged report and combined Solution Set for the whole case.
                  </p>
                ) : null}
              </div>
              {intakeHasData && intakeLoaded && <Badge tone="green">Saved for this case</Badge>}
            </div>

            {!intakeLoaded && selectedCaseId ? (
              <Spinner />
            ) : (
              <div className="space-y-8">
                <section>
                  <SectionHeading>Site overview</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      <Field label="Client name">
                        <Input
                          value={gapIntake.client_name ?? ""}
                          onChange={(e) => patchIntake({ client_name: e.target.value })}
                          placeholder="LILAVATI HOSPITAL"
                        />
                      </Field>
                      <Field label="Branch location(s)">
                        <Input
                          value={gapIntake.branch_locations ?? ""}
                          onChange={(e) => patchIntake({ branch_locations: e.target.value })}
                        />
                      </Field>
                      <Field label="Contact person">
                        <Input
                          value={gapIntake.contact_person ?? ""}
                          onChange={(e) => patchIntake({ contact_person: e.target.value })}
                        />
                      </Field>
                      <Field label="Date of visit">
                        <Input
                          value={gapIntake.date_of_visit ?? ""}
                          onChange={(e) => patchIntake({ date_of_visit: e.target.value })}
                          placeholder="DD-MM-YYYY"
                        />
                      </Field>
                      <Field label="Author">
                        <Input value={gapIntake.author ?? ""} onChange={(e) => patchIntake({ author: e.target.value })} />
                      </Field>
                      <Field label="Document version">
                        <Input
                          value={gapIntake.document_version ?? ""}
                          onChange={(e) => patchIntake({ document_version: e.target.value })}
                          placeholder="1.0"
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>General information</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      <Field label="Geographic locations">
                        <Input
                          value={gapIntake.geographic_locations ?? ""}
                          onChange={(e) => patchIntake({ geographic_locations: e.target.value })}
                        />
                      </Field>
                      <Field label="Number of offices">
                        <Input
                          value={gapIntake.num_offices ?? ""}
                          onChange={(e) => patchIntake({ num_offices: e.target.value })}
                        />
                      </Field>
                      <Field label="Number of endpoints">
                        <Input
                          value={gapIntake.num_endpoints ?? ""}
                          onChange={(e) => patchIntake({ num_endpoints: e.target.value })}
                          placeholder="600+"
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>Operating systems</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                      <Field label="Windows">
                        <Input
                          value={os.windows ?? ""}
                          onChange={(e) => patchNested("operating_systems", { windows: e.target.value })}
                        />
                      </Field>
                      <Field label="Linux/Ubuntu">
                        <Input
                          value={os.linux ?? ""}
                          onChange={(e) => patchNested("operating_systems", { linux: e.target.value })}
                        />
                      </Field>
                      <Field label="Mac">
                        <Input
                          value={os.mac ?? ""}
                          onChange={(e) => patchNested("operating_systems", { mac: e.target.value })}
                        />
                      </Field>
                      <Field label="Data centers">
                        <Input
                          value={gapIntake.data_centers ?? ""}
                          onChange={(e) => patchIntake({ data_centers: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>IT security &amp; network</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                      <Field label="Critical servers">
                        <Input
                          value={gapIntake.critical_servers ?? ""}
                          onChange={(e) => patchIntake({ critical_servers: e.target.value })}
                        />
                      </Field>
                      <Field label="Critical devices">
                        <Input
                          value={gapIntake.critical_devices ?? ""}
                          onChange={(e) => patchIntake({ critical_devices: e.target.value })}
                        />
                      </Field>
                      <Field label="Web applications">
                        <Input
                          value={gapIntake.web_apps ?? ""}
                          onChange={(e) => patchIntake({ web_apps: e.target.value })}
                        />
                      </Field>
                      <Field label="Mobile applications">
                        <Input
                          value={gapIntake.mobile_apps ?? ""}
                          onChange={(e) => patchIntake({ mobile_apps: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>Firewall</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <Field label="Make &amp; model">
                        <Input
                          value={fw.make_model ?? ""}
                          onChange={(e) => patchNested("firewall", { make_model: e.target.value })}
                        />
                      </Field>
                      <Field label="Policies &amp; logs">
                        <Input
                          value={fw.policies_logs ?? ""}
                          onChange={(e) => patchNested("firewall", { policies_logs: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>Internet connectivity</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      <Field label="Type">
                        <Input value={inet.type ?? ""} onChange={(e) => patchNested("internet", { type: e.target.value })} />
                      </Field>
                      <Field label="Vendors">
                        <Input
                          value={inet.vendors ?? ""}
                          onChange={(e) => patchNested("internet", { vendors: e.target.value })}
                        />
                      </Field>
                      <Field label="VPN &amp; SDWAN">
                        <Input
                          value={inet.vpn_sdwans ?? ""}
                          onChange={(e) => patchNested("internet", { vpn_sdwans: e.target.value })}
                        />
                      </Field>
                      <Field label="IDS/IPS">
                        <Input
                          value={inet.ids_ips ?? ""}
                          onChange={(e) => patchNested("internet", { ids_ips: e.target.value })}
                        />
                      </Field>
                      <Field label="DNS security">
                        <Input
                          value={inet.dns_security ?? ""}
                          onChange={(e) => patchNested("internet", { dns_security: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>Other infrastructure</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      <Field label="Network access control (NAC)">
                        <Input value={gapIntake.nac ?? ""} onChange={(e) => patchIntake({ nac: e.target.value })} />
                      </Field>
                      <Field label="Antivirus">
                        <Input
                          value={gapIntake.antivirus ?? ""}
                          onChange={(e) => patchIntake({ antivirus: e.target.value })}
                        />
                      </Field>
                      <Field label="Backup storage">
                        <Input
                          value={gapIntake.backup_storage ?? ""}
                          onChange={(e) => patchIntake({ backup_storage: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <div className="flex flex-wrap gap-2 border-t border-ink-100 pt-6">
                  <Button
                    variant={intakeHasData ? "brand" : "outline"}
                    loading={savingIntake}
                    onClick={() => void saveGapIntake()}
                    disabled={!selectedCaseId}
                  >
                    {intakeHasData ? "Update site overview" : "Save site overview"}
                  </Button>
                  <Button
                    variant="brand"
                    loading={gapExporting === "pdf"}
                    disabled={!selectedCaseId || jobsLoading}
                    onClick={() => void exportGap("pdf")}
                  >
                    <Download className="h-4 w-4" /> Download PDF
                  </Button>
                  <Button
                    variant="outline"
                    loading={gapExporting === "docx"}
                    disabled={!selectedCaseId || jobsLoading}
                    onClick={() => void exportGap("docx")}
                  >
                    <Download className="h-4 w-4" /> Download DOCX
                  </Button>
                </div>

                <section className="border-t border-ink-100 pt-6">
                  <SectionHeading>Merge gap reports</SectionHeading>
                  <p className="mt-2 max-w-3xl text-sm text-ink-600">
                    Finished scan jobs appear here, newest first, from every case with a saved site overview.
                    Pick two or more: several jobs of one case (re-scans, other network segments) or jobs from
                    different cases. Without dates the latest 20 jobs are listed; set From and/or To to search by
                    scan date. Identical findings are combined with IP addresses appended by comma; different
                    findings stay separate. The download is one merged PDF and one combined Solution Set Excel.
                  </p>
                  <div className="mt-4 grid max-w-3xl grid-cols-1 items-end gap-3 sm:grid-cols-[1fr_1fr_auto]">
                    <Field label="From" hint="Optional">
                      <Input
                        type="date"
                        value={mergeFromDate}
                        max={mergeToDate || todayYmd}
                        onChange={(e) => {
                          const next = e.target.value;
                          setMergeFromDate(next);
                          if (next && mergeToDate && next > mergeToDate) setMergeToDate(next);
                        }}
                      />
                    </Field>
                    <Field label="To" hint="Optional">
                      <Input
                        type="date"
                        value={mergeToDate}
                        min={mergeFromDate || undefined}
                        max={todayYmd}
                        onChange={(e) => {
                          const next = e.target.value;
                          setMergeToDate(next);
                          if (next && mergeFromDate && next < mergeFromDate) setMergeFromDate(next);
                        }}
                      />
                    </Field>
                    <div className="pb-6">
                      <Button
                        variant="ghost"
                        disabled={!mergeFromDate && !mergeToDate}
                        onClick={() => {
                          setMergeFromDate("");
                          setMergeToDate("");
                        }}
                      >
                        Show latest 20
                      </Button>
                    </div>
                  </div>
                  <p className="mt-3 text-sm text-ink-600">
                    {mergeLoading
                      ? "Loading…"
                      : mergeMeta.filtered
                        ? `${mergeCandidates.length} scan job${mergeCandidates.length === 1 ? "" : "s"} run ${
                            mergeFromDate && mergeToDate
                              ? `between ${displayYmd(mergeFromDate)} and ${displayYmd(mergeToDate)}`
                              : mergeFromDate
                                ? `on or after ${displayYmd(mergeFromDate)}`
                                : `on or before ${displayYmd(mergeToDate)}`
                          }${mergeMeta.hasMore ? ` (showing the newest ${mergeCandidates.length} of ${mergeMeta.totalMatching})` : ""}`
                        : `Latest ${mergeCandidates.length} scan job${mergeCandidates.length === 1 ? "" : "s"}${
                            mergeMeta.hasMore ? ` of ${mergeMeta.totalMatching}. Set From/To to find older ones.` : ""
                          }`}
                  </p>
                  <FieldGroupPanel className="mt-4">
                    <div className="max-h-96 space-y-2 overflow-y-auto">
                      {mergeCandidates.length === 0 ? (
                        <p className="text-sm text-ink-400">
                          {mergeMeta.filtered
                            ? "No finished scan job in this date range (its case also needs a saved site overview)."
                            : "No finished scan job yet whose case has a saved site overview."}
                        </p>
                      ) : (
                        mergeCandidates.map((c) => {
                          const checked = mergeJobIds.includes(c.job_id);
                          const caseLabel = c.case_title || c.case_number || c.case_id.slice(0, 8);
                          const dayBadge = mergeDayBadge(c.day_label);
                          const d = c.gap_details || {};
                          const detailParts = [
                            d.client_name ? `Client: ${d.client_name}` : null,
                            d.branch_locations ? `Branch: ${d.branch_locations}` : null,
                            d.contact_person ? `Contact: ${d.contact_person}` : null,
                            d.date_of_visit ? `Visit: ${d.date_of_visit}` : null,
                            d.author ? `Author: ${d.author}` : null,
                            d.document_version ? `Ver: ${d.document_version}` : null,
                          ].filter(Boolean);
                          const fmt = (v?: string | null) =>
                            v
                              ? new Date(v).toLocaleString("en-IN", {
                                  day: "2-digit",
                                  month: "short",
                                  year: "numeric",
                                  hour: "2-digit",
                                  minute: "2-digit",
                                })
                              : "";
                          const started = fmt(c.started_at || c.created_at);
                          const finished = fmt(c.completed_at);
                          const sev = c.severity_counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                          const sameCaseSelected = mergeCandidates.filter(
                            (o) => o.case_id === c.case_id && mergeJobIds.includes(o.job_id),
                          ).length;
                          return (
                            <label
                              key={c.job_id}
                              className="flex cursor-pointer items-start gap-2 rounded-lg border border-transparent px-2 py-2 text-sm hover:border-ink-100 hover:bg-ink-50"
                            >
                              <input
                                type="checkbox"
                                className="mt-1 h-4 w-4 rounded border-ink-300"
                                checked={checked}
                                onChange={() => toggleMergeJob(c.job_id)}
                              />
                              <span className="min-w-0 flex-1">
                                <span className="flex flex-wrap items-center gap-1.5">
                                  <span className="font-medium text-ink-800">{caseLabel}</span>
                                  <span className="font-mono text-xs text-ink-600">job {c.job_id.slice(0, 8)}</span>
                                  <Badge tone={dayBadge.tone}>{dayBadge.text}</Badge>
                                  <Badge tone={c.status === "completed" ? "green" : "amber"}>{c.status}</Badge>
                                  {checked && sameCaseSelected > 1 ? (
                                    <span className="text-[11px] text-ink-500">
                                      {sameCaseSelected} jobs of this case selected
                                    </span>
                                  ) : null}
                                </span>
                                <span className="mt-0.5 block text-[11px] text-ink-500">
                                  Scan {started}
                                  {finished ? ` → ${finished}` : ""} · {c.target_count} target
                                  {c.target_count === 1 ? "" : "s"}
                                </span>
                                <span className="mt-0.5 block text-[11px] tabular-nums">
                                  <span className="text-red-700">{sev.critical} critical</span>
                                  <span className="text-ink-300">, </span>
                                  <span className="text-orange-700">{sev.high} high</span>
                                  <span className="text-ink-300">, </span>
                                  <span className="text-amber-600">{sev.medium} medium</span>
                                  <span className="text-ink-300">, </span>
                                  <span className="text-amber-700">{sev.low} low</span>
                                  <span className="text-ink-300">, </span>
                                  <span className="text-ink-500">{sev.info} info</span>
                                </span>
                                {detailParts.length > 0 ? (
                                  <span className="mt-0.5 block text-[11px] text-ink-600">
                                    {detailParts.join(" · ")}
                                  </span>
                                ) : null}
                              </span>
                            </label>
                          );
                        })
                      )}
                    </div>
                    <div className="mt-4 flex flex-wrap items-center gap-2">
                      <Button
                        variant="brand"
                        loading={gapExporting === "merged"}
                        disabled={mergeJobIds.length < 2}
                        onClick={() => void exportMergedGap()}
                      >
                        <Download className="h-4 w-4" /> Merge &amp; download PDF + Excel
                      </Button>
                      <span className="text-xs text-ink-500">
                        {mergeJobIds.length} scan job{mergeJobIds.length === 1 ? "" : "s"} selected
                        {mergeJobIds.length > 0 && mergeJobIds.length < 2
                          ? " · pick one more"
                          : ""}
                      </span>
                    </div>
                  </FieldGroupPanel>
                </section>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
