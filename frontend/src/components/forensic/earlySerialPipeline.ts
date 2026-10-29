import type { Job, PipelineProgress } from "../../lib/types/forensic";
import { extractStillRunning, waitingForEvidenceFolder } from "../../lib/orchestrationStages";

type Serial = NonNullable<PipelineProgress["serial_pipeline"]>;
type Stage = Serial["stages"][number];

/** Presentation-only adapter. The backend serial pipeline replaces this once available.
 * Never marks extraction complete from file counters alone: the immutable manifest
 * and extracted_disk_uri must exist first.
 */
export function earlySerialPipeline(job: Job): Serial {
  const pp = job.pipeline_progress;
  const agents = pp?.orchestration?.agents || {};
  const extracting = extractStillRunning(job);
  const nextDirectory = Boolean(pp?.extraction_activity?.next_directory);
  const extractionCommitted = Boolean(job.extracted_disk_uri) && !nextDirectory;
  const uploaded = Math.max(0, Number(pp?.extraction_activity?.files_uploaded ?? job.files_extracted ?? 0));
  const packed = Math.max(uploaded, Number(pp?.extraction_activity?.files_packed ?? pp?.extraction_activity?.files_extracted ?? job.files_extracted ?? uploaded));
  const total = Math.max(0, Number(job.files_total ?? pp?.extraction_activity?.files_total ?? 0));
  const found = Math.max(0, Number(pp?.extraction_activity?.files_found ?? 0));
  const enumeration = pp?.extraction_activity?.subphase === "enumerating";
  const stageSpecs = [
    ["intake", "Intake / preflight", "drive_mount_agent"],
    ["source", "Source preparation", "segments_agent"],
    ["extract", "Complete extraction", "extraction_agent"],
    ["materialize", "Register extracted artifacts", "materialize_agent"],
    ["parse", "Native forensic parsing", "parse_agent"],
    ["recovery", "Deleted / recovery analysis", "recovery_agent"],
    ["ocr", "GPU OCR", "ocr_agent"],
    ["media", "Image / video evidence observations", "media_review_agent"],
    ["inventory", "Normalize / correlate / artifact inventory", "artifacts_agent"],
    ["rag", "RAG chunking", "chunk_agent"],
    ["entity", "Entity / annotation / ontology enrichment", "entity_agent"],
    ["graph", "Graph synchronization", "neo4j_agent"],
    ["validate", "Process agent / completeness validation", "validation_agent"],
  ] as const;
  const stages: Stage[] = stageSpecs.map(([id, label, agentId], index) => {
    const agent = agents[agentId];
    const isExtraction = id === "extract";
    const baselineDone = index < 2 && (extractionCommitted || extracting);
    const status: Stage["status"] = isExtraction
      ? extractionCommitted ? "done" : extracting ? "running" : "pending"
      : agent?.state === "failed" ? "failed"
      : agent?.state === "done" ? "done"
      : agent?.state === "running" ? "running"
      : baselineDone ? "done" : "pending";
    const effectiveTotal = isExtraction ? total : 0;
    const effectiveDone = isExtraction ? Math.min(total, uploaded) : 0;
    const pct = status === "done" ? 100 : isExtraction
      ? total > 0 ? Math.min(99, Math.round(100 * effectiveDone / total)) : 0
      : Math.max(0, Math.min(99, Number(agent?.pct ?? 0)));
    const details: Record<string, unknown> = {};
    if (isExtraction) {
      details.extraction_label = pp?.extraction_activity?.label || "";
      details.files_found = found;
      details.files_uploaded = uploaded;
      details.files_packed = packed;
      details.files_remaining = total > 0 ? Math.max(total - uploaded, 0) : null;
      details.enumerating = enumeration;
      details.bytes_remaining = pp?.extraction_activity?.bytes_remaining ?? null;
      details.shards_done = pp?.extraction_activity?.shards_done ?? null;
      details.shards_total = pp?.extraction_activity?.shards_total ?? null;
    }
    return {
      id, agent_id: agentId, label, status,
      process_status: status === "done" ? "completed" : status === "running" ? "in process" : status === "failed" ? "failed" : "wait",
      pct, total: effectiveTotal, completed: effectiveDone, failed: 0, skipped: 0,
      attempt: 0, error: null, details,
      started_at: agent?.started_at ?? null, completed_at: agent?.finished_at ?? null,
    };
  });
  const active = stages.find(s => s.status === "running");
  const extract = stages[2];
  // Extraction is only one part of the job. Never display 100% until the authoritative
  // serial stage feed has finalized all work.
  const overallPct = Math.min(99, Math.max(0, Math.round((2 * 100 + extract.pct) / 13)));
  const hasSource = !waitingForEvidenceFolder(job);
  return {
    version: 1, serial: true, max_parallelism: 1, current_stage: active?.id || (hasSource ? "extract" : "intake"),
    complete: false, overall_pct: hasSource ? overallPct : 0, stages,
    source_coverage: {
      status: "unknown", processing_complete: false, coverage_complete: false,
      notice: "Evidence processing is still running. Completion is not evidence coverage.",
      scope_note: "The full source-coverage assessment is available after validation.", limitations: [],
    },
  };
}
