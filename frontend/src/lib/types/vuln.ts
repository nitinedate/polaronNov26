export interface Scanner {
  id: string;
  name: string;
  url: string;
  edition: string | null;
  status: string;
  connection_mode?: "gmp" | "edge_agent" | string;
  scanner_role?: "persistent_edge" | "portable" | "remote_vpn" | "central" | string;
  online?: boolean | null;
  openvas_ready?: boolean | null;
  agent_status_detail?: string | null;
  openvas_ready_at?: string | null;
  agent_token_hint?: string | null;
  /** V1.10.0: Windows computer name of the laptop this scanner record belongs to */
  agent_computer_name?: string | null;
  last_heartbeat_at?: string | null;
  plugin_feed_updated_at: string | null;
  created_at: string;
  /** Present only once on create / rotate — copy immediately. */
  agent_token?: string;
  agent_token_once?: boolean;
  agent_recovery_token?: string;
  agent_recovery_token_once?: boolean;
  previous_token_grace_hours?: number;
}

export interface ScannerCreate {
  name: string;
  url?: string;
  edition?: string | null;
  api_key_ref?: string | null;
  connection_mode?: "gmp" | "edge_agent";
  scanner_role?: "persistent_edge" | "portable" | "remote_vpn" | "central";
}

export interface ScannerUpdate {
  name?: string | null;
  url?: string | null;
  edition?: string | null;
  api_key_ref?: string | null;
  status?: "active" | "disabled";
  connection_mode?: "gmp" | "edge_agent";
  scanner_role?: "persistent_edge" | "portable" | "remote_vpn" | "central";
}

export interface ScanPolicy {
  id: string;
  case_id: string | null;
  name: string;
  policy_type: string;
  scanner_id: string | null;
  settings_json: Record<string, unknown> | null;
  template_key?: string | null;
  /** V1.8.0 */
  template_name?: string | null;
  vendor?: "polaron" | "nexpose" | "nessus" | "aetheris" | "custom" | string | null;
  category?: string | null;
  requires_credentials?: string[];
  credentials_missing?: boolean;
  is_builtin?: boolean;
  /** V1.10.2: built-in row of the default template (Polaron policy). */
  is_default?: boolean;
  lifecycle_state?: string;
  compliance_framework: string | null;
  created_by: string | null;
  created_at: string;
}

export interface ScanPolicyCreate {
  name: string;
  policy_type: string;
  case_id?: string | null;
  scanner_id?: string | null;
  settings_json?: Record<string, unknown> | null;
  compliance_framework?: string | null;
  template_key?: string | null;
}

/** Nexpose/Nessus-equivalent scan template (GET /api/scan-policy-templates). */
export interface ScanPolicyTemplate {
  key: string;
  name: string;
  /** V1.8.0: which scanner's built-in template this mirrors */
  vendor?: "polaron" | "nexpose" | "nessus" | "aetheris" | string;
  /** null for Aetheris threat checks that have no current Nessus template */
  nessus_template: string | null;
  /** Rapid7 InsightVM / Nexpose built-in template name, when vendor is nexpose */
  nexpose_template?: string | null;
  /** created automatically as a ready-to-use policy */
  seed_as_builtin?: boolean;
  /** V1.10.2: preselected at launch and in New policy (Polaron policy) */
  is_default?: boolean;
  reference?: string | null;
  category: "discovery" | "vulnerability" | "compliance" | "threat" | string;
  description: string;
  compliance_framework?: string | null;
  nessus_reference: string | null;
  deviations: string;
  settings: {
    port_profile?: string;
    udp_profile?: string;
    scan_config?: string;
    alive_test?: string;
    safe_checks?: string;
    optimize_test?: string;
    custom_tcp_ports?: number[];
    custom_udp_ports?: number[];
    require_credentials?: string[];
    nvt_families?: string[];
    cve_watchlist?: string[];
    scan_purpose?: "vulnerability" | "ping_discovery" | "credential_validation" | "compliance";
    nvt_filter?: { min_severity?: number; name_contains?: string; families?: string[] };
    [key: string]: unknown;
  };
  tcp_port_count_floor: number | null;
  udp_port_count: number | null;
  requires_credentials: string[];
}

/** V1.7.0 service port policy (GET /api/scan-service-port-policy). */
export interface ServicePortPolicyService {
  key: string;
  name: string;
  category: string;
  catalog_family: string | null;
  tcp: number[];
  udp: number[];
  low_plus_examples: string;
  enabled_by_default: boolean;
}

export interface ServicePortPolicy {
  policy_version: string;
  description: string;
  services: ServicePortPolicyService[];
  not_checked: { port: string; service: string; reason: string }[];
  tcp_port_count: number;
  udp_port_count: number;
}

export interface PolicyServiceStatus {
  key: string;
  name: string;
  category: string;
  state: "finding" | "open" | "closed" | "filtered" | "not-observed" | "unknown" | "not-in-policy" | string;
  ports: { port: string; state: string }[];
  severity_counts: Record<string, number>;
  finding_result_ids: string[];
}

export interface ServiceResultBucket {
  service_id: string;
  name: string;
  status: string;
  severity_counts: Record<string, number>;
  source_result_ids: string[];
  finding_result_ids: string[];
  results: { result_id: string; title: string; port: string; severity: string; cvss: number; nvt_oid: string }[];
  ports: string[];
}

export interface ScanPolicyUpdate {
  name?: string | null;
  policy_type?: string | null;
  scanner_id?: string | null;
  settings_json?: Record<string, unknown> | null;
  compliance_framework?: string | null;
}

export interface ScanTarget {
  target: string;
  target_type?: string;
  credential_ref?: string | null;
  excluded?: boolean;
}

export interface ScanJob {
  id: string;
  case_id: string;
  policy_id: string | null;
  status: string;
  progress_pct?: number;
  progress_label?: string;
  error?: string | null;
  scheduled_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  source: string;
  authorization_ref: string | null;
  scan_window_start: string | null;
  scan_window_end: string | null;
  external_scan_id: string | null;
  created_at: string;
  targets: ScanTarget[];
}

export interface ScanJobCreate {
  policy_id?: string | null;
  /** V1.8.0: launch straight from a built-in template */
  template_key?: string | null;
  scanner_id?: string | null;
  scheduled_at?: string | null;
  authorization_ref?: string | null;
  scan_window_start?: string | null;
  scan_window_end?: string | null;
  targets?: ScanTarget[];
  orchestration_enabled?: boolean | null;
  network_token_id?: string | null;
}

export interface NetworkToken {
  id: string;
  name: string;
  cidr: string;
  note?: string | null;
  authorization_ref?: string | null;
  token_hint?: string | null;
  status: "issued" | "connected" | "revoked" | string;
  connected_public_ip?: string | null;
  connected_at?: string | null;
  connected_by?: string | null;
  created_by?: string | null;
  expires_at?: string | null;
  created_at?: string | null;
  token?: string;
  token_once?: boolean;
}

export interface NetworkTokenCreate {
  name: string;
  cidr: string;
  note?: string;
  authorization_ref?: string;
}

export interface ScanJobUpdate {
  status?: "pending" | "queued" | "running" | "completed" | "failed" | "cancelled";
  external_scan_id?: string | null;
}

export interface ScanJobSeverityBucket {
  severity: string;
  count: number;
  pct: number;
  hosts: string[];
}

export interface ScanJobTargetProgress {
  ip: string;
  status: string;
  activity: string;
  progress_pct?: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  engines?: Record<string, string>;
  excluded?: boolean;
  warnings?: string[];
  /** V1.8.0: neutral observations (not warnings) */
  notes?: string[];
  /** V1.8.0: this IP is the scanner laptop, scanned through the Docker loopback */
  self_scan?: {
    scanned_via?: string;
    view?: string;
    network_exposure?: { open?: number[]; filtered_count?: number; closed_count?: number } | null;
  } | null;
  coverage?: {
    verdict?: string;
    network_scan_complete?: boolean;
    open_tcp_port_list?: number[];
    open_udp_port_list?: number[];
    nvts_launched?: number;
    results_evidenced?: number;
    warnings?: number;
    port_state_counts?: { open?: number; closed?: number; filtered?: number };
    /** V1.10.2: false when nothing on the host answered, so it was not assessed. */
    host_responded?: boolean;
    icmp_echo?: "reply" | "no_reply" | "unavailable" | string | null;
    silent_cause?: "host_firewall" | "client_isolation_suspected" | "no_answer" | string | null;
  };
}

export interface ScanJobSeveritySummary {
  job_id: string;
  status: string;
  progress_pct: number;
  progress_label?: string | null;
  error?: string | null;
  total: number;
  all_hosts: string[];
  severities: ScanJobSeverityBucket[];
  targets?: ScanJobTargetProgress[];
  service_coverage?: Record<string, {
    policy_version: string;
    coverage_complete: boolean;
    limitation: string;
    counts: Record<string, number>;
    services: { service_id: string; name: string; status: string; reason: string;
      endpoint_count: number; port_hint_count?: number; port_hints?: string[];
      source_result_ids: string[]; finding_result_ids?: string[];
      severity_counts?: Record<string, number>; attribution?: string[]; credentialed_checks: string }[];
    host_level?: ServiceResultBucket;
    other_ports?: ServiceResultBucket;
    policy_services?: PolicyServiceStatus[];
    policy_summary?: Record<string, number | string>;
    network_scan_complete?: boolean;
    ip_forwarding: { status: string; reason: string };
  }>;
  policy_snapshots?: Record<string, { port_range?: string; snapshot_status: string;
    configuration_sha256?: string; feed_versions?: Record<string, string>;
    credential_status?: Record<string, string>; template?: string; template_name?: string;
    /** V1.9.0: laptop-local credential provisioning (kind -> status text; no secret). */
    local_credential_status?: Record<string, string>; auto_provisioned_credentials?: string[];
    scan_config_name?: string; port_list_status?: string; family_scope_status?: string;
    tcp_port_count?: number; udp_port_count?: number;
    performance?: "fast" | "standard" | string;
    performance_status?: { config?: string; nmap_timing?: string; nvt_timeout_caps?: number;
      checks_read_timeout?: number; max_checks?: number; plugins_timeout?: number;
      scanner_preferences?: Record<string, string> };
    nvt_timeout_caps?: { count: number; applied: number; cap_sec: number | null; oids: string[] };
    check_scope?: "vulnerability" | "all" | string;
    check_scope_status?: { config?: string; scope?: string; nvt_count?: number | null; base_nvt_count?: number | null;
      filtered_families?: number; severity_checks_selected?: number; excluded_families?: string[];
      filter?: { min_severity?: number; name_contains?: string; families?: string[] } };
    scan_purpose?: string }>;
  cve_watchlist?: {
    cves: string[];
    hit_count: number;
    status: "hit" | "no_hit_in_scanned_scope" | string;
    note: string;
    hits: { result_id: string; host?: string; port?: number; title: string; cves: string[]; severity: string; cvss: number }[];
  } | null;
  accel?: { gpu_present: boolean; used_for_scan: boolean; detail: string };
  assessment?: {
    assessed: number;
    target_count: number;
    skipped: number;
    verified: boolean;
    label: string;
    clean_eligible: boolean;
    plugin_error_count?: number;
    network_scan_complete?: boolean;
    network_complete_hosts?: string[];
    degraded_hosts?: string[];
    /** V1.9.8: IPs the agent could not assess; the job still completed with warnings */
    not_assessed?: string[];
    clean_blockers?: string[];
    /** V1.8.0: real problems that make the job amber */
    warnings?: string[];
    /** V1.8.0: scope explanations (unauthenticated scan, self-scan, firewall) */
    notes?: string[];
  };
}

export interface Vulnerability {
  id: string;
  case_id: string;
  scan_job_id: string | null;
  asset_id: string | null;
  plugin_id: string | null;
  plugin_family: string | null;
  cve: string | null;
  cvss: number | null;
  score_available?: boolean;
  severity: string;
  port: number | null;
  protocol: string | null;
  service: string | null;
  synopsis: string | null;
  remediation: string | null;
  status: string;
  created_at: string;
}

export interface VulnerabilityList {
  items: Vulnerability[];
  total: number;
  page: number;
  page_size: number;
}

export interface Asset {
  id: string;
  case_id: string;
  hostname: string | null;
  primary_ip: string | null;
  mac: string | null;
  os: string | null;
  asset_type: string | null;
  risk_score: number | null;
  created_at: string;
  identifiers: AssetIdentifier[];
}

export interface AssetIdentifier {
  id: string;
  id_type: string;
  value: string;
  source: string | null;
}

export interface AssetList {
  items: Asset[];
  total: number;
  page: number;
  page_size: number;
}

export interface AssetRisk {
  asset_id: string;
  risk_score: number | null;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  top_cves: string[];
}

export interface RemediationTask {
  id: string;
  finding_id: string;
  owner_id: string | null;
  sla_due: string | null;
  status: string;
  resolution: string | null;
  rescan_job_id: string | null;
  accepted_risk_ref: string | null;
  escalation_level: number;
  created_at: string;
}

export interface RemediationTaskList {
  items: RemediationTask[];
  total: number;
  page: number;
  page_size: number;
}

export interface RemediationTaskCreate {
  finding_id: string;
  owner_id?: string | null;
  sla_due?: string | null;
  status?: "open" | "in_progress" | "resolved" | "accepted_risk";
}

export interface RemediationTaskUpdate {
  owner_id?: string | null;
  sla_due?: string | null;
  status?: "open" | "in_progress" | "resolved" | "accepted_risk";
  resolution?: string | null;
  rescan_job_id?: string | null;
  accepted_risk_ref?: string | null;
  escalation_level?: number;
}

export interface TimelineEvent {
  id: string;
  case_id: string;
  source_type: string;
  source_id: string | null;
  timestamp_utc: string;
  event_type: string;
  actor: string | null;
  asset_id: string | null;
  summary: string | null;
}

export interface Timeline {
  case_id: string;
  events: TimelineEvent[];
  total: number;
}

export interface CorrelationEdge {
  id: string;
  case_id: string;
  source_type: string;
  source_id: string;
  target_type: string;
  target_id: string;
  relation: string;
  confidence: number | null;
  explanation: string | null;
  created_at: string;
}

export interface ReportExportCreate {
  format?: "pdf" | "docx" | "html" | "json";
  template?: string | null;
  case_id?: string | null;
}
