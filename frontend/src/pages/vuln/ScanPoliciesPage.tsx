import { useCallback, useEffect, useMemo, useState } from "react";
import { KeyRound, Plus, Shield } from "lucide-react";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import { useAuth } from "../../lib/auth";
import type { ScanPolicy, ScanPolicyTemplate, Scanner, ServicePortPolicy } from "../../lib/types/vuln";

const CATEGORY_LABEL: Record<string, string> = {
  discovery: "Discovery",
  vulnerability: "Vulnerability scans",
  compliance: "Compliance",
  threat: "Threat checks (Aetheris, not Nessus templates)",
};

/** V1.8.0: which scanner's built-in template a policy mirrors. */
const VENDOR_LABEL: Record<string, string> = {
  polaron: "Polaron",
  nexpose: "Nexpose / InsightVM",
  nessus: "Nessus",
  aetheris: "Aetheris",
};
const VENDOR_ORDER = ["polaron", "nexpose", "nessus", "aetheris"];

function templateEquivalent(t: ScanPolicyTemplate | undefined): string {
  if (!t) return "";
  if (t.vendor === "polaron") return `Polaron default: Nessus ${t.nessus_template || "Basic Network Scan"} + report ports`;
  if (t.vendor === "nexpose" && t.nexpose_template) return `Nexpose: ${t.nexpose_template}`;
  if (t.nessus_template) return `Nessus: ${t.nessus_template}`;
  return "Aetheris threat check";
}

const SEVERITY_FLOOR: { value: string; label: string }[] = [
  { value: "0.1", label: "Low and above (0.1+)" },
  { value: "4", label: "Medium and above (4.0+)" },
  { value: "7", label: "High and above (7.0+)" },
  { value: "9", label: "Critical only (9.0+)" },
];

const PORT_PROFILE_LABEL: Record<string, string> = {
  nexus: "Service port policy (services that can have Low+ findings)",
  catalog: "Service port policy (services that can have Low+ findings)",
  nessus: "IANA TCP list + service ports (wider, slower)",
  full: "All 65,535 TCP ports",
  focused: "Only the listed ports",
};

const UDP_LABEL: Record<string, string> = {
  priority: "30 common UDP service ports",
  off: "No UDP",
  full: "All 65,535 UDP ports (slow)",
};

function portScope(settings: Record<string, unknown> | null | undefined): string {
  const profile = String(settings?.port_profile ?? "");
  const custom = Array.isArray(settings?.custom_tcp_ports) ? (settings?.custom_tcp_ports as unknown[]) : [];
  if (profile === "focused" && custom.length) return `TCP ${custom.join(", ")}`;
  const base = PORT_PROFILE_LABEL[profile] || (profile ? profile : "Scanner default");
  return custom.length ? `${base} + ${custom.length} extra` : base;
}

function parsePorts(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
}

export function ScanPoliciesPage() {
  const toast = useToast();
  const { hasPermission } = useAuth();
  const canManage = hasPermission("scan:policy_manage");

  const [policies, setPolicies] = useState<ScanPolicy[]>([]);
  const [scanners, setScanners] = useState<Scanner[]>([]);
  const [templates, setTemplates] = useState<ScanPolicyTemplate[]>([]);
  const [portPolicy, setPortPolicy] = useState<ServicePortPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [p, s, t, pp] = await Promise.all([
        vulnApi.listScanPolicies(),
        vulnApi.listScanners(),
        vulnApi.listScanPolicyTemplates().catch(() => [] as ScanPolicyTemplate[]),
        vulnApi.getServicePortPolicy().catch(() => null),
      ]);
      setPolicies(p);
      setScanners(s);
      setTemplates(t);
      setPortPolicy(pp);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load policies");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const templateByKey = useMemo(() => new Map(templates.map((t) => [t.key, t])), [templates]);

  return (
    <div>
      <PageHeader
        title="Scan policies"
        subtitle="Reusable scan settings. The Polaron policy (default) and the built-in Nexpose and Nessus equivalents are ready to launch; create your own from a template to change ports, UDP, and credentials."
        actions={
          canManage && (
            <Button variant="brand" onClick={() => setCreateOpen(true)} disabled={templates.length === 0 && !loading}>
              <Plus className="h-4 w-4" /> New policy
            </Button>
          )
        }
      />

      <Card className="overflow-hidden">
        {loading ? (
          <Spinner />
        ) : policies.length === 0 ? (
          <p className="px-5 py-16 text-center text-sm text-ink-400">
            No scan policies yet. Create one from a template to control ports, UDP, and credentials for your scans.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">Policy</th>
                  <th className="px-5 py-3 font-semibold">Template</th>
                  <th className="px-5 py-3 font-semibold">Ports</th>
                  <th className="px-5 py-3 font-semibold">Credentials</th>
                  <th className="px-5 py-3 font-semibold">Framework</th>
                  <th className="px-5 py-3 font-semibold">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {policies.map((p) => {
                  const settings = (p.settings_json || {}) as Record<string, unknown>;
                  const template = p.template_key ? templateByKey.get(p.template_key) : undefined;
                  const effective = { ...(template?.settings || {}), ...settings };
                  const refs = (settings.gmp_credential_refs || {}) as Record<string, string>;
                  const credKinds = Object.keys(refs);
                  return (
                    <tr key={p.id} className="hover:bg-ink-50/60">
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-3">
                          <Shield className="h-4 w-4 text-brand-600" />
                          <span className="font-semibold text-ink-800">{p.name}</span>
                          {p.is_builtin ? <Badge tone="neutral">Built-in</Badge> : null}
                          {p.is_default ? <Badge tone="green">Default</Badge> : null}
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        {template ? (
                          <div>
                            <span className="text-ink-800">{template.name}</span>
                            <span className="block text-xs text-ink-500">{templateEquivalent(template)}</span>
                          </div>
                        ) : (
                          <Badge tone="neutral">{p.policy_type}</Badge>
                        )}
                      </td>
                      <td className="px-5 py-3 text-ink-600">
                        {portScope(effective)}
                        <span className="block text-xs text-ink-500">
                          {UDP_LABEL[String(effective.udp_profile ?? "")] || "Scanner default UDP"}
                          {effective.performance ? ` · ${String(effective.performance) === "fast" ? "Fast" : "Standard"} speed` : ""}
                          {effective.check_scope ? ` · ${String(effective.check_scope) === "all" ? "All checks" : "Vulnerability checks only"}` : ""}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-ink-600">
                        {credKinds.length ? (
                          <span className="inline-flex items-center gap-1">
                            <KeyRound className="h-3.5 w-3.5" /> {credKinds.map((k) => k.toUpperCase()).join(", ")}
                          </span>
                        ) : p.credentials_missing || template?.requires_credentials.length ? (
                          <span className="text-red-700">Missing (required)</span>
                        ) : (
                          "None"
                        )}
                      </td>
                      <td className="px-5 py-3 text-ink-500">{p.compliance_framework || "—"}</td>
                      <td className="px-5 py-3 text-ink-500">{new Date(p.created_at).toLocaleDateString()}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {createOpen && (
        <PolicyModal
          scanners={scanners}
          templates={templates}
          portPolicy={portPolicy}
          onClose={() => setCreateOpen(false)}
          onSaved={() => {
            setCreateOpen(false);
            load();
          }}
        />
      )}
    </div>
  );
}

function PolicyModal({
  scanners,
  templates,
  portPolicy,
  onClose,
  onSaved,
}: {
  scanners: Scanner[];
  templates: ScanPolicyTemplate[];
  portPolicy: ServicePortPolicy | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const initial =
    templates.find((t) => t.is_default) ||
    templates.find((t) => t.key === "polaron") ||
    templates.find((t) => t.key === "basic_network") ||
    templates[0];
  const [templateKey, setTemplateKey] = useState(initial?.key || "");
  const template = templates.find((t) => t.key === templateKey);
  const [name, setName] = useState(initial?.name || "");
  const [nameTouched, setNameTouched] = useState(false);
  const [scannerId, setScannerId] = useState("");
  const [portProfile, setPortProfile] = useState("");
  const [udpProfile, setUdpProfile] = useState("");
  const [performance, setPerformance] = useState("");
  const [checkScope, setCheckScope] = useState("");
  const [minSeverity, setMinSeverity] = useState("");
  const [disabledServices, setDisabledServices] = useState<string[]>([]);
  const [nameContains, setNameContains] = useState("");
  const [extraPorts, setExtraPorts] = useState("");
  const [smbRef, setSmbRef] = useState("");
  const [sshRef, setSshRef] = useState("");
  const [framework, setFramework] = useState(initial?.compliance_framework || "");

  const grouped = useMemo(() => {
    // V1.8.0: grouped by scanner (Nexpose first), then category.
    const out = new Map<string, ScanPolicyTemplate[]>();
    const sorted = [...templates].sort(
      (a, b) =>
        VENDOR_ORDER.indexOf(a.vendor || "nessus") - VENDOR_ORDER.indexOf(b.vendor || "nessus") ||
        a.category.localeCompare(b.category),
    );
    for (const t of sorted) {
      const vendor = t.vendor || (t.category === "threat" ? "aetheris" : "nessus");
      const label =
        vendor === "aetheris"
          ? CATEGORY_LABEL[t.category] || t.category
          : `${VENDOR_LABEL[vendor] || vendor} — ${CATEGORY_LABEL[t.category] || t.category}`;
      out.set(label, [...(out.get(label) || []), t]);
    }
    return out;
  }, [templates]);

  function chooseTemplate(key: string) {
    const next = templates.find((t) => t.key === key);
    setTemplateKey(key);
    if (next && !nameTouched) setName(next.name);
    setFramework(next?.compliance_framework || "");
    setPortProfile("");
    setUdpProfile("");
  }

  const required = template?.requires_credentials || [];
  const isDynamic = Boolean(template?.settings.nvt_filter);
  const effectiveProfile = portProfile || String(template?.settings.port_profile || "");
  const usesPortPolicy = ["nexus", "catalog"].includes(effectiveProfile) && Boolean(portPolicy);
  const policyGroups = useMemo(() => {
    const out = new Map<string, NonNullable<typeof portPolicy>["services"]>();
    for (const svc of portPolicy?.services || []) out.set(svc.category, [...(out.get(svc.category) || []), svc]);
    return Array.from(out.entries());
  }, [portPolicy]);
  const enabledPorts = useMemo(() => {
    const off = new Set(disabledServices);
    const tcp = new Set<number>();
    const udp = new Set<number>();
    for (const svc of portPolicy?.services || []) {
      if (off.has(svc.key)) continue;
      svc.tcp.forEach((p) => tcp.add(p));
      svc.udp.forEach((p) => udp.add(p));
    }
    return { tcp: tcp.size, udp: udp.size };
  }, [portPolicy, disabledServices]);
  function toggleService(key: string) {
    setDisabledServices((cur) => (cur.includes(key) ? cur.filter((k) => k !== key) : [...cur, key]));
  }
  const purpose = template?.settings.scan_purpose || "vulnerability";
  const credentialsMissing = required.length > 0 && !smbRef.trim() && !sshRef.trim();
  const focused = template?.settings.port_profile === "focused";

  async function submit() {
    if (!template) return;
    const settings: Record<string, unknown> = {};
    if (portProfile) settings.port_profile = portProfile;
    if (udpProfile) settings.udp_profile = udpProfile;
    if (performance) settings.performance = performance;
    if (checkScope) settings.check_scope = checkScope;
    if (usesPortPolicy && disabledServices.length) settings.disabled_services = disabledServices;
    if (isDynamic && (minSeverity || nameContains.trim())) {
      const base = template.settings.nvt_filter || {};
      settings.nvt_filter = {
        ...base,
        ...(minSeverity ? { min_severity: Number(minSeverity) } : {}),
        ...(nameContains.trim() ? { name_contains: nameContains.trim() } : {}),
      };
    }
    const extra = parsePorts(extraPorts);
    if (extra.length) {
      const base = (template.settings.custom_tcp_ports || []).map(String);
      settings.custom_tcp_ports = Array.from(new Set([...base, ...extra]));
    }
    const refs: Record<string, string> = {};
    if (smbRef.trim()) refs.smb = smbRef.trim();
    if (sshRef.trim()) refs.ssh = sshRef.trim();
    if (Object.keys(refs).length) settings.gmp_credential_refs = refs;
    setLoading(true);
    try {
      await vulnApi.createScanPolicy({
        name: name.trim() || template.name,
        policy_type: template.category,
        scanner_id: scannerId || null,
        compliance_framework: framework || null,
        template_key: template.key,
        settings_json: settings,
      });
      toast.success("Policy created");
      onSaved();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Create failed");
    } finally {
      setLoading(false);
    }
  }

  const s = template?.settings || {};
  const effectivePorts = portScope({ ...s, ...(portProfile ? { port_profile: portProfile } : {}) });
  const effectiveUdp = UDP_LABEL[udpProfile || String(s.udp_profile ?? "")] || "Scanner default UDP";

  return (
    <Modal
      open
      onClose={onClose}
      title="New scan policy"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={submit} disabled={!template || credentialsMissing}>
            Create policy
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Template">
          <Select value={templateKey} onChange={(e) => chooseTemplate(e.target.value)}>
            {Array.from(grouped.entries()).map(([category, items]) => (
              <optgroup key={category} label={category}>
                {items.map((t) => (
                  <option key={t.key} value={t.key}>
                    {t.name}
                  </option>
                ))}
              </optgroup>
            ))}
          </Select>
        </Field>

        {template ? (
          <div className="rounded-xl border border-ink-200 bg-white px-4 py-3 text-sm">
            <p className="text-ink-700">{template.description}</p>
            <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-ink-600">
              <dt className="font-semibold text-ink-700">Equivalent of</dt>
              <dd>{templateEquivalent(template)}</dd>
              <dt className="font-semibold text-ink-700">TCP ports</dt>
              <dd>{effectivePorts}</dd>
              <dt className="font-semibold text-ink-700">UDP</dt>
              <dd>{effectiveUdp}</dd>
              <dt className="font-semibold text-ink-700">Greenbone config</dt>
              <dd>{String(s.scan_config || "Full and fast")}</dd>
              <dt className="font-semibold text-ink-700">Safe checks</dt>
              <dd>{s.safe_checks === "no" ? "Off (may disrupt services)" : "On"}</dd>
              <dt className="font-semibold text-ink-700">Checks run</dt>
              <dd>
                {s.optimize_test === "no"
                  ? "Every check, even for services not detected (slower)"
                  : "Only checks for services the scan detects (Nessus default)"}
              </dd>
              {s.nvt_families?.length ? (
                <>
                  <dt className="font-semibold text-ink-700">Check families</dt>
                  <dd>{s.nvt_families.join(", ")}</dd>
                </>
              ) : null}
              {s.nvt_filter ? (
                <>
                  <dt className="font-semibold text-ink-700">Check filter</dt>
                  <dd>
                    {s.nvt_filter.min_severity ? `Severity ${s.nvt_filter.min_severity}+` : "Any severity"}
                    {s.nvt_filter.name_contains ? `, name contains "${s.nvt_filter.name_contains}"` : ""}
                  </dd>
                </>
              ) : null}
              {s.cve_watchlist?.length ? (
                <>
                  <dt className="font-semibold text-ink-700">CVE watchlist</dt>
                  <dd className="break-words">{s.cve_watchlist.join(", ")}</dd>
                </>
              ) : null}
            </dl>
            <details className="mt-3">
              <summary className="cursor-pointer text-xs font-semibold text-brand-700">
                How this differs from{" "}
                {template.vendor === "nexpose"
                  ? "Nexpose"
                  : template.vendor === "aetheris"
                    ? "a vendor template"
                    : template.vendor === "polaron"
                      ? "Nessus Basic Network Scan"
                      : "Nessus"}
              </summary>
              {template.reference ? <p className="mt-1 text-xs text-ink-500">Reference: {template.reference}</p> : null}
              <p className="mt-1 text-xs text-ink-600">{template.deviations}</p>
            </details>
          </div>
        ) : (
          <p className="text-sm text-red-700">Templates could not be loaded. Check that the server is on Polaron 1.8.0 or later.</p>
        )}

        <Field label="Name">
          <Input
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setNameTouched(true);
            }}
          />
        </Field>

        <Field label="Scanner" hint="Optional. Jobs can still pick a scanner when they are launched.">
          <Select value={scannerId} onChange={(e) => setScannerId(e.target.value)}>
            <option value="">Choose at launch</option>
            {scanners.map((sc) => (
              <option key={sc.id} value={sc.id}>
                {sc.name}
              </option>
            ))}
          </Select>
        </Field>

        {!focused ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="TCP port scope">
              <Select value={portProfile} onChange={(e) => setPortProfile(e.target.value)}>
                <option value="">Template default</option>
                <option value="nexus">Service port policy</option>
                <option value="nessus">IANA TCP list (wider, slower)</option>
                <option value="full">All 65,535 TCP ports (slowest)</option>
              </Select>
            </Field>
            <Field label="UDP">
              <Select value={udpProfile} onChange={(e) => setUdpProfile(e.target.value)}>
                <option value="">Template default</option>
                <option value="priority">30 common UDP service ports</option>
                <option value="off">No UDP</option>
                <option value="full">All UDP ports (slow)</option>
              </Select>
            </Field>
          </div>
        ) : null}

        <Field
          label="Speed"
          hint={
            performance === "standard"
              ? "Pre-1.6.6 engine timing: 10 s socket timeout and 4 checks at once per host."
              : "Fast uses the Nessus/OpenVAS default 5 s socket timeout, 5 checks at once per host and Nmap Aggressive timing. Checks that already timed out twice are limited to 60 s. There is no time limit on an IP."
          }
        >
          <Select value={performance} onChange={(e) => setPerformance(e.target.value)}>
            <option value="">Scanner default</option>
            <option value="fast">Fast</option>
            <option value="standard">Standard</option>
          </Select>
        </Field>

        {isDynamic ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Minimum check severity" hint="Only checks at or above this CVSS score run.">
              <Select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
                <option value="">Template default ({s.nvt_filter?.min_severity ?? "any"})</option>
                {SEVERITY_FLOOR.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </Select>
            </Field>
            <Field label="Check name contains" hint="Optional, for example SMB, OpenSSH or Apache.">
              <Input value={nameContains} onChange={(e) => setNameContains(e.target.value)} placeholder="SMB" />
            </Field>
          </div>
        ) : null}

        {purpose === "vulnerability" && !isDynamic ? (
        <Field
          label="Checks"
          hint={
            checkScope === "all"
              ? "Every check in Full and fast, including informational inventory and reporting checks."
              : "Only checks that can report Critical, High, Medium or Low, plus the detection they need. Brute force, compliance and policy checks are skipped."
          }
        >
          <Select value={checkScope} onChange={(e) => setCheckScope(e.target.value)}>
            <option value="">Scanner default</option>
            <option value="vulnerability">Vulnerability checks only</option>
            <option value="all">All checks (includes informational)</option>
          </Select>
        </Field>
        ) : null}

        {usesPortPolicy && portPolicy ? (
          <details className="rounded-xl border border-ink-200 bg-white px-4 py-3 text-sm" open={false}>
            <summary className="cursor-pointer font-semibold text-ink-800">
              Services to check: {portPolicy.services.length - disabledServices.length} of {portPolicy.services.length} ·{" "}
              {enabledPorts.tcp} TCP and {enabledPorts.udp} UDP ports
            </summary>
            <p className="mt-2 text-xs text-ink-600">
              Only services that can produce Low, Medium, High or Critical findings are listed. Only the ports of
              ticked services are scanned. Policy {portPolicy.policy_version}.
            </p>
            <div className="mt-3 max-h-80 space-y-3 overflow-y-auto pr-1">
              {policyGroups.map(([category, items]) => (
                <div key={category}>
                  <p className="text-xs font-semibold text-ink-700">{category}</p>
                  {items.map((svc) => (
                    <label key={svc.key} className="mt-1 flex cursor-pointer items-start gap-2 text-xs text-ink-700">
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={!disabledServices.includes(svc.key)}
                        onChange={() => toggleService(svc.key)}
                      />
                      <span>
                        <span className="font-medium text-ink-800">{svc.name}</span>{" "}
                        <span className="text-ink-500">
                          {[...svc.tcp.map((p) => `${p}/tcp`), ...svc.udp.map((p) => `${p}/udp`)].join(", ")}
                        </span>
                        <span className="block text-ink-500">{svc.low_plus_examples}</span>
                      </span>
                    </label>
                  ))}
                </div>
              ))}
            </div>
            {portPolicy.not_checked.length ? (
              <p className="mt-3 text-xs text-ink-500">
                Not checked:{" "}
                {portPolicy.not_checked.map((x) => `${x.port} (${x.reason})`).join("; ")}
              </p>
            ) : null}
          </details>
        ) : null}

        <Field
          label={focused ? "Extra TCP ports" : "Additional TCP ports"}
          hint="Comma-separated ports or ranges, for example 8888, 9443, 10000-10010."
        >
          <Input value={extraPorts} onChange={(e) => setExtraPorts(e.target.value)} placeholder="8888, 9443" />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label={required.includes("smb") ? "SMB credential ID (Windows)" : "SMB credential ID (optional)"}
            hint="Greenbone credential UUID on the laptop scanner."
          >
            <Input value={smbRef} onChange={(e) => setSmbRef(e.target.value)} placeholder="UUID" />
          </Field>
          <Field
            label={required.includes("ssh") ? "SSH credential ID (Linux/macOS)" : "SSH credential ID (optional)"}
            error={credentialsMissing ? `${template?.name} needs an SMB or SSH credential ID.` : undefined}
          >
            <Input value={sshRef} onChange={(e) => setSshRef(e.target.value)} placeholder="UUID" />
          </Field>
        </div>

        <Field label="Compliance framework" hint="Optional label for reports, for example PCI DSS.">
          <Input value={framework} onChange={(e) => setFramework(e.target.value)} />
        </Field>
      </div>
    </Modal>
  );
}
