import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  ClientBrowseFolderDialog,
  ClientEvidenceBrowser,
  EvidenceLocationSwitch,
  type ClientSelectedFolder,
} from "./ClientEvidenceBrowser";
import { clientAgentInstallCommand } from "../../lib/clientEvidenceAgent";

/* --------------------------------------------------------------------- */
/* Fake Client Evidence Agent on http://127.0.0.1:9877                     */
/* --------------------------------------------------------------------- */

type AgentMode = "offline" | "unpaired" | "online" | "localhost-only" | "old-agent";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function installFakeAgent(mode: AgentMode) {
  const calls: Array<{ url: string; method: string; body?: unknown }> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method || "GET").toUpperCase();
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url, method, body });
    if (!url.startsWith("http://127.0.0.1:9877") && !url.startsWith("http://localhost:9877")) {
      return json({ ok: false }, 404);
    }
    if (mode === "offline") throw new TypeError("Failed to fetch");
    const path = url.replace(/^http:\/\/(127\.0\.0\.1|localhost):9877/, "");
    if (path === "/health") {
      if (mode === "unpaired") return json({ ok: true, service: "polaron-client-evidence-agent", origin_allowed: false });
      return json({
        ok: true, service: "polaron-client-evidence-agent", version: "1.0.0", origin_allowed: true,
        hostname: "WS-EXAM-07", addresses: ["10.20.30.41"], port: 9877, lan_bound: mode !== "localhost-only",
        relay_supported: mode !== "old-agent",
      });
    }
    if (path === "/drives") {
      return json({ ok: true, drives: [
        { letter: "C", root: "C:\\", drive_type: "fixed", ready: true, size_bytes: 512e9 },
        { letter: "E", root: "E:\\", drive_type: "removable", ready: true, label: "EVIDENCE", size_bytes: 2e12 },
      ] });
    }
    if (path === "/list-dir") {
      const target = String((body as { path: string }).path);
      if (target === "E:\\") {
        return json({ ok: true, path: "E:\\", parent: null, count: 2, truncated: false, entries: [
          { name: "Case-0423", kind: "dir" },
          { name: "System Volume Information", kind: "dir" },
        ] });
      }
      return json({ ok: true, path: "E:\\Case-0423", parent: "E:\\", count: 3, truncated: false, entries: [
        { name: "laptop.E01", kind: "file", size_bytes: 2147483648 },
        { name: "laptop.E02", kind: "file", size_bytes: 1073741824 },
        { name: "notes.txt", kind: "file", size_bytes: 1200 },
      ] });
    }
    if (path === "/shares" && method === "POST") {
      return json({
        ok: true, share_id: "ce0123456789abcdef01234567", token: "t".repeat(43), root: "E:\\Case-0423",
        hostname: "WS-EXAM-07", addresses: ["10.20.30.41"], port: 9877,
        file_count: 3, dir_count: 0, total_bytes: 3221226672, manifest_sha256: "a".repeat(64),
        truncated: false, skipped: 0, expires_utc: "2026-11-25T00:00:00Z", agent_version: "1.1.0", files_preview: [],
        lan_bound: mode !== "localhost-only", relay_supported: true, relay_enabled: Boolean((body as { relay_url?: string }).relay_url),
      });
    }
    return json({ ok: false, error: "unknown" }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("EvidenceLocationSwitch", () => {
  it("offers Forensic server and This computer as a radio group", async () => {
    const onChange = vi.fn();
    render(<EvidenceLocationSwitch value="server" onChange={onChange} />);
    const radios = screen.getAllByRole("radio");
    expect(radios).toHaveLength(2);
    expect(screen.getByRole("radio", { name: /Forensic server/ }).getAttribute("aria-checked")).toBe("true");
    expect(screen.getByRole("radio", { name: /This computer/ }).getAttribute("aria-checked")).toBe("false");
    await userEvent.click(screen.getByRole("radio", { name: /This computer/ }));
    expect(onChange).toHaveBeenCalledWith("client");
  });
});

describe("ClientEvidenceBrowser", () => {
  it("guides installation with the console address when the agent is not running", async () => {
    installFakeAgent("offline");
    render(<ClientEvidenceBrowser onUseFolder={vi.fn()} />);
    expect(await screen.findByText(/Install the Client Evidence Agent on this computer/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Install-PolaronClientEvidenceAgent.cmd" }).getAttribute("href")).toBe("/downloads/client-evidence-agent/Install-PolaronClientEvidenceAgent.cmd");
    expect(screen.getByText(clientAgentInstallCommand(window.location.origin))).toBeTruthy();
  });

  it("asks to pair when the agent rejects this console origin", async () => {
    installFakeAgent("unpaired");
    render(<ClientEvidenceBrowser onUseFolder={vi.fn()} />);
    expect(await screen.findByText(/Pair this console with the Client Evidence Agent/)).toBeTruthy();
  });

  it("browses this computer and returns the chosen folder with its evidence files", async () => {
    const calls = installFakeAgent("online");
    const onUseFolder = vi.fn();
    render(<ClientEvidenceBrowser onUseFolder={onUseFolder} />);
    await userEvent.click(await screen.findByRole("button", { name: /E:.*EVIDENCE.*USB/ }));
    expect(await screen.findByText("Case-0423")).toBeTruthy();
    expect(screen.queryByText("System Volume Information")).toBeNull();
    await userEvent.click(screen.getByText("Case-0423"));
    await userEvent.click(await screen.findByRole("button", { name: "Use this directory (2 evidence files)" }));
    expect(onUseFolder).toHaveBeenCalledWith({
      path: "E:\\Case-0423",
      name: "Case-0423",
      files: [
        { name: "laptop.E01", size: 2147483648 },
        { name: "laptop.E02", size: 1073741824 },
        { name: "notes.txt", size: 1200 },
      ],
      evidenceCount: 2,
    });
    // Browsing is local only: every request went to the loopback agent.
    expect(calls.every((c) => c.url.startsWith("http://127.0.0.1:9877"))).toBe(true);
  });

  it("asks to update an old agent that cannot connect out to the server", async () => {
    installFakeAgent("old-agent");
    render(<ClientEvidenceBrowser onUseFolder={vi.fn()} />);
    expect(await screen.findByText(/works on the office network only/)).toBeTruthy();
  });

  it("does not warn about LAN access when the agent can connect out", async () => {
    installFakeAgent("localhost-only");
    render(<ClientEvidenceBrowser onUseFolder={vi.fn()} />);
    expect(await screen.findByRole("button", { name: /E:.*EVIDENCE/ })).toBeTruthy();
    expect(screen.queryByText(/listening on this computer only/)).toBeNull();
    expect(screen.queryByText(/office network only/)).toBeNull();
  });
});

describe("ClientBrowseFolderDialog", () => {
  it("collects directories and starts extraction only after one is chosen", async () => {
    installFakeAgent("online");
    const onConfirm = vi.fn();
    render(<ClientBrowseFolderDialog open onClose={vi.fn()} onConfirm={onConfirm} />);
    const start = screen.getByRole("button", { name: "Start extraction (0 directories)" });
    expect((start as HTMLButtonElement).disabled).toBe(true);
    await userEvent.click(await screen.findByRole("button", { name: /E:.*EVIDENCE/ }));
    await userEvent.click(await screen.findByText("Case-0423"));
    await userEvent.click(await screen.findByRole("button", { name: /Use this directory/ }));
    await userEvent.click(screen.getByRole("button", { name: "Start extraction (1 directory)" }));
    const folders = onConfirm.mock.calls[0][0] as ClientSelectedFolder[];
    expect(folders.map((f) => f.path)).toEqual(["E:\\Case-0423"]);
  });
});

/* --------------------------------------------------------------------- */
/* HostEvidencePanel: the whole "This computer" flow                       */
/* --------------------------------------------------------------------- */

const api = vi.hoisted(() => ({
  registerClientEvidenceSource: vi.fn(),
  listHostFolder: vi.fn(),
  listHostFolderStatus: vi.fn(),
  ingestHostPath: vi.fn(),
  processJob: vi.fn(),
  browseHostEvidence: vi.fn(),
  setProcessingProfile: vi.fn(),
  resolveHostFolder: vi.fn(),
  getJob: vi.fn(),
  setExtractReviewRequired: vi.fn(),
  submitExtractReview: vi.fn(),
}));
const toast = vi.hoisted(() => ({ info: vi.fn(), success: vi.fn(), error: vi.fn() }));

vi.mock("../../lib/forensicApi", () => ({ forensicApi: api }));
vi.mock("../../lib/toast", () => ({ useToast: () => toast }));
vi.mock("./StopUsbCollectionButton", () => ({ UsbCollectionBusyBanner: () => null }));
vi.mock("../../lib/jobUploadSession", () => ({
  jobUploadSession: {
    markServerLocalZeroCopy: vi.fn(() => true),
    clearInactiveForServerSource: vi.fn(),
    reset: vi.fn(),
    get: vi.fn(() => ({ files: [], progress: null })),
  },
}));
vi.mock("../../lib/hostDriveHelper", () => ({
  ensureHostDriveHelper: vi.fn(async () => ({ ok: true })),
  ensureOfficePathMounted: vi.fn(async () => ({ ok: true })),
  friendlyMobileAcquireError: (m: string) => m,
  getCachedHelperOnline: () => true,
  helperOfflineRetryInMs: () => 60_000,
  hostDriveHelperHealth: vi.fn(async () => ({ ok: true })),
  hostDriveHelperInstallHint: () => "install",
  invalidateHelperHealthCache: vi.fn(),
  listHostDriveLetters: vi.fn(async () => ({ drives: ["D"], volumes: [] })),
  listHostMobileDevices: vi.fn(async () => ({ mobile_devices: [] })),
  mobileAttachHostLabel: () => "this PC",
  mobileKindLabel: () => "Android",
  runHostDriveAgentRefresh: vi.fn(async () => ({ ok: true })),
  startHostDriveAgentFromBrowser: vi.fn(async () => ({ ok: true })),
  resolveFolderOnHost: vi.fn(async () => null),
  startMobileAcquisition: vi.fn(),
  listHostAcquisitionJobs: vi.fn(async () => []),
  isUsbCollectionBusyError: () => false,
  listOfficeServerDirectory: vi.fn(),
  listOfficeServerDriveLetters: vi.fn(async () => ({ ok: true, drives: [], volumes: [] })),
}));

describe("HostEvidencePanel — evidence on this computer", () => {
  beforeEach(() => {
    sessionStorage.clear();
    for (const fn of Object.values(api)) fn.mockReset();
    api.browseHostEvidence.mockResolvedValue({
      configured: true, host_evidence_path: "", host_root: "", drive_root: "", current_path: "", display_path: "This PC",
      parent_path: null, entries: [], folder_segment_count: 0, folder_segments: [], drives: [], error: null, mount_hint: null,
    });
    api.registerClientEvidenceSource.mockResolvedValue({
      ok: true, share_id: "ce0123456789abcdef01234567", path: "client-evidence://ce0123456789abcdef01234567",
      display_path: "WS-EXAM-07: E:\\Case-0423", hostname: "WS-EXAM-07", client_root: "E:\\Case-0423",
      agent_url: "http://10.20.30.41:9877", file_count: 3, total_bytes: 3221226672, truncated: false, manifest_sha256: "a".repeat(64),
    });
    api.listHostFolder.mockResolvedValue({ status: "done", count: 3, segment_count: 2, entries: [], segments: [] });
    api.ingestHostPath.mockResolvedValue({ job_id: "job-1", status: "registered", message: "", processing_queued: true, accepted: [{}, {}], skipped: [] });
    api.setProcessingProfile.mockResolvedValue({});
  });

  it("publishes the folder, lets the server connect, then registers it like a server path", async () => {
    const calls = installFakeAgent("online");
    const { HostEvidencePanel } = await import("./HostEvidencePanel");
    const onProcessingStarted = vi.fn();
    render(<HostEvidencePanel jobId="job-1" embedded autoProcess onProcessingStarted={onProcessingStarted} />);

    // Server mode is the default and still shows the server browser.
    expect(await screen.findByText(/Server evidence browser — zero-copy/)).toBeTruthy();
    await userEvent.click(screen.getByRole("radio", { name: /This computer/ }));
    expect(await screen.findByText(/Client evidence browser — stays on this computer/)).toBeTruthy();
    expect(screen.queryByText(/Server evidence browser — zero-copy/)).toBeNull();
    expect(screen.getByRole("button", { name: /Browse this computer/ })).toBeTruthy();

    await userEvent.click(await screen.findByRole("button", { name: /E:.*EVIDENCE/ }));
    await userEvent.click(await screen.findByText("Case-0423"));
    await userEvent.click(await screen.findByRole("button", { name: /Use this folder \(2 evidence files\)/ }));

    await waitFor(() => expect(api.ingestHostPath).toHaveBeenCalled());
    const share = calls.find((c) => c.url.endsWith("/shares") && c.method === "POST");
    // The agent is told to connect out to this console, routed to the job's product stack.
    expect(share?.body).toEqual({
      path: "E:\\Case-0423", job_id: "job-1", label: "Case-0423",
      relay_url: `${window.location.origin}/api/client-agent/relay`, relay_service: "forensic",
    });
    expect(api.registerClientEvidenceSource).toHaveBeenCalledWith("job-1", expect.objectContaining({
      share_id: "ce0123456789abcdef01234567",
      token: "t".repeat(43),
      addresses: ["10.20.30.41"],
      client_root: "E:\\Case-0423",
      source_type: "disk",
      replace_existing: true,
      relay: true,
    }));
    // From here on it is exactly the server-drive flow, keyed by the virtual path.
    expect(api.listHostFolder).toHaveBeenCalledWith("job-1", { path: "client-evidence://ce0123456789abcdef01234567" });
    expect(api.ingestHostPath).toHaveBeenCalledWith("job-1", expect.objectContaining({
      path: "client-evidence://ce0123456789abcdef01234567",
      source_type: "disk",
      auto_process: true,
      processing_profile: "standard",
    }));
    await waitFor(() => expect(onProcessingStarted).toHaveBeenCalled());
    expect(toast.info).toHaveBeenCalledWith(expect.stringContaining("WS-EXAM-07: E:\\Case-0423"));
    // The location choice is remembered for this job.
    expect(sessionStorage.getItem("polaron.evidenceLocation.job-1")).toBe("client");
    // Evidence on this computer: review folders before extraction is on by default.
    expect(api.setExtractReviewRequired).toHaveBeenCalledWith("job-1", true);
    const order = (fn: { mock: { invocationCallOrder: number[] } }) => fn.mock.invocationCallOrder[0];
    expect(order(api.setExtractReviewRequired)).toBeLessThan(order(api.ingestHostPath));
  });

  it("uses the outbound connection when the agent has no LAN access", async () => {
    installFakeAgent("localhost-only");
    api.registerClientEvidenceSource.mockResolvedValue({
      ok: true, share_id: "ce0123456789abcdef01234567", path: "client-evidence://ce0123456789abcdef01234567",
      display_path: "WS-EXAM-07: E:\\Case-0423", hostname: "WS-EXAM-07", client_root: "E:\\Case-0423",
      agent_url: "relay:", transport: "relay", file_count: 3, total_bytes: 3221226672, truncated: false, manifest_sha256: "a".repeat(64),
    });
    const { HostEvidencePanel } = await import("./HostEvidencePanel");
    render(<HostEvidencePanel jobId="job-3" embedded autoProcess initialEvidenceLocation="client" />);
    await userEvent.click(await screen.findByRole("button", { name: /E:.*EVIDENCE/ }));
    await userEvent.click(await screen.findByText("Case-0423"));
    await userEvent.click(await screen.findByRole("button", { name: /Use this folder/ }));
    await waitFor(() => expect(api.ingestHostPath).toHaveBeenCalled());
    expect(api.registerClientEvidenceSource).toHaveBeenCalledWith("job-3", expect.objectContaining({ relay: true }));
    expect(toast.success).toHaveBeenCalledWith(expect.stringContaining("outbound connection"));
  });

  it("withdraws the share on the agent when the server cannot reach this computer", async () => {
    const calls = installFakeAgent("online");
    api.registerClientEvidenceSource.mockRejectedValue(new Error("The forensic server could not reach the Client Evidence Agent"));
    const { HostEvidencePanel } = await import("./HostEvidencePanel");
    const onRegisterError = vi.fn();
    render(<HostEvidencePanel jobId="job-2" embedded autoProcess initialEvidenceLocation="client" onRegisterError={onRegisterError} />);
    await userEvent.click(await screen.findByRole("button", { name: /E:.*EVIDENCE/ }));
    await userEvent.click(await screen.findByText("Case-0423"));
    await userEvent.click(await screen.findByRole("button", { name: /Use this folder/ }));
    await waitFor(() => expect(onRegisterError).toHaveBeenCalledWith(expect.stringContaining("could not reach")));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "DELETE" && c.url.endsWith("/shares/ce0123456789abcdef01234567"))).toBe(true),
    );
    expect(api.ingestHostPath).not.toHaveBeenCalled();
  });
});

describe("HostEvidencePanel — compact mobile view (Select the mobile image folder)", () => {
  beforeEach(() => {
    sessionStorage.clear();
    for (const fn of Object.values(api)) fn.mockReset();
  });

  it("offers the location choice, opens no popup on its own, and opens the matching dialog on click", async () => {
    installFakeAgent("online");
    const { HostEvidencePanel } = await import("./HostEvidencePanel");
    render(
      <HostEvidencePanel
        jobId="job-m"
        embedded
        autoProcess
        highlightStart
        lockedSourceType="mobile"
        initialSourceType="mobile"
        allowLiveMobileAcquisition
      />,
    );
    expect(await screen.findByText("One click to start")).toBeTruthy();
    expect(screen.getByRole("radio", { name: /Forensic server/ }).getAttribute("aria-checked")).toBe("true");
    // No dialog is visible until the examiner asks for one.
    expect(screen.queryByText("Select evidence directory on this computer")).toBeNull();
    expect(screen.queryByText("Choose the directory that contains the evidence.")).toBeNull();

    // Server choice keeps the existing server drive dialog.
    await userEvent.click(screen.getByRole("button", { name: "Select extraction directory…" }));
    expect(await screen.findByText("Choose the directory that contains the evidence.")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    // This computer: inline browser plus a client dialog.
    await userEvent.click(screen.getByRole("radio", { name: /This computer/ }));
    expect(await screen.findByText(/Client evidence browser — stays on this computer/)).toBeTruthy();
    expect(screen.getByText(/The files stay on this computer; the forensic server processes them in place/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Select extraction directory on this computer…" }));
    expect(await screen.findByText("Select evidence directory on this computer")).toBeTruthy();
    expect(screen.getByText(/Choose the extraction directory that holds the .pas \/ .ufd \/ .ufdx \/ .zip files/)).toBeTruthy();
  });
});


describe("ClientEvidenceSourceCard", () => {
  it("shows how much evidence was read from the PC and what crossed the network", async () => {
    const getClientEvidenceSource = vi.fn(async () => ({
      configured: true, hostname: "HOME-PC", client_root: "D:\\Case", file_count: 3, total_bytes: 100e9,
      agent_online: true, transport: "relay",
      transfer: { logical_bytes: 12.4e9, wire_bytes: 7.1e9, zero_bytes: 2e9, requests: 900 },
    }));
    (api as unknown as Record<string, unknown>).getClientEvidenceSource = getClientEvidenceSource;
    const { ClientEvidenceSourceCard } = await import("./ClientEvidenceSourceCard");
    render(<ClientEvidenceSourceCard jobId="job-9" active={false} />);
    const line = await screen.findByTestId("client-transfer");
    expect(line.textContent).toContain("Read from HOME-PC so far: 11.55 GB of the 93.13 GB evidence");
    expect(line.textContent).toContain("6.61 GB sent over the network");
    expect(screen.getByText(/through its outbound connection/)).toBeTruthy();
  });
});


describe("ExtractReviewPanel", () => {
  it("lets the examiner leave folders and large files out before anything is read", async () => {
    api.submitExtractReview.mockResolvedValue({ ok: true, excluded: [], excluded_estimate_bytes: 0 });
    const { ExtractReviewPanel } = await import("./ExtractReviewPanel");
    const onSubmitted = vi.fn();
    const GB = 1024 ** 3;
    render(
      <ExtractReviewPanel
        jobId="job-r"
        sourceLabel="HOME-PC"
        onSubmitted={onSubmitted}
        review={{
          required: true, status: "pending",
          summary: {
            total_files: 5000, total_bytes: 100 * GB,
            folders: [
              { path: "Program Files (x86)", bytes: 70 * GB, files: 900, depth: 1 },
              { path: "Program Files (x86)/VMs", bytes: 60 * GB, files: 3, depth: 2 },
              { path: "Users", bytes: 30 * GB, files: 4000, depth: 1 },
            ],
            big_files: [{ path: "Users/alice/Downloads/backup.iso", bytes: 8 * GB }],
            auto_excluded: { files: 150000, bytes: 40 * GB },
          },
        }}
      />,
    );
    expect(screen.getByText(/would be read from HOME-PC/)).toBeTruthy();
    await userEvent.click(screen.getByRole("checkbox", { name: "Read Program Files (x86)" }));
    // Children of a left-out folder follow it and cannot be re-ticked on their own.
    const child = screen.getByRole("checkbox", { name: "Read Program Files (x86)/VMs" }) as HTMLInputElement;
    expect(child.disabled).toBe(true);
    expect(child.checked).toBe(false);
    await userEvent.click(screen.getByRole("checkbox", { name: "Read Users/alice/Downloads/backup.iso" }));
    expect(screen.getByRole("status").textContent).toContain("Leaving out 78.00 GB; 22.00 GB will be read");
    await userEvent.click(screen.getByRole("button", { name: "Continue extraction" }));
    await waitFor(() => expect(onSubmitted).toHaveBeenCalled());
    expect(api.submitExtractReview).toHaveBeenCalledWith("job-r", ["Program Files (x86)", "Users/alice/Downloads/backup.iso"]);
  });
});
