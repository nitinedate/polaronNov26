<#
.SYNOPSIS
    Polaron Client Evidence Agent - lets the Polaron forensic server process evidence
    that stays on this computer. Nothing is uploaded or copied.

.DESCRIPTION
    When an examiner chooses "This computer" in Polaron, the browser asks this agent
    to publish one selected folder as a read-only, token-protected share. The forensic
    server then reads the disk image / mobile extraction byte-by-byte over the LAN
    while it processes it. The original files are opened read-only and are never
    modified, moved or deleted.

    Two ways for the server to read the evidence (chosen automatically):
      * Direct: the server connects to this computer on TCP 9877 (office LAN; fastest).
      * Outbound: this computer connects out to the Polaron console over HTTPS and the
        server sends its read requests back through that connection. Works from home or
        another site behind a router; no open port is needed on this computer.

    Security model
      * Folder browsing and share creation answer only to this computer (loopback)
        and only to the Polaron console address(es) given with -ConsoleOrigin.
      * Evidence bytes are served only to callers holding the per-share token, never
        to a web browser, and optionally only to the addresses given with -AllowedServer.
      * Every share, revocation and first read of each file is written to
        %LOCALAPPDATA%\Polaron\ClientEvidenceAgent\access.log.
      * If a selected file changes on disk after selection, reads are refused
        (HTTP 409) so the server never mixes old and new evidence bytes.

.EXAMPLE
    # One-time install (asks for administrator rights once):
    powershell -NoProfile -ExecutionPolicy Bypass -File .\polaron-client-evidence-agent.ps1 -Install -ConsoleOrigin https://polaron.lab

.EXAMPLE
    # Restrict evidence reads to the forensic server's address:
    .\polaron-client-evidence-agent.ps1 -Install -ConsoleOrigin https://polaron.lab -AllowedServer 10.20.30.5

.EXAMPLE
    .\polaron-client-evidence-agent.ps1 -Status
    .\polaron-client-evidence-agent.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status,
    [string[]]$ConsoleOrigin = @(),
    [string[]]$AllowedServer = @(),
    # Certificate thumbprint(s) to accept when the Polaron console uses a self-signed
    # certificate that Windows does not trust (used by the outbound connection).
    [string[]]$TrustServerThumbprint = @(),
    [int]$Port = 0,
    [int]$ShareDays = 0,
    [string]$StateDir = ''
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$script:BoundArgs = $PSBoundParameters
$AgentVersion = '1.2.0'
$TaskName = 'Polaron Client Evidence Agent'
$RuleNameFormat = 'Polaron Client Evidence Agent (TCP {0})'
$DefaultPort = 9877
$ConfigDir = Join-Path $env:ProgramData 'Polaron\ClientEvidenceAgent'
$ConfigFile = Join-Path $ConfigDir 'agent.json'
$InstallDir = Join-Path $env:ProgramFiles 'Polaron\ClientEvidenceAgent'
$InstalledScript = Join-Path $InstallDir 'polaron-client-evidence-agent.ps1'
$WindowsPowerShell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'

# The embedded HTTP server uses System.Web.Extensions, which exists only in
# Windows PowerShell 5.1 (.NET Framework). Re-launch there from PowerShell 7.
if ($PSVersionTable.PSEdition -eq 'Core') {
    $forward = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) { if ($value.IsPresent) { $forward += "-$key" } }
        elseif ($value -is [array]) { $forward += "-$key"; $forward += ($value -join ',') }
        else { $forward += "-$key"; $forward += [string]$value }
    }
    & $WindowsPowerShell @forward
    exit $LASTEXITCODE
}

$AgentSource = @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace Polaron.ClientEvidence
{
    public class ManifestFile
    {
        public string path;
        public long size;
        public long mtime_ms;
    }

    public class ShareState
    {
        public string share_id;
        public string token_sha256;
        public string root;
        public string label;
        public string job_id;
        public string created_utc;
        public string expires_utc;
        public string manifest_sha256;
        public bool truncated;
        public long total_bytes;
        public int skipped;
        public List<ManifestFile> files;
        public List<string> dirs;
        // Outbound ("relay") connection to the Polaron server that created the share.
        public string relay_url;
        public string relay_service;
        public string token_protected;
    }

    public sealed class RelayWorker
    {
        public string ShareId;
        public string Token;
        public DateTime Created;
        public volatile bool Stop;
        public volatile string LastError = "";
        public long LastOkTicks;
    }

    public sealed class Agent
    {
        public const string Version = "1.2.0";
        public const string Service = "polaron-client-evidence-agent";

        public int Port = 9877;
        public string StateDir = "";
        public int ShareDays = 30;
        public int MaxFiles = 250000;
        public int MaxManifestSeconds = 300;
        public int MaxListEntries = 5000;
        public int RelayConnections = 6;
        public const long MaxRelayChunk = 64L * 1024 * 1024;
        public bool LanBound;
        public string ListenPrefix = "";

        private readonly HashSet<string> allowedOrigins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> allowedServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ShareState> shares = new Dictionary<string, ShareState>(StringComparer.Ordinal);
        private readonly HashSet<string> loggedOpens = new HashSet<string>(StringComparer.Ordinal);
        private readonly Dictionary<string, DateTime> lastTouch = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        private readonly Dictionary<string, RelayWorker> relays = new Dictionary<string, RelayWorker>(StringComparer.Ordinal);
        private readonly HashSet<string> trustedThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly byte[] TokenEntropy = Encoding.UTF8.GetBytes("polaron-client-evidence-v1");
        private readonly object gate = new object();
        private readonly object logGate = new object();
        private readonly SemaphoreSlim streams = new SemaphoreSlim(24, 24);
        private HttpListener listener;
        private Thread loop;
        private volatile bool running;

        private static readonly long EpochTicks = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;
        private static readonly string[] SkipDirs = new string[] { "$recycle.bin", "system volume information", "config.msi", "recovery" };

        public bool IsRunning { get { return running; } }

        public void AddAllowedOrigin(string origin)
        {
            if (String.IsNullOrEmpty(origin)) return;
            string o = origin.Trim().TrimEnd('/');
            if (o.Length > 0) allowedOrigins.Add(o);
        }

        public void AddAllowedServer(string address)
        {
            if (String.IsNullOrEmpty(address)) return;
            IPAddress ip;
            if (IPAddress.TryParse(address.Trim(), out ip)) allowedServers.Add(ip.ToString());
        }

        /// <summary>Accept this server certificate even if Windows does not trust it (self-signed console).</summary>
        public void AddTrustedThumbprint(string thumbprint)
        {
            if (String.IsNullOrEmpty(thumbprint)) return;
            string t = thumbprint.Replace(" ", "").Replace(":", "").Trim();
            if (t.Length > 0) trustedThumbprints.Add(t.ToUpperInvariant());
        }

        public string[] AllowedOrigins()
        {
            string[] arr = new string[allowedOrigins.Count];
            allowedOrigins.CopyTo(arr);
            return arr;
        }

        // ------------------------------------------------------------------
        // Lifecycle
        // ------------------------------------------------------------------

        public void Start()
        {
            if (String.IsNullOrEmpty(StateDir))
                StateDir = Path.Combine(Path.GetTempPath(), "PolaronClientEvidenceAgent");
            Directory.CreateDirectory(SharesDir());
            LoadShares();

            string lanPrefix = "http://+:" + Port.ToString(CultureInfo.InvariantCulture) + "/";
            listener = new HttpListener();
            listener.Prefixes.Add(lanPrefix);
            try
            {
                listener.Start();
                LanBound = true;
                ListenPrefix = lanPrefix;
            }
            catch (HttpListenerException)
            {
                // No URL reservation (installer not run as admin): loopback only.
                try { listener.Close(); } catch { }
                listener = new HttpListener();
                string localPrefix = "http://localhost:" + Port.ToString(CultureInfo.InvariantCulture) + "/";
                listener.Prefixes.Add(localPrefix);
                listener.Start();
                LanBound = false;
                ListenPrefix = localPrefix;
            }
            running = true;
            ConfigureOutboundHttp();
            List<ShareState> existing = new List<ShareState>();
            lock (gate) { existing.AddRange(shares.Values); }
            foreach (ShareState s in existing) StartRelay(s, UnprotectToken(s));
            loop = new Thread(AcceptLoop);
            loop.IsBackground = true;
            loop.Name = "polaron-agent-accept";
            loop.Start();
            Audit("-", "agent_start", "-", ListenPrefix + " lan=" + LanBound);
        }

        public void Stop()
        {
            running = false;
            try { listener.Stop(); } catch { }
            try { listener.Close(); } catch { }
            Audit("-", "agent_stop", "-", "");
        }

        private void AcceptLoop()
        {
            while (running)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = listener.GetContext();
                }
                catch (Exception)
                {
                    if (!running) break;
                    Thread.Sleep(50);
                    continue;
                }
                ThreadPool.QueueUserWorkItem(Handle, ctx);
            }
        }

        private void Handle(object state)
        {
            HttpListenerContext ctx = (HttpListenerContext)state;
            try
            {
                Dispatch(ctx);
            }
            catch (HttpListenerException)
            {
                // client disconnected
            }
            catch (IOException)
            {
                // client disconnected mid-stream
            }
            catch (Exception ex)
            {
                try { WriteJson(ctx.Response, 500, Error("internal_error", ex.Message)); } catch { }
            }
            finally
            {
                try { ctx.Response.Close(); } catch { }
            }
        }

        // ------------------------------------------------------------------
        // Routing
        // ------------------------------------------------------------------

        private void Dispatch(HttpListenerContext ctx)
        {
            HttpListenerRequest req = ctx.Request;
            HttpListenerResponse resp = ctx.Response;
            string path = req.Url.AbsolutePath;
            if (path.Length > 1 && path.EndsWith("/")) path = path.TrimEnd('/');
            string method = req.HttpMethod.ToUpperInvariant();
            string origin = req.Headers["Origin"];
            bool originAllowed = origin != null && allowedOrigins.Contains(origin.Trim().TrimEnd('/'));

            // Server-facing evidence endpoints: token protected, never for browsers.
            if (path.StartsWith("/s/", StringComparison.Ordinal))
            {
                ServeShare(req, resp, path, method, origin);
                return;
            }

            if (method == "DELETE" && path.StartsWith("/shares/", StringComparison.Ordinal) && HasBearer(req) && origin == null)
            {
                RevokeWithToken(req, resp, path.Substring("/shares/".Length));
                return;
            }

            if (method == "OPTIONS")
            {
                if (!originAllowed && path != "/health")
                {
                    WriteJson(resp, 403, Error("origin_not_paired", "This console is not paired with the agent."));
                    return;
                }
                SetCors(resp, origin, true);
                resp.StatusCode = 204;
                resp.ContentLength64 = 0;
                resp.OutputStream.Close();
                return;
            }

            if (path == "/" || path == "/health")
            {
                if (origin != null) SetCors(resp, origin, false);
                WriteJson(resp, 200, Health(origin == null || originAllowed));
                return;
            }

            if (originAllowed) SetCors(resp, origin, false);
            if (!req.IsLocal || !HostIsLoopback(req))
            {
                WriteJson(resp, 403, Error("local_only", "Folder browsing and sharing are only available from this computer."));
                return;
            }
            if (origin != null && !originAllowed)
            {
                WriteJson(resp, 403, Error("origin_not_paired",
                    "This console (" + origin + ") is not paired with the agent. Re-run the installer with -ConsoleOrigin " + origin + "."));
                return;
            }

            if (method == "GET" && path == "/drives") { WriteJson(resp, 200, Drives()); return; }
            if (method == "POST" && (path == "/list-dir" || path == "/list_dir")) { ListDir(req, resp); return; }
            if (method == "POST" && path == "/shares") { CreateShare(req, resp); return; }
            if (method == "GET" && path == "/shares") { WriteJson(resp, 200, ListShares()); return; }
            if (method == "DELETE" && path.StartsWith("/shares/", StringComparison.Ordinal))
            {
                string id = path.Substring("/shares/".Length);
                bool removed = RemoveShare(id, "local");
                WriteJson(resp, removed ? 200 : 404, removed ? Ok() : Error("not_found", "Unknown share"));
                return;
            }
            WriteJson(resp, 404, Error("not_found", "Unknown endpoint"));
        }

        private static bool HostIsLoopback(HttpListenerRequest req)
        {
            string host = (req.Url.Host ?? "").Trim().ToLowerInvariant();
            return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
        }

        private void SetCors(HttpListenerResponse resp, string origin, bool preflight)
        {
            if (origin == null) return;
            resp.AddHeader("Access-Control-Allow-Origin", origin);
            resp.AddHeader("Vary", "Origin");
            if (preflight)
            {
                resp.AddHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
                resp.AddHeader("Access-Control-Allow-Headers", "Content-Type");
                resp.AddHeader("Access-Control-Allow-Private-Network", "true");
                resp.AddHeader("Access-Control-Max-Age", "600");
            }
        }

        // ------------------------------------------------------------------
        // Browser-facing endpoints (loopback + paired origin)
        // ------------------------------------------------------------------

        private Dictionary<string, object> Health(bool full)
        {
            Dictionary<string, object> h = new Dictionary<string, object>();
            h["ok"] = true;
            h["service"] = Service;
            h["version"] = Version;
            h["origin_allowed"] = full;
            if (!full)
            {
                h["pairing_hint"] = "Re-run the Client Evidence Agent installer with -ConsoleOrigin set to this console's address.";
                return h;
            }
            h["hostname"] = Environment.MachineName;
            h["addresses"] = LocalAddresses();
            h["port"] = Port;
            h["lan_bound"] = LanBound;
            h["listen"] = ListenPrefix;
            h["server_allow_list"] = allowedServers.Count > 0;
            h["relay_supported"] = true;
            h["wire_encodings"] = new string[] { "zero", "deflate" };
            List<object> relayState = new List<object>();
            lock (gate)
            {
                h["share_count"] = shares.Count;
                foreach (RelayWorker w in relays.Values)
                {
                    Dictionary<string, object> r = new Dictionary<string, object>();
                    r["share_id"] = w.ShareId;
                    r["connected"] = w.LastOkTicks > 0 && (DateTime.UtcNow - new DateTime(w.LastOkTicks, DateTimeKind.Utc)).TotalSeconds < 90;
                    r["last_error"] = w.LastError;
                    relayState.Add(r);
                }
            }
            h["relay"] = relayState;
            return h;
        }

        public static List<string> LocalAddresses()
        {
            List<string> list = new List<string>();
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (UnicastIPAddressInformation ua in nic.GetIPProperties().UnicastAddresses)
                    {
                        IPAddress ip = ua.Address;
                        if (IPAddress.IsLoopback(ip)) continue;
                        if (ip.AddressFamily == AddressFamily.InterNetwork)
                        {
                            byte[] b = ip.GetAddressBytes();
                            if (b[0] == 169 && b[1] == 254) continue;
                            list.Add(ip.ToString());
                        }
                        else if (ip.AddressFamily == AddressFamily.InterNetworkV6 && !ip.IsIPv6LinkLocal && !ip.IsIPv6Multicast)
                        {
                            string s = ip.ToString();
                            int pct = s.IndexOf('%');
                            list.Add(pct >= 0 ? s.Substring(0, pct) : s);
                        }
                    }
                }
            }
            catch { }
            return list;
        }

        private Dictionary<string, object> Drives()
        {
            List<object> drives = new List<object>();
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                Dictionary<string, object> item = new Dictionary<string, object>();
                string root = d.Name;
                string letter = root.Length >= 2 && root[1] == ':' ? root.Substring(0, 1).ToUpperInvariant() : root;
                item["letter"] = letter;
                item["root"] = root;
                string kind;
                switch (d.DriveType)
                {
                    case DriveType.Fixed: kind = "fixed"; break;
                    case DriveType.Removable: kind = "removable"; break;
                    case DriveType.Network: kind = "network"; break;
                    case DriveType.CDRom: kind = "cdrom"; break;
                    case DriveType.Ram: kind = "fixed"; break;
                    default: kind = "unknown"; break;
                }
                item["drive_type"] = kind;
                bool ready = false;
                try { ready = d.IsReady; } catch { }
                item["ready"] = ready;
                if (ready)
                {
                    try { item["label"] = d.VolumeLabel; } catch { }
                    try { item["size_bytes"] = d.TotalSize; } catch { }
                    try { item["free_bytes"] = d.AvailableFreeSpace; } catch { }
                    try { item["format"] = d.DriveFormat; } catch { }
                }
                drives.Add(item);
            }
            Dictionary<string, object> res = Ok();
            res["hostname"] = Environment.MachineName;
            res["drives"] = drives;
            return res;
        }

        private void ListDir(HttpListenerRequest req, HttpListenerResponse resp)
        {
            Dictionary<string, object> body = ReadBody(req);
            string raw = Str(body, "path");
            if (String.IsNullOrEmpty(raw)) { WriteJson(resp, 400, Error("bad_request", "No path specified")); return; }
            string full;
            try { full = Path.GetFullPath(raw); }
            catch (Exception ex) { WriteJson(resp, 400, Error("bad_path", ex.Message)); return; }
            if (!Directory.Exists(full)) { WriteJson(resp, 404, Error("not_found", "Folder not found: " + full)); return; }

            List<object> entries = new List<object>();
            bool truncated = false;
            DirectoryInfo di = new DirectoryInfo(full);
            try
            {
                foreach (FileSystemInfo fsi in di.EnumerateFileSystemInfos())
                {
                    if (entries.Count >= MaxListEntries) { truncated = true; break; }
                    Dictionary<string, object> e = new Dictionary<string, object>();
                    bool isDir = (fsi.Attributes & FileAttributes.Directory) == FileAttributes.Directory;
                    e["name"] = fsi.Name;
                    e["kind"] = isDir ? "dir" : "file";
                    e["hidden"] = (fsi.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0;
                    e["link"] = (fsi.Attributes & FileAttributes.ReparsePoint) != 0;
                    try { e["mtime_ms"] = ToMs(fsi.LastWriteTimeUtc); } catch { }
                    if (!isDir)
                    {
                        try { e["size_bytes"] = ((FileInfo)fsi).Length; } catch { e["size_bytes"] = null; }
                    }
                    entries.Add(e);
                }
            }
            catch (UnauthorizedAccessException)
            {
                WriteJson(resp, 403, Error("access_denied", "Windows denied access to " + full));
                return;
            }
            entries.Sort(CompareEntries);
            Dictionary<string, object> res = Ok();
            res["path"] = full;
            DirectoryInfo parent = di.Parent;
            res["parent"] = parent == null ? null : parent.FullName;
            res["entries"] = entries;
            res["count"] = entries.Count;
            res["truncated"] = truncated;
            WriteJson(resp, 200, res);
        }

        private static int CompareEntries(object a, object b)
        {
            Dictionary<string, object> x = (Dictionary<string, object>)a;
            Dictionary<string, object> y = (Dictionary<string, object>)b;
            int kx = (string)x["kind"] == "dir" ? 0 : 1;
            int ky = (string)y["kind"] == "dir" ? 0 : 1;
            if (kx != ky) return kx - ky;
            return String.Compare((string)x["name"], (string)y["name"], StringComparison.OrdinalIgnoreCase);
        }

        private void CreateShare(HttpListenerRequest req, HttpListenerResponse resp)
        {
            string ctype = req.ContentType ?? "";
            if (ctype.IndexOf("application/json", StringComparison.OrdinalIgnoreCase) < 0)
            {
                WriteJson(resp, 415, Error("json_required", "Content-Type must be application/json"));
                return;
            }
            Dictionary<string, object> body = ReadBody(req);
            string raw = Str(body, "path");
            if (String.IsNullOrEmpty(raw)) { WriteJson(resp, 400, Error("bad_request", "No path specified")); return; }
            string root;
            try { root = Path.GetFullPath(raw); }
            catch (Exception ex) { WriteJson(resp, 400, Error("bad_path", ex.Message)); return; }
            if (!Directory.Exists(root)) { WriteJson(resp, 404, Error("not_found", "Folder not found: " + root)); return; }

            ShareState s = BuildManifest(root);
            s.share_id = "ce" + RandomHex(12);
            string token = RandomToken();
            s.token_sha256 = Sha256Hex(token);
            s.label = Truncate(Str(body, "label"), 200);
            s.job_id = Truncate(Str(body, "job_id"), 80);
            bool relayEnabled = AcceptRelayTarget(s, Str(body, "relay_url"), Str(body, "relay_service"), req.Headers["Origin"]);
            if (relayEnabled) s.token_protected = ProtectToken(token);
            DateTime now = DateTime.UtcNow;
            s.created_utc = now.ToString("o", CultureInfo.InvariantCulture);
            s.expires_utc = now.AddDays(Math.Max(1, ShareDays)).ToString("o", CultureInfo.InvariantCulture);
            lock (gate) { shares[s.share_id] = s; }
            SaveShare(s);
            if (relayEnabled) StartRelay(s, token);
            Audit(RemoteOf(req), "share_create", s.share_id,
                root + " files=" + s.files.Count + " bytes=" + s.total_bytes + " job=" + s.job_id + " truncated=" + s.truncated);

            Dictionary<string, object> res = Ok();
            res["share_id"] = s.share_id;
            res["token"] = token;
            res["root"] = s.root;
            res["hostname"] = Environment.MachineName;
            res["addresses"] = LocalAddresses();
            res["port"] = Port;
            res["lan_bound"] = LanBound;
            res["file_count"] = s.files.Count;
            res["dir_count"] = s.dirs.Count;
            res["total_bytes"] = s.total_bytes;
            res["manifest_sha256"] = s.manifest_sha256;
            res["truncated"] = s.truncated;
            res["skipped"] = s.skipped;
            res["expires_utc"] = s.expires_utc;
            res["agent_version"] = Version;
            res["relay_supported"] = true;
            res["relay_enabled"] = relayEnabled;
            List<object> preview = new List<object>();
            for (int i = 0; i < s.files.Count && i < 500; i++)
            {
                Dictionary<string, object> f = new Dictionary<string, object>();
                f["path"] = s.files[i].path;
                f["size"] = s.files[i].size;
                preview.Add(f);
            }
            res["files_preview"] = preview;
            WriteJson(resp, 200, res);
        }

        private Dictionary<string, object> ListShares()
        {
            List<object> list = new List<object>();
            lock (gate)
            {
                foreach (ShareState s in shares.Values)
                {
                    Dictionary<string, object> d = new Dictionary<string, object>();
                    d["share_id"] = s.share_id;
                    d["root"] = s.root;
                    d["job_id"] = s.job_id;
                    d["label"] = s.label;
                    d["file_count"] = s.files == null ? 0 : s.files.Count;
                    d["total_bytes"] = s.total_bytes;
                    d["created_utc"] = s.created_utc;
                    d["expires_utc"] = s.expires_utc;
                    list.Add(d);
                }
            }
            Dictionary<string, object> res = Ok();
            res["shares"] = list;
            return res;
        }

        // ------------------------------------------------------------------
        // Manifest
        // ------------------------------------------------------------------

        public ShareState BuildManifest(string root)
        {
            ShareState s = new ShareState();
            s.root = root;
            s.files = new List<ManifestFile>();
            s.dirs = new List<string>();
            DateTime deadline = DateTime.UtcNow.AddSeconds(Math.Max(5, MaxManifestSeconds));
            Stack<KeyValuePair<string, string>> stack = new Stack<KeyValuePair<string, string>>();
            stack.Push(new KeyValuePair<string, string>(root, ""));
            while (stack.Count > 0)
            {
                KeyValuePair<string, string> top = stack.Pop();
                IEnumerable<FileSystemInfo> items;
                try { items = new DirectoryInfo(top.Key).EnumerateFileSystemInfos(); }
                catch { s.skipped++; continue; }
                try
                {
                    foreach (FileSystemInfo fsi in items)
                    {
                        if (s.files.Count >= MaxFiles || DateTime.UtcNow > deadline) { s.truncated = true; break; }
                        string rel = top.Value.Length == 0 ? fsi.Name : top.Value + "/" + fsi.Name;
                        if ((fsi.Attributes & FileAttributes.ReparsePoint) != 0) { s.skipped++; continue; }
                        if ((fsi.Attributes & FileAttributes.Directory) != 0)
                        {
                            if (Array.IndexOf(SkipDirs, fsi.Name.ToLowerInvariant()) >= 0) continue;
                            s.dirs.Add(rel);
                            stack.Push(new KeyValuePair<string, string>(fsi.FullName, rel));
                            continue;
                        }
                        ManifestFile mf = new ManifestFile();
                        mf.path = rel;
                        try
                        {
                            FileInfo fi = (FileInfo)fsi;
                            mf.size = fi.Length;
                            mf.mtime_ms = ToMs(fi.LastWriteTimeUtc);
                        }
                        catch { s.skipped++; continue; }
                        s.files.Add(mf);
                        s.total_bytes += mf.size;
                    }
                }
                catch { s.skipped++; }
                if (s.truncated) break;
            }
            s.files.Sort(delegate (ManifestFile a, ManifestFile b) { return String.CompareOrdinal(a.path, b.path); });
            s.dirs.Sort(String.CompareOrdinal);
            s.manifest_sha256 = ManifestDigest(s.files);
            return s;
        }

        public static string ManifestDigest(List<ManifestFile> files)
        {
            using (SHA256 sha = SHA256.Create())
            {
                StringBuilder sb = new StringBuilder();
                foreach (ManifestFile f in files)
                {
                    sb.Append(f.path).Append('\t')
                      .Append(f.size.ToString(CultureInfo.InvariantCulture)).Append('\t')
                      .Append(f.mtime_ms.ToString(CultureInfo.InvariantCulture)).Append('\n');
                }
                return Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString())));
            }
        }

        // ------------------------------------------------------------------
        // Server-facing share endpoints
        // ------------------------------------------------------------------

        private void ServeShare(HttpListenerRequest req, HttpListenerResponse resp, string path, string method, string origin)
        {
            if (origin != null)
            {
                WriteJson(resp, 403, Error("browser_forbidden", "Evidence bytes are only served to the forensic server."));
                return;
            }
            string remote = RemoteOf(req);
            if (allowedServers.Count > 0 && !allowedServers.Contains(remote))
            {
                Audit(remote, "denied_remote", "-", path);
                WriteJson(resp, 403, Error("server_not_allowed", "This address is not an allowed forensic server."));
                return;
            }
            string[] parts = path.Split('/');
            // "", "s", "<id>", "manifest" | "f", "<index>"
            if (parts.Length < 4) { WriteJson(resp, 404, Error("not_found", "Unknown endpoint")); return; }
            ShareState s = Authorize(req, resp, parts[2]);
            if (s == null) return;

            if (parts.Length == 4 && parts[3] == "manifest" && method == "GET")
            {
                Audit(remote, "manifest", s.share_id, "files=" + s.files.Count);
                WriteJson(resp, 200, ManifestPayload(s));
                return;
            }
            if (parts.Length == 5 && parts[3] == "f" && (method == "GET" || method == "HEAD"))
            {
                int index;
                if (!Int32.TryParse(parts[4], NumberStyles.None, CultureInfo.InvariantCulture, out index) || index < 0 || index >= s.files.Count)
                {
                    WriteJson(resp, 404, Error("not_found", "Unknown file index"));
                    return;
                }
                ServeFile(req, resp, s, index, method == "HEAD", remote);
                return;
            }
            WriteJson(resp, 404, Error("not_found", "Unknown endpoint"));
        }

        private static Dictionary<string, object> ManifestPayload(ShareState s)
        {
            Dictionary<string, object> res = Ok();
            res["agent_version"] = Version;
            res["share_id"] = s.share_id;
            res["root"] = s.root;
            res["hostname"] = Environment.MachineName;
            res["files"] = s.files;
            res["dirs"] = s.dirs;
            res["file_count"] = s.files.Count;
            res["total_bytes"] = s.total_bytes;
            res["manifest_sha256"] = s.manifest_sha256;
            res["truncated"] = s.truncated;
            return res;
        }

        private ShareState Authorize(HttpListenerRequest req, HttpListenerResponse resp, string shareId)
        {
            ShareState s;
            lock (gate) { shares.TryGetValue(shareId, out s); }
            if (s == null) { WriteJson(resp, 404, Error("not_found", "Unknown or expired share")); return null; }
            if (IsExpired(s))
            {
                RemoveShare(s.share_id, "expired");
                WriteJson(resp, 404, Error("expired", "Share expired"));
                return null;
            }
            string token = BearerOf(req);
            if (token == null || !FixedEquals(Sha256Hex(token), s.token_sha256))
            {
                Audit(RemoteOf(req), "bad_token", shareId, req.Url.AbsolutePath);
                WriteJson(resp, 401, Error("unauthorized", "Invalid share token"));
                return null;
            }
            Touch(s);
            return s;
        }

        private void ServeFile(HttpListenerRequest req, HttpListenerResponse resp, ShareState s, int index, bool headOnly, string remote)
        {
            ManifestFile mf = s.files[index];
            string full;
            string problem = CheckFile(s, mf, out full);
            if (problem != null)
            {
                Audit(remote, problem, s.share_id, mf.path);
                WriteJson(resp, problem == "outside_share" ? 403 : 409, Error(problem, ProblemText(problem, mf.path)));
                return;
            }
            long size = mf.size;
            long start = 0, end = size - 1;
            bool partial = false;
            string range = req.Headers["Range"];
            if (!String.IsNullOrEmpty(range))
            {
                if (!ParseRange(range, size, out start, out end))
                {
                    resp.AddHeader("Content-Range", "bytes */" + size.ToString(CultureInfo.InvariantCulture));
                    WriteJson(resp, 416, Error("bad_range", "Requested range not satisfiable"));
                    return;
                }
                partial = true;
            }
            long length = size == 0 ? 0 : end - start + 1;
            resp.StatusCode = partial ? 206 : 200;
            resp.ContentType = "application/octet-stream";
            resp.AddHeader("Accept-Ranges", "bytes");
            resp.AddHeader("ETag", "\"" + mf.size.ToString(CultureInfo.InvariantCulture) + "-" + mf.mtime_ms.ToString(CultureInfo.InvariantCulture) + "\"");
            resp.AddHeader("Cache-Control", "no-store");
            if (partial)
                resp.AddHeader("Content-Range", "bytes " + start.ToString(CultureInfo.InvariantCulture) + "-" + end.ToString(CultureInfo.InvariantCulture) + "/" + size.ToString(CultureInfo.InvariantCulture));
            resp.ContentLength64 = length;
            if (headOnly || length == 0)
            {
                resp.OutputStream.Close();
                return;
            }
            string accept = req.Headers["X-Polaron-Accept-Encoding"];
            if (partial && !String.IsNullOrEmpty(accept) && length <= MaxRelayChunk)
            {
                // Read the range, then send it as-is, as an "all zero" marker or compressed.
                byte[] raw = ReadExact(full, start, length);
                if (raw == null)
                {
                    Audit(remote, "evidence_modified", s.share_id, mf.path);
                    resp.StatusCode = 409;
                    resp.ContentLength64 = 0;
                    resp.OutputStream.Close();
                    return;
                }
                string encoding;
                byte[] wire = EncodeForWire(raw, accept, out encoding);
                if (encoding != null)
                {
                    resp.AddHeader("X-Polaron-Encoding", encoding);
                    resp.AddHeader("X-Polaron-Raw-Length", length.ToString(CultureInfo.InvariantCulture));
                }
                resp.ContentLength64 = wire.Length;
                LogOpenOnce(remote, s.share_id, index, mf.path);
                if (wire.Length > 0) resp.OutputStream.Write(wire, 0, wire.Length);
                resp.OutputStream.Close();
                return;
            }
            LogOpenOnce(remote, s.share_id, index, mf.path);
            streams.Wait();
            try
            {
                using (FileStream fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.None))
                {
                    fs.Seek(start, SeekOrigin.Begin);
                    byte[] buf = new byte[1 << 20];
                    long remaining = length;
                    Stream output = resp.OutputStream;
                    while (remaining > 0)
                    {
                        int n = fs.Read(buf, 0, (int)Math.Min(buf.Length, remaining));
                        if (n <= 0) break;
                        output.Write(buf, 0, n);
                        remaining -= n;
                    }
                    output.Close();
                }
            }
            finally
            {
                streams.Release();
            }
        }

        /// <summary>Read exactly length bytes at start, or null if the file got shorter.</summary>
        private byte[] ReadExact(string full, long start, long length)
        {
            byte[] buf = new byte[length];
            streams.Wait();
            try
            {
                using (FileStream fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.None))
                {
                    fs.Seek(start, SeekOrigin.Begin);
                    int got = 0;
                    while (got < length)
                    {
                        int n = fs.Read(buf, got, (int)Math.Min(1 << 20, length - got));
                        if (n <= 0) break;
                        got += n;
                    }
                    return got == length ? buf : null;
                }
            }
            finally
            {
                streams.Release();
            }
        }

        public static bool IsAllZero(byte[] data)
        {
            int i = 0;
            for (; i + 8 <= data.Length; i += 8) if (BitConverter.ToInt64(data, i) != 0) return false;
            for (; i < data.Length; i++) if (data[i] != 0) return false;
            return true;
        }

        public static byte[] Deflate(byte[] data, int offset, int count)
        {
            using (MemoryStream ms = new MemoryStream(Math.Max(1024, count / 2)))
            {
                using (DeflateStream ds = new DeflateStream(ms, CompressionLevel.Fastest, true)) { ds.Write(data, offset, count); }
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Wire form of a block: an empty "zero" marker for all-zero data, raw DEFLATE when it saves at
        /// least 10 %, otherwise the bytes unchanged. Four 4 KiB samples spread over the block decide
        /// whether compressing is worth the CPU (a run can start with random data and end in empty
        /// space), so already-compressed E01 / ZIP data is passed through almost for free.
        /// </summary>
        private static bool WorthCompressing(byte[] raw)
        {
            const int Sample = 4096;
            for (int i = 0; i < 4; i++)
            {
                int offset = (int)((long)(raw.Length - Sample) * i / 3);
                if (Deflate(raw, offset, Sample).Length <= Sample * 9 / 10) return true;
            }
            return false;
        }

        public static byte[] EncodeForWire(byte[] raw, string accept, out string encoding)
        {
            encoding = null;
            if (String.IsNullOrEmpty(accept) || raw.Length == 0) return raw;
            string a = accept.ToLowerInvariant();
            if (a.Contains("zero") && IsAllZero(raw))
            {
                encoding = "zero";
                return new byte[0];
            }
            if (a.Contains("deflate") && raw.Length >= 4096)
            {
                if (raw.Length > 64 * 1024 && !WorthCompressing(raw)) return raw;
                byte[] packed = Deflate(raw, 0, raw.Length);
                if (packed.Length < raw.Length - raw.Length / 10)
                {
                    encoding = "deflate";
                    return packed;
                }
            }
            return raw;
        }

        /// <summary>Null when the file is still exactly as selected; otherwise the reason it must not be read.</summary>
        private static string CheckFile(ShareState s, ManifestFile mf, out string full)
        {
            full = Path.GetFullPath(Path.Combine(s.root, mf.path.Replace('/', Path.DirectorySeparatorChar)));
            string rootFull = Path.GetFullPath(s.root);
            string rootPrefix = rootFull.EndsWith(Path.DirectorySeparatorChar.ToString()) ? rootFull : rootFull + Path.DirectorySeparatorChar;
            if (!full.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase)) return "outside_share";
            FileInfo fi = new FileInfo(full);
            if (!fi.Exists) return "evidence_missing";
            if (fi.Length != mf.size || ToMs(fi.LastWriteTimeUtc) != mf.mtime_ms) return "evidence_modified";
            return null;
        }

        private static string ProblemText(string problem, string path)
        {
            if (problem == "outside_share") return "Path escapes the shared folder";
            if (problem == "evidence_missing") return path + " is no longer present on this computer";
            return path + " changed after it was selected";
        }

        public static bool ParseRange(string header, long size, out long start, out long end)
        {
            start = 0; end = size - 1;
            string h = header.Trim();
            if (!h.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase)) return false;
            string spec = h.Substring(6).Trim();
            if (spec.IndexOf(',') >= 0) return false;
            int dash = spec.IndexOf('-');
            if (dash < 0) return false;
            string a = spec.Substring(0, dash).Trim();
            string b = spec.Substring(dash + 1).Trim();
            long x, y;
            if (a.Length == 0)
            {
                if (!Int64.TryParse(b, NumberStyles.None, CultureInfo.InvariantCulture, out y) || y <= 0) return false;
                if (size == 0) return false;
                start = Math.Max(0, size - y);
                end = size - 1;
                return true;
            }
            if (!Int64.TryParse(a, NumberStyles.None, CultureInfo.InvariantCulture, out x)) return false;
            if (x >= size) return false;
            start = x;
            if (b.Length == 0) { end = size - 1; return true; }
            if (!Int64.TryParse(b, NumberStyles.None, CultureInfo.InvariantCulture, out y) || y < x) return false;
            end = Math.Min(y, size - 1);
            return true;
        }

        private void RevokeWithToken(HttpListenerRequest req, HttpListenerResponse resp, string shareId)
        {
            ShareState s;
            lock (gate) { shares.TryGetValue(shareId, out s); }
            if (s == null) { WriteJson(resp, 404, Error("not_found", "Unknown share")); return; }
            string token = BearerOf(req);
            if (token == null || !FixedEquals(Sha256Hex(token), s.token_sha256))
            {
                WriteJson(resp, 401, Error("unauthorized", "Invalid share token"));
                return;
            }
            RemoveShare(shareId, "server:" + RemoteOf(req));
            WriteJson(resp, 200, Ok());
        }

        // ------------------------------------------------------------------
        // Outbound relay: this PC connects to the Polaron server
        // ------------------------------------------------------------------

        private void ConfigureOutboundHttp()
        {
            // Windows PowerShell 5.1 (.NET Framework) may default to TLS 1.0 only.
            try { ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072 | (SecurityProtocolType)768; }
            catch { }
            // The .NET Framework default of 2 connections per host would starve the pollers.
            ServicePointManager.DefaultConnectionLimit = Math.Max(ServicePointManager.DefaultConnectionLimit, 128);
            ServicePointManager.Expect100Continue = false;
            if (trustedThumbprints.Count > 0)
                ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;
        }

        private bool ValidateServerCertificate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            if (errors == SslPolicyErrors.None) return true;
            if (cert == null) return false;
            string thumb = new X509Certificate2(cert).Thumbprint;
            return thumb != null && trustedThumbprints.Contains(thumb.ToUpperInvariant());
        }

        /// <summary>Relay only to the paired console that asked for this share, on the same origin.</summary>
        private bool AcceptRelayTarget(ShareState s, string relayUrl, string relayService, string origin)
        {
            if (String.IsNullOrEmpty(relayUrl) || String.IsNullOrEmpty(origin)) return false;
            string o = origin.Trim().TrimEnd('/');
            if (!allowedOrigins.Contains(o)) return false;
            Uri u;
            if (!Uri.TryCreate(relayUrl, UriKind.Absolute, out u)) return false;
            if (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp) return false;
            if (!String.Equals(u.GetLeftPart(UriPartial.Authority).TrimEnd('/'), o, StringComparison.OrdinalIgnoreCase)) return false;
            s.relay_url = relayUrl.Trim().TrimEnd('/');
            s.relay_service = IsServiceName(relayService) ? relayService : "";
            return true;
        }

        private static bool IsServiceName(string value)
        {
            if (String.IsNullOrEmpty(value) || value.Length > 40) return false;
            foreach (char c in value) if (!((c >= 'a' && c <= 'z') || c == '-')) return false;
            return true;
        }

        public static string ProtectToken(string token)
        {
            byte[] raw = Encoding.UTF8.GetBytes(token);
            try { return "dpapi:" + Convert.ToBase64String(ProtectedData.Protect(raw, TokenEntropy, DataProtectionScope.CurrentUser)); }
            catch { return "plain:" + Convert.ToBase64String(raw); }
        }

        private static string UnprotectToken(ShareState s)
        {
            string blob = s.token_protected;
            if (String.IsNullOrEmpty(blob)) return null;
            try
            {
                string token;
                if (blob.StartsWith("dpapi:", StringComparison.Ordinal))
                    token = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(blob.Substring(6)), TokenEntropy, DataProtectionScope.CurrentUser));
                else if (blob.StartsWith("plain:", StringComparison.Ordinal))
                    token = Encoding.UTF8.GetString(Convert.FromBase64String(blob.Substring(6)));
                else return null;
                return FixedEquals(Sha256Hex(token), s.token_sha256) ? token : null;
            }
            catch { return null; }
        }

        private void StartRelay(ShareState s, string token)
        {
            if (s == null || String.IsNullOrEmpty(s.relay_url) || String.IsNullOrEmpty(token)) return;
            RelayWorker w;
            lock (gate)
            {
                if (relays.ContainsKey(s.share_id)) return;
                w = new RelayWorker();
                w.ShareId = s.share_id;
                w.Token = token;
                w.Created = DateTime.UtcNow;
                relays[s.share_id] = w;
            }
            for (int i = 0; i < Math.Max(1, RelayConnections); i++)
            {
                Thread t = new Thread(RelayLoop);
                t.IsBackground = true;
                t.Name = "polaron-relay-" + i.ToString(CultureInfo.InvariantCulture);
                t.Start(w);
            }
            Audit("-", "relay_start", s.share_id, s.relay_url + " service=" + s.relay_service);
        }

        private void SleepUnlessStopped(RelayWorker w, int ms)
        {
            DateTime until = DateTime.UtcNow.AddMilliseconds(ms);
            while (running && !w.Stop && DateTime.UtcNow < until) Thread.Sleep(200);
        }

        private HttpWebRequest NewRelayRequest(ShareState s, string token, string suffix)
        {
            HttpWebRequest r = (HttpWebRequest)WebRequest.Create(s.relay_url + suffix);
            r.Method = "POST";
            r.KeepAlive = true;
            r.AllowAutoRedirect = false;
            r.UserAgent = "PolaronClientEvidenceAgent/" + Version;
            r.Headers["Authorization"] = "Bearer " + token;
            r.Headers["X-Polaron-Share"] = s.share_id;
            if (!String.IsNullOrEmpty(s.relay_service)) r.Headers["X-Aetheris-Service"] = s.relay_service;
            if (r.Proxy != null) r.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
            return r;
        }

        private static void WriteRequestBody(HttpWebRequest r, byte[] body, string contentType)
        {
            r.ContentType = contentType;
            r.ContentLength = body.Length;
            r.AllowWriteStreamBuffering = false;
            using (Stream st = r.GetRequestStream()) { st.Write(body, 0, body.Length); }
        }

        private void RelayLoop(object state)
        {
            RelayWorker w = (RelayWorker)state;
            int backoff = 1000;
            DateTime unknownSince = DateTime.MinValue;
            byte[] hello = Encoding.UTF8.GetBytes("{\"agent_version\":\"" + Version + "\"}");
            while (running && !w.Stop)
            {
                ShareState s;
                lock (gate) { shares.TryGetValue(w.ShareId, out s); }
                if (s == null || IsExpired(s)) break;
                HttpWebResponse resp = null;
                try
                {
                    HttpWebRequest req = NewRelayRequest(s, w.Token, "/poll");
                    req.Timeout = 60000;
                    req.ReadWriteTimeout = 60000;
                    req.Headers["X-Polaron-Wait"] = "25";
                    WriteRequestBody(req, hello, "application/json");
                    resp = (HttpWebResponse)req.GetResponse();
                    backoff = 1000;
                    unknownSince = DateTime.MinValue;
                    w.LastOkTicks = DateTime.UtcNow.Ticks;
                    w.LastError = "";
                    if ((int)resp.StatusCode == 204) continue;
                    string json;
                    using (StreamReader rd = new StreamReader(resp.GetResponseStream(), Encoding.UTF8)) { json = rd.ReadToEnd(); }
                    resp.Close();
                    resp = null;
                    Dictionary<string, object> msg = Json().Deserialize<Dictionary<string, object>>(json);
                    if (msg != null) HandleRelayMessage(s, w, msg);
                }
                catch (WebException ex)
                {
                    HttpWebResponse er = ex.Response as HttpWebResponse;
                    int code = er != null ? (int)er.StatusCode : 0;
                    if (er != null) { try { er.Close(); } catch { } }
                    w.LastError = code > 0 ? "HTTP " + code.ToString(CultureInfo.InvariantCulture) : ex.Message;
                    if (code == 401 || code == 403)
                    {
                        Audit("-", "relay_rejected", w.ShareId, w.LastError);
                        w.Stop = true;
                        break;
                    }
                    if (code == 404)
                    {
                        // Not attached yet, or the server is rebuilding its share list: keep trying.
                        if (unknownSince == DateTime.MinValue) unknownSince = DateTime.UtcNow;
                        if ((DateTime.UtcNow - unknownSince).TotalHours > 6)
                        {
                            Audit("-", "relay_stopped", w.ShareId, "unknown to the server for 6 hours");
                            w.Stop = true;
                            break;
                        }
                        bool young = (DateTime.UtcNow - w.Created).TotalMinutes < 3;
                        SleepUnlessStopped(w, young ? 1500 : 30000);
                        continue;
                    }
                    SleepUnlessStopped(w, backoff);
                    backoff = Math.Min(backoff * 2, 30000);
                }
                catch (Exception ex)
                {
                    w.LastError = ex.Message;
                    SleepUnlessStopped(w, backoff);
                    backoff = Math.Min(backoff * 2, 30000);
                }
                finally
                {
                    if (resp != null) { try { resp.Close(); } catch { } }
                }
            }
            lock (gate)
            {
                RelayWorker current;
                if (relays.TryGetValue(w.ShareId, out current) && current == w && w.Stop) relays.Remove(w.ShareId);
            }
        }

        private void HandleRelayMessage(ShareState s, RelayWorker w, Dictionary<string, object> msg)
        {
            string reqId = Str(msg, "req_id");
            string op = Str(msg, "op");
            if (reqId.Length == 0 || reqId.Length > 64) return;
            foreach (char c in reqId) if (!Char.IsLetterOrDigit(c)) return;
            // Tell the server at once that this request arrived, so it can tell a slow
            // upload from a request lost on a dropped connection.
            try
            {
                HttpWebRequest ack = NewRelayRequest(s, w.Token, "/ack/" + reqId);
                ack.Timeout = 15000;
                ack.ReadWriteTimeout = 15000;
                WriteRequestBody(ack, new byte[0], "application/octet-stream");
                using (HttpWebResponse r = (HttpWebResponse)ack.GetResponse()) { }
            }
            catch (WebException) { }
            int status = 200;
            byte[] body = new byte[0];
            string etag = null, contentRange = null, error = null, encoding = null;
            long rawLength = -1;
            try
            {
                if (op == "range")
                {
                    body = RelayRange(s, Convert.ToInt64(msg["index"], CultureInfo.InvariantCulture),
                        Convert.ToInt64(msg["start"], CultureInfo.InvariantCulture), Convert.ToInt64(msg["end"], CultureInfo.InvariantCulture),
                        out status, out etag, out contentRange, out error);
                    if (status == 206)
                    {
                        rawLength = body.Length;
                        body = EncodeForWire(body, Str(msg, "accept"), out encoding);
                    }
                }
                else if (op == "manifest")
                {
                    Audit("relay", "manifest", s.share_id, "files=" + s.files.Count);
                    body = Encoding.UTF8.GetBytes(Json().Serialize(ManifestPayload(s)));
                }
                else if (op == "revoke")
                {
                    RemoveShare(s.share_id, "server (relay)");
                    w.Stop = true;
                }
                else if (op == "health")
                {
                    body = Encoding.UTF8.GetBytes(Json().Serialize(Health(true)));
                }
                else
                {
                    status = 400;
                    error = "unknown_op";
                }
            }
            catch (Exception)
            {
                status = 500;
                error = "agent_error";
                body = new byte[0];
            }
            try
            {
                HttpWebRequest req = NewRelayRequest(s, w.Token, "/respond/" + reqId);
                req.Timeout = 300000;
                req.ReadWriteTimeout = 300000;
                req.Headers["X-Relay-Status"] = status.ToString(CultureInfo.InvariantCulture);
                if (etag != null) req.Headers["X-Relay-ETag"] = etag;
                if (contentRange != null) req.Headers["X-Relay-Content-Range"] = contentRange;
                if (error != null) req.Headers["X-Relay-Error"] = error;
                if (encoding != null)
                {
                    req.Headers["X-Relay-Encoding"] = encoding;
                    req.Headers["X-Relay-Raw-Length"] = rawLength.ToString(CultureInfo.InvariantCulture);
                }
                WriteRequestBody(req, body, "application/octet-stream");
                using (HttpWebResponse r = (HttpWebResponse)req.GetResponse()) { }
            }
            catch (WebException ex)
            {
                // The server stops waiting after its timeout; the reader simply asks again.
                w.LastError = "respond: " + ex.Message;
            }
        }

        private byte[] RelayRange(ShareState s, long index, long start, long end, out int status, out string etag, out string contentRange, out string error)
        {
            etag = null; contentRange = null; error = null;
            byte[] empty = new byte[0];
            if (index < 0 || index >= s.files.Count) { status = 404; error = "not_found"; return empty; }
            ManifestFile mf = s.files[(int)index];
            string full;
            string problem = CheckFile(s, mf, out full);
            if (problem != null)
            {
                Audit("relay", problem, s.share_id, mf.path);
                status = problem == "outside_share" ? 403 : 409;
                error = problem;
                return empty;
            }
            if (start < 0 || end < start || start >= mf.size) { status = 416; error = "bad_range"; return empty; }
            end = Math.Min(end, mf.size - 1);
            long length = end - start + 1;
            if (length > MaxRelayChunk) { status = 416; error = "range_too_large"; return empty; }
            byte[] buf = new byte[length];
            streams.Wait();
            try
            {
                using (FileStream fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.None))
                {
                    fs.Seek(start, SeekOrigin.Begin);
                    int got = 0;
                    while (got < length)
                    {
                        int n = fs.Read(buf, got, (int)Math.Min(1 << 20, length - got));
                        if (n <= 0) break;
                        got += n;
                    }
                    if (got != length) { status = 409; error = "evidence_modified"; return empty; }
                }
            }
            finally
            {
                streams.Release();
            }
            LogOpenOnce("relay", s.share_id, (int)index, mf.path);
            status = 206;
            etag = "\"" + mf.size.ToString(CultureInfo.InvariantCulture) + "-" + mf.mtime_ms.ToString(CultureInfo.InvariantCulture) + "\"";
            contentRange = "bytes " + start.ToString(CultureInfo.InvariantCulture) + "-" + end.ToString(CultureInfo.InvariantCulture) + "/" + mf.size.ToString(CultureInfo.InvariantCulture);
            return buf;
        }

        // ------------------------------------------------------------------
        // Share persistence
        // ------------------------------------------------------------------

        private string SharesDir() { return Path.Combine(StateDir, "shares"); }

        private static JavaScriptSerializer Json()
        {
            JavaScriptSerializer js = new JavaScriptSerializer();
            js.MaxJsonLength = Int32.MaxValue;
            js.RecursionLimit = 64;
            return js;
        }

        private void SaveShare(ShareState s)
        {
            string file = Path.Combine(SharesDir(), s.share_id + ".json");
            string tmp = file + ".tmp";
            File.WriteAllText(tmp, Json().Serialize(s), new UTF8Encoding(false));
            if (File.Exists(file)) File.Delete(file);
            File.Move(tmp, file);
        }

        private void LoadShares()
        {
            foreach (string file in Directory.GetFiles(SharesDir(), "*.json"))
            {
                try
                {
                    ShareState s = Json().Deserialize<ShareState>(File.ReadAllText(file, Encoding.UTF8));
                    if (s == null || String.IsNullOrEmpty(s.share_id) || s.files == null) continue;
                    if (s.dirs == null) s.dirs = new List<string>();
                    if (IsExpired(s)) { File.Delete(file); continue; }
                    lock (gate) { shares[s.share_id] = s; }
                }
                catch (Exception ex)
                {
                    Audit("-", "share_load_failed", Path.GetFileName(file), ex.Message);
                }
            }
        }

        public bool RemoveShare(string shareId, string reason)
        {
            bool removed;
            lock (gate)
            {
                removed = shares.Remove(shareId);
                RelayWorker w;
                if (relays.TryGetValue(shareId, out w)) { w.Stop = true; relays.Remove(shareId); }
            }
            try { File.Delete(Path.Combine(SharesDir(), shareId + ".json")); } catch { }
            if (removed) Audit("-", "share_revoke", shareId, reason);
            return removed;
        }

        private static bool IsExpired(ShareState s)
        {
            DateTime exp;
            if (!DateTime.TryParse(s.expires_utc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out exp)) return false;
            return exp.ToUniversalTime() < DateTime.UtcNow;
        }

        private void Touch(ShareState s)
        {
            DateTime now = DateTime.UtcNow;
            lock (gate)
            {
                DateTime last;
                if (lastTouch.TryGetValue(s.share_id, out last) && (now - last).TotalHours < 1) return;
                lastTouch[s.share_id] = now;
                s.expires_utc = now.AddDays(Math.Max(1, ShareDays)).ToString("o", CultureInfo.InvariantCulture);
            }
            try { SaveShare(s); } catch { }
        }

        // ------------------------------------------------------------------
        // Helpers
        // ------------------------------------------------------------------

        private void LogOpenOnce(string remote, string shareId, int index, string rel)
        {
            string key = shareId + "|" + index.ToString(CultureInfo.InvariantCulture);
            lock (logGate)
            {
                if (loggedOpens.Contains(key)) return;
                if (loggedOpens.Count > 100000) loggedOpens.Clear();
                loggedOpens.Add(key);
            }
            Audit(remote, "file_read", shareId, rel);
        }

        public void Audit(string remote, string action, string shareId, string detail)
        {
            try
            {
                if (String.IsNullOrEmpty(StateDir)) return;
                string file = Path.Combine(StateDir, "access.log");
                string line = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + "\t" + remote + "\t" + action + "\t" + shareId + "\t" + (detail ?? "").Replace('\t', ' ').Replace('\n', ' ') + Environment.NewLine;
                lock (logGate)
                {
                    FileInfo fi = new FileInfo(file);
                    if (fi.Exists && fi.Length > 10L * 1024 * 1024)
                    {
                        string old = file + ".1";
                        if (File.Exists(old)) File.Delete(old);
                        File.Move(file, old);
                    }
                    File.AppendAllText(file, line, new UTF8Encoding(false));
                }
            }
            catch { }
        }

        private static string RemoteOf(HttpListenerRequest req)
        {
            try
            {
                IPAddress ip = req.RemoteEndPoint.Address;
                if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
                return ip.ToString();
            }
            catch { return "?"; }
        }

        private static bool HasBearer(HttpListenerRequest req) { return BearerOf(req) != null; }

        private static string BearerOf(HttpListenerRequest req)
        {
            string auth = req.Headers["Authorization"];
            if (String.IsNullOrEmpty(auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
            string t = auth.Substring(7).Trim();
            return t.Length == 0 ? null : t;
        }

        private static Dictionary<string, object> ReadBody(HttpListenerRequest req)
        {
            if (!req.HasEntityBody) return new Dictionary<string, object>();
            if (req.ContentLength64 > 1024 * 1024) throw new InvalidOperationException("Request body too large");
            string text;
            using (StreamReader r = new StreamReader(req.InputStream, Encoding.UTF8)) { text = r.ReadToEnd(); }
            if (String.IsNullOrEmpty(text)) return new Dictionary<string, object>();
            Dictionary<string, object> d = Json().Deserialize<Dictionary<string, object>>(text);
            return d ?? new Dictionary<string, object>();
        }

        private static string Str(Dictionary<string, object> d, string key)
        {
            object v;
            if (d == null || !d.TryGetValue(key, out v) || v == null) return "";
            return Convert.ToString(v, CultureInfo.InvariantCulture).Trim();
        }

        private static string Truncate(string s, int max) { return s == null ? "" : (s.Length > max ? s.Substring(0, max) : s); }

        public static long ToMs(DateTime utc) { return (utc.ToUniversalTime().Ticks - EpochTicks) / TimeSpan.TicksPerMillisecond; }

        private static Dictionary<string, object> Ok()
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["ok"] = true;
            return d;
        }

        private static Dictionary<string, object> Error(string code, string message)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["ok"] = false;
            d["code"] = code;
            d["error"] = message;
            return d;
        }

        private static void WriteJson(HttpListenerResponse resp, int status, object body)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(Json().Serialize(body));
            resp.StatusCode = status;
            resp.ContentType = "application/json; charset=utf-8";
            resp.AddHeader("Cache-Control", "no-store");
            resp.ContentLength64 = bytes.Length;
            resp.OutputStream.Write(bytes, 0, bytes.Length);
            resp.OutputStream.Close();
        }

        private static string RandomHex(int bytes)
        {
            byte[] b = new byte[bytes];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) { rng.GetBytes(b); }
            return Hex(b);
        }

        private static string RandomToken()
        {
            byte[] b = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) { rng.GetBytes(b); }
            return Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static string Sha256Hex(string text)
        {
            using (SHA256 sha = SHA256.Create()) { return Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(text))); }
        }

        private static string Hex(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        private static bool FixedEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
'@

function Get-ForwardArgList {
    $list = New-Object System.Collections.Generic.List[string]
    $list.Add('-NoProfile'); $list.Add('-ExecutionPolicy'); $list.Add('Bypass')
    $list.Add('-File'); $list.Add(('"{0}"' -f $PSCommandPath))
    foreach ($key in $script:BoundArgs.Keys) {
        $value = $script:BoundArgs[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $list.Add("-$key") }
        }
        elseif ($value -is [array]) {
            $list.Add("-$key"); $list.Add(('"{0}"' -f ($value -join ',')))
        }
        else {
            $list.Add("-$key"); $list.Add(('"{0}"' -f [string]$value))
        }
    }
    return $list.ToArray()
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-OriginList {
    param([object[]]$Values)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($part in ([string]$value -split '[,;\s]+')) {
            $origin = $part.Trim().TrimEnd('/')
            if (-not $origin) { continue }
            if ($origin -notmatch '^https?://[^/\s?#]+$') {
                throw ("Invalid console address '{0}'. Use the address shown in the browser's address bar, for example https://polaron.lab" -f $origin)
            }
            if (-not $out.Contains($origin)) { $out.Add($origin) }
        }
    }
    return , $out.ToArray()
}

function ConvertTo-ServerList {
    param([object[]]$Values)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($part in ([string]$value -split '[,;\s]+')) {
            $candidate = $part.Trim()
            if (-not $candidate) { continue }
            $ip = $null
            if (-not [System.Net.IPAddress]::TryParse($candidate, [ref]$ip)) {
                throw ("Invalid -AllowedServer value '{0}'. Use the forensic server's IP address." -f $candidate)
            }
            if (-not $out.Contains($ip.ToString())) { $out.Add($ip.ToString()) }
        }
    }
    return , $out.ToArray()
}

function Read-AgentConfig {
    $cfg = @{ port = $DefaultPort; console_origins = @(); allowed_servers = @(); share_days = 30; trusted_thumbprints = @() }
    if (Test-Path -LiteralPath $ConfigFile) {
        try {
            $json = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
            if ($json.PSObject.Properties['port'] -and $json.port) { $cfg.port = [int]$json.port }
            if ($json.PSObject.Properties['console_origins'] -and $json.console_origins) { $cfg.console_origins = @($json.console_origins) }
            if ($json.PSObject.Properties['allowed_servers'] -and $json.allowed_servers) { $cfg.allowed_servers = @($json.allowed_servers) }
            if ($json.PSObject.Properties['share_days'] -and $json.share_days) { $cfg.share_days = [int]$json.share_days }
            if ($json.PSObject.Properties['trusted_thumbprints'] -and $json.trusted_thumbprints) { $cfg.trusted_thumbprints = @($json.trusted_thumbprints) }
        }
        catch {
            Write-Warning ("Ignoring unreadable configuration {0}: {1}" -f $ConfigFile, $_.Exception.Message)
        }
    }
    return $cfg
}

function Get-EffectiveSettings {
    $cfg = Read-AgentConfig
    $origins = ConvertTo-OriginList (@($ConsoleOrigin) + @($cfg.console_origins))
    $servers = ConvertTo-ServerList (@($AllowedServer) + @($cfg.allowed_servers))
    $effectivePort = if ($Port -gt 0) { $Port } else { [int]$cfg.port }
    $days = if ($ShareDays -gt 0) { $ShareDays } else { [int]$cfg.share_days }
    $state = if ($StateDir) { $StateDir } else { Join-Path $env:LOCALAPPDATA 'Polaron\ClientEvidenceAgent' }
    $thumbs = New-Object System.Collections.Generic.List[string]
    foreach ($t in (@($TrustServerThumbprint) + @($cfg.trusted_thumbprints))) {
        if ($null -eq $t) { continue }
        foreach ($part in ([string]$t -split '[,;\s]+')) {
            $clean = ($part -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
            if ($clean.Length -eq 40 -and -not $thumbs.Contains($clean)) { $thumbs.Add($clean) }
        }
    }
    return @{ origins = $origins; servers = $servers; port = $effectivePort; share_days = $days; state = $state; thumbprints = $thumbs.ToArray() }
}

function Get-AgentHealth {
    param([int]$AgentPort, [int]$TimeoutSec = 3)
    try {
        return Invoke-RestMethod -Uri ('http://127.0.0.1:{0}/health' -f $AgentPort) -TimeoutSec $TimeoutSec -UseBasicParsing
    }
    catch {
        return $null
    }
}

function Wait-AgentHealth {
    param([int]$AgentPort, [int]$Seconds = 20)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $health = Get-AgentHealth -AgentPort $AgentPort -TimeoutSec 2
        if ($health -and $health.ok) { return $health }
        Start-Sleep -Milliseconds 700
    }
    return $null
}

function Stop-AgentProcesses {
    $self = $PID
    $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue
    foreach ($proc in @($procs)) {
        $cmd = [string]$proc.CommandLine
        if (-not $cmd -or $proc.ProcessId -eq $self) { continue }
        if ($cmd -notlike '*polaron-client-evidence-agent.ps1*') { continue }
        if ($cmd -match '\s-(Install|Uninstall|Status)\b') { continue }
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function Start-AgentHidden {
    Start-Process -FilePath $WindowsPowerShell -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $InstalledScript)
    ) | Out-Null
}

function Install-Agent {
    if (-not (Test-IsAdmin)) {
        Write-Host 'Administrator rights are needed once to reserve the port, open the firewall for the forensic server and register the logon task. Requesting elevation...'
        $proc = Start-Process -FilePath $WindowsPowerShell -Verb RunAs -ArgumentList (Get-ForwardArgList) -Wait -PassThru
        if ($proc.ExitCode -ne 0) { throw ('Installation failed (exit code {0}).' -f $proc.ExitCode) }
        # Back in the examiner's own (non-elevated) session: start the agent here so it
        # sees this user's mapped drives and USB devices.
        $settings = Get-EffectiveSettings
        if (-not (Get-AgentHealth -AgentPort $settings.port)) { Start-AgentHidden }
        $health = Wait-AgentHealth -AgentPort $settings.port
        Show-InstallResult -Health $health -AgentPort $settings.port
        return
    }

    $settings = Get-EffectiveSettings
    $origins = $settings.origins
    if ($origins.Count -eq 0) {
        $entered = Read-Host 'Polaron console address (exactly as shown in the browser, e.g. https://polaron.lab)'
        $origins = ConvertTo-OriginList @($entered)
    }
    if ($origins.Count -eq 0) { throw 'A Polaron console address is required (-ConsoleOrigin).' }
    $agentPort = $settings.port

    Stop-AgentProcesses
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
    if ($PSCommandPath -ne $InstalledScript) {
        Copy-Item -LiteralPath $PSCommandPath -Destination $InstalledScript -Force
    }
    $config = [ordered]@{
        version         = $AgentVersion
        port            = $agentPort
        console_origins = @($origins)
        allowed_servers = @($settings.servers)
        share_days      = $settings.share_days
        trusted_thumbprints = @($settings.thumbprints)
        installed_utc   = (Get-Date).ToUniversalTime().ToString('o')
    }
    Set-Content -LiteralPath $ConfigFile -Value ($config | ConvertTo-Json) -Encoding UTF8

    # URL reservation so the agent (running as the signed-in examiner) may listen on the LAN.
    $url = 'http://+:{0}/' -f $agentPort
    & netsh.exe http delete urlacl ("url={0}" -f $url) 2>&1 | Out-Null
    $netsh = & netsh.exe http add urlacl ("url={0}" -f $url) 'sddl=D:(A;;GX;;;IU)' 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("Port reservation failed: {0}. The agent will listen on localhost only and the forensic server will not reach it." -f (($netsh | Out-String).Trim()))
    }

    # Inbound firewall rule: only the forensic server (or the local subnet) may connect.
    $ruleName = $RuleNameFormat -f $agentPort
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $remote = if ($settings.servers.Count) { @($settings.servers) } else { @('LocalSubnet') }
    New-NetFirewallRule -DisplayName $ruleName -Description 'Lets the Polaron forensic server read evidence that stays on this computer (read-only, token protected).' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort $agentPort -Profile Domain, Private -RemoteAddress $remote | Out-Null

    # Logon task for every interactive user, so the agent runs in the examiner's session.
    $usersGroup = ([Security.Principal.SecurityIdentifier]'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value
    $action = New-ScheduledTaskAction -Execute $WindowsPowerShell -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $InstalledScript)
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -GroupId $usersGroup -RunLevel Limited
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $taskSettings `
        -Description 'Polaron Client Evidence Agent: read-only evidence access for the Polaron forensic server.' -Force | Out-Null

    # Start it now in the signed-in session (limited token). A non-elevated parent
    # process, if any, also starts it; the per-session mutex prevents duplicates.
    try { Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop } catch { }

    Write-Host ''
    Write-Host 'Polaron Client Evidence Agent installed.' -ForegroundColor Green
    Write-Host ('  Script:   {0}' -f $InstalledScript)
    Write-Host ('  Config:   {0}' -f $ConfigFile)
    Write-Host ('  Port:     TCP {0} (firewall: {1})' -f $agentPort, ($remote -join ', '))
    Write-Host ('  Consoles: {0}' -f ($origins -join ', '))
    if (-not $settings.servers.Count) {
        Write-Host '  Tip: add -AllowedServer <forensic server IP> to accept evidence reads from that address only.' -ForegroundColor Yellow
    }
    Show-InstallResult -Health (Wait-AgentHealth -AgentPort $agentPort -Seconds 10) -AgentPort $agentPort
    exit 0
}

function Show-InstallResult {
    param($Health, [int]$AgentPort)
    if ($Health -and $Health.ok) {
        Write-Host ('Agent is running on {0} (port {1}).' -f $Health.hostname, $AgentPort) -ForegroundColor Green
        if ($Health.PSObject.Properties['lan_bound'] -and -not $Health.lan_bound) {
            Write-Warning 'The agent is listening on localhost only; the forensic server cannot reach it. Re-run the installer.'
        }
        Write-Host 'Return to Polaron and choose "This computer" to select the evidence folder.'
    }
    else {
        Write-Warning ('The agent did not answer on port {0} yet. Sign out and back in, or start it with: {1} -File "{2}"' -f $AgentPort, $WindowsPowerShell, $InstalledScript)
    }
}

function Uninstall-Agent {
    if (-not (Test-IsAdmin)) {
        Write-Host 'Administrator rights are needed to remove the port reservation, firewall rule and logon task. Requesting elevation...'
        Start-Process -FilePath $WindowsPowerShell -Verb RunAs -ArgumentList (Get-ForwardArgList) -Wait | Out-Null
        return
    }
    $settings = Get-EffectiveSettings
    Stop-AgentProcesses
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    & netsh.exe http delete urlacl ("url=http://+:{0}/" -f $settings.port) 2>&1 | Out-Null
    Get-NetFirewallRule -DisplayName ($RuleNameFormat -f $settings.port) -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ConfigFile -Force -ErrorAction SilentlyContinue
    Write-Host 'Polaron Client Evidence Agent removed. Audit logs remain under %LOCALAPPDATA%\Polaron\ClientEvidenceAgent.' -ForegroundColor Green
    exit 0
}

function Show-AgentStatus {
    $settings = Get-EffectiveSettings
    Write-Host ('Config:   {0}' -f $(if (Test-Path -LiteralPath $ConfigFile) { $ConfigFile } else { '(not installed)' }))
    Write-Host ('Consoles: {0}' -f $(if ($settings.origins.Count) { $settings.origins -join ', ' } else { '(none)' }))
    Write-Host ('Servers:  {0}' -f $(if ($settings.servers.Count) { $settings.servers -join ', ' } else { '(any on the local subnet)' }))
    $health = Get-AgentHealth -AgentPort $settings.port
    if ($health -and $health.ok) {
        Write-Host ('Agent:    running v{0} on {1}, port {2}, LAN={3}, shares={4}' -f $health.version, $health.hostname, $health.port, $health.lan_bound, $health.share_count) -ForegroundColor Green
        Write-Host ('Addresses: {0}' -f (@($health.addresses) -join ', '))
    }
    else {
        Write-Host ('Agent:    not answering on port {0}' -f $settings.port) -ForegroundColor Yellow
    }
}

function Start-AgentLoop {
    $settings = Get-EffectiveSettings
    $mutex = New-Object System.Threading.Mutex($false, ('Local\PolaronClientEvidenceAgent_{0}' -f $settings.port))
    if (-not $mutex.WaitOne(0)) {
        Write-Host 'The Polaron Client Evidence Agent is already running in this session.'
        return
    }
    $agent = $null
    try {
        if (-not ('Polaron.ClientEvidence.Agent' -as [type])) {
            Add-Type -TypeDefinition $AgentSource -Language CSharp -ReferencedAssemblies @('System.Web.Extensions', 'System.Core', 'System.Security')
        }
        $agent = New-Object Polaron.ClientEvidence.Agent
        $agent.Port = $settings.port
        $agent.StateDir = $settings.state
        $agent.ShareDays = $settings.share_days
        foreach ($origin in $settings.origins) { $agent.AddAllowedOrigin($origin) }
        foreach ($server in $settings.servers) { $agent.AddAllowedServer($server) }
        foreach ($thumb in $settings.thumbprints) { $agent.AddTrustedThumbprint($thumb) }
        $agent.Start()
        Write-Host ('Polaron Client Evidence Agent {0} listening on {1}' -f $AgentVersion, $agent.ListenPrefix)
        Write-Host ('State and audit log: {0}' -f $settings.state)
        if (-not $settings.origins.Count) {
            Write-Warning 'No Polaron console address is configured, so no browser can use this agent. Run with -Install -ConsoleOrigin <address>.'
        }
        if (-not $agent.LanBound) {
            Write-Warning 'Listening on localhost only (no port reservation). Direct LAN access is off; evidence is served through the outbound connection to the Polaron server instead.'
        }
        while ($agent.IsRunning) { Start-Sleep -Milliseconds 500 }
    }
    finally {
        if ($agent) { $agent.Stop() }
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}

if ($Install) { Install-Agent; return }
if ($Uninstall) { Uninstall-Agent; return }
if ($Status) { Show-AgentStatus; return }
Start-AgentLoop
