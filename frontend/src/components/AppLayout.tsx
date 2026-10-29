import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import clsx from "clsx";
import {
  Brain,
  Bug,
  Building2,
  ChevronDown,
  Database,
  ListChecks,
  ScanSearch,
  FileText,
  FolderSearch,
  HardDrive,
  ImageIcon,
  KeyRound,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  Palette,
  Radar,
  ScrollText,
  Search,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  UserCircle,
  Users,
  X,
} from "lucide-react";
import { Brand } from "./Brand";
import { useAuth } from "../lib/auth";
import { tokenStore } from "../lib/api";
import { isVulnModuleEnabled } from "../lib/vulnFlags";
import { isMalwareModuleEnabled } from "../lib/malwareFlags";
import { isDedicatedMobileService, isForensicService, isLegacyMobileExtractService, isUnifiedService, mobilePlatformService, serviceProductTitle } from "../lib/serviceMode";
import { useTheme } from "../lib/theme";

interface NavItem {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  requiredPerm?: string;
  requiredAnyPerm?: string[];
  firmOnly?: boolean;
  platformOnly?: boolean;
  exact?: boolean;
  work?: "acquire" | "images" | "jobs" | "artifacts" | "rag" | "reports" | "malware";
  /** Renders the item as an expandable submenu. */
  children?: NavItem[];
  /** Exact highlight rule when a prefix match would light up siblings. */
  match?: RegExp;
}
interface NavGroup {
  title: string;
  items: NavItem[];
}

/** Malware Detection: its own sidebar section (mobile-malware service), after the mobile forensics section. */
const MALWARE_GROUPS: NavGroup[] = isMalwareModuleEnabled() && (isUnifiedService() || isDedicatedMobileService())
  ? [
      {
        title: "Malware Detection",
        items: [
          { to: "/mobile/malware", label: "Malware Overview", icon: Bug, requiredPerm: "malware:read", firmOnly: true, exact: true },
          { to: "/mobile/malware/scans/new", label: "New scan", icon: ScanSearch, requiredPerm: "malware:scan", firmOnly: true, exact: true },
          { to: "/mobile/malware/live", label: "Scan a connected phone", icon: Smartphone, requiredPerm: "malware:scan", firmOnly: true },
          { to: "/mobile/malware/whatsapp", label: "Mobile key (WhatsApp)", icon: KeyRound, requiredPerm: "malware:scan", firmOnly: true },
          {
            to: "/mobile/malware/scans",
            label: "Scans and results",
            icon: ListChecks,
            requiredPerm: "malware:read",
            firmOnly: true,
            match: /^\/mobile\/malware\/scans(?:\/(?!new(?:\/|$))[^/]+)?\/?$/,
          },
          { to: "/mobile/malware/intel", label: "Threat intelligence", icon: Database, requiredPerm: "malware:read", firmOnly: true },
          { to: "/mobile/malware/models", label: "Models and training", icon: Brain, requiredPerm: "malware:read", firmOnly: true },
        ],
      },
    ]
  : [];

const GROUPS: NavGroup[] = [
  {
    title: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard },
      {
        to: "/logs",
        label: "Logs",
        icon: ScrollText,
        firmOnly: true,
        requiredAnyPerm: ["job:read", "scan:read", "vuln:read"],
      },
    ],
  },
  {
    title: "Identity",
    items: [{ to: "/users", label: "Users", icon: Users, requiredPerm: "user:read", firmOnly: true }],
  },
  {
    title: "Access Control",
    items: [
      { to: "/roles", label: "Roles", icon: ShieldCheck, requiredPerm: "role:read", firmOnly: true },
      { to: "/permissions", label: "Permissions", icon: KeyRound, requiredPerm: "permission:read", firmOnly: true },
    ],
  },
  { title: "Organization", items: [{ to: "/tenants", label: "Firms", icon: Building2, requiredPerm: "tenant:manage", platformOnly: true }] },
  ...(isForensicService()
    ? ([
        {
          title: isUnifiedService() ? "Disk Forensics" : "Forensic",
          items: [
            { to: "/forensic/jobs", label: "Disk Jobs", icon: HardDrive, requiredPerm: "job:read", firmOnly: true },
            { to: "/forensic/image-evidence", label: "Image evidence", icon: ImageIcon, requiredPerm: "job:run", firmOnly: true },
            { to: "/forensic/artifacts", label: "Artifacts", icon: FolderSearch, requiredPerm: "artifact:read", firmOnly: true },
            { to: "/forensic/reports", label: "Report list", icon: FileText, requiredPerm: "job:read", firmOnly: true },
            { to: "/forensic/evidence-search", label: "Search evidence", icon: Search, requiredPerm: "job:read", firmOnly: true },
          ],
        },
      ] as NavGroup[])
    : []),
  ...(isUnifiedService()
    ? ([
        {
          title: "Mobile Forensics",
          items: [
            { to: "/mobile", label: "Mobile Overview", icon: Smartphone, requiredPerm: "job:read", firmOnly: true, exact: true },
            { to: "/mobile/acquisition", label: "Device → Image", icon: Smartphone, requiredPerm: "job:run", firmOnly: true, work: "acquire" },
            { to: "/mobile/images", label: "Images → RAG", icon: ImageIcon, requiredPerm: "job:run", firmOnly: true, work: "images" },
            { to: "/mobile/jobs", label: "Mobile Jobs", icon: HardDrive, requiredPerm: "job:read", firmOnly: true, work: "jobs" },
            { to: "/mobile/artifacts", label: "Mobile Artifacts", icon: FolderSearch, requiredPerm: "artifact:read", firmOnly: true, work: "artifacts" },
            { to: "/mobile/rag", label: "Mobile RAG", icon: Search, requiredPerm: "job:read", firmOnly: true, work: "rag" },
            { to: "/mobile/reports", label: "Mobile Reports", icon: FileText, requiredPerm: "job:read", firmOnly: true, work: "reports" },
          ],
        },
      ] as NavGroup[])
    : []),
  ...(isDedicatedMobileService()
    ? ([
        {
          title: mobilePlatformService() === "ios" ? "iOS Forensics" : "Android Forensics",
          items: [
            { to: "/mobile", label: "Mobile Jobs", icon: Smartphone, requiredPerm: "job:read", firmOnly: true, exact: true, work: "jobs" },
            { to: "/mobile/acquire", label: "Device → Image", icon: Smartphone, requiredPerm: "job:run", firmOnly: true, work: "acquire" },
            { to: "/mobile/new", label: "Images → RAG", icon: ImageIcon, requiredPerm: "job:run", firmOnly: true, work: "images" },
            { to: "/mobile/artifacts", label: "Mobile Artifacts", icon: FolderSearch, requiredPerm: "artifact:read", firmOnly: true, work: "artifacts" },
            { to: "/mobile/rag", label: "Mobile RAG", icon: Search, requiredPerm: "job:read", firmOnly: true, work: "rag" },
            { to: "/mobile/reports", label: "Mobile Reports", icon: FileText, requiredPerm: "job:read", firmOnly: true, work: "reports" },
          ],
        },
      ] as NavGroup[])
    : []),
  ...(isLegacyMobileExtractService()
    ? ([
          { title: "Mobile Extraction (Legacy)", items: [
            { to: "/forensic/mobile", label: "Extractions", icon: Smartphone, requiredPerm: "job:read", firmOnly: true },
            { to: "/forensic/mobile/new", label: "Import package", icon: Smartphone, requiredPerm: "job:run", firmOnly: true },
            { to: "/forensic/mobile/acquire", label: "Live acquire", icon: Smartphone, requiredPerm: "job:run", firmOnly: true },
          ] },
        ] as NavGroup[])
      : []),
  ...MALWARE_GROUPS,
  ...(isVulnModuleEnabled()
    ? ([
        {
          title: "Vuln Dashboards",
          items: [
            {
              to: "/vuln/dashboards",
              label: "Risk & Coverage",
              icon: ShieldAlert,
              requiredPerm: "vuln:read",
              firmOnly: true,
            },
          ],
        },
        {
          title: "Vuln Operations",
          items: [
            { to: "/vuln/ops", label: "Ops Home", icon: Radar, requiredPerm: "scan:read", firmOnly: true },
            { to: "/vuln/scanners", label: "Scanners", icon: Radar, requiredPerm: "scan:read", firmOnly: true },
            { to: "/vuln/connect", label: "Connect network", icon: Radar, requiredPerm: "scan:read", firmOnly: true },
            { to: "/vuln/agents", label: "Agents", icon: Radar, requiredPerm: "agent:read", firmOnly: true },
            { to: "/vuln/scans", label: "Scan Jobs", icon: Radar, requiredPerm: "scan:read", firmOnly: true },
            { to: "/vuln/findings", label: "Findings", icon: ShieldAlert, requiredPerm: "vuln:read", firmOnly: true },
            {
              to: "/vuln/remediation",
              label: "Remediation",
              icon: ShieldCheck,
              requiredPerm: "vuln:read",
              firmOnly: true,
            },
          ],
        },
      ] as NavGroup[])
    : []),
  {
    title: "Account",
    items: [
      { to: "/profile", label: "My Profile", icon: UserCircle },
      { to: "/security", label: "Security & MFA", icon: Lock },
    ],
  },
];

const TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/logs": "Logs",
  "/users": "Users",
  "/roles": "Roles",
  "/permissions": "Permissions",
  "/tenants": "Firms",
  "/tenants/:firmId/iam": "Firm IAM",
  "/forensic/jobs": "Forensic Jobs",
  "/forensic/jobs/new": "New Forensic Job",
  "/forensic/artifacts": "Disk Artifacts",
  "/forensic/mobile": "Mobile Extraction",
  "/forensic/mobile/new": "New Mobile Extraction",
  "/mobile": "Mobile Forensics",
  "/mobile/acquisition": "Mobile Device → Image",
  "/mobile/images": "Mobile Images → RAG",
  "/mobile/jobs": "Mobile Jobs",
  "/mobile/artifacts": "Mobile Artifacts",
  "/mobile/rag": "Mobile RAG",
  "/mobile/reports": "Mobile Reports",
  "/mobile/new": "New Mobile Job",
  "/mobile/acquire": "Live Mobile Acquisition",
  "/mobile/malware": "Malware Detection",
  "/mobile/malware/scans": "Malware Scans",
  "/mobile/malware/scans/new": "New Malware Scan",
  "/mobile/malware/intel": "Threat Intelligence",
  "/mobile/malware/whatsapp": "Mobile Key (WhatsApp)",
  "/mobile/malware/models": "Models and Training",
  "/forensic/reports": "Report list",
  "/forensic/evidence-search": "Search evidence",
  "/vuln/dashboards": "Vulnerability Dashboards",
  "/vuln/ops": "Vulnerability Operations",
  "/vuln/scanners": "Scanners",
  "/vuln/connect": "Connect client network",
  "/vuln/agents": "Nessus Agents",
  "/vuln/credentials": "Scan Credentials",
  "/vuln/policies": "Scan Policies",
  "/vuln/scans": "Scan Jobs",
  "/vuln/findings": "Findings",
  "/vuln/remediation": "Remediation",
  "/vuln/exceptions": "Exceptions",
  "/vuln/timeline": "Timeline",
  "/vuln/reports": "Reports",
  "/profile": "My Profile",
  "/security": "Security & MFA",
  "/settings/appearance": "Appearance",
};

function resolveTitle(pathname: string): string {
  if (pathname === "/forensic/artifacts") return "Disk Artifacts";
  if (pathname === "/forensic/reports") return "Report list";
  if (pathname === "/forensic/evidence-search") return "Search evidence";
  if (pathname === "/forensic/mobile") return "Mobile Extraction";
  if (pathname === "/forensic/mobile/new") return "New Mobile Extraction";
  if (pathname === "/mobile/malware") return "Malware Detection";
  if (pathname === "/mobile/malware/scans/new") return "New Malware Scan";
  if (pathname === "/mobile/malware/scans") return "Malware Scans";
  if (pathname === "/mobile/malware/intel") return "Threat Intelligence";
  if (pathname === "/mobile/malware/whatsapp") return "Mobile Key (WhatsApp)";
  if (pathname === "/mobile/malware/models") return "Models and Training";
  if (pathname.startsWith("/mobile/malware/scans/")) return "Malware Scan";
  if (pathname === "/mobile") return isUnifiedService() ? "Mobile Forensics" : "Mobile Jobs";
  if (pathname === "/mobile/acquisition") return "Mobile Device → Image";
  if (pathname === "/mobile/images") return "Mobile Images → RAG";
  if (pathname === "/mobile/jobs") return "Mobile Jobs";
  if (pathname === "/mobile/artifacts") return "Mobile Artifacts";
  if (pathname === "/mobile/rag") return "Mobile RAG";
  if (pathname === "/mobile/reports") return "Mobile Reports";
  if (pathname === "/mobile/new") return "New Mobile Job";
  if (pathname === "/mobile/acquire") return "Live Mobile Acquisition";
  if (pathname.match(/^\/mobile\/(?:android|ios)\/jobs\/[^/]+\/artifacts$/)) return "Mobile Artifacts";
  if (pathname.match(/^\/mobile\/(?:android|ios)\/jobs\/[^/]+\/intake$/)) return "Mobile Intake";
  if (pathname.match(/^\/mobile\/(?:android|ios)\/jobs\/[^/]+\/report$/)) return "Mobile Report";
  if (pathname.match(/^\/mobile\/(?:android|ios)\/jobs\/[^/]+$/)) return "Mobile Job";
  if (pathname.match(/^\/mobile\/(?:android|ios)\/new$/)) return "New Mobile Job";
  if (pathname.match(/^\/mobile\/(?:android|ios)\/acquire$/)) return "Live Mobile Acquisition";
  if (pathname.match(/^\/mobile\/(?:android|ios)$/)) return pathname.includes("/ios") ? "iOS Mobile Jobs" : "Android Mobile Jobs";
  if (pathname.match(/^\/mobile\/jobs\/[^/]+\/artifacts$/)) return "Mobile Artifacts";
  if (pathname.match(/^\/mobile\/jobs\/[^/]+\/intake$/)) return "Mobile Intake";
  if (pathname.match(/^\/mobile\/jobs\/[^/]+\/report$/)) return "Mobile Report";
  if (pathname.startsWith("/mobile/jobs/")) return "Mobile Job";
  if (pathname.match(/^\/forensic\/jobs\/[^/]+\/artifacts$/)) return "Disk Artifacts";
  if (pathname.match(/^\/forensic\/jobs\/[^/]+\/intake$/)) return "Case Intake";
  if (pathname.match(/^\/forensic\/jobs\/[^/]+\/report$/)) return "Forensic Report";
  if (pathname.startsWith("/forensic/jobs/") && pathname !== "/forensic/jobs/new") {
    return "Job Detail";
  }
  if (pathname.match(/^\/tenants\/[^/]+\/iam$/)) {
    return "Firm IAM";
  }
  if (pathname.startsWith("/vuln/assets/")) {
    return "Asset 360";
  }
  return TITLES[pathname] || "Console";
}

function SettingsNav({
  open,
  onToggle,
  onNavigate,
}: {
  open: boolean;
  onToggle: () => void;
  onNavigate?: () => void;
}) {
  const { theme, setTheme, themes } = useTheme();

  return (
    <div>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="mb-1 flex w-full items-center rounded-xl px-2 py-2 text-left text-[11px] font-bold uppercase tracking-wider text-ink-400 hover:bg-brand-50/70 hover:text-ink-700"
      >
        <span className="text-[11px] font-bold uppercase tracking-wider">Settings</span>
        <ChevronDown className={clsx("ml-auto h-4 w-4 transition", open && "rotate-180")} />
      </button>
      {open ? (
        <div className="mt-1 space-y-1 border-l border-ink-200 ml-5 pl-2">
          <NavLink
            to="/settings/appearance"
            onClick={onNavigate}
            className={({ isActive }) =>
              clsx(
                "flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition",
                isActive
                  ? "bg-brand-50 text-brand-900"
                  : "text-ink-500 hover:bg-accent-50/70 hover:text-ink-800"
              )
            }
          >
            <Palette className="h-4 w-4 text-brand-600" />
            Appearance
          </NavLink>
          <p className="px-3 pt-1 text-[10px] font-semibold uppercase tracking-wide text-ink-400">Theme</p>
          {themes.map((item) => {
            const selected = theme === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  setTheme(item.id);
                  onNavigate?.();
                }}
                className={clsx(
                  "flex w-full items-center gap-2 rounded-xl px-3 py-1.5 text-left text-xs font-medium transition",
                  selected
                    ? "bg-white text-ink-900 shadow-panel ring-1 ring-brand-200"
                    : "text-ink-500 hover:bg-brand-50/70 hover:text-ink-800"
                )}
              >
                <span
                  className="h-2.5 w-2.5 shrink-0 rounded-full ring-1 ring-black/10"
                  style={{ background: item.preview.brand }}
                />
                <span className="truncate">{item.name}</span>
                {item.isDefault ? <span className="ml-auto text-[10px] text-ink-400">default</span> : null}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function NavItems({
  items,
  pathname,
  onNavigate,
}: {
  items: NavItem[];
  pathname: string;
  onNavigate?: () => void;
}) {
  return (
    <div className="space-y-0.5">
      {items.map((item) => item.children ? (
        <NavSubmenu key={`submenu:${item.to}`} item={item} pathname={pathname} onNavigate={onNavigate} />
      ) : (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.exact || item.to === "/"}
          onClick={onNavigate}
          className={({ isActive }) => {
            const active = item.match ? itemMatchesPath(pathname, item) : isActive || itemMatchesPath(pathname, item);
            return clsx(
              "flex min-w-0 items-center gap-2 rounded-lg px-2 py-2 text-[13px] font-medium transition",
              active
                ? "bg-brand-50 text-brand-900 shadow-panel ring-1 ring-brand-200"
                : "text-ink-500 hover:bg-accent-50/70 hover:text-ink-800"
            );
          }}
        >
          {({ isActive }) => {
            const active = item.match ? itemMatchesPath(pathname, item) : isActive || itemMatchesPath(pathname, item);
            return (
              <>
                <item.icon
                  className={clsx("h-4 w-4 shrink-0", active ? "text-brand-600" : "text-ink-400")}
                />
                <span className="truncate">{item.label}</span>
              </>
            );
          }}
        </NavLink>
      ))}
    </div>
  );
}

function NavSubmenu({ item, pathname, onNavigate }: { item: NavItem; pathname: string; onNavigate?: () => void }) {
  const childActive = itemMatchesPath(pathname, item);
  const [open, setOpen] = useState(childActive);
  useEffect(() => {
    if (childActive) setOpen(true);
  }, [childActive]);
  const panelId = `submenu-${item.to.replace(/[^a-z0-9]+/gi, "-")}`;
  return (
    <div>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
        className={clsx(
          "flex w-full min-w-0 items-center gap-2 rounded-lg px-2 py-2 text-left text-[13px] font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-300",
          childActive ? "text-brand-900" : "text-ink-500 hover:bg-accent-50/70 hover:text-ink-800"
        )}
      >
        <item.icon className={clsx("h-4 w-4 shrink-0", childActive ? "text-brand-600" : "text-ink-400")} />
        <span className="truncate">{item.label}</span>
        <ChevronDown className={clsx("ml-auto h-3.5 w-3.5 shrink-0 text-ink-400 transition-transform", open && "rotate-180")} aria-hidden />
      </button>
      {open ? (
        <div id={panelId} className="ml-[15px] mt-0.5 border-l border-ink-200 pl-2">
          <NavItems items={item.children ?? []} pathname={pathname} onNavigate={onNavigate} />
        </div>
      ) : null}
    </div>
  );
}

function mobileWorkSection(pathname: string): NavItem["work"] | null {
  const match = pathname.match(/^\/mobile(?:\/(android|ios))?(\/.*)?$/);
  if (!match) return null;
  const platform = match[1];
  const rest = match[2] || "";
  // Before /report and /jobs: a malware page must never light up Mobile Reports or Jobs.
  if (rest === "/malware" || rest.startsWith("/malware/")) return "malware";
  if (rest.includes("/artifacts")) return "artifacts";
  if (rest.includes("/report")) return "reports";
  if (rest === "/rag" || rest.startsWith("/rag/")) return "rag";
  if (
    rest === "/acquire" ||
    rest.startsWith("/acquire/") ||
    rest === "/acquisition" ||
    rest.startsWith("/acquisition/")
  ) {
    return "acquire";
  }
  if (rest === "/new" || rest.startsWith("/new/") || rest === "/images" || rest.startsWith("/images/")) {
    return "images";
  }
  if (rest.startsWith("/jobs") || platform) return "jobs";
  return null;
}

function itemMatchesPath(pathname: string, item: NavItem): boolean {
  if (item.children) return item.children.some((child) => itemMatchesPath(pathname, child));
  if (item.match) return item.match.test(pathname);
  if (item.work) return item.work === mobileWorkSection(pathname);
  if (item.exact || item.to === "/") return pathname === item.to;
  return pathname === item.to || pathname.startsWith(`${item.to}/`);
}

function groupMatchesPath(pathname: string, group: NavGroup): boolean {
  return group.items.some((item) => itemMatchesPath(pathname, item));
}

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const location = useLocation();
  const { hasPermission, isPlatformScope } = useAuth();
  const visible = (item: NavItem): boolean => {
    if (item.firmOnly && isPlatformScope) return false;
    if (item.platformOnly && !isPlatformScope) return false;
    if (item.requiredAnyPerm && item.requiredAnyPerm.length > 0) {
      return item.requiredAnyPerm.some((perm) => hasPermission(perm));
    }
    return !item.requiredPerm || hasPermission(item.requiredPerm);
  };
  const filterItems = (items: NavItem[]): NavItem[] =>
    items
      .filter(visible)
      .map((item) => (item.children ? { ...item, children: filterItems(item.children) } : item))
      .filter((item) => !item.children || item.children.length > 0);
  const groups = GROUPS.map((group) => ({
    ...group,
    items: filterItems(group.items),
  })).filter((group) => group.items.length > 0);
  const navGroups = groups.filter((group) => group.title !== "Account");
  const accountGroups = groups.filter((group) => group.title === "Account");
  const routeTitle = location.pathname.startsWith("/settings")
    ? "Settings"
    : [...navGroups, ...accountGroups].find(
        (group) => group.title !== "Overview" && groupMatchesPath(location.pathname, group)
      )?.title ?? null;
  const [extraTitle, setExtraTitle] = useState<string | null>(null);
  const [pathSnap, setPathSnap] = useState(location.pathname);
  if (pathSnap !== location.pathname) {
    setPathSnap(location.pathname);
    setExtraTitle(null);
  }
  const toggleGroup = (title: string) => {
    if (title === routeTitle) return;
    setExtraTitle((current) => (current === title ? null : title));
  };
  const groupIsOpen = (title: string) => title === routeTitle || title === extraTitle;

  return (
    <div className="flex h-full flex-col">
      <div className="px-3 pb-2 pt-3">
        <Brand />
      </div>
      <div className="px-3">
        <div className="rounded-lg border border-brand-200/80 bg-brand-50/70 px-2 py-1.5 text-center text-[10px] font-semibold uppercase tracking-wider text-brand-800 shadow-panel">
          Enterprise Console
        </div>
      </div>
      <nav className="relative z-[1] mt-3 flex-1 space-y-2 overflow-y-auto px-2 pb-4">
        {navGroups.map((group) => {
          const pinned = group.title === "Overview";
          const open = pinned || groupIsOpen(group.title);
          return (
            <div key={group.title}>
              {pinned ? (
                <p className="px-2 pb-1 text-[10px] font-bold uppercase tracking-wider text-ink-400">
                  {group.title}
                </p>
              ) : (
                <button
                  type="button"
                  onClick={() => toggleGroup(group.title)}
                  className="mb-0.5 flex w-full min-w-0 items-center rounded-lg px-2 py-1.5 text-left text-[10px] font-bold uppercase tracking-wider text-ink-400 hover:bg-brand-50/70 hover:text-ink-700"
                  aria-expanded={open}
                >
                  <span className="truncate">{group.title}</span>
                  <ChevronDown className={clsx("ml-auto h-3.5 w-3.5 shrink-0 transition", open && "rotate-180")} />
                </button>
              )}
              {open ? <NavItems items={group.items} pathname={location.pathname} onNavigate={onNavigate} /> : null}
            </div>
          );
        })}
        <SettingsNav
          open={groupIsOpen("Settings")}
          onToggle={() => toggleGroup("Settings")}
          onNavigate={onNavigate}
        />
        {accountGroups.map((group) => {
          const open = groupIsOpen(group.title);
          return (
            <div key={group.title}>
              <button
                type="button"
                onClick={() => toggleGroup(group.title)}
                className="mb-0.5 flex w-full min-w-0 items-center rounded-lg px-2 py-1.5 text-left text-[10px] font-bold uppercase tracking-wider text-ink-400 hover:bg-brand-50/70 hover:text-ink-700"
                aria-expanded={open}
              >
                <span className="truncate">{group.title}</span>
                <ChevronDown className={clsx("ml-auto h-3.5 w-3.5 shrink-0 transition", open && "rotate-180")} />
              </button>
              {open ? <NavItems items={group.items} pathname={location.pathname} onNavigate={onNavigate} /> : null}
            </div>
          );
        })}
      </nav>
    </div>
  );
}

export function AppLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const title = resolveTitle(location.pathname);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  return (
    <div className="min-h-screen bg-transparent">
      <aside className="fixed inset-y-0 left-0 z-[280] hidden w-[272px] border-r border-ink-300 bg-white/95 shadow-panel backdrop-blur-sm lg:block">
        <SidebarContent />
      </aside>

      {mobileOpen ? (
        <div className="fixed inset-0 z-[280] lg:hidden">
          <div className="absolute inset-0 bg-ink-950/40" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-[272px] border-r border-ink-300 bg-white shadow-soft">
            <button
              className="absolute right-3 top-5 rounded-xl p-1 text-ink-400 hover:bg-brand-50"
              onClick={() => setMobileOpen(false)}
              type="button"
            >
              <X className="h-5 w-5" />
            </button>
            <SidebarContent onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      ) : null}

      <div className="lg:pl-[272px]">
        <header className="sticky top-0 z-30 border-b border-ink-300 bg-white/75 shadow-panel backdrop-blur-md">
          <div className="flex h-16 items-center justify-between px-4 sm:px-8">
            <div className="flex items-center gap-3">
              <button
                className="rounded-xl p-2 text-ink-500 hover:bg-brand-50 lg:hidden"
                onClick={() => setMobileOpen(true)}
                type="button"
              >
                <Menu className="h-5 w-5" />
              </button>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wider text-brand-600">
                  {serviceProductTitle()}
                </p>
                <h2 className="text-base font-bold text-ink-900">{title}</h2>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="hidden items-center gap-1.5 rounded-full border border-accent-200 bg-accent-50/90 px-3 py-1 text-xs font-semibold text-accent-800 shadow-panel sm:inline-flex">
                <span className="h-1.5 w-1.5 rounded-full bg-accent-600" />
                Online
              </span>
              <div className="hidden text-right sm:block">
                <p className="text-sm font-semibold text-ink-800">{user?.email}</p>
                <p className="text-xs text-ink-400">Tenant: {tokenStore.tenant()}</p>
              </div>
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-ink-900 text-sm font-bold text-white shadow-panel">
                {(user?.email || "?").slice(0, 1).toUpperCase()}
              </div>
              <button
                onClick={logout}
                className="inline-flex items-center gap-1.5 rounded-xl border border-ink-300 bg-white/80 px-3 py-2 text-sm font-semibold text-ink-600 shadow-panel hover:border-brand-400 hover:bg-brand-50/70"
                type="button"
              >
                <LogOut className="h-4 w-4" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          </div>
        </header>

        <main className="container-fluid mx-auto max-w-7xl px-4 py-6 sm:px-8 sm:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
