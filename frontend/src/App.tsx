import {
  ArrowClockwise,
  ArrowRight,
  CaretRight,
  Check,
  CheckCircle,
  ClipboardText,
  ClockCounterClockwise,
  CircleNotch,
  Copy,
  Database,
  Eye,
  FileText,
  Fingerprint,
  Flask,
  GlobeHemisphereWest,
  HardDrives,
  Info,
  Key,
  ListChecks,
  LockKey,
  MagnifyingGlass,
  Pulse,
  ShieldCheck,
  ShieldWarning,
  SignIn,
  SignOut,
  SlidersHorizontal,
  ThumbsDown,
  ThumbsUp,
  Trash,
  UserCircle,
  UsersThree,
  WarningCircle,
  XCircle,
  type Icon,
} from "@phosphor-icons/react";
import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  Link,
  Navigate,
  NavLink,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom";
import {
  ApiError,
  api,
  type AdminHealth,
  type AdminUser,
  type AssignableRole,
  type AuditEvent,
  type DatasetSnapshot,
  type DecisionPolicy,
  type Experiment,
  type FeedbackReceipt,
  type ModelRelease,
  type PrivilegedRequestedRole,
  type ProviderConfiguration,
  type ResearchExport,
  type ReviewAction,
  type ReviewCase,
  type ReviewCaseDetail,
  type RoleRequest,
  type RequestedRole,
  type EvidenceObservation,
  type RiskBand,
  type Scan,
} from "./api";
import {
  beginPasswordSignIn,
  beginSessionReauthentication,
  beginTotpEnrollment,
  completeSessionReauthentication,
  completeTotpEnrollment,
  completeTotpSignIn,
  createPasswordAccount,
  identityConfigured,
  IdentityError,
  requestPasswordReset,
} from "./identity";
import { SessionProvider, useSession } from "./session";

const publicNavigation: { to: string; label: string; icon: Icon; session?: "GUEST_OR_USER" | "USER" }[] = [
  { to: "/", label: "Scan", icon: MagnifyingGlass },
  { to: "/how-it-works", label: "How it works", icon: ListChecks },
  { to: "/history", label: "History", icon: ClockCounterClockwise, session: "GUEST_OR_USER" },
  { to: "/privacy", label: "Privacy", icon: LockKey },
  { to: "/account", label: "Account", icon: UserCircle, session: "USER" },
];

const workspaceNavigation = [
  { to: "/analyst/cases", label: "Cases", icon: ListChecks, roles: ["ANALYST", "ADMINISTRATOR"] },
  { to: "/admin", label: "Administration", icon: SlidersHorizontal, roles: ["ADMINISTRATOR"] },
  { to: "/research", label: "Research", icon: Flask, roles: ["RESEARCHER", "ADMINISTRATOR"] },
];

const registeredRoles = ["REGISTERED_USER", "ANALYST", "ADMINISTRATOR", "RESEARCHER"];
const analystRoles = ["ANALYST", "ADMINISTRATOR"];
const administratorRoles = ["ADMINISTRATOR"];
const researcherRoles = ["RESEARCHER", "ADMINISTRATOR"];

function Brand() {
  return (
    <Link className="brand" to="/" aria-label="PhishGuard home">
      <img className="brand-mark" src="/phishguard-mark.svg" alt="" />
      <span>PhishGuard</span>
    </Link>
  );
}

function roleLabel(role: string) {
  return role.toLowerCase().replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

const REGISTRATION_INTENT_KEY = "phishguard.registration.intent";

function registrationIntent(email: string): RequestedRole | undefined {
  try {
    const value = JSON.parse(sessionStorage.getItem(REGISTRATION_INTENT_KEY) ?? "null") as { email?: string; role?: RequestedRole } | null;
    return value?.email?.trim().toLowerCase() === email.trim().toLowerCase() ? value.role : undefined;
  } catch {
    return undefined;
  }
}

function defaultRoute(role: string) {
  if (role === "ADMINISTRATOR") return "/admin";
  if (role === "ANALYST") return "/analyst/cases";
  if (role === "RESEARCHER") return "/research";
  return "/history";
}

function safeInternalFrom(value: string | null) {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes("\\") || value.startsWith("/sign-in")) return undefined;
  return value;
}

function Shell({ children }: { children: ReactNode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const session = useSession();
  const previousPath = useRef(location.pathname);
  const [signingOut, setSigningOut] = useState(false);
  const [signOutWarning, setSignOutWarning] = useState("");
  const workspace = /^\/(analyst|admin|research)/.test(location.pathname);
  const authenticated = session.status === "ready" && session.me?.session_kind === "USER" && Boolean(session.me.role);
  const hasGuestHistory = session.status === "ready" && ["GUEST", "USER"].includes(session.me?.session_kind ?? "ANONYMOUS");
  const navigation = workspace
    ? workspaceNavigation.filter((item) => session.me?.role && item.roles.includes(session.me.role))
    : publicNavigation.filter((item) => !item.session || (item.session === "USER" ? authenticated : hasGuestHistory));
  const workspaceRoute = authenticated && session.me?.role !== "REGISTERED_USER" ? defaultRoute(session.me?.role ?? "") : undefined;

  useEffect(() => {
    if (previousPath.current !== location.pathname) {
      document.getElementById("main-content")?.focus({ preventScroll: true });
      window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    }
    previousPath.current = location.pathname;
  }, [location.pathname]);

  async function signOut() {
    setSigningOut(true);
    setSignOutWarning("");
    try {
      await session.signOut();
    } catch {
      setSignOutWarning("You were signed out locally, but remote session revocation could not be confirmed.");
    } finally {
      setSigningOut(false);
      navigate("/sign-in", { replace: true });
    }
  }

  return (
    <div className="app">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="topbar">
        <Brand />
        <div className="topbar-actions">
          {workspace && <span className="environment"><Info aria-hidden weight="fill" /> Experimental workspace</span>}
          {authenticated ? (
            <><Link className="user-chip" to="/account"><UserCircle aria-hidden /><span className="user-copy"><strong>Account</strong><small>{roleLabel(session.me?.role ?? "")}{session.me?.is_canonical_admin ? " · Canonical administrator" : ""}</small></span></Link>{!workspace && workspaceRoute && <Link className="button button-secondary button-small" to={workspaceRoute}>Open workspace</Link>}{!workspace && <button className="button button-secondary button-small" type="button" disabled={signingOut} onClick={signOut}><SignOut aria-hidden />{signingOut ? "Signing out…" : "Sign out"}</button>}</>
          ) : session.status === "loading" ? (
            <span className="session-status" role="status"><CircleNotch className="spinner" aria-hidden />Checking session</span>
          ) : location.pathname === "/sign-in" ? (
            <Link className="button button-secondary button-small" to="/"><GlobeHemisphereWest aria-hidden /> Scanner</Link>
          ) : (
            <Link className="button button-secondary button-small" to="/sign-in"><SignIn aria-hidden /> Sign in</Link>
          )}
        </div>
      </header>
      {signOutWarning && <div className="session-warning alert alert-warning" role="status"><WarningCircle aria-hidden /><span>{signOutWarning}</span><button type="button" className="text-button" onClick={() => setSignOutWarning("")}>Dismiss</button></div>}
      <div className="shell-body">
        <aside className="sidebar" aria-label={workspace ? "Workspace navigation" : "Primary navigation"}>
          <p className="nav-label">{workspace ? "Workspace" : "PhishGuard"}</p>
          <nav>
            {navigation.map(({ to, label, icon: NavIcon }) => (
              <NavLink key={to} to={to} end={to === "/" || to === "/admin"} className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                <NavIcon aria-hidden /> <span>{label}</span>
              </NavLink>
            ))}
          </nav>
          {workspace ? (
            <div className="sidebar-footer">
              <Link to="/" className="nav-item"><GlobeHemisphereWest aria-hidden /><span>Public scanner</span></Link>
              {authenticated && <button type="button" className="nav-item nav-button" disabled={signingOut} onClick={signOut}><SignOut aria-hidden /><span>{signingOut ? "Signing out…" : "Sign out"}</span></button>}
            </div>
          ) : (
            <div className="privacy-note"><LockKey aria-hidden /><span><strong>Private by default</strong>Local-only scans do not contact the destination.</span></div>
          )}
        </aside>
        <main id="main-content" className="main-content" tabIndex={-1}>{children}</main>
      </div>
    </div>
  );
}

function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description?: string; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

function StatePanel({ kind, title, detail, retry, signInTo = "/sign-in" }: { kind: "loading" | "error" | "empty" | "auth" | "forbidden"; title: string; detail: string; retry?: () => void; signInTo?: string }) {
  const StateIcon = kind === "loading" ? CircleNotch : kind === "error" ? WarningCircle : kind === "auth" || kind === "forbidden" ? LockKey : Database;
  return <div className={`empty-state card state-panel state-${kind}`} role={kind === "error" ? "alert" : kind === "loading" ? "status" : undefined} aria-busy={kind === "loading" || undefined}><StateIcon className={kind === "loading" ? "spinner" : undefined} aria-hidden /><h1>{title}</h1><p>{detail}</p>{kind === "auth" && <Link className="button button-primary" to={signInTo}>Sign in</Link>}{retry && <button className="button button-secondary" type="button" onClick={retry}><ArrowClockwise aria-hidden />Try again</button>}</div>;
}

function ProtectedRoute({ roles, children }: { roles: string[]; children: ReactNode }) {
  const session = useSession();
  const location = useLocation();
  if (session.status === "loading") return <div className="page narrow-page"><StatePanel kind="loading" title="Checking access" detail="Verifying your current application session." /></div>;
  if (session.status === "error") return <div className="page narrow-page"><StatePanel kind="error" title="Access check unavailable" detail={session.error} retry={() => { session.refresh().catch(() => undefined); }} /></div>;
  if (session.me?.session_kind !== "USER" || !session.me.role) return <div className="page narrow-page"><StatePanel kind="auth" title="Sign in required" detail="Sign in with an authorised PhishGuard account to continue." signInTo={`/sign-in?from=${encodeURIComponent(location.pathname + location.search)}`} /></div>;
  if (!roles.includes(session.me.role)) return <div className="page narrow-page"><StatePanel kind="forbidden" title="Access restricted" detail={`Your ${roleLabel(session.me.role)} role does not have access to this workspace.`} /></div>;
  return <>{children}</>;
}

export function verdictPresentation(risk: RiskBand, status: Scan["status"] = "COMPLETE") {
  const presentations: Record<RiskBand, { label: string; title: string; summary: string; icon: Icon }> = {
    LOW: { label: "Low risk", title: "No strong phishing indicators found.", summary: "The available evidence did not reveal strong phishing indicators.", icon: CheckCircle },
    MEDIUM: { label: "Medium risk", title: "Use caution with this link.", summary: "The available evidence contains indicators that warrant caution.", icon: WarningCircle },
    HIGH: { label: "High risk", title: "Avoid this link.", summary: "The available evidence contains strong phishing indicators.", icon: XCircle },
    INCONCLUSIVE: { label: "Inconclusive", title: "Treat this link as unverified.", summary: "PhishGuard cannot reach a reliable risk conclusion from the available evidence.", icon: Info },
  };
  const presentation = presentations[risk];
  return status === "PROCESSING"
    ? { ...presentation, label: `Preliminary ${presentation.label.toLowerCase()}`, provisional: true }
    : { ...presentation, provisional: false };
}

function RiskBadge({ risk, status }: { risk: RiskBand; status?: Scan["status"] }) {
  const presentation = verdictPresentation(risk, status);
  const BadgeIcon = presentation.icon;
  return <span className={`badge badge-${risk.toLowerCase()}`}><BadgeIcon aria-hidden weight="fill" />{presentation.label}</span>;
}

function StatusBadge({ status }: { status: Scan["status"] }) {
  const label = status === "PROCESSING" ? "Analyzing" : status.toLowerCase().replace(/^./, (c) => c.toUpperCase());
  return <span className={`badge status-${status.toLowerCase()}`}>{status === "PROCESSING" && <CircleNotch className="spinner" aria-hidden />} {label}</span>;
}

function SimulatedDataBanner({ shared = false }: { shared?: boolean }) {
  return <div className="alert alert-warning simulated-data-banner" role="status"><WarningCircle aria-hidden /><span><strong>Simulated data — not a live assessment.</strong>{shared ? "This shared report" : "This result"} was generated locally because the development API was unavailable. Google Web Risk and the destination were not contacted.</span></div>;
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function defangUrl(value: string) {
  return value
    .replace(/^https:/i, "hxxps:")
    .replace(/^http:/i, "hxxp:")
    .replace(/\./g, "[.]");
}

export const RESULT_POLL_DEADLINE_MS = 120_000;
const RESULT_POLL_DEFAULT_MS = 1_000;
const RESULT_POLL_MIN_MS = 250;
const RESULT_POLL_MAX_MS = 10_000;

export function resultPollDelay(serverDelayMs: number | undefined, attempt: number) {
  const requested = Number.isFinite(serverDelayMs) ? Number(serverDelayMs) : RESULT_POLL_DEFAULT_MS;
  const baseline = Math.min(RESULT_POLL_MAX_MS, Math.max(RESULT_POLL_MIN_MS, requested));
  return Math.min(RESULT_POLL_MAX_MS, baseline * (2 ** Math.max(0, attempt)));
}

function ScanPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const session = useSession();
  const [url, setUrl] = useState(() => new URLSearchParams(location.search).get("url") ?? "");
  const [mode, setMode] = useState<"local_only" | "enriched">("local_only");
  const [consent, setConsent] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [recentScans, setRecentScans] = useState<Scan[]>([]);

  useEffect(() => {
    if (session.status !== "ready" || !["GUEST", "USER"].includes(session.me?.session_kind ?? "ANONYMOUS")) {
      setRecentScans([]);
      return;
    }
    api.listScans().then((items) => setRecentScans(items.slice(0, 3))).catch(() => setRecentScans([]));
  }, [session.status, session.me?.session_kind]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const parsed = new URL(url);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
      if (mode === "enriched" && !consent) {
        setError("Confirm the enrichment notice before starting an enriched scan.");
        return;
      }
    } catch {
      setError("Enter a complete HTTP or HTTPS URL, including the protocol.");
      return;
    }

    setSubmitting(true);
    try {
      const response = await api.createScan({ url, analysis_mode: mode, enrichment_consent: mode === "enriched" && consent });
      session.refresh().catch(() => undefined);
      navigate(`/scan/${response.scan.id}`, { state: { demo: response.demo } });
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "The scan could not be started. Try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page scan-page">
      <PageHeader eyebrow="Evidence-led link analysis" title="Check a link without opening it in your browser" description="PhishGuard examines the structure and available evidence behind a URL, then explains what matters." />
      <div className={`scan-layout ${recentScans.length > 0 ? "has-recent-scans" : ""}`}>
        <form className="card scan-card" onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="scan-url">URL to inspect</label>
            <div className="input-with-icon">
              <GlobeHemisphereWest aria-hidden />
              <input id="scan-url" type="url" inputMode="url" autoComplete="url" maxLength={4096} value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/account" required />
            </div>
            <p className="field-hint">Include http:// or https://. PhishGuard never provides an action that opens the destination in your browser.</p>
          </div>

          <fieldset className="mode-fieldset">
            <legend>Analysis mode</legend>
            <label className={`choice-card ${mode === "local_only" ? "selected" : ""}`}>
              <input type="radio" name="mode" value="local_only" checked={mode === "local_only"} onChange={() => { setMode("local_only"); setConsent(false); }} />
              <span className="choice-icon"><LockKey aria-hidden /></span>
              <span><strong>Local only</strong><small>Checks URL structure locally. No URL-derived network requests.</small></span>
              <span className="recommended">Recommended</span>
            </label>
            <label className={`choice-card ${mode === "enriched" ? "selected" : ""}`}>
              <input type="radio" name="mode" value="enriched" checked={mode === "enriched"} onChange={() => setMode("enriched")} />
              <span className="choice-icon"><Fingerprint aria-hidden /></span>
              <span><strong>Enriched evidence</strong><small>Adds bounded DNS, registration, TLS, redirect, reputation and static HTML checks.</small></span>
            </label>
          </fieldset>

          {mode === "enriched" && (
            <div className="notice-panel">
              <Info aria-hidden />
              <div>
                <strong>External processing notice</strong>
                <p>The destination will be contacted through an isolated fetcher, and the full URL may be sent to Google Web Risk. Query strings can contain sensitive data.</p>
                <label className="checkbox-row"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} /> I understand and consent to this one enriched scan.</label>
              </div>
            </div>
          )}

          {error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden /><span>{error}</span></div>}
          <button className="button button-primary button-large" type="submit" disabled={submitting || !url.trim()}>
            {submitting ? <><CircleNotch className="spinner" aria-hidden /> Starting analysis</> : <><MagnifyingGlass aria-hidden /> Analyze safely</>}
          </button>
          <p className="form-footnote"><ShieldCheck aria-hidden /> Automated results support—not replace—your judgement.</p>
        </form>

        <Link className="scan-guide-link card" to="/how-it-works"><span className="choice-icon"><ListChecks aria-hidden /></span><span><strong>How does PhishGuard reach a verdict?</strong><small>Review the evidence pipeline, safety boundaries, decision logic, and limitations.</small></span><CaretRight aria-hidden /></Link>
        {recentScans.length > 0 && <section className="card recent-scans" aria-labelledby="recent-scans-title"><div className="section-heading"><div><p className="eyebrow">Continue reviewing</p><h2 id="recent-scans-title">Recent scans</h2></div><Link to="/history">View all</Link></div>{recentScans.map((scan) => <Link key={scan.id} to={`/scan/${scan.id}`}><span><strong>{scan.display_url}</strong><small>{formatDate(scan.created_at)}</small></span><RiskBadge risk={scan.decision.risk_band} status={scan.status} /><CaretRight aria-hidden /></Link>)}</section>}
      </div>
    </div>
  );
}

function HowItWorksPage() {
  return (
    <div className="page how-page">
      <PageHeader
        eyebrow="Transparent analysis"
        title="Evidence first. Verdict second."
        description="PhishGuard separates local inspection, optional external collection, and decision-making so each result can show exactly what was—and was not—checked."
        actions={<><Link className="button button-primary" to="/"><MagnifyingGlass aria-hidden />Analyze a URL</Link><Link className="button button-secondary" to="/privacy"><LockKey aria-hidden />Privacy controls</Link></>}
      />
      <ol className="process-grid">
        <li className="card"><span>01</span><GlobeHemisphereWest aria-hidden /><h2>Validate locally</h2><p>The URL is parsed, normalised, redacted, and checked by deterministic rules and the approved URL-only model before any URL-derived external request.</p></li>
        <li className="card"><span>02</span><LockKey aria-hidden /><h2>Ask before enrichment</h2><p>Local-only analysis ends here. DNS, RDAP, TLS, redirects, reputation, and static HTML checks require explicit consent for that scan.</p></li>
        <li className="card"><span>03</span><ShieldCheck aria-hidden /><h2>Collect within a sandbox</h2><p>An isolated fetcher enforces public-address validation, strict redirects and timeouts, content limits, no JavaScript, and no credential or subresource loading.</p></li>
        <li className="card"><span>04</span><Fingerprint aria-hidden /><h2>Fuse independent signals</h2><p>Versioned rules, calibrated model output, and corroborated evidence contribute bounded weight. Reputation cannot determine the verdict by itself.</p></li>
        <li className="card"><span>05</span><ClipboardText aria-hidden /><h2>Explain the decision</h2><p>The result preserves provenance and presents risk reasons, counter-evidence, missing checks, limitations, safe next actions, and exact engine versions.</p></li>
        <li className="card"><span>06</span><WarningCircle aria-hidden /><h2>Keep uncertainty visible</h2><p>Unavailable evidence never becomes a safe signal. It can reduce coverage, produce a partial result, or make the verdict inconclusive.</p></li>
      </ol>
      <section className="mode-comparison">
        <article className="card"><p className="eyebrow">Default</p><h2>Local-only</h2><ul className="plain-list"><li>No destination, DNS, RDAP, or reputation request</li><li>URL structure, rules, and URL-only model</li><li>Fastest and most private analysis scope</li></ul></article>
        <article className="card"><p className="eyebrow">With per-scan consent</p><h2>Enriched</h2><ul className="plain-list"><li>Isolated destination and infrastructure checks</li><li>Google Web Risk lookup under provider policy</li><li>Missing checks stay explicit and neutral</li></ul></article>
      </section>
      <div className="alert alert-warning how-limit"><WarningCircle aria-hidden /><span><strong>What PhishGuard cannot promise.</strong>Automated evidence can be incomplete, stale, or adversarially manipulated. A low-risk result is not proof of safety, and PhishGuard never offers to open the submitted URL in your browser.</span></div>
    </div>
  );
}

function PrivacyPage() {
  const session = useSession();
  const retentionDays = session.me?.scan_retention_max_days ?? 30;
  return (
    <div className="page privacy-page">
      <PageHeader
        eyebrow="Privacy and data use"
        title="You choose when external checks happen"
        description="Every scan starts with local-only analysis inside PhishGuard. Destination, infrastructure, reputation, and bounded HTML checks happen only after explicit per-scan consent."
      />
      <section className="privacy-hero card" aria-labelledby="privacy-default-title">
        <div className="privacy-hero-icon"><LockKey aria-hidden weight="fill" /></div>
        <div>
          <h2 id="privacy-default-title">Local-only is the default</h2>
          <p>Local-only scans inspect URL structure without contacting the destination, DNS, RDAP, Google Web Risk, or externally derived caches.</p>
        </div>
      </section>
      <div className="privacy-grid">
        <article className="card privacy-card">
          <Fingerprint aria-hidden />
          <h2>Enrichment requires consent</h2>
          <p>With consent, an isolated fetcher may contact the destination and inspect bounded static HTML for forms, links, and credential fields. It does not run JavaScript, load subresources, send credentials, or retain raw page content. The full URL may also be sent to Google Web Risk.</p>
        </article>
        <article className="card privacy-card">
          <Database aria-hidden />
          <h2>Stored with restraint</h2>
          <p>Original URLs are encrypted. Interfaces and logs use redacted values, and target response bodies or raw HTML are never stored by the application.</p>
        </article>
        <article className="card privacy-card">
          <ClockCounterClockwise aria-hidden />
          <h2>Limited retention</h2>
          <p>Guest scans expire after one hour. Signed-in users can choose retention for new scans up to {retentionDays} days and delete individual or all stored scans.</p>
        </article>
        <article className="card privacy-card">
          <UsersThree aria-hidden />
          <h2>Governed use</h2>
          <p>Feedback is quarantined from training data until independently adjudicated. Shared reports are temporary, unguessable, and redact the submitted URL and account details.</p>
        </article>
      </div>
      <section className="card privacy-controls">
        <div>
          <ShieldCheck aria-hidden />
          <div><h2>Your controls</h2><p>Review saved scans, download a redacted account export, adjust retention, or remove stored scan data.</p></div>
        </div>
        <div className="page-actions">
          {session.me?.session_kind === "USER" ? <Link className="button button-primary" to="/account">Open account controls</Link> : session.me?.session_kind === "GUEST" ? <Link className="button button-primary" to="/history">Review guest history</Link> : <Link className="button button-primary" to="/sign-in">Sign in for account controls</Link>}
          <Link className="button button-secondary" to="/">Return to scanner</Link>
        </div>
      </section>
      <div className="alert alert-info privacy-caveat"><Info aria-hidden /><span><strong>Browser safety and retrieval are separate.</strong>PhishGuard never navigates your browser to the submitted URL. With your consent, enriched analysis may contact the destination through the isolated fetcher. No result is a guarantee of safety.</span></div>
    </div>
  );
}

function ResultPage({ shared = false }: { shared?: boolean }) {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState("");
  const [pollingPause, setPollingPause] = useState<{ reason: "deadline" | "error"; message: string } | null>(null);
  const [pollCycle, setPollCycle] = useState(0);
  const [copied, setCopied] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [shareError, setShareError] = useState("");
  const [shareUrl, setShareUrl] = useState("");
  const [reportExpiresAt, setReportExpiresAt] = useState("");
  const [completionAnnouncement, setCompletionAnnouncement] = useState("");
  const [pendingRescan, setPendingRescan] = useState<(() => Promise<void>) | null>(null);
  const [rescanError, setRescanError] = useState("");
  const shareDialog = useRef<HTMLDialogElement>(null);
  const loadedTarget = useRef<string | null>(null);
  const previousScanStatus = useRef<{ target: string; status: Scan["status"] } | null>(null);

  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    let attempt = 0;
    const startedAt = Date.now();
    const target = `${shared ? "report" : "scan"}:${id}`;
    if (loadedTarget.current && loadedTarget.current !== target) {
      setScan(null);
      setError("");
      setPollingPause(null);
      setCompletionAnnouncement("");
    }
    async function load() {
      try {
        let next: Scan;
        let pollAfterMs: number | undefined;
        let nextReportExpiresAt: string | undefined;
        if (shared) {
          const report = await api.getReport(id);
          next = report.scan;
          nextReportExpiresAt = report.expires_at;
        } else {
          const update = await api.getScanUpdate(id);
          next = update.scan;
          pollAfterMs = update.poll_after_ms;
        }
        if (!active) return;
        const previous = previousScanStatus.current;
        if (previous?.target === target && previous.status === "PROCESSING" && next.status !== "PROCESSING") {
          setCompletionAnnouncement(`Analysis complete. ${verdictPresentation(next.decision.risk_band, next.status).label}. ${next.decision.completion === "PARTIAL" ? "Partial evidence coverage." : "Complete evidence coverage."}`);
        }
        previousScanStatus.current = { target, status: next.status };
        loadedTarget.current = target;
        setScan(next);
        if (nextReportExpiresAt) setReportExpiresAt(nextReportExpiresAt);
        setError("");
        setPollingPause(null);
        if (next.status === "PROCESSING") {
          const elapsed = Date.now() - startedAt;
          if (elapsed >= RESULT_POLL_DEADLINE_MS) {
            setPollingPause({ reason: "deadline", message: "Enrichment has not finished within two minutes. It may still complete later." });
            return;
          }
          const delay = Math.min(resultPollDelay(pollAfterMs, attempt), RESULT_POLL_DEADLINE_MS - elapsed);
          attempt += 1;
          timer = window.setTimeout(load, delay);
        }
      } catch (reason) {
        if (!active) return;
        const message = reason instanceof ApiError && reason.status === 404
          ? "This scan does not exist or is no longer available."
          : "We could not refresh this scan.";
        if (loadedTarget.current === target) setPollingPause({ reason: "error", message });
        else setError(message);
      }
    }
    load();
    return () => { active = false; if (timer) clearTimeout(timer); };
  }, [id, shared, pollCycle]);

  function retryPolling() {
    setError("");
    setPollingPause(null);
    setPollCycle((value) => value + 1);
  }

  function downloadDecision() {
    if (!scan) return;
    const payload = {
      schema_version: "phishguard-decision-export/1",
      exported_at: new Date().toISOString(),
      scan_id: scan.id,
      redacted_url: scan.display_url,
      status: scan.status,
      decision: scan.decision,
    };
    const objectUrl = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = `phishguard-decision-${scan.id}.json`;
    link.click();
    URL.revokeObjectURL(objectUrl);
  }

  async function prepareRescan() {
    setRescanError("");
    try {
      const revealed = await api.revealOriginalUrl(id);
      navigate(`/?url=${encodeURIComponent(revealed.url)}`);
    } catch (reason) {
      if (reason instanceof ApiError && reason.code === "fresh_auth_required") {
        setPendingRescan(() => prepareRescan);
      } else {
        setRescanError(apiMessage(reason, "The original URL could not be prepared for a new scan."));
      }
    }
  }

  if (error && !scan) return <div className="page narrow-page"><div className="empty-state"><XCircle aria-hidden /><h1>Scan unavailable</h1><p role="alert">{error}</p><div className="form-actions"><button className="button button-secondary" type="button" onClick={retryPolling}><ArrowClockwise aria-hidden /> Try again</button><Link className="button button-primary" to="/">Start a new scan</Link></div></div></div>;
  if (!scan) return <ResultSkeleton />;

  const { decision } = scan;
  const presentation = verdictPresentation(decision.risk_band, scan.status);
  const RiskIcon = presentation.icon;
  const limitedCoverage = decision.completion === "PARTIAL" || scan.status === "PARTIAL";
  const openLimitations = limitedCoverage || decision.risk_band === "INCONCLUSIVE" || decision.missing_evidence.length > 0;
  const resolvedEvidence = decision.evidence.filter((item) => ["OBSERVED", "NO_MATCH", "NOT_APPLICABLE"].includes(item.state)).length;
  const riskGuidance: Record<RiskBand, { className: string; content: ReactNode }> = {
    HIGH: { className: "alert-danger", content: <><strong>Do not open this link or enter any information.</strong>Use a known address or verified bookmark instead.</> },
    MEDIUM: { className: "alert-warning", content: <><strong>Verify the request through a trusted channel.</strong>Do not rely on contact details provided with the link.</> },
    LOW: { className: "alert-info", content: <><strong>Continue only if this link is expected and you recognise the sender.</strong>Low risk is not proof that a link is safe.</> },
    INCONCLUSIVE: { className: "alert-warning", content: <><strong>Treat this link as unverified.</strong>Use a known address or independently confirm the request before proceeding.</> },
  };

  async function copyReport() {
    setSharing(true);
    setShareError("");
    try {
      let nextUrl = shareUrl;
      if (!nextUrl) {
        const report = await api.createShare(id);
        nextUrl = `${location.origin}/reports/${report.report_id}`;
        setShareUrl(nextUrl);
        setReportExpiresAt(report.expires_at);
      }
      await navigator.clipboard?.writeText(nextUrl);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch (reason) {
      setShareError(reason instanceof ApiError ? reason.message : "The report link could not be created.");
    } finally {
      setSharing(false);
    }
  }

  return (
    <div className="page result-page">
      <div className="sr-only" aria-live="polite" aria-atomic="true">{completionAnnouncement}</div>
      <div className="result-toolbar">
        <Link className="back-link" to="/"><CaretRight aria-hidden /> New scan</Link>
        {!shared && <div>
          <button className="button button-secondary" type="button" onClick={prepareRescan}><ArrowClockwise aria-hidden /> Re-scan</button>
          <button className="button button-secondary" type="button" onClick={downloadDecision}><FileText aria-hidden /> Download JSON</button>
          <button className="button button-secondary" onClick={() => shareDialog.current?.showModal()}>Share report</button>
          <Link className="button button-secondary" to={`/feedback/${scan.id}`}>Give feedback</Link>
        </div>}
      </div>
      {(scan.simulated || scan.id.startsWith("demo-")) && <SimulatedDataBanner shared={shared} />}
      {rescanError && <div className="alert alert-danger shared-report-note" role="alert"><WarningCircle aria-hidden />{rescanError}</div>}
      {shared && <div className="alert alert-info shared-report-note" role="status"><Eye aria-hidden /><span><strong>Read-only shared report.</strong> This redacted view expires {formatDate(reportExpiresAt)}.</span></div>}
      <section className={`risk-summary risk-${decision.risk_band.toLowerCase()}`} aria-labelledby="result-title">
        <div className="risk-icon"><RiskIcon aria-hidden weight="fill" /></div>
        <div className="risk-content">
          <div className="result-badges"><RiskBadge risk={decision.risk_band} status={scan.status} /><StatusBadge status={scan.status} /><span className="badge badge-neutral">{decision.analysis_scope === "LOCAL_ONLY" ? "Local only" : "Enriched"}</span>{limitedCoverage && <span className="badge badge-medium"><WarningCircle aria-hidden weight="fill" />Partial coverage</span>}{decision.engine_mode === "RULE_ONLY" && <span className="badge badge-medium"><ShieldWarning aria-hidden weight="fill" />Rule-only fallback</span>}</div>
          <h1 id="result-title">{presentation.title}</h1>
          <p className="display-url">{scan.display_url}{scan.ascii_display_url && <small>ASCII: {scan.ascii_display_url}</small>}</p>
          <p>{decision.reasons[0] || presentation.summary}</p>
          <p className="evidence-coverage"><ClipboardText aria-hidden /><strong>Evidence coverage:</strong> {resolvedEvidence} of {decision.evidence.length} observations resolved{decision.evidence.length === 0 ? "." : ` · ${decision.missing_evidence.length} explicitly missing.`}</p>
          {limitedCoverage && <div className="alert alert-warning coverage-note"><WarningCircle aria-hidden /><span><strong>Partial evidence coverage.</strong>Some checks were unavailable. Missing evidence did not lower the risk.</span></div>}
          {decision.engine_mode === "RULE_ONLY" && <div className="alert alert-warning coverage-note"><ShieldWarning aria-hidden /><span><strong>Rule-only result.</strong>The approved model was unavailable, so this decision uses deterministic rules and available evidence only.</span></div>}
          {scan.status === "PROCESSING" && (pollingPause ? <div className={`alert ${pollingPause.reason === "error" ? "alert-danger" : "alert-warning"} polling-paused`} role={pollingPause.reason === "error" ? "alert" : "status"}><WarningCircle aria-hidden /><span><strong>Automatic updates paused.</strong>{pollingPause.message}</span><button className="button button-secondary button-small" type="button" onClick={retryPolling}><ArrowClockwise aria-hidden />Check again</button></div> : <div className="progress-note" role="status"><CircleNotch className="spinner" aria-hidden /><span><strong>External checks are still running; risk may increase.</strong>This page updates automatically when enrichment finishes.</span></div>)}
        </div>
      </section>

      <div className="result-grid">
        <section className="result-sections" aria-label="Analysis details">
          <ResultSection title="Reasons" icon={ShieldWarning} count={decision.reasons.length} open>
            {decision.reasons.length ? <ul className="finding-list">{decision.reasons.map((reason, index) => <li key={reason}><span>{index + 1}</span><p>{reason}</p></li>)}</ul> : <p className="section-empty">No specific risk reasons were recorded for this decision.</p>}
            {decision.counter_evidence.length > 0 && <div className="counter-evidence"><CheckCircle aria-hidden /><div><strong>Counter-evidence</strong>{decision.counter_evidence.map((item) => <p key={item}>{item}</p>)}</div></div>}
          </ResultSection>
          <ResultSection title="Evidence" icon={ClipboardText} count={decision.evidence.length}>
            {decision.evidence.length ? <div className="evidence-list" aria-label="Evidence observations">
              {decision.evidence.map((item) => <EvidenceRow key={item.id} item={item} />)}
            </div> : <p className="section-empty">No evidence observations were stored for this decision.</p>}
          </ResultSection>
          <ResultSection title="Limitations" icon={Info} count={decision.limitations.length + decision.missing_evidence.length} open={openLimitations}>
            {decision.missing_evidence.map((item) => <div className="alert alert-warning" key={item}><WarningCircle aria-hidden /><span>{item}</span></div>)}
            {decision.limitations.length ? <ul className="plain-list">{decision.limitations.map((item) => <li key={item}>{item}</li>)}</ul> : decision.missing_evidence.length === 0 && <p className="section-empty">No additional limitations were recorded.</p>}
          </ResultSection>
          <ResultSection title="Technical details" icon={FileText}>
            <dl className="technical-grid">
              <div><dt>Analysis scope</dt><dd>{decision.analysis_scope.replace("_", " ")}</dd></div>
              <div><dt>Completion</dt><dd>{decision.completion}</dd></div>
              <div><dt>Engine mode</dt><dd>{decision.engine_mode.replace("_", " ")}</dd></div>
              <div><dt>Policy</dt><dd>{decision.versions.policy}</dd></div>
              <div><dt>Ruleset</dt><dd>{decision.versions.ruleset}</dd></div>
              <div><dt>Model</dt><dd>{decision.versions.model}</dd></div>
            </dl>
          </ResultSection>
        </section>
        <aside className="next-actions card">
          <h2>What to do next</h2>
          <ul>{(decision.safe_actions.length ? decision.safe_actions : ["Use a known address or verified bookmark for sensitive tasks."]).map((action) => <li key={action}><Check aria-hidden /><span>{action}</span></li>)}</ul>
          <div className={`alert ${riskGuidance[decision.risk_band].className}`}><LockKey aria-hidden /><span>{riskGuidance[decision.risk_band].content}</span></div>
        </aside>
      </div>

      {!shared && <dialog ref={shareDialog} className="dialog" aria-modal="true" aria-labelledby="share-report-title" aria-describedby="share-report-description" onClick={(event) => { if (event.target === shareDialog.current) shareDialog.current.close(); }}>
        <form method="dialog">
          <div className="dialog-icon"><Eye aria-hidden /></div>
          <h2 id="share-report-title">Share a redacted report</h2>
          <p id="share-report-description">The temporary report does not reveal the original URL or account details.</p>
          <div className="copy-row"><code>{shareUrl || "A new unguessable link will be created."}</code>{shareUrl && <button type="button" className="icon-button" onClick={copyReport} aria-label="Copy report link">{copied ? <Check aria-hidden /> : <Copy aria-hidden />}</button>}</div>
          {reportExpiresAt && <p className="field-hint">Expires {formatDate(reportExpiresAt)}</p>}
          {shareError && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden /><span>{shareError}</span></div>}
          <div className="dialog-actions"><button className="button button-secondary" value="cancel">Cancel</button><button type="button" className="button button-primary" onClick={copyReport} disabled={sharing}>{sharing ? "Creating link…" : copied ? "Copied" : shareUrl ? "Copy link" : "Create and copy link"}</button></div>
        </form>
      </dialog>}
      {pendingRescan && <FreshAuthDialog action={pendingRescan} close={() => setPendingRescan(null)} />}
    </div>
  );
}

function ResultSkeleton() {
  return <div className="page result-page" aria-busy="true" aria-label="Loading scan result"><div className="skeleton skeleton-line short" /><div className="skeleton skeleton-hero" /><div className="skeleton skeleton-panel" /></div>;
}

function ResultSection({ title, icon: SectionIcon, count, open, children }: { title: string; icon: Icon; count?: number; open?: boolean; children: ReactNode }) {
  return <details className="result-section" open={open}><summary><span><SectionIcon aria-hidden />{title}{count !== undefined && <small>{count}</small>}</span><CaretRight className="section-caret" aria-hidden /></summary><div className="section-body">{children}</div></details>;
}

const evidenceStateLabels: Record<EvidenceObservation["state"], string> = {
  OBSERVED: "Available",
  NO_MATCH: "No match",
  NOT_APPLICABLE: "Not applicable",
  SKIPPED_POLICY: "Skipped by policy",
  UNAVAILABLE: "Unavailable",
  TIMED_OUT: "Timed out",
  REJECTED_SAFETY: "Blocked for safety",
  STALE: "Stale",
};

function evidenceName(item: EvidenceObservation) {
  const label = item.label?.trim() || item.family;
  return label.replace(/\b(dns|rdap|tls|url|html)\b/gi, (value) => value.toUpperCase());
}

function sourceName(source: string) {
  if (source === "google_web_risk") return "Google Web Risk";
  if (source.startsWith("isolated_fetcher:")) return `Isolated fetcher · ${source.slice("isolated_fetcher:".length).replaceAll(/[_-]/g, " ")}`;
  return source.replaceAll(/[_-]/g, " ");
}

function evidenceSummary(item: EvidenceObservation) {
  if (item.value_redacted) return "Detailed evidence is hidden in this shared report.";
  if (!["OBSERVED", "NO_MATCH"].includes(item.state)) {
    return item.reason_code ? `Check ${item.reason_code.replaceAll("_", " ")}.` : `${evidenceStateLabels[item.state]}.`;
  }
  const value = item.value ?? {};
  const family = item.family.toUpperCase();
  const list = (key: string) => Array.isArray(value[key]) ? value[key] as unknown[] : [];
  const number = (key: string) => typeof value[key] === "number" ? value[key] as number : 0;
  if (family === "DNS") {
    const addresses = list("addresses");
    return addresses.length ? `${addresses.length} public address${addresses.length === 1 ? "" : "es"} resolved: ${addresses.join(", ")}.` : "No public address was returned.";
  }
  if (family === "RDAP") {
    const events = value.events && typeof value.events === "object" ? value.events as Record<string, unknown> : {};
    const registered = typeof events.registration === "string" ? formatDate(events.registration) : undefined;
    const expires = typeof events.expiration === "string" ? formatDate(events.expiration) : undefined;
    return [registered && `Registered ${registered}`, expires && `expires ${expires}`, `${list("nameservers").length} nameserver${list("nameservers").length === 1 ? "" : "s"}`].filter(Boolean).join(" · ") + ".";
  }
  if (family === "REDIRECT") {
    const count = number("count");
    return count ? `${count} redirect${count === 1 ? "" : "s"} followed within the safety limit.` : "No redirect was followed.";
  }
  if (family === "REPUTATION") {
    return item.state === "NO_MATCH" ? "No supported threat-list match was returned; this is neutral evidence, not proof of safety." : "The reputation provider returned a threat-list match.";
  }
  if (family === "STATIC_HTML") {
    return `${number("forms")} form${number("forms") === 1 ? "" : "s"} · ${number("password_inputs")} password field${number("password_inputs") === 1 ? "" : "s"} · ${number("external_links")} external link${number("external_links") === 1 ? "" : "s"}.`;
  }
  if (family === "TLS") {
    if (!Object.keys(value).length) return "TLS evidence was not applicable to this destination.";
    return `${typeof value.version === "string" ? value.version : "TLS"} connection${value.hostname_verified === true ? " with a verified hostname" : ""}.`;
  }
  if (family === "URL") {
    if (typeof value.protocol === "string") return `${String(value.protocol).toUpperCase()} transport scheme.`;
    const matches = list("matches");
    return matches.length ? `${matches.length} suspicious URL term${matches.length === 1 ? "" : "s"} found: ${matches.join(", ")}.` : "No suspicious URL terms matched.";
  }
  return Object.keys(value).length ? `${Object.keys(value).length} structured field${Object.keys(value).length === 1 ? "" : "s"} available.` : evidenceStateLabels[item.state] + ".";
}

function EvidenceRow({ item }: { item: EvidenceObservation }) {
  return (
    <article className="evidence-card">
      <header><div><p className="eyebrow">{item.family.replaceAll("_", " ")}</p><h3>{evidenceName(item)}</h3></div><span className={`evidence-state state-${item.state.toLowerCase()}`}>{evidenceStateLabels[item.state]}</span></header>
      <p className="evidence-summary">{evidenceSummary(item)}</p>
      <div className="evidence-meta"><span><strong>Source</strong>{sourceName(item.source)}</span><span><strong>Version</strong>{item.version}</span>{item.observed_at && <span><strong>Observed</strong>{formatDate(item.observed_at)}</span>}{item.cached && <span><strong>Cache</strong>Cached observation</span>}</div>
      {!item.value_redacted && item.value && Object.keys(item.value).length > 0 && <details className="evidence-technical"><summary>Technical details</summary><pre>{JSON.stringify(item.value, null, 2)}</pre></details>}
    </article>
  );
}

function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<"ALL" | RiskBand>("ALL");
  const [deleteTarget, setDeleteTarget] = useState<Scan | null>(null);
  const [deleteError, setDeleteError] = useState("");
  const [deleting, setDeleting] = useState(false);
  const deleteDialog = useRef<HTMLDialogElement>(null);

  function loadHistory() {
    setLoading(true);
    setError("");
    api.listScans().then(setScans).catch(() => setError("History could not be loaded.")).finally(() => setLoading(false));
  }
  useEffect(loadHistory, []);
  useEffect(() => {
    const dialog = deleteDialog.current;
    if (!deleteTarget || !dialog || dialog.open) return;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  }, [deleteTarget]);

  function askToDelete(scan: Scan) {
    setNotice("");
    setDeleteError("");
    setDeleteTarget(scan);
  }

  function closeDeleteDialog() {
    if (deleting) return;
    const dialog = deleteDialog.current;
    if (dialog?.open && typeof dialog.close === "function") dialog.close();
    setDeleteTarget(null);
    setDeleteError("");
  }

  async function confirmDelete(event: FormEvent) {
    event.preventDefault();
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError("");
    try {
      await api.deleteScan(deleteTarget.id);
      setScans((items) => items.filter((scan) => scan.id !== deleteTarget.id));
      setNotice("Scan deleted from history.");
      if (deleteDialog.current?.open && typeof deleteDialog.current.close === "function") deleteDialog.current.close();
      setDeleteTarget(null);
    } catch (reason) {
      setDeleteError(apiMessage(reason, "The scan could not be deleted. Try again."));
    } finally {
      setDeleting(false);
    }
  }

  const visibleScans = scans.filter((scan) => {
    const matchesQuery = !query.trim() || scan.display_url.toLowerCase().includes(query.trim().toLowerCase()) || scan.id.toLowerCase().includes(query.trim().toLowerCase());
    return matchesQuery && (riskFilter === "ALL" || scan.decision.risk_band === riskFilter);
  });

  return (
    <div className="page">
      <PageHeader eyebrow="Your account" title="Scan history" description="Only redacted URLs are shown here. Delete records whenever you no longer need them." actions={<Link className="button button-primary" to="/"><MagnifyingGlass aria-hidden /> New scan</Link>} />
      {notice && <div className="alert alert-success history-notice" role="status"><CheckCircle aria-hidden />{notice}</div>}
      {loading ? <div className="skeleton skeleton-panel" role="status" aria-label="Loading scan history" /> : error ? (
        <StatePanel kind="error" title="History unavailable" detail={error} retry={loadHistory} />
      ) : scans.length === 0 ? (
        <div className="empty-state card"><ClockCounterClockwise aria-hidden /><h2>No saved scans</h2><p>Your completed scans will appear here.</p><Link className="button button-primary" to="/">Analyze a URL</Link></div>
      ) : (
        <>{scans.some((scan) => scan.simulated || scan.id.startsWith("demo-")) && <SimulatedDataBanner />}
        <div className="toolbar card"><div className="search-field"><MagnifyingGlass aria-hidden /><input aria-label="Search scan history" placeholder="Search redacted URL or scan ID" value={query} onChange={(event) => setQuery(event.target.value)} /></div><select aria-label="Filter by risk" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value as "ALL" | RiskBand)}><option value="ALL">All risk bands</option><option value="HIGH">High risk</option><option value="MEDIUM">Medium risk</option><option value="LOW">Low risk</option><option value="INCONCLUSIVE">Inconclusive</option></select></div>
        {visibleScans.length === 0 ? <div className="empty-state card compact-empty"><MagnifyingGlass aria-hidden /><h2>No matching scans</h2><p>Change the search text or risk filter.</p><button className="button button-secondary" type="button" onClick={() => { setQuery(""); setRiskFilter("ALL"); }}>Clear filters</button></div> : <div className="table-card">
          <div className="data-table history-data-table" role="table" aria-label="Scan history">
            <div className="data-row data-head" role="row"><span role="columnheader">URL</span><span role="columnheader">Risk</span><span role="columnheader">Scope</span><span role="columnheader">Scanned</span><span role="columnheader"><span className="sr-only">Actions</span></span></div>
            {visibleScans.map((scan) => (
              <div className="data-row" role="row" key={scan.id}>
                <span role="cell"><Link className="table-link" to={`/scan/${scan.id}`}>{scan.display_url}</Link><small>{scan.id.slice(0, 16)}</small></span>
                <span role="cell"><RiskBadge risk={scan.decision.risk_band} status={scan.status} /></span>
                <span role="cell">{scan.decision.analysis_scope === "LOCAL_ONLY" ? "Local only" : "Enriched"}</span>
                <span role="cell">{formatDate(scan.created_at)}</span>
                <span role="cell" className="row-actions"><Link className="icon-button" aria-label={`View scan for ${scan.display_url}`} to={`/scan/${scan.id}`}><CaretRight aria-hidden /></Link><button className="icon-button" type="button" aria-label={`Delete scan for ${scan.display_url}`} onClick={() => askToDelete(scan)}><Trash aria-hidden /></button></span>
              </div>
            ))}
          </div>
        </div>}</>
      )}
      {deleteTarget && <dialog ref={deleteDialog} className="dialog" aria-modal="true" aria-labelledby="delete-scan-title" aria-describedby="delete-scan-description" onCancel={(event) => { if (deleting) event.preventDefault(); }} onClose={() => { if (!deleting) { setDeleteTarget(null); setDeleteError(""); } }}>
        <form onSubmit={confirmDelete} aria-busy={deleting}>
          <div className="dialog-icon danger"><Trash aria-hidden /></div>
          <h2 id="delete-scan-title">Delete this scan?</h2>
          <p id="delete-scan-description">This removes the stored scan and revokes its reports. This action cannot be undone.</p>
          <code className="delete-scan-target">{defangUrl(deleteTarget.display_url)}</code>
          {deleteError && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden /><span>{deleteError}</span></div>}
          <div className="dialog-actions"><button className="button button-secondary" type="button" autoFocus disabled={deleting} onClick={closeDeleteDialog}>Cancel</button><button className="button button-danger" type="submit" disabled={deleting}>{deleting ? <><CircleNotch className="spinner" aria-hidden />Deleting…</> : <><Trash aria-hidden />Delete scan</>}</button></div>
        </form>
      </dialog>}
    </div>
  );
}

function AccountPage() {
  const navigate = useNavigate();
  const session = useSession();
  const account = session.me;
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [retentionDays, setRetentionDays] = useState(account?.scan_retention_days ?? account?.scan_retention_max_days ?? 30);
  const [requestedRole, setRequestedRole] = useState<PrivilegedRequestedRole>("ANALYST");
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [pendingAction, setPendingAction] = useState<(() => Promise<void>) | null>(null);
  const deleteDialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { setRetentionDays(account?.scan_retention_days ?? account?.scan_retention_max_days ?? 30); }, [account?.scan_retention_days, account?.scan_retention_max_days]);
  useEffect(() => {
    const dialog = deleteDialog.current;
    if (!confirmDelete || !dialog || dialog.open) return;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  }, [confirmDelete]);

  async function signOut() {
    try {
      await session.signOut();
    } finally {
      navigate("/sign-in", { replace: true });
    }
  }

  async function runProtected(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (reason) {
      if (reason instanceof ApiError && reason.code === "fresh_auth_required") {
        setPendingAction(() => action);
      } else {
        setError(apiMessage(reason, "The protected account action could not be completed."));
      }
    } finally {
      setBusy(false);
    }
  }

  async function downloadExport() {
    const payload = await api.exportAccount();
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `phishguard-account-export-${payload.generated_at.slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    setNotice("Your redacted account export was downloaded.");
  }

  async function saveRetention() {
    const result = await api.updateAccountRetention(retentionDays);
    if (account) session.accept({ ...account, scan_retention_days: result.scan_retention_days });
    setNotice(`New scans will be retained for ${result.scan_retention_days} days.`);
  }

  async function requestRoleAccess() {
    const roleRequest = await api.createRoleRequest(requestedRole);
    if (account) session.accept({ ...account, role_request: roleRequest });
    setNotice(`${roleLabel(requestedRole)} access was requested for administrator review.`);
  }

  async function cancelRoleAccess() {
    if (!account?.role_request) return;
    await api.cancelRoleRequest(account.role_request.id);
    session.accept({ ...account, role_request: null });
    setNotice("The pending role request was cancelled.");
  }

  async function deleteAllScanData() {
    await api.deleteAccountScans();
    try { await session.signOut(); } catch { /* The API session was already revoked by deletion. */ }
    navigate("/sign-in", { replace: true });
  }

  const retentionMaximum = account?.scan_retention_max_days ?? 30;
  const retentionOptions = [...new Set([1, 7, 14, 30, retentionDays])].filter((days) => days <= retentionMaximum).sort((a, b) => a - b);

  return (
    <div className="page narrow-content">
      <PageHeader eyebrow="Your account" title="Privacy and account" description="Review the application session and available privacy controls." />
      {error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}
      {notice && <div className="alert alert-success" role="status"><CheckCircle aria-hidden />{notice}</div>}
      <section className="settings-section"><h2>Application session</h2><div className="settings-card stacked"><dl className="account-facts"><div><dt>Role</dt><dd>{roleLabel(account?.role ?? "GUEST")} {account?.is_canonical_admin && <span className="badge badge-neutral">Canonical administrator</span>}</dd></div><div><dt>User ID</dt><dd className="mono">{account?.user_id ?? "Not available"}</dd></div></dl><button className="button button-secondary" type="button" onClick={signOut}><SignOut aria-hidden /> Sign out</button></div></section>
      {account?.role === "REGISTERED_USER" && <section className="settings-section"><h2>Workspace access</h2><div className="settings-card role-request-card">{account.role_request?.state === "PENDING" ? <><div><strong>{roleLabel(account.role_request.requested_role)} access pending</strong><small>Requested {formatDate(account.role_request.requested_at)}. An administrator must review this request.</small></div><span className="badge badge-medium"><ClockCounterClockwise aria-hidden />Pending review</span><button className="button button-secondary" type="button" disabled={busy} onClick={() => runProtected(cancelRoleAccess)}>Cancel request</button></> : <><div><strong>Request a governed role</strong><small>Analyst and researcher access require verified email, TOTP and administrator approval.</small></div><label className="field compact-field"><span>Requested role</span><select value={requestedRole} onChange={(event) => setRequestedRole(event.target.value as PrivilegedRequestedRole)}><option value="ANALYST">Analyst</option><option value="RESEARCHER">Researcher</option></select></label><button className="button button-secondary" type="button" disabled={busy} onClick={() => runProtected(requestRoleAccess)}>Request access</button></>}</div></section>}
      <section className="settings-section"><h2>Security</h2><div className="settings-list"><Link to="/totp"><span><Key aria-hidden /><span><strong>Authenticator app</strong><small>Enroll or update TOTP through Identity Platform.</small></span></span><CaretRight aria-hidden /></Link></div></section>
      <section className="settings-section"><h2>Data controls</h2><div className="settings-card account-data-controls"><div><strong>Scan retention</strong><small>Applies to new scans. The application policy permits up to {retentionMaximum} days.</small></div><div className="retention-control"><label htmlFor="retention-days">Keep new scans for</label><select id="retention-days" value={retentionDays} onChange={(event) => setRetentionDays(Number(event.target.value))}>{retentionOptions.map((days) => <option value={days} key={days}>{days} {days === 1 ? "day" : "days"}</option>)}</select><button className="button button-secondary" type="button" disabled={busy || retentionDays === account?.scan_retention_days} onClick={() => runProtected(saveRetention)}>Save retention</button></div><div className="account-action"><span><strong>Download your data</strong><small>Exports redacted scan history and stored decisions as JSON. Original URLs are never included.</small></span><button className="button button-secondary" type="button" disabled={busy} onClick={() => runProtected(downloadExport)}><FileText aria-hidden /> Download JSON</button></div><Link className="button button-secondary account-history-link" to="/history">Open scan history</Link></div></section>
      <section className="settings-section danger-zone"><h2>Delete scan data</h2><div className="settings-card"><p>Delete every scan owned by this application account, revoke shared reports and application sessions, and sign out. Your Google Identity Platform identity is not deleted.</p><button className="button button-danger" type="button" disabled={busy} onClick={() => setConfirmDelete(true)}><Trash aria-hidden /> Delete all scan data</button></div></section>
      {confirmDelete && <dialog ref={deleteDialog} className="dialog" aria-modal="true" aria-labelledby="delete-account-scans-title" aria-describedby="delete-account-scans-description" onCancel={() => setConfirmDelete(false)} onClose={() => setConfirmDelete(false)}><form onSubmit={(event) => { event.preventDefault(); setConfirmDelete(false); runProtected(deleteAllScanData); }}><div className="dialog-icon danger"><Trash aria-hidden /></div><h2 id="delete-account-scans-title">Delete all scan data?</h2><p id="delete-account-scans-description">This permanently removes access to every saved scan and report and signs out every PhishGuard application session. It does not delete your Google Identity Platform identity.</p><div className="dialog-actions"><button className="button button-secondary" type="button" autoFocus onClick={() => { if (typeof deleteDialog.current?.close === "function") deleteDialog.current.close(); else setConfirmDelete(false); }}>Cancel</button><button className="button button-danger" type="submit"><Trash aria-hidden />Delete all scan data</button></div></form></dialog>}
      {pendingAction && <FreshAuthDialog action={pendingAction} close={() => setPendingAction(null)} />}
    </div>
  );
}

function SignInPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const session = useSession();
  const configured = identityConfigured();
  const [mode, setMode] = useState<"sign-in" | "register" | "reset">("sign-in");
  const [requestedRole, setRequestedRole] = useState<RequestedRole>("REGISTERED_USER");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfaFactor, setMfaFactor] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);
  const requestedDestination = safeInternalFrom(new URLSearchParams(location.search).get("from"));

  useEffect(() => { heading.current?.focus(); }, [mode, mfaFactor]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setNotice("");
    if (!configured) {
      setError("Identity Platform is not configured for this build.");
      return;
    }
    setBusy(true);
    try {
      if (mfaFactor) {
        const nextSession = await completeTotpSignIn(code);
        session.accept(nextSession);
        sessionStorage.removeItem(REGISTRATION_INTENT_KEY);
        navigate(requestedDestination ?? nextSession.default_route ?? defaultRoute(nextSession.role), { replace: true });
      } else if (mode === "register") {
        await createPasswordAccount(email, password);
        sessionStorage.setItem(REGISTRATION_INTENT_KEY, JSON.stringify({ email: email.trim().toLowerCase(), role: requestedRole }));
        setNotice("Check your inbox to verify your email address before signing in.");
        setMode("sign-in");
        setPassword("");
      } else if (mode === "reset") {
        await requestPasswordReset(email);
        setNotice("If an eligible account exists, Identity Platform will send recovery instructions.");
      } else {
        const result = await beginPasswordSignIn(email, password, registrationIntent(email));
        if (result.mfaRequired) {
          setMfaFactor(result.factorName);
          setPassword("");
        } else {
          session.accept(result.session);
          sessionStorage.removeItem(REGISTRATION_INTENT_KEY);
          navigate(requestedDestination ?? result.session.default_route ?? defaultRoute(result.session.role), { replace: true });
        }
      }
    } catch (reason) {
      setError(reason instanceof IdentityError || reason instanceof ApiError ? reason.message : "Authentication could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  const title = mfaFactor ? "Enter your verification code" : mode === "register" ? "Create your PhishGuard account" : mode === "reset" ? "Recover your account" : "Sign in to PhishGuard";
  const description = mfaFactor ? `Use the current code from ${mfaFactor}.` : mode === "register" ? "Identity Platform securely manages your password and email verification." : mode === "reset" ? "Recovery is handled by Google Identity Platform." : "Review your history and manage protected reports.";
  if (session.status === "loading") return <div className="page narrow-page"><StatePanel kind="loading" title="Checking your session" detail="Confirming whether you are already signed in." /></div>;
  if (session.status === "ready" && session.me?.session_kind === "USER" && session.me.role) return <Navigate to={requestedDestination ?? session.me.default_route ?? defaultRoute(session.me.role)} replace />;
  return (
    <div className="auth-page">
      <section className="auth-card card">
        <div className="auth-heading"><span className="auth-icon"><LockKey aria-hidden /></span><h1 ref={heading} tabIndex={-1}>{title}</h1><p>{description}</p></div>
        <form onSubmit={submit}>
          {!mfaFactor && <label className="field"><span>Email address</span><input type="email" autoComplete="email" required placeholder="name@university.edu" value={email} onChange={(event) => setEmail(event.target.value)} /></label>}
          {!mfaFactor && mode !== "reset" && <label className="field"><span>Password</span><input type="password" autoComplete={mode === "register" ? "new-password" : "current-password"} minLength={8} required value={password} onChange={(event) => setPassword(event.target.value)} /></label>}
          {!mfaFactor && mode === "register" && <label className="field"><span>Intended account role</span><select value={requestedRole} onChange={(event) => setRequestedRole(event.target.value as RequestedRole)}><option value="REGISTERED_USER">Registered user</option><option value="ANALYST">Analyst (approval required)</option><option value="RESEARCHER">Researcher (approval required)</option></select><small className="field-hint">Privileged access is only requested after email verification and sign-in. It also requires TOTP and administrator approval.</small></label>}
          {mfaFactor && <label className="field"><span>6-digit verification code</span><input className="code-input" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required placeholder="000000" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} /></label>}
          {!mfaFactor && mode === "sign-in" && <div className="form-row"><span className="field-hint">Sessions expire after 8 hours.</span><button type="button" className="text-button" onClick={() => setMode("reset")}>Forgot password?</button></div>}
          {!configured && <div className="alert alert-warning" role="status"><Info aria-hidden /><span>Configure the Firebase web client environment before using account features.</span></div>}
          {error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden /><span>{error}</span></div>}
          {notice && <div className="alert alert-success" role="status"><CheckCircle aria-hidden /><span>{notice}</span></div>}
          <button className="button button-primary button-large" type="submit" disabled={busy || !configured}>{busy ? "Please wait…" : mfaFactor ? "Verify and sign in" : mode === "register" ? "Create account" : mode === "reset" ? "Send recovery email" : <>Sign in <ArrowRight aria-hidden /></>}</button>
        </form>
        <p className="auth-footer">{mode === "sign-in" && !mfaFactor ? <>New here? <button className="text-button" onClick={() => setMode("register")}>Create an account</button></> : <button className="text-button" onClick={() => { setMode("sign-in"); setMfaFactor(""); setError(""); }}>Return to sign in</button>}</p>
      </section>
      <aside className="auth-aside"><ShieldCheck aria-hidden weight="fill" /><blockquote>“Understand the evidence before you trust the link.”</blockquote><p>PhishGuard does not store passwords. Authentication is delegated to Google Identity Platform.</p></aside>
    </div>
  );
}

function TotpPage() {
  const configured = identityConfigured();
  const navigate = useNavigate();
  const session = useSession();
  const [secret, setSecret] = useState("");
  const [qrCodeUrl, setQrCodeUrl] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [verified, setVerified] = useState(false);

  async function generateSecret() {
    setBusy(true);
    setError("");
    try {
      const enrollment = await beginTotpEnrollment();
      setSecret(enrollment.secretKey);
      setQrCodeUrl(enrollment.qrCodeUrl);
    } catch (reason) {
      setError(reason instanceof IdentityError ? reason.message : "Two-step verification setup could not begin.");
    } finally {
      setBusy(false);
    }
  }

  async function verify(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await completeTotpEnrollment(code);
      setVerified(true);
      setSecret("");
      setQrCodeUrl("");
    } catch (reason) {
      setError(reason instanceof IdentityError || reason instanceof ApiError ? reason.message : "The verification code could not be accepted.");
    } finally {
      setBusy(false);
    }
  }

  async function restartSignIn() {
    setBusy(true);
    setError("");
    try {
      await session.signOut();
      navigate("/sign-in", { replace: true });
    } catch {
      setError("Sign out could not be completed. Try again before requesting a privileged role.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page narrow-page">
      <PageHeader eyebrow="Account security" title="Set up two-step verification" description="Privileged roles require a time-based one-time password in addition to your password." />
      <div className="card setup-card">
        <ol className="setup-steps"><li className="done"><span><Check aria-hidden /></span>Install an authenticator app</li><li className="active"><span>2</span>Add your PhishGuard account</li><li><span>3</span>Verify a code</li></ol>
        <div className="setup-content">
          <div className="key-panel"><Key aria-hidden /><p>{secret ? "Scan this QR code with your authenticator app, or enter the setup key manually:" : "Generate a fresh setup key after signing in and verifying your email address."}</p>{qrCodeUrl && <div className="totp-qr" role="img" aria-label="Scan this QR code with your authenticator app"><QRCodeSVG value={qrCodeUrl} size={192} level="M" title="PhishGuard authenticator setup QR code" /></div>}{secret && <code>{secret.match(/.{1,4}/g)?.join(" ")}</code>}<button type="button" className="button button-secondary" disabled={busy || !configured} onClick={secret ? () => navigator.clipboard?.writeText(secret) : generateSecret}>{secret ? <><Copy aria-hidden /> Copy key</> : <><Key aria-hidden /> Generate setup key</>}</button></div>
          <form onSubmit={verify}><label className="field"><span>6-digit verification code</span><input className="code-input" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required placeholder="000000" value={code} disabled={!secret || verified} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} /></label><button className="button button-primary button-large" disabled={!secret || busy || verified}>{busy ? "Please wait…" : "Verify and enable"}</button>{!configured && <div className="alert alert-warning" role="status"><Info aria-hidden />Identity Platform is not configured for this build.</div>}{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}{verified && <div className="alert alert-success" role="status"><CheckCircle aria-hidden /><span>Two-step verification is enabled. Sign out and sign back in with your authenticator code before requesting or receiving a privileged role.</span><button className="button button-secondary" type="button" disabled={busy} onClick={restartSignIn}>Sign out and continue</button></div>}</form>
        </div>
      </div>
    </div>
  );
}

function FeedbackPage() {
  const { scanId = "" } = useParams();
  const [verdict, setVerdict] = useState("");
  const [comment, setComment] = useState("");
  const [sent, setSent] = useState(false);
  const [receipt, setReceipt] = useState<FeedbackReceipt | null>(null);
  const [researchConsent, setResearchConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const nextReceipt = await api.submitFeedback(scanId, verdict, comment, researchConsent);
      setReceipt(nextReceipt);
      setSent(true);
    } catch (reason) {
      setError(apiMessage(reason, "Feedback could not be submitted. Try again."));
    } finally {
      setBusy(false);
    }
  }
  if (sent) return <div className="page narrow-page"><div className="empty-state card"><CheckCircle aria-hidden /><h1>Feedback received</h1><p>Your report is quarantined for independent analyst review. It does not change the original result.</p>{receipt && <dl className="feedback-receipt"><div><dt>Status</dt><dd>{receipt.status.replaceAll("_", " ")}</dd></div><div><dt>Reference</dt><dd>{receipt.id}</dd></div><div><dt>Research consideration</dt><dd>{receipt.research_consent ? "Consented, subject to adjudication" : "Not permitted"}</dd></div></dl>}<Link className="button button-primary" to={`/scan/${scanId}`}>Return to result</Link></div></div>;
  return <div className="page narrow-page"><PageHeader eyebrow="Improve the evidence" title="Report an incorrect result" description="Feedback is reviewed independently and never becomes training data automatically." /><form className="card feedback-card" onSubmit={submit} aria-busy={busy}><fieldset disabled={busy}><legend>What seems wrong?</legend><div className="feedback-choices"><label className={verdict === "should_be_high" ? "selected" : ""}><input type="radio" name="verdict" value="should_be_high" required onChange={(event) => setVerdict(event.target.value)} /><ThumbsDown aria-hidden /><span><strong>This link is more dangerous</strong><small>The displayed risk is too low.</small></span></label><label className={verdict === "should_be_low" ? "selected" : ""}><input type="radio" name="verdict" value="should_be_low" onChange={(event) => setVerdict(event.target.value)} /><ThumbsUp aria-hidden /><span><strong>This link is safer</strong><small>The displayed risk is too high.</small></span></label></div></fieldset><label className="field"><span>What evidence should we review? <small>Optional</small></span><textarea maxLength={1000} rows={5} value={comment} disabled={busy} onChange={(event) => setComment(event.target.value)} placeholder="Do not include passwords or other sensitive information." /><small className="character-count">{comment.length} / 1000</small></label><label className="research-consent"><input type="checkbox" checked={researchConsent} disabled={busy} onChange={(event) => setResearchConsent(event.target.checked)} /><span><strong>Allow governed research consideration</strong><small>Optional. Even with consent, this feedback remains quarantined and cannot enter a research dataset until independently adjudicated and included in an approved snapshot.</small></span></label>{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden /><span>{error}</span></div>}<div className="form-actions"><Link className="button button-secondary" aria-disabled={busy} to={`/scan/${scanId}`}>Cancel</Link><button className="button button-primary" disabled={!verdict || busy}>{busy ? <><CircleNotch className="spinner" aria-hidden />Submitting…</> : "Submit feedback"}</button></div></form></div>;
}

function apiMessage(reason: unknown, fallback: string) {
  return reason instanceof ApiError ? reason.message : fallback;
}

function parseJsonObject(value: string, label: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error(`${label} must be a valid JSON object.`);
  }
}

function WorkspaceFailure({ message, retry }: { message: string; retry: () => void }) {
  return <StatePanel kind="error" title="Data unavailable" detail={message} retry={retry} />;
}

function WorkspaceEmpty({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state card compact-empty"><Database aria-hidden /><h2>{title}</h2><p>{detail}</p></div>;
}

function AnalystCasesPage() {
  const session = useSession();
  const [cases, setCases] = useState<ReviewCase[] | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState("ALL");
  const [queueView, setQueueView] = useState<"OPEN" | "MINE" | "ADJUDICATED">("OPEN");

  function load() {
    setError("");
    setCases(null);
    api.listReviewCases().then(setCases).catch((reason) => setError(apiMessage(reason, "Review cases could not be loaded.")));
  }
  useEffect(load, []);

  const visible = (cases ?? []).filter((item) => {
    const matchesText = `${item.id} ${item.scan_id}`.toLowerCase().includes(query.toLowerCase());
    const matchesQueue = queueView === "OPEN"
      ? item.state !== "ADJUDICATED"
      : queueView === "MINE"
        ? item.state !== "ADJUDICATED" && item.claimed_by === session.me?.user_id
        : item.state === "ADJUDICATED";
    return matchesText && matchesQueue && (stateFilter === "ALL" || item.state === stateFilter);
  });
  const states = [...new Set((cases ?? []).map((item) => item.state))].sort();
  const unassigned = (cases ?? []).filter((item) => !item.claimed_by).length;
  const openCount = (cases ?? []).filter((item) => item.state !== "ADJUDICATED").length;
  const mineCount = (cases ?? []).filter((item) => item.state !== "ADJUDICATED" && item.claimed_by === session.me?.user_id).length;
  const adjudicatedCount = (cases ?? []).filter((item) => item.state === "ADJUDICATED").length;

  return <div className="page workspace-page">
    <PageHeader eyebrow="Analyst workspace" title="Review cases" description="Review persisted feedback cases. Submitted targets remain inert text." actions={<button className="button button-secondary" type="button" onClick={load}>Refresh</button>} />
    {cases && <div className="metric-grid"><Metric label="Cases returned" value={String(cases.length)} detail="Latest 100 records" icon={ListChecks} /><Metric label="Unassigned" value={String(unassigned)} detail="No recorded claimant" icon={UsersThree} /><Metric label="States" value={String(states.length)} detail="Persisted workflow states" icon={SlidersHorizontal} /></div>}
    <div className="queue-switcher card" aria-label="Case queue view"><button type="button" className={queueView === "OPEN" ? "active" : ""} onClick={() => setQueueView("OPEN")}>Open <span>{openCount}</span></button><button type="button" className={queueView === "MINE" ? "active" : ""} onClick={() => setQueueView("MINE")}>Mine <span>{mineCount}</span></button><button type="button" className={queueView === "ADJUDICATED" ? "active" : ""} onClick={() => setQueueView("ADJUDICATED")}>Adjudicated <span>{adjudicatedCount}</span></button></div>
    <div className="toolbar card"><div className="search-field"><MagnifyingGlass aria-hidden /><input aria-label="Search cases" placeholder="Search case or scan ID" value={query} onChange={(event) => setQuery(event.target.value)} /></div><select aria-label="Filter by state" value={stateFilter} onChange={(event) => setStateFilter(event.target.value)}><option value="ALL">All states</option>{states.map((state) => <option value={state} key={state}>{state.replaceAll("_", " ")}</option>)}</select></div>
    {!cases && !error && <div className="skeleton skeleton-panel" aria-label="Loading review cases" />}
    {error && <WorkspaceFailure message={error} retry={load} />}
    {cases && visible.length === 0 && <WorkspaceEmpty title="No matching cases" detail={cases.length ? "Change the search or state filter." : "No review cases have been recorded."} />}
    {visible.length > 0 && <div className="table-card"><div className="data-table case-data-table" role="table" aria-label="Review cases"><div className="data-row data-head" role="row"><span role="columnheader">Case</span><span role="columnheader">Scan</span><span role="columnheader">State</span><span role="columnheader">Assignment</span><span role="columnheader">Updated</span></div>{visible.map((item) => <Link className="data-row clickable-row" role="row" to={`/analyst/cases/${item.id}`} key={item.id}><span role="cell"><strong className="mono">{item.id}</strong></span><span role="cell" className="mono truncate">{item.scan_id}</span><span role="cell"><span className="badge badge-neutral">{item.state.replaceAll("_", " ")}</span></span><span role="cell">{item.claimed_by ? <span className="mono">{item.claimed_by.slice(0, 12)}…</span> : "Unassigned"}</span><span role="cell">{formatDate(item.updated_at)}</span></Link>)}</div></div>}
  </div>;
}

function AnalystCasePage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const session = useSession();
  const [reviewCase, setReviewCase] = useState<ReviewCaseDetail | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [scanUnavailable, setScanUnavailable] = useState(false);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<"" | "MALICIOUS" | "BENIGN" | "INCONCLUSIVE">("");
  const [note, setNote] = useState("");
  const [evidenceIds, setEvidenceIds] = useState<string[]>([]);
  const [revealedUrl, setRevealedUrl] = useState("");
  const [pendingSensitiveAction, setPendingSensitiveAction] = useState<(() => Promise<void>) | null>(null);

  async function load() {
    setError("");
    setReviewCase(null);
    setScan(null);
    setScanUnavailable(false);
    try {
      const detail = await api.getReviewCase(id);
      setReviewCase(detail);
      try {
        setScan(await api.getScan(detail.scan_id));
      } catch {
        setScanUnavailable(true);
      }
    } catch (reason) {
      setError(apiMessage(reason, "The review case could not be loaded."));
    }
  }
  useEffect(() => { load(); }, [id]);

  async function act(action: ReviewAction) {
    setBusy(true);
    setActionError("");
    try {
      await api.reviewCaseAction(id, action);
      const detail = await api.getReviewCase(id);
      setReviewCase(detail);
      setNote("");
      if (action.action === "adjudicate") {
        setOutcome("");
        setEvidenceIds([]);
      }
    } catch (reason) {
      setActionError(apiMessage(reason, "The review action could not be recorded."));
    } finally {
      setBusy(false);
    }
  }

  async function revealOriginal(forRescan = false) {
    setActionError("");
    try {
      const result = await api.revealReviewCaseUrl(id);
      if (forRescan) navigate(`/?url=${encodeURIComponent(result.url)}`);
      else setRevealedUrl(result.url);
    } catch (reason) {
      if (reason instanceof ApiError && reason.code === "fresh_auth_required") {
        setPendingSensitiveAction(() => () => revealOriginal(forRescan));
      } else {
        setActionError(apiMessage(reason, "The original URL could not be revealed."));
      }
    }
  }

  function toggleEvidence(evidenceId: string) {
    setEvidenceIds((current) => current.includes(evidenceId) ? current.filter((item) => item !== evidenceId) : [...current, evidenceId]);
  }

  if (!reviewCase && !error) return <div className="page workspace-page"><div className="skeleton skeleton-panel" aria-label="Loading review case" /></div>;
  if (error) return <div className="page workspace-page"><WorkspaceFailure message={error} retry={load} /></div>;
  if (!reviewCase) return null;
  const isMine = reviewCase.claimed_by === session.me?.user_id;
  const isClosed = reviewCase.state === "ADJUDICATED";

  return <div className="page workspace-page">
    <div className="result-toolbar"><Link className="back-link" to="/analyst/cases"><CaretRight aria-hidden /> All cases</Link><div>{isMine && !isClosed && <><button className="button button-secondary" disabled={busy} type="button" onClick={() => revealOriginal(false)}><Eye aria-hidden />Reveal URL</button><button className="button button-secondary" disabled={busy} type="button" onClick={() => revealOriginal(true)}><ArrowClockwise aria-hidden />Controlled re-scan</button></>}{!isClosed && (!reviewCase.claimed_by || isMine) && <button className="button button-secondary" disabled={busy} type="button" onClick={() => act({ action: isMine ? "release" : "claim" })}>{isMine ? "Release claim" : "Claim case"}</button>}</div></div>
    <PageHeader eyebrow="Analyst review" title={reviewCase.id} description={`State ${reviewCase.state.replaceAll("_", " ")} · updated ${formatDate(reviewCase.updated_at)}`} />
    <div className="case-layout"><section>
      {reviewCase.feedback && <section className="card review-feedback" aria-labelledby="submitted-feedback-title"><div className="section-heading"><div><p className="eyebrow">Quarantined user report</p><h2 id="submitted-feedback-title">Submitted feedback</h2></div><span className="badge badge-neutral">{reviewCase.feedback.status.replaceAll("_", " ")}</span></div><dl><div><dt>Category</dt><dd>{reviewCase.feedback.category.replaceAll("_", " ")}</dd></div><div><dt>Submitted</dt><dd>{formatDate(reviewCase.feedback.created_at)}</dd></div><div><dt>Research eligibility</dt><dd>{reviewCase.feedback.research_consent ? "Consent recorded; adjudication still required" : "Excluded—no consent"}</dd></div></dl><p>{reviewCase.feedback.comment || "No supporting comment was provided."}</p><small>Feedback cannot alter a result or enter training data without independent adjudication.</small></section>}
      {scan ? <><div className="card case-url"><span>{revealedUrl ? "Original submitted URL — sensitive" : "Redacted submitted URL"}</span><code>{defangUrl(revealedUrl || scan.display_url)}</code>{revealedUrl && <div className="alert alert-warning"><WarningCircle aria-hidden />Do not open this target. The reveal was recorded in the audit chain.</div>}<div><RiskBadge risk={scan.decision.risk_band} /><StatusBadge status={scan.status} /><span className="badge badge-neutral">{scan.decision.analysis_scope.replaceAll("_", " ")}</span></div></div><ResultSection title="Stored decision reasons" icon={Fingerprint} count={scan.decision.reasons.length} open>{scan.decision.reasons.length ? <ul className="finding-list">{scan.decision.reasons.map((reason, index) => <li key={reason}><span>{index + 1}</span><p>{reason}</p></li>)}</ul> : <p>No reason templates were stored for this decision.</p>}</ResultSection><ResultSection title="Pinned evidence" icon={Database} count={scan.decision.evidence.length} open>{scan.decision.evidence.length ? <div className="evidence-list">{scan.decision.evidence.map((item) => <EvidenceRow item={item} key={item.id} />)}</div> : <p>No evidence observations are exposed for this decision.</p>}</ResultSection></> : scanUnavailable && <div className="alert alert-warning"><WarningCircle aria-hidden /><span><strong>Scan evidence is unavailable.</strong>The case record remains accessible, but its linked scan could not be read.</span></div>}
      <section className="card event-panel"><div className="section-heading"><div><p className="eyebrow">Append-only history</p><h2>Case events</h2></div><span className="badge badge-neutral">{reviewCase.events.length}</span></div>{reviewCase.events.length ? <ol className="event-list">{reviewCase.events.map((event) => <li key={event.id}><div><strong>{event.action.replaceAll("_", " ")}</strong><time dateTime={event.created_at}>{formatDate(event.created_at)}</time></div>{event.detail.outcome && <p>Outcome: {event.detail.outcome}</p>}{event.detail.note && <p>{event.detail.note}</p>}{event.detail.evidence_ids?.length ? <p>Cited evidence: {event.detail.evidence_ids.join(", ")}</p> : null}</li>)}</ol> : <p className="muted-copy">No case events have been recorded.</p>}</section>
    </section><aside className="card review-panel"><h2>Record review action</h2><p className="claim-state"><CheckCircle aria-hidden weight="fill" />{isClosed ? "Adjudicated" : isMine ? "Claimed by you" : reviewCase.claimed_by ? `Claimed (${reviewCase.claimed_by.slice(0, 12)}…)` : "Unassigned"}</p>{!isMine && !isClosed && <div className="alert alert-info"><Info aria-hidden />Claim this case before revealing the URL or recording an adjudication.</div>}{isMine && !isClosed && <><label className="field"><span>Adjudication</span><select value={outcome} onChange={(event) => setOutcome(event.target.value as typeof outcome)}><option value="">Select a decision</option><option value="MALICIOUS">Malicious</option><option value="BENIGN">Benign</option><option value="INCONCLUSIVE">Inconclusive</option></select></label><label className="field"><span>Rationale</span><textarea rows={7} minLength={20} maxLength={2000} value={note} onChange={(event) => setNote(event.target.value)} placeholder="Explain how the cited evidence supports the decision." /><small className="character-count">{note.trim().length} / 20 minimum</small></label><fieldset className="citation-field"><legend>Cited decision evidence</legend>{scan?.decision.reasons.map((reason, index) => <label key={`reason:${index}`}><input type="checkbox" checked={evidenceIds.includes(`reason:${index}`)} onChange={() => toggleEvidence(`reason:${index}`)} /><span><strong>Decision reason {index + 1}</strong><small>{reason}</small></span></label>)}{scan?.decision.evidence.map((item) => <label key={item.id}><input type="checkbox" checked={evidenceIds.includes(item.id)} onChange={() => toggleEvidence(item.id)} /><span><strong>{evidenceName(item)}</strong><small>{item.id}</small></span></label>)}{!scan?.decision.reasons.length && !scan?.decision.evidence.length && <p>No citable decision evidence is available.</p>}</fieldset>{actionError && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{actionError}</div>}<div className="stacked-actions"><button className="button button-secondary" type="button" disabled={busy || !note.trim()} onClick={() => act({ action: "annotate", note: note.trim() })}>Add note</button><button className="button button-primary" type="button" disabled={busy || !outcome || note.trim().length < 20 || evidenceIds.length === 0} onClick={() => outcome && act({ action: "adjudicate", outcome, note: note.trim(), evidence_ids: evidenceIds })}>{busy ? "Saving…" : "Record adjudication"}</button></div></>}</aside></div>
    {pendingSensitiveAction && <FreshAuthDialog action={pendingSensitiveAction} close={() => setPendingSensitiveAction(null)} />}
  </div>;
}

function Metric({ label, value, detail, icon: MetricIcon }: { label: string; value: string; detail: string; icon: Icon }) {
  return <article className="metric-card"><div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div><span className="metric-icon"><MetricIcon aria-hidden /></span></article>;
}

type SensitiveActionRunner = (action: () => Promise<void>) => Promise<void>;

function FreshAuthDialog({ action, close }: { action: () => Promise<void>; close: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const configured = identityConfigured();
  const [stage, setStage] = useState<"password" | "totp">("password");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [factor, setFactor] = useState("Authenticator app");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (typeof dialog.current?.showModal === "function") dialog.current.showModal();
    else dialog.current?.setAttribute("open", "");
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (stage === "password") {
        const result = await beginSessionReauthentication(password);
        setPassword("");
        if (result.mfaRequired) {
          setFactor(result.factorName);
          setStage("totp");
          return;
        }
      } else {
        await completeSessionReauthentication(code);
      }
      await action();
      if (typeof dialog.current?.close === "function") dialog.current.close();
      close();
    } catch (reason) {
      setError(reason instanceof IdentityError || reason instanceof ApiError ? reason.message : "Verification or the protected change could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  return <dialog ref={dialog} className="dialog fresh-auth-dialog" onCancel={(event) => { event.preventDefault(); close(); }}>
    <form onSubmit={submit}>
      <div className="dialog-icon"><LockKey aria-hidden /></div>
      <h2>Verify it’s you</h2>
      <p>{stage === "password" ? "Protected changes require authentication within the last five minutes." : `Enter the current code from ${factor}.`}</p>
      {stage === "password" ? <label className="field"><span>Identity Platform password</span><input type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></label> : <label className="field"><span>6-digit verification code</span><input className="code-input" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} /></label>}
      <p className="reauth-privacy"><LockKey aria-hidden />Your password is sent directly to Google Identity Platform. PhishGuard receives only a verified ID token.</p>
      {!configured && <div className="alert alert-warning" role="status"><Info aria-hidden />Identity Platform is not configured for this build.</div>}
      {error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}
      <div className="dialog-actions"><button className="button button-secondary" type="button" onClick={close}>Cancel</button><button className="button button-primary" type="submit" disabled={busy || !configured}>{busy ? "Verifying…" : stage === "password" ? "Continue" : "Verify and retry"}</button></div>
    </form>
  </dialog>;
}

function AdminPage() {
  const [tab, setTab] = useState("Overview");
  const [pendingAction, setPendingAction] = useState<(() => Promise<void>) | null>(null);
  const tabs = ["Overview", "Users", "Role requests", "Providers", "Policies & models", "Audit"];
  const runSensitive: SensitiveActionRunner = async (action) => {
    try {
      await action();
    } catch (reason) {
      if (reason instanceof ApiError && reason.code === "fresh_auth_required") {
        setPendingAction(() => action);
        return;
      }
      throw reason;
    }
  };
  return <div className="page workspace-page"><PageHeader eyebrow="System administration" title="Control centre" description="Manage persisted governed configuration and inspect the health data exposed by the API." /><div className="tabs" aria-label="Administration sections">{tabs.map((item) => <button type="button" className={tab === item ? "active" : ""} key={item} onClick={() => setTab(item)}>{item}</button>)}</div>{tab === "Overview" ? <AdminOverview /> : tab === "Users" ? <AdminUsers runSensitive={runSensitive} /> : tab === "Role requests" ? <AdminRoleRequests runSensitive={runSensitive} /> : tab === "Providers" ? <AdminProviders runSensitive={runSensitive} /> : tab === "Policies & models" ? <AdminReleases runSensitive={runSensitive} /> : <AdminAudit />}{pendingAction && <FreshAuthDialog action={pendingAction} close={() => setPendingAction(null)} />}</div>;
}

function AdminOverview() {
  const [health, setHealth] = useState<AdminHealth | null>(null);
  const [error, setError] = useState("");
  function load() { setHealth(null); setError(""); api.getAdminHealth().then(setHealth).catch((reason) => setError(apiMessage(reason, "Administrative health could not be loaded."))); }
  useEffect(load, []);
  if (!health && !error) return <div className="skeleton skeleton-panel" aria-label="Loading administrative health" />;
  if (error) return <WorkspaceFailure message={error} retry={load} />;
  if (!health) return null;
  const jobTotal = Object.values(health.jobs).reduce((total, count) => total + count, 0);
  const canonicalStatus = health.canonical_admin?.status;
  const canonicalLabel = canonicalStatus === "CONFIGURED" ? "Configured" : canonicalStatus === "MISSING" ? "Missing" : "Not reported";
  const canonicalDetail = health.canonical_admin ? `${health.canonical_admin.count} canonical administrator record` : "Older health contract";
  const provider = health.provider_telemetry?.google_web_risk;
  return <><div className="metric-grid four"><Metric label="Database" value={health.database} detail="API connectivity check" icon={HardDrives} /><Metric label="Recorded jobs" value={String(jobTotal)} detail="Across persisted states" icon={ListChecks} /><Metric label="Decisions (7 d)" value={String(health.decisions_7d ?? 0)} detail="Latest decision per analysis run" icon={ShieldCheck} /><Metric label="Active sessions" value={String(health.active_user_sessions ?? 0)} detail={`Checked ${formatDate(health.checked_at)}`} icon={UsersThree} /></div><div className="admin-grid"><section className="card"><div className="section-heading"><div><p className="eyebrow">PostgreSQL queue</p><h2>Jobs by state</h2></div></div><DistributionList entries={health.jobs} empty="No persisted scan jobs were reported." /></section><section className="card"><div className="section-heading"><div><p className="eyebrow">Latest run decision</p><h2>Scan outcomes (7 days)</h2></div></div><DistributionList entries={health.outcomes_7d ?? {}} empty="No decisions were recorded in this period." /></section><section className="card"><div className="section-heading"><div><p className="eyebrow">Observed provenance</p><h2>Decisions by model version</h2></div></div><DistributionList entries={health.model_versions_7d ?? {}} empty="No model-version observations were recorded." /></section><section className="card"><div className="section-heading"><div><p className="eyebrow">Google Web Risk</p><h2>Provider outcomes</h2></div><span className="badge badge-neutral">{provider?.observations_7d ?? 0} checks</span></div><DistributionList entries={provider?.states ?? {}} empty="No provider observations were recorded in this period." />{provider?.last_retrieved_at && <p className="muted-copy">Last retrieved {formatDate(provider.last_retrieved_at)}</p>}</section></div><div className={`alert admin-health-alert ${canonicalStatus === "MISSING" ? "alert-danger" : "alert-info"}`}><Info aria-hidden /><span><strong>Canonical administrator: {canonicalLabel}.</strong>{canonicalStatus === "MISSING" ? "Bootstrap an administrator before relying on in-app governance." : canonicalStatus === "CONFIGURED" ? `${canonicalDetail}; the protected trust anchor is present.` : "Upgrade the backend to expose the canonical administrator check."}</span></div></>;
}

function DistributionList({ entries, empty }: { entries: Record<string, number>; empty: string }) {
  const total = Object.values(entries).reduce((sum, value) => sum + value, 0);
  return Object.keys(entries).length ? <dl className="distribution-list">{Object.entries(entries).sort((left, right) => right[1] - left[1]).map(([label, value]) => <div key={label}><dt><span>{label.replaceAll("_", " ")}</span><small>{value}</small></dt><dd><span style={{ width: `${total ? Math.max(3, value / total * 100) : 0}%` }} /></dd></div>)}</dl> : <p className="muted-copy">{empty}</p>;
}

function AdminUsers({ runSensitive }: { runSensitive: SensitiveActionRunner }) {
  const session = useSession();
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [error, setError] = useState("");
  function load() { setUsers(null); setError(""); api.listAdminUsers().then(setUsers).catch((reason) => setError(apiMessage(reason, "Users could not be loaded."))); }
  useEffect(load, []);
  if (!users && !error) return <div className="skeleton skeleton-panel" aria-label="Loading users" />;
  if (error) return <WorkspaceFailure message={error} retry={load} />;
  if (!users?.length) return <WorkspaceEmpty title="No users" detail="No application user accounts were returned." />;
  return <section className="card admin-table-section"><div className="section-heading"><div><h2>Users and roles</h2><p>Identity is represented by opaque application IDs; email addresses are not exposed here.</p></div></div><div className="governance-list">{users.map((user) => <AdminUserRow key={user.id} user={user} canManageAdministrators={Boolean(session.me?.is_canonical_admin)} runSensitive={runSensitive} update={(next) => setUsers((current) => current?.map((item) => item.id === next.id ? { ...item, ...next } : item) ?? null)} />)}</div></section>;
}

function AdminUserRow({ user, update, runSensitive, canManageAdministrators }: { user: AdminUser; update: (value: Pick<AdminUser, "id" | "role" | "disabled">) => void; runSensitive: SensitiveActionRunner; canManageAdministrators: boolean }) {
  const editable = !user.is_canonical_admin && (user.role !== "ADMINISTRATOR" || canManageAdministrators);
  const [role, setRole] = useState<AssignableRole>(user.role);
  const [disabled, setDisabled] = useState(user.disabled);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  async function save() { setBusy(true); setError(""); try { await runSensitive(async () => { const result = await api.updateAdminUser(user.id, role, disabled); update(result); }); } catch (reason) { setError(apiMessage(reason, "The user could not be updated.")); } finally { setBusy(false); } }
  async function revokeSessions() { setBusy(true); setError(""); setNotice(""); try { await runSensitive(async () => { const result = await api.revokeUserSessions(user.id); setNotice(`${result.revoked_session_count} active session${result.revoked_session_count === 1 ? "" : "s"} revoked.`); }); } catch (reason) { setError(apiMessage(reason, "Sessions could not be revoked.")); } finally { setBusy(false); } }
  return <article className="governance-row"><div><strong className="mono">{user.id}</strong><small>Created {formatDate(user.created_at)} · email {user.email_verified ? "verified" : "not verified"} · MFA {user.mfa_verified ? "verified" : "not verified"}</small>{user.role_request?.state === "PENDING" && <small>Pending request: {roleLabel(user.role_request.requested_role)}</small>}</div>{editable ? <><label><span className="sr-only">Role for {user.id}</span><select value={role} onChange={(event) => setRole(event.target.value as AssignableRole)}><option value="REGISTERED_USER">Registered user</option><option value="ANALYST">Analyst</option><option value="RESEARCHER">Researcher</option><option value="ADMINISTRATOR">Administrator</option></select></label><label className="checkbox-row compact-checkbox"><input type="checkbox" checked={disabled} onChange={(event) => setDisabled(event.target.checked)} /> Disabled</label><div className="row-actions"><button className="button button-secondary button-small" type="button" disabled={busy} onClick={revokeSessions}>Revoke sessions</button><button className="button button-primary button-small" type="button" disabled={busy} onClick={save}>{busy ? "Saving…" : "Save"}</button></div></> : <><span className="badge badge-neutral">{user.is_canonical_admin ? "Canonical administrator" : "Administrator"}</span><small>{user.is_canonical_admin ? "Immutable in application UI" : "Canonical administrator approval required"}</small></>}{notice && <div className="alert alert-success row-alert" role="status"><CheckCircle aria-hidden />{notice}</div>}{error && <div className="alert alert-danger row-alert" role="alert"><WarningCircle aria-hidden />{error}</div>}</article>;
}

function AdminRoleRequests({ runSensitive }: { runSensitive: SensitiveActionRunner }) {
  const [requests, setRequests] = useState<RoleRequest[] | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  function load() {
    setRequests(null);
    setError("");
    api.listRoleRequests("PENDING").then(setRequests).catch((reason) => setError(apiMessage(reason, "Role requests could not be loaded.")));
  }
  useEffect(load, []);

  async function decide(request: RoleRequest, action: "APPROVE" | "REJECT") {
    setBusy(request.id);
    setError("");
    try {
      await runSensitive(async () => {
        await api.decideRoleRequest(request.id, action);
        setRequests((current) => current?.filter((item) => item.id !== request.id) ?? null);
      });
    } catch (reason) {
      setError(apiMessage(reason, "The role request could not be decided."));
    } finally {
      setBusy("");
    }
  }

  if (!requests && !error) return <div className="skeleton skeleton-panel" role="status" aria-label="Loading role requests" />;
  if (error && !requests) return <WorkspaceFailure message={error} retry={load} />;
  if (!requests?.length) return <WorkspaceEmpty title="No pending role requests" detail="New analyst and researcher requests will appear here." />;
  return <section className="card admin-table-section"><div className="section-heading"><div><h2>Pending role requests</h2><p>Approval assigns the requested role. Verified email and TOTP remain mandatory for privileged sessions.</p></div></div>{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}<div className="governance-list">{requests.map((request) => <article className="governance-row role-request-row" key={request.id}><div><strong>{roleLabel(request.requested_role)} request</strong><small className="mono">User {request.user_id}</small><small>Requested {formatDate(request.requested_at)}</small></div><span className="badge badge-medium">Pending</span><div className="row-actions"><button className="button button-secondary button-small" type="button" disabled={busy === request.id} onClick={() => decide(request, "REJECT")}>Reject</button><button className="button button-primary button-small" type="button" disabled={busy === request.id} onClick={() => decide(request, "APPROVE")}>{busy === request.id ? "Saving…" : "Approve"}</button></div></article>)}</div></section>;
}

function AdminProviders({ runSensitive }: { runSensitive: SensitiveActionRunner }) {
  const [providers, setProviders] = useState<ProviderConfiguration[] | null>(null);
  const [telemetry, setTelemetry] = useState<AdminHealth["provider_telemetry"]>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  function load() { setProviders(null); setError(""); Promise.all([api.listProviders(), api.getAdminHealth()]).then(([items, health]) => { setProviders(items); setTelemetry(health.provider_telemetry); }).catch((reason) => setError(apiMessage(reason, "Provider configuration could not be loaded."))); }
  useEffect(load, []);
  async function toggle(provider: ProviderConfiguration) { setBusy(provider.provider); setError(""); try { await runSensitive(async () => { const next = await api.updateProvider(provider.provider, !provider.enabled, provider.config); setProviders((items) => items?.map((item) => item.provider === next.provider ? next : item) ?? [next]); }); } catch (reason) { setError(apiMessage(reason, "Provider configuration could not be changed.")); } finally { setBusy(""); } }
  if (!providers && !error) return <div className="skeleton skeleton-panel" aria-label="Loading providers" />;
  return <section className="card admin-table-section"><div className="section-heading"><div><h2>Runtime reputation providers</h2><p>Persisted controls and URL-free outcomes from the last seven days.</p></div></div>{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}{providers?.length ? <div className="governance-list">{providers.map((provider) => { const status = telemetry?.[provider.provider]; return <article className="provider-row" key={provider.id}><div><strong>{provider.provider.replaceAll("_", " ")}</strong><small>Updated {formatDate(provider.updated_at)} · {Object.keys(provider.config).length} non-secret configuration fields</small></div><div><span className={`badge ${provider.enabled ? "badge-low" : "badge-neutral"}`}>{provider.enabled ? "Enabled" : "Disabled"}</span><button className="button button-secondary button-small" type="button" disabled={busy === provider.provider} onClick={() => toggle(provider)}>{busy === provider.provider ? "Saving…" : provider.enabled ? "Disable" : "Enable"}</button></div><div className="provider-stats"><span><strong>{status?.observations_7d ?? 0}</strong><small>Checks (7 d)</small></span><span><strong>{status ? Object.values(status.states).reduce((sum, count) => sum + count, 0) : 0}</strong><small>Recorded outcomes</small></span><span><strong>{status?.last_retrieved_at ? formatDate(status.last_retrieved_at) : "Never"}</strong><small>Last retrieval</small></span></div><DistributionList entries={status?.states ?? {}} empty="No outcomes recorded." /></article>; })}</div> : !error && <WorkspaceEmpty title="No persisted provider configuration" detail="The API returned no provider records. Runtime defaults are intentionally not inferred." />}</section>;
}

function AdminReleases({ runSensitive }: { runSensitive: SensitiveActionRunner }) {
  const [policies, setPolicies] = useState<DecisionPolicy[] | null>(null);
  const [models, setModels] = useState<ModelRelease[] | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");
  const [policyVersion, setPolicyVersion] = useState("");
  const [policyConfig, setPolicyConfig] = useState('{\n  "low_threshold": 0.35,\n  "high_threshold": 0.7\n}');
  const [modelVersion, setModelVersion] = useState("");
  const [artifactUri, setArtifactUri] = useState("");
  const [sha256, setSha256] = useState("");
  const [modelMetrics, setModelMetrics] = useState('{\n  "recall": 0.9,\n  "false_positive_rate": 0.05,\n  "pr_auc": 0.9,\n  "expected_calibration_error": 0.1\n}');
  const [gates, setGates] = useState({ data: false, feature: false, evaluation: false, security: false });
  function load() { setPolicies(null); setModels(null); setError(""); Promise.all([api.listDecisionPolicies(), api.listModels()]).then(([nextPolicies, nextModels]) => { setPolicies(nextPolicies); setModels(nextModels); }).catch((reason) => setError(apiMessage(reason, "Policy and model registries could not be loaded."))); }
  useEffect(load, []);
  async function createPolicy(event: FormEvent) { event.preventDefault(); setBusy("policy-create"); setError(""); setNotice(""); try { const config = parseJsonObject(policyConfig, "Policy configuration"); await runSensitive(async () => { const created = await api.createDecisionPolicy(policyVersion, config); setPolicies((items) => [created, ...(items ?? [])]); setPolicyVersion(""); setNotice(`Policy ${created.version} registered.`); }); } catch (reason) { setError(apiMessage(reason, reason instanceof Error ? reason.message : "The policy could not be registered.")); } finally { setBusy(""); } }
  async function approvePolicy(policy: DecisionPolicy) { setBusy(policy.id); setError(""); setNotice(""); try { await runSensitive(async () => { const next = await api.activateDecisionPolicy(policy.id); setPolicies((items) => items?.map((item) => item.id === next.id ? next : { ...item, active: false }) ?? [next]); setNotice(`${policy.version} approved as the deployment policy pointer.`); }); } catch (reason) { setError(apiMessage(reason, "The policy approval could not be changed.")); } finally { setBusy(""); } }
  async function registerModel(event: FormEvent) { event.preventDefault(); setBusy("model-create"); setError(""); setNotice(""); try { const metrics = { ...parseJsonObject(modelMetrics, "Model metrics"), gates }; await runSensitive(async () => { const created = await api.registerModel(modelVersion, artifactUri, sha256, metrics); setModels((items) => [created, ...(items ?? [])]); setModelVersion(""); setArtifactUri(""); setSha256(""); setNotice(`Model ${created.version} registered for governance review.`); }); } catch (reason) { setError(apiMessage(reason, reason instanceof Error ? reason.message : "The model could not be registered.")); } finally { setBusy(""); } }
  async function activate(model: ModelRelease) { setBusy(model.id); setError(""); setNotice(""); try { await runSensitive(async () => { const next = await api.activateModel(model.id); setModels((items) => items?.map((item) => item.id === next.id ? next : { ...item, approved_for_deployment: false }) ?? [next]); setNotice(`${model.version} approved. Deploy its checksum-pinned overlay before it can affect runtime decisions.`); }); } catch (reason) { setError(apiMessage(reason, "The model approval could not be changed.")); } finally { setBusy(""); } }
  if ((!policies || !models) && !error) return <div className="skeleton skeleton-panel" aria-label="Loading release registries" />;
  if (error && !policies && !models) return <WorkspaceFailure message={error} retry={load} />;
  const activeModel = models?.find((model) => model.approved_for_deployment);
  return <><div className="alert alert-warning"><WarningCircle aria-hidden /><span><strong>Approval is not runtime activation.</strong>A trusted checksum-pinned deployment is still required before a model or policy affects decisions.</span></div>{notice && <div className="alert alert-success release-notice" role="status"><CheckCircle aria-hidden />{notice}</div>}{error && <div className="alert alert-danger release-notice" role="alert"><WarningCircle aria-hidden />{error}</div>}<div className="release-columns"><section className="card release-panel"><div className="section-heading"><div><h2>Decision policies</h2><p>Register immutable configuration, then approve a deployment pointer.</p></div></div><form className="compact-form" onSubmit={createPolicy}><label className="field"><span>Version</span><input required pattern="[A-Za-z0-9._-]{1,64}" value={policyVersion} onChange={(event) => setPolicyVersion(event.target.value)} placeholder="policy-2026.08" /></label><label className="field"><span>Configuration JSON</span><textarea rows={5} required value={policyConfig} onChange={(event) => setPolicyConfig(event.target.value)} /></label><button className="button button-primary" disabled={busy === "policy-create"}>{busy === "policy-create" ? "Registering…" : "Register policy"}</button></form>{policies?.length ? <div className="governance-list release-list">{policies.map((policy) => <article className="registry-row" key={policy.id}><div><strong>{policy.version}</strong><small>{formatDate(policy.created_at)} · {Object.keys(policy.config).length} configuration fields</small></div>{policy.active ? <span className="badge badge-low">Deployment pointer</span> : <button className="button button-secondary button-small" type="button" disabled={busy === policy.id} onClick={() => approvePolicy(policy)}>{busy === policy.id ? "Saving…" : "Approve / roll back"}</button>}</article>)}</div> : <p className="muted-copy">No policy records were returned.</p>}</section><section className="card release-panel"><div className="section-heading"><div><h2>Model releases</h2><p>Register checksum-pinned artifacts and record every governance gate.</p></div></div><form className="compact-form" onSubmit={registerModel}><div className="form-pair"><label className="field"><span>Version</span><input required pattern="[A-Za-z0-9._-]{1,128}" value={modelVersion} onChange={(event) => setModelVersion(event.target.value)} placeholder="url-logistic-1.1" /></label><label className="field"><span>Artifact URI</span><input required value={artifactUri} onChange={(event) => setArtifactUri(event.target.value)} placeholder="gs://bucket/model.joblib" /></label></div><label className="field"><span>SHA-256</span><input className="mono" required pattern="[0-9a-f]{64}" minLength={64} maxLength={64} value={sha256} onChange={(event) => setSha256(event.target.value.toLowerCase())} /></label><label className="field"><span>Evaluation metrics JSON</span><textarea rows={5} required value={modelMetrics} onChange={(event) => setModelMetrics(event.target.value)} /></label><fieldset className="gate-checks"><legend>Governance gate evidence</legend>{Object.keys(gates).map((gate) => <label key={gate}><input type="checkbox" checked={gates[gate as keyof typeof gates]} onChange={(event) => setGates((current) => ({ ...current, [gate]: event.target.checked }))} />{roleLabel(gate)} gate passed</label>)}</fieldset><button className="button button-primary" disabled={busy === "model-create"}>{busy === "model-create" ? "Registering…" : "Register model"}</button></form>{models?.length ? <div className="governance-list release-list">{models.map((model) => { const modelGates = model.metrics.gates && typeof model.metrics.gates === "object" ? model.metrics.gates as Record<string, unknown> : {}; return <article className="model-release" key={model.id}><div><strong>{model.version}</strong><small className="mono">SHA-256 {model.sha256.slice(0, 16)}…</small><small className="mono">{model.artifact_uri}</small></div><div className="model-gates">{["data", "feature", "evaluation", "security"].map((gate) => <span className={`badge ${modelGates[gate] === true ? "badge-low" : "badge-high"}`} key={gate}>{modelGates[gate] === true ? <Check aria-hidden /> : <XCircle aria-hidden />}{gate}</span>)}</div>{model.approved_for_deployment ? <span className="badge badge-low">Approved for deployment</span> : <button className="button button-secondary button-small" type="button" disabled={busy === model.id} onClick={() => activate(model)}>{busy === model.id ? "Saving…" : activeModel ? "Approve as rollback / replacement" : "Approve for deployment"}</button>}</article>; })}</div> : <p className="muted-copy">No model releases were returned.</p>}</section></div></>;
}

function AdminAudit() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [verification, setVerification] = useState<{ valid: boolean; checked_events: number; failed_event_id: string | null; head_hmac: string | null; verified_at: string } | null>(null);
  const [verifying, setVerifying] = useState(false);
  function load(search = query) { setEvents(null); setError(""); api.listAuditEvents(search).then(setEvents).catch((reason) => setError(apiMessage(reason, "Audit events could not be loaded."))); }
  useEffect(load, []);
  async function verify() { setVerifying(true); setError(""); try { setVerification(await api.verifyAuditEvents()); } catch (reason) { setError(apiMessage(reason, "The audit chain could not be verified.")); } finally { setVerifying(false); } }
  if (!events && !error) return <div className="skeleton skeleton-panel" aria-label="Loading audit events" />;
  if (error) return <WorkspaceFailure message={error} retry={load} />;
  return <><div className="toolbar card"><form className="search-field" onSubmit={(event) => { event.preventDefault(); load(query); }}><MagnifyingGlass aria-hidden /><input aria-label="Search audit events" maxLength={100} placeholder="Search action, object, outcome, or correlation ID" value={query} onChange={(event) => setQuery(event.target.value)} /></form><button className="button button-secondary" type="button" onClick={verify} disabled={verifying}><ShieldCheck aria-hidden />{verifying ? "Verifying…" : "Verify hash chain"}</button></div>{verification && <div className={`alert ${verification.valid ? "alert-success" : "alert-danger"} audit-verification`} role="status">{verification.valid ? <CheckCircle aria-hidden /> : <XCircle aria-hidden />}<span><strong>{verification.valid ? "Audit chain verified." : "Audit chain verification failed."}</strong>{verification.checked_events} events checked at {formatDate(verification.verified_at)}{verification.failed_event_id ? ` · first failure ${verification.failed_event_id}` : ""}{verification.head_hmac ? <small className="mono">Head HMAC {verification.head_hmac}</small> : null}</span></div>}<section className="card admin-table-section"><div className="section-heading"><div><h2>Audit events</h2><p>Latest 200 matching privileged events with chain provenance.</p></div></div>{events?.length ? <ol className="event-list audit-list">{events.map((event) => <li key={event.id}><div><strong>{event.action.replaceAll("_", " ")}</strong><time dateTime={event.created_at}>{formatDate(event.created_at)}</time></div><p>{event.object_type}{event.object_id ? ` · ${event.object_id}` : ""} · {event.outcome}</p><small className="mono">Correlation {event.correlation_id}</small>{event.event_hmac && <details><summary>Chain hashes</summary><code>Previous: {event.previous_hmac ?? "genesis"}{"\n"}Event: {event.event_hmac}</code></details>}</li>)}</ol> : <p className="muted-copy">No audit events matched this search.</p>}</section></>;
}

function ResearchPage() {
  const [datasets, setDatasets] = useState<DatasetSnapshot[] | null>(null);
  const [experiments, setExperiments] = useState<Experiment[] | null>(null);
  const [exports, setExports] = useState<ResearchExport[] | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [tab, setTab] = useState<"Datasets" | "Experiments" | "Results" | "Model cards" | "Exports">("Datasets");
  const [pendingAction, setPendingAction] = useState<(() => Promise<void>) | null>(null);
  function load() { setDatasets(null); setExperiments(null); setExports(null); setError(""); Promise.all([api.listDatasets(), api.listExperiments(), api.listResearchExports()]).then(([nextDatasets, nextExperiments, nextExports]) => { setDatasets(nextDatasets); setExperiments(nextExperiments); setExports(nextExports); }).catch((reason) => setError(apiMessage(reason, "Research records could not be loaded."))); }
  useEffect(load, []);
  if ((!datasets || !experiments || !exports) && !error) return <div className="page workspace-page"><div className="skeleton skeleton-panel" aria-label="Loading research workspace" /></div>;
  if (error) return <div className="page workspace-page"><PageHeader eyebrow="Research workspace" title="Datasets and experiments" description="Inspect persisted research governance records." /><WorkspaceFailure message={error} retry={load} /></div>;
  if (!datasets || !experiments || !exports) return null;
  const tabs = ["Datasets", "Experiments", "Results", "Model cards", "Exports"] as const;
  const runSensitive: SensitiveActionRunner = async (action) => {
    try { await action(); } catch (reason) {
      if (reason instanceof ApiError && reason.code === "fresh_auth_required") { setPendingAction(() => action); return; }
      throw reason;
    }
  };
  return (
    <div className="page workspace-page">
      <PageHeader
        eyebrow="Research workspace"
        title="Research and evaluation"
        description="Create frozen records, run the on-demand evaluator, inspect measured outputs, and request governed exports."
        actions={<button className="button button-secondary" type="button" onClick={load}>Refresh</button>}
      />
      {notice && <div className="alert alert-success research-notice" role="status"><CheckCircle aria-hidden />{notice}</div>}
      <div className="metric-grid">
        <Metric label="Dataset snapshots" value={String(datasets.length)} detail="Frozen registry records" icon={Database} />
        <Metric label="Experiments" value={String(experiments.length)} detail={`${experiments.filter((item) => item.state === "COMPLETE").length} complete`} icon={Flask} />
        <Metric label="Governed exports" value={String(exports.length)} detail={`${exports.filter((item) => Boolean(item.artifact_uri)).length} artifacts available`} icon={FileText} />
      </div>
      <div className="tabs" aria-label="Research sections">
        {tabs.map((item) => <button type="button" className={tab === item ? "active" : ""} key={item} onClick={() => setTab(item)}>{item}</button>)}
      </div>
      {tab === "Datasets" ? (
        <ResearchDatasets items={datasets} add={(item) => {
          setDatasets((current) => [item, ...(current ?? [])]);
          setNotice(`Dataset snapshot ${item.name} registered.`);
        }} />
      ) : tab === "Experiments" ? (
        <ResearchExperiments items={experiments} datasets={datasets} add={(item) => {
          setExperiments((current) => [item, ...(current ?? [])]);
          setNotice(`Experiment ${item.id} queued. Run make evaluate-next against the cluster to execute it.`);
        }} />
      ) : tab === "Results" ? (
        <ResearchResults items={experiments} />
      ) : tab === "Model cards" ? (
        <ResearchModelCards items={experiments} />
      ) : (
        <ResearchExports items={exports} runSensitive={runSensitive} add={(item) => {
          setExports((current) => [item, ...(current ?? [])]);
          setNotice(`Governed export ${item.id} queued.`);
        }} />
      )}
      {pendingAction && <FreshAuthDialog action={pendingAction} close={() => setPendingAction(null)} />}
    </div>
  );
}

function ResearchDatasets({ items, add }: { items: DatasetSnapshot[]; add: (item: DatasetSnapshot) => void }) {
  const [name, setName] = useState("");
  const [sha256, setSha256] = useState("");
  const [manifest, setManifest] = useState('{\n  "artifact_path": "input.csv",\n  "source": "OpenPhish Academic + Tranco",\n  "license_reviewed": false,\n  "label_provenance_reviewed": false\n}');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(""); try { const created = await api.createDataset(name, sha256, parseJsonObject(manifest, "Dataset manifest")); add(created); setName(""); setSha256(""); } catch (reason) { setError(apiMessage(reason, reason instanceof Error ? reason.message : "The dataset snapshot could not be registered.")); } finally { setBusy(false); } }
  return <div className="research-workspace"><form className="card research-form" onSubmit={submit}><div className="section-heading"><div><p className="eyebrow">Immutable input</p><h2>Register a dataset snapshot</h2><p>The mounted CSV is checksum-verified before evaluation.</p></div></div><div className="form-pair"><label className="field"><span>Name</span><input required value={name} onChange={(event) => setName(event.target.value)} placeholder="openphish-tranco-2026-07" /></label><label className="field"><span>SHA-256</span><input className="mono" required pattern="[0-9a-f]{64}" value={sha256} onChange={(event) => setSha256(event.target.value.toLowerCase())} /></label></div><label className="field"><span>Manifest JSON</span><textarea required rows={7} value={manifest} onChange={(event) => setManifest(event.target.value)} /></label>{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}<button className="button button-primary" disabled={busy}>{busy ? "Registering…" : "Register frozen snapshot"}</button></form><section className="card research-records"><div className="section-heading"><div><p className="eyebrow">Immutable inputs</p><h2>Dataset snapshots</h2></div></div>{items.length ? <div className="dataset-list">{items.map((item) => <div key={item.id}><span className="dataset-icon"><Database aria-hidden /></span><span><strong>{item.name}</strong><small>Created {formatDate(item.created_at)}</small></span><span><strong>{item.state.replaceAll("_", " ")}</strong><small className="mono">{item.sha256.slice(0, 16)}…</small></span><details><summary>Manifest</summary><pre>{JSON.stringify(item.manifest, null, 2)}</pre></details></div>)}</div> : <p className="muted-copy">No dataset snapshots were returned.</p>}</section></div>;
}

function ResearchExperiments({ items, datasets, add }: { items: Experiment[]; datasets: DatasetSnapshot[]; add: (item: Experiment) => void }) {
  const [datasetId, setDatasetId] = useState(datasets[0]?.id ?? "");
  const [config, setConfig] = useState('{\n  "seed": 20250722,\n  "max_expected_calibration_error": 0.1,\n  "max_brier_score": 0.1\n}');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(""); try { const created = await api.createExperiment(datasetId, parseJsonObject(config, "Experiment configuration")); add(created); } catch (reason) { setError(apiMessage(reason, reason instanceof Error ? reason.message : "The experiment could not be queued.")); } finally { setBusy(false); } }
  return <div className="research-workspace"><form className="card research-form" onSubmit={submit}><div className="section-heading"><div><p className="eyebrow">Reproducible execution</p><h2>Queue an experiment</h2><p>The suspended Kubernetes evaluator claims one queued experiment when <code>make evaluate-next</code> is run.</p></div></div><label className="field"><span>Frozen dataset</span><select required value={datasetId} onChange={(event) => setDatasetId(event.target.value)}><option value="">Select a dataset</option>{datasets.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label><label className="field"><span>Experiment configuration JSON</span><textarea required rows={7} value={config} onChange={(event) => setConfig(event.target.value)} /></label>{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}<button className="button button-primary" disabled={busy || !datasetId}>{busy ? "Queueing…" : "Queue experiment"}</button></form><section className="card research-records"><div className="section-heading"><div><p className="eyebrow">Recorded runs</p><h2>Experiments</h2></div></div>{items.length ? <div className="experiment-list">{items.map((item) => <div key={item.id}><span className={`experiment-icon ${["QUEUED", "RUNNING"].includes(item.state) ? "running" : ""}`}>{["QUEUED", "RUNNING"].includes(item.state) ? <Pulse aria-hidden /> : <Flask aria-hidden />}</span><span><strong className="mono">{item.id}</strong><small>{item.state.replaceAll("_", " ")} · dataset {item.dataset_id} · {formatDate(item.created_at)}</small></span><details><summary>Configuration</summary><pre>{JSON.stringify(item.config, null, 2)}</pre></details></div>)}</div> : <p className="muted-copy">No experiment records were returned.</p>}</section></div>;
}

function ResearchResults({ items }: { items: Experiment[] }) {
  const completed = items.filter((item) => item.state === "COMPLETE" && Object.keys(item.result).length);
  if (!completed.length) return <WorkspaceEmpty title="No completed experiment results" detail="Queue an experiment, run the on-demand Kubernetes evaluator, then refresh this workspace." />;
  return <div className="result-records">{completed.map((item) => { const selection = item.result.selection && typeof item.result.selection === "object" ? item.result.selection as Record<string, unknown> : {}; const locked = item.result.locked_test && typeof item.result.locked_test === "object" ? item.result.locked_test as Record<string, unknown> : {}; const metrics = locked.metrics && typeof locked.metrics === "object" ? locked.metrics as Record<string, unknown> : {}; const candidates = item.result.candidate_validation_metrics && typeof item.result.candidate_validation_metrics === "object" ? item.result.candidate_validation_metrics as Record<string, unknown> : {}; return <section className="card research-result" key={item.id}><div className="section-heading"><div><p className="eyebrow">Experiment {item.id}</p><h2>{String(selection.selected ?? "No candidate selected")}</h2><p>{String(selection.reason ?? "No selection reason recorded.")}</p></div><span className="badge badge-low">Complete</span></div><div className="metric-grid">{Object.entries(metrics).slice(0, 6).map(([name, value]) => <Metric key={name} label={name.replaceAll("_", " ")} value={formatMetric(value)} detail="Locked test set" icon={Pulse} />)}</div><div className="research-detail-grid"><details open><summary>Candidate baselines</summary><pre>{JSON.stringify(candidates, null, 2)}</pre></details><details><summary>Ablation and robustness</summary><pre>{JSON.stringify({ ablation: item.result.validation_ablation, robustness: locked.robustness, slices: locked.slices }, null, 2)}</pre></details><details><summary>Reproducibility manifest</summary><pre>{JSON.stringify(item.result, null, 2)}</pre></details></div></section>; })}</div>;
}

function ResearchModelCards({ items }: { items: Experiment[] }) {
  const candidates = items.filter((item) => item.state === "COMPLETE" && item.result.candidate_artifact);
  if (!candidates.length) return <WorkspaceEmpty title="No candidate model cards" detail="A model card becomes available only when a completed governed experiment selects a candidate." />;
  return <div className="model-card-list">{candidates.map((item) => { const artifact = item.result.candidate_artifact as Record<string, unknown>; const selection = item.result.selection as Record<string, unknown>; const dataset = item.result.dataset as Record<string, unknown>; return <article className="card model-card" key={item.id}><div className="section-heading"><div><p className="eyebrow">Research-only candidate</p><h2>{String(artifact.model_version ?? selection.selected)}</h2></div><span className="badge badge-medium">Not approved for production</span></div><dl className="technical-grid"><div><dt>Artifact SHA-256</dt><dd>{String(artifact.sha256 ?? "Not recorded")}</dd></div><div><dt>Dataset SHA-256</dt><dd>{String(dataset.raw_sha256 ?? "Not recorded")}</dd></div><div><dt>Rows / domains</dt><dd>{String(dataset.rows ?? "—")} / {String(dataset.domains ?? "—")}</dd></div><div><dt>Experiment</dt><dd>{item.id}</dd></div></dl><h3>Intended use</h3><p>Offline comparison of URL-only phishing classifiers under the recorded dataset, split, calibration, and selection protocol.</p><h3>Out of scope</h3><p>Direct runtime activation, autonomous blocking, or use outside the documented URL-only feature schema.</p><h3>Known limitations</h3><p>{String(dataset.known_domain_isolation_limitation ?? "See the complete experiment manifest for recorded limitations and slice results.")}</p><details><summary>Complete card evidence</summary><pre>{JSON.stringify(item.result, null, 2)}</pre></details></article>; })}</div>;
}

function ResearchExports({ items, add, runSensitive }: { items: ResearchExport[]; add: (item: ResearchExport) => void; runSensitive: SensitiveActionRunner }) {
  const [filters, setFilters] = useState('{\n  "consent_required": true,\n  "adjudicated_only": true,\n  "redacted_only": true\n}');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(""); try { const parsed = parseJsonObject(filters, "Export filters"); await runSensitive(async () => add(await api.createResearchExport(parsed))); } catch (reason) { setError(apiMessage(reason, reason instanceof Error ? reason.message : "The export could not be queued.")); } finally { setBusy(false); } }
  return <div className="research-workspace"><form className="card research-form" onSubmit={submit}><div className="section-heading"><div><p className="eyebrow">Governed extraction</p><h2>Request a redacted export</h2><p>Fresh authentication is required. The request never grants access to raw URLs.</p></div></div><label className="field"><span>Filters JSON</span><textarea required rows={7} value={filters} onChange={(event) => setFilters(event.target.value)} /></label>{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}<button className="button button-primary" disabled={busy}>{busy ? "Queueing…" : "Request export"}</button></form><section className="card research-records"><div className="section-heading"><div><h2>Governed exports</h2><p>Queued records remain unavailable until the export worker records an artifact.</p></div></div>{items.length ? <div className="governance-list">{items.map((item) => <article className="registry-row" key={item.id}><div><strong className="mono">{item.id}</strong><small>{item.expires_at ? `Expires ${formatDate(item.expires_at)}` : "No expiry recorded"}</small></div><span className="badge badge-neutral">{item.state.replaceAll("_", " ")}</span><small>{item.artifact_uri ? "Artifact recorded" : "No artifact recorded"}</small></article>)}</div> : <p className="muted-copy">No export records were returned.</p>}</section></div>;
}

function formatMetric(value: unknown) {
  if (typeof value !== "number") return String(value ?? "—");
  return value >= 0 && value <= 1 ? value.toFixed(3) : value.toLocaleString();
}

function NotFoundPage() {
  return <div className="page narrow-page"><div className="empty-state"><ShieldWarning aria-hidden /><h1>Page not found</h1><p>The page may have moved or you may not have access.</p><Link className="button button-primary" to="/">Return to scanner</Link></div></div>;
}

export function App() {
  return <SessionProvider><Shell><Routes><Route path="/" element={<ScanPage />} /><Route path="/how-it-works" element={<HowItWorksPage />} /><Route path="/scan/:id" element={<ResultPage />} /><Route path="/history" element={<HistoryPage />} /><Route path="/privacy" element={<PrivacyPage />} /><Route path="/account" element={<ProtectedRoute roles={registeredRoles}><AccountPage /></ProtectedRoute>} /><Route path="/sign-in" element={<SignInPage />} /><Route path="/totp" element={<ProtectedRoute roles={registeredRoles}><TotpPage /></ProtectedRoute>} /><Route path="/feedback/:scanId" element={<FeedbackPage />} /><Route path="/analyst/cases" element={<ProtectedRoute roles={analystRoles}><AnalystCasesPage /></ProtectedRoute>} /><Route path="/analyst/cases/:id" element={<ProtectedRoute roles={analystRoles}><AnalystCasePage /></ProtectedRoute>} /><Route path="/admin" element={<ProtectedRoute roles={administratorRoles}><AdminPage /></ProtectedRoute>} /><Route path="/research" element={<ProtectedRoute roles={researcherRoles}><ResearchPage /></ProtectedRoute>} /><Route path="/reports/:id" element={<ResultPage shared />} /><Route path="*" element={<NotFoundPage />} /></Routes></Shell></SessionProvider>;
}
