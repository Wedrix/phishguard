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
import {
  Link,
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
  type ModelRelease,
  type ProviderConfiguration,
  type ResearchExport,
  type ReviewAction,
  type ReviewCase,
  type ReviewCaseDetail,
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
  signOutIdentity,
} from "./identity";

const publicNavigation = [
  { to: "/", label: "Scan", icon: MagnifyingGlass },
  { to: "/history", label: "History", icon: ClockCounterClockwise },
  { to: "/account", label: "Account", icon: UserCircle },
];

const workspaceNavigation = [
  { to: "/analyst/cases", label: "Cases", icon: ListChecks },
  { to: "/admin", label: "Administration", icon: SlidersHorizontal },
  { to: "/research", label: "Research", icon: Flask },
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

function Shell({ children }: { children: ReactNode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const workspace = /^\/(analyst|admin|research)/.test(location.pathname);
  const navigation = workspace ? workspaceNavigation : publicNavigation;

  return (
    <div className="app" data-theme={workspace ? "dark" : "light"}>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="topbar">
        <Brand />
        <div className="topbar-actions">
          {workspace ? (
            <>
              <span className="environment"><Info aria-hidden weight="fill" /> Experimental workspace</span>
              <Link className="user-chip" to="/account"><UserCircle aria-hidden /><span className="user-copy"><strong>Account</strong><small>Role-protected session</small></span></Link>
            </>
          ) : (
            <Link className="button button-secondary button-small" to="/sign-in"><SignIn aria-hidden /> Sign in</Link>
          )}
        </div>
      </header>
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
              <button type="button" className="nav-item nav-button" onClick={async () => { await signOutIdentity(); navigate("/sign-in"); }}><SignOut aria-hidden /><span>Sign out</span></button>
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

function ProtectedRoute({ roles, children }: { roles: string[]; children: ReactNode }) {
  const [state, setState] = useState<"loading" | "allowed" | "denied">("loading");
  useEffect(() => {
    let active = true;
    api.me()
      .then((me) => { if (active) setState(roles.includes(me.role) ? "allowed" : "denied"); })
      .catch(() => { if (active) setState("denied"); });
    return () => { active = false; };
  }, [roles]);
  if (state === "loading") return <div className="page narrow-page"><div className="skeleton skeleton-panel" aria-label="Checking access" /></div>;
  if (state === "denied") return <div className="page narrow-page"><div className="empty-state card"><LockKey aria-hidden /><h1>Sign in required</h1><p>This workspace is available only to an authorised PhishGuard role.</p><Link className="button button-primary" to="/sign-in">Sign in</Link></div></div>;
  return <>{children}</>;
}

function RiskBadge({ risk }: { risk: RiskBand }) {
  const labels: Record<RiskBand, string> = { LOW: "Low risk", MEDIUM: "Needs caution", HIGH: "High risk", INCONCLUSIVE: "Inconclusive" };
  const BadgeIcon: Icon = risk === "LOW" ? CheckCircle : risk === "MEDIUM" ? WarningCircle : risk === "HIGH" ? XCircle : Info;
  return <span className={`badge badge-${risk.toLowerCase()}`}><BadgeIcon aria-hidden weight="fill" />{labels[risk]}</span>;
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
  const [url, setUrl] = useState("");
  const [mode, setMode] = useState<"local_only" | "enriched">("local_only");
  const [consent, setConsent] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

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
      navigate(`/scan/${response.scan.id}`, { state: { demo: response.demo } });
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "The scan could not be started. Try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page scan-page">
      <PageHeader eyebrow="Evidence-led link analysis" title="Check a link without opening it" description="PhishGuard examines the structure and available evidence behind a URL, then explains what matters." />
      <div className="scan-layout">
        <form className="card scan-card" onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="scan-url">URL to inspect</label>
            <div className="input-with-icon">
              <GlobeHemisphereWest aria-hidden />
              <input id="scan-url" type="url" inputMode="url" autoComplete="url" maxLength={4096} value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/account" required />
            </div>
            <p className="field-hint">Include http:// or https://. We never provide a link that opens the destination.</p>
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

        <aside className="evidence-aside" aria-label="How PhishGuard works">
          <p className="eyebrow">How it works</p>
          <h2>Evidence first. Verdict second.</h2>
          <ol className="step-list">
            <li><span>01</span><div><strong>Parse locally</strong><p>Normalize the URL and inspect structural indicators before any network request.</p></div></li>
            <li><span>02</span><div><strong>Collect safely</strong><p>Only with consent, gather bounded evidence through an isolated service.</p></div></li>
            <li><span>03</span><div><strong>Explain the result</strong><p>See reasons, counter-evidence, missing evidence and version provenance.</p></div></li>
          </ol>
          <div className="aside-callout"><ShieldCheck aria-hidden weight="fill" /><p><strong>Designed for uncertainty</strong>If evidence is missing, PhishGuard says so. Missing evidence is never treated as safe.</p></div>
        </aside>
      </div>
    </div>
  );
}

function ResultPage({ shared = false }: { shared?: boolean }) {
  const { id = "" } = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState("");
  const [pollingPause, setPollingPause] = useState<{ reason: "deadline" | "error"; message: string } | null>(null);
  const [pollCycle, setPollCycle] = useState(0);
  const [copied, setCopied] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [shareError, setShareError] = useState("");
  const [shareUrl, setShareUrl] = useState("");
  const [reportExpiresAt, setReportExpiresAt] = useState("");
  const shareDialog = useRef<HTMLDialogElement>(null);
  const loadedTarget = useRef<string | null>(null);

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

  if (error && !scan) return <div className="page narrow-page"><div className="empty-state"><XCircle aria-hidden /><h1>Scan unavailable</h1><p role="alert">{error}</p><div className="form-actions"><button className="button button-secondary" type="button" onClick={retryPolling}><ArrowClockwise aria-hidden /> Try again</button><Link className="button button-primary" to="/">Start a new scan</Link></div></div></div>;
  if (!scan) return <ResultSkeleton />;

  const { decision } = scan;
  const RiskIcon: Icon = decision.risk_band === "HIGH" ? XCircle : decision.risk_band === "MEDIUM" ? WarningCircle : decision.risk_band === "LOW" ? CheckCircle : Info;
  const title = decision.risk_band === "HIGH" ? "Strong phishing indicators found" : decision.risk_band === "MEDIUM" ? "Treat this link with caution" : decision.risk_band === "LOW" ? "No strong indicators found" : "There is not enough evidence";

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
      <div className="result-toolbar">
        <Link className="back-link" to="/"><CaretRight aria-hidden /> New scan</Link>
        {!shared && <div>
          <button className="button button-secondary" onClick={() => shareDialog.current?.showModal()}>Share report</button>
          <Link className="button button-secondary" to={`/feedback/${scan.id}`}>Give feedback</Link>
        </div>}
      </div>
      {(scan.simulated || scan.id.startsWith("demo-")) && <SimulatedDataBanner shared={shared} />}
      {shared && <div className="alert alert-info shared-report-note" role="status"><Eye aria-hidden /><span><strong>Read-only shared report.</strong> This redacted view expires {formatDate(reportExpiresAt)}.</span></div>}
      <section className={`risk-summary risk-${decision.risk_band.toLowerCase()}`} aria-labelledby="result-title">
        <div className="risk-icon"><RiskIcon aria-hidden weight="fill" /></div>
        <div className="risk-content">
          <div className="result-badges"><RiskBadge risk={decision.risk_band} /><StatusBadge status={scan.status} /><span className="badge badge-neutral">{decision.analysis_scope === "LOCAL_ONLY" ? "Local only" : "Enriched"}</span>{decision.engine_mode === "RULE_ONLY" && <span className="badge badge-medium"><ShieldWarning aria-hidden weight="fill" />Rule-only fallback</span>}</div>
          <h1 id="result-title">{title}</h1>
          <p className="display-url">{scan.display_url}{scan.ascii_display_url && <small>ASCII: {scan.ascii_display_url}</small>}</p>
          <p>{decision.reasons[0]}</p>
          {scan.status === "PROCESSING" && (pollingPause ? <div className={`alert ${pollingPause.reason === "error" ? "alert-danger" : "alert-warning"} polling-paused`} role={pollingPause.reason === "error" ? "alert" : "status"}><WarningCircle aria-hidden /><span><strong>Automatic updates paused.</strong>{pollingPause.message}</span><button className="button button-secondary button-small" type="button" onClick={retryPolling}><ArrowClockwise aria-hidden />Check again</button></div> : <div className="progress-note" role="status"><CircleNotch className="spinner" aria-hidden /><span><strong>Local analysis complete.</strong> Isolated enrichment is still collecting evidence. This page updates automatically.</span></div>)}
        </div>
      </section>

      <div className="result-grid">
        <section className="result-sections" aria-label="Analysis details">
          <ResultSection title="Reasons" icon={ShieldWarning} count={decision.reasons.length} open>
            <ul className="finding-list">{decision.reasons.map((reason, index) => <li key={reason}><span>{index + 1}</span><p>{reason}</p></li>)}</ul>
            {decision.counter_evidence.length > 0 && <div className="counter-evidence"><CheckCircle aria-hidden /><div><strong>Counter-evidence</strong>{decision.counter_evidence.map((item) => <p key={item}>{item}</p>)}</div></div>}
          </ResultSection>
          <ResultSection title="Evidence" icon={ClipboardText} count={decision.evidence.length}>
            <div className="evidence-table" role="table" aria-label="Evidence observations">
              <div className="evidence-row evidence-head" role="row"><span role="columnheader">Observation</span><span role="columnheader">State</span><span role="columnheader">Source</span></div>
              {decision.evidence.map((item) => <EvidenceRow key={item.id} item={item} />)}
            </div>
          </ResultSection>
          <ResultSection title="Limitations" icon={Info} count={decision.limitations.length + decision.missing_evidence.length}>
            {decision.missing_evidence.map((item) => <div className="alert alert-warning" key={item}><WarningCircle aria-hidden /><span>{item}</span></div>)}
            <ul className="plain-list">{decision.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
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
          <ul>{decision.safe_actions.map((action) => <li key={action}><Check aria-hidden /><span>{action}</span></li>)}</ul>
          <div className="alert alert-danger"><LockKey aria-hidden /><span><strong>Do not open the submitted link.</strong> Use a known address or verified bookmark instead.</span></div>
        </aside>
      </div>

      {!shared && <dialog ref={shareDialog} className="dialog" onClick={(event) => { if (event.target === shareDialog.current) shareDialog.current.close(); }}>
        <form method="dialog">
          <div className="dialog-icon"><Eye aria-hidden /></div>
          <h2>Share a redacted report</h2>
          <p>The temporary report does not reveal the original URL or account details.</p>
          <div className="copy-row"><code>{shareUrl || "A new unguessable link will be created."}</code>{shareUrl && <button type="button" className="icon-button" onClick={copyReport} aria-label="Copy report link">{copied ? <Check aria-hidden /> : <Copy aria-hidden />}</button>}</div>
          {reportExpiresAt && <p className="field-hint">Expires {formatDate(reportExpiresAt)}</p>}
          {shareError && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden /><span>{shareError}</span></div>}
          <div className="dialog-actions"><button className="button button-secondary" value="cancel">Cancel</button><button type="button" className="button button-primary" onClick={copyReport} disabled={sharing}>{sharing ? "Creating link…" : copied ? "Copied" : shareUrl ? "Copy link" : "Create and copy link"}</button></div>
        </form>
      </dialog>}
    </div>
  );
}

function ResultSkeleton() {
  return <div className="page result-page" aria-busy="true" aria-label="Loading scan result"><div className="skeleton skeleton-line short" /><div className="skeleton skeleton-hero" /><div className="skeleton skeleton-panel" /></div>;
}

function ResultSection({ title, icon: SectionIcon, count, open, children }: { title: string; icon: Icon; count?: number; open?: boolean; children: ReactNode }) {
  return <details className="result-section" open={open}><summary><span><SectionIcon aria-hidden />{title}{count !== undefined && <small>{count}</small>}</span><CaretRight className="section-caret" aria-hidden /></summary><div className="section-body">{children}</div></details>;
}

function EvidenceRow({ item }: { item: EvidenceObservation }) {
  const positive = item.state === "OBSERVED";
  return (
    <div className="evidence-row" role="row">
      <span role="cell"><strong>{item.label}</strong><small>{item.value}</small></span>
      <span role="cell"><span className={`evidence-state ${positive ? "state-observed" : ""}`}>{item.state.replaceAll("_", " ")}</span></span>
      <span role="cell"><span>{item.source}</span><small>{item.version}{item.observed_at ? ` · ${formatDate(item.observed_at)}` : ""}{item.cached ? " · cached" : ""}</small>{item.reason_code && <small>{item.reason_code.replaceAll("_", " ")}</small>}</span>
    </div>
  );
}

function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<Scan | null>(null);
  const [deleteError, setDeleteError] = useState("");
  const [deleting, setDeleting] = useState(false);
  const deleteDialog = useRef<HTMLDialogElement>(null);

  useEffect(() => { api.listScans().then(setScans).catch(() => setError("History could not be loaded.")).finally(() => setLoading(false)); }, []);
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

  return (
    <div className="page">
      <PageHeader eyebrow="Your account" title="Scan history" description="Only redacted URLs are shown here. Delete records whenever you no longer need them." actions={<Link className="button button-primary" to="/"><MagnifyingGlass aria-hidden /> New scan</Link>} />
      {scans.some((scan) => scan.simulated || scan.id.startsWith("demo-")) && <SimulatedDataBanner />}
      {error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}
      {notice && <div className="alert alert-success history-notice" role="status"><CheckCircle aria-hidden />{notice}</div>}
      {loading ? <div className="skeleton skeleton-panel" /> : scans.length === 0 ? (
        <div className="empty-state card"><ClockCounterClockwise aria-hidden /><h2>No saved scans</h2><p>Your completed scans will appear here.</p><Link className="button button-primary" to="/">Analyze a URL</Link></div>
      ) : (
        <div className="table-card">
          <div className="data-table history-data-table" role="table" aria-label="Scan history">
            <div className="data-row data-head" role="row"><span role="columnheader">URL</span><span role="columnheader">Risk</span><span role="columnheader">Scope</span><span role="columnheader">Scanned</span><span role="columnheader"><span className="sr-only">Actions</span></span></div>
            {scans.map((scan) => (
              <div className="data-row" role="row" key={scan.id}>
                <span role="cell"><Link className="table-link" to={`/scan/${scan.id}`}>{scan.display_url}</Link><small>{scan.id.slice(0, 16)}</small></span>
                <span role="cell"><RiskBadge risk={scan.decision.risk_band} /></span>
                <span role="cell">{scan.decision.analysis_scope === "LOCAL_ONLY" ? "Local only" : "Enriched"}</span>
                <span role="cell">{formatDate(scan.created_at)}</span>
                <span role="cell" className="row-actions"><Link className="icon-button" aria-label={`View scan for ${scan.display_url}`} to={`/scan/${scan.id}`}><CaretRight aria-hidden /></Link><button className="icon-button" type="button" aria-label={`Delete scan for ${scan.display_url}`} onClick={() => askToDelete(scan)}><Trash aria-hidden /></button></span>
              </div>
            ))}
          </div>
        </div>
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
  const [account, setAccount] = useState<Awaited<ReturnType<typeof api.me>> | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [retentionDays, setRetentionDays] = useState(30);
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [pendingAction, setPendingAction] = useState<(() => Promise<void>) | null>(null);
  const deleteDialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    let active = true;
    api.me().then((value) => {
      if (!active) return;
      setAccount(value);
      setRetentionDays(value.scan_retention_days ?? value.scan_retention_max_days ?? 30);
    }).catch(() => { if (active) setError("Account details could not be loaded."); });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    const dialog = deleteDialog.current;
    if (!confirmDelete || !dialog || dialog.open) return;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  }, [confirmDelete]);

  async function signOut() {
    await signOutIdentity();
    navigate("/sign-in");
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
    setAccount((current) => current ? { ...current, scan_retention_days: result.scan_retention_days } : current);
    setNotice(`New scans will be retained for ${result.scan_retention_days} days.`);
  }

  async function deleteAllScanData() {
    await api.deleteAccountScans();
    try { await signOutIdentity(); } catch { /* The API session was already revoked by deletion. */ }
    navigate("/sign-in", { replace: true });
  }

  const retentionMaximum = account?.scan_retention_max_days ?? 30;
  const retentionOptions = [...new Set([1, 7, 14, 30, retentionDays])].filter((days) => days <= retentionMaximum).sort((a, b) => a - b);

  return (
    <div className="page narrow-content">
      <PageHeader eyebrow="Your account" title="Privacy and account" description="Review the application session and available privacy controls." />
      {error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}
      {notice && <div className="alert alert-success" role="status"><CheckCircle aria-hidden />{notice}</div>}
      {!account && !error ? <div className="skeleton skeleton-panel" aria-label="Loading account" /> : account && <section className="settings-section"><h2>Application session</h2><div className="settings-card stacked"><dl className="account-facts"><div><dt>Role</dt><dd>{account.role.replaceAll("_", " ")}</dd></div><div><dt>User ID</dt><dd className="mono">{account.user_id ?? "Not available"}</dd></div></dl><button className="button button-secondary" type="button" onClick={signOut}><SignOut aria-hidden /> Sign out</button></div></section>}
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
  const configured = identityConfigured();
  const [mode, setMode] = useState<"sign-in" | "register" | "reset">("sign-in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfaFactor, setMfaFactor] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

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
        await completeTotpSignIn(code);
        navigate("/history");
      } else if (mode === "register") {
        await createPasswordAccount(email, password);
        setNotice("Check your inbox to verify your email address before signing in.");
        setMode("sign-in");
        setPassword("");
      } else if (mode === "reset") {
        await requestPasswordReset(email);
        setNotice("If an eligible account exists, Identity Platform will send recovery instructions.");
      } else {
        const result = await beginPasswordSignIn(email, password);
        if (result.mfaRequired) {
          setMfaFactor(result.factorName);
          setPassword("");
        } else {
          navigate("/history");
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
  return (
    <div className="auth-page">
      <section className="auth-card card">
        <div className="auth-heading"><span className="auth-icon"><LockKey aria-hidden /></span><h1>{title}</h1><p>{description}</p></div>
        <form onSubmit={submit}>
          {!mfaFactor && <label className="field"><span>Email address</span><input type="email" autoComplete="email" required placeholder="name@university.edu" value={email} onChange={(event) => setEmail(event.target.value)} /></label>}
          {!mfaFactor && mode !== "reset" && <label className="field"><span>Password</span><input type="password" autoComplete={mode === "register" ? "new-password" : "current-password"} minLength={8} required value={password} onChange={(event) => setPassword(event.target.value)} /></label>}
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
  const [secret, setSecret] = useState("");
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
    } catch (reason) {
      setError(reason instanceof IdentityError || reason instanceof ApiError ? reason.message : "The verification code could not be accepted.");
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
          <div className="key-panel"><Key aria-hidden /><p>{secret ? "Enter this one-time setup key in your authenticator app:" : "Generate a fresh setup key after signing in and verifying your email address."}</p>{secret && <code>{secret.match(/.{1,4}/g)?.join(" ")}</code>}<button type="button" className="button button-secondary" disabled={busy || !configured} onClick={secret ? () => navigator.clipboard?.writeText(secret) : generateSecret}>{secret ? <><Copy aria-hidden /> Copy key</> : <><Key aria-hidden /> Generate setup key</>}</button></div>
          <form onSubmit={verify}><label className="field"><span>6-digit verification code</span><input className="code-input" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required placeholder="000000" value={code} disabled={!secret || verified} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} /></label><button className="button button-primary button-large" disabled={!secret || busy || verified}>{busy ? "Please wait…" : "Verify and enable"}</button>{!configured && <div className="alert alert-warning" role="status"><Info aria-hidden />Identity Platform is not configured for this build.</div>}{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}{verified && <div className="alert alert-success" role="status"><CheckCircle aria-hidden />Two-step verification is enabled.</div>}</form>
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
  async function submit(event: FormEvent) { event.preventDefault(); await api.submitFeedback(scanId, verdict, comment); setSent(true); }
  if (sent) return <div className="page narrow-page"><div className="empty-state card"><CheckCircle aria-hidden /><h1>Feedback received</h1><p>Your report is quarantined for independent analyst review. It does not change the original result.</p><Link className="button button-primary" to={`/scan/${scanId}`}>Return to result</Link></div></div>;
  return <div className="page narrow-page"><PageHeader eyebrow="Improve the evidence" title="Report an incorrect result" description="Feedback is reviewed independently and never becomes training data automatically." /><form className="card feedback-card" onSubmit={submit}><fieldset><legend>What seems wrong?</legend><div className="feedback-choices"><label className={verdict === "should_be_high" ? "selected" : ""}><input type="radio" name="verdict" value="should_be_high" required onChange={(event) => setVerdict(event.target.value)} /><ThumbsDown aria-hidden /><span><strong>This link is more dangerous</strong><small>The displayed risk is too low.</small></span></label><label className={verdict === "should_be_low" ? "selected" : ""}><input type="radio" name="verdict" value="should_be_low" onChange={(event) => setVerdict(event.target.value)} /><ThumbsUp aria-hidden /><span><strong>This link is safer</strong><small>The displayed risk is too high.</small></span></label></div></fieldset><label className="field"><span>What evidence should we review? <small>Optional</small></span><textarea maxLength={1000} rows={5} value={comment} onChange={(event) => setComment(event.target.value)} placeholder="Do not include passwords or other sensitive information." /><small className="character-count">{comment.length} / 1000</small></label><div className="form-actions"><Link className="button button-secondary" to={`/scan/${scanId}`}>Cancel</Link><button className="button button-primary" disabled={!verdict}>Submit feedback</button></div></form></div>;
}

function apiMessage(reason: unknown, fallback: string) {
  return reason instanceof ApiError ? reason.message : fallback;
}

function WorkspaceFailure({ message, retry }: { message: string; retry: () => void }) {
  return <div className="empty-state card"><WarningCircle aria-hidden /><h2>Data unavailable</h2><p>{message}</p><button className="button button-secondary" type="button" onClick={retry}>Try again</button></div>;
}

function WorkspaceEmpty({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state card compact-empty"><Database aria-hidden /><h2>{title}</h2><p>{detail}</p></div>;
}

function AnalystCasesPage() {
  const [cases, setCases] = useState<ReviewCase[] | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState("ALL");

  function load() {
    setError("");
    setCases(null);
    api.listReviewCases().then(setCases).catch((reason) => setError(apiMessage(reason, "Review cases could not be loaded.")));
  }
  useEffect(load, []);

  const visible = (cases ?? []).filter((item) => {
    const matchesText = `${item.id} ${item.scan_id}`.toLowerCase().includes(query.toLowerCase());
    return matchesText && (stateFilter === "ALL" || item.state === stateFilter);
  });
  const states = [...new Set((cases ?? []).map((item) => item.state))].sort();
  const unassigned = (cases ?? []).filter((item) => !item.claimed_by).length;

  return <div className="page workspace-page">
    <PageHeader eyebrow="Analyst workspace" title="Review cases" description="Review persisted feedback cases. Submitted targets remain inert text." actions={<button className="button button-secondary" type="button" onClick={load}>Refresh</button>} />
    {cases && <div className="metric-grid"><Metric label="Cases returned" value={String(cases.length)} detail="Latest 100 records" icon={ListChecks} /><Metric label="Unassigned" value={String(unassigned)} detail="No recorded claimant" icon={UsersThree} /><Metric label="States" value={String(states.length)} detail="Persisted workflow states" icon={SlidersHorizontal} /></div>}
    <div className="toolbar card"><div className="search-field"><MagnifyingGlass aria-hidden /><input aria-label="Search cases" placeholder="Search case or scan ID" value={query} onChange={(event) => setQuery(event.target.value)} /></div><select aria-label="Filter by state" value={stateFilter} onChange={(event) => setStateFilter(event.target.value)}><option value="ALL">All states</option>{states.map((state) => <option value={state} key={state}>{state.replaceAll("_", " ")}</option>)}</select></div>
    {!cases && !error && <div className="skeleton skeleton-panel" aria-label="Loading review cases" />}
    {error && <WorkspaceFailure message={error} retry={load} />}
    {cases && visible.length === 0 && <WorkspaceEmpty title="No matching cases" detail={cases.length ? "Change the search or state filter." : "No review cases have been recorded."} />}
    {visible.length > 0 && <div className="table-card"><div className="data-table case-data-table" role="table" aria-label="Review cases"><div className="data-row data-head" role="row"><span role="columnheader">Case</span><span role="columnheader">Scan</span><span role="columnheader">State</span><span role="columnheader">Assignment</span><span role="columnheader">Updated</span></div>{visible.map((item) => <Link className="data-row clickable-row" role="row" to={`/analyst/cases/${item.id}`} key={item.id}><span role="cell"><strong className="mono">{item.id}</strong></span><span role="cell" className="mono truncate">{item.scan_id}</span><span role="cell"><span className="badge badge-neutral">{item.state.replaceAll("_", " ")}</span></span><span role="cell">{item.claimed_by ? <span className="mono">{item.claimed_by.slice(0, 12)}…</span> : "Unassigned"}</span><span role="cell">{formatDate(item.updated_at)}</span></Link>)}</div></div>}
  </div>;
}

function AnalystCasePage() {
  const { id = "" } = useParams();
  const [reviewCase, setReviewCase] = useState<ReviewCaseDetail | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [scanUnavailable, setScanUnavailable] = useState(false);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<"" | "MALICIOUS" | "BENIGN" | "INCONCLUSIVE">("");
  const [note, setNote] = useState("");

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
      if (action.action === "adjudicate") setOutcome("");
    } catch (reason) {
      setActionError(apiMessage(reason, "The review action could not be recorded."));
    } finally {
      setBusy(false);
    }
  }

  if (!reviewCase && !error) return <div className="page workspace-page"><div className="skeleton skeleton-panel" aria-label="Loading review case" /></div>;
  if (error) return <div className="page workspace-page"><WorkspaceFailure message={error} retry={load} /></div>;
  if (!reviewCase) return null;

  return <div className="page workspace-page">
    <div className="result-toolbar"><Link className="back-link" to="/analyst/cases"><CaretRight aria-hidden /> All cases</Link><div><button className="button button-secondary" disabled={busy} type="button" onClick={() => act({ action: reviewCase.claimed_by ? "release" : "claim" })}>{reviewCase.claimed_by ? "Release claim" : "Claim case"}</button></div></div>
    <PageHeader eyebrow="Analyst review" title={reviewCase.id} description={`State ${reviewCase.state.replaceAll("_", " ")} · updated ${formatDate(reviewCase.updated_at)}`} />
    <div className="case-layout"><section>
      {reviewCase.feedback && <section className="card review-feedback" aria-labelledby="submitted-feedback-title"><div className="section-heading"><div><p className="eyebrow">Quarantined user report</p><h2 id="submitted-feedback-title">Submitted feedback</h2></div><span className="badge badge-neutral">{reviewCase.feedback.status.replaceAll("_", " ")}</span></div><dl><div><dt>Category</dt><dd>{reviewCase.feedback.category.replaceAll("_", " ")}</dd></div><div><dt>Submitted</dt><dd>{formatDate(reviewCase.feedback.created_at)}</dd></div></dl><p>{reviewCase.feedback.comment || "No supporting comment was provided."}</p><small>Feedback cannot alter a result or enter training data without independent adjudication.</small></section>}
      {scan ? <><div className="card case-url"><span>Redacted submitted URL</span><code>{defangUrl(scan.display_url)}</code><div><RiskBadge risk={scan.decision.risk_band} /><StatusBadge status={scan.status} /><span className="badge badge-neutral">{scan.decision.analysis_scope.replaceAll("_", " ")}</span></div></div><ResultSection title="Stored decision reasons" icon={Fingerprint} count={scan.decision.reasons.length} open>{scan.decision.reasons.length ? <ul className="finding-list">{scan.decision.reasons.map((reason, index) => <li key={reason}><span>{index + 1}</span><p>{reason}</p></li>)}</ul> : <p>No reason templates were stored for this decision.</p>}</ResultSection><ResultSection title="Pinned evidence" icon={Database} count={scan.decision.evidence.length} open>{scan.decision.evidence.length ? <div className="evidence-table">{scan.decision.evidence.map((item) => <EvidenceRow item={item} key={item.id} />)}</div> : <p>No evidence observations are exposed for this decision.</p>}</ResultSection></> : scanUnavailable && <div className="alert alert-warning"><WarningCircle aria-hidden /><span><strong>Scan evidence is unavailable.</strong>The case record remains accessible, but its linked scan could not be read.</span></div>}
      <section className="card event-panel"><div className="section-heading"><div><p className="eyebrow">Append-only history</p><h2>Case events</h2></div><span className="badge badge-neutral">{reviewCase.events.length}</span></div>{reviewCase.events.length ? <ol className="event-list">{reviewCase.events.map((event) => <li key={event.id}><div><strong>{event.action.replaceAll("_", " ")}</strong><time dateTime={event.created_at}>{formatDate(event.created_at)}</time></div>{event.detail.outcome && <p>Outcome: {event.detail.outcome}</p>}{event.detail.note && <p>{event.detail.note}</p>}</li>)}</ol> : <p className="muted-copy">No case events have been recorded.</p>}</section>
    </section><aside className="card review-panel"><h2>Record review action</h2><p className="claim-state"><CheckCircle aria-hidden weight="fill" />{reviewCase.claimed_by ? `Claimed (${reviewCase.claimed_by.slice(0, 12)}…)` : "Unassigned"}</p><label className="field"><span>Adjudication</span><select value={outcome} onChange={(event) => setOutcome(event.target.value as typeof outcome)}><option value="">Select a decision</option><option value="MALICIOUS">Malicious</option><option value="BENIGN">Benign</option><option value="INCONCLUSIVE">Inconclusive</option></select></label><label className="field"><span>Analyst note</span><textarea rows={7} maxLength={2000} value={note} onChange={(event) => setNote(event.target.value)} placeholder="Cite only evidence visible in this case." /></label>{actionError && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{actionError}</div>}<div className="stacked-actions"><button className="button button-secondary" type="button" disabled={busy || !note.trim()} onClick={() => act({ action: "annotate", note: note.trim() })}>Add note</button><button className="button button-primary" type="button" disabled={busy || !outcome} onClick={() => outcome && act({ action: "adjudicate", outcome, note: note.trim() || undefined })}>{busy ? "Saving…" : "Record adjudication"}</button></div></aside></div>
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
  const tabs = ["Overview", "Users", "Providers", "Policies & models", "Audit"];
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
  return <div className="page workspace-page"><PageHeader eyebrow="System administration" title="Control centre" description="Manage persisted governed configuration and inspect the health data exposed by the API." /><div className="tabs" role="tablist" aria-label="Administration sections">{tabs.map((item) => <button role="tab" aria-selected={tab === item} key={item} onClick={() => setTab(item)}>{item}</button>)}</div>{tab === "Overview" ? <AdminOverview /> : tab === "Users" ? <AdminUsers runSensitive={runSensitive} /> : tab === "Providers" ? <AdminProviders runSensitive={runSensitive} /> : tab === "Policies & models" ? <AdminReleases runSensitive={runSensitive} /> : <AdminAudit />}{pendingAction && <FreshAuthDialog action={pendingAction} close={() => setPendingAction(null)} />}</div>;
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
  return <><div className="metric-grid"><Metric label="Database" value={health.database} detail="API connectivity check" icon={HardDrives} /><Metric label="Recorded jobs" value={String(jobTotal)} detail="Across persisted states" icon={ListChecks} /><Metric label="Job states" value={String(Object.keys(health.jobs).length)} detail={`Checked ${formatDate(health.checked_at)}`} icon={SlidersHorizontal} /></div><section className="card admin-table-section"><div className="section-heading"><div><p className="eyebrow">PostgreSQL queue</p><h2>Jobs by state</h2></div></div>{Object.keys(health.jobs).length ? <dl className="version-list">{Object.entries(health.jobs).sort().map(([state, count]) => <div key={state}><dt>{state.replaceAll("_", " ")}</dt><dd>{count}</dd></div>)}</dl> : <p className="muted-copy">No persisted scan jobs were reported.</p>}<div className="alert alert-info"><Info aria-hidden /><span><strong>Limited health surface.</strong>Availability, latency, provider health, backups, and pod status are not exposed by this API.</span></div></section></>;
}

function AdminUsers({ runSensitive }: { runSensitive: SensitiveActionRunner }) {
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [error, setError] = useState("");
  function load() { setUsers(null); setError(""); api.listAdminUsers().then(setUsers).catch((reason) => setError(apiMessage(reason, "Users could not be loaded."))); }
  useEffect(load, []);
  if (!users && !error) return <div className="skeleton skeleton-panel" aria-label="Loading users" />;
  if (error) return <WorkspaceFailure message={error} retry={load} />;
  if (!users?.length) return <WorkspaceEmpty title="No users" detail="No application user accounts were returned." />;
  return <section className="card admin-table-section"><div className="section-heading"><div><h2>Users and roles</h2><p>Identity is represented by opaque application IDs; email addresses are not exposed here.</p></div></div><div className="governance-list">{users.map((user) => <AdminUserRow key={user.id} user={user} runSensitive={runSensitive} update={(next) => setUsers((current) => current?.map((item) => item.id === next.id ? { ...item, ...next } : item) ?? null)} />)}</div></section>;
}

function AdminUserRow({ user, update, runSensitive }: { user: AdminUser; update: (value: Pick<AdminUser, "id" | "role" | "disabled">) => void; runSensitive: SensitiveActionRunner }) {
  const editable = user.role !== "ADMINISTRATOR";
  const [role, setRole] = useState<AssignableRole>(user.role === "ADMINISTRATOR" ? "REGISTERED_USER" : user.role);
  const [disabled, setDisabled] = useState(user.disabled);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function save() { setBusy(true); setError(""); try { await runSensitive(async () => { const result = await api.updateAdminUser(user.id, role, disabled); update(result); }); } catch (reason) { setError(apiMessage(reason, "The user could not be updated.")); } finally { setBusy(false); } }
  return <article className="governance-row"><div><strong className="mono">{user.id}</strong><small>Created {formatDate(user.created_at)} · email {user.email_verified ? "verified" : "not verified"} · MFA {user.mfa_verified ? "verified" : "not verified"}</small></div>{editable ? <><label><span className="sr-only">Role for {user.id}</span><select value={role} onChange={(event) => setRole(event.target.value as AssignableRole)}><option value="REGISTERED_USER">Registered user</option><option value="ANALYST">Analyst</option><option value="RESEARCHER">Researcher</option></select></label><label className="checkbox-row compact-checkbox"><input type="checkbox" checked={disabled} onChange={(event) => setDisabled(event.target.checked)} /> Disabled</label><button className="button button-secondary button-small" type="button" disabled={busy} onClick={save}>{busy ? "Saving…" : "Save"}</button></> : <><span className="badge badge-neutral">Administrator</span><small>Bootstrap-managed</small></>}{error && <div className="alert alert-danger row-alert" role="alert"><WarningCircle aria-hidden />{error}</div>}</article>;
}

function AdminProviders({ runSensitive }: { runSensitive: SensitiveActionRunner }) {
  const [providers, setProviders] = useState<ProviderConfiguration[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  function load() { setProviders(null); setError(""); api.listProviders().then(setProviders).catch((reason) => setError(apiMessage(reason, "Provider configuration could not be loaded."))); }
  useEffect(load, []);
  async function toggle(provider: ProviderConfiguration) { setBusy(provider.provider); setError(""); try { await runSensitive(async () => { const next = await api.updateProvider(provider.provider, !provider.enabled, provider.config); setProviders((items) => items?.map((item) => item.provider === next.provider ? next : item) ?? [next]); }); } catch (reason) { setError(apiMessage(reason, "Provider configuration could not be changed.")); } finally { setBusy(""); } }
  if (!providers && !error) return <div className="skeleton skeleton-panel" aria-label="Loading providers" />;
  return <section className="card admin-table-section"><div className="section-heading"><div><h2>Runtime reputation providers</h2><p>Only persisted provider configuration is shown. Health and quota telemetry are unavailable.</p></div></div>{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}{providers?.length ? <div className="governance-list">{providers.map((provider) => <article className="governance-row" key={provider.id}><div><strong>{provider.provider.replaceAll("_", " ")}</strong><small>Updated {formatDate(provider.updated_at)} · {Object.keys(provider.config).length} non-secret configuration fields</small></div><span className={`badge ${provider.enabled ? "badge-low" : "badge-neutral"}`}>{provider.enabled ? "Enabled" : "Disabled"}</span><button className="button button-secondary button-small" type="button" disabled={busy === provider.provider} onClick={() => toggle(provider)}>{busy === provider.provider ? "Saving…" : provider.enabled ? "Disable" : "Enable"}</button></article>)}</div> : !error && <WorkspaceEmpty title="No persisted provider configuration" detail="The API returned no provider records. Runtime defaults are intentionally not inferred." />}</section>;
}

function AdminReleases({ runSensitive }: { runSensitive: SensitiveActionRunner }) {
  const [policies, setPolicies] = useState<DecisionPolicy[] | null>(null);
  const [models, setModels] = useState<ModelRelease[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  function load() { setPolicies(null); setModels(null); setError(""); Promise.all([api.listDecisionPolicies(), api.listModels()]).then(([nextPolicies, nextModels]) => { setPolicies(nextPolicies); setModels(nextModels); }).catch((reason) => setError(apiMessage(reason, "Policy and model registries could not be loaded."))); }
  useEffect(load, []);
  async function activate(model: ModelRelease) { setBusy(model.id); setError(""); try { await runSensitive(async () => { const next = await api.activateModel(model.id); setModels((items) => items?.map((item) => item.id === next.id ? next : { ...item, approved_for_deployment: false }) ?? [next]); }); } catch (reason) { setError(apiMessage(reason, "The model approval could not be changed.")); } finally { setBusy(""); } }
  if ((!policies || !models) && !error) return <div className="skeleton skeleton-panel" aria-label="Loading release registries" />;
  if (error && !policies && !models) return <WorkspaceFailure message={error} retry={load} />;
  return <><div className="alert alert-warning"><WarningCircle aria-hidden /><span><strong>Approval is not runtime activation.</strong>A trusted checksum-pinned deployment is still required before a model or policy affects decisions.</span></div>{error && <div className="alert alert-danger" role="alert"><WarningCircle aria-hidden />{error}</div>}<div className="admin-grid registry-grid"><section className="card"><div className="section-heading"><div><h2>Decision policies</h2><p>Read-only registry view</p></div></div>{policies?.length ? <div className="governance-list">{policies.map((policy) => <article className="registry-row" key={policy.id}><div><strong>{policy.version}</strong><small>{formatDate(policy.created_at)} · {Object.keys(policy.config).length} configuration fields</small></div><span className={`badge ${policy.active ? "badge-low" : "badge-neutral"}`}>{policy.active ? "Registry active" : "Inactive"}</span></article>)}</div> : <p className="muted-copy">No policy records were returned. Policy creation is not exposed because runtime policy constants require a reviewed deployment.</p>}</section><section className="card"><div className="section-heading"><div><h2>Model releases</h2><p>Checksum and deployment metadata</p></div></div>{models?.length ? <div className="governance-list">{models.map((model) => <article className="registry-row" key={model.id}><div><strong>{model.version}</strong><small className="mono">SHA-256 {model.sha256.slice(0, 16)}…</small><small className="mono truncate">{model.artifact_uri}</small></div>{model.approved_for_deployment ? <span className="badge badge-low">Approved for deployment</span> : <button className="button button-secondary button-small" type="button" disabled={busy === model.id} onClick={() => activate(model)}>{busy === model.id ? "Saving…" : "Approve for deployment"}</button>}</article>)}</div> : <p className="muted-copy">No model releases were returned. Artifact registration is handled outside this UI.</p>}</section></div></>;
}

function AdminAudit() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState("");
  function load() { setEvents(null); setError(""); api.listAuditEvents().then(setEvents).catch((reason) => setError(apiMessage(reason, "Audit events could not be loaded."))); }
  useEffect(load, []);
  if (!events && !error) return <div className="skeleton skeleton-panel" aria-label="Loading audit events" />;
  if (error) return <WorkspaceFailure message={error} retry={load} />;
  return <section className="card admin-table-section"><div className="section-heading"><div><h2>Audit events</h2><p>Latest 200 persisted privileged events. Digest export is not available from the current API.</p></div></div>{events?.length ? <ol className="event-list audit-list">{events.map((event) => <li key={event.id}><div><strong>{event.action.replaceAll("_", " ")}</strong><time dateTime={event.created_at}>{formatDate(event.created_at)}</time></div><p>{event.object_type}{event.object_id ? ` · ${event.object_id}` : ""} · {event.outcome}</p><small className="mono">Correlation {event.correlation_id}</small></li>)}</ol> : <p className="muted-copy">No audit events were returned.</p>}</section>;
}

function ResearchPage() {
  const [datasets, setDatasets] = useState<DatasetSnapshot[] | null>(null);
  const [experiments, setExperiments] = useState<Experiment[] | null>(null);
  const [exports, setExports] = useState<ResearchExport[] | null>(null);
  const [error, setError] = useState("");
  function load() { setDatasets(null); setExperiments(null); setExports(null); setError(""); Promise.all([api.listDatasets(), api.listExperiments(), api.listResearchExports()]).then(([nextDatasets, nextExperiments, nextExports]) => { setDatasets(nextDatasets); setExperiments(nextExperiments); setExports(nextExports); }).catch((reason) => setError(apiMessage(reason, "Research records could not be loaded."))); }
  useEffect(load, []);
  if ((!datasets || !experiments || !exports) && !error) return <div className="page workspace-page"><div className="skeleton skeleton-panel" aria-label="Loading research workspace" /></div>;
  if (error) return <div className="page workspace-page"><PageHeader eyebrow="Research workspace" title="Datasets and experiments" description="Inspect persisted research governance records." /><WorkspaceFailure message={error} retry={load} /></div>;
  if (!datasets || !experiments || !exports) return null;
  return <div className="page workspace-page"><PageHeader eyebrow="Research workspace" title="Datasets and experiments" description="Inspect persisted research governance records without implying that queued work has run." actions={<button className="button button-secondary" type="button" onClick={load}>Refresh</button>} /><div className="alert alert-warning"><WarningCircle aria-hidden /><span><strong>Experimental, read-only workflow.</strong>The API can record queued experiments and exports, but no executor is deployed. Creation is therefore unavailable in this interface.</span></div><div className="metric-grid"><Metric label="Dataset records" value={String(datasets.length)} detail="Returned by the registry" icon={Database} /><Metric label="Experiment records" value={String(experiments.length)} detail="States are not inferred" icon={Flask} /><Metric label="Export records" value={String(exports.length)} detail="Artifact presence is reported" icon={FileText} /></div><div className="research-grid"><ResearchDatasets items={datasets} /><ResearchExperiments items={experiments} /></div><section className="card admin-table-section research-exports"><div className="section-heading"><div><h2>Governed exports</h2><p>Existing requests only; new requests are disabled until an executor is deployed.</p></div></div>{exports.length ? <div className="governance-list">{exports.map((item) => <article className="registry-row" key={item.id}><div><strong className="mono">{item.id}</strong><small>{item.expires_at ? `Expires ${formatDate(item.expires_at)}` : "No expiry recorded"}</small></div><span className="badge badge-neutral">{item.state.replaceAll("_", " ")}</span><small>{item.artifact_uri ? "Artifact recorded" : "No artifact recorded"}</small></article>)}</div> : <p className="muted-copy">No export records were returned.</p>}</section></div>;
}

function ResearchDatasets({ items }: { items: DatasetSnapshot[] }) {
  return <section className="card"><div className="section-heading"><div><p className="eyebrow">Immutable inputs</p><h2>Dataset snapshots</h2></div></div>{items.length ? <div className="dataset-list">{items.map((item) => <div key={item.id}><span className="dataset-icon"><Database aria-hidden /></span><span><strong>{item.name}</strong><small>Created {formatDate(item.created_at)}</small></span><span><strong>{item.state.replaceAll("_", " ")}</strong><small className="mono">{item.sha256.slice(0, 16)}…</small></span></div>)}</div> : <p className="muted-copy">No dataset snapshots were returned.</p>}</section>;
}

function ResearchExperiments({ items }: { items: Experiment[] }) {
  return <section className="card"><div className="section-heading"><div><p className="eyebrow">Recorded runs</p><h2>Experiments</h2></div></div>{items.length ? <div className="experiment-list">{items.map((item) => <div key={item.id}><span className={`experiment-icon ${item.state === "QUEUED" ? "running" : ""}`}>{item.state === "QUEUED" ? <Pulse aria-hidden /> : <Flask aria-hidden />}</span><span><strong className="mono">{item.id}</strong><small>{item.state.replaceAll("_", " ")} · dataset {item.dataset_id} · {formatDate(item.created_at)}</small></span></div>)}</div> : <p className="muted-copy">No experiment records were returned.</p>}</section>;
}

function NotFoundPage() {
  return <div className="page narrow-page"><div className="empty-state"><ShieldWarning aria-hidden /><h1>Page not found</h1><p>The page may have moved or you may not have access.</p><Link className="button button-primary" to="/">Return to scanner</Link></div></div>;
}

export function App() {
  return <Shell><Routes><Route path="/" element={<ScanPage />} /><Route path="/scan/:id" element={<ResultPage />} /><Route path="/history" element={<HistoryPage />} /><Route path="/account" element={<ProtectedRoute roles={registeredRoles}><AccountPage /></ProtectedRoute>} /><Route path="/sign-in" element={<SignInPage />} /><Route path="/totp" element={<ProtectedRoute roles={registeredRoles}><TotpPage /></ProtectedRoute>} /><Route path="/feedback/:scanId" element={<FeedbackPage />} /><Route path="/analyst/cases" element={<ProtectedRoute roles={analystRoles}><AnalystCasesPage /></ProtectedRoute>} /><Route path="/analyst/cases/:id" element={<ProtectedRoute roles={analystRoles}><AnalystCasePage /></ProtectedRoute>} /><Route path="/admin" element={<ProtectedRoute roles={administratorRoles}><AdminPage /></ProtectedRoute>} /><Route path="/research" element={<ProtectedRoute roles={researcherRoles}><ResearchPage /></ProtectedRoute>} /><Route path="/reports/:id" element={<ResultPage shared />} /><Route path="*" element={<NotFoundPage />} /></Routes></Shell>;
}
