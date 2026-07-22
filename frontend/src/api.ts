export type RiskBand = "LOW" | "MEDIUM" | "HIGH" | "INCONCLUSIVE";
export type AnalysisScope = "LOCAL_ONLY" | "ENRICHED";
export type Completion = "COMPLETE" | "PARTIAL";
export type EngineMode = "HYBRID" | "RULE_ONLY";
export type ScanStatus = "PROCESSING" | "COMPLETE" | "PARTIAL" | "INCONCLUSIVE";
export type EvidenceState =
  | "OBSERVED"
  | "NO_MATCH"
  | "NOT_APPLICABLE"
  | "SKIPPED_POLICY"
  | "UNAVAILABLE"
  | "TIMED_OUT"
  | "REJECTED_SAFETY"
  | "STALE";

export interface EvidenceObservation {
  id: string;
  family: string;
  label: string;
  state: EvidenceState;
  value: string;
  source: string;
  observed_at?: string;
  retrieved_at?: string;
  expires_at?: string;
  cached?: boolean;
  version: string;
  reason_code?: string;
}

export interface Decision {
  risk_band: RiskBand;
  analysis_scope: AnalysisScope;
  completion: Completion;
  engine_mode: EngineMode;
  reasons: string[];
  counter_evidence: string[];
  missing_evidence: string[];
  limitations: string[];
  safe_actions: string[];
  evidence: EvidenceObservation[];
  versions: {
    policy: string;
    ruleset: string;
    model: string;
  };
}

export interface Scan {
  id: string;
  simulated?: boolean;
  display_url: string;
  ascii_display_url?: string;
  status: ScanStatus;
  requested_mode: "local_only" | "enriched" | "LOCAL_ONLY" | "ENRICHED";
  created_at: string;
  updated_at: string;
  decision: Decision;
}

export interface CreateScanRequest {
  url: string;
  analysis_mode: "local_only" | "enriched";
  enrichment_consent: boolean;
}

export interface ScanFetchResponse {
  scan: Scan;
  poll_after_ms?: number;
}

export interface CreateScanResponse extends ScanFetchResponse {
  demo?: boolean;
}

export interface SharedReportResponse {
  scan: Scan;
  expires_at: string;
}

export type ApplicationRole = "REGISTERED_USER" | "ANALYST" | "ADMINISTRATOR" | "RESEARCHER";
export type AssignableRole = Exclude<ApplicationRole, "ADMINISTRATOR">;

export interface MeResponse {
  authenticated: boolean;
  user_id: string | null;
  role: ApplicationRole | "GUEST";
  scan_retention_days?: number | null;
  scan_retention_max_days?: number;
}

export interface AccountExport {
  schema_version: string;
  generated_at: string;
  user_id: string;
  scans: Scan[];
  identity_platform_identity_included: false;
}

export interface ReviewCase {
  id: string;
  scan_id: string;
  feedback_id: string | null;
  state: string;
  claimed_by: string | null;
  updated_at: string;
}

export interface ReviewCaseEvent {
  id: string;
  action: string;
  detail: { note?: string | null; outcome?: string | null };
  created_at: string;
}

export interface ReviewCaseDetail extends ReviewCase {
  feedback?: {
    id: string;
    category: string;
    comment: string | null;
    status: string;
    created_at: string;
  };
  events: ReviewCaseEvent[];
}

export type ReviewAction =
  | { action: "claim" | "release" }
  | { action: "annotate"; note: string }
  | { action: "adjudicate"; note?: string; outcome: "MALICIOUS" | "BENIGN" | "INCONCLUSIVE" };

export interface AdminUser {
  id: string;
  role: ApplicationRole;
  email_verified: boolean;
  mfa_verified: boolean;
  disabled: boolean;
  created_at: string;
}

export interface ProviderConfiguration {
  id: string;
  provider: string;
  enabled: boolean;
  config: Record<string, unknown>;
  updated_at: string;
}

export interface DecisionPolicy {
  id: string;
  version: string;
  config: Record<string, unknown>;
  active: boolean;
  created_at: string;
}

export interface ModelRelease {
  id: string;
  version: string;
  artifact_uri: string;
  sha256: string;
  metrics: Record<string, unknown>;
  approved_for_deployment: boolean;
  runtime_active: boolean;
  deployment_required?: boolean;
  next_step?: string;
}

export interface AuditEvent {
  id: string;
  action: string;
  object_type: string;
  object_id: string | null;
  outcome: string;
  correlation_id: string;
  created_at: string;
}

export interface AdminHealth {
  database: string;
  jobs: Record<string, number>;
  checked_at: string;
}

export interface DatasetSnapshot {
  id: string;
  name: string;
  sha256: string;
  manifest: Record<string, unknown>;
  state: string;
  created_at: string;
}

export interface Experiment {
  id: string;
  dataset_id: string;
  state: string;
  config: Record<string, unknown>;
  result: Record<string, unknown>;
  created_at: string;
}

export interface ResearchExport {
  id: string;
  state: string;
  filters: Record<string, unknown>;
  artifact_uri: string | null;
  expires_at: string | null;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code = "request_failed",
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  const headers = new Headers(init?.headers);
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const method = (init?.method ?? "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = readCookie("phishguard_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  try {
    response = await fetch(`/api/v1${path}`, {
      ...init,
      credentials: "same-origin",
      headers,
    });
  } catch {
    throw new ApiError(0, "The API is unavailable.", "api_unavailable");
  }

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(
      response.status,
      body?.error?.message ?? "The request could not be completed.",
      body?.error?.code,
    );
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

function readCookie(name: string) {
  const prefix = `${encodeURIComponent(name)}=`;
  const value = document.cookie.split("; ").find((item) => item.startsWith(prefix));
  return value ? decodeURIComponent(value.slice(prefix.length)) : undefined;
}

const DEMO_KEY = "phishguard.demo.scans";
const DEMO_REPORT_KEY = "phishguard.demo.reports";

function redactUrl(raw: string) {
  const url = new URL(raw);
  const path = url.pathname === "/" ? "/" : "/[path hidden]";
  const query = url.search ? "?[query hidden]" : "";
  const enteredHost = raw.match(/^https?:\/\/(?:[^@/?#]+@)?(\[[^\]]+\]|[^:/?#]+)/i)?.[1];
  return `${url.protocol}//${enteredHost || url.hostname}${url.port ? `:${url.port}` : ""}${path}${query}`;
}

function asciiRedactedUrl(raw: string) {
  const url = new URL(raw);
  const path = url.pathname === "/" ? "/" : "/[path hidden]";
  const query = url.search ? "?[query hidden]" : "";
  return `${url.protocol}//${url.hostname}${url.port ? `:${url.port}` : ""}${path}${query}`;
}

function demoDecision(raw: string, scope: AnalysisScope): Decision {
  const url = new URL(raw);
  const text = `${url.hostname}${url.pathname}`.toLowerCase();
  const suspiciousWords = ["login", "verify", "secure", "wallet", "gift", "password", "account"];
  const hits = suspiciousWords.filter((word) => text.includes(word));
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname);
  const manyLabels = url.hostname.split(".").length > 4;
  const indicatorWeight = Math.min(96, 18 + hits.length * 23 + Number(isIp) * 38 + Number(manyLabels) * 18);
  const risk: RiskBand = indicatorWeight >= 70 ? "HIGH" : indicatorWeight >= 40 ? "MEDIUM" : "LOW";
  const now = new Date().toISOString();
  const urlEvidence: EvidenceObservation[] = [
    {
      id: "url-scheme",
      family: "URL",
      label: "Transport scheme",
      state: "OBSERVED",
      value: url.protocol === "https:" ? "HTTPS present" : "Plain HTTP",
      source: "Simulated local URL parser",
      observed_at: now,
      version: "url-policy/1.0",
    },
    {
      id: "url-lexical",
      family: "URL",
      label: "Suspicious URL terms",
      state: hits.length ? "OBSERVED" : "NO_MATCH",
      value: hits.length ? hits.join(", ") : "No high-risk terms found",
      source: "Simulated deterministic rules",
      observed_at: now,
      version: "ruleset/1.0",
    },
  ];
  const enrichment: EvidenceObservation[] = scope === "ENRICHED"
    ? [
        {
          id: "reputation",
          family: "REPUTATION",
          label: "External reputation",
          state: "UNAVAILABLE",
          value: "Not contacted in simulated demo mode",
          source: "Simulated demo policy",
          version: "demo/1.0",
          reason_code: "simulated_not_contacted",
        },
        {
          id: "tls",
          family: "TLS",
          label: "TLS certificate",
          state: "UNAVAILABLE",
          value: "Not retrieved in simulated demo mode",
          source: "Simulated demo policy",
          version: "demo/1.0",
          reason_code: "simulated_not_contacted",
        },
      ]
    : [
        {
          id: "policy",
          family: "REPUTATION",
          label: "External reputation",
          state: "SKIPPED_POLICY",
          value: "Not requested in local-only mode",
          source: "Enrichment policy",
          version: "policy/1.0",
          reason_code: "local_only",
        },
      ];

  return {
    risk_band: risk,
    analysis_scope: scope,
    completion: scope === "ENRICHED" ? "PARTIAL" : "COMPLETE",
    engine_mode: "RULE_ONLY",
    reasons: [
      ...(hits.length ? [`The URL contains ${hits.length} term${hits.length > 1 ? "s" : ""} commonly used in credential lures.`] : []),
      ...(isIp ? ["The destination uses an IP address instead of a registered hostname."] : []),
      ...(manyLabels ? ["The hostname has an unusually deep subdomain structure."] : []),
      ...(hits.length || isIp || manyLabels ? [] : ["Local structural checks found no strong phishing indicators."]),
    ].slice(0, 3),
    counter_evidence: url.protocol === "https:" ? ["The URL uses HTTPS, although encryption alone does not establish trust."] : [],
    missing_evidence: scope === "LOCAL_ONLY" ? ["External evidence was not requested."] : ["External enrichment was not run in simulated demo mode."],
    limitations: ["This simulated result demonstrates the interface and is not a real phishing assessment."],
    safe_actions: ["Verify the sender through a trusted channel.", "Navigate to the organisation by typing its known address yourself."],
    evidence: [...urlEvidence, ...enrichment],
    versions: { policy: "simulated-demo/1.0", ruleset: "simulated-rules/1.0", model: "not-run" },
  };
}

function demoScans(): Scan[] {
  try {
    return JSON.parse(localStorage.getItem(DEMO_KEY) ?? "[]") as Scan[];
  } catch {
    return [];
  }
}

function saveDemo(scans: Scan[]) {
  localStorage.setItem(DEMO_KEY, JSON.stringify(scans.slice(0, 20)));
}

function demoReports(): Record<string, { scan_id: string; expires_at: string }> {
  try {
    return JSON.parse(localStorage.getItem(DEMO_REPORT_KEY) ?? "{}") as Record<string, { scan_id: string; expires_at: string }>;
  } catch {
    return {};
  }
}

function createDemo(payload: CreateScanRequest): CreateScanResponse {
  const created = new Date().toISOString();
  const scope = payload.analysis_mode === "enriched" ? "ENRICHED" : "LOCAL_ONLY";
  const displayUrl = redactUrl(payload.url);
  const asciiDisplayUrl = asciiRedactedUrl(payload.url);
  const scan: Scan = {
    id: `demo-${crypto.randomUUID()}`,
    simulated: true,
    display_url: displayUrl,
    ascii_display_url: displayUrl !== asciiDisplayUrl ? asciiDisplayUrl : undefined,
    status: scope === "ENRICHED" ? "PARTIAL" : "COMPLETE",
    requested_mode: payload.analysis_mode,
    created_at: created,
    updated_at: created,
    decision: demoDecision(payload.url, scope),
  };
  saveDemo([scan, ...demoScans()]);
  return { scan, demo: true };
}

function getDemo(id: string): Scan | undefined {
  return demoScans().find((item) => item.id === id);
}

function canDemo(error: unknown) {
  return import.meta.env.DEV
    && import.meta.env.VITE_DEMO_FALLBACK === "true"
    && error instanceof ApiError
    && [0, 500, 502, 503, 504].includes(error.status);
}

export const api = {
  async me(): Promise<MeResponse> {
    return request("/me");
  },

  async exchangeSession(idToken: string): Promise<{ user_id: string; role: string; csrf_token: string }> {
    return request("/session", {
      method: "POST",
      body: JSON.stringify({ id_token: idToken }),
    });
  },

  async reauthenticate(idToken: string): Promise<void> {
    await request("/session/reauth", {
      method: "POST",
      body: JSON.stringify({ id_token: idToken }),
    });
  },

  async endSession(): Promise<void> {
    await request<void>("/session", { method: "DELETE" });
  },

  async exportAccount(): Promise<AccountExport> {
    return request<AccountExport>("/account/export", { method: "POST" });
  },

  async updateAccountRetention(days: number): Promise<{ scan_retention_days: number; applies_to: "new_scans" }> {
    return request("/account/retention", {
      method: "PUT",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ days }),
    });
  },

  async deleteAccountScans(): Promise<{
    status: "deleted";
    deleted_scan_count: number;
    application_sessions_revoked: true;
    identity_platform_identity_deleted: false;
  }> {
    return request("/account/scans", {
      method: "DELETE",
      headers: { "Idempotency-Key": crypto.randomUUID() },
    });
  },

  async listReviewCases(): Promise<ReviewCase[]> {
    return (await request<{ items: ReviewCase[] }>("/review-cases")).items;
  },

  async getReviewCase(id: string): Promise<ReviewCaseDetail> {
    return request(`/review-cases/${encodeURIComponent(id)}`);
  },

  async reviewCaseAction(id: string, action: ReviewAction): Promise<ReviewCase> {
    return request(`/review-cases/${encodeURIComponent(id)}/actions`, {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify(action),
    });
  },

  async listAdminUsers(): Promise<AdminUser[]> {
    return (await request<{ items: AdminUser[] }>("/admin/users")).items;
  },

  async updateAdminUser(id: string, role: AssignableRole, disabled: boolean): Promise<Pick<AdminUser, "id" | "role" | "disabled">> {
    return request(`/admin/users/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ role, disabled }),
    });
  },

  async listProviders(): Promise<ProviderConfiguration[]> {
    return (await request<{ items: ProviderConfiguration[] }>("/admin/providers")).items;
  },

  async updateProvider(provider: string, enabled: boolean, config: Record<string, unknown>): Promise<ProviderConfiguration> {
    return request(`/admin/providers/${encodeURIComponent(provider)}`, {
      method: "PUT",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ enabled, config }),
    });
  },

  async listDecisionPolicies(): Promise<DecisionPolicy[]> {
    return (await request<{ items: DecisionPolicy[] }>("/admin/decision-policies")).items;
  },

  async listModels(): Promise<ModelRelease[]> {
    return (await request<{ items: ModelRelease[] }>("/admin/models")).items;
  },

  async activateModel(id: string): Promise<ModelRelease> {
    return request(`/admin/models/${encodeURIComponent(id)}/activate`, {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
    });
  },

  async listAuditEvents(): Promise<AuditEvent[]> {
    return (await request<{ items: AuditEvent[] }>("/admin/audit-events")).items;
  },

  async getAdminHealth(): Promise<AdminHealth> {
    return request("/admin/health");
  },

  async listDatasets(): Promise<DatasetSnapshot[]> {
    return (await request<{ items: DatasetSnapshot[] }>("/research/datasets")).items;
  },

  async listExperiments(): Promise<Experiment[]> {
    return (await request<{ items: Experiment[] }>("/research/experiments")).items;
  },

  async listResearchExports(): Promise<ResearchExport[]> {
    return (await request<{ items: ResearchExport[] }>("/research/exports")).items;
  },

  async createScan(payload: CreateScanRequest): Promise<CreateScanResponse> {
    try {
      return await request<CreateScanResponse>("/scans", {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify(payload),
      });
    } catch (error) {
      if (canDemo(error)) return createDemo(payload);
      throw error;
    }
  },

  async getScanUpdate(id: string): Promise<ScanFetchResponse> {
    if (id.startsWith("demo-")) {
      const scan = getDemo(id);
      if (scan) return { scan };
    }
    return request<ScanFetchResponse>(`/scans/${encodeURIComponent(id)}`);
  },

  async getScan(id: string): Promise<Scan> {
    return (await api.getScanUpdate(id)).scan;
  },

  async listScans(): Promise<Scan[]> {
    try {
      const response = await request<{ items: Scan[] }>("/scans");
      return response.items;
    } catch (error) {
      if (canDemo(error)) return demoScans();
      throw error;
    }
  },

  async deleteScan(id: string): Promise<void> {
    if (id.startsWith("demo-")) {
      saveDemo(demoScans().filter((scan) => scan.id !== id));
      return;
    }
    await request<void>(`/scans/${encodeURIComponent(id)}`, { method: "DELETE" });
  },

  async submitFeedback(scanId: string, verdict: string, comment: string): Promise<void> {
    if (scanId.startsWith("demo-")) return;
    const category = verdict === "should_be_high" ? "FALSE_NEGATIVE" : verdict === "should_be_low" ? "FALSE_POSITIVE" : "OTHER";
    await request(`/scans/${encodeURIComponent(scanId)}/feedback`, {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ category, comment }),
    });
  },

  async createShare(scanId: string): Promise<{ report_id: string; expires_at: string }> {
    if (scanId.startsWith("demo-")) {
      const reportId = `demo-report-${crypto.randomUUID()}`;
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      localStorage.setItem(DEMO_REPORT_KEY, JSON.stringify({
        ...demoReports(),
        [reportId]: { scan_id: scanId, expires_at: expiresAt },
      }));
      return { report_id: reportId, expires_at: expiresAt };
    }
    return request(`/scans/${encodeURIComponent(scanId)}/shares`, {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ expires_in_hours: 24 }),
    });
  },

  async getReport(reportId: string): Promise<SharedReportResponse> {
    if (reportId.startsWith("demo-report-")) {
      const report = demoReports()[reportId];
      if (report && Date.parse(report.expires_at) > Date.now()) {
        const scan = getDemo(report.scan_id);
        if (scan) return { scan, expires_at: report.expires_at };
      }
      throw new ApiError(404, "This report does not exist or is no longer available.", "not_found");
    }
    return request<SharedReportResponse>(`/reports/${encodeURIComponent(reportId)}`);
  },
};
