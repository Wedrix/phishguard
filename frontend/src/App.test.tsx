import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App, RESULT_POLL_DEADLINE_MS, resultPollDelay, verdictPresentation } from "./App";
import { ApiError, api, type EngineMode, type RoleRequest, type Scan, type ScanStatus } from "./api";
import * as identity from "./identity";

function renderRoute(route = "/") {
  return render(<MemoryRouter initialEntries={[route]}><App /></MemoryRouter>);
}

function scanFixture(status: ScanStatus = "COMPLETE", engineMode: EngineMode = "HYBRID"): Scan {
  return {
    id: "scan-real-001",
    display_url: "https://example[.]test/[path hidden]",
    status,
    requested_mode: status === "PROCESSING" ? "enriched" : "local_only",
    created_at: "2026-07-22T10:00:00Z",
    updated_at: "2026-07-22T10:00:00Z",
    decision: {
      risk_band: "MEDIUM",
      analysis_scope: status === "PROCESSING" ? "ENRICHED" : "LOCAL_ONLY",
      completion: status === "PROCESSING" ? "PARTIAL" : "COMPLETE",
      engine_mode: engineMode,
      reasons: ["The URL contains a structural risk indicator."],
      counter_evidence: [],
      missing_evidence: [],
      limitations: [],
      safe_actions: ["Use a known address instead."],
      evidence: [],
      versions: { policy: "policy-1", ruleset: "rules-1", model: "model-1" },
    },
  };
}

function roleRequestFixture(): RoleRequest {
  return {
    id: "role-request-001",
    user_id: "user-1",
    requested_role: "ANALYST",
    state: "PENDING",
    requested_at: "2026-07-22T10:00:00Z",
    decided_at: null,
    decided_by_user_id: null,
    decision_note: null,
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.useRealTimers();
  localStorage.clear();
  sessionStorage.clear();
  document.cookie = "phishguard_csrf=; max-age=0; path=/";
});

describe("PhishGuard scan journey", () => {
  it("renders the TOTP enrollment URI as a scannable QR code", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "user-1", role: "REGISTERED_USER" });
    vi.spyOn(identity, "identityConfigured").mockReturnValue(true);
    vi.spyOn(identity, "beginTotpEnrollment").mockResolvedValue({ secretKey: "ABCDEFGHIJKLMNOP", qrCodeUrl: "otpauth://totp/PhishGuard:test?secret=ABCDEFGHIJKLMNOP" });
    const user = userEvent.setup();
    renderRoute("/totp");

    await user.click(await screen.findByRole("button", { name: /generate setup key/i }));

    expect(await screen.findByRole("img", { name: /scan this qr code/i })).toBeVisible();
    expect(screen.getByText("ABCD EFGH IJKL MNOP")).toBeVisible();
  });

  it("defaults to local-only and gates enrichment behind explicit consent", async () => {
    const user = userEvent.setup();
    renderRoute();

    expect(screen.getByRole("radio", { name: /local only/i })).toBeChecked();
    expect(screen.queryByText(/external processing notice/i)).not.toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: /enriched evidence/i }));
    expect(screen.getByText(/external processing notice/i)).toBeVisible();
    await user.type(screen.getByLabelText(/url to inspect/i), "https://verify-account.example/login");
    await user.click(screen.getByRole("button", { name: /analyze safely/i }));

    expect(screen.getByRole("alert")).toHaveTextContent(/confirm the enrichment notice/i);
  });

  it("does not force a route theme and leaves colour selection to the device", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "user-1", role: "ADMINISTRATOR" });
    vi.spyOn(api, "getAdminHealth").mockResolvedValue({
      database: "available",
      jobs: { QUEUED: 2, COMPLETE: 4 },
      checked_at: "2026-07-22T10:00:00Z",
    });
    const { container } = renderRoute("/admin");
    expect(container.querySelector(".app")).not.toHaveAttribute("data-theme");
    expect(await screen.findByRole("heading", { name: /control centre/i })).toBeVisible();
    expect(await screen.findByText("available")).toBeVisible();
    expect(screen.getByText("6", { selector: ".metric-card strong" })).toBeVisible();
    expect(screen.queryByText(/99\.98%/)).not.toBeInTheDocument();
  });

  it("does not render privileged content for an unauthorised role", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "user-1", role: "REGISTERED_USER" });
    renderRoute("/admin");
    expect(await screen.findByRole("heading", { name: /access restricted/i })).toBeVisible();
    expect(screen.queryByRole("heading", { name: /control centre/i })).not.toBeInTheDocument();
  });

  it("shows session-aware public navigation for anonymous, guest, and user sessions", async () => {
    const me = vi.spyOn(api, "me")
      .mockResolvedValueOnce({ authenticated: false, session_kind: "ANONYMOUS", user_id: null, role: null })
      .mockResolvedValueOnce({ authenticated: false, session_kind: "GUEST", user_id: null, role: null })
      .mockResolvedValueOnce({ authenticated: true, session_kind: "USER", user_id: "analyst-1", role: "ANALYST" });

    renderRoute();
    expect(await screen.findByRole("link", { name: /^sign in$/i })).toBeVisible();
    expect(screen.getByRole("link", { name: /^privacy$/i })).toBeVisible();
    expect(screen.queryByRole("link", { name: /^history$/i })).not.toBeInTheDocument();
    cleanup();

    renderRoute();
    expect(await screen.findByRole("link", { name: /^history$/i })).toBeVisible();
    expect(screen.queryByRole("link", { name: /^account$/i })).not.toBeInTheDocument();
    cleanup();

    renderRoute();
    expect((await screen.findAllByRole("link", { name: /^account/i })).some((link) => link.classList.contains("user-chip"))).toBe(true);
    expect(screen.getByRole("link", { name: /open workspace/i })).toHaveAttribute("href", "/analyst/cases");
    expect(screen.getByRole("button", { name: /^sign out$/i })).toBeVisible();
    expect(me).toHaveBeenCalledTimes(3);
  });

  it("provides a dedicated privacy page to anonymous, guest, and signed-in users", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: false, session_kind: "GUEST", user_id: null, role: null });
    renderRoute("/privacy");

    expect(await screen.findByRole("heading", { name: /you choose what leaves your browser session/i })).toBeVisible();
    expect(screen.getByRole("heading", { name: /local-only is the default/i })).toBeVisible();
    expect(screen.getByText(/guest scans expire after one hour/i)).toBeVisible();
    expect(screen.getByRole("link", { name: /review guest history/i })).toHaveAttribute("href", "/history");
  });

  it("explains the analysis pipeline on a dedicated public route", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: false, session_kind: "ANONYMOUS", user_id: null, role: null });
    renderRoute("/how-it-works");

    expect(await screen.findByRole("heading", { name: /evidence first. verdict second/i })).toBeVisible();
    expect(screen.getByRole("heading", { name: /^local-only$/i })).toBeVisible();
    expect(screen.getByRole("heading", { name: /^enriched$/i })).toBeVisible();
    expect(screen.getByText(/unavailable evidence never becomes a safe signal/i)).toBeVisible();
  });

  it("preserves a validated internal destination when authentication is required", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: false, session_kind: "ANONYMOUS", user_id: null, role: null });
    renderRoute("/admin?section=users");

    const link = (await screen.findAllByRole("link", { name: /^sign in$/i })).find((item) => item.getAttribute("href")?.includes("from="));
    expect(link).toBeDefined();
    expect(link).toHaveAttribute("href", "/sign-in?from=%2Fadmin%3Fsection%3Dusers");
  });

  it("filters workspace navigation by role", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "analyst-1", role: "ANALYST" });
    vi.spyOn(api, "listReviewCases").mockResolvedValue([]);
    renderRoute("/analyst/cases");

    expect(await screen.findByRole("heading", { name: /review cases/i })).toBeVisible();
    expect(screen.getByRole("link", { name: /^cases$/i })).toBeVisible();
    expect(screen.queryByRole("link", { name: /administration/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /^research$/i })).not.toBeInTheDocument();
  });

  it("moves focus to main content only when the pathname changes", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: false, session_kind: "GUEST", user_id: null, role: null });
    vi.spyOn(api, "listScans").mockResolvedValue([]);
    renderRoute();

    const main = document.getElementById("main-content");
    expect(document.activeElement).not.toBe(main);
    await user.click(await screen.findByRole("link", { name: /^history$/i }));
    await screen.findByRole("heading", { name: /scan history/i });
    expect(document.activeElement).toBe(main);
  });

  it("clears the local session and leaves the protected route when sign-out revocation fails", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "analyst-1", role: "ANALYST" });
    vi.spyOn(api, "listReviewCases").mockResolvedValue([]);
    vi.spyOn(api, "endSession").mockRejectedValue(new ApiError(503, "Unavailable", "api_unavailable"));
    renderRoute("/analyst/cases");

    await screen.findByRole("heading", { name: /review cases/i });
    await user.click(screen.getByRole("button", { name: /^sign out$/i }));

    expect(await screen.findByRole("heading", { name: /sign in to phishguard/i })).toBeVisible();
    expect(screen.getByText(/signed out locally/i)).toBeVisible();
  });

  it("distinguishes model deployment approval from runtime activation", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "admin-1", role: "ADMINISTRATOR" });
    vi.spyOn(api, "getAdminHealth").mockResolvedValue({ database: "available", jobs: {}, checked_at: "2026-07-22T10:00:00Z" });
    vi.spyOn(api, "listDecisionPolicies").mockResolvedValue([]);
    vi.spyOn(api, "listModels").mockResolvedValue([{
      id: "model-real-001",
      version: "url-logistic-1.0",
      artifact_uri: "gs://approved-models/url-logistic-1.0.joblib",
      sha256: "b".repeat(64),
      metrics: {},
      approved_for_deployment: true,
      runtime_active: false,
    }]);

    renderRoute("/admin");
    await screen.findByRole("heading", { name: /control centre/i });
    await user.click(screen.getByRole("button", { name: /policies & models/i }));

    expect(await screen.findByText("Approved for deployment")).toBeVisible();
    expect(screen.getByText(/approval is not runtime activation/i)).toBeVisible();
    expect(screen.queryByText(/^Runtime active$/i)).not.toBeInTheDocument();
  });

  it("shows canonical-administrator health and protects the canonical user row", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "admin-1", role: "ADMINISTRATOR", is_canonical_admin: true });
    vi.spyOn(api, "getAdminHealth").mockResolvedValue({ database: "available", jobs: {}, canonical_admin: { status: "CONFIGURED", count: 1 }, checked_at: "2026-07-22T10:00:00Z" });
    vi.spyOn(api, "listAdminUsers").mockResolvedValue([
      { id: "admin-1", role: "ADMINISTRATOR", is_canonical_admin: true, email_verified: true, mfa_verified: true, disabled: false, created_at: "2026-07-22T10:00:00Z" },
      { id: "admin-2", role: "ADMINISTRATOR", is_canonical_admin: false, email_verified: true, mfa_verified: true, disabled: false, created_at: "2026-07-22T10:00:00Z" },
    ]);
    renderRoute("/admin");

    expect(await screen.findByText(/canonical administrator: configured/i)).toBeVisible();
    await user.click(screen.getByRole("button", { name: /^users$/i }));
    expect(await screen.findByText(/immutable in application ui/i)).toBeVisible();
    expect(screen.queryByLabelText("Role for admin-1")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Role for admin-2")).toBeVisible();
  });

  it("approves pending role requests with the governed upper-case action", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "admin-1", role: "ADMINISTRATOR", is_canonical_admin: true });
    vi.spyOn(api, "getAdminHealth").mockResolvedValue({ database: "available", jobs: {}, canonical_admin: { status: "CONFIGURED", count: 1 }, checked_at: "2026-07-22T10:00:00Z" });
    const request = roleRequestFixture();
    vi.spyOn(api, "listRoleRequests").mockResolvedValue([request]);
    const decide = vi.spyOn(api, "decideRoleRequest").mockResolvedValue({ ...request, state: "APPROVED", decided_at: "2026-07-22T10:05:00Z", decided_by_user_id: "admin-1" });
    renderRoute("/admin");

    await screen.findByRole("heading", { name: /control centre/i });
    await user.click(screen.getByRole("button", { name: /role requests/i }));
    expect(await screen.findByText(/analyst request/i)).toBeVisible();
    await user.click(screen.getByRole("button", { name: /^approve$/i }));
    expect(decide).toHaveBeenCalledWith(request.id, "APPROVE");
    expect(await screen.findByRole("heading", { name: /no pending role requests/i })).toBeVisible();
  });

  it("falls back to local demo analysis without retaining a query string", async () => {
    vi.stubEnv("VITE_DEMO_FALLBACK", "true");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));
    const response = await api.createScan({
      url: "https://münich.example/login?token=secret#fragment",
      analysis_mode: "local_only",
      enrichment_consent: false,
    });

    expect(response.demo).toBe(true);
    expect(response.scan.simulated).toBe(true);
    expect(response.scan.display_url).toContain("münich.example/[path hidden]");
    expect(response.scan.display_url).toContain("?[query hidden]");
    expect(response.scan.ascii_display_url).toContain("xn--mnich-kva.example/[path hidden]");
    expect(localStorage.getItem("phishguard.demo.scans")).not.toContain("secret");
  });

  it("labels simulated results persistently and never invents external provider evidence", async () => {
    vi.stubEnv("VITE_DEMO_FALLBACK", "true");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));
    const response = await api.createScan({
      url: "https://verify-account.example/login",
      analysis_mode: "enriched",
      enrichment_consent: true,
    });

    expect(response.scan.status).toBe("PARTIAL");
    expect(response.scan.decision.completion).toBe("PARTIAL");
    expect(JSON.stringify(response.scan.decision)).not.toContain("Google Web Risk Lookup");
    expect(JSON.stringify(response.scan.decision)).not.toContain("Social-engineering match");

    renderRoute(`/scan/${response.scan.id}`);
    expect(await screen.findByText(/simulated data — not a live assessment/i)).toBeVisible();
    expect(screen.getByText(/google web risk and the destination were not contacted/i)).toBeVisible();
  });

  it("keeps a rule-only fallback warning visible beside the result status", async () => {
    vi.spyOn(api, "getScanUpdate").mockResolvedValue({ scan: scanFixture("COMPLETE", "RULE_ONLY") });

    renderRoute("/scan/scan-real-001");

    expect(await screen.findByText("Rule-only fallback")).toBeVisible();
    expect(screen.getByText("Rule-only fallback").closest(".result-badges")).toBeTruthy();
  });

  it("uses the approved risk headlines for every verdict", () => {
    expect(verdictPresentation("HIGH").title).toBe("Avoid this link.");
    expect(verdictPresentation("MEDIUM").title).toBe("Use caution with this link.");
    expect(verdictPresentation("LOW").title).toBe("No strong phishing indicators found.");
    expect(verdictPresentation("INCONCLUSIVE").title).toBe("Treat this link as unverified.");
  });

  it("renders structured evidence as readable cards without treating availability as safety", async () => {
    const scan = scanFixture();
    scan.decision.evidence = [{
      id: "dns-1",
      family: "DNS",
      label: "Dns",
      state: "OBSERVED",
      value: { addresses: ["23.92.20.184"] },
      source: "isolated_fetcher:recursive-dns",
      version: "fetcher-0.1.0",
      observed_at: "2026-07-23T04:02:00Z",
    }, {
      id: "reputation-1",
      family: "REPUTATION",
      label: "Reputation",
      state: "NO_MATCH",
      value: {},
      source: "google_web_risk",
      version: "v1",
    }];
    vi.spyOn(api, "getScanUpdate").mockResolvedValue({ scan });
    renderRoute("/scan/scan-real-001");

    fireEvent.click(await screen.findByText("Evidence"));
    expect(screen.getByRole("heading", { name: "DNS" })).toBeVisible();
    expect(screen.getByText(/1 public address resolved: 23\.92\.20\.184/i)).toBeVisible();
    expect(screen.getByText("Available")).toBeVisible();
    expect(screen.getByText("No match")).toBeVisible();
    expect(screen.getByText(/neutral evidence, not proof of safety/i)).toBeVisible();
    expect(screen.getByText(/isolated fetcher · recursive dns/i)).toBeVisible();
  });

  it("makes provisional, partial, and empty-evidence states explicit", async () => {
    const processing = scanFixture("PROCESSING");
    processing.decision.risk_band = "INCONCLUSIVE";
    processing.decision.reasons = [];
    processing.decision.evidence = [];
    vi.spyOn(api, "getScanUpdate").mockResolvedValue({ scan: processing, poll_after_ms: 10_000 });
    renderRoute("/scan/scan-real-001");

    expect(await screen.findByRole("heading", { name: "Treat this link as unverified." })).toBeVisible();
    expect(screen.getByText(/external checks are still running; risk may increase/i)).toBeVisible();
    expect(screen.getByText(/some checks were unavailable\. missing evidence did not lower the risk/i)).toBeVisible();
    expect(screen.getByText(/no specific risk reasons were recorded/i)).toBeVisible();
    fireEvent.click(screen.getByText("Evidence"));
    expect(screen.getByText(/no evidence observations were stored/i)).toBeVisible();
    expect(screen.getByText(/treat this link as unverified/i, { selector: ".next-actions strong" })).toBeVisible();
  });

  it("honours the polling interval, pauses after refresh failure, and retries manually", async () => {
    vi.useFakeTimers();
    const processing = scanFixture("PROCESSING");
    const complete = scanFixture("COMPLETE");
    const getUpdate = vi.spyOn(api, "getScanUpdate")
      .mockResolvedValueOnce({ scan: processing, poll_after_ms: 1_250 })
      .mockRejectedValueOnce(new ApiError(503, "Provider unavailable", "provider_unavailable"))
      .mockResolvedValueOnce({ scan: complete });

    renderRoute("/scan/scan-real-001");
    await act(async () => { await Promise.resolve(); });
    expect(getUpdate).toHaveBeenCalledTimes(1);
    expect(resultPollDelay(1_250, 1)).toBe(2_500);

    await act(async () => { await vi.advanceTimersByTimeAsync(1_249); });
    expect(getUpdate).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });

    expect(screen.getByRole("alert")).toHaveTextContent(/automatic updates paused/i);
    fireEvent.click(screen.getByRole("button", { name: /check again/i }));
    await act(async () => { await Promise.resolve(); });

    expect(getUpdate).toHaveBeenCalledTimes(3);
    expect(screen.getByText("Complete", { selector: ".status-complete" })).toBeVisible();
  });

  it("announces exactly one processing-to-final transition atomically", async () => {
    vi.useFakeTimers();
    vi.spyOn(api, "getScanUpdate")
      .mockResolvedValueOnce({ scan: scanFixture("PROCESSING"), poll_after_ms: 250 })
      .mockResolvedValueOnce({ scan: scanFixture("COMPLETE") });
    const { container } = renderRoute("/scan/scan-real-001");
    await act(async () => { await Promise.resolve(); });

    const liveRegions = container.querySelectorAll('[aria-live="polite"]');
    expect(liveRegions).toHaveLength(1);
    expect(liveRegions[0]).toHaveTextContent("");
    await act(async () => { await vi.advanceTimersByTimeAsync(250); });
    expect(liveRegions[0]).toHaveAttribute("aria-atomic", "true");
    expect(liveRegions[0]).toHaveTextContent("Analysis complete. Medium risk. Complete evidence coverage.");
  });

  it("stops automatic result polling at the two-minute processing deadline", async () => {
    vi.useFakeTimers();
    const getUpdate = vi.spyOn(api, "getScanUpdate").mockResolvedValue({
      scan: scanFixture("PROCESSING"),
      poll_after_ms: 10_000,
    });

    renderRoute("/scan/scan-real-001");
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(RESULT_POLL_DEADLINE_MS); });

    expect(screen.getByRole("status")).toHaveTextContent(/has not finished within two minutes/i);
    const callsAtDeadline = getUpdate.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(getUpdate).toHaveBeenCalledTimes(callsAtDeadline);
    expect(screen.getByRole("button", { name: /check again/i })).toBeVisible();
  });

  it("offers governed role intent during registration without offering administrator", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: false, session_kind: "ANONYMOUS", user_id: null, role: null });
    renderRoute("/sign-in");

    await user.click(await screen.findByRole("button", { name: /create an account/i }));
    const roles = screen.getByLabelText(/intended account role/i);
    expect(within(roles).getByRole("option", { name: /^registered user$/i })).toBeVisible();
    expect(within(roles).getByRole("option", { name: /analyst.*approval required/i })).toBeVisible();
    expect(within(roles).getByRole("option", { name: /researcher.*approval required/i })).toBeVisible();
    expect(within(roles).queryByRole("option", { name: /administrator/i })).not.toBeInTheDocument();
  });

  it("confirms history deletion, preserves failures, and announces success", async () => {
    const user = userEvent.setup();
    const scan = scanFixture();
    vi.spyOn(api, "listScans").mockResolvedValue([scan]);
    const deleteScan = vi.spyOn(api, "deleteScan")
      .mockRejectedValueOnce(new ApiError(503, "Deletion is temporarily unavailable", "delete_unavailable"))
      .mockResolvedValueOnce();

    renderRoute("/history");
    await screen.findByRole("link", { name: scan.display_url });
    await user.click(screen.getByRole("button", { name: `Delete scan for ${scan.display_url}` }));

    const dialog = screen.getByRole("dialog", { name: /delete this scan/i });
    expect(dialog).toHaveAttribute("aria-describedby", "delete-scan-description");
    expect(deleteScan).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: /^delete scan$/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/temporarily unavailable/i);
    expect(screen.getByRole("link", { name: scan.display_url })).toBeVisible();

    await user.click(screen.getByRole("button", { name: /^delete scan$/i }));
    expect(await screen.findByRole("status")).toHaveTextContent(/scan deleted from history/i);
    expect(deleteScan).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("link", { name: scan.display_url })).not.toBeInTheDocument();
  });

  it("keeps history error and empty states mutually exclusive and supports retry", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "listScans").mockRejectedValueOnce(new ApiError(503, "Unavailable")).mockResolvedValueOnce([]);
    renderRoute("/history");

    expect(await screen.findByRole("heading", { name: /history unavailable/i })).toBeVisible();
    expect(screen.queryByRole("heading", { name: /no saved scans/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /try again/i }));
    expect(await screen.findByRole("heading", { name: /no saved scans/i })).toBeVisible();
    expect(screen.queryByRole("heading", { name: /history unavailable/i })).not.toBeInTheDocument();
  });

  it("updates retention and downloads the redacted account export", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({
      authenticated: true,
      session_kind: "USER",
      user_id: "user-1",
      role: "REGISTERED_USER",
      scan_retention_days: 30,
      scan_retention_max_days: 30,
    });
    const updateRetention = vi.spyOn(api, "updateAccountRetention").mockResolvedValue({
      scan_retention_days: 7,
      applies_to: "new_scans",
    });
    vi.spyOn(api, "exportAccount").mockResolvedValue({
      schema_version: "phishguard-account-export/1",
      generated_at: "2026-07-22T10:00:00Z",
      user_id: "user-1",
      scans: [scanFixture()],
      identity_platform_identity_included: false,
    });
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: vi.fn(() => "blob:export") });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    renderRoute("/account");
    await screen.findByRole("heading", { name: /privacy and account/i });
    await user.selectOptions(screen.getByLabelText(/keep new scans for/i), "7");
    await user.click(screen.getByRole("button", { name: /save retention/i }));

    expect(updateRetention).toHaveBeenCalledWith(7);
    expect(await screen.findByRole("status")).toHaveTextContent(/retained for 7 days/i);
    await user.click(screen.getByRole("button", { name: /download json/i }));
    expect(await screen.findByRole("status")).toHaveTextContent(/redacted account export was downloaded/i);
    expect(URL.createObjectURL).toHaveBeenCalled();
  });

  it("creates and cancels a governed workspace role request from the account page", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({
      authenticated: true,
      session_kind: "USER",
      user_id: "user-1",
      role: "REGISTERED_USER",
      role_request: null,
      scan_retention_days: 30,
      scan_retention_max_days: 30,
    });
    const request = roleRequestFixture();
    const create = vi.spyOn(api, "createRoleRequest").mockResolvedValue(request);
    const cancel = vi.spyOn(api, "cancelRoleRequest").mockResolvedValue();
    renderRoute("/account");

    await screen.findByRole("heading", { name: /workspace access/i });
    await user.click(screen.getByRole("button", { name: /request access/i }));
    expect(create).toHaveBeenCalledWith("ANALYST");
    expect(await screen.findByText(/analyst access pending/i)).toBeVisible();

    await user.click(screen.getByRole("button", { name: /cancel request/i }));
    expect(cancel).toHaveBeenCalledWith(request.id);
    expect(await screen.findByRole("status")).toHaveTextContent(/pending role request was cancelled/i);
  });

  it("confirms account-wide scan deletion and explains the identity boundary", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({
      authenticated: true,
      session_kind: "USER",
      user_id: "user-1",
      role: "REGISTERED_USER",
      scan_retention_days: 30,
      scan_retention_max_days: 30,
    });
    const deleteScans = vi.spyOn(api, "deleteAccountScans").mockResolvedValue({
      status: "deleted",
      deleted_scan_count: 2,
      application_sessions_revoked: true,
      identity_platform_identity_deleted: false,
    });
    vi.spyOn(api, "endSession").mockResolvedValue();

    renderRoute("/account");
    await screen.findByRole("heading", { name: /privacy and account/i });
    await user.click(screen.getByRole("button", { name: /^delete all scan data$/i }));
    const dialog = screen.getByRole("dialog", { name: /delete all scan data/i });
    expect(dialog).toHaveTextContent(/does not delete your google identity platform identity/i);
    await user.click(within(dialog).getByRole("button", { name: /^delete all scan data$/i }));

    expect(deleteScans).toHaveBeenCalledOnce();
    expect(await screen.findByRole("heading", { name: /sign in to phishguard/i })).toBeVisible();
  });

  it("sends CSRF and idempotency headers for account governance actions", async () => {
    document.cookie = "phishguard_csrf=account-csrf; path=/";
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        schema_version: "phishguard-account-export/1",
        generated_at: "2026-07-22T10:00:00Z",
        user_id: "user-1",
        scans: [],
        identity_platform_identity_included: false,
      }), { status: 200, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ scan_retention_days: 7, applies_to: "new_scans" }), { status: 200, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ status: "deleted", deleted_scan_count: 0, application_sessions_revoked: true, identity_platform_identity_deleted: false }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await api.exportAccount();
    await api.updateAccountRetention(7);
    await api.deleteAccountScans();

    for (const [, init] of fetchMock.mock.calls as [string, RequestInit][]) {
      expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("account-csrf");
    }
    expect(new Headers((fetchMock.mock.calls[1][1] as RequestInit).headers).get("Idempotency-Key")).toBeTruthy();
    expect(new Headers((fetchMock.mock.calls[2][1] as RequestInit).headers).get("Idempotency-Key")).toBeTruthy();
  });

  it("uses the plural role-request contract and retains structured API error details", async () => {
    document.cookie = "phishguard_csrf=role-csrf; path=/";
    const request = roleRequestFixture();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(request), { status: 201, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "role_request_pending", message: "A request is already pending.", correlation_id: "correlation-1", fields: { requested_role: "ANALYST" } } }), { status: 409, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await api.createRoleRequest("ANALYST");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/account/role-requests");
    expect(init.body).toBe(JSON.stringify({ requested_role: "ANALYST" }));
    expect(new Headers(init.headers).get("Idempotency-Key")).toBeTruthy();
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("role-csrf");

    const failure = await api.createRoleRequest("ANALYST").catch((reason: unknown) => reason);
    expect(failure).toBeInstanceOf(ApiError);
    if (!(failure instanceof ApiError)) throw new Error("Expected ApiError");
    expect(failure.correlationId).toBe("correlation-1");
    expect(failure.fields).toEqual({ requested_role: "ANALYST" });
  });

  it("sends JSON, idempotency and CSRF headers to the scan API", async () => {
    document.cookie = "phishguard_csrf=test-csrf; path=/";
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      scan: {
        id: "scan-1",
        display_url: "https://example.test/login",
        status: "COMPLETE",
        requested_mode: "local_only",
        created_at: "2026-07-22T10:00:00Z",
        updated_at: "2026-07-22T10:00:00Z",
        decision: {},
      },
    }), { status: 201, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await api.createScan({ url: "https://example.test/login", analysis_mode: "local_only", enrichment_consent: false });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(headers.get("Idempotency-Key")).toBeTruthy();
    expect(headers.get("X-CSRF-Token")).toBe("test-csrf");
  });

  it("creates and resolves an unguessable demo report without exposing the submitted query", async () => {
    vi.stubEnv("VITE_DEMO_FALLBACK", "true");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));
    const created = await api.createScan({
      url: "https://example.test/login?token=private#fragment",
      analysis_mode: "local_only",
      enrichment_consent: false,
    });
    const share = await api.createShare(created.scan.id);
    const report = await api.getReport(share.report_id);

    expect(share.report_id).toMatch(/^demo-report-/);
    expect(report.scan.id).toBe(created.scan.id);
    expect(JSON.stringify(report)).not.toContain("private");
  });

  it("prevents duplicate feedback submission and surfaces API failure", async () => {
    const user = userEvent.setup();
    let rejectSubmission: (reason: unknown) => void = () => undefined;
    vi.spyOn(api, "submitFeedback").mockImplementation(() => new Promise<never>((_resolve, reject) => { rejectSubmission = reject; }));
    renderRoute("/feedback/scan-real-001");

    await user.click(screen.getByRole("radio", { name: /more dangerous/i }));
    await user.click(screen.getByRole("button", { name: /submit feedback/i }));
    expect(screen.getByRole("button", { name: /submitting/i })).toBeDisabled();
    await act(async () => { rejectSubmission(new ApiError(503, "Feedback service unavailable")); });
    expect(await screen.findByRole("alert")).toHaveTextContent(/feedback service unavailable/i);
    expect(screen.getByRole("button", { name: /submit feedback/i })).toBeEnabled();
  });

  it("renders analyst cases returned by the API without placeholder targets", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "analyst-1", role: "ANALYST" });
    vi.spyOn(api, "listReviewCases").mockResolvedValue([{
      id: "case-real-001",
      scan_id: "scan-real-001",
      feedback_id: null,
      state: "OPEN",
      claimed_by: null,
      updated_at: "2026-07-22T10:00:00Z",
    }]);

    renderRoute("/analyst/cases");

    expect(await screen.findByText("case-real-001")).toBeVisible();
    expect(screen.getByText("scan-real-001")).toBeVisible();
    expect(screen.queryByText(/micr0soft/i)).not.toBeInTheDocument();
  });

  it("shows quarantined feedback content in the analyst review workspace", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "analyst-1", role: "ANALYST" });
    vi.spyOn(api, "getReviewCase").mockResolvedValue({
      id: "case-real-001",
      scan_id: "scan-real-001",
      feedback_id: "feedback-real-001",
      state: "OPEN",
      claimed_by: null,
      updated_at: "2026-07-22T10:00:00Z",
      feedback: {
        id: "feedback-real-001",
        category: "FALSE_NEGATIVE",
        comment: "The page requested an account password.",
        status: "QUARANTINED",
        research_consent: false,
        created_at: "2026-07-22T09:55:00Z",
      },
      events: [],
    });
    vi.spyOn(api, "getScan").mockRejectedValue(new ApiError(404, "Unavailable", "not_found"));

    renderRoute("/analyst/cases/case-real-001");

    expect(await screen.findByRole("heading", { name: /submitted feedback/i })).toBeVisible();
    expect(screen.getByText("The page requested an account password.")).toBeVisible();
    expect(screen.getByText("FALSE NEGATIVE")).toBeVisible();
    expect(screen.getByText("QUARANTINED")).toBeVisible();
  });

  it("shows real research registry records and governed creation controls", async () => {
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "researcher-1", role: "RESEARCHER" });
    vi.spyOn(api, "listDatasets").mockResolvedValue([{
      id: "dataset-real-001",
      name: "OpenPhish temporal snapshot",
      sha256: "a".repeat(64),
      manifest: { source: "OpenPhish Academic" },
      state: "APPROVED",
      created_at: "2026-07-22T10:00:00Z",
    }]);
    vi.spyOn(api, "listExperiments").mockResolvedValue([]);
    vi.spyOn(api, "listResearchExports").mockResolvedValue([]);

    renderRoute("/research");

    expect(await screen.findByText("OpenPhish temporal snapshot")).toBeVisible();
    expect(screen.getByRole("heading", { name: /register a dataset snapshot/i })).toBeVisible();
    expect(screen.queryByText(/PG-2026/i)).not.toBeInTheDocument();
  });

  it("sends CSRF and idempotency headers for review-case transitions", async () => {
    document.cookie = "phishguard_csrf=review-csrf; path=/";
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: "case-real-001",
      scan_id: "scan-real-001",
      feedback_id: null,
      state: "CLAIMED",
      claimed_by: "analyst-1",
      updated_at: "2026-07-22T10:00:00Z",
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await api.reviewCaseAction("case-real-001", { action: "claim" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(url).toBe("/api/v1/review-cases/case-real-001/actions");
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ action: "claim" }));
    expect(headers.get("Idempotency-Key")).toBeTruthy();
    expect(headers.get("X-CSRF-Token")).toBe("review-csrf");
  });

  it("opens fresh verification before retrying a protected admin change", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "me").mockResolvedValue({ authenticated: true, session_kind: "USER", user_id: "admin-1", role: "ADMINISTRATOR" });
    vi.spyOn(api, "getAdminHealth").mockResolvedValue({ database: "available", jobs: {}, checked_at: "2026-07-22T10:00:00Z" });
    vi.spyOn(api, "listAdminUsers").mockResolvedValue([{
      id: "user-real-001",
      role: "REGISTERED_USER",
      email_verified: true,
      mfa_verified: false,
      disabled: false,
      created_at: "2026-07-22T10:00:00Z",
    }]);
    vi.spyOn(api, "updateAdminUser").mockRejectedValueOnce(new ApiError(403, "Authentication within the last five minutes is required", "fresh_auth_required"));

    renderRoute("/admin");
    await screen.findByRole("heading", { name: /control centre/i });
    await user.click(screen.getByRole("button", { name: /users/i }));
    await screen.findByText("user-real-001");
    await user.click(screen.getByRole("button", { name: /^save$/i }));

    expect(await screen.findByRole("heading", { name: /verify it’s you/i })).toBeVisible();
    expect(screen.getByLabelText(/identity platform password/i)).toBeVisible();
    expect(screen.getByText(/phishguard receives only a verified id token/i)).toBeVisible();
  });

  it("sends only the verified ID token to the session reauthentication API", async () => {
    document.cookie = "phishguard_csrf=reauth-csrf; path=/";
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ status: "reauthenticated" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await api.reauthenticate("verified-identity-token");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/session/reauth");
    expect(init.body).toBe(JSON.stringify({ id_token: "verified-identity-token" }));
    expect(init.body).not.toContain("password");
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("reauth-csrf");
  });
});
