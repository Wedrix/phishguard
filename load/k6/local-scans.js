import http from "k6/http";
import { check, sleep } from "k6";

const baseUrl = __ENV.BASE_URL || "http://127.0.0.1:8080";
const profile = __ENV.K6_PROFILE || "throughput";

const scenarios = {
  latency: {
    executor: "constant-vus",
    vus: 20,
    duration: __ENV.K6_DURATION || "2m",
  },
  throughput: {
    executor: "constant-arrival-rate",
    rate: 60,
    timeUnit: "1m",
    duration: __ENV.K6_DURATION || "15m",
    preAllocatedVUs: 10,
    maxVUs: 40,
  },
};

if (!scenarios[profile]) throw new Error("K6_PROFILE must be latency or throughput");

export const options = {
  scenarios: { [profile]: scenarios[profile] },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    "http_req_duration{operation:create_local_scan}": ["p(95)<1500"],
    checks: ["rate>0.99"],
  },
};

export default function () {
  const cookies = http.cookieJar().cookiesForURL(baseUrl);
  const csrf = cookies.phishguard_csrf?.[0];
  const headers = {
    "Content-Type": "application/json",
    "Idempotency-Key": `k6-${__VU}-${__ITER}-${Date.now()}`,
  };
  if (csrf) headers["X-CSRF-Token"] = csrf;

  const response = http.post(
    `${baseUrl}/api/v1/scans`,
    JSON.stringify({
      url: `https://load-${__VU}-${__ITER}.example/account`,
      analysis_mode: "local_only",
      enrichment_consent: false,
    }),
    { headers, tags: { operation: "create_local_scan" } },
  );

  check(response, {
    "local scan returns 201": (result) => result.status === 201,
    "local scan is complete": (result) => result.json("scan.status") === "COMPLETE",
    "local scan stays local": (result) => result.json("scan.decision.analysis_scope") === "LOCAL_ONLY",
  });

  if (profile === "latency") sleep(1);
}
