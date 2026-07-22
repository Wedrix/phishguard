# Load profiles

Run against a disposable environment. Each iteration persists a real local-only scan; the script never requests enrichment or contacts the submitted destination.

```sh
K6_PROFILE=latency k6 run load/k6/local-scans.js
K6_PROFILE=throughput k6 run load/k6/local-scans.js
```

`latency` uses 20 concurrent virtual users and enforces local-scan p95 below 1.5 seconds. `throughput` submits 60 scans per minute for 15 minutes and enforces an error rate below 1%. Override `BASE_URL` and, for a short rehearsal, `K6_DURATION`.

Archive the k6 JSON summary, application metrics and deployment identifiers with the acceptance evidence. Enriched processing latency is intentionally measured separately in the controlled deployed smoke environment because that exercise requires consented provider and fetcher traffic.
