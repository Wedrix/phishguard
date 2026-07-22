# PhishGuard isolated fetcher

This package is the only workload allowed to make requests to target-controlled
hosts. It has no database, Google Cloud, Kubernetes, identity, object-store, or
reputation-provider credentials. In GKE it runs under gVisor with mutual TLS,
no service-account token, a read-only root filesystem, and public HTTP/HTTPS
egress only.

## Contract

`POST /internal/v1/enrich` accepts a schema-closed request:

```json
{
  "schema_version": 1,
  "analysis_run_id": "11111111-1111-4111-8111-111111111111",
  "correlation_id": "22222222-2222-4222-8222-222222222222",
  "target_url": "https://example.com/",
  "allowed_ports": [80, 443]
}
```

The response contains bounded DNS, RDAP, TLS, redirect and static-HTML
observations. It never contains the final full URL, an HTTP response body,
HTML, page text, credentials, cookies, or executable content.

## Enforced ceilings

- three redirects and a ten-second total retrieval deadline;
- two-second connect and five-second read deadlines;
- 64 KiB response headers;
- 2 MiB wire and decoded bodies, with a 20:1 decompression ceiling;
- 256 KiB identity-encoded JSON from HTTPS-only RDAP bootstrap endpoints;
- HTML/XHTML only for content features;
- no scripts, subresources, cookies, referrer, authentication or downloads;
- every address in every DNS answer set must be globally routable;
- the validated address set is pinned while the original host remains the
  HTTP Host, TLS SNI and certificate-verification name.
- RDAP queries use the registrable domain selected from a pinned ICANN Public
  Suffix List snapshot.

The request can reduce any ceiling, but cannot raise one.

## Local verification

```sh
uv sync --extra dev
uv run pytest
```

For local Compose only, `FETCHER_DEV_INSECURE=true` disables mTLS. Deployment
must provide `FETCHER_TLS_KEY`, `FETCHER_TLS_CERT`, and `FETCHER_CLIENT_CA`.
