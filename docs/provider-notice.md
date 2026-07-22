# External enrichment provider notice

Version: 2026-07-22

Enrichment is optional and off by default. When selected:

- **Google Web Risk Lookup:** PhishGuard sends the complete submitted URL to Google to request social-engineering and malware-list matches. Google may process request metadata under the operator's Google Cloud agreement and applicable Google terms. A no-match is neutral and does not mean safe.
- **DNS, RDAP, TLS, redirects, and static HTML:** the isolated fetcher contacts resolvers, registries, certificate endpoints, and the submitted public host. The target may observe the scanner's fixed egress IP, hostname request, TLS handshake, time, and user agent. PhishGuard does not execute JavaScript, load subresources, submit credentials, or retain response bodies.

Provider timeout, denial, quota exhaustion, and safety rejection are recorded as missing/partial evidence; they are never converted to benign evidence. Reputation cannot determine the risk band without a corroborating local signal.

OpenPhish Academic and Tranco are governed research inputs, not live runtime lookups. Web Risk verdicts are not training labels. Research artefacts must follow their licences, attribution rules, access limits, and non-redistribution obligations.

