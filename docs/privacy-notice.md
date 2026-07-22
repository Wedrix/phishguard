# PhishGuard privacy notice

Version: 2026-07-22

PhishGuard processes the URL you submit to estimate phishing risk. It is an experimental decision-support tool and cannot guarantee that a URL is safe.

## Local-only analysis

Local-only is the default. The PhishGuard application receives the URL, encrypts the original value, and derives structural features locally. It does not perform URL-derived DNS, registration, reputation, target, or cached external-evidence lookups. The application still uses its normal hosting, security, and identity services.

## Optional enriched analysis

If you affirmatively choose enrichment, PhishGuard may send the full URL to Google Web Risk and resolve or connect to the submitted host to collect bounded DNS, RDAP, TLS, redirect, and static-HTML observations. This can reveal the complete hostname, path, query, or fragment to Google and can reveal the scanner's fixed egress IP and request to the target and relevant infrastructure providers. Review the provider notice before consenting.

## Storage and access

The original URL is encrypted with Cloud KMS. A redacted form may appear in results; a keyed digest supports deduplication. Evidence stores bounded observations, not fetched bodies. Logs exclude raw URLs, query strings, fragments, email addresses, tokens, and target content. Access is limited by role and object ownership and is audited.

Guest sessions expire after one hour. The demo default for registered scan retention is 30 days; registered users may select a shorter period for new scans. Account export contains redacted scan history and stored decisions, never decrypted original URLs. Account-wide scan deletion revokes reports and PhishGuard application sessions but does not delete the separately managed Google Identity Platform identity. Backups may retain encrypted data for up to 30 days.

Do not submit URLs containing personal, confidential, authentication, or regulated information. Contact the project operator shown in the deployed application's About page to request access, correction, export, or deletion, or to report a privacy incident.
