# Pinned RDAP bootstrap

- Source: `https://data.iana.org/rdap/dns.json`
- IANA publication time: `2026-07-14T22:00:03Z`
- Retrieved: `2026-07-22`
- SHA-256: `bd6802420291079b3b87653da5a622b5bbfcc1a4bc56d97be9a9b1ba3a7b4f3f`

The fetcher never downloads this file at runtime. Update it as an explicit,
reviewed dependency change, record the new hash, rebuild the image, and rerun
the SSRF suite before deployment.

`public-suffix-list.dat` is the pinned Public Suffix List used to select the
registrable domain for RDAP. Runtime matching uses only its ICANN section.

- Source: `https://publicsuffix.org/list/public_suffix_list.dat`
- PSL version: `2026-07-20_19-57-20_UTC`
- Commit: `ca355e4aadee94e349e1f9c86145618cf762249d`
- Retrieved: `2026-07-22`
- SHA-256: `bc29842a9ffd0b804db0094ba649d2365224f6b65cd415271dc90fa6005f2856`
