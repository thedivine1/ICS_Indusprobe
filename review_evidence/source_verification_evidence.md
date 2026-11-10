# Source Verification Evidence Log

**Environment**: macOS (Darwin)  
**Retrieval Methodology**: Bounded discovery fetch (no bulk harvesting)  
**Status**: Authoritative records retrieved and verified for SHA-256 integrity.

---

## 1. Verified Official Artifacts

| Source Identifier | Document Role | Canonical URL | Retrieval Timestamp (UTC) | HTTP Status | Content-Type | Size (Bytes) | SHA-256 Checksum | Schema Detected |
|---|---|---|---|---|---|---|---|---|
| **CVE-2020-7537** | Official CVE Record | `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2020/7xxx/CVE-2020-7537.json` | 2026-11-10T10:17:25Z | 200 OK | application/json | 6,286 | `8de4724a87ad1e0b5ef37e584f107936a282f6e5229efaf988c5a27896173a5a` | CVE JSON 5.1 |
| **CVE-2021-22779** | Official CVE Record | `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/22xxx/CVE-2021-22779.json` | 2026-11-10T10:17:25Z | 200 OK | application/json | 10,012 | `c81011df64cb5d4ce5e7ef34fe06cfa0fe3ea43d34a413d9434857dd5ee0fa09` | CVE JSON 5.1 |
| **CVE-2018-10620** | Official CVE Record | `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2018/10xxx/CVE-2018-10620.json` | 2026-11-10T10:17:25Z | 200 OK | application/json | 9,393 | `ec542cec349195b0fe21aa5b6ceee57cb341c2c31c0c6606a380ce3e970a2fdf` | CVE JSON 5.1 |
| **SEVD-2020-343-08** | Vendor CSAF Advisory | `https://www.se.com/.well-known/csaf/2020/sevd-2020-343-08.json` | 2026-11-10T11:16:30Z | 200 OK | application/json | 30,178 | `8590e455e3725b87c7aa8853b8fbf4c6439e76722d307771ea683ae594fe3d10` | CSAF 2.0 |
| **SEVD-2021-194-01** | Vendor CSAF Advisory | `https://www.se.com/.well-known/csaf/2021/sevd-2021-194-01.json` | 2026-11-10T11:16:45Z | 200 OK | application/json | 74,573 | `b5e3a3251e7bcbbdf2c3e1b74737d2fbf0d3d19129e9aeec765c4fc9ce6ff7a2` | CSAF 2.0 |
| **Schneider Provider Metadata** | Vendor CSAF Index | `https://www.se.com/.well-known/csaf/provider-metadata.json` | 2026-11-10T11:44:29Z | 200 OK | application/json | 1,008 | `7cc8c35e9fca21272719114f6b158bb68bce73663bfe773099042b5ba476a8d7` | CSAF 2.0 Metadata |
| **ICSA-22-090-05** | CISA Rockwell Mirror | `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf/white/2022/icsa-22-090-05.json` | 2026-11-10T12:13:33Z | 200 OK | application/json | 35,948 | `da22c37a6cb394d682496d59b21f37e46ea95d2c525f058097b69b5966d58253` | CSAF 2.0 (CISA) |
| **CISA Known Exploited Vulns** | Known Exploited Catalog | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 2026-11-10T11:38:52Z | 200 OK | application/json | ~1.8 MB | ETag: `"8413a9681cb9f4089304343110bbce2b"` | CISA KEV JSON |

---

## 2. Access Restrictions and Observations

1. **Schneider Electric Direct Endpoint**:
   - `download.schneider-electric.com/.well-known/csaf/` issues a 301 redirect to `download.se.com`, which returns HTTP 404.
   - The verified working endpoint is `https://www.se.com/.well-known/csaf/`.
   - Access is public and unauthenticated.

2. **Rockwell Automation Direct Endpoint**:
   - `https://www.rockwellautomation.com/.well-known/csaf/provider-metadata.json` returns **HTTP 403 Forbidden** (Akamai Edge Server WAF).
   - Direct harvesting is blocked by the CDN.
   - Authoritative fallback: CISA ICS-CERT CSAF repository (`github.com/cisagov/CSAF`), where official CSAF 2.0 translations of Rockwell advisories are published with CISA attribution.

3. **Rate Throttling Disclosure**:
   - The 2 requests/second limit implemented in `fetcher.py` is an **internal defensive client throttle**, not an authoritative vendor-published rate quota.

