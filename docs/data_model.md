# IndusProbe Advisory Intelligence — Normalized Data Model Specification
## Database Architecture, SQL DDL & Categorical Taxonomy

**Document Version:** 1.1.0-REVISED  
**Date:** 2026-11-10  
**Storage Engine:** SQLite 3 (WAL Mode) / PostgreSQL Compatible DDL  
**Migration Version:** `schema_v1.0.0`  
**Table Count Reconciled:** Exactly 11 Tables  
**Status:** PROPOSED — PENDING ARCHITECTURAL APPROVAL  

---

## 1. Schema Design Principles

1. **Categorical Evaluation (Non-Ordinal)**: The 8 matching states are strictly **categorical outcomes**, not a ranked severity scale. A status of `INSUFFICIENT_IDENTITY` is an epistemic state, not a "less severe" vulnerability.
2. **Raw String & Source Preservation**: Raw prose descriptions and ambiguous version ranges from CNAs are preserved verbatim. They are never parsed into activated machine-executable bounds without either authoritative structured CSAF product trees or explicit human review.
3. **Multi-Metric CVSS**: Vulnerabilities support multiple simultaneous CVSS ratings (e.g. Vendor CVSS vs NVD CVSS vs CISA CVSS), retaining vector, score, and version without collapsing them.
4. **Analyst Invalidation Conditions**: Every manual review decision records the applicable rule hash and asset fact hash; if either changes, the decision is flagged as stale (`is_stale = 1`).

---

## 2. Reconciled Entity List (11 Tables Total)

1. `schema_migrations`: Version tracking and migration audit log.
2. `source_artifacts`: Immutable content-addressed archive of raw downloaded payloads.
3. `advisories`: Top-level vendor advisory metadata and tracking revisions.
4. `vulnerabilities`: CVE definitions and disclosures.
5. `cvss_metrics`: Multiple CVSS metrics per vulnerability with explicit source attribution.
6. `product_nodes`: Canonical product hierarchy tree (vendor, family, product, model, series).
7. `product_aliases`: Normalized search tokens and legacy brand mappings.
8. `applicability_rules`: Discrete machine-evaluable version and condition assertions.
9. `asset_observations`: Discovered assets with baseline attributes.
10. `asset_fact_provenance`: Granular, per-attribute evidence sources and confidence scores.
11. `match_results`: Categorical matching outcomes linked to matching runs and analyst decisions.

---

## 3. Authoritative SQLite 3 DDL Specification

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ============================================================================
-- 1. Schema Migration & Versioning
-- ============================================================================
CREATE TABLE IF NOT EXISTS schema_migrations (
    version_id          INTEGER PRIMARY KEY,
    version_code        TEXT NOT NULL UNIQUE, -- e.g. 'v1.0.0'
    applied_at_utc      TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    description         TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_migrations (version_id, version_code, description)
VALUES (1, 'v1.0.0', 'Initial normalized advisory intelligence schema');

-- ============================================================================
-- 2. Source Artifacts (Immutable Raw Archive)
-- ============================================================================
CREATE TABLE IF NOT EXISTS source_artifacts (
    artifact_id         TEXT PRIMARY KEY,
    source_id           TEXT NOT NULL,
    requested_url       TEXT NOT NULL,
    final_url           TEXT NOT NULL,
    retrieved_utc       TEXT NOT NULL, -- ISO-8601 UTC
    http_status         INTEGER NOT NULL,
    content_type        TEXT NOT NULL,
    sha256_hash         TEXT NOT NULL UNIQUE,
    original_filename   TEXT,
    storage_path        TEXT NOT NULL, -- Relative path under data/advisories/archive/
    signature_status    TEXT NOT NULL DEFAULT 'NOT_CHECKED'
                        CHECK (signature_status IN ('VERIFIED', 'FAILED', 'UNSIGNED', 'NOT_CHECKED')),
    connector_version   TEXT NOT NULL,
    parsing_status      TEXT NOT NULL DEFAULT 'PENDING'
                        CHECK (parsing_status IN ('PENDING', 'PARSED', 'FAILED', 'QUARANTINED'))
);

CREATE INDEX IF NOT EXISTS idx_artifacts_source ON source_artifacts(source_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_hash ON source_artifacts(sha256_hash);

-- ============================================================================
-- 3. Advisories (Vendor & CNA Tracking Revisions)
-- ============================================================================
CREATE TABLE IF NOT EXISTS advisories (
    advisory_id         TEXT PRIMARY KEY,
    artifact_id         TEXT NOT NULL REFERENCES source_artifacts(artifact_id) ON DELETE CASCADE,
    publisher           TEXT NOT NULL,
    advisory_code       TEXT NOT NULL, -- e.g. 'SEVD-2020-343-08', 'ICSA-22-090-05'
    revision            TEXT NOT NULL, -- e.g. '1.0', 'Rev 2'
    title               TEXT NOT NULL,
    initial_release_utc TEXT,
    current_release_utc TEXT,
    source_url          TEXT,
    csaf_version        TEXT,          -- '2.0', '2.1', or NULL for CVE JSON
    created_at_utc      TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_advisories_code_rev ON advisories(publisher, advisory_code, revision);

-- ============================================================================
-- 4. Vulnerabilities (CVE Definitions & Raw Disclosures)
-- ============================================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id             TEXT PRIMARY KEY,
    advisory_id         TEXT NOT NULL REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    cve_id              TEXT NOT NULL, -- e.g. 'CVE-2020-7537'
    cwe_id              TEXT,          -- e.g. 'CWE-754'
    official_title      TEXT NOT NULL,
    raw_description     TEXT NOT NULL, -- Verbatim CNA description
    raw_affected_text   TEXT,          -- Verbatim raw affected products string
    is_kev              INTEGER NOT NULL DEFAULT 0 CHECK (is_kev IN (0, 1)),
    kev_date_added_utc  TEXT,
    source_locator      TEXT NOT NULL  -- JSON Pointer (e.g. '/vulnerabilities/0')
);

CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_advisory ON vulnerabilities(advisory_id);

-- ============================================================================
-- 5. CVSS Metrics (Multiple Ratings per Vulnerability)
-- ============================================================================
CREATE TABLE IF NOT EXISTS cvss_metrics (
    metric_id           TEXT PRIMARY KEY,
    vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE,
    cvss_version        TEXT NOT NULL, -- '3.1', '3.0', '2.0'
    source_name         TEXT NOT NULL, -- 'Schneider Electric', 'Rockwell Automation', 'NIST NVD'
    vector_string       TEXT NOT NULL,
    base_score          REAL NOT NULL,
    base_severity       TEXT NOT NULL CHECK (base_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'))
);

CREATE INDEX IF NOT EXISTS idx_cvss_vuln ON cvss_metrics(vuln_id);

-- ============================================================================
-- 6. Product Nodes (CSAF Canonical Tree & Hardware Series)
-- ============================================================================
CREATE TABLE IF NOT EXISTS product_nodes (
    product_id          TEXT PRIMARY KEY,
    advisory_id         TEXT NOT NULL REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    vendor              TEXT NOT NULL,
    product_family      TEXT,          -- e.g. 'Modicon', 'ControlLogix'
    product_name        TEXT NOT NULL, -- e.g. 'Modicon M580 CPUs'
    model_or_cat_no     TEXT,          -- e.g. 'BMEx58xxxxx', '1756-L83E'
    hardware_series     TEXT,          -- e.g. 'Series A', 'BMXP34'
    component_module    TEXT,          -- e.g. 'Embedded Ethernet'
    software_edition    TEXT,          -- e.g. 'Control Expert'
    cpe23_uri           TEXT,          -- Canonical CPE 2.3 if officially declared
    source_locator      TEXT NOT NULL  -- JSON Pointer into product_tree
);

CREATE INDEX IF NOT EXISTS idx_prod_vendor_name ON product_nodes(vendor, product_name);

-- ============================================================================
-- 7. Product Aliases (Tokenized Matching Index)
-- ============================================================================
CREATE TABLE IF NOT EXISTS product_aliases (
    alias_id            TEXT PRIMARY KEY,
    product_id          TEXT NOT NULL REFERENCES product_nodes(product_id) ON DELETE CASCADE,
    alias_term          TEXT NOT NULL, -- Normalized lowercase token
    alias_type          TEXT NOT NULL CHECK (alias_type IN ('EXACT_MODEL', 'FAMILY_NAME', 'LEGACY_BRAND', 'CATALOG_PREFIX'))
);

CREATE INDEX IF NOT EXISTS idx_alias_term ON product_aliases(alias_term);

-- ============================================================================
-- 8. Applicability Rules (Discrete Assertions)
-- ============================================================================
CREATE TABLE IF NOT EXISTS applicability_rules (
    rule_id             TEXT PRIMARY KEY,
    vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE,
    product_id          TEXT NOT NULL REFERENCES product_nodes(product_id) ON DELETE CASCADE,
    rule_status         TEXT NOT NULL CHECK (rule_status IN ('AFFECTED', 'KNOWN_NOT_AFFECTED', 'FIXED', 'UNDER_INVESTIGATION')),
    version_scheme      TEXT NOT NULL CHECK (version_scheme IN ('SCHNEIDER_OT', 'ROCKWELL_LOGIX', 'SEMVER', 'EXACT_ONLY', 'AMBIGUOUS_UNORDERED')),
    raw_version_string  TEXT,          -- Verbatim advisory text
    version_min         TEXT,
    min_inclusive       INTEGER CHECK (min_inclusive IN (0, 1)),
    version_max         TEXT,
    max_inclusive       INTEGER CHECK (max_inclusive IN (0, 1)),
    fixed_versions      TEXT,          -- JSON list of explicit fixed versions
    required_series     TEXT,          -- Required hardware series constraint
    configuration_prereq TEXT,         -- Configuration requirement (e.g. 'Web Server active')
    rule_activation     TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (rule_activation IN ('ACTIVE', 'STAGED_REVIEW', 'SUPERSEDED')),
    source_locator      TEXT NOT NULL, -- JSON Pointer into product_status
    rule_hash           TEXT NOT NULL  -- Checksum of rule constraints for invalidation tracking
);

CREATE INDEX IF NOT EXISTS idx_rules_vuln ON applicability_rules(vuln_id);
CREATE INDEX IF NOT EXISTS idx_rules_prod ON applicability_rules(product_id);

-- ============================================================================
-- 9. Observed Assets (Inventory Entities)
-- ============================================================================
CREATE TABLE IF NOT EXISTS asset_observations (
    asset_id            TEXT PRIMARY KEY,
    ip_address          TEXT NOT NULL,
    mac_address         TEXT,
    vendor              TEXT NOT NULL,
    product_family      TEXT,
    product_name        TEXT,
    model_or_cat_no     TEXT,
    hardware_series     TEXT,
    firmware_version    TEXT,
    version_scheme      TEXT,
    purdue_level        TEXT,
    observation_time_utc TEXT NOT NULL,
    is_ot_device        INTEGER NOT NULL DEFAULT 1 CHECK (is_ot_device IN (0, 1))
);

-- ============================================================================
-- 10. Asset Fact Provenance (Granular Per-Attribute Audit)
-- ============================================================================
CREATE TABLE IF NOT EXISTS asset_fact_provenance (
    fact_id             TEXT PRIMARY KEY,
    asset_id            TEXT NOT NULL REFERENCES asset_observations(asset_id) ON DELETE CASCADE,
    attribute_name      TEXT NOT NULL, -- 'vendor', 'model_or_cat_no', 'firmware_version'
    attribute_value     TEXT NOT NULL,
    source_type         TEXT NOT NULL CHECK (source_type IN ('PASSIVE_DPI', 'REFERENCE_MANIFEST', 'HUMAN_WALKDOWN', 'OUI_HEURISTIC')),
    confidence          TEXT NOT NULL CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW')),
    validation_status   TEXT NOT NULL CHECK (validation_status IN ('VERIFIED', 'INFERRED', 'CUSTOMER_CONFIRMED'))
);

CREATE INDEX IF NOT EXISTS idx_provenance_asset ON asset_fact_provenance(asset_id);

-- ============================================================================
-- 11. Match Results & Analyst Reviews
-- ============================================================================
CREATE TABLE IF NOT EXISTS match_results (
    match_id            TEXT PRIMARY KEY,
    asset_id            TEXT NOT NULL REFERENCES asset_observations(asset_id) ON DELETE CASCADE,
    rule_id             TEXT NOT NULL REFERENCES applicability_rules(rule_id) ON DELETE CASCADE,
    evaluation_status   TEXT NOT NULL CHECK (evaluation_status IN (
                            'INSUFFICIENT_IDENTITY',
                            'FAMILY_CANDIDATE',
                            'PRODUCT_MATCH_VERSION_UNKNOWN',
                            'VERSION_MATCH_CONDITIONS_UNKNOWN',
                            'AFFECTED_PER_ADVISORY',
                            'NOT_AFFECTED_PER_ADVISORY',
                            'CONFLICT_REQUIRES_REVIEW',
                            'NO_APPLICABLE_RULE_FOUND'
                        )),
    matched_conditions  TEXT,          -- JSON list of validated facts
    unknown_conditions  TEXT,          -- JSON list of unverified conditions
    contradictory_facts TEXT,          -- Details of conflicting attributes
    evaluated_utc       TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    evaluated_rule_hash TEXT NOT NULL,
    analyst_decision    TEXT DEFAULT NULL CHECK (analyst_decision IN ('CONFIRMED', 'DISMISSED_FALSE_POSITIVE', 'OVERRIDDEN_AFFECTED', 'DEFERRED', NULL)),
    analyst_username    TEXT DEFAULT NULL,
    analyst_rationale   TEXT DEFAULT NULL,
    reviewed_at_utc     TEXT DEFAULT NULL,
    is_stale            INTEGER NOT NULL DEFAULT 0 CHECK (is_stale IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_match_asset ON match_results(asset_id);
CREATE INDEX IF NOT EXISTS idx_match_rule ON match_results(rule_id);
```

---

## 4. The 8 Categorical Matching States

The 8 evaluation outcomes are **categorical epistemic states**, not an ordinal severity score:

| Categorical State | Technical Meaning | Defensible Customer-Facing Phrasing |
|---|---|---|
| `INSUFFICIENT_IDENTITY` | Observed attributes are inadequate to determine manufacturer or model. | "Insufficient product identity to evaluate advisory applicability." |
| `FAMILY_CANDIDATE` | Product family matches, but specific model/hardware series differs or is unobserved. | "Product family candidate; specific model/series requires verification." |
| `PRODUCT_MATCH_VERSION_UNKNOWN` | Exact product model matches an advisory, but installed firmware version is unobserved. | "Potentially applicable advisory; installed firmware/software version unknown." |
| `VERSION_MATCH_CONDITIONS_UNKNOWN` | Firmware version falls into advisory range, but prerequisites (e.g. Web Server) are unobserved. | "Product and version match advisory; configuration prerequisites unverified." |
| `AFFECTED_PER_ADVISORY` | Product, version, and prerequisites match authoritative advisory. | "Affected according to cited advisory; operational exploitation not tested." |
| `NOT_AFFECTED_PER_ADVISORY` | Product is verified as patched, fixed, or explicitly listed as unaffected. | "Not affected according to cited advisory (Patched version or unaffected product)." |
| `CONFLICT_REQUIRES_REVIEW` | Contradictory assertions exist between vendor CSAF and CNA/NVD disclosures. | "Conflicting applicability assertions between authoritative sources; requires review." |
| `NO_APPLICABLE_RULE_FOUND` | Verified product identity does not match any active rule in the evaluated advisory scope. | "No applicable published advisory found for this verified asset identity." |
