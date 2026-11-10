"""
indus_probe.advisory.db
~~~~~~~~~~~~~~~~~~~~~~~
SQLite schema creation, WAL-mode setup, and schema-migration tracking.

Design decisions:
- Single embedded SQLite file. No external DB server required.
- WAL (Write-Ahead Logging) for concurrent read access during report generation.
- All writes happen through this module only; no ad-hoc SQL elsewhere.
- schema_migrations table ensures idempotent schema evolution.
- Python 3.9 compatible — no walrus operators, no match statements.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = 1

_DDL_STATEMENTS = [
    # Migration tracking — always the first table created.
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version        INTEGER PRIMARY KEY,
        applied_at     TEXT    NOT NULL,
        description    TEXT    NOT NULL
    )
    """,

    # Content-addressed raw advisory archive.
    """
    CREATE TABLE IF NOT EXISTS raw_artifacts (
        sha256         TEXT    PRIMARY KEY,
        source_url     TEXT    NOT NULL,
        advisory_id    TEXT,
        content_type   TEXT,
        file_size      INTEGER NOT NULL,
        fetched_at     TEXT    NOT NULL,
        storage_path   TEXT    NOT NULL
    )
    """,

    # Advisory master table — one row per advisory document.
    """
    CREATE TABLE IF NOT EXISTS advisories (
        advisory_id        TEXT    PRIMARY KEY,
        vendor_code        TEXT    NOT NULL
                           CHECK(vendor_code IN ('SCHNEIDER','ROCKWELL')),
        title              TEXT    NOT NULL,
        source_url         TEXT    NOT NULL,
        raw_sha256         TEXT,
        file_size_bytes    INTEGER,
        retrieval_ts       TEXT    NOT NULL,
        published_date     TEXT,
        revised_date       TEXT,
        is_stale           INTEGER NOT NULL DEFAULT 0
                           CHECK(is_stale IN (0,1))
    )
    """,

    # Many-to-many: advisory ↔ CVE IDs.
    """
    CREATE TABLE IF NOT EXISTS advisory_cves (
        advisory_id    TEXT    NOT NULL REFERENCES advisories(advisory_id)
                               ON DELETE CASCADE,
        cve_id         TEXT    NOT NULL,
        PRIMARY KEY (advisory_id, cve_id)
    )
    """,

    # CVSS metrics — multiple per advisory (v3.1, v4.0, etc.).
    """
    CREATE TABLE IF NOT EXISTS cvss_metrics (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        advisory_id    TEXT    NOT NULL REFERENCES advisories(advisory_id)
                               ON DELETE CASCADE,
        cvss_version   TEXT    NOT NULL,
        score          REAL    NOT NULL,
        vector         TEXT,
        metric_source  TEXT    NOT NULL
    )
    """,

    # Affected product rules extracted from advisory product trees.
    """
    CREATE TABLE IF NOT EXISTS applicability_rules (
        rule_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        advisory_id      TEXT    NOT NULL REFERENCES advisories(advisory_id)
                                 ON DELETE CASCADE,
        product_id       TEXT    NOT NULL,
        product_name     TEXT    NOT NULL,
        vendor           TEXT    NOT NULL,
        version_scheme   TEXT    NOT NULL
                         CHECK(version_scheme IN (
                             'SCHNEIDER_OT','ROCKWELL_LOGIX',
                             'SEMVER','EXACT_ONLY','AMBIGUOUS_UNORDERED'
                         )),
        version_lt       TEXT,
        version_lte      TEXT,
        version_gte      TEXT,
        all_versions     INTEGER NOT NULL DEFAULT 0
                         CHECK(all_versions IN (0,1)),
        match_keywords   TEXT    NOT NULL DEFAULT '[]',   -- JSON array
        source_locator   TEXT,
        rule_hash        TEXT    NOT NULL,
        UNIQUE(advisory_id, product_id)
    )
    """,

    # Asset inventory snapshots used during a match run.
    """
    CREATE TABLE IF NOT EXISTS assets (
        id                      INTEGER PRIMARY KEY AUTOINCREMENT,
        ip                      TEXT    NOT NULL,
        mac                     TEXT,
        vendor                  TEXT,
        model_raw               TEXT,
        firmware_version_raw    TEXT,
        software_name           TEXT,
        software_version_raw    TEXT,
        identification_basis    TEXT    NOT NULL DEFAULT 'OUI_INFERENCE'
                                CHECK(identification_basis IN (
                                    'LAB_MANIFEST','CLIENT_REGISTER',
                                    'PARSED_IDENTITY','OUI_INFERENCE',
                                    'ANALYST_ANNOTATION'
                                )),
        provenance_note         TEXT,
        device_hint             TEXT,
        snapshot_id             TEXT    NOT NULL,
        UNIQUE(ip, snapshot_id)
    )
    """,

    # Inventory snapshots — groups assets for a single assessment run.
    """
    CREATE TABLE IF NOT EXISTS inventory_snapshots (
        snapshot_id    TEXT    PRIMARY KEY,
        created_at     TEXT    NOT NULL,
        label          TEXT,
        asset_count    INTEGER NOT NULL DEFAULT 0
    )
    """,

    # Match results — one row per (asset, advisory, CVE) evaluation.
    """
    CREATE TABLE IF NOT EXISTS match_results (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id            INTEGER NOT NULL REFERENCES assets(id)
                                    ON DELETE CASCADE,
        advisory_id         TEXT    NOT NULL REFERENCES advisories(advisory_id),
        cve_id              TEXT    NOT NULL,
        state               TEXT    NOT NULL
                            CHECK(state IN (
                                'AFFECTED_PER_ADVISORY',
                                'NOT_AFFECTED_PER_ADVISORY',
                                'PRODUCT_MATCH_VERSION_UNKNOWN',
                                'PRODUCT_MATCH_VERSION_AMBIGUOUS',
                                'PRODUCT_EXCLUDED_BY_ADVISORY',
                                'NO_APPLICABLE_RULE_FOUND',
                                'INSUFFICIENT_IDENTITY',
                                'EVALUATION_ERROR'
                            )),
        reasoning           TEXT    NOT NULL,
        missing_evidence    TEXT,
        advisory_title      TEXT,
        vendor              TEXT,
        affected_range_text TEXT,
        mitigation_note     TEXT,
        evaluated_at        TEXT    NOT NULL,
        -- Analyst review columns (populated after human review)
        analyst_decision    TEXT,
        analyst_note        TEXT,
        analyst_timestamp   TEXT,
        UNIQUE(asset_id, advisory_id, cve_id)
    )
    """,

    # Ingest job log — tracks each bounded fetch operation.
    """
    CREATE TABLE IF NOT EXISTS ingest_jobs (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at     TEXT    NOT NULL,
        completed_at   TEXT,
        vendor_code    TEXT,
        source_url     TEXT    NOT NULL,
        advisory_count INTEGER NOT NULL DEFAULT 0,
        status         TEXT    NOT NULL DEFAULT 'RUNNING'
                       CHECK(status IN ('RUNNING','COMPLETED','FAILED','PARTIAL')),
        error_detail   TEXT
    )
    """,
]


# ---------------------------------------------------------------------------
# DB initialisation and helpers
# ---------------------------------------------------------------------------

def _compute_rule_hash(advisory_id: str, product_id: str, product_name: str,
                       version_lt: Optional[str], version_lte: Optional[str],
                       version_gte: Optional[str], all_versions: bool) -> str:
    """Deterministic hash of rule parameters for stale-detection."""
    parts = "|".join([
        advisory_id, product_id, product_name,
        version_lt or "", version_lte or "", version_gte or "",
        str(int(all_versions)),
    ])
    return hashlib.sha256(parts.encode()).hexdigest()[:16]


def open_db(db_path: str) -> sqlite3.Connection:
    """
    Open (or create) the advisory SQLite database with safe settings.

    Returns a connection in WAL mode with foreign key enforcement enabled.
    The caller is responsible for closing the connection.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Safety settings
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    _apply_schema(conn)
    return conn


def _apply_schema(conn: sqlite3.Connection) -> None:
    """
    Apply DDL statements idempotently.
    Records the schema version in schema_migrations if not already present.
    """
    with conn:
        for stmt in _DDL_STATEMENTS:
            conn.execute(stmt)

        existing = conn.execute(
            "SELECT version FROM schema_migrations WHERE version = ?",
            (_SCHEMA_VERSION,),
        ).fetchone()

        if existing is None:
            import datetime
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                (
                    _SCHEMA_VERSION,
                    datetime.datetime.utcnow().isoformat() + "Z",
                    "Initial schema: advisories, applicability_rules, assets, match_results",
                ),
            )
            logger.info("Schema version %d applied.", _SCHEMA_VERSION)
        else:
            logger.debug("Schema version %d already applied.", _SCHEMA_VERSION)


def upsert_advisory(conn: sqlite3.Connection, advisory_id: str, vendor_code: str,
                    title: str, source_url: str, raw_sha256: str,
                    file_size_bytes: int, retrieval_ts: str,
                    published_date: Optional[str] = None,
                    revised_date: Optional[str] = None) -> None:
    with conn:
        conn.execute(
            """
            INSERT INTO advisories
                (advisory_id, vendor_code, title, source_url, raw_sha256,
                 file_size_bytes, retrieval_ts, published_date, revised_date)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(advisory_id) DO UPDATE SET
                title=excluded.title,
                raw_sha256=excluded.raw_sha256,
                file_size_bytes=excluded.file_size_bytes,
                retrieval_ts=excluded.retrieval_ts,
                is_stale=0
            """,
            (advisory_id, vendor_code, title, source_url, raw_sha256,
             file_size_bytes, retrieval_ts, published_date, revised_date),
        )


def upsert_advisory_cve(conn: sqlite3.Connection, advisory_id: str, cve_id: str) -> None:
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO advisory_cves (advisory_id, cve_id) VALUES (?,?)",
            (advisory_id, cve_id),
        )


def upsert_raw_artifact(conn: sqlite3.Connection, sha256: str, source_url: str,
                        advisory_id: Optional[str], content_type: Optional[str],
                        file_size: int, fetched_at: str, storage_path: str) -> None:
    with conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO raw_artifacts
                (sha256, source_url, advisory_id, content_type, file_size, fetched_at, storage_path)
            VALUES (?,?,?,?,?,?,?)
            """,
            (sha256, source_url, advisory_id, content_type, file_size, fetched_at, storage_path),
        )


def upsert_applicability_rule(conn: sqlite3.Connection, advisory_id: str,
                              product_id: str, product_name: str, vendor: str,
                              version_scheme: str, version_lt: Optional[str],
                              version_lte: Optional[str], version_gte: Optional[str],
                              all_versions: bool, match_keywords_json: str,
                              source_locator: Optional[str]) -> None:
    rule_hash = _compute_rule_hash(
        advisory_id, product_id, product_name,
        version_lt, version_lte, version_gte, all_versions,
    )
    with conn:
        conn.execute(
            """
            INSERT INTO applicability_rules
                (advisory_id, product_id, product_name, vendor, version_scheme,
                 version_lt, version_lte, version_gte, all_versions,
                 match_keywords, source_locator, rule_hash)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(advisory_id, product_id) DO UPDATE SET
                product_name=excluded.product_name,
                version_scheme=excluded.version_scheme,
                version_lt=excluded.version_lt,
                version_lte=excluded.version_lte,
                version_gte=excluded.version_gte,
                all_versions=excluded.all_versions,
                match_keywords=excluded.match_keywords,
                source_locator=excluded.source_locator,
                rule_hash=excluded.rule_hash
            """,
            (advisory_id, product_id, product_name, vendor, version_scheme,
             version_lt, version_lte, version_gte, int(all_versions),
             match_keywords_json, source_locator, rule_hash),
        )


def save_match_result(conn: sqlite3.Connection, asset_db_id: int,
                      advisory_id: str, cve_id: str, state: str,
                      reasoning: str, missing_evidence: Optional[str],
                      advisory_title: Optional[str], vendor: Optional[str],
                      affected_range_text: Optional[str],
                      mitigation_note: Optional[str],
                      evaluated_at: str) -> None:
    with conn:
        conn.execute(
            """
            INSERT INTO match_results
                (asset_id, advisory_id, cve_id, state, reasoning, missing_evidence,
                 advisory_title, vendor, affected_range_text, mitigation_note, evaluated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(asset_id, advisory_id, cve_id) DO UPDATE SET
                state=excluded.state,
                reasoning=excluded.reasoning,
                missing_evidence=excluded.missing_evidence,
                evaluated_at=excluded.evaluated_at
            """,
            (asset_db_id, advisory_id, cve_id, state, reasoning, missing_evidence,
             advisory_title, vendor, affected_range_text, mitigation_note, evaluated_at),
        )


def get_all_rules(conn: sqlite3.Connection) -> list:
    """Return all applicability rules as sqlite3.Row objects."""
    return conn.execute("SELECT * FROM applicability_rules").fetchall()


def get_all_advisories(conn: sqlite3.Connection) -> list:
    return conn.execute("SELECT * FROM advisories").fetchall()


def get_match_results(conn: sqlite3.Connection,
                      snapshot_id: Optional[str] = None) -> list:
    """Return match results, optionally filtered to a specific inventory snapshot."""
    if snapshot_id:
        return conn.execute(
            """
            SELECT mr.*, a.ip, a.vendor, a.model_raw, a.firmware_version_raw,
                   a.identification_basis, a.device_hint
            FROM match_results mr
            JOIN assets a ON a.id = mr.asset_id
            WHERE a.snapshot_id = ?
            ORDER BY mr.advisory_id, a.ip
            """,
            (snapshot_id,),
        ).fetchall()
    return conn.execute(
        """
        SELECT mr.*, a.ip, a.vendor, a.model_raw, a.firmware_version_raw,
               a.identification_basis, a.device_hint
        FROM match_results mr
        JOIN assets a ON a.id = mr.asset_id
        ORDER BY mr.advisory_id, a.ip
        """
    ).fetchall()


def insert_asset(conn: sqlite3.Connection, snapshot_id: str, ip: str,
                 mac: Optional[str], vendor: Optional[str],
                 model_raw: Optional[str], firmware_version_raw: Optional[str],
                 software_name: Optional[str], software_version_raw: Optional[str],
                 identification_basis: str, provenance_note: Optional[str],
                 device_hint: Optional[str]) -> int:
    """Insert or ignore an asset record; returns the row id."""
    with conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO assets
                (ip, mac, vendor, model_raw, firmware_version_raw,
                 software_name, software_version_raw, identification_basis,
                 provenance_note, device_hint, snapshot_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (ip, mac, vendor, model_raw, firmware_version_raw,
             software_name, software_version_raw, identification_basis,
             provenance_note, device_hint, snapshot_id),
        )
        row = conn.execute(
            "SELECT id FROM assets WHERE ip=? AND snapshot_id=?",
            (ip, snapshot_id),
        ).fetchone()
        return row["id"]


def upsert_snapshot(conn: sqlite3.Connection, snapshot_id: str,
                    created_at: str, label: Optional[str]) -> None:
    with conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO inventory_snapshots (snapshot_id, created_at, label)
            VALUES (?,?,?)
            """,
            (snapshot_id, created_at, label),
        )

