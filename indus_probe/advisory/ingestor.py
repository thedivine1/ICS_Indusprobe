"""
indus_probe.advisory.ingestor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Bounded advisory ingestion pipeline.

Orchestrates:
  fetcher → archive → CSAF parser → DB writer

Phase 1 MVP: Schneider Electric and Rockwell Automation only.
Maximum 10 advisories per vendor per session (bounded sample).

Offline import:
  If a CSAF JSON file is already on disk (e.g. from tests/fixtures/advisories/),
  use ingest_from_file() instead of ingest_from_url().

NO bulk downloads. Each advisory URL must be explicitly provided.
"""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
from pathlib import Path
from typing import List, Optional

from indus_probe.advisory.archive import store_artifact
from indus_probe.advisory.db import (
    upsert_advisory, upsert_advisory_cve, upsert_raw_artifact,
    upsert_applicability_rule,
)
from indus_probe.advisory.models import VendorCode
from indus_probe.advisory.parsers.csaf import parse_csaf_advisory

logger = logging.getLogger(__name__)

# Phase 1 hard limit — prevents accidental bulk ingestion
_MAX_ADVISORIES_PER_SESSION = 10


def ingest_from_url(
    url: str,
    advisory_id: str,
    vendor_code: VendorCode,
    conn: sqlite3.Connection,
    data_dir: str,
    retrieval_ts: Optional[str] = None,
) -> bool:
    """
    Fetch one advisory from a URL, archive it, parse it, and write to DB.

    Returns True on success, False on failure (error is logged).
    """
    from indus_probe.advisory.fetcher import fetch_url, FetchError, SSRFBlockedError
    if retrieval_ts is None:
        retrieval_ts = datetime.datetime.utcnow().isoformat() + "Z"

    try:
        content = fetch_url(url)
    except SSRFBlockedError as exc:
        logger.error("SSRF guard blocked fetch of %s: %s", url, exc)
        return False
    except FetchError as exc:
        logger.error("Fetch failed for %s: %s", url, exc)
        return False

    return _store_and_parse(
        content=content,
        source_url=url,
        advisory_id=advisory_id,
        vendor_code=vendor_code,
        conn=conn,
        data_dir=data_dir,
        retrieval_ts=retrieval_ts,
    )


def ingest_from_file(
    file_path: str,
    advisory_id: str,
    vendor_code: VendorCode,
    conn: sqlite3.Connection,
    data_dir: str,
    source_url: str = "",
) -> bool:
    """
    Ingest an advisory from a local file (fixtures, offline bundles).

    Returns True on success, False on failure.
    """
    path = Path(file_path)
    if not path.exists():
        logger.error("Advisory file not found: %s", file_path)
        return False

    retrieval_ts = datetime.datetime.utcnow().isoformat() + "Z"
    content = path.read_bytes()
    return _store_and_parse(
        content=content,
        source_url=source_url or "file://{}".format(path.name),
        advisory_id=advisory_id,
        vendor_code=vendor_code,
        conn=conn,
        data_dir=data_dir,
        retrieval_ts=retrieval_ts,
    )


def _store_and_parse(
    content: bytes,
    source_url: str,
    advisory_id: str,
    vendor_code: VendorCode,
    conn: sqlite3.Connection,
    data_dir: str,
    retrieval_ts: str,
) -> bool:
    """Archive + parse + DB write for one advisory."""
    # 1. Archive raw bytes
    sha256, storage_path = store_artifact(data_dir, content, advisory_id)
    file_size = len(content)

    # 2. Record in raw_artifacts
    upsert_raw_artifact(
        conn=conn,
        sha256=sha256,
        source_url=source_url,
        advisory_id=advisory_id,
        content_type="application/json",
        file_size=file_size,
        fetched_at=retrieval_ts,
        storage_path=storage_path,
    )

    # 3. Parse CSAF
    try:
        advisory = parse_csaf_advisory(
            raw_json=content.decode("utf-8", errors="replace"),
            advisory_id=advisory_id,
            vendor_code=vendor_code,
            source_url=source_url,
            retrieval_timestamp=retrieval_ts,
            raw_sha256=sha256,
            file_size_bytes=file_size,
        )
    except Exception as exc:
        logger.error("Parse failed for advisory %s: %s", advisory_id, exc)
        return False

    # 4. Write advisory to DB
    upsert_advisory(
        conn=conn,
        advisory_id=advisory.advisory_id,
        vendor_code=advisory.vendor.value,
        title=advisory.title,
        source_url=advisory.source_url,
        raw_sha256=sha256,
        file_size_bytes=file_size,
        retrieval_ts=retrieval_ts,
        published_date=advisory.published_date,
        revised_date=advisory.revised_date,
    )

    # 5. Write CVE associations
    for cve_id in advisory.cve_ids:
        upsert_advisory_cve(conn, advisory.advisory_id, cve_id)

    # 6. Write applicability rules
    for product in advisory.affected_products:
        upsert_applicability_rule(
            conn=conn,
            advisory_id=advisory.advisory_id,
            product_id=product.product_id,
            product_name=product.product_name,
            vendor=product.vendor,
            version_scheme=product.version_scheme.value,
            version_lt=product.version_lt,
            version_lte=product.version_lte,
            version_gte=product.version_gte,
            all_versions=product.all_versions,
            match_keywords_json=json.dumps(product.match_keywords),
            source_locator=product.source_locator,
        )

    logger.info(
        "Ingested advisory %s (%s) — %d CVEs, %d product rules",
        advisory.advisory_id, vendor_code.value,
        len(advisory.cve_ids), len(advisory.affected_products),
    )
    return True

