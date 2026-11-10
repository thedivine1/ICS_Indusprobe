"""
indus_probe.advisory.archive
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Content-addressed immutable raw advisory archive.

Every fetched advisory document is stored with its SHA-256 hash as the
filename under <data_dir>/archive/<sha256>.  This provides:
  - Deduplication (identical content stored once).
  - Tamper-evidence (file content can be re-verified against stored hash).
  - Provenance traceability (hash is recorded in raw_artifacts table).

No network calls happen here. The archive only stores bytes already fetched.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Tuple

logger = logging.getLogger(__name__)


def _sha256_of_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def store_artifact(data_dir: str, content: bytes, advisory_id: str) -> Tuple[str, str]:
    """
    Store raw advisory bytes in the content-addressed archive.

    Returns:
        (sha256_hex, storage_path)

    The file is written to <data_dir>/archive/<sha256>.  If the file
    already exists with identical content, the write is skipped.
    """
    sha256 = _sha256_of_bytes(content)
    archive_dir = Path(data_dir) / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    storage_path = archive_dir / sha256

    if storage_path.exists():
        # Verify content matches — guard against unlikely collision
        existing = storage_path.read_bytes()
        if existing == content:
            logger.debug("Artifact %s already archived (sha256=%s).", advisory_id, sha256[:12])
            return sha256, str(storage_path)
        else:
            logger.error(
                "SHA-256 collision or corruption: existing file %s does not match "
                "new content for advisory %s. Overwriting.", sha256[:12], advisory_id
            )

    storage_path.write_bytes(content)
    logger.info(
        "Archived %s → %s (%d bytes, sha256=%s)",
        advisory_id, storage_path.name, len(content), sha256[:12],
    )
    return sha256, str(storage_path)


def verify_artifact(data_dir: str, sha256: str) -> bool:
    """
    Verify that the archived file at <data_dir>/archive/<sha256> exists
    and its content hashes to the expected sha256.

    Returns True if intact, False if missing or corrupted.
    """
    archive_dir = Path(data_dir) / "archive"
    file_path = archive_dir / sha256

    if not file_path.exists():
        logger.warning("Archive missing: %s", sha256[:12])
        return False

    computed = _sha256_of_bytes(file_path.read_bytes())
    if computed != sha256:
        logger.error(
            "Archive integrity failure: expected %s, got %s", sha256[:12], computed[:12]
        )
        return False

    return True


def load_artifact(data_dir: str, sha256: str) -> bytes:
    """
    Load a previously archived artifact by its SHA-256.

    Raises FileNotFoundError if not archived.
    Raises ValueError if content integrity check fails.
    """
    archive_dir = Path(data_dir) / "archive"
    file_path = archive_dir / sha256

    if not file_path.exists():
        raise FileNotFoundError("Archive not found: {}".format(sha256))

    content = file_path.read_bytes()
    computed = _sha256_of_bytes(content)
    if computed != sha256:
        raise ValueError(
            "Archive integrity check failed for {}. Expected {}, got {}.".format(
                sha256[:12], sha256[:12], computed[:12]
            )
        )
    return content

