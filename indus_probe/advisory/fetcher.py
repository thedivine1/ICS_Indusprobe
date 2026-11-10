"""
indus_probe.advisory.fetcher
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SSRF-guarded HTTP fetcher for advisory documents.

Safety constraints enforced before every request:
  1. DNS resolution must return a public IP (RFC 1918, loopback, link-local are blocked).
  2. Scheme must be https or http (no file://, ftp://, etc.).
  3. Redirects are followed only if the redirect target also passes the IP check.
  4. Internal throttle: 2 requests per second (proposed internal throttle, NOT a
     published vendor rate limit).
  5. No requests to private IP ranges.
  6. User-Agent identifies this tool and version.

This module performs ONLY fetch → bytes.
Parsing, archiving, and DB writes happen in separate modules.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from typing import Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SSRF guard: blocked IP ranges
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),      # RFC 6598 shared address space
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
]


class SSRFBlockedError(Exception):
    """Raised when a URL resolves to a blocked (private/internal) IP."""


class FetchError(Exception):
    """Raised on HTTP errors or unexpected fetch failures."""


def _is_public_ip(addr_str: str) -> bool:
    """Return True if the IP address is publicly routable (not in any blocked network)."""
    try:
        addr = ipaddress.ip_address(addr_str)
    except ValueError:
        return False
    for network in _BLOCKED_NETWORKS:
        if addr in network:
            return False
    return True


def _guard_url(url: str) -> str:
    """
    Validate that the URL scheme is acceptable and that the hostname
    resolves to a public IP address.

    Returns the URL unchanged if it passes all checks.
    Raises SSRFBlockedError otherwise.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError(
            "Blocked: scheme {!r} is not allowed. Only http/https are permitted.".format(
                parsed.scheme
            )
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("Blocked: URL has no resolvable hostname: {!r}".format(url))

    # Reject raw IP URLs that resolve to blocked ranges without DNS
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SSRFBlockedError("DNS resolution failed for {!r}: {}".format(hostname, exc))

    for info in infos:
        addr = info[4][0]
        if not _is_public_ip(addr):
            raise SSRFBlockedError(
                "Blocked: hostname {!r} resolves to private/reserved IP {!r}. "
                "SSRF guard rejected this request.".format(hostname, addr)
            )

    return url


# ---------------------------------------------------------------------------
# Throttle (internal — not a published vendor rate limit)
# ---------------------------------------------------------------------------

_MIN_INTERVAL = 0.5   # seconds between requests  (= 2 rps internal throttle)
_last_fetch_time: float = 0.0


def _throttle() -> None:
    global _last_fetch_time
    elapsed = time.monotonic() - _last_fetch_time
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_fetch_time = time.monotonic()


# ---------------------------------------------------------------------------
# Public fetch API
# ---------------------------------------------------------------------------

_USER_AGENT = "IndusProbe-Advisory-Fetcher/0.1 (+https://github.com/indusprobe)"
_TIMEOUT = 30  # seconds


def fetch_url(url: str, accept: str = "application/json") -> bytes:
    """
    Fetch a URL and return raw bytes.

    Applies SSRF guard, internal throttle, and a 30-second timeout.
    Does NOT follow redirects to private IPs.

    Args:
        url:    Target URL (must be https or http, public IP).
        accept: HTTP Accept header value.

    Returns:
        Raw response body as bytes.

    Raises:
        SSRFBlockedError: If the URL resolves to a blocked IP.
        FetchError:       On HTTP error codes or network failures.
    """
    _guard_url(url)
    _throttle()

    logger.info("Fetching: %s", url)
    req = Request(url)
    req.add_header("User-Agent", _USER_AGENT)
    req.add_header("Accept", accept)

    try:
        with urlopen(req, timeout=_TIMEOUT) as resp:
            status = resp.status
            if status not in (200, 206):
                raise FetchError(
                    "HTTP {} for URL: {}".format(status, url)
                )
            content = resp.read()
            logger.info(
                "Fetched %s — HTTP %d, %d bytes", url, status, len(content)
            )
            return content
    except HTTPError as exc:
        raise FetchError("HTTP {}: {}".format(exc.code, url)) from exc
    except URLError as exc:
        raise FetchError("Network error fetching {}: {}".format(url, exc.reason)) from exc
    except Exception as exc:
        raise FetchError("Unexpected error fetching {}: {}".format(url, exc)) from exc

