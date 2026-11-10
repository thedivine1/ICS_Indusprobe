"""
IndusProbe — OT/ICS Vulnerability & CVE Knowledge Base

Cross-references discovered vendor devices, models, and protocols
with known high-impact ICS CVEs (CISA ICS-CERT / NVD).

Enforces strict product-level keyword matching and authoritative advisory tracking.
Groups findings by advisory to avoid repetitive per-asset rows.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ICSCve:
    cve_id: str
    vendor: str
    product_keywords: list[str]  # Required keywords in device_hint or model
    identified_product: str
    affected_range: str
    official_title: str
    cisa_advisory: str
    vendor_advisory: str
    source_url: str
    mitigation: str
    mechanism: str


_KNOWN_ICS_CVES: list[ICSCve] = [
    # Schneider Electric Modicon Controllers & Engineering Software
    ICSCve(
        cve_id="CVE-2021-22779",
        vendor="Schneider Electric",
        product_keywords=["m580", "m340", "quantum", "premium", "control expert", "unity pro", "epac"],
        identified_product="Modicon M580, M340, Quantum Controllers & EcoStruxure Control Expert",
        affected_range="Modicon M580 (all versions), M340 (all versions), EcoStruxure Control Expert (< V15.0 SP1)",
        official_title="Authentication Bypass by Spoofing (Modbus UMAS Protocol)",
        cisa_advisory="ICSA-21-194-01",
        vendor_advisory="Schneider SEVD-2021-194-01",
        source_url="https://www.cisa.gov/news-events/ics-advisories/icsa-21-194-01",
        mitigation="Validate controller firmware & Control Expert version; configure IP Access Control Lists (ACL) in Control Expert; restrict port 502 to authorized engineering/SCADA stations.",
        mechanism="Vulnerability allows an attacker to bypass authentication mechanisms by spoofing communication on Modbus UMAS (FC90 / 0x5A), enabling unauthorized control commands.",
    ),
    ICSCve(
        cve_id="CVE-2020-7537",
        vendor="Schneider Electric",
        product_keywords=["m340", "quantum"],  # Specifically M340 and Quantum, NOT M580, NOT Altivar drives
        identified_product="Modicon M340 & Quantum Controllers",
        affected_range="Modicon M340 (all versions prior to BMXP34 SV3.30), Quantum (all versions)",
        official_title="Denial of Service via Crafted Modbus Read Physical Memory Request",
        cisa_advisory="ICSA-20-343-04",
        vendor_advisory="Schneider SEVD-2020-343-08",
        source_url="https://www.cisa.gov/news-events/ics-advisories/icsa-20-343-04",
        mitigation="Deploy network conduit ACLs to restrict Modbus port 502 strictly to authorized SCADA polling servers; schedule firmware update during planned turnaround.",
        mechanism="A specially crafted Modbus Read Physical Memory request sent to port 502 triggers a controller crash or reboot, resulting in denial of service.",
    ),
    # Siemens PLCs
    ICSCve(
        cve_id="CVE-2019-13946",
        vendor="Siemens",
        product_keywords=["s7-300", "s7-400", "simatic"],
        identified_product="SIMATIC S7-300 / S7-400 CPUs",
        affected_range="SIMATIC S7-300 and S7-400 CPU families (all versions)",
        official_title="S7Comm Authentication Bypass / Replay Vulnerability",
        cisa_advisory="ICSA-19-344-01",
        vendor_advisory="SSA-434534",
        source_url="https://www.cisa.gov/news-events/ics-advisories/icsa-19-344-01",
        mitigation="Evaluate upgrading to S7-1500; apply CP security module with IPsec conduit in scheduled maintenance window.",
        mechanism="Protocol implementation flaw in legacy S7Comm allows session replay and unauthenticated command execution.",
    ),
    ICSCve(
        cve_id="CVE-2022-38465",
        vendor="Siemens",
        product_keywords=["s7-1200", "s7-1500"],
        identified_product="SIMATIC S7-1200 / S7-1500 CPUs",
        affected_range="S7-1500 (Firmware < v2.9), S7-1200 (Firmware < v4.5)",
        official_title="Cryptographic Key Extraction & S7CommPlus Protocol Impersonation",
        cisa_advisory="ICSA-22-314-01",
        vendor_advisory="SSA-568427",
        source_url="https://www.cisa.gov/news-events/ics-advisories/icsa-22-314-01",
        mitigation="Update firmware to v2.9+ (S7-1500) / v4.5+ (S7-1200); enable TLS-encrypted PG/PC communication in TIA Portal.",
        mechanism="Extraction of global private keys enables attackers on the local subnet to compute authentication hashes and spoof TIA Portal stations.",
    ),
    # Rockwell Automation
    ICSCve(
        cve_id="CVE-2022-1161",
        vendor="Rockwell Automation",
        product_keywords=["controllogix", "guardlogix", "1756"],
        identified_product="ControlLogix & GuardLogix 5580 / 1756 Series",
        affected_range="ControlLogix 5580 (Firmware versions < v33.011)",
        official_title="Unauthenticated Bytecode Modification / Execution Vulnerability",
        cisa_advisory="ICSA-22-090-05",
        vendor_advisory="Rockwell Automation Advisory 1134010",
        source_url="https://www.cisa.gov/news-events/ics-advisories/icsa-22-090-05",
        mitigation="Apply firmware v33.011+ or newer; enable CIP Security to cryptographically authenticate and sign CIP messages.",
        mechanism="Allows an unauthenticated remote attacker to inject and execute arbitrary user bytecode on the controller while displaying unmodified ladder logic in Studio 5000.",
    ),
]


def lookup_cves_for_assets(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Given a list of discovered assets, return product-matched ICS CVE advisories.
    Groups results by advisory and lists affected assets to eliminate redundant rows.
    """
    # Group assets by advisory
    advisory_map: dict[str, dict[str, Any]] = {}

    for asset in assets:
        vendor = asset.get("vendor", "")
        ip = asset.get("ip", "")
        hint = asset.get("device_hint", "")
        hint_lower = hint.lower()
        identity_basis = asset.get("identity_source", "Lab reference manifest")

        for cve in _KNOWN_ICS_CVES:
            # Step 1: Vendor Match
            vendor_matches = (cve.vendor.lower() in vendor.lower() or vendor.lower() in cve.vendor.lower())
            if not vendor_matches:
                continue

            # Step 2: Strict Product/Model Keyword Match
            product_matches = any(kw in hint_lower for kw in cve.product_keywords)
            if not product_matches:
                continue

            if cve.cve_id not in advisory_map:
                advisory_map[cve.cve_id] = {
                    "cve_id": cve.cve_id,
                    "vendor": cve.vendor,
                    "identified_product": cve.identified_product,
                    "affected_range": cve.affected_range,
                    "official_title": cve.official_title,
                    "cisa_advisory": cve.cisa_advisory,
                    "vendor_advisory": cve.vendor_advisory,
                    "source_url": cve.source_url,
                    "mitigation": cve.mitigation,
                    "mechanism": cve.mechanism,
                    "applicability": "Candidate advisory — firmware / version validation required",
                    "installed_version": "Unknown (Passive capture cannot query internal firmware)",
                    "affected_assets": [],
                    "identity_basis": identity_basis,
                }

            advisory_map[cve.cve_id]["affected_assets"].append(f"`{ip}` ({hint})")

    return list(advisory_map.values())
