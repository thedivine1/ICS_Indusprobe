"""
indus_probe.advisory — Evidence-Based Advisory Intelligence & CVE Matcher

Phase 1 MVP: Schneider Electric and Rockwell Automation advisories only.
No active network probes. Offline-capable. Conservative matching logic.

Public entry point: run the CLI via  `indus-advisory`
Programmatic entry: from indus_probe.advisory.adapter import lookup_cves_for_assets
"""

__version__ = "0.1.0"

