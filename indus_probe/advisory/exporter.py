"""
indus_probe.advisory.exporter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Export match results to JSON, analyst-review CSV, and standalone HTML.

All outputs are self-contained and do not require a running server.
HTML uses inline CSS only — no external CDN dependencies.
"""

from __future__ import annotations

import csv
import datetime
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def export_json(results: List[Any], output_path: str) -> None:
    """Export match results to a structured JSON file."""
    rows = []
    for r in results:
        if hasattr(r, "__dict__"):
            rows.append(r.__dict__)
        elif hasattr(r, "keys"):
            rows.append(dict(r))
        else:
            rows.append(str(r))

    output = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "tool": "IndusProbe Advisory Intelligence v0.1",
        "disclaimer": (
            "A result of NOT_AFFECTED_PER_ADVISORY or NO_APPLICABLE_RULE_FOUND "
            "for a specific advisory is NOT a clean bill of health. "
            "It applies only to the evaluated advisory. "
            "Other unevaluated advisories may still be relevant."
        ),
        "result_count": len(rows),
        "results": rows,
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# CSV export (analyst review format)
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "asset_ip",
    "cve_id",
    "advisory_id",
    "state",
    "vendor",
    "advisory_title",
    "affected_range_text",
    "reasoning",
    "missing_evidence",
    "mitigation_note",
    "analyst_decision",
    "analyst_note",
    "analyst_timestamp",
]


def export_csv(results: List[Any], output_path: str) -> None:
    """Export match results to a CSV file for analyst review."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            if hasattr(r, "__dict__"):
                row = r.__dict__
            elif hasattr(r, "keys"):
                row = dict(r)
            else:
                continue
            # Ensure all columns present
            out_row = {col: row.get(col, "") for col in _CSV_COLUMNS}
            writer.writerow(out_row)


# ---------------------------------------------------------------------------
# HTML export (standalone)
# ---------------------------------------------------------------------------

_STATE_COLOURS = {
    "AFFECTED_PER_ADVISORY": "#c0392b",
    "NOT_AFFECTED_PER_ADVISORY": "#27ae60",
    "PRODUCT_MATCH_VERSION_UNKNOWN": "#e67e22",
    "PRODUCT_MATCH_VERSION_AMBIGUOUS": "#f39c12",
    "PRODUCT_EXCLUDED_BY_ADVISORY": "#7f8c8d",
    "NO_APPLICABLE_RULE_FOUND": "#95a5a6",
    "INSUFFICIENT_IDENTITY": "#bdc3c7",
    "EVALUATION_ERROR": "#8e44ad",
}


def _state_badge(state: str) -> str:
    colour = _STATE_COLOURS.get(state, "#7f8c8d")
    return (
        '<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;'
        'font-size:0.85em;font-weight:600">{s}</span>'.format(c=colour, s=state)
    )


def export_html(results: List[Any], output_path: str, label: str = "IndusProbe Advisory Match Results") -> None:
    """Export match results to a standalone HTML file with inline CSS."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    rows_html = []
    for r in results:
        if hasattr(r, "__dict__"):
            d = r.__dict__
        elif hasattr(r, "keys"):
            d = dict(r)
        else:
            continue

        state = d.get("state", "")
        rows_html.append(
            "<tr>"
            "<td>{ip}</td>"
            "<td>{cve}</td>"
            "<td>{adv}</td>"
            "<td>{badge}</td>"
            "<td style='font-size:0.82em'>{reasoning}</td>"
            "<td style='font-size:0.82em;color:#c0392b'>{missing}</td>"
            "</tr>".format(
                ip=d.get("asset_ip", ""),
                cve=d.get("cve_id", ""),
                adv=d.get("advisory_id", ""),
                badge=_state_badge(state),
                reasoning=str(d.get("reasoning", "")).replace("<", "&lt;").replace(">", "&gt;"),
                missing=str(d.get("missing_evidence", "") or "").replace("<", "&lt;"),
            )
        )

    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{label}</title>
<style>
  body {{ font-family: Arial, sans-serif; font-size: 14px; margin: 2em; color: #2c3e50; }}
  h1 {{ color: #2c3e50; }}
  .disclaimer {{ background:#fef9e7;border-left:4px solid #f39c12;padding:12px;margin-bottom:1em; }}
  table {{ border-collapse:collapse; width:100%; }}
  th {{ background:#2c3e50;color:#fff;padding:8px;text-align:left;font-size:0.9em; }}
  td {{ border-bottom:1px solid #ecf0f1;padding:7px;vertical-align:top; }}
  tr:hover {{ background:#f9f9f9; }}
</style>
</head>
<body>
<h1>{label}</h1>
<p>Generated: {ts} &nbsp;|&nbsp; Tool: IndusProbe Advisory Intelligence v0.1</p>
<div class="disclaimer">
  <strong>⚠ Epistemic Disclaimer:</strong> A result of <em>NOT_AFFECTED_PER_ADVISORY</em>
  or <em>NO_APPLICABLE_RULE_FOUND</em> for a specific advisory is <strong>NOT a clean bill of health</strong>.
  It applies only to the evaluated advisory. Other unevaluated advisories may still be relevant.
  <em>PRODUCT_MATCH_VERSION_UNKNOWN</em> results require firmware version walkdown before they can be closed.
</div>
<table>
<thead>
<tr>
  <th>Asset IP</th><th>CVE ID</th><th>Advisory</th>
  <th>State</th><th>Reasoning</th><th>Missing Evidence</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
<p style="font-size:0.8em;color:#7f8c8d;margin-top:1em">
  CANDIDATE results require version verification. AFFECTED results require
  patch scheduling during planned maintenance. This report is generated from
  passive network analysis only — no active probes were sent.
</p>
</body>
</html>""".format(
        label=label,
        ts=generated_at,
        rows="\n".join(rows_html),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

