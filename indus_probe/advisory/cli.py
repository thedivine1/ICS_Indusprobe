"""
indus_probe.advisory.cli
~~~~~~~~~~~~~~~~~~~~~~~~~
Standalone CLI entry point: `indus-advisory`

Commands:
  verify-db     — Verify DB schema and archive integrity
  ingest        — Ingest a single advisory from URL or local file
  match         — Run advisory matching against an asset inventory JSON
  export-bundle — Export last match results to JSON + CSV + HTML

Usage examples:
  indus-advisory verify-db --db ./data/advisories.db
  indus-advisory ingest --advisory-id SEVD-2020-343-08 --vendor schneider \\
      --file tests/fixtures/advisories/sevd-2020-343-08.json
  indus-advisory match --inventory assets.json --db ./data/advisories.db \\
      --out ./reports/match_results
  indus-advisory export-bundle --db ./data/advisories.db --out ./reports/

Python 3.9 compatible — uses click for argument parsing.
"""

from __future__ import annotations

import datetime
import json
import logging
import sys
from pathlib import Path
from typing import Optional

try:
    import click
except ImportError:
    print("ERROR: 'click' package is required. Install via: pip install click")
    sys.exit(1)

from indus_probe.advisory.db import open_db, get_match_results
from indus_probe.advisory.models import AssetFact, IdentificationBasis, VendorCode
from indus_probe.advisory.matcher import run_match
from indus_probe.advisory.exporter import export_json, export_csv, export_html
from indus_probe.advisory.archive import verify_artifact

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("indus-advisory")

DEFAULT_DB = "./data/advisories.db"
DEFAULT_DATA_DIR = "./data"


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def cli(debug: bool) -> None:
    """IndusProbe Advisory Intelligence CLI — OT CVE Matching (Phase 1 MVP)."""
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# verify-db
# ---------------------------------------------------------------------------

@cli.command("verify-db")
@click.option("--db", default=DEFAULT_DB, show_default=True, help="Path to advisories.db")
@click.option("--data-dir", default=DEFAULT_DATA_DIR, show_default=True, help="Archive data directory")
def verify_db(db: str, data_dir: str) -> None:
    """Verify DB schema version and raw artifact archive integrity."""
    conn = open_db(db)
    advisories = conn.execute("SELECT * FROM advisories").fetchall()
    artifacts = conn.execute("SELECT * FROM raw_artifacts").fetchall()
    rules = conn.execute("SELECT COUNT(*) as cnt FROM applicability_rules").fetchone()

    click.echo("=== IndusProbe Advisory DB Verification ===")
    click.echo("DB:              {}".format(db))
    click.echo("Advisories:      {}".format(len(advisories)))
    click.echo("Applicability rules: {}".format(rules["cnt"] if rules else 0))
    click.echo("Archived artifacts:  {}".format(len(artifacts)))
    click.echo("")

    all_ok = True
    for art in artifacts:
        ok = verify_artifact(data_dir, art["sha256"])
        status = click.style("OK", fg="green") if ok else click.style("FAIL", fg="red")
        click.echo("  Archive [{status}]  {sha256:.12s}  {advisory}".format(
            status=status,
            sha256=art["sha256"],
            advisory=art["advisory_id"] or "(no ID)",
        ))
        if not ok:
            all_ok = False

    if all_ok:
        click.echo(click.style("\n✓ Archive integrity check passed.", fg="green"))
    else:
        click.echo(click.style("\n✗ One or more archive files failed integrity check.", fg="red"))
        sys.exit(1)

    conn.close()


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------

@cli.command("ingest")
@click.option("--advisory-id", required=True, help="Advisory ID, e.g. SEVD-2020-343-08")
@click.option("--vendor", required=True,
              type=click.Choice(["schneider", "rockwell"], case_sensitive=False),
              help="Vendor code")
@click.option("--url", default=None, help="URL to fetch advisory from")
@click.option("--file", "file_path", default=None, help="Local advisory JSON file path")
@click.option("--db", default=DEFAULT_DB, show_default=True, help="Path to advisories.db")
@click.option("--data-dir", default=DEFAULT_DATA_DIR, show_default=True, help="Archive data directory")
def ingest(advisory_id: str, vendor: str, url: Optional[str],
           file_path: Optional[str], db: str, data_dir: str) -> None:
    """Ingest a single advisory from a URL or local file into the DB."""
    if not url and not file_path:
        raise click.UsageError("Provide either --url or --file.")

    vendor_code = VendorCode.SCHNEIDER if vendor.lower() == "schneider" else VendorCode.ROCKWELL
    conn = open_db(db)

    from indus_probe.advisory.ingestor import ingest_from_url, ingest_from_file

    if file_path:
        success = ingest_from_file(
            file_path=file_path,
            advisory_id=advisory_id,
            vendor_code=vendor_code,
            conn=conn,
            data_dir=data_dir,
            source_url=url or "",
        )
    else:
        success = ingest_from_url(
            url=url,
            advisory_id=advisory_id,
            vendor_code=vendor_code,
            conn=conn,
            data_dir=data_dir,
        )

    conn.close()
    if success:
        click.echo(click.style("✓ Advisory {} ingested successfully.".format(advisory_id), fg="green"))
    else:
        click.echo(click.style("✗ Ingestion failed for {}.".format(advisory_id), fg="red"))
        sys.exit(1)


# ---------------------------------------------------------------------------
# match
# ---------------------------------------------------------------------------

@cli.command("match")
@click.option("--inventory", required=True, help="Asset inventory JSON file")
@click.option("--db", default=DEFAULT_DB, show_default=True, help="Path to advisories.db")
@click.option("--out", default="./reports/match", show_default=True, help="Output path prefix")
@click.option("--label", default=None, help="Label for this assessment (e.g. plant name)")
def match(inventory: str, db: str, out: str, label: Optional[str]) -> None:
    """
    Match an asset inventory JSON against all loaded advisories.

    The inventory JSON should be a list of asset objects with fields:
      ip, mac, vendor, model_raw, firmware_version_raw,
      software_name, software_version_raw, device_hint,
      identification_basis (optional), provenance_note (optional)
    """
    inventory_path = Path(inventory)
    if not inventory_path.exists():
        click.echo(click.style("Inventory file not found: {}".format(inventory), fg="red"))
        sys.exit(1)

    with open(inventory_path, "r", encoding="utf-8") as f:
        raw_assets = json.load(f)

    # Convert dicts to AssetFact objects
    assets = []
    for d in raw_assets:
        basis_raw = d.get("identification_basis", "OUI_INFERENCE")
        try:
            basis = IdentificationBasis(basis_raw)
        except ValueError:
            basis = IdentificationBasis.OUI_INFERENCE

        assets.append(AssetFact(
            ip=d.get("ip", ""),
            mac=d.get("mac"),
            vendor=d.get("vendor"),
            model_raw=d.get("model_raw"),
            firmware_version_raw=d.get("firmware_version_raw"),
            software_name=d.get("software_name"),
            software_version_raw=d.get("software_version_raw"),
            identification_basis=basis,
            provenance_note=d.get("provenance_note"),
            device_hint=d.get("device_hint"),
        ))

    conn = open_db(db)
    results = run_match(assets, conn)

    # Summary
    from collections import Counter
    state_counts = Counter(r.state.value for r in results)
    click.echo("\n=== Match Summary ===")
    for state, count in sorted(state_counts.items()):
        click.echo("  {:45s} {}".format(state, count))
    click.echo("  {:45s} {}".format("TOTAL", len(results)))

    # Export
    out_base = out
    export_json(results, out_base + ".json")
    export_csv(results, out_base + ".csv")
    export_html(results, out_base + ".html",
                label=label or "IndusProbe Advisory Match Results")

    click.echo(click.style(
        "\n✓ Results exported to:\n  {}.json\n  {}.csv\n  {}.html".format(
            out_base, out_base, out_base
        ), fg="green"
    ))
    conn.close()


# ---------------------------------------------------------------------------
# export-bundle
# ---------------------------------------------------------------------------

@cli.command("export-bundle")
@click.option("--db", default=DEFAULT_DB, show_default=True, help="Path to advisories.db")
@click.option("--out", default="./reports/", show_default=True, help="Output directory")
@click.option("--snapshot-id", default=None, help="Restrict to a specific inventory snapshot ID")
def export_bundle(db: str, out: str, snapshot_id: Optional[str]) -> None:
    """Export all match results from the DB to JSON + CSV + HTML."""
    conn = open_db(db)
    rows = get_match_results(conn, snapshot_id)
    conn.close()

    if not rows:
        click.echo("No match results found in DB.")
        return

    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base = str(Path(out) / "advisory_match_{}".format(ts))

    export_json(rows, base + ".json")
    export_csv(rows, base + ".csv")
    export_html(rows, base + ".html")

    click.echo(click.style("✓ Bundle exported to {}.*".format(base), fg="green"))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()

