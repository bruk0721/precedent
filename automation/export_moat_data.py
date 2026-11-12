"""
Precedent -- Moat Data Export

Purpose: export the engineering-prototype's real data (precedent_moat.db) to
a static JSON file the live site's Underwriter Console can query client-side.
GitHub Pages only serves static files -- there is no live backend -- so this
is a deliberate "build-step" export (same pattern as evidence.json ->
data.json for the two trackers), not a live database connection. Re-run this
whenever precedent_moat.db changes and the console should reflect it.

Run:
    python export_moat_data.py [output_path]
"""

import json
import sys
from datetime import datetime, timezone

from db_schema import get_connection
from downstream_naics_adjacency import DOWNSTREAM_NAICS_ADJACENCY

TABLES = ["severity_anchors", "plaintiff_network", "legislative_timeline", "corporate_subsidiaries", "facility_pfas_reports"]


def dump_table(conn, table: str) -> list:
    conn.row_factory = __import__("sqlite3").Row
    return [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]


def export(output_path: str):
    conn = get_connection()
    data = {t: dump_table(conn, t) for t in TABLES}
    conn.close()
    data["downstream_adjacency"] = DOWNSTREAM_NAICS_ADJACENCY
    data["generated_at"] = datetime.now(timezone.utc).isoformat()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    counts = {k: len(v) for k, v in data.items() if isinstance(v, list)}
    print(f"Exported to {output_path}: {counts}")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "moat_export.json"
    export(out)
