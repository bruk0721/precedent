"""
Precedent -- Automated EPA TRI Refresh (month-gated)

EPA's Toxics Release Inventory Basic Data Files are published ANNUALLY, not
continuously -- re-downloading the ~60MB national file every week would
burn CI bandwidth for no new data almost every run. This script only
actually re-downloads and re-parses on the 1st of the month (the scheduled
workflow still runs weekly; this just no-ops most weeks rather than the
workflow needing a separate, second cron schedule).

Adapted from data-pipelines/epa_tri_pipeline.py -- same logic verbatim,
same curated company-match dict (EPA's own standardized parent-company
name, not re-invented here).
"""

import csv
import datetime as dt
import os
import sys

import requests

from db_schema import get_connection, init_db

TRI_URL_TEMPLATE = "https://data.epa.gov/efservice/downloads/tri/mv_tri_basic_download/{year}_US/csv"
DATA_DIR = os.path.join(os.path.dirname(__file__), "epa_tri_data")

CURATED_COMPANY_MATCH = {
    "3M": "3M CO",
    "DUPONT": "DuPont de Nemours, Inc.",
    "CHEMOURS": "Chemours Co",
    "CORTEVA": "Corteva, Inc.",
    "JOHNSON CONTROLS": "Johnson Controls International plc",
    "HONEYWELL": "HONEYWELL INTERNATIONAL INC",
}


def download(year: str):
    os.makedirs(DATA_DIR, exist_ok=True)
    out = os.path.join(DATA_DIR, f"{year}_us.csv")
    url = TRI_URL_TEMPLATE.format(year=year)
    print(f"Downloading {url} ...")
    with requests.get(url, timeout=180, stream=True) as r:
        r.raise_for_status()
        with open(out, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                f.write(chunk)
    return out


def load(path: str, year: str) -> int:
    init_db()
    matched = {}
    with open(path, encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        idx = {h: i for i, h in enumerate(header)}
        for row in reader:
            parent = row[idx["17. STANDARD PARENT CO NAME"]].upper()
            if row[idx["48. PFAS"]] != "YES":
                continue
            hit_key = next((k for k in CURATED_COMPANY_MATCH if k in parent), None)
            if not hit_key:
                continue
            key = (CURATED_COMPANY_MATCH[hit_key], row[idx["4. FACILITY NAME"]], row[idx["6. CITY"]], row[idx["8. ST"]], row[idx["30. PRIMARY NAICS"]], row[idx["12. LATITUDE"]], row[idx["13. LONGITUDE"]])
            matched.setdefault(key, set()).add(row[idx["37. CHEMICAL"]])

    conn = get_connection()
    inserted = 0
    for (company, facility, city, state, naics, lat, lon), chemicals in matched.items():
        for chemical in chemicals:
            cur = conn.execute(
                """INSERT OR IGNORE INTO facility_pfas_reports
                   (company_name, facility_name, city, state, chemical, naics_code, report_year, extracted_at, latitude, longitude)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (company, facility, city, state, chemical, naics, year, dt.datetime.now(dt.timezone.utc).isoformat(),
                 float(lat) if lat else None, float(lon) if lon else None),
            )
            inserted += cur.rowcount
    conn.commit()
    conn.close()
    print(f"{len(matched)} distinct real facilities, {sum(len(v) for v in matched.values())} facility-chemical rows, {inserted} newly inserted.")
    return inserted


def main():
    force = "--force" in sys.argv
    today = dt.date.today()
    if not force and today.day > 7:
        print(f"EPA TRI refresh skipped -- only runs in the first week of the month (today is day {today.day}); "
              f"the source data is published annually, so a weekly re-check is unnecessary most weeks. Pass --force to override.")
        return
    year = str(today.year - 1) if today.month <= 6 else str(today.year)
    try:
        path = download(year)
        load(path, year)
    except Exception as e:
        print(f"EPA TRI refresh FAILED for year {year}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
