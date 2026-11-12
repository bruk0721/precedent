"""
Precedent — Shared SQLite schema (precedent_moat.db)

The actual moat isn't any one pipeline's output -- it's this database. Every
pipeline (CourtListener, LegiScan, SEC EDGAR, and whatever comes after) writes
into the same three tables here instead of just printing to a terminal, so
the crosswalk accumulates instead of evaporating between runs.

Run standalone to (re)create the database:
    python db_schema.py
"""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "precedent_moat.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS plaintiff_network (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plaintiff_firm TEXT NOT NULL,
    defendant TEXT NOT NULL,
    docket_id TEXT,
    case_name TEXT,
    court TEXT,
    confidence TEXT NOT NULL,
    extracted_at TEXT NOT NULL,
    date_filed TEXT,
    UNIQUE(plaintiff_firm, defendant, docket_id)
);

CREATE TABLE IF NOT EXISTS legislative_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state TEXT NOT NULL,
    bill_number TEXT NOT NULL,
    enactment_date TEXT,
    title TEXT,
    confidence TEXT NOT NULL,
    extracted_at TEXT NOT NULL,
    UNIQUE(state, bill_number)
);

CREATE TABLE IF NOT EXISTS corporate_subsidiaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_company TEXT NOT NULL,
    subsidiary_name TEXT NOT NULL,
    jurisdiction TEXT,
    cik TEXT,
    extracted_at TEXT NOT NULL,
    UNIQUE(parent_company, subsidiary_name)
);

CREATE TABLE IF NOT EXISTS facility_pfas_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT NOT NULL,
    facility_name TEXT NOT NULL,
    city TEXT,
    state TEXT,
    chemical TEXT NOT NULL,
    naics_code TEXT,
    report_year TEXT NOT NULL,
    extracted_at TEXT NOT NULL,
    UNIQUE(facility_name, chemical, report_year)
);

CREATE TABLE IF NOT EXISTS severity_anchors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cik TEXT NOT NULL,
    company_name TEXT,
    ticker TEXT,
    filing_date TEXT,
    dollar_amount TEXT NOT NULL,
    liability_term TEXT NOT NULL,
    keyword TEXT NOT NULL,
    context_snippet TEXT NOT NULL,
    extracted_at TEXT NOT NULL,
    UNIQUE(cik, filing_date, dollar_amount, context_snippet)
);
"""

# Added after the fact, not in the original CREATE TABLE, because they were
# found to be necessary mid-project rather than designed in up front:
#   sec_sic_code / sec_sic_description -- the REGISTRANT-LEVEL SIC code SEC
#     EDGAR itself reports (e.g. 3M's is 3841 "Surgical & Medical Instruments,"
#     which has nothing to do with its AFFF/PFAS liability segment). Captured
#     honestly as what it is, not treated as the liability-relevant code.
#   naics_code -- a CURATED, manually-assigned liability-segment NAICS code
#     (e.g. 3M -> 325998 for AFFF/specialty chemicals). This is NOT derived
#     automatically from SEC data -- a diversified company's single corporate
#     SIC code can't tell you which product line is actually exposed, so this
#     column only gets populated where a human has verified the right code
#     for the specific liability being tracked. NULL means "not yet curated,"
#     not "no industry."
SEVERITY_ANCHORS_MIGRATIONS = [
    ("sec_sic_code", "TEXT"),
    ("sec_sic_description", "TEXT"),
    ("naics_code", "TEXT"),
    # source_url -- the real, direct SEC EDGAR document URL this row's
    # context_snippet was extracted from (ARCHIVE_BASE-built, same pattern
    # severity_dollar_pipeline.py already uses to fetch the document). Added
    # for the Underwriter Console's evidence-trail links: a buyer should be
    # able to click straight through to the actual highlighted filing, not
    # just read our excerpt of it. NULL means not yet backfilled, not "no
    # source" -- every row has a real source, this column just didn't exist
    # when the row was inserted.
    ("source_url", "TEXT"),
]

# date_filed -- the actual docket filing date (CourtListener's own dateFiled
# field), not extracted_at (when WE happened to pull it). Needed for any real
# filing-velocity computation; added after the fact because the first version
# of this table didn't capture it at all, confirmed empty when checked.
PLAINTIFF_NETWORK_MIGRATIONS = [
    ("date_filed", "TEXT"),
    # source_url -- CourtListener's own absolute_url for this docket (e.g.
    # "/docket/74803840/volpe-v-3m-company/"). Confirmed live that a bare
    # "/docket/{id}/" 404s -- CourtListener requires the real slug, which
    # isn't a guaranteed-predictable slugification of case_name, so this is
    # backfilled via a real API call per distinct docket rather than
    # constructed client-side.
    ("source_url", "TEXT"),
]

# category distinguishes "firefighter_presumption" (workers'-comp claims
# against employers) from "pfas_regulation" (consumer/environmental PFAS
# bills) -- the first LegiScan pull conflated these and most of the
# "pfas_regulation" rows were discarded as noise for the presumption
# tracker, but they're exactly the right input for the Time-to-Impact
# Window, which needs PFAS regulation (not presumption) paired with PFAS
# products-liability filings -- same litigation track on both ends.
LEGISLATIVE_TIMELINE_MIGRATIONS = [
    ("category", "TEXT"),
    # source_url -- LegiScan's own state_link for this exact bill (the real
    # official state-legislature page, not a guessed URL pattern -- LegiScan
    # bill URLs aren't predictable from state+bill_number alone, so this gets
    # backfilled via a live getBill call per row, not constructed).
    ("source_url", "TEXT"),
]


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def _migrate_table(conn: sqlite3.Connection, table: str, migrations: list):
    existing_cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for col_name, col_type in migrations:
        if col_name not in existing_cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")


def init_db():
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        _migrate_table(conn, "severity_anchors", SEVERITY_ANCHORS_MIGRATIONS)
        _migrate_table(conn, "plaintiff_network", PLAINTIFF_NETWORK_MIGRATIONS)
        _migrate_table(conn, "legislative_timeline", LEGISLATIVE_TIMELINE_MIGRATIONS)
        conn.execute("UPDATE legislative_timeline SET category = 'firefighter_presumption' WHERE category IS NULL")
        conn.commit()
    finally:
        conn.close()
    print(f"Initialized/verified schema at {DB_PATH}")


def table_counts():
    conn = get_connection()
    try:
        for table in ["plaintiff_network", "legislative_timeline", "severity_anchors", "corporate_subsidiaries"]:
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  {table}: {count} rows")
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print("\nCurrent row counts:")
    table_counts()
