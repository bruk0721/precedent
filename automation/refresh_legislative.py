"""
Precedent -- Automated Legislative Refresh (LegiScan, already-scoped categories)

Re-runs the two already-vetted category queries (firefighter_presumption,
pfas_regulation) every scheduled run so newly enacted bills get picked up
without a human re-running this by hand. Deliberately does NOT add new
query categories or try broader/generic searches -- item 9 and item 41 of
precedent_project_archive.md both document real false-positive incidents
from loose LegiScan queries (budget bills, an unrelated cosmetics bill, a
memorial resolution), caught only by a human reading titles. An automated
job must not reintroduce that risk by broadening scope on its own.

Adapted from data-pipelines/time_resolution_pipeline.py -- same extraction
logic verbatim.
"""

import os
import sys
from datetime import datetime, timezone

import requests

from db_schema import get_connection, init_db

API_BASE = "https://api.legiscan.com/"
CATEGORY_QUERIES = {
    "firefighter_presumption": ["firefighter cancer presumption", "firefighter PTSD presumption", "firefighter workers compensation presumption"],
    "pfas_regulation": ["PFAS firefighting equipment ban", "PFAS consumer product ban", "PFAS environmental regulation"],
}
SINCE_YEAR = 2016
ENACTED_STATUS_CODE = 4
ENACTMENT_KEYWORDS = ["signed by governor", "chaptered", "approved by governor", "became law"]


def _api_key():
    key = os.environ.get("LEGISCAN_API_KEY")
    if not key:
        raise RuntimeError("LEGISCAN_API_KEY is not set.")
    return key


def search_bills(query: str) -> list:
    resp = requests.get(API_BASE, params={"key": _api_key(), "op": "getSearch", "state": "ALL", "query": query}, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "OK":
        raise RuntimeError(f"LegiScan search failed: {data}")
    return [v for k, v in data.get("searchresult", {}).items() if k != "summary"]


def get_bill_detail(bill_id: int) -> dict:
    resp = requests.get(API_BASE, params={"key": _api_key(), "op": "getBill", "id": bill_id}, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "OK":
        raise RuntimeError(f"LegiScan getBill failed for id={bill_id}: {data}")
    return data.get("bill", {})


def extract_enactment_date(bill: dict):
    for entry in bill.get("history", []):
        action = (entry.get("action") or "").lower()
        if any(kw in action for kw in ENACTMENT_KEYWORDS):
            return entry.get("date")
    if bill.get("status") == ENACTED_STATUS_CODE:
        return bill.get("status_date")
    return None


def insert_bill(state, bill_number, enactment_date, title, confidence, category, source_url) -> int:
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT OR IGNORE INTO legislative_timeline
               (state, bill_number, enactment_date, title, confidence, extracted_at, category, source_url)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (state, bill_number, enactment_date, title, confidence, datetime.now(timezone.utc).isoformat(), category, source_url),
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def refresh_category(category: str) -> int:
    seen_bill_ids = set()
    total_new = 0
    for query in CATEGORY_QUERIES[category]:
        for b in search_bills(query):
            bill_id = b.get("bill_id") or b.get("id")
            if not bill_id or bill_id in seen_bill_ids:
                continue
            seen_bill_ids.add(bill_id)
            detail = get_bill_detail(bill_id)
            if detail.get("status") != ENACTED_STATUS_CODE:
                continue
            enactment_date = extract_enactment_date(detail)
            if not enactment_date or (enactment_date[:4].isdigit() and int(enactment_date[:4]) < SINCE_YEAR):
                continue
            confidence = "medium" if any(kw in (e.get("action") or "").lower() for e in detail.get("history", []) for kw in ENACTMENT_KEYWORDS) else "low (status-date fallback, not a matched history action)"
            total_new += insert_bill(
                detail.get("state"), detail.get("bill_number"), enactment_date, detail.get("title"),
                confidence, category, detail.get("state_link"),
            )
    print(f"  {category}: {len(seen_bill_ids)} unique candidate(s) checked, {total_new} new row(s).")
    return total_new


def main():
    init_db()
    total_new = 0
    for category in CATEGORY_QUERIES:
        try:
            total_new += refresh_category(category)
        except Exception as e:
            print(f"  {category}: FAILED -- {e}", file=sys.stderr)
    print(f"Legislative refresh complete: {total_new} new row(s) across {len(CATEGORY_QUERIES)} categories.")


if __name__ == "__main__":
    main()
