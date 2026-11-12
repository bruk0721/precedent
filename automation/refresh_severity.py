"""
Precedent -- Automated Severity Refresh (SEC EDGAR, curated tickers only)

Re-checks the 6 already-curated companies' LATEST 10-Ks for new PFAS
liability figures every scheduled run. Deliberately does NOT discover new
candidate defendants -- that requires the manual judgment calls documented
in severity_discovery_pipeline.py (which company is plausibly liable vs. a
false-positive category like a plaintiff utility) and stays a human-run,
deliberate step. This script only re-pulls companies a human has already
vetted, so it's safe to run unattended: INSERT OR IGNORE means a 10-K that
hasn't changed since the last run simply inserts 0 new rows.

Adapted from data-pipelines/severity_dollar_pipeline.py -- same extraction
logic verbatim (sentence-level liability-context matching, both table-dump
guards). Copied rather than imported because this folder is a separate,
CI-only checkout of just what's needed to refresh the live site; see
precedent_project_archive.md for the known file-duplication tradeoff this
creates with the dev copy in data-pipelines/.
"""

import os
import re
import sys
from datetime import datetime, timezone

import requests

from db_schema import get_connection, init_db

TICKER_MAP_URL = "https://www.sec.gov/files/company_tickers.json"
SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik}.json"
ARCHIVE_BASE = "https://www.sec.gov/Archives/edgar/data/{cik_int}/{accession_nodash}/{doc}"

# Every ticker this project has already curated a liability NAICS for (see
# severity_dollar_pipeline.py's CURATED_LIABILITY_NAICS for the full
# reasoning on each). Adding a NEW company here is a manual, deliberate
# decision -- not something this automated script should ever do itself.
CURATED_TICKERS = ["MMM", "DD", "CC", "CTVA", "HON", "JCI"]

CURATED_LIABILITY_NAICS = {
    "3M CO": "325998",
    "DUPONT DE NEMOURS, INC.": "325199",
    "CHEMOURS CO": "325199",
    "HONEYWELL INTERNATIONAL INC": "332813",
    "CORTEVA, INC.": "325199",
    "JOHNSON CONTROLS INTERNATIONAL PLC": "325998",
}

KEYWORDS = ["PFAS", "AFFF", "per- and polyfluoroalkyl"]
LIABILITY_TERMS = ["charge", "reserve", "settlement", "accrual", "liability", "liabilities", "loss", "losses", "judgment"]
DOLLAR_RE = re.compile(r"\$\s?[\d,]+(?:\.\d+)?\s?(?:million|billion)?", re.IGNORECASE)
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


def _headers():
    contact = os.environ.get("SEC_EDGAR_CONTACT")
    if not contact:
        raise RuntimeError("SEC_EDGAR_CONTACT is not set (needs a real contact string per SEC's fair-access policy).")
    return {"User-Agent": contact}


def get_cik_and_name(ticker: str) -> tuple:
    resp = requests.get(TICKER_MAP_URL, headers=_headers(), timeout=20)
    resp.raise_for_status()
    for entry in resp.json().values():
        if entry["ticker"].upper() == ticker.upper():
            return str(entry["cik_str"]).zfill(10), entry.get("title", ticker)
    raise RuntimeError(f"Ticker {ticker!r} not found in SEC's company_tickers.json")


def get_submissions(cik: str) -> dict:
    resp = requests.get(SUBMISSIONS_URL.format(cik=cik), headers=_headers(), timeout=20)
    resp.raise_for_status()
    return resp.json()


def get_latest_10k(submissions: dict) -> dict:
    recent = submissions["filings"]["recent"]
    for i, form in enumerate(recent["form"]):
        if form == "10-K":
            return {"accession_number": recent["accessionNumber"][i], "filing_date": recent["filingDate"][i], "primary_document": recent["primaryDocument"][i]}
    raise RuntimeError(f"No 10-K found for CIK {submissions.get('cik')}")


def fetch_document(cik: str, filing: dict) -> str:
    accession_nodash = filing["accession_number"].replace("-", "")
    url = ARCHIVE_BASE.format(cik_int=int(cik), accession_nodash=accession_nodash, doc=filing["primary_document"])
    resp = requests.get(url, headers=_headers(), timeout=30)
    resp.raise_for_status()
    return resp.text


def strip_html(raw_html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", raw_html)
    text = re.sub(r"&nbsp;|&#160;", " ", text)
    return re.sub(r"\s+", " ", text)


def split_sentences(text: str) -> list:
    return [s.strip() for s in SENTENCE_SPLIT_RE.split(text) if s.strip()]


def extract_liability_findings(text: str) -> list:
    confirmed = []
    for sentence in split_sentences(text):
        has_keyword = any(
            kw.lower() in sentence.lower() and not re.search(rf"\b(?:non|not)[\s-]*{re.escape(kw)}", sentence, re.IGNORECASE)
            for kw in KEYWORDS
        )
        has_liability_term = any(re.search(rf"\b{re.escape(term)}s?\b", sentence, re.IGNORECASE) for term in LIABILITY_TERMS)
        dollars_here = DOLLAR_RE.findall(sentence)
        if len(dollars_here) > 5:
            continue
        if re.search(r"\$\s*[\d,.]+\s+\$\s*[\d,.]+", sentence):
            continue
        if has_keyword and has_liability_term and dollars_here:
            matched_kw = next(kw for kw in KEYWORDS if kw.lower() in sentence.lower())
            matched_term = next(term for term in LIABILITY_TERMS if re.search(rf"\b{re.escape(term)}s?\b", sentence, re.IGNORECASE))
            confirmed.append({"keyword": matched_kw, "liability_term": matched_term, "dollar_figures": dollars_here, "sentence": sentence})
    return confirmed


def insert_severity_anchors(cik, company_name, ticker, filing_date, sec_sic_code, sec_sic_description, naics_code, confirmed) -> int:
    conn = get_connection()
    inserted = 0
    try:
        for f in confirmed:
            for amount in f["dollar_figures"]:
                cur = conn.execute(
                    """INSERT OR IGNORE INTO severity_anchors
                       (cik, company_name, ticker, filing_date, dollar_amount, liability_term, keyword,
                        context_snippet, extracted_at, sec_sic_code, sec_sic_description, naics_code)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (cik, company_name, ticker, filing_date, amount, f["liability_term"], f["keyword"],
                     f["sentence"], datetime.now(timezone.utc).isoformat(), sec_sic_code, sec_sic_description, naics_code),
                )
                inserted += cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return inserted


def refresh_one(ticker: str) -> int:
    cik, company_name = get_cik_and_name(ticker)
    submissions = get_submissions(cik)
    naics_code = CURATED_LIABILITY_NAICS.get(company_name.upper())
    filing = get_latest_10k(submissions)
    text = strip_html(fetch_document(cik, filing))
    confirmed = extract_liability_findings(text)
    inserted = insert_severity_anchors(
        cik, company_name, ticker, filing["filing_date"], submissions.get("sic"), submissions.get("sicDescription"), naics_code, confirmed
    )
    print(f"  {ticker} ({company_name}): latest 10-K {filing['filing_date']}, {len(confirmed)} confirmed finding(s) this pass, {inserted} new row(s).")
    return inserted


def main():
    init_db()
    total_new = 0
    for ticker in CURATED_TICKERS:
        try:
            total_new += refresh_one(ticker)
        except Exception as e:
            # One company's failure (a rename, a temporary SEC outage) should
            # never block refreshing the other five -- log it loudly and move on.
            print(f"  {ticker}: FAILED -- {e}", file=sys.stderr)
    print(f"Severity refresh complete: {total_new} new row(s) across {len(CURATED_TICKERS)} curated companies.")


if __name__ == "__main__":
    main()
