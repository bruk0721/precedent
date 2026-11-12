"""
Precedent -- Weekly Automated Refresh Orchestrator

Runs the three SAFE, already-vetted refresh scripts (SEC EDGAR severity,
LegiScan legislative, EPA TRI month-gated), then re-exports moat_export.json.
Deliberately does NOT touch CourtListener (plaintiff_network) -- resolving a
new docket is a manual, judgment-driven step (deciding which real lead to
pursue, e.g. precedent_project_archive.md items 52/67), and CourtListener's
free tier (5/min, 50/hr, 125/day) is already the project's tightest
constraint; an unattended weekly job should not spend that budget on
something a human hasn't decided to look at yet.

Each step is isolated -- one pipeline failing (a changed SEC filing format,
a LegiScan outage) never blocks the others or the final export, so the live
site's data only ever gets fresher, never stale from one partial failure.

Run (locally or in CI):
    pip install -r requirements.txt
    export SEC_EDGAR_CONTACT="Your Name your@email.com"
    export LEGISCAN_API_KEY=...
    python run_refresh.py
"""

import subprocess
import sys

STEPS = [
    ("Severity refresh (SEC EDGAR, 6 curated companies)", ["python", "refresh_severity.py"]),
    ("Legislative refresh (LegiScan, 2 vetted categories)", ["python", "refresh_legislative.py"]),
    ("EPA TRI refresh (month-gated)", ["python", "refresh_tri.py"]),
    ("Re-export moat_export.json", ["python", "export_moat_data.py", "../shared/moat_export.json"]),
]


def main():
    any_failed = False
    for label, cmd in STEPS:
        print(f"\n=== {label} ===")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"!!! Step failed (exit {result.returncode}): {label}", file=sys.stderr)
            any_failed = True
    print("\n=== Refresh run complete ===")
    if any_failed:
        print("One or more steps failed -- see output above. The export step still ran against whatever data was successfully refreshed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
