"""
Precedent -- Downstream NAICS Adjacency ("Next Target" forecast)

Purpose: when a Tier-1 PFAS/AFFF manufacturer's NAICS goes RED, flag the
real downstream industries that USE that chemical class next -- the
"supply chain contagion" pattern in actual mass-tort litigation: once a
manufacturer's insurance limits are exhausted or its name is radioactive,
plaintiffs' firms move down the supply chain to the companies that bought
and used the chemical. This is a forecast, not a finding -- every entry
here is a manually-curated judgment call (same discipline as
CURATED_LIABILITY_NAICS in severity_dollar_pipeline.py), grounded in real,
documented industrial uses of PFAS/AFFF, not derived from any pipeline.

Each entry's "reason" states the actual real-world use case driving the
adjacency, and whether this project already has any corroborating signal
for that specific NAICS (several of these overlap with companies already
checked in the discovery pipeline -- e.g. Mohawk/Dixie Group for carpet,
Clearwater Paper for food packaging -- where the earlier check found no
*current* liability finding, which is a different question from "is this
NAICS a plausible next target," answered here independently).
"""

DOWNSTREAM_NAICS_ADJACENCY = {
    # Tier 1: 325998 -- AFFF / specialty chemical mfg (3M, Johnson
    # Controls/Tyco Fire Products). Downstream = industries that USE AFFF
    # for fire suppression, not ones that manufacture it.
    "325998": [
        {
            "naics": "324110",
            "label": "Petroleum Refineries",
            "reason": "Refineries maintain AFFF-based fire suppression systems and historically ran AFFF fire-training exercises on-site -- a real, documented PFAS contamination pathway distinct from manufacturing it. (Checked live in this project's discovery pipeline for direct liability findings -- none yet; this flag is a forward-looking use-case risk, not a finding.)",
        },
        {
            "naics": "481111",
            "label": "Scheduled Air Transportation",
            "reason": "FAA Part 139 historically mandated AFFF-based fire suppression at certificated airports; airport authorities and some airlines have been named co-defendants in real AFFF contamination litigation.",
        },
    ],
    # Tier 1: 325199 -- basic organic chemical mfg (DuPont, Chemours,
    # Corteva -- PFAS feedstock producers). Downstream = industries that buy
    # PFAS as a raw material to treat or manufacture consumer products.
    "325199": [
        {
            "naics": "313310",
            "label": "Textile and Fabric Finishing Mills",
            "reason": "PFAS-based water/stain-repellent textile treatments (the same chemical family as 3M's Scotchgard) are a well-documented downstream use.",
        },
        {
            "naics": "314110",
            "label": "Carpet and Rug Mills",
            "reason": "PFAS stain-resistant carpet treatments -- the same reasoning this project already applied when curating Mohawk Industries and Dixie Group as candidate defendants (checked live, no current liability finding, but the use case itself is real and documented).",
        },
        {
            "naics": "322299",
            "label": "All Other Converted Paper Product Manufacturing",
            "reason": "PFAS grease-resistant food-packaging coatings -- the same reasoning already applied to Clearwater Paper.",
        },
        {
            "naics": "325620",
            "label": "Toilet Preparation Manufacturing",
            "reason": "PFAS use in cosmetics -- directly corroborated by a real signal already in this project's own data: California AB1603, 'Perfluoroalkyl and polyfluoroalkyl substances (PFAS): Department of Pesticide Regulation,' on record in legislative_timeline.",
        },
        {
            "naics": "332813",
            "label": "Electroplating, Plating, Polishing, Anodizing and Coloring",
            "reason": "PFAS used as a mist suppressant in chrome electroplating -- the same reasoning this project already used curating Honeywell International into CURATED_LIABILITY_NAICS.",
        },
    ],
}
