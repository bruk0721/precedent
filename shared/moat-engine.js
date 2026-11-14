/* Nubuye -- shared query engine for the Underwriter Console and the
   PFAS Portfolio X-Ray. Single source of truth for the actual threat-
   assessment logic, mirroring underwriter-dashboard/app.py, so the two
   tools can never silently drift into different answers for the same
   NAICS/state. Loads moat_export.json (a static snapshot of the real
   precedent_moat.db, exported via export_moat_data.py) once, then queries
   it entirely client-side. */

const MoatEngine = (() => {
  const US_BORDERS = {
    AL:["FL","GA","MS","TN"],AZ:["CA","NV","NM","UT"],AR:["LA","MS","MO","OK","TN","TX"],CA:["AZ","NV","OR"],
    CO:["AZ","KS","NE","NM","OK","UT","WY"],CT:["MA","NY","RI"],DE:["MD","NJ","PA"],FL:["AL","GA"],GA:["AL","FL","NC","SC","TN"],
    ID:["MT","NV","OR","UT","WA","WY"],IL:["IN","IA","KY","MO","WI"],IN:["IL","KY","MI","OH"],IA:["IL","MN","MO","NE","SD","WI"],
    KS:["CO","MO","NE","OK"],KY:["IL","IN","MO","OH","TN","VA","WV"],LA:["AR","MS","TX"],ME:["NH"],MD:["DE","PA","VA","WV"],
    MA:["CT","NH","NY","RI","VT"],MI:["IN","OH","WI"],MN:["IA","ND","SD","WI"],MS:["AL","AR","LA","TN"],
    MO:["AR","IL","IA","KS","KY","NE","OK","TN"],MT:["ID","ND","SD","WY"],NE:["CO","IA","KS","MO","SD","WY"],
    NV:["AZ","CA","ID","OR","UT"],NH:["ME","MA","VT"],NJ:["DE","NY","PA"],NM:["AZ","CO","OK","TX","UT"],
    NY:["CT","MA","NJ","PA","VT"],NC:["GA","SC","TN","VA"],ND:["MN","MT","SD"],OH:["IN","KY","MI","PA","WV"],
    OK:["AR","CO","KS","MO","NM","TX"],OR:["CA","ID","NV","WA"],PA:["DE","MD","NJ","NY","OH","WV"],RI:["CT","MA"],
    SC:["GA","NC"],SD:["IA","MN","MT","NE","ND","WY"],TN:["AL","AR","GA","KY","MS","MO","NC","VA"],
    TX:["AR","LA","NM","OK"],UT:["AZ","CO","ID","NV","NM","WY"],VT:["MA","NH","NY"],VA:["KY","MD","NC","TN","WV"],
    WA:["ID","OR"],WV:["KY","MD","OH","PA","VA"],WI:["IL","IA","MI","MN"],WY:["CO","ID","MT","NE","SD","UT"],
    AK:[],HI:[],DC:["MD","VA"],
  };
  const STATE_NAMES = {AL:"Alabama",AK:"Alaska",AZ:"Arizona",AR:"Arkansas",CA:"California",CO:"Colorado",CT:"Connecticut",DE:"Delaware",DC:"D.C.",FL:"Florida",GA:"Georgia",HI:"Hawaii",ID:"Idaho",IL:"Illinois",IN:"Indiana",IA:"Iowa",KS:"Kansas",KY:"Kentucky",LA:"Louisiana",ME:"Maine",MD:"Maryland",MA:"Massachusetts",MI:"Michigan",MN:"Minnesota",MS:"Mississippi",MO:"Missouri",MT:"Montana",NE:"Nebraska",NV:"Nevada",NH:"New Hampshire",NJ:"New Jersey",NM:"New Mexico",NY:"New York",NC:"North Carolina",ND:"North Dakota",OH:"Ohio",OK:"Oklahoma",OR:"Oregon",PA:"Pennsylvania",RI:"Rhode Island",SC:"South Carolina",SD:"South Dakota",TN:"Tennessee",TX:"Texas",UT:"Utah",VT:"Vermont",VA:"Virginia",WA:"Washington",WV:"West Virginia",WI:"Wisconsin",WY:"Wyoming"};

  let DB = null;

  function normalizeForMatch(s) { return String(s).toUpperCase().replace(/[^A-Z0-9]/g, ""); }

  function getDefendantsForNaics(naics) {
    const names = new Set();
    for (const r of DB.severity_anchors) if (r.naics_code === naics) names.add(r.company_name);
    return [...names];
  }

  function queryPlaintiffRadar(defendants) {
    if (!defendants.length) return [];
    const tokens = defendants.map(d => normalizeForMatch(d.split(" ")[0]));
    return DB.plaintiff_network.filter(r => tokens.some(t => normalizeForMatch(r.defendant).includes(t)));
  }

  // Legislative tracks are kept separate by `category` -- firefighter
  // presumption laws and PFAS regulation bills are two different litigation
  // tracks this project deliberately does not conflate.
  function queryLegislativeContagion(state) {
    const neighbors = US_BORDERS[state] || [];
    const byCategory = {};
    for (const row of DB.legislative_timeline) {
      const cat = row.category || "uncategorized";
      if (row.state === state) {
        (byCategory[cat] = byCategory[cat] || { own: [], neighbor: [] }).own.push(row);
      } else if (neighbors.includes(row.state)) {
        (byCategory[cat] = byCategory[cat] || { own: [], neighbor: [] }).neighbor.push(row);
      }
    }
    return { byCategory, neighbors };
  }

  function querySeverityAnchor(naics) {
    return DB.severity_anchors.filter(r => r.naics_code === naics);
  }

  function parseDollarToMillions(raw) {
    const m = /\$\s?([\d,.]+)\s?(million|billion)?/i.exec(raw);
    if (!m) return null;
    const amount = parseFloat(m[1].replace(/,/g, ""));
    const unit = (m[2] || "").toLowerCase();
    return unit === "billion" ? amount * 1000 : amount;
  }

  // naicsIsRelevant -- found live via the Portfolio X-Ray's own test data: an
  // unrelated account (a bakery) was coming back AMBER purely because its
  // STATE had some unrelated bill on record, with zero check that the
  // account's own NAICS has anything to do with PFAS/presumption litigation
  // at all. query_legislative_contagion is intentionally state-only (a law
  // is a jurisdiction fact), but letting that alone drive the threat level
  // for an industry with no plausible exposure path is exactly the kind of
  // false-elevated signal this project's hard rules exist to prevent. Gate
  // the legislative signal's effect on the VERDICT (not its visibility --
  // the Legislative Contagion panel itself still shows real data honestly)
  // on the account's NAICS being a known Tier-1 defendant/manufacturer OR a
  // curated Tier-2 downstream-adjacent industry.
  //
  // Second, more subtle version of the same bug, also found live: a carpet
  // mill (a real PFAS-regulation downstream target) was still getting
  // elevated by a FIREFIGHTER_PRESUMPTION bill hit on its state -- but
  // firefighter presumption laws are workers'-comp law for public fire
  // departments/municipalities, a completely different insured category
  // than any NAICS this project curates. Every NAICS-based commercial
  // account in this engine's current scope is only ever plausibly exposed
  // to the pfas_regulation track, never firefighter_presumption -- so only
  // that category counts toward the verdict, even once naicsIsRelevant.
  const LEGISLATIVE_CATEGORIES_RELEVANT_TO_NAICS = ["pfas_regulation"];
  const RISK_CATEGORY_LABELS = { pfas: "PFAS/chemical", talc: "talc litigation" };

  function computeThreatLevel(plaintiffRows, legResult, severityRows, naicsIsRelevant) {
    const hasPlaintiff = plaintiffRows.length > 0;
    const hasLegislative = naicsIsRelevant && Object.keys(legResult.byCategory)
      .some(cat => LEGISLATIVE_CATEGORIES_RELEVANT_TO_NAICS.includes(cat));
    const severityValues = severityRows.map(r => parseDollarToMillions(r.dollar_amount)).filter(v => v !== null);
    const maxSeverity = severityValues.length ? Math.max(...severityValues) : null;
    // Which category actually drove the max severity figure -- so the RED
    // recommendation never says "PFAS exclusion" for a talc finding or vice
    // versa. Found live while adding talc as a second category: the
    // recommendation text was hardcoded to "PFAS/chemical exclusion"
    // regardless of which category's data actually triggered it.
    const maxRow = severityRows.find(r => parseDollarToMillions(r.dollar_amount) === maxSeverity);
    const categoryLabel = RISK_CATEGORY_LABELS[maxRow && maxRow.risk_category] || "this category's";

    if (!hasPlaintiff && !hasLegislative && maxSeverity === null) {
      return { color: "gray", label: "INSUFFICIENT DATA",
        rec: "No plaintiff, legislative, or severity signal has been collected for this NAICS/state combination yet. This is not a clean bill of health — it means nothing has been found yet, not that nothing exists. Route to manual underwriting review; do not treat the absence of a flag as the presence of safety." };
    }
    if (maxSeverity !== null && maxSeverity >= 1000 && (hasPlaintiff || hasLegislative)) {
      return { color: "red", label: "HIGH THREAT",
        rec: `Recommend: attach an absolute ${categoryLabel} exclusion endorsement. Refer to the exposure team for a portfolio accumulation check given an active policy-trigger signal and a severity anchor above $1B.` };
    }
    if (maxSeverity !== null || hasPlaintiff || hasLegislative) {
      return { color: "amber", label: "ELEVATED — REVIEW",
        rec: "Recommend: flag for underwriter review. Consider a sublimit, monitoring endorsement, or additional loss-cost loading pending next renewal cycle rather than a full exclusion." };
    }
    return { color: "amber", label: "LOW SIGNAL (data-backed)",
      rec: "No material signal found despite data being present for this query. Standard terms." };
  }

  function getFilingVelocity(defendants) {
    if (!defendants.length) return { velocity: null, count: 0, span: 0 };
    const tokens = defendants.map(d => normalizeForMatch(d.split(" ")[0]));
    const rows = DB.plaintiff_network.filter(r => r.date_filed && tokens.some(t => normalizeForMatch(r.defendant).includes(t)));
    const seen = new Set(); const uniqueRows = [];
    for (const r of rows) { const k = r.docket_id + "|" + r.date_filed; if (!seen.has(k)) { seen.add(k); uniqueRows.push(r); } }
    if (uniqueRows.length < 2) return { velocity: null, count: uniqueRows.length, span: 0 };
    const dates = uniqueRows.map(r => new Date(r.date_filed)).sort((a, b) => a - b);
    const spanMonths = Math.max((dates[dates.length - 1] - dates[0]) / (1000 * 60 * 60 * 24 * 30.44), 1.0);
    return { velocity: uniqueRows.length / spanMonths, count: uniqueRows.length, span: spanMonths };
  }

  // EPA TRI facility-level PFAS reports -- real, EPA-standardized parent-
  // company names (facility_pfas_reports.company_name uses the exact same
  // strings as severity_anchors.company_name, matched at load time in
  // epa_tri_pipeline.py), so this is a direct equality match, not a fuzzy
  // substring one.
  function getFacilityReports(defendants) {
    if (!defendants.length) return [];
    return (DB.facility_pfas_reports || []).filter(r => defendants.includes(r.company_name));
  }

  function getDownstreamAdjacency(naics) {
    return (DB.downstream_adjacency || {})[naics] || [];
  }

  // Entity Traversal / veil-piercing -- ported from
  // entity_traversal_pipeline.py's detect_veil_piercing(). For every docket,
  // flag it when BOTH a known subsidiary AND its parent company appear as
  // defendants in that same docket -- that co-occurrence is the real signal
  // a complaint reached past the subsidiary up to the parent's much larger
  // corporate insurance tower, not just a naming coincidence. Scoped to the
  // CURRENT account's own defendants (parents it's actually exposed to),
  // not run globally, so the console only ever shows a signal relevant to
  // the NAICS being assessed.
  function detectVeilPiercing(defendants) {
    if (!defendants.length) return [];
    const defTokens = defendants.map(d => normalizeForMatch(d));
    const subsidiaryRows = (DB.corporate_subsidiaries || []).filter(
      s => defTokens.some(t => t.includes(normalizeForMatch(s.parent_company)) || normalizeForMatch(s.parent_company).includes(t))
    );
    if (!subsidiaryRows.length) return [];

    const docketDefendants = {};
    for (const r of DB.plaintiff_network) {
      const key = r.docket_id;
      (docketDefendants[key] = docketDefendants[key] || new Set()).add(normalizeForMatch(r.defendant));
    }

    const flags = [];
    for (const { parent_company, subsidiary_name } of subsidiaryRows) {
      const p = normalizeForMatch(parent_company);
      const s = normalizeForMatch(subsidiary_name);
      for (const [docketId, defs] of Object.entries(docketDefendants)) {
        const parentHit = [...defs].some(d => d.includes(p) || p.includes(d));
        const subHit = [...defs].some(d => d.includes(s) || s.includes(d));
        if (parentHit && subHit) {
          const sampleRow = DB.plaintiff_network.find(r => r.docket_id === docketId);
          flags.push({ docketId, parent: parent_company, subsidiary: subsidiary_name, caseName: sampleRow && sampleRow.case_name, sourceUrl: sampleRow && sampleRow.source_url });
        }
      }
    }
    return flags;
  }

  function isDownstreamTarget(naics) {
    const adj = DB.downstream_adjacency || {};
    return Object.values(adj).some(list => list.some(a => a.naics === naics));
  }

  // Defense & Cost Containment (DCC) proxy -- checked live whether any of
  // the 5 curated companies' real 10-Ks disclose a standalone defense/legal
  // cost figure for PFAS litigation (a dedicated pipeline, dcc_cost_
  // pipeline.py, searched all 5): zero clean hits. Companies bundle legal
  // fees into aggregate settlement charges, never break them out. Rather
  // than invent a plausible-sounding range (the exact mistake a pasted
  // strategy doc made, quoting an uncited "$350k-$1.2M per co-defendant"
  // figure), this uses the one real, sourced number found: RAND's 2005
  // asbestos-litigation study (RAND MG162, data through 2002) found 31
  // cents of every dollar spent on that litigation went to defense costs.
  // This is a DIFFERENT, OLDER mass tort, not a PFAS-specific disclosure --
  // used here only as an order-of-magnitude historical analog, exactly the
  // same "not an actuarial estimate" framing Zero-Day IBNR already uses.
  const DCC_ASBESTOS_ANALOG_RATIO = 0.31;

  function getDccProxy(maxSeverity) {
    if (maxSeverity === null) return null;
    return maxSeverity * DCC_ASBESTOS_ANALOG_RATIO;
  }

  // Entity Resolution Crosswalk -- search any name against the real,
  // SEC-Exhibit-21-sourced corporate_subsidiaries table and surface its
  // parent's own real severity anchor, so a search for a benign-sounding
  // subsidiary ("Tyco Fire Products") surfaces its parent's $7.7B PFAS
  // liability instead of coming back empty. Honestly scoped: this only
  // covers subsidiaries of companies whose Exhibit 21 has actually been
  // pulled (3M, Johnson Controls as of this build) -- NOT a general
  // web-scale company crosswalk. A broader version pitched alongside this
  // (cross-referencing EPA's Chemical Data Reporting and 50 states' business
  // registries) was checked and rejected: CDR manufacturer identity is
  // routinely withheld as confidential business information per EPA's own
  // CDR documentation, and bulk state-registry scraping across 50
  // non-uniform systems is a real infrastructure project, not a feature --
  // see precedent_project_archive.md for the full feasibility note.
  function searchEntity(query) {
    const q = normalizeForMatch(query);
    if (!q) return [];
    const subs = (DB.corporate_subsidiaries || []).filter(
      s => normalizeForMatch(s.subsidiary_name).includes(q) || normalizeForMatch(s.parent_company).includes(q)
    );
    const seen = new Set();
    const results = [];
    for (const s of subs) {
      const key = s.parent_company + "|" + s.subsidiary_name;
      if (seen.has(key)) continue;
      seen.add(key);
      const parentSeverity = (DB.severity_anchors || []).filter(r => r.company_name === s.parent_company);
      const values = parentSeverity.map(r => parseDollarToMillions(r.dollar_amount)).filter(v => v !== null);
      const maxSeverity = values.length ? Math.max(...values) : null;
      results.push({ subsidiary: s.subsidiary_name, parent: s.parent_company, maxSeverityMillions: maxSeverity, severityRows: parentSeverity });
    }
    return results;
  }

  function getCrosswalkCoverage() {
    return [...new Set((DB.corporate_subsidiaries || []).map(s => s.parent_company))];
  }

  // Plaintiff Firm Tracker -- a ranked, real view of which firms are filing
  // against which defendants, in which courts, across every docket this
  // project has actually pulled. Deliberately NOT called a "venue matrix":
  // checked live against the real plaintiff_network data before building
  // this, and as of this build every row resolves to just 3 distinct
  // dockets and effectively ONE real venue (the MDL 2873 leadership docket
  // sits with the national JPML; the other two member dockets are both in
  // "scd", D. South Carolina, where MDL 2873 is centralized) -- there is no
  // real cross-state venue-shopping signal in the data yet to show a
  // multi-jurisdiction matrix. Excludes PRO SE and UNKNOWN rows (no real
  // firm name) since this tracker is specifically about firm behavior.
  function getPlaintiffFirmTracker() {
    const byFirm = {};
    for (const r of DB.plaintiff_network) {
      if (/^PRO SE|^UNKNOWN/i.test(r.plaintiff_firm)) continue;
      const entry = byFirm[r.plaintiff_firm] || { firm: r.plaintiff_firm, defendants: new Set(), courts: new Set(), dockets: new Set(), caseNames: new Set() };
      entry.defendants.add(r.defendant);
      entry.courts.add(r.court);
      entry.dockets.add(r.docket_id);
      entry.caseNames.add(r.case_name);
      byFirm[r.plaintiff_firm] = entry;
    }
    const rows = Object.values(byFirm).map(f => ({
      firm: f.firm,
      defendantCount: f.defendants.size,
      defendants: [...f.defendants],
      courts: [...f.courts],
      docketCount: f.dockets.size,
      caseNames: [...f.caseNames],
    })).sort((a, b) => b.docketCount - a.docketCount || a.firm.localeCompare(b.firm));
    const distinctCourts = new Set(DB.plaintiff_network.map(r => r.court));
    const distinctDockets = new Set(DB.plaintiff_network.map(r => r.docket_id));
    // "United States Judicial Panel on Multidistrict Litigation" is the
    // national panel that assigns where an MDL sits, not a filing venue
    // itself -- excluded here so a real cross-state venue-shopping signal
    // isn't confused with the MDL-leadership docket's procedural label.
    const realVenues = new Set([...distinctCourts].filter(c => c !== "United States Judicial Panel on Multidistrict Litigation"));
    // Plaintiff-firm concentration -- a real, buildable signal from
    // research (precedent_project_archive.md item 78): legal trade press
    // documents that a small number of firms tend to lead MDL after MDL,
    // but no external study quantifies "how concentrated is normal" to
    // compare against. This computes OUR OWN real concentration (top
    // firm's and top-3 firms' share of all real, named-firm filing rows)
    // as an honest internal metric -- not benchmarked against an
    // external number that doesn't exist, just reported as what it is.
    const namedFirmRows = DB.plaintiff_network.filter(r => !/^PRO SE|^UNKNOWN/i.test(r.plaintiff_firm));
    const totalNamedRows = namedFirmRows.length;
    const byFirmRowCount = {};
    for (const r of namedFirmRows) byFirmRowCount[r.plaintiff_firm] = (byFirmRowCount[r.plaintiff_firm] || 0) + 1;
    const sortedCounts = Object.values(byFirmRowCount).sort((a, b) => b - a);
    const topFirmShare = totalNamedRows ? sortedCounts[0] / totalNamedRows : null;
    const top3Share = totalNamedRows ? sortedCounts.slice(0, 3).reduce((s, v) => s + v, 0) / totalNamedRows : null;

    return {
      rows,
      distinctCourtCount: distinctCourts.size,
      distinctDocketCount: distinctDockets.size,
      venueConcentrationNote: realVenues.size <= 1
        ? "All real filings on record currently resolve to a single venue (D. South Carolina, where MDL 2873 is centralized) -- no cross-state venue-shopping signal exists in the data yet."
        : null,
      concentration: {
        totalNamedFirmRows: totalNamedRows,
        distinctFirmCount: rows.length,
        topFirmShare, top3Share,
      },
    };
  }

  // Renewal Window Monitor -- filters legislative_timeline to bills whose
  // RECORDED date falls in a given quarter. Important, honest limitation:
  // the date we store (enactment_date) is the bill's SIGNING/history-action
  // date pulled from LegiScan's history array (see time_resolution_pipeline.
  // py's extract_enactment_date) -- it is NOT a verified statutory EFFECTIVE
  // date. Many statutes take effect on a later date than signing (e.g. "90
  // days after adjournment" or an explicit later date written into the
  // bill), and this project has not yet verified, against real bill text,
  // whether LegiScan exposes that separately or how often it actually
  // differs from the signing date for the bills already on file -- that
  // check needs a live LegiScan API call this build didn't have the key to
  // run. Ships with that gap stated up front rather than silently treated
  // as resolved.
  // Real EPA ECHO compliance/enforcement data for the SAME facilities
  // already on file via facility_pfas_reports -- joined through
  // facility_name, not a separate company crosswalk. Deliberately returns
  // EVERY real registry record found for those facility names (see
  // echo_compliance_pipeline.py's own comment on why picking a single
  // "best match" silently discarded a real $79,500-penalty violation
  // record at one site) -- never collapsed into one summary number.
  function getComplianceRecords(defendants) {
    if (!defendants.length) return [];
    const facilityNames = new Set(
      (DB.facility_pfas_reports || []).filter(r => defendants.includes(r.company_name)).map(r => r.facility_name)
    );
    if (!facilityNames.size) return [];
    return (DB.facility_compliance_echo || []).filter(r => facilityNames.has(r.facility_name));
  }

  // State insurance rate/form filings (SERFF, via Texas TDI's real public
  // filing list) -- a genuinely different signal type from everything else
  // here: not "is there liability," but "has the insurance market itself
  // already started pricing/excluding this risk." Global, not NAICS/state
  // scoped, same as the Plaintiff Firm Tracker -- honestly labeled as
  // Texas-only (the one state this project has actually pulled), never
  // implied to be nationwide.
  function getRegulatoryFilings() {
    return DB.regulatory_filings || [];
  }

  // Scientific literature momentum (PubMed) -- a genuinely different axis
  // from everything else here: not legal or financial, but how fast the
  // underlying peer-reviewed science is accumulating. Returns the real
  // per-year counts for a risk category, sorted by year.
  function getScientificMomentum(riskCategory) {
    return (DB.scientific_literature_momentum || [])
      .filter(r => r.risk_category === riskCategory)
      .sort((a, b) => a.year - b.year);
  }

  // Real state contamination-site geodata (Michigan EGLE) -- the
  // contamination-OUTCOME counterpart to TRI (what was released) and ECHO
  // (was the facility cited). Global, not NAICS/state scoped, and
  // honestly limited to Michigan (the one state this project has pulled).
  function getStateContaminationSites() {
    return DB.state_contamination_sites || [];
  }

  // Real-time material events (SEC 8-Ks) -- closes a real gap: this
  // project previously only pulled annual 10-Ks, so a settlement or
  // material charge could sit unseen for up to a year. Joined by CIK
  // against the account's own curated defendants, same join pattern as
  // severity_anchors.
  function getMaterialEvents(defendants) {
    if (!defendants.length) return [];
    const ciks = new Set((DB.severity_anchors || []).filter(r => defendants.includes(r.company_name)).map(r => r.cik));
    return (DB.material_event_filings || []).filter(r => ciks.has(r.cik))
      .sort((a, b) => new Date(b.filing_date) - new Date(a.filing_date));
  }

  // Real FDA FAERS adverse-event report counts (talc only -- PFAS isn't a
  // drug and has no equivalent FAERS presence, not forced into this).
  function getAdverseEvents(riskCategory) {
    return (DB.fda_adverse_events || []).filter(r => r.risk_category === riskCategory).sort((a, b) => a.year - b.year);
  }

  // Real, official JPML pending-MDL case counts -- straight from the
  // court system, not a news estimate or a single company's own
  // disclosure. Most recent report only (one row per MDL per report
  // date currently on file).
  function getJpmlStats(riskCategory) {
    return (DB.jpml_mdl_statistics || []).filter(r => r.risk_category === riskCategory);
  }

  // Real federal PFAS/AFFF remediation contract awards (USASpending.gov)
  // -- where federal remediation money is actually flowing right now.
  // Global, not NAICS/state scoped, same as the Plaintiff Firm Tracker.
  function getFederalRemediationContracts() {
    return DB.federal_remediation_contracts || [];
  }

  // Real SEC 8-K Item 1.05 (material cybersecurity incident) filings,
  // across ALL real SEC filers -- not tied to a litigation category or a
  // curated defendant list. See cyber_incident_pipeline.py. Global, same
  // role as getFederalRemediationContracts: a real roster to cross-
  // reference against a book of business, not a per-account finding this
  // engine computes on its own.
  function getCyberIncidentFilings() {
    return DB.cyber_incident_filings || [];
  }

  // Settlement-Stage classification -- curated, not computed (see
  // settlement_stage_classification.py for the real, cited reasoning per
  // category). Never an algorithmic score.
  function getSettlementStage(riskCategory) {
    return (DB.settlement_stage_classification || {})[riskCategory] || null;
  }

  // Historical Scale Comparison -- curated, real, cited external
  // benchmark totals (asbestos/PFAS/talc), same role as the RAND DCC
  // proxy and the CAS reserving benchmark: context, never a legal or
  // actuarial fact about any specific curated defendant.
  function getHistoricalScaleComparison() {
    return DB.historical_scale_comparison || {};
  }

  // Aggregation Map -- the real "common shock" correlation structure this
  // project already has the raw data for, surfaced explicitly: how ONE
  // litigation event against a single curated parent touches many
  // seemingly-unrelated accounts, through real subsidiary entities (SEC
  // Exhibit 21), real facility locations (EPA TRI), and real documented
  // downstream NAICS use-cases -- the actual hard problem that separates
  // casualty aggregation risk from property catastrophe risk. Every count
  // below is real; the NAICS-mapping judgment calls mirror the same
  // curated, cited decisions already made in severity_dollar_pipeline.py's
  // CURATED_LIABILITY_NAICS, not re-derived or guessed here.
  const PARENT_TIER1_NAICS = {
    "3M CO": "325998",
    "JOHNSON CONTROLS INTERNATIONAL PLC": "325998",
    "CHEMOURS CO": "325199",
    "DUPONT DE NEMOURS, INC.": "325199",
  };

  function getAggregationMap() {
    const parents = new Set([
      ...(DB.corporate_subsidiaries || []).map(s => s.parent_company),
      ...(DB.facility_pfas_reports || []).map(f => f.company_name),
    ]);
    return [...parents].map(parent => {
      const subsidiaries = (DB.corporate_subsidiaries || []).filter(s => s.parent_company === parent);
      const facilities = (DB.facility_pfas_reports || []).filter(f => f.company_name === parent);
      const states = [...new Set(facilities.map(f => f.state).filter(Boolean))];
      const naics = PARENT_TIER1_NAICS[parent.toUpperCase()];
      const downstream = naics ? getDownstreamAdjacency(naics) : [];
      const severityRows = (DB.severity_anchors || []).filter(r => r.company_name === parent);
      const severityValues = severityRows.map(r => parseDollarToMillions(r.dollar_amount)).filter(v => v !== null);
      const maxSeverityMillions = severityValues.length ? Math.max(...severityValues) : null;
      return {
        parent, naics, maxSeverityMillions,
        subsidiaryCount: subsidiaries.length,
        facilityCount: facilities.length,
        facilityStates: states,
        downstreamCount: downstream.length,
        downstream,
      };
    }).filter(r => r.subsidiaryCount > 0 || r.facilityCount > 0)
      .sort((a, b) => (b.subsidiaryCount + b.facilityCount) - (a.subsidiaryCount + a.facilityCount));
  }

  // Emergence Signal -- real JPML scale + real leading-indicator momentum,
  // reported separately per risk category (never blended into one score).
  // See emergence_signal_pipeline.py for the full methodology and why a
  // category's missing components are reported as "not tracked," never
  // silently scored as zero.
  function getEmergenceSignal(riskCategory) {
    const rows = DB.emergence_signal || [];
    return riskCategory ? (rows.find(r => r.risk_category === riskCategory) || null) : rows;
  }

  // Momentum Backtest -- the same emergence-signal formula recomputed "as
  // of" each historical year using only data that existed through that
  // year. See momentum_backtest_pipeline.py.
  function getMomentumBacktest(riskCategory) {
    const rows = DB.momentum_backtest || [];
    const filtered = riskCategory ? rows.filter(r => r.risk_category === riskCategory) : rows;
    return [...filtered].sort((a, b) => a.as_of_year - b.as_of_year);
  }

  // Severity x Momentum comparison -- does the backtest's momentum
  // score trajectory actually track real settlement MAGNITUDE, not just
  // timing? Joins the real backtest scores against this project's own
  // real, dated timeline milestones that carry a real dollar magnitude.
  // Stated honestly: this is NOT guaranteed to show a clean correlation,
  // and for talc it visibly does not (scientific-literature momentum
  // drops in the project's own real later years while the real
  // settlement size kept rising) -- shown as-is, not cherry-picked.
  function getSeverityMomentumComparison(riskCategory) {
    const backtest = getMomentumBacktest(riskCategory);
    const milestones = (DB.timeline_milestones || []).filter(m =>
      m.category === riskCategory && m.magnitude_usd_millions != null
    );
    const byYear = {};
    milestones.forEach(m => {
      const year = parseInt(String(m.date).slice(0, 4), 10);
      if (!byYear[year]) byYear[year] = { year, totalMagnitude: 0, titles: [] };
      byYear[year].totalMagnitude += m.magnitude_usd_millions;
      byYear[year].titles.push(m.title);
    });
    return backtest.map(b => ({
      year: b.as_of_year,
      momentumScore: b.score,
      realMagnitudeMillions: byYear[b.as_of_year] ? byYear[b.as_of_year].totalMagnitude : null,
      realEventTitles: byYear[b.as_of_year] ? byYear[b.as_of_year].titles : [],
    }));
  }

  // Discovery Scan -- the same leading-indicator methodology pointed at
  // real, named candidates this project does not yet track. See
  // discovery_scan_pipeline.py.
  function getDiscoveryCandidates() {
    return DB.discovery_candidates || [];
  }

  // Clinical trials -- real terminated/withdrawn trials for a candidate,
  // each classified SAFETY_FLAGGED (the stated reason mentions an adverse
  // event/safety/toxicity finding) or NON_SAFETY (enrollment, funding, a
  // sponsor decision, or no reason given) -- never counted as a danger
  // signal just because a trial stopped. See clinical_trials_pipeline.py.
  function getClinicalTrials(candidate) {
    const rows = DB.clinical_trials || [];
    return candidate ? rows.filter(r => r.candidate === candidate) : rows;
  }

  // Pharma recalls -- real FDA drug/enforcement recalls. Most tracked
  // candidates here are not FDA-regulated drugs, so an empty result for
  // a given candidate is expected, not a gap. See pharma_recall_pipeline.py.
  function getPharmaRecalls(candidate) {
    const rows = DB.pharma_recalls || [];
    return candidate ? rows.filter(r => r.candidate === candidate) : rows;
  }

  // Cancer incidence x contamination-site correlation -- a real, honest
  // CORRELATION, never presented as causation, and deliberately NOT a
  // "trend" claim: these are raw case COUNTS, not age-adjusted rates, so
  // comparing an early year's count to a recent year's count would mostly
  // just measure population growth over that period, not any real change
  // in cancer risk -- that comparison is left out on purpose. This only
  // reports each state's most recent real case count alongside its real
  // tracked contamination-site count; the viewer draws their own
  // conclusion from the two real, independent numbers, not from a
  // computed trend this pipeline isn't equipped to state honestly.
  // See cancer_incidence_pipeline.py and state_contamination_sites.
  // Coverage matrix -- the real answer to "what does Nubuye actually track."
  // Different real pipelines name the same category differently (JPML
  // calls it "hair_relaxer", the discovery-scan/clinical-trials/pharma
  // pipelines call the same thing "hair_relaxer_chemicals"; JPML's
  // "social_media_mental_health" vs discovery-scan's
  // "social_media_adolescent_mental_health"). This alias map exists
  // ONLY to let one canonical row represent the same real category
  // across tables that independently named it differently -- it does
  // not invent coverage; a category with zero real rows in a table
  // still shows as not-tracked for that signal.
  const CATEGORY_ALIASES = {
    pfas: ["pfas"],
    talc: ["talc"],
    turnout_gear: ["turnout_gear"],
    hair_relaxer: ["hair_relaxer", "hair_relaxer_chemicals"],
    social_media_mental_health: ["social_media_mental_health", "social_media_adolescent_mental_health"],
    glyphosate: ["glyphosate"],
    // Added after direct follow-up requests covering other emerging/
    // unknown casualty risk -- this matrix is the real, comprehensive
    // "what does Nubuye actually track" answer, so every real category
    // added anywhere else on the site belongs here too, not just the
    // original 6. Each key below is a real, live-verified category (see
    // jpml_mdl_pipeline.py / discovery_scan_pipeline.py / settlement_
    // stage_classification.py), not a placeholder.
    glp1_weight_loss: ["glp1_weight_loss"],
    paraquat: ["paraquat"],
    cpap: ["cpap"],
    earplugs: ["earplugs"],
    opioid: ["opioid"],
    insulin_pbm: ["insulin_pbm"],
    // Climate-attribution litigation is real and growing but genuinely
    // has NO federal MDL (confirmed live, state-court litigation only)
    // and its sec_10k_risk_factor_matches rows use a different category
    // key ("climate_litigation") than its discovery_candidates rows
    // ("climate_attribution_litigation") -- both aliased together here,
    // same purpose as the hair_relaxer/social_media aliasing above.
    climate_litigation: ["climate_litigation", "climate_attribution_litigation"],
  };
  const CATEGORY_LABELS = {
    pfas: "PFAS / AFFF", talc: "Talc", turnout_gear: "Turnout Gear",
    hair_relaxer: "Hair Relaxer", social_media_mental_health: "Social Media / Mental Health", glyphosate: "Glyphosate / Roundup",
    glp1_weight_loss: "GLP-1 Weight-Loss Drugs", paraquat: "Paraquat", cpap: "Philips CPAP", earplugs: "3M Combat Arms Earplugs",
    opioid: "Opioid", insulin_pbm: "Insulin / PBM Pricing", climate_litigation: "Climate-Attribution Litigation*",
  };

  function _hasAny(rows, field, aliases) {
    return rows.some(r => aliases.includes(r[field]));
  }

  function getCoverageMatrix() {
    const db = DB || {};
    const sciMomentum = db.scientific_literature_momentum || [];
    const legislative = db.legislative_timeline || [];
    const materialEvents = db.material_event_filings || [];
    const fdaEvents = db.fda_adverse_events || [];
    const clinicalTrials = db.clinical_trials || [];
    const pharmaRecalls = db.pharma_recalls || [];
    const jpml = db.jpml_mdl_statistics || [];
    const discovery = db.discovery_candidates || [];
    const osha = db.osha_inspections || [];
    const tenKs = db.sec_10k_risk_factor_matches || [];

    const SIGNALS = [
      { key: "jpml", label: "Real MDL / JPML scale", check: (al) => _hasAny(jpml, "risk_category", al) },
      { key: "sci", label: "Scientific literature (PubMed)", check: (al) => _hasAny(sciMomentum, "risk_category", al) || _hasAny(discovery, "candidate", al) },
      { key: "leg", label: "State legislation", check: (al) => al.some(a => legislative.some(r => r.category && r.category.includes(a))) },
      { key: "sec8k", label: "SEC 8-K filings", check: (al) => _hasAny(materialEvents, "risk_category", al) },
      { key: "ftf", label: "SEC 10-K risk factors", check: (al) => _hasAny(tenKs, "risk_category", al) },
      { key: "fda", label: "FDA adverse events", check: (al) => _hasAny(fdaEvents, "risk_category", al) },
      { key: "trials", label: "Clinical trials (terminated/withdrawn)", check: (al) => _hasAny(clinicalTrials, "candidate", al) },
      { key: "recalls", label: "FDA drug recalls", check: (al) => _hasAny(pharmaRecalls, "candidate", al) },
      { key: "osha", label: "OSHA inspections", check: (al) => _hasAny(osha, "risk_category", al) },
    ];

    return Object.entries(CATEGORY_ALIASES).map(([key, aliases]) => ({
      key, label: CATEGORY_LABELS[key],
      signals: SIGNALS.map(s => ({ key: s.key, label: s.label, tracked: s.check(aliases) })),
    }));
  }

  // SAMHSA treatment facilities -- real per-state count of licensed
  // mental-health/substance-use treatment facilities, from SAMHSA's own
  // FindTreatment.gov API. A real proxy for existing behavioral-health
  // infrastructure, NOT an incidence or litigation signal on its own.
  // See samhsa_treatment_locator_pipeline.py.
  // OSHA inspections -- real inspection records matched against this
  // project's own already-sourced real defendant names (Fire-Dex, Globe
  // Manufacturing, 3M, DuPont, Johnson, etc.), not a loose category
  // keyword. See osha_inspection_pipeline.py.
  // EPA TSCA new-chemical notices -- real, dated monthly Federal Register
  // notices of new substances entering EPA's TSCA review pipeline. Not a
  // claim any one substance is dangerous -- a real "regrettable
  // substitution" leading indicator: a replacement chemical for an
  // already-litigated category often shows up here years before any
  // litigation could exist around it. See epa_tsca_new_chemicals_pipeline.py.
  function getEpaTscaNotices() {
    return DB.epa_tsca_new_chemical_notices || [];
  }

  // SEC 10-K risk-factor language -- real, dated detection of which real
  // companies have started naming a tracked category in their own 10-K
  // risk factors, across ALL real SEC filers, not just this project's
  // curated defendant list. See sec_10k_risk_factor_pipeline.py.
  function getSec10kRiskFactorMatches(riskCategory) {
    const rows = DB.sec_10k_risk_factor_matches || [];
    return riskCategory ? rows.filter(r => r.risk_category === riskCategory) : rows;
  }

  function getOshaInspections(riskCategory) {
    const rows = DB.osha_inspections || [];
    return riskCategory ? rows.filter(r => r.risk_category === riskCategory) : rows;
  }

  function getSamhsaTreatmentFacilities(stateCode) {
    const rows = DB.samhsa_treatment_facilities || [];
    return stateCode ? (rows.find(r => r.state_code === stateCode) || null) : rows;
  }

  function getContaminationCancerCorrelation() {
    const incidence = DB.cancer_incidence || [];
    // Two real, independent site sources, combined: Michigan's own EGLE
    // sites (state-reported, "state_contamination_sites") and EPA's own
    // national PFAS Analytic Tools Superfund-sites-with-detections layer
    // ("national_pfas_superfund_sites", 45 states/territories) -- fixes
    // the earlier n=1-state limitation. Both are real tracked-site
    // counts from different real sources, summed per state, not
    // deduplicated against each other (they're structurally different:
    // state-reported investigation sites vs. federal Superfund sites),
    // which is stated here rather than silently assumed away.
    const mi = DB.state_contamination_sites || [];
    const national = DB.national_pfas_superfund_sites || [];
    if (!incidence.length || (!mi.length && !national.length)) return [];

    const siteCountByState = {};
    mi.forEach(s => { siteCountByState[s.state] = (siteCountByState[s.state] || 0) + 1; });
    national.forEach(s => { siteCountByState[s.state] = (siteCountByState[s.state] || 0) + 1; });

    const byState = {};
    incidence.forEach(r => {
      if (!r.state_code) return;
      (byState[r.state_code] = byState[r.state_code] || []).push(r);
    });

    return Object.entries(siteCountByState).map(([state, siteCount]) => {
      const rows = (byState[state] || []).slice().sort((a, b) => b.year - a.year);
      const latest = rows[0] || null;
      return {
        state, siteCount,
        latestYear: latest ? latest.year : null,
        latestCount: latest ? latest.case_count : null,
      };
    }).sort((a, b) => b.siteCount - a.siteCount);
  }

  function getRenewalWindow(quarterStartISO, quarterEndISO) {
    const start = new Date(quarterStartISO);
    const end = new Date(quarterEndISO);
    const rows = DB.legislative_timeline.filter(r => {
      if (!r.enactment_date) return false;
      const d = new Date(r.enactment_date);
      return d >= start && d <= end;
    });
    return {
      rows,
      dateFieldCaveat: "Filtered on the bill's recorded SIGNING date, not a verified statutory effective date -- see getRenewalWindow's comment in moat-engine.js for why that distinction is still open.",
    };
  }

  function assess(naics, state) {
    const defendants = getDefendantsForNaics(naics);
    const plaintiffRows = queryPlaintiffRadar(defendants);
    const legResult = queryLegislativeContagion(state);
    const severityRows = querySeverityAnchor(naics);
    const naicsIsRelevant = defendants.length > 0 || isDownstreamTarget(naics);
    const threat = computeThreatLevel(plaintiffRows, legResult, severityRows, naicsIsRelevant);
    const velocity = getFilingVelocity(defendants);
    const severityValues = severityRows.map(r => parseDollarToMillions(r.dollar_amount)).filter(v => v !== null);
    const maxSeverity = severityValues.length ? Math.max(...severityValues) : null;
    const maxRow = severityRows.find(r => parseDollarToMillions(r.dollar_amount) === maxSeverity);
    const scientificMomentum = maxRow && maxRow.risk_category ? getScientificMomentum(maxRow.risk_category) : [];
    return {
      naics, state, defendants, plaintiffRows, legResult, severityRows, threat,
      maxSeverity, velocity, naicsIsRelevant, nextTarget: getDownstreamAdjacency(naics),
      veilPiercing: detectVeilPiercing(defendants), dccProxy: getDccProxy(maxSeverity),
      facilityReports: getFacilityReports(defendants),
      complianceRecords: getComplianceRecords(defendants),
      scientificMomentum,
      materialEvents: getMaterialEvents(defendants),
    };
  }

  async function load(jsonPath) {
    const resp = await fetch(jsonPath);
    DB = await resp.json();
    return DB;
  }

  return {
    load, assess, getDefendantsForNaics, queryPlaintiffRadar, queryLegislativeContagion,
    querySeverityAnchor, parseDollarToMillions, computeThreatLevel, getFilingVelocity,
    getDownstreamAdjacency, detectVeilPiercing, getDccProxy, getFacilityReports, normalizeForMatch, US_BORDERS, STATE_NAMES,
    searchEntity, getCrosswalkCoverage, getPlaintiffFirmTracker, getRenewalWindow,
    getComplianceRecords, getRegulatoryFilings, getScientificMomentum, getStateContaminationSites,
    getMaterialEvents, getAdverseEvents, getJpmlStats, getFederalRemediationContracts, getCyberIncidentFilings,
    getSettlementStage, getHistoricalScaleComparison, getEmergenceSignal,
    getMomentumBacktest, getSeverityMomentumComparison, getDiscoveryCandidates, getAggregationMap,
    getClinicalTrials, getPharmaRecalls, getContaminationCancerCorrelation, getCoverageMatrix,
    getSamhsaTreatmentFacilities, getOshaInspections, getEpaTscaNotices, getSec10kRiskFactorMatches,
    get db() { return DB; },
  };
})();
