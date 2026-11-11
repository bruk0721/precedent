/* Precedent -- shared query engine for the Underwriter Console and the
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
  function computeThreatLevel(plaintiffRows, legResult, severityRows, naicsIsRelevant) {
    const hasPlaintiff = plaintiffRows.length > 0;
    const hasLegislative = naicsIsRelevant && Object.keys(legResult.byCategory)
      .some(cat => LEGISLATIVE_CATEGORIES_RELEVANT_TO_NAICS.includes(cat));
    const severityValues = severityRows.map(r => parseDollarToMillions(r.dollar_amount)).filter(v => v !== null);
    const maxSeverity = severityValues.length ? Math.max(...severityValues) : null;

    if (!hasPlaintiff && !hasLegislative && maxSeverity === null) {
      return { color: "gray", label: "INSUFFICIENT DATA",
        rec: "No plaintiff, legislative, or severity signal has been collected for this NAICS/state combination yet. This is not a clean bill of health — it means nothing has been found yet, not that nothing exists. Route to manual underwriting review; do not treat the absence of a flag as the presence of safety." };
    }
    if (maxSeverity !== null && maxSeverity >= 1000 && (hasPlaintiff || hasLegislative)) {
      return { color: "red", label: "HIGH THREAT",
        rec: "Recommend: attach an absolute PFAS/chemical exclusion endorsement. Refer to the exposure team for a portfolio accumulation check given an active policy-trigger signal and a severity anchor above $1B." };
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
    return {
      naics, state, defendants, plaintiffRows, legResult, severityRows, threat,
      maxSeverity, velocity, naicsIsRelevant, nextTarget: getDownstreamAdjacency(naics),
      veilPiercing: detectVeilPiercing(defendants), dccProxy: getDccProxy(maxSeverity),
      facilityReports: getFacilityReports(defendants),
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
    get db() { return DB; },
  };
})();
