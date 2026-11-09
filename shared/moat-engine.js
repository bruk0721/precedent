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

  function getDownstreamAdjacency(naics) {
    return (DB.downstream_adjacency || {})[naics] || [];
  }

  function isDownstreamTarget(naics) {
    const adj = DB.downstream_adjacency || {};
    return Object.values(adj).some(list => list.some(a => a.naics === naics));
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
    getDownstreamAdjacency, normalizeForMatch, US_BORDERS, STATE_NAMES,
    get db() { return DB; },
  };
})();
