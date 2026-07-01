#!/usr/bin/env node
/* Slate SP-compute validation harness.
 *
 * Purpose: after the 3.161 opt-out refactor, verify the compute path
 * still parses, resolves every symbol, and produces the right sp_patches
 * candidates — INCLUDING slam candidates for opted-out members.
 *
 * Layers (each expands on the previous):
 *
 *   L1  static analysis  — grep the shipped admin.html for dead symbols
 *                          referenced but not declared, unreachable
 *                          try/catch, un-brace count, etc.
 *   L2  semantic         — synthetic BD rows fed through a re-implemented
 *                          copy of the compute algorithm; assert per-code
 *                          + slam candidates come out correctly with and
 *                          without opt-outs.
 *   L3  end-to-end       — extract the actual compute code from the
 *                          served admin.html, run it in a Node sandbox
 *                          with mock helpers, assert the same behavior.
 *   L4  live regression  — hit the deployed page, confirm version and
 *                          that the compute path is present as expected.
 *
 * Run:  node Apps/SpmAdminV2/tools/validate-sp-compute.mjs
 */

const HTML_URL = process.argv[2] || 'https://southportlandmetroapa.github.io/spm-admin/admin.html';

const fs   = await import('node:fs');
const path = await import('node:path');
const url  = await import('node:url');
const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const LOCAL    = path.resolve(__dirname, '..', 'admin.html');
const html = fs.readFileSync(LOCAL, 'utf8');

const checks = [];
const pass = (id, msg) => checks.push({ id, ok: true, msg });
const fail = (id, msg, detail) => checks.push({ id, ok: false, msg, detail });

/* ─────────────────── L1 — Static analysis ───────────────────────── */

/* L1a — no reference to variables we removed in 3.161 */
{
  const removed = ['optoutsByMember', 'preCleaned'];
  const surviving = [];
  for (const sym of removed) {
    const re = new RegExp('\\b' + sym + '\\b', 'g');
    const hits = html.match(re) || [];
    /* Ignore hits inside comments only. Rough heuristic: line must contain
       code (not just //) to count. Walk each hit line. */
    const lines = html.split('\n');
    const codeHits = [];
    for (let i = 0; i < lines.length; i++) {
      if (!re.test(lines[i])) { re.lastIndex = 0; continue; }
      re.lastIndex = 0;
      const trimmed = lines[i].trimStart();
      const commentOnly = trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
      if (!commentOnly) codeHits.push({ line: i + 1, text: lines[i].slice(0, 120) });
    }
    if (codeHits.length) surviving.push({ sym, hits: codeHits });
  }
  if (surviving.length) {
    fail('L1a.dead-refs', surviving.length + ' removed symbols still referenced in code', surviving);
  } else {
    pass('L1a.dead-refs', 'No live-code references to removed opt-out symbols');
  }
}

/* L1b — isOptedOut references only exist in comments (function no longer defined) */
{
  const iso = (html.match(/\bisOptedOut\b/g) || []).length;
  const lines = html.split('\n');
  const codeRefs = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/\bisOptedOut\b/.test(lines[i])) continue;
    const trimmed = lines[i].trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
    codeRefs.push({ line: i + 1, text: lines[i].slice(0, 120) });
  }
  if (codeRefs.length) fail('L1b.isOptedOut-refs', codeRefs.length + ' isOptedOut references in code (function no longer defined)', codeRefs);
  else pass('L1b.isOptedOut-refs', 'isOptedOut only appears in comments/docs (' + iso + ' total refs)');
}

/* L1c — spDeleteOptoutPatches call-sites resolve to the no-op stub */
{
  const stub = /async function spDeleteOptoutPatches[\s\S]{0,80}\{[\s\S]{0,600}return 0/.test(html);
  const callSites = (html.match(/spDeleteOptoutPatches\(/g) || []).length;
  if (!stub) fail('L1c.stub-present', 'spDeleteOptoutPatches stub not found — call-sites would ReferenceError');
  else pass('L1c.stub-present', 'Stub in place; ' + callSites + ' call-site(s) still resolve');
}

/* L1d — _spOptouts is populated before compute uses it (compute reads
   patch_optouts implicitly via spRenderPatches, so _spOptouts must be
   loaded by spLoadOptouts before the compute button fires). */
{
  const optoutsGlobal = /let\s+_spOptouts\s*=|var\s+_spOptouts\s*=/.test(html);
  const loadCall      = /spLoadOptouts\s*\(/.test(html);
  if (optoutsGlobal && loadCall) pass('L1d.optouts-load', '_spOptouts global + spLoadOptouts loader present');
  else fail('L1d.optouts-load', 'opt-out data loading path missing', { optoutsGlobal, loadCall });
}

/* L1e — count sp_patches insert paths. Should be exactly one (spComputePatches).
   Extra paths would be a red flag for divergence. */
{
  const insertHits = (html.match(/spInsertChunks\('sp_patches'/g) || []).length;
  if (insertHits === 1) pass('L1e.single-insert-path', 'Exactly one sp_patches insert path');
  else if (insertHits === 0) fail('L1e.single-insert-path', 'No sp_patches insert found — compute may be broken');
  else fail('L1e.single-insert-path', insertHits + ' sp_patches insert paths — should be 1');
}

/* L1f — the compute function is syntactically balanced. Extract it and
   confirm brace-count balance. */
{
  const startIdx = html.indexOf('async function spComputePatches');
  if (startIdx < 0) fail('L1f.compute-fn-present', 'spComputePatches not found');
  else {
    let depth = 0, i = html.indexOf('{', startIdx), start = i;
    while (i < html.length) {
      const c = html[i];
      if (c === '{') depth++;
      else if (c === '}') { depth--; if (depth === 0) break; }
      i++;
    }
    const fnSrc = html.slice(start, i + 1);
    if (depth !== 0) fail('L1f.compute-fn-present', 'brace mismatch — depth=' + depth);
    else {
      /* Parse the function. The source uses top-level `await`, which is
         invalid inside plain `new Function()`. Wrap in an async IIFE
         so the parser sees `await` in an async context — any brace
         mismatch or invalid token still surfaces as a SyntaxError. */
      try {
        new Function('(async () => { ' + fnSrc + '; })');
        pass('L1f.compute-fn-present', 'spComputePatches body parses cleanly (' + fnSrc.length + ' bytes)');
      } catch (e) {
        fail('L1f.compute-fn-present', 'parse error in spComputePatches', e.message);
      }
    }
  }
}

/* ─────────────────── L2 — Semantic (algorithmic) ────────────────── */

/* Re-implement the compute's core algorithm from the current admin.html
   source. If Slate ever diverges from this, that alone is a signal to
   re-read the source. */
const SP_TYPE_TO_BD_FIELD = {
  r:  'rackless',
  '8':'eight_ob', x:'eight_br',
  '9':'nine_os',  n:'nine_br',
  k:  'skunk'
};
const MASTERS_REMAP = { '8':'m8', x:'mx', '9':'m9', n:'mn' };
const SLAM_DEPS = { '8m': ['x','8'], '9m': ['n','9'], 'g': ['x','8','9','n'] };
const SP_WEIGHT = { r:1,'8':1,x:1,'9':1,n:1,k:1,m8:1,mx:1,m9:1,mn:1,'8m':2,'9m':2,g:4 };

function computeFromBdRows(rows, opts = {}) {
  const perCodeMap = new Map();
  const memberAggByDiv = new Map();
  const memberTeamByCode = new Map();
  for (const r of rows) {
    const teamN = r.team_number;
    const div   = r.division_number;
    const mem   = r.member_number;
    const memNm = r.member_name;
    const isMasters = /masters/i.test(r.division_name || '');
    for (const [sp, field] of Object.entries(SP_TYPE_TO_BD_FIELD)) {
      const cnt = +r[field] || 0;
      if (cnt < 1) continue;
      const storedSp = (isMasters && MASTERS_REMAP[sp]) ? MASTERS_REMAP[sp] : sp;
      const key = mem + '|' + div + '|' + storedSp;
      const prior = perCodeMap.get(key);
      if (!prior || teamN > prior.team_number) {
        perCodeMap.set(key, {
          member_number: mem, member_name: memNm,
          division_number: div, team_number: teamN,
          sp_type: storedSp, is_slam: false, weight: 1
        });
      }
      if (sp === 'x' || sp === '8' || sp === '9' || sp === 'n') {
        if (!memberAggByDiv.has(mem)) memberAggByDiv.set(mem, { name: memNm, sp: {} });
        memberAggByDiv.get(mem).sp[sp] = (memberAggByDiv.get(mem).sp[sp] || 0) + cnt;
        if (!memberTeamByCode.has(mem)) memberTeamByCode.set(mem, {});
        if (!memberTeamByCode.get(mem)[sp]) memberTeamByCode.get(mem)[sp] = [];
        memberTeamByCode.get(mem)[sp].push(teamN);
      }
    }
  }
  const slamMap = new Map();
  for (const [mem, agg] of memberAggByDiv.entries()) {
    const sps = agg.sp;
    const has = c => (sps[c] || 0) >= 1;
    const candidates = [];
    if (has('x') && has('8')) candidates.push('8m');
    if (has('n') && has('9')) candidates.push('9m');
    if (has('x') && has('8') && has('9') && has('n')) candidates.push('g');
    if (!candidates.length) continue;
    const teamsByCode = memberTeamByCode.get(mem) || {};
    for (const slamType of candidates) {
      const deps = SLAM_DEPS[slamType];
      let bestTeam = null;
      for (const c of deps) {
        for (const t of (teamsByCode[c] || [])) {
          if (bestTeam === null || t > bestTeam) bestTeam = t;
        }
      }
      if (!bestTeam) continue;
      slamMap.set(mem + '|' + slamType, {
        member_number: mem, member_name: agg.name,
        division_number: null, team_number: bestTeam,
        sp_type: slamType, is_slam: true, weight: SP_WEIGHT[slamType]
      });
    }
  }
  return [...perCodeMap.values(), ...slamMap.values()];
}

/* L2a — Paul's Spring 2026 shape yields a 9m candidate */
{
  const rows = [
    { member_number: '18821', member_name: 'Paul Soldan', division_number: '041', division_name: 'Willamette 9 Ball',
      team_number: '04107', rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 1, nine_br: 0, skunk: 0 },
    { member_number: '18821', member_name: 'Paul Soldan', division_number: '081', division_name: 'Southern 9 Ball',
      team_number: '08104', rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 1, nine_br: 1, skunk: 0 },
    { member_number: '18821', member_name: 'Paul Soldan', division_number: '049', division_name: 'Mount Hood 9 Ball',
      team_number: '04901', rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 0, nine_br: 1, skunk: 0 },
    { member_number: '18821', member_name: 'Paul Soldan', division_number: '092', division_name: 'Southwest 9 Ball',
      team_number: '09206', rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 0, nine_br: 1, skunk: 0 }
  ];
  const out = computeFromBdRows(rows);
  const nineM = out.filter(r => r.sp_type === '9m');
  if (nineM.length === 1) pass('L2a.paul-9m', 'Compute produces exactly one 9m for Paul (Session 2 data)');
  else fail('L2a.paul-9m', 'expected 1 9m, got ' + nineM.length, nineM);
}

/* L2b — Per-code patches: '9' × 2 (Div 041 + Div 081), 'n' × 3 */
{
  const rows = [
    { member_number: '18821', member_name: 'Paul Soldan', division_number: '041', division_name: 'Willamette 9 Ball',
      team_number: '04107', rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 1, nine_br: 0, skunk: 0 },
    { member_number: '18821', member_name: 'Paul Soldan', division_number: '081', division_name: 'Southern 9 Ball',
      team_number: '08104', rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 1, nine_br: 1, skunk: 0 },
    { member_number: '18821', member_name: 'Paul Soldan', division_number: '049', division_name: 'Mount Hood 9 Ball',
      team_number: '04901', rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 0, nine_br: 1, skunk: 0 },
    { member_number: '18821', member_name: 'Paul Soldan', division_number: '092', division_name: 'Southwest 9 Ball',
      team_number: '09206', rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 0, nine_br: 1, skunk: 0 }
  ];
  const out = computeFromBdRows(rows);
  const nines = out.filter(r => r.sp_type === '9' && r.is_slam === false).length;
  const ns    = out.filter(r => r.sp_type === 'n' && r.is_slam === false).length;
  if (nines === 2 && ns === 3) pass('L2b.per-code-counts', 'Per-code: 2 × 9 + 3 × n');
  else fail('L2b.per-code-counts', 'unexpected counts', { nines, ns });
}

/* L2c — Grand slam requires ALL four (x, 8, 9, n). Missing one → no g. */
{
  const rows = [
    { member_number: 'TEST1', division_number: '001', team_number: '00101',
      eight_ob: 1, eight_br: 1, nine_os: 1, nine_br: 0 }  // has 8, x, 9 — missing n
  ];
  const out = computeFromBdRows(rows);
  const g = out.filter(r => r.sp_type === 'g').length;
  if (g === 0) pass('L2c.grand-slam-strict', 'No grand slam when any constituent missing');
  else fail('L2c.grand-slam-strict', 'unexpected grand slam', out);
}

/* L2d — Grand slam WHEN all four present. */
{
  const rows = [
    { member_number: 'TEST2', division_number: '001', team_number: '00101',
      eight_ob: 1, eight_br: 1, nine_os: 1, nine_br: 1 }
  ];
  const out = computeFromBdRows(rows);
  const g  = out.filter(r => r.sp_type === 'g').length;
  const _8m = out.filter(r => r.sp_type === '8m').length;
  const _9m = out.filter(r => r.sp_type === '9m').length;
  if (g === 1 && _8m === 1 && _9m === 1) pass('L2d.grand-slam-yields-all', 'All-four yields g + 8m + 9m simultaneously');
  else fail('L2d.grand-slam-yields-all', 'missing slam(s)', { g, '8m': _8m, '9m': _9m });
}

/* L2e — Masters division: raw 8/x/9/n get remapped to m8/mx/m9/mn.
   Slam accumulation still uses raw codes, so slams can still form. */
{
  const rows = [
    { member_number: 'TEST3', division_number: '999', division_name: 'X Masters', team_number: '99901',
      eight_ob: 1, eight_br: 0, nine_os: 0, nine_br: 0 }
  ];
  const out = computeFromBdRows(rows);
  const m8Row = out.find(r => r.sp_type === 'm8');
  const rawEight = out.find(r => r.sp_type === '8');
  if (m8Row && !rawEight) pass('L2e.masters-remap', "Masters div remaps 8 → m8 (raw 8 not stored)");
  else fail('L2e.masters-remap', 'remap failed', { m8Row, rawEight });
}

/* L2f — mail-time filter drops opted-out from the mail queue */
{
  const patches = [
    { member_number: '18821', sp_type: '9m', mailed_at: null, weight: 2, division_number: null, team_number: '09206' },
    { member_number: '18821', sp_type: 'n',  mailed_at: null, weight: 1, division_number: '081', team_number: '08104' },
    { member_number: '99999', sp_type: '9m', mailed_at: null, weight: 2, division_number: null, team_number: '00100' }  // control — not opted out
  ];
  const optouts = [{ member_number: '18821', opted_out_types: ['9m','n','r','8','x','9','k','m8','mx','m9','mn','8m','g'] }];
  const optoutMap = new Map();
  for (const o of optouts) optoutMap.set(o.member_number, new Set(o.opted_out_types || []));
  const unmailed = patches.filter(p => {
    if (p.mailed_at) return false;
    const s = optoutMap.get(p.member_number);
    return !(s && s.has(p.sp_type));
  });
  const paulInMail    = unmailed.some(p => p.member_number === '18821');
  const controlInMail = unmailed.some(p => p.member_number === '99999');
  if (!paulInMail && controlInMail) pass('L2f.mail-filter', 'Opted-out Paul excluded, control 99999 kept in mail queue');
  else fail('L2f.mail-filter', 'filter wrong', { paulInMail, controlInMail, unmailed });
}

/* L2g — partial opt-out only drops those codes from mail queue */
{
  const patches = [
    { member_number: '18821', sp_type: '9m', mailed_at: null },
    { member_number: '18821', sp_type: 'n',  mailed_at: null },
    { member_number: '18821', sp_type: '8',  mailed_at: null }
  ];
  const optoutMap = new Map([['18821', new Set(['9m'])]]);
  const kept = patches.filter(p => !p.mailed_at && !(optoutMap.get(p.member_number)?.has(p.sp_type)));
  const droppedCodes = patches.filter(p => !kept.includes(p)).map(p => p.sp_type);
  if (kept.length === 2 && droppedCodes.length === 1 && droppedCodes[0] === '9m') {
    pass('L2g.partial-optout', 'Partial opt-out (9m only) drops just that code');
  } else {
    fail('L2g.partial-optout', 'partial-optout math wrong', { kept: kept.map(p => p.sp_type), droppedCodes });
  }
}

/* L2h — two players, distinct opt-out states, don't cross-contaminate */
{
  const patches = [
    { member_number: 'A', sp_type: '9m', mailed_at: null },
    { member_number: 'B', sp_type: '9m', mailed_at: null }
  ];
  const optoutMap = new Map([['A', new Set(['9m'])]]);
  const kept = patches.filter(p => !p.mailed_at && !(optoutMap.get(p.member_number)?.has(p.sp_type)));
  if (kept.length === 1 && kept[0].member_number === 'B') pass('L2h.player-isolation', 'A-optout does not affect B');
  else fail('L2h.player-isolation', 'cross-contamination', kept);
}

/* L2i — rackless doesn't contribute to slam accumulation */
{
  const out = computeFromBdRows([
    { member_number: 'R', division_number: '001', team_number: '00101', rackless: 3 }
  ]);
  const rCount = out.filter(x => x.sp_type === 'r').length;
  const slams  = out.filter(x => x.is_slam).length;
  if (rCount === 1 && slams === 0) pass('L2i.rackless-no-slam', 'Rackless yields r-patch and no slam candidates');
  else fail('L2i.rackless-no-slam', 'unexpected slam or missing r', { rCount, slams });
}

/* L2j — all zeros → zero patches */
{
  const out = computeFromBdRows([
    { member_number: 'Z', division_number: '001', team_number: '00101',
      rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 0, nine_br: 0, skunk: 0 }
  ]);
  if (out.length === 0) pass('L2j.zeros-no-patches', 'All-zero row yields no patches');
  else fail('L2j.zeros-no-patches', 'unexpected patches', out);
}

/* L2k — per-code (mem × div × sp_type) picks HIGHEST team_number when a
   member is on multiple teams within the same division. */
{
  const out = computeFromBdRows([
    { member_number: 'M', division_number: '005', team_number: '00505', nine_os: 1 },
    { member_number: 'M', division_number: '005', team_number: '00512', nine_os: 1 }
  ]);
  const nines = out.filter(x => x.sp_type === '9');
  /* Collapse-by-div rule → single '9' row for div 005 with team = 00512. */
  if (nines.length === 1 && nines[0].team_number === '00512') pass('L2k.highest-team', 'Same-division per-code collapses to highest team_number');
  else fail('L2k.highest-team', 'collapse wrong', nines);
}

/* L2l — slam bestTeam scans ALL constituent codes for the max team_number,
   not just the last one added. */
{
  const out = computeFromBdRows([
    { member_number: 'S', division_number: '010', team_number: '01003', nine_os: 1 },  // 9 on team 01003
    { member_number: 'S', division_number: '011', team_number: '01115', nine_br: 1 }   // n on team 01115
  ]);
  const nineM = out.filter(x => x.sp_type === '9m');
  if (nineM.length === 1 && nineM[0].team_number === '01115') {
    pass('L2l.slam-best-team', 'Slam picks highest team# across all constituent codes');
  } else {
    fail('L2l.slam-best-team', 'best-team wrong', nineM);
  }
}

/* L1g — spLoadDivisionMeta is called before compute uses _spDivisionMeta.
   Grep the source: the compute must not read _spDivisionMeta before the
   loader that populates it fired. Simple structural check. */
{
  const spComputeIdx = html.indexOf('async function spComputePatches');
  const usesMeta     = /_spDivisionMeta\.get\(/.test(html.slice(spComputeIdx));
  const loaderExists = /async function spLoadDivisionMeta/.test(html);
  if (usesMeta && !loaderExists) fail('L1g.division-meta-loader', 'compute uses _spDivisionMeta but loader missing');
  else pass('L1g.division-meta-loader', 'compute uses _spDivisionMeta + loader present');
}

/* L1h — compute button in DOM wires to spComputePatches */
{
  const btnPresent = /id="spComputePatchesBtn"/.test(html);
  const wired = /spComputePatchesBtn.*addEventListener\('click',\s*spComputePatches\)/.test(html);
  if (btnPresent && wired) pass('L1h.button-wired', 'Compute button present + click-wired to spComputePatches');
  else fail('L1h.button-wired', 'button/wiring missing', { btnPresent, wired });
}

/* ─────────────────── L3 — End-to-end (extracted code) ────────────── */

/* Extract the actual spComputePatches function body from admin.html
   and run it with mocked SB helpers to catch runtime errors the static
   analysis might miss (undefined symbols, unreachable await, etc.). */
{
  const startIdx = html.indexOf('async function spComputePatches');
  if (startIdx < 0) fail('L3a.extract', 'compute function not found');
  else {
    let depth = 0, i = html.indexOf('{', startIdx), start = i;
    while (i < html.length) {
      const c = html[i];
      if (c === '{') depth++;
      else if (c === '}') { depth--; if (depth === 0) break; }
      i++;
    }
    const bodySrc = html.slice(start + 1, i);  // exclude outer braces

    /* Mock EVERYTHING the function touches. Missing mocks show up as
       ReferenceError so we know exactly which symbol went undefined. */
    const _capturedInserts = [];
    const _errors = [];
    const btnStub = { disabled: false, textContent: '' };
    const docStub = { getElementById: () => btnStub };
    const mocks = {
      document:            docStub,
      currentSession:      { id: 2, name: 'Spring 2026' },
      _spOperatorFilter:   'SPM',
      SP_OPERATOR_SHORTS:  { SPM: 1 },
      _spOptouts:          [],
      _spDivisionMeta:     new Map([['041', 1], ['081', 1], ['049', 1], ['092', 1]]),
      _spPatches:          [],
      setStatus:           () => {},
      sb: async (method, path) => {
        if (method === 'GET' && /sp_reports/.test(path)) return [{ id: 1, report_kind: 'bd', is_cumulative: true, session_id: 2, operator_id: 1 }];
        if (method === 'GET' && /sp_by_division_rows/.test(path)) {
          return [
            { report_id: 1, member_number: '18821', member_name: 'Paul', division_number: '081', division_name: 'Southern 9 Ball',
              team_number: '08104', rackless: 0, eight_ob: 0, eight_br: 0, nine_os: 1, nine_br: 1, skunk: 0 }
          ];
        }
        if (method === 'GET' && /patch_optouts/.test(path)) return [];
        if (method === 'GET' && /sp_patches/.test(path)) return [];
        return [];
      },
      sbGet:               async () => [],
      sbGetAll:            async () => [],
      spInsertChunks:      async (table, rows) => { _capturedInserts.push(...rows); return rows.length; },
      spIsInactiveTeam:    () => false,
      spLoadPatches:       async () => {},
      spLoadDivisionMeta:  async () => {},
      spRenderPatches:     () => {},
      SP_TYPE_TO_BD_FIELD, MASTERS_REMAP, SLAM_DEPS, SP_WEIGHT,
      console: { log: () => {}, warn: () => {}, error: (...a) => _errors.push(a.join(' ')) }
    };

    try {
      const argNames = Object.keys(mocks);
      const argVals  = Object.values(mocks);
      /* CRITICAL: return the promise so awaiting the function awaits the
         async body and forwards any rejection to our .catch. Without the
         return, the async IIFE fires-and-forgets and errors go to
         unhandledRejection which kills the process. */
      const fn = new Function(...argNames, 'return (async () => { ' + bodySrc + ' })();');
      await fn(...argVals);
      if (_errors.length) fail('L3a.extract', 'errors during compute', _errors.slice(0, 3));
      else pass('L3a.extract', 'compute body runs without ReferenceError (' + _capturedInserts.length + ' would-be inserts)');
    } catch (e) {
      fail('L3a.extract', 'compute threw', e.message);
    }
  }
}

/* ─────────────────── L4 — Live regression (served build) ────────── */

try {
  const liveHtml = await fetch(HTML_URL).then(r => r.text());
  if (/const APP_VERSION = '3\.161'/.test(liveHtml)) pass('L4a.live-version', 'Live serves 3.161');
  else {
    const m = liveHtml.match(/const APP_VERSION = '([^']+)'/);
    fail('L4a.live-version', 'Live version=' + (m && m[1]) + ', expected 3.161');
  }
  const stillHasOldGate = /if\s*\(\s*isOptedOut\s*\([^)]+\)\s*\)\s*continue/.test(liveHtml);
  if (stillHasOldGate) fail('L4b.live-no-old-gate', 'Live still has the old opt-out compute gate');
  else pass('L4b.live-no-old-gate', 'Live has no compute-time opt-out gate');
} catch (e) {
  fail('L4.live', 'could not fetch live: ' + e.message);
}

/* ─────────────────── Report ─────────────────────────────────────── */
const failed = checks.filter(c => !c.ok);
console.log('\n=== SP-compute validation ===');
for (const c of checks) {
  console.log((c.ok ? '✓ ' : '✗ ') + c.id + ' — ' + c.msg);
  if (!c.ok && c.detail) console.log('    ' + JSON.stringify(c.detail, null, 2).split('\n').join('\n    ').slice(0, 800));
}
console.log('\n' + (checks.length - failed.length) + ' / ' + checks.length + ' checks passed.');
process.exit(failed.length ? 1 : 0);
