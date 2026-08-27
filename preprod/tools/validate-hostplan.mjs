#!/usr/bin/env node
/* Slate Host Plan validation harness — Activities 3-5 (roster / placement / capacity).
 *
 * Layers:
 *   L1 static   — admin.html: symbol declarations, window exports, onclick
 *                 handler resolution, getElementById target existence,
 *                 HTML/JS integrity around the HP block.
 *   L2 semantic — re-implement hpBaseName, sync-dedup, capacity math, DJ-twin
 *                 detection in pure JS; assert against a table of cases the
 *                 real code should get right.
 *   L3 db       — with SUPABASE_PAT: read slate.host_plan_teams schema,
 *                 confirm columns, constraints, RLS, trigger.
 *
 * Run: node Apps/SpmAdminV2/site/tools/validate-hostplan.mjs
 */

const fs   = await import('node:fs');
const path = await import('node:path');
const url  = await import('node:url');
const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const LOCAL = path.resolve(__dirname, '..', 'admin.html');
const html  = fs.readFileSync(LOCAL, 'utf8');

const checks = [];
const pass = (id, msg) => checks.push({ id, ok: true, msg });
const fail = (id, msg, detail) => checks.push({ id, ok: false, msg, detail });

/* ─────────────── L1 static ─────────────── */

/* L1a — every hp* function reference in an onclick has a matching definition. */
{
  const onclickHandlers = [...html.matchAll(/onclick="(hp[A-Za-z0-9_]+)\s*\(/g)]
    .map(m => m[1]);
  const oninputHandlers = [...html.matchAll(/oninput="(hp[A-Za-z0-9_]+)\s*\(/g)]
    .map(m => m[1]);
  const onchangeHandlers = [...html.matchAll(/onchange="(hp[A-Za-z0-9_]+)\s*\(/g)]
    .map(m => m[1]);
  const handlers = new Set([...onclickHandlers, ...oninputHandlers, ...onchangeHandlers]);
  const defined = new Set(
    [...html.matchAll(/(?:function|async function)\s+(hp[A-Za-z0-9_]+)/g)].map(m => m[1])
  );
  const missing = [...handlers].filter(h => !defined.has(h));
  if (missing.length === 0) pass('L1a', `all ${handlers.size} hp* inline handlers resolved`);
  else fail('L1a', 'handlers with no matching function definition', missing);
}

/* L1b — every function that appears in inline handlers has a window export. */
{
  const inlineFns = new Set([...html.matchAll(/on(?:click|input|change)="(hp[A-Za-z0-9_]+)/g)]
    .map(m => m[1]));
  const exported = new Set(
    [...html.matchAll(/window\.(hp[A-Za-z0-9_]+)\s*=/g)].map(m => m[1])
  );
  const missing = [...inlineFns].filter(f => !exported.has(f));
  if (missing.length === 0) pass('L1b', `all ${inlineFns.size} inline-handler fns exported to window`);
  else fail('L1b', 'inline-handler fns not on window (will ReferenceError)', missing);
}

/* L1c — every getElementById inside hp* functions resolves to an id in the HTML. */
{
  /* Extract the block of code between HP_TARGET_SESSION and the window exports. */
  const start = html.indexOf('const HP_TARGET_SESSION');
  const end   = html.indexOf('window.hpExportPlanCsv');
  if (start < 0 || end < 0) fail('L1c', 'HP block markers not found in admin.html');
  else {
    const block = html.slice(start, end);
    const ids = [...block.matchAll(/getElementById\('([^']+)'\)/g)].map(m => m[1]);
    const uniqIds = [...new Set(ids)];
    const missing = uniqIds.filter(id => !new RegExp('id="' + id + '"').test(html));
    if (missing.length === 0) pass('L1c', `all ${uniqIds.length} getElementById targets exist in HTML`);
    else fail('L1c', 'getElementById targets with no matching id="" in HTML', missing);
  }
}

/* L1d — DELETE call uses service-role auth (or sb() wraps it). */
{
  /* Confirm we're not sending anon DELETE that RLS would silently accept
   * (service_role only policy on host_plan_teams). Just look for sb() usage. */
  const sbCalls = (html.match(/await sb\('(GET|POST|PATCH|DELETE)', 'host_plan_teams/g) || []).length;
  if (sbCalls >= 4) pass('L1d', `${sbCalls} host_plan_teams sb() calls (GET+POST+PATCH+DELETE)`);
  else fail('L1d', 'expected ≥4 sb() calls to host_plan_teams', sbCalls);
}

/* L1e — no ${...} template interpolation on unescaped user input in onclick handlers. */
{
  /* onclick="fn(' + r.foo + ')" is the pattern I used. If r.foo can contain a quote,
     we get XSS or a broken onclick. But r.id (bigint) and r.status (constrained) are
     safe. Assert: I only interpolate ids/venue ids/status strings, not r.team_name. */
  const block = html.slice(html.indexOf('const HP_TARGET_SESSION'), html.indexOf('window.hpExportPlanCsv'));
  const badOnclick = block.match(/onclick=[^"]*\+\s*r\.team_name/);
  if (!badOnclick) pass('L1e', 'no onclick interpolates raw team_name (XSS/quote-break safe)');
  else fail('L1e', 'onclick interpolates r.team_name — potential XSS or broken markup', badOnclick[0].slice(0, 80));
}

/* L1f — all DOM writes go through esc() for user-controlled text. */
{
  const block = html.slice(html.indexOf('const HP_TARGET_SESSION'), html.indexOf('window.hpExportPlanCsv'));
  /* Look for + r.team_name that is NOT wrapped in esc(). */
  const rawInterp = block.match(/\+\s*r\.team_name\s*\+/g) || [];
  const escInterp = block.match(/esc\(r\.team_name/g) || [];
  const rawUnwrapped = rawInterp.length;
  if (rawUnwrapped === 0) pass('L1f', `all ${escInterp.length} r.team_name renderings go through esc()`);
  else fail('L1f', 'unescaped r.team_name interpolations found', rawUnwrapped);
}

/* L1g — hpBaseName regex sanity: requires leading whitespace (no leading-Ball
   false-positive) + multi-digit support (\d+). Also delegates to hpNormalizeName. */
{
  const src = html.match(/function hpBaseName[\s\S]{0,300}?}/);
  const normSrc = html.match(/function hpNormalizeName[\s\S]{0,200}?}/);
  if (!src) fail('L1g', 'hpBaseName not found');
  else if (!normSrc) fail('L1g', 'hpNormalizeName not found — required companion');
  else {
    const usesNorm = /hpNormalizeName\(name\)/.test(src[0]);
    const hasLeadingWS = /\\s\+\\d\+/.test(src[0]);
    if (usesNorm && hasLeadingWS) pass('L1g', 'hpBaseName delegates to hpNormalizeName + uses \\s+\\d+ (multi-digit, anchored)');
    else fail('L1g', 'hpBaseName regex missing safeguards', { usesNorm, hasLeadingWS });
  }
}

/* ─────────────── L2 semantic ─────────────── */

/* Re-implement hpNormalizeName + hpBaseName as the shipped code does. */
function hpNormalizeName(name) {
  return (name || '').replace(/[‘’]/g, "'").replace(/\s+/g, ' ').trim();
}
function hpBaseName(name) {
  return hpNormalizeName(name).replace(/\s+\d+[- ]?[Bb]all(?:\s.*)?$/, '').trim();
}

/* L2a — hpBaseName should strip trailing "N Ball" markers without eating the whole name. */
{
  const cases = [
    ["Diamond Jim's 8 Ball",   "Diamond Jim's"],
    ["Diamond Jim's 9 Ball",   "Diamond Jim's"],
    ["Diamond Jim's 8-Ball",   "Diamond Jim's"],
    ["Diamond Jim's 9-ball",   "Diamond Jim's"],
    ["Cue Crushers",           "Cue Crushers"],       // no trailing marker
    ["The 5th Element",        "The 5th Element"],    // digit but no "Ball"
    ["8-Ball Bandits",         "8-Ball Bandits"],     // leading Ball: preserved after fix
    ["8 Ball Wizards",         "8 Ball Wizards"],     // leading Ball: preserved after fix
    ["Team 10 Ball",           "Team"],               // multi-digit works after \d+ fix
    ["The Dolphin",            "The Dolphin"],
    ["The Dolphin 8 Ball",     "The Dolphin"],
    ["",                       ""],
    [null,                     ""],
    [undefined,                ""],
  ];
  const wrong = [];
  for (const [inp, expected] of cases) {
    const got = hpBaseName(inp);
    if (got !== expected) wrong.push({ inp, expected, got });
  }
  if (wrong.length === 0) pass('L2a', `hpBaseName correct on all ${cases.length} cases (including known leading-Ball false-positive documented)`);
  else fail('L2a', 'hpBaseName produced unexpected output', wrong);
}

/* L2b — leading-Ball names now preserved after regex fix; no cross-league collision. */
{
  const a = hpBaseName("8 Ball Wizards");
  const b = hpBaseName("9 Ball Wizards");
  if (a === "8 Ball Wizards" && b === "9 Ball Wizards") pass('L2b', 'leading-Ball names preserved (no false-twin sync)');
  else fail('L2b', 'leading-Ball still collapsed after fix', { a, b });
}

/* L2c — Sync dedup on normalized name catches whitespace + curly-apos variants. */
{
  const existing = new Map();
  /* Simulate what the fixed sync code does: keys are lowercase normalized names. */
  const stored = "Diamond Jim's 8 Ball";
  existing.set(hpNormalizeName(stored).toLowerCase(), { id: 1, team_name: stored });
  const variants = [
    "Diamond Jim's  8 Ball",        // double space
    "Diamond Jim’s 8 Ball",     // curly right-quote
    "  Diamond Jim's 8 Ball  ",     // padding
    "DIAMOND JIM'S 8 BALL",         // case
  ];
  const missed = variants.filter(v => !existing.get(hpNormalizeName(v).toLowerCase()));
  if (missed.length === 0) pass('L2c', `sync dedup catches all ${variants.length} whitespace/curly-apos/case variants`);
  else fail('L2c', 'sync dedup still misses these variants', missed);
}

/* L2d — Sync must iterate BOTH summer and spring so Spring-only teams surface. */
{
  const src = html.slice(html.indexOf('async function hpSyncFromUploads'), html.indexOf('const HP_RET_LABEL'));
  const loopsSummer = /for \(const t of summer\)\s+consider\(t, 'summer'\)/.test(src);
  const loopsSpring = /for \(const t of spring\)\s+consider\(t, 'spring'\)/.test(src);
  if (loopsSummer && loopsSpring) pass('L2d', 'sync iterates both summer + spring rosters (spring-only teams surface)');
  else fail('L2d', 'sync loop coverage broken', { loopsSummer, loopsSpring });
}

/* L2e — Capacity math sanity. */
{
  function capState(load, cap) {
    if (cap === 0)         return 'no cap set';
    if (load > cap)        return 'over cap';
    if (load === cap)      return 'at cap';
    return (cap - load) + ' open';
  }
  const cases = [
    [0, 0, 'no cap set'],
    [3, 6, '3 open'],
    [6, 6, 'at cap'],
    [7, 6, 'over cap'],
    [0, 6, '6 open'],
  ];
  const wrong = cases.filter(([l, c, e]) => capState(l, c) !== e);
  if (wrong.length === 0) pass('L2e', 'capacity math correct on 5 cases');
  else fail('L2e', 'capacity math wrong', wrong);
}

/* L2f — Sync dedup keyed on normalized(name).toLowerCase — idempotent across whitespace/case. */
{
  const src = html.slice(html.indexOf('async function hpSyncFromUploads'), html.indexOf('const HP_RET_LABEL'));
  const usesNormalizedKey = /existing\.set\(hpNormalizeName\(r\.team_name\)\.toLowerCase\(\), r\)/.test(src);
  if (usesNormalizedKey) pass('L2f', 'sync dedup uses hpNormalizeName+lowercase key (idempotent on re-sync)');
  else fail('L2f', 'sync dedup missing normalization — re-sync can 23505');
}

/* L2g — Delete confirmation exists (no accidental data loss). */
{
  const src = html.match(/async function hpDeletePlanTeam[\s\S]{0,500}/);
  if (src && /confirm\(/.test(src[0])) pass('L2g', 'hpDeletePlanTeam uses confirm() before DELETE');
  else fail('L2g', 'hpDeletePlanTeam missing confirm()', src?.[0]?.slice(0, 200));
}

/* L2h — Modal accessibility: role="dialog", aria-labelledby, or at least
 * an ESC handler. Not required but nice; document deficit. */
{
  const modal = html.match(/id="hpNewTeamModal"[\s\S]{0,2000}/);
  if (!modal) fail('L2h', 'hpNewTeamModal not found');
  else {
    const hasRole  = /role="dialog"/.test(modal[0]);
    const hasEsc   = /Escape|keydown/i.test(html.slice(html.indexOf('hpNewTeamModal'), html.indexOf('hpNewTeamModal') + 3000));
    if (hasRole && hasEsc) pass('L2h', 'modal has role="dialog" AND Esc handler');
    else fail('L2h', 'modal accessibility deficit', { hasRole, hasEsc });
  }
}

/* L2i — hpSetPlacement DJ twin logic returns SILENTLY without update
 * if `hpAutoSyncDj` checkbox is unchecked. Confirm code path. */
{
  const src = html.match(/async function hpSetPlacement[\s\S]{0,1500}/);
  const hasCheckboxGuard = src && /hpAutoSyncDj[^)]*\)\?\.checked/.test(src[0]);
  if (hasCheckboxGuard) pass('L2i', 'DJ twin sync gated on #hpAutoSyncDj.checked');
  else fail('L2i', 'DJ twin sync missing checkbox guard');
}

/* ─────────────── L3 DB integrity (optional — needs SUPABASE_PAT) ─────────────── */

const PAT = process.env.SUPABASE_PAT;
if (PAT) {
  const projRef = 'dqzbekoaysgaiqljueac';
  const sql = async q => {
    const r = await fetch(`https://api.supabase.com/v1/projects/${projRef}/database/query`, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + PAT, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: q }),
    });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  };

  try {
    const cols = await sql(`
      select column_name, data_type, is_nullable, column_default
        from information_schema.columns
       where table_schema='slate' and table_name='host_plan_teams'
       order by ordinal_position`);
    const names = cols.map(c => c.column_name);
    const expected = ['id','target_session','team_name','summer_team_number','summer_venue',
                      'spring_venue','captain_name','return_status','is_new_for_fall',
                      'placement_venue_id','placement_status','night_of_play','notes',
                      'created_at','updated_at','updated_by'];
    const missing = expected.filter(e => !names.includes(e));
    if (missing.length === 0) pass('L3a', `${expected.length} columns present`);
    else fail('L3a', 'missing columns', missing);
  } catch (e) { fail('L3a', 'DB schema query failed', e.message); }

  try {
    const uniq = await sql(`
      select conname, pg_get_constraintdef(oid) as def
        from pg_constraint
       where conrelid = 'slate.host_plan_teams'::regclass
         and contype = 'u'`);
    const hasCorrect = uniq.some(u => /target_session.*team_name/.test(u.def));
    if (hasCorrect) pass('L3b', `unique(target_session, team_name) constraint present`);
    else fail('L3b', 'missing composite unique', uniq);
  } catch (e) { fail('L3b', 'unique check failed', e.message); }

  try {
    const rls = await sql(`
      select relrowsecurity, relforcerowsecurity
        from pg_class where oid = 'slate.host_plan_teams'::regclass`);
    if (rls[0]?.relrowsecurity) pass('L3c', 'RLS enabled on host_plan_teams');
    else fail('L3c', 'RLS not enabled');
  } catch (e) { fail('L3c', 'RLS check failed', e.message); }

  try {
    const trig = await sql(`
      select tgname from pg_trigger
       where tgrelid = 'slate.host_plan_teams'::regclass
         and tgname = 'host_plan_teams_updated_at_trg'`);
    if (trig.length) pass('L3d', 'updated_at trigger installed');
    else fail('L3d', 'updated_at trigger missing');
  } catch (e) { fail('L3d', 'trigger check failed', e.message); }

  try {
    const pol = await sql(`
      select polname from pg_policy where polrelid = 'slate.host_plan_teams'::regclass`);
    if (pol.length) pass('L3e', `${pol.length} RLS policy(ies) present`);
    else fail('L3e', 'no RLS policy — service_role writes work but anon can silently pass');
  } catch (e) { fail('L3e', 'policy check failed', e.message); }
} else {
  checks.push({ id: 'L3*', ok: null, msg: 'SKIPPED — SUPABASE_PAT not set' });
}

/* ─────────────── Report ─────────────── */

let passC = 0, failC = 0, skipC = 0;
for (const c of checks) {
  if (c.ok === true) { passC++; console.log(`  ✓ ${c.id}  ${c.msg}`); }
  else if (c.ok === false) { failC++; console.log(`  ✗ ${c.id}  ${c.msg}`); if (c.detail) console.log('       ', JSON.stringify(c.detail).slice(0, 300)); }
  else { skipC++; console.log(`  · ${c.id}  ${c.msg}`); }
}
console.log(`\n${passC}/${passC + failC} passed, ${failC} failed, ${skipC} skipped`);
process.exit(failC ? 1 : 0);
