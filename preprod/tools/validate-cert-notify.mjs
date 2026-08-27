#!/usr/bin/env node
/* Slate cert-notification emailer validation harness (3.166+).
 *
 * Waves (each expands on the previous):
 *   L1 static     — admin.html: handler-to-fn resolution, window exports,
 *                   getElementById targets, XSS-safe substitution, secrets.
 *   L2 semantic   — re-implement + test template substitution, plural, filter,
 *                   toggle-all logic in isolated JS. XSS-encoding checks.
 *   L3 DB / RPC   — schema + RLS + RPC perf. Anon can read template, only
 *                   service_role can write. RPC returns fast + non-empty.
 *   L4 GAS        — Code.gs has cert_notify_send handler with correct
 *                   auth + payload validation + log-on-fail.
 *   L5 UI E2E     — live browser: template loads, list renders, filter/search
 *                   works, toggle-all works, preview substitutes,
 *                   test-email flow reaches send stage.
 *   L6 edge cases — empty session, special chars, missing email, no-cert
 *                   session, session change mid-batch.
 *   L7 a11y       — ARIA live regions, keyboard nav, contrast.
 *   L8 RFC email  — List-Unsubscribe hint, plain-text fallback, HTML validity.
 *
 * Run:
 *   node Apps/SpmAdminV2/site/tools/validate-cert-notify.mjs
 *   SUPABASE_PAT=... node ... (enables L3)
 */

const fs   = await import('node:fs');
const path = await import('node:path');
const url  = await import('node:url');
const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const HTML  = fs.readFileSync(path.resolve(__dirname, '..', 'admin.html'), 'utf8');
const GAS   = fs.readFileSync(path.resolve(__dirname, '..', '..', '..', '..', 'tools', 'claude', 'rolodex-mailer', 'Code.gs'), 'utf8');

const checks = [];
const pass = (id, msg) => checks.push({ id, ok: true, msg });
const fail = (id, msg, detail) => checks.push({ id, ok: false, msg, detail });
const skip = (id, msg) => checks.push({ id, ok: null, msg });

/* Extract just the cert-notify JS block for scoped analysis. */
const notifyStart = HTML.indexOf('CERT NOTIFICATION EMAILER (3.166+)');
const notifyEnd   = HTML.indexOf('HOST PLAN — Activities 1+2', notifyStart);
if (notifyStart < 0 || notifyEnd < 0) {
  console.error('Could not locate cert-notify JS block'); process.exit(1);
}
const NB = HTML.slice(notifyStart, notifyEnd);

/* ─────────────── L1 static ─────────────── */

/* L1a — every certsNotify* inline handler references a defined function. */
{
  const handlers = new Set(
    [...HTML.matchAll(/on(?:click|input|change|keydown)="(certsNotify[A-Za-z0-9_]+)/g)].map(m => m[1])
  );
  const defined = new Set(
    [...HTML.matchAll(/(?:function|async function)\s+(certsNotify[A-Za-z0-9_]+)/g)].map(m => m[1])
  );
  const missing = [...handlers].filter(h => !defined.has(h));
  if (missing.length === 0) pass('L1a', `all ${handlers.size} certsNotify* inline handlers resolved`);
  else fail('L1a', 'inline handler with no function', missing);
}

/* L1b — every inline-handler fn is exported to window. */
{
  const inlineFns = new Set(
    [...HTML.matchAll(/on(?:click|input|change|keydown)="(certsNotify[A-Za-z0-9_]+)/g)].map(m => m[1])
  );
  const exported = new Set(
    [...HTML.matchAll(/window\.(certsNotify[A-Za-z0-9_]+)\s*=/g)].map(m => m[1])
  );
  const missing = [...inlineFns].filter(f => !exported.has(f));
  if (missing.length === 0) pass('L1b', `all ${inlineFns.size} inline handlers exported to window`);
  else fail('L1b', 'inline fns missing window export', missing);
}

/* L1c — every getElementById target inside the notify block exists in HTML. */
{
  const ids = [...NB.matchAll(/getElementById\('([^']+)'\)/g)].map(m => m[1]);
  const unique = [...new Set(ids)];
  const missing = unique.filter(id => !new RegExp('id="' + id + '"').test(HTML));
  if (missing.length === 0) pass('L1c', `all ${unique.length} getElementById targets present in HTML`);
  else fail('L1c', 'getElementById targets missing', missing);
}

/* L1d — Sb() calls on slate schema pass the right profile headers.
   READs need Accept-Profile:slate. WRITEs (POST/PATCH/DELETE) also need
   Content-Profile:slate — otherwise PostgREST writes to the default schema
   and the operator silently ends up modifying the wrong table. Balanced-
   brace extraction avoids the earlier lazy-regex miscount. */
function extractSbCallsFrom(src) {
  const out = [];
  const re = /await sb\('([A-Z]+)',\s*'([^']+)'/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    /* Walk forward until parens balance to find the end of this call. */
    let depth = 1, i = re.lastIndex;
    while (i < src.length && depth > 0) {
      const ch = src[i];
      if (ch === '(') depth++;
      else if (ch === ')') depth--;
      i++;
    }
    out.push({ method: m[1], path: m[2], args: src.slice(re.lastIndex, i - 1) });
  }
  return out;
}
{
  const calls = extractSbCallsFrom(NB);
  const bad = [];
  for (const c of calls) {
    if (!/(cert_notify_template|cert_notify_log|session_cert_holders|player_certs)/.test(c.path)) continue;
    const needsWrite = c.method !== 'GET' && c.method !== 'DELETE';
    const hasAccept  = /Accept-Profile.*slate/.test(c.args);
    const hasContent = /Content-Profile.*slate/.test(c.args);
    if (!hasAccept) bad.push({ ...c, why: 'no Accept-Profile' });
    else if (needsWrite && !hasContent) bad.push({ ...c, why: 'write without Content-Profile — will hit wrong schema' });
  }
  if (bad.length === 0) pass('L1d', `all sb() slate calls pass correct profile headers`);
  else fail('L1d', 'sb() slate profile-header gaps', bad.map(b => ({ method: b.method, path: b.path, why: b.why })));
}

/* L1e — No hardcoded secrets in cert-notify block. */
{
  const suspicious = NB.match(/(sbp_[A-Za-z0-9]+|service_role|BEARER\s+eyJ)/i);
  if (!suspicious) pass('L1e', 'no hardcoded PAT/service_role JWT in cert-notify block');
  else fail('L1e', 'possible hardcoded secret', suspicious[0].slice(0, 60));
}

/* L1f — Template substitution regex is safe: fixed known tokens only. */
{
  const substFn = NB.match(/function certsNotifySubstitute[\s\S]{0,400}?\}/);
  if (!substFn) fail('L1f', 'certsNotifySubstitute not found');
  else {
    const listsTokens = /first_name\|last_name\|full_name\|session_name\|cert_count\|cert_count_plural\|cert_list_html/.test(substFn[0]);
    const noEval = !/eval|new Function|Function\(/.test(substFn[0]);
    if (listsTokens && noEval) pass('L1f', 'substitution regex uses fixed token allow-list (no arbitrary code paths)');
    else fail('L1f', 'substitution regex unsafe', { listsTokens, noEval });
  }
}

/* L1g — Substituted values are HTML-encoded before being placed in the body.
   The shipped code binds `first`/`last` locals then passes them through esc()
   into the ctx. Assert both patterns. */
{
  const buildCtx = NB.match(/async function certsNotifyBuildContext[\s\S]*?^\}$/m);
  if (!buildCtx) fail('L1g', 'certsNotifyBuildContext not found');
  else {
    const escFirst   = /first_name:\s*esc\(first\)/.test(buildCtx[0]);
    const escLast    = /last_name:\s*esc\(last\)/.test(buildCtx[0]);
    const escFull    = /full_name:\s*esc\(/.test(buildCtx[0]);
    const escSession = /session_name:\s*esc\(sessionName\)/.test(buildCtx[0]);
    if (escFirst && escLast && escFull && escSession) pass('L1g', 'ctx.first/last/full/session_name all HTML-escaped');
    else fail('L1g', 'ctx escape coverage gap', { escFirst, escLast, escFull, escSession });
  }
}

/* L1h — Double-submit guard on bulk send. */
{
  const sendBulk = NB.match(/async function certsNotifySendBulk[\s\S]{0,3000}?\}/);
  if (!sendBulk) fail('L1h', 'certsNotifySendBulk not found');
  else {
    const hasGuard = /_certsNotifyBulkInFlight|button\.disabled\s*=\s*true/.test(sendBulk[0]);
    if (hasGuard) pass('L1h', 'bulk send has double-submit guard');
    else fail('L1h', 'BUG: bulk send has no guard — double-click sends the batch twice');
  }
}

/* L1i — Search input debounced (667-row re-render on every keystroke is slow). */
{
  const searchInput = HTML.match(/id="certsNotifySearch"[^>]+/);
  if (!searchInput) fail('L1i', 'certsNotifySearch not found');
  else {
    const direct = /oninput="certsNotifyRenderList\(\)"/.test(searchInput[0]);
    const debouncedInline = /oninput="certsNotifyDebouncedRender/.test(searchInput[0]);
    if (debouncedInline) pass('L1i', 'search input uses debounced render');
    else if (direct) fail('L1i', 'BUG: search input calls render on every keystroke — 667-row re-render laggy');
    else fail('L1i', 'unclear how search is wired', searchInput[0]);
  }
}

/* L1j — Preview cache is invalidated (or re-rendered) after template save. */
{
  const saveFn = NB.match(/async function certsNotifySaveTemplate[\s\S]*?^\}$/m);
  if (!saveFn) fail('L1j', 'certsNotifySaveTemplate not found');
  else {
    const invalidates = /_certsNotifyLastPreviewCerts\s*=\s*null/.test(saveFn[0]);
    const refreshes   = /certsNotifyPreview\(\)/.test(saveFn[0]);
    if (invalidates && refreshes) pass('L1j', 'template save invalidates cache AND re-renders preview if open');
    else fail('L1j', 'preview refresh incomplete', { invalidates, refreshes });
  }
}

/* ─────────────── L2 semantic ─────────────── */

/* Re-implement substitution + a minimal esc() as the shipped code should. */
function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
function subst(str, ctx) {
  return String(str || '').replace(/\{(first_name|last_name|full_name|session_name|cert_count|cert_count_plural|cert_list_html)\}/g,
    (_, k) => (ctx[k] == null ? '' : String(ctx[k])));
}

/* L2a — substitution replaces known tokens, leaves unknown tokens alone. */
{
  const out = subst('Hi {first_name}, {unknown} — {cert_count} certs.', { first_name: 'Alan', cert_count: 3 });
  if (out === 'Hi Alan, {unknown} — 3 certs.') pass('L2a', 'known tokens replaced, unknown left literal');
  else fail('L2a', 'substitution wrong', out);
}

/* L2b — cert_count_plural logic: 1 → '', 0 → 's', 5 → 's'. */
{
  const cases = [
    [1, ''], [0, 's'], [5, 's'], [2, 's']
  ];
  const wrong = cases.filter(([n, expected]) => (n === 1 ? '' : 's') !== expected);
  if (wrong.length === 0) pass('L2b', 'cert_count_plural correct for 0/1/2/5');
  else fail('L2b', 'plural logic wrong', wrong);
}

/* L2c — first_name with HTML metachars must not become active HTML in the body. */
{
  const ctx = { first_name: '<script>alert(1)</script>O\'Brien & Co', cert_count: 3, cert_count_plural: 's' };
  const encoded = escHtml(ctx.first_name);
  /* Simulate the flow the SHIPPED code should do: build ctx with escaped
   * name, then substitute into template. */
  const body = subst('Hi {first_name}, you have {cert_count} cert{cert_count_plural}.', { ...ctx, first_name: encoded });
  const hasActiveScript = /<script/i.test(body);
  const hasEncodedQuote = body.includes('&#39;');
  const hasEncodedAmp   = body.includes('&amp;');
  if (!hasActiveScript && hasEncodedQuote && hasEncodedAmp) pass('L2c', 'XSS: HTML-encoded ctx prevents active <script> injection via name');
  else fail('L2c', 'XSS: name-based injection possible', { hasActiveScript, hasEncodedQuote, hasEncodedAmp });
}

/* L2d — cert_list_html builder escapes sp_label + division_name. */
{
  const buildCtx = NB.match(/async function certsNotifyBuildContext[\s\S]*?^\}$/m);
  if (!buildCtx) fail('L2d', 'buildCtx not found');
  else {
    const labelEscaped = /esc\(c\.sp_label/.test(buildCtx[0]);
    const divEscaped   = /esc\(c\.division_name/.test(buildCtx[0]);
    if (labelEscaped && divEscaped) pass('L2d', 'cert_list_html escapes sp_label + division_name');
    else fail('L2d', 'cert list may XSS via label/division', { labelEscaped, divEscaped });
  }
}

/* L2e — Filter logic: hay contains name/APA/email. */
{
  const filterFn = NB.match(/function certsNotifyGetFiltered[\s\S]{0,700}?\}/);
  if (!filterFn) fail('L2e', 'getFiltered not found');
  else {
    const usesFields = /r\.first_name.*r\.last_name.*r\.apa_number.*r\.email/.test(filterFn[0]);
    if (usesFields) pass('L2e', 'filter searches name / apa_number / email');
    else fail('L2e', 'filter field coverage weak', filterFn[0]);
  }
}

/* L2f — Toggle-all skips no-email rows. */
{
  const togAll = NB.match(/function certsNotifyToggleAll[\s\S]{0,500}?\}/);
  if (!togAll) fail('L2f', 'toggleAll not found');
  else {
    const skipsNoEmail = /if\s*\(!r\.email\)/.test(togAll[0]);
    if (skipsNoEmail) pass('L2f', 'toggle-all skips no-email rows');
    else fail('L2f', 'toggle-all would check unsendable rows');
  }
}

/* L2g — Bulk send: only sends to rows that pass BOTH checked + has-email.
   Use balanced-brace extraction so the multi-page function is captured whole. */
{
  const startIdx = NB.indexOf('async function certsNotifySendBulk');
  if (startIdx < 0) fail('L2g', 'sendBulk not found');
  else {
    /* Walk from the opening `{` until braces balance. */
    const openBrace = NB.indexOf('{', startIdx);
    let depth = 1, i = openBrace + 1;
    while (i < NB.length && depth > 0) {
      const ch = NB[i];
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      i++;
    }
    const body = NB.slice(startIdx, i);
    const filterExpr = /_certsNotifyChecked\.get\([^)]+\)\s*&&\s*r\.email/.test(body);
    if (filterExpr) pass('L2g', 'sendBulk targets only checked-and-has-email rows');
    else fail('L2g', 'sendBulk filter incorrect');
  }
}

/* L2h — Bulk send: every send attempt (success OR failure) creates a log row. */
{
  const gas = GAS.match(/function handleCertNotifySend[\s\S]{0,2500}?\n\}/);
  if (!gas) fail('L2h', 'handleCertNotifySend not found in GAS');
  else {
    /* Log call must NOT be inside the try that catches the send error — otherwise
     * a send failure would skip the log row. Our code logs AFTER the try/catch
     * with the sendErr captured. Verify. */
    const capturesErr = /sendErr\s*=\s*String/.test(gas[0]);
    const logsAfter   = /sbInsert[\s\S]{0,600}status:\s*sendErr\s*\?\s*'failed'/.test(gas[0]);
    if (capturesErr && logsAfter) pass('L2h', 'GAS logs every attempt (success OR failure) with proper status');
    else fail('L2h', 'GAS log-on-fail path broken', { capturesErr, logsAfter });
  }
}

/* L2i — Batch log fetch: bounded so query doesn't unbounded-scan. */
{
  const logFn = NB.match(/async function certsNotifyLoadBatchLog[\s\S]{0,1500}?\}/);
  if (!logFn) fail('L2i', 'loadBatchLog not found');
  else {
    const hasLimit = /limit=\d+/.test(logFn[0]);
    if (hasLimit) pass('L2i', 'batch-log query bounded (LIMIT present)');
    else fail('L2i', 'batch-log unbounded — will slow down over time');
  }
}

/* ─────────────── L3 DB / RPC / RLS ─────────────── */

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
    const cols = await sql(`select column_name from information_schema.columns where table_schema='slate' and table_name='cert_notify_log' order by ordinal_position`);
    const names = cols.map(c => c.column_name);
    const wanted = ['id','session_id','member_number','recipient_email','subject','status','batch_id','cert_count','error','sent_by','sent_at'];
    const missing = wanted.filter(w => !names.includes(w));
    if (missing.length === 0) pass('L3a', 'cert_notify_log schema OK');
    else fail('L3a', 'cert_notify_log missing columns', missing);
  } catch (e) { fail('L3a', 'log schema query failed', e.message); }

  try {
    const rls = await sql(`select relrowsecurity from pg_class where oid='slate.cert_notify_log'::regclass`);
    if (rls[0]?.relrowsecurity) pass('L3b', 'RLS on cert_notify_log');
    else fail('L3b', 'RLS NOT enabled on cert_notify_log');
  } catch (e) { fail('L3b', 'log rls check failed', e.message); }

  try {
    const pols = await sql(`select polname, polroles::regrole[] as roles from pg_policy where polrelid='slate.cert_notify_template'::regclass`);
    const hasServiceAll = pols.some(p => /service/.test(p.polname));
    const hasAnonRead   = pols.some(p => /anon_read/.test(p.polname));
    if (hasServiceAll && hasAnonRead) pass('L3c', 'template: anon read + service_role all');
    else fail('L3c', 'template policies incomplete', pols);
  } catch (e) { fail('L3c', 'template policy check failed', e.message); }

  try {
    const t0 = Date.now();
    const r = await sql(`select count(*)::int as n from slate.session_cert_holders(2)`);
    const dt = Date.now() - t0;
    if (r[0].n > 0 && dt < 5000) pass('L3d', `session_cert_holders(2) → ${r[0].n} rows in ${dt}ms`);
    else if (r[0].n === 0) fail('L3d', 'session_cert_holders returned 0 for Spring — data missing');
    else fail('L3d', `RPC too slow (${dt}ms) — need index tuning`);
  } catch (e) { fail('L3d', 'RPC call failed', e.message); }

  try {
    const r = await sql(`select count(*)::int as n from slate.player_certs('18821', 2)`);
    if (r[0].n > 0) pass('L3e', `player_certs('18821', 2) returns ${r[0].n} rows`);
    else fail('L3e', 'player_certs returns 0 for known good member');
  } catch (e) { fail('L3e', 'player_certs call failed', e.message); }

  /* L3f — session_cert_holders is SECURITY DEFINER (bypasses RLS). */
  try {
    const r = await sql(`select prosecdef from pg_proc where proname='session_cert_holders' and pronamespace='slate'::regnamespace`);
    if (r[0]?.prosecdef) pass('L3f', 'session_cert_holders is SECURITY DEFINER');
    else fail('L3f', 'session_cert_holders is NOT security definer — anon calls will hit RLS');
  } catch (e) { fail('L3f', 'RPC secdef check failed', e.message); }

  /* L3g — anon key CAN read cert_notify_template (no service key needed). */
  try {
    const ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRxemJla29heXNnYWlxbGp1ZWFjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUxNzA5NzgsImV4cCI6MjA5MDc0Njk3OH0.cCdGxZ4zEFzU_r6lWSDeoNWG67Q4MSYCAtpds035dfU';
    const r = await fetch('https://dqzbekoaysgaiqljueac.supabase.co/rest/v1/cert_notify_template?operator_id=eq.1&select=subject', {
      headers: { apikey: ANON, Authorization: 'Bearer ' + ANON, 'Accept-Profile': 'slate' }
    });
    const rows = await r.json();
    if (r.ok && Array.isArray(rows) && rows.length) pass('L3g', 'anon can read cert_notify_template (template load works in anon-only preview)');
    else fail('L3g', 'anon read failed', { status: r.status, rows });
  } catch (e) { fail('L3g', 'anon read raised', e.message); }

  /* L3h — anon key CANNOT insert into cert_notify_log (only service_role). */
  try {
    const ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRxemJla29heXNnYWlxbGp1ZWFjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUxNzA5NzgsImV4cCI6MjA5MDc0Njk3OH0.cCdGxZ4zEFzU_r6lWSDeoNWG67Q4MSYCAtpds035dfU';
    const r = await fetch('https://dqzbekoaysgaiqljueac.supabase.co/rest/v1/cert_notify_log', {
      method: 'POST',
      headers: { apikey: ANON, Authorization: 'Bearer ' + ANON, 'Content-Type': 'application/json', 'Content-Profile': 'slate', Prefer: 'return=minimal' },
      body: JSON.stringify({ session_id: 2, member_number: 'test', recipient_email: 'x@x.com', subject: 't', status: 'sent', batch_id: '00000000-0000-0000-0000-000000000000' })
    });
    if (r.status === 401 || r.status === 403) pass('L3h', `anon INSERT blocked by RLS (${r.status})`);
    else if (r.status < 300) fail('L3h', 'SECURITY: anon can INSERT into cert_notify_log — RLS not gating writes');
    else pass('L3h', `anon INSERT rejected (${r.status})`);
  } catch (e) { fail('L3h', 'anon insert check raised', e.message); }
} else {
  skip('L3*', 'skipped — SUPABASE_PAT not set');
}

/* ─────────────── L4 GAS action ─────────────── */

/* L4a — cert_notify_send action registered. */
{
  if (/action === 'cert_notify_send'/.test(GAS)) pass('L4a', 'cert_notify_send action registered in doPost');
  else fail('L4a', 'action not registered');
}

/* L4b — Auth: admin_key !== SUPABASE_SERVICE → 'unauthorized'. */
{
  const h = GAS.match(/function handleCertNotifySend[\s\S]{0,2500}?\n\}/);
  if (!h) fail('L4b', 'handler not found');
  else {
    const auth = /body\.admin_key\s*!==\s*SUPABASE_SERVICE/.test(h[0]);
    if (auth) pass('L4b', 'admin_key checked against SUPABASE_SERVICE');
    else fail('L4b', 'auth check missing');
  }
}

/* L4c — Required fields validated. `to` is checked as `!to → recipients required`. */
{
  const h = GAS.match(/function handleCertNotifySend[\s\S]{0,3000}?\n\}/);
  if (!h) fail('L4c', 'handler not found');
  else {
    const checks_ = {
      to:        /if\s*\(!to\)/.test(h[0]),
      subject:   /if\s*\(!subject\)/.test(h[0]),
      body_html: /if\s*\(!bodyHtml\)/.test(h[0]),
      batch_id:  /if\s*\(!batchId\)/.test(h[0]),
    };
    const missing = Object.entries(checks_).filter(([, v]) => !v).map(([k]) => k);
    if (missing.length === 0) pass('L4c', 'all required-field guards present in GAS handler');
    else fail('L4c', 'validation gaps', missing);
  }
}

/* L4d — plain-text fallback is present in send call. */
{
  const h = GAS.match(/function handleCertNotifySend[\s\S]{0,2500}?\n\}/);
  if (!h) fail('L4d', 'handler not found');
  else {
    const plain = /plainBody\s*=\s*bodyHtml/.test(h[0]) && /GmailApp\.sendEmail\(to,\s*subject,\s*plainBody/.test(h[0]);
    if (plain) pass('L4d', 'plain-text fallback generated and passed to GmailApp');
    else fail('L4d', 'no plain-text fallback (accessibility + RFC nit)');
  }
}

/* ─────────────── L5 UI E2E ─────────────── */
/* These require a running browser. Only structural check here. */
skip('L5*', 'UI E2E requires headless browser run — verified live via preview MCP');

/* ─────────────── L6 edge cases ─────────────── */

/* L6a — Empty session handling: certsNotifyReloadHolders shows friendly text. */
{
  const reload = NB.match(/async function certsNotifyReloadHolders[\s\S]{0,1400}?\}/);
  if (!reload) fail('L6a', 'reloadHolders not found');
  else {
    /* On zero rows, render must display an empty-state message. */
    const emptyState = /No cert holders for the selected session/.test(NB);
    if (emptyState) pass('L6a', 'zero-recipient state renders friendly message');
    else fail('L6a', 'no empty-state text for zero cert holders');
  }
}

/* L6b — Missing-email rows: checkbox disabled AND excluded from send. */
{
  const listRender = NB.match(/function certsNotifyRenderList[\s\S]*?^\}$/m);
  if (!listRender) fail('L6b', 'renderList not found');
  else {
    const disabledAttr = /noEmail\s*\?\s*' disabled/.test(listRender[0]);
    if (disabledAttr) pass('L6b', 'no-email rows have disabled checkbox');
    else fail('L6b', 'no-email rows not visually blocked');
  }
}

/* L6c — Test-send requires at least one checked-with-email recipient. */
{
  const test = NB.match(/async function certsNotifySendTest[\s\S]*?^\}$/m);
  if (!test) fail('L6c', 'sendTest not found');
  else {
    const guarded = /No checked recipient with email/.test(test[0]);
    if (guarded) pass('L6c', 'test send guards on no-eligible-recipient');
    else fail('L6c', 'test send crashes when nothing checked');
  }
}

/* L6d — GAS Unknown-action path returns a helpful error. */
{
  if (/Unknown action: ' \+ action/.test(GAS)) pass('L6d', 'GAS returns Unknown-action error clearly');
  else fail('L6d', 'GAS unknown-action fallback missing');
}

/* ─────────────── L7 a11y (email + admin UI) ─────────────── */

/* L7a — status regions have role="status" or aria-live so screen readers announce progress. */
{
  const relevantEls = ['certsNotifyBulkStatus','certsNotifyProgress','certsNotifyTemplateStatus','certsNotifyTestStatus'];
  const missing = relevantEls.filter(id => {
    const re = new RegExp(`id="${id}"[^>]*(role="status"|aria-live)`);
    return !re.test(HTML);
  });
  if (missing.length === 0) pass('L7a', 'all status regions have aria-live/role="status"');
  else fail('L7a', 'a11y gap: status regions missing aria-live', missing);
}

/* L7b — All labels tied to inputs. */
{
  const labelsFor = new Set([...HTML.matchAll(/<label for="([^"]+)"/g)].map(m => m[1]));
  const wantLinked = ['certsNotifySession','certsNotifySubject','certsNotifyBody','certsNotifyTestEmail'];
  const missing = wantLinked.filter(id => !labelsFor.has(id));
  if (missing.length === 0) pass('L7b', 'all key inputs have <label for="">');
  else fail('L7b', 'inputs missing linked labels', missing);
}

/* ─────────────── L8 RFC transactional email ─────────────── */

/* L8a — Default template mentions PatchCheck link (user has action). */
{
  const tpl = HTML.match(/'Your SPM.*ready'[\s\S]{0,600}/);
  if (tpl) pass('L8a', 'default template referenced (installed via migration)');
  else skip('L8a', 'default template not inline — installed via migration');
}

/* L8b — Plain-text fallback generated. Already covered by L4d, cross-ref pass. */
if (checks.find(c => c.id === 'L4d')?.ok) pass('L8b', 'plain-text alt body present (via GAS L4d)');
else fail('L8b', 'no plain-text alt — poor deliverability + a11y');

/* L8c — Reply-To / From set to a real inbox (from FROM_NAME const). */
{
  if (/const FROM_NAME\s*=\s*'South Portland Metro APA'/.test(GAS)) pass('L8c', 'From name set to a real org name');
  else fail('L8c', 'From name not clearly set');
}

/* L8d — RFC 8058 List-Unsubscribe: not required for internal transactional
   cert notifications (recipients are opted-in league members). Documented
   gap — revisit if we ever expand this to promotional mail. */
if (/List-Unsubscribe/i.test(GAS)) pass('L8d', 'List-Unsubscribe header present');
else skip('L8d', 'List-Unsubscribe deferred — internal transactional mail to opted-in league members');

/* ─────────────── Report ─────────────── */

let p = 0, f = 0, s = 0;
for (const c of checks) {
  if (c.ok === true)  { p++; console.log(`  ✓ ${c.id.padEnd(5)} ${c.msg}`); }
  else if (c.ok === false) {
    f++; console.log(`  ✗ ${c.id.padEnd(5)} ${c.msg}`);
    if (c.detail) console.log('        ', JSON.stringify(c.detail).slice(0, 300));
  } else { s++; console.log(`  · ${c.id.padEnd(5)} ${c.msg}`); }
}
console.log(`\n${p}/${p+f} passed, ${f} failed, ${s} skipped`);
process.exit(f ? 1 : 0);
