const { getSupabaseConfig, supabaseRequest } = require('../lib/supabase');
const R = require('../lib/sub-rules');
const CONFIG = getSupabaseConfig();
const MAXLEN = 262144;
const MAXSECS = 200;
const BODY_LIMIT = 4200000;
const SEC_COLS = 'id,title,sub_key,slug,expires_at,sort_no,created_at';
const ID_RE = /^[0-9a-f-]{36}$/;

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return done(res, 405, { ok: false, e: 'method' });
  if (!CONFIG.ok) return done(res, 503, { ok: false, e: 'env', missing: CONFIG.missing });

  let b = null;
  try { b = JSON.parse(await body(req)); }
  catch (err) {
    if (err && err.code === 'BODY_TOO_LARGE') return done(res, 413, { ok: false, e: 'size' });
    b = null;
  }
  if (!b || typeof b !== 'object') return done(res, 400, { ok: false, e: 'body' });

  const action = String(b.action || '');
  const tok    = String(b.s || '');
  if (!/^[a-f0-9]{48}$/.test(tok)) return done(res, 400, { ok: false, e: 'sess' });

  try {
    const me = await meOf(tok);
    if (!me) return done(res, 401, { ok: false, e: 'sess' });
    // The temporary session from the default admin/admin login may only be used to set a password.
    if (me.pass_hash === 'DEFAULT') return done(res, 403, { ok: false, e: 'setup' });

    if (action === 'list')    return await list(res, me);
    if (action === 'get')     return await get(res, me, b);
    if (action === 'create')  return await create(res, me, b);
    if (action === 'save')    return await save(res, me, b);
    if (action === 'del')     return await del(res, me, b);
    if (action === 'key')     return await key(res, me, b);
    if (action === 'link')    return await link(res, me, b);
    if (action === 'expire')  return await expire(res, me, b);
    if (action === 'short')   return await short(res, me, b, req.headers);
    if (action === 'backup')  return await backup(res, me);
    if (action === 'restore') return await restore(res, me, b);
    return done(res, 400, { ok: false, e: 'action' });
  } catch (err) {
    // PostgREST answers 400 for unknown columns: schema.sql has not been re-run after the update.
    if (err && err.status === 400) return done(res, 500, { ok: false, e: 'schema' });
    return done(res, 500, { ok: false, e: 'db' });
  }
};

function pub(r) {
  return { id: r.id, title: r.title, sub_key: r.sub_key || null, slug: r.slug || null,
    expires_at: r.expires_at || null, sort_no: r.sort_no, created_at: r.created_at };
}

async function ownRow(me, id, cols) {
  const rows = await sb(`/rest/v1/sections?id=eq.${id}&user_id=eq.${me.id}&select=${cols || 'id'}&limit=1`);
  return (rows && rows.length) ? rows[0] : null;
}

async function list(res, me) {
  const rows = await sb(`/rest/v1/sections?user_id=eq.${me.id}&order=sort_no.asc,created_at.asc&select=${SEC_COLS}&limit=${MAXSECS}`);
  done(res, 200, { ok: true, list: (rows || []).map(pub) });
}

async function get(res, me, b) {
  const id = String(b.id || '');
  if (!ID_RE.test(id)) return done(res, 400, { ok: false, e: 'id' });
  const row = await ownRow(me, id, SEC_COLS + ',content');
  if (!row) return done(res, 403, { ok: false, e: 'owner' });
  done(res, 200, { ok: true, sec: Object.assign(pub(row), { content: row.content || '' }) });
}

async function create(res, me, b) {
  const title = String(b.title || '').slice(0, 60);
  const cnt = await sb(`/rest/v1/sections?user_id=eq.${me.id}&select=id&limit=${MAXSECS + 1}`);
  if (cnt && cnt.length >= MAXSECS) return done(res, 400, { ok: false, e: 'limit' });

  const row = { user_id: me.id, title, content: '', sort_no: cnt ? cnt.length : 0 };
  if (b.days !== undefined && b.days !== null && b.days !== '') {
    const days = R.parseDays(b.days);
    if (days === null) return done(res, 400, { ok: false, e: 'days' });
    row.expires_at = R.expiryFromDays(days);
  }
  try {
    const mx = await sb(`/rest/v1/sections?user_id=eq.${me.id}&order=sort_no.desc&select=sort_no&limit=1`);
    if (mx && mx.length && Number.isFinite(mx[0].sort_no)) row.sort_no = mx[0].sort_no + 1;
  } catch (e) {}

  const ins = await sbPost('/rest/v1/sections', row, true);
  done(res, 200, { ok: true, sec: ins && ins[0] ? pub(ins[0]) : null });
}

async function save(res, me, b) {
  const id = String(b.id || '');
  const title = String(b.title || '').slice(0, 60);
  const content = String(b.content || '');
  if (!ID_RE.test(id)) return done(res, 400, { ok: false, e: 'id' });
  if (content.length > MAXLEN) return done(res, 400, { ok: false, e: 'size' });

  if (!await ownRow(me, id)) return done(res, 403, { ok: false, e: 'owner' });
  const patched = await sbPatchRet(`/rest/v1/sections?id=eq.${id}&user_id=eq.${me.id}`, { title, content });
  if (!patched) return done(res, 403, { ok: false, e: 'owner' });
  done(res, 200, { ok: true });
}

async function del(res, me, b) {
  const id = String(b.id || '');
  if (!ID_RE.test(id)) return done(res, 400, { ok: false, e: 'id' });
  if (!await ownRow(me, id)) return done(res, 403, { ok: false, e: 'owner' });
  await sbDel(`/rest/v1/sections?id=eq.${id}&user_id=eq.${me.id}`);
  done(res, 200, { ok: true });
}

async function newKey() {
  for (let i = 0; i < 20; i++) {
    const cand = rand(8);
    const ex = await sb(`/rest/v1/sections?sub_key=eq.${cand}&select=id&limit=1`);
    if (!ex || !ex.length) return cand;
  }
  return null;
}

// Creates the random link address. With reset:true it also removes the custom name,
// so every old address of this sub stops working.
async function key(res, me, b) {
  const id = String(b.id || '');
  if (!ID_RE.test(id)) return done(res, 400, { ok: false, e: 'id' });
  if (!await ownRow(me, id)) return done(res, 403, { ok: false, e: 'owner' });

  const nk = await newKey();
  if (!nk) return done(res, 500, { ok: false, e: 'db' });
  const patch = { sub_key: nk };
  if (b.reset === true) patch.slug = null;
  await sbPatch(`/rest/v1/sections?id=eq.${id}&user_id=eq.${me.id}`, patch);
  done(res, 200, { ok: true, key: nk, slug: b.reset === true ? null : undefined });
}

// Sets or clears the custom link name: /s/<slug>
async function link(res, me, b) {
  const id = String(b.id || '');
  if (!ID_RE.test(id)) return done(res, 400, { ok: false, e: 'id' });
  const slug = R.normSlug(b.slug);
  const bad = R.slugError(slug);
  if (bad) return done(res, 400, { ok: false, e: bad });

  const row = await ownRow(me, id, 'id,sub_key,slug');
  if (!row) return done(res, 403, { ok: false, e: 'owner' });

  if (slug) {
    const ex = await sb(`/rest/v1/sections?slug=eq.${enc(slug)}&select=id&limit=1`);
    if (ex && ex.length && ex[0].id !== id) return done(res, 409, { ok: false, e: 'slug_taken' });
  }
  const patch = { slug: slug || null };
  let keyOut = row.sub_key || null;
  // A sub with a name always also gets a private random address.
  if (slug && !keyOut) { keyOut = await newKey(); if (keyOut) patch.sub_key = keyOut; }
  try {
    await sbPatch(`/rest/v1/sections?id=eq.${id}&user_id=eq.${me.id}`, patch);
  } catch (err) {
    if (err && err.status === 409) return done(res, 409, { ok: false, e: 'slug_taken' });
    throw err;
  }
  done(res, 200, { ok: true, slug: slug || null, key: keyOut });
}

// Sets how many days the link stays active (0 = no limit), counted from now.
async function expire(res, me, b) {
  const id = String(b.id || '');
  if (!ID_RE.test(id)) return done(res, 400, { ok: false, e: 'id' });
  const days = R.parseDays(b.days);
  if (days === null) return done(res, 400, { ok: false, e: 'days' });
  if (!await ownRow(me, id)) return done(res, 403, { ok: false, e: 'owner' });

  const expires_at = R.expiryFromDays(days);
  await sbPatch(`/rest/v1/sections?id=eq.${id}&user_id=eq.${me.id}`, { expires_at });
  done(res, 200, { ok: true, expires_at });
}

function hostOf(headers) {
  const configured = configuredHost();
  if (configured) return configured;
  const raw = String(headers['x-forwarded-host'] || headers.host || '').split(',')[0].trim();
  const h = raw.split(':')[0].toLowerCase();
  if (!h.includes('.') || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(h)) return '';
  if (/^\d+(\.\d+){3}$/.test(h)) return ''; // bare IP (local run): public shorteners refuse these
  return h;
}
function configuredHost() {
  const raw = String(process.env.PUBLIC_ORIGIN || process.env.VERCEL_PROJECT_PRODUCTION_URL || process.env.VERCEL_URL || '').trim();
  if (!raw) return '';
  try {
    const u = new URL(/^https?:\/\//i.test(raw) ? raw : 'https://' + raw);
    const h = u.hostname.toLowerCase();
    if (!h.includes('.') || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(h)) return '';
    return h;
  } catch (e) { return ''; }
}

async function short(res, me, b, headers) {
  let row = null;
  const id = String(b.id || '');
  if (ID_RE.test(id)) row = await ownRow(me, id, 'id,sub_key,slug');
  else if (R.isKey(b.key)) {
    const r = await sb(`/rest/v1/sections?sub_key=eq.${b.key}&user_id=eq.${me.id}&select=id,sub_key,slug&limit=1`);
    row = r && r.length ? r[0] : null;
  } else return done(res, 400, { ok: false, e: 'id' });
  if (!row) return done(res, 403, { ok: false, e: 'owner' });

  const seg = row.slug || row.sub_key;
  if (!seg) return done(res, 400, { ok: false, e: 'nolink' });
  const h = hostOf(headers);
  if (!h) return done(res, 400, { ok: false, e: 'host' });
  const direct = 'https://' + h + '/s/' + seg;
  const sh = await shorten(direct);
  done(res, 200, { ok: true, key: row.sub_key, slug: row.slug || null, direct, short: sh });
}

// Asks several free shorteners at once and keeps the first one that answers with a valid link.
async function shorten(u) {
  const q = encodeURIComponent(u);
  const need = s => { if (!/^https:\/\/[a-z0-9.-]+\/[A-Za-z0-9_-]+$/.test(s)) throw new Error('bad'); return s; };
  const jsonShort = t => { const j = JSON.parse(t); return need(String((j && j.shorturl) || '')); };
  const tasks = [
    grab('https://is.gd/create.php?format=json&url=' + q, 6000).then(jsonShort),
    grab('https://v.gd/create.php?format=json&url=' + q, 6000).then(jsonShort),
    grab('https://tinyurl.com/api-create.php?url=' + q, 6000).then(t => need(t.trim())),
    grab('https://spoo.me/', 6000, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'url=' + q,
    }).then(t => need(String((JSON.parse(t) || {}).short_url || '').replace(/^http:/i, 'https:'))),
  ];
  try { return await Promise.any(tasks); } catch (e) { return ''; }
}

async function grab(u, ms, opt) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try {
    const r = await fetch(u, Object.assign({ signal: c.signal }, opt || {}));
    if (!r.ok) throw new Error('http');
    return await r.text();
  } finally { clearTimeout(t); }
}

async function backup(res, me) {
  if (me.role !== 'admin') return done(res, 403, { ok: false, e: 'forb' });

  const users = await allRows('/rest/v1/users?select=id,username,role,created_at&order=created_at.asc,id.asc');
  const secs  = await allRows('/rest/v1/sections?select=id,user_id,title,content,sub_key,slug,expires_at,sort_no,created_at&order=created_at.asc,id.asc');
  const byId = {};
  (users || []).forEach(u => { byId[u.id] = u.username; });

  const payload = {
    app: 'panel-vercel-sub',
    version: 2,
    at: new Date().toISOString(),
    users: (users || []).map(u => ({ username: u.username, role: u.role })),
    sections: (secs || []).map(s => ({ user: byId[s.user_id] || '', title: s.title, content: s.content,
      sub_key: s.sub_key, slug: s.slug || null, expires_at: s.expires_at || null, sort: s.sort_no })),
  };

  done(res, 200, { ok: true, data: payload });
}

async function restore(res, me, b) {
  if (me.role !== 'admin') return done(res, 403, { ok: false, e: 'forb' });
  if (!b || typeof b.data !== 'object' || !b.data || !Array.isArray(b.data.sections))
    return done(res, 400, { ok: false, e: 'bad' });

  const d = b.data;
  const mine = await sb(`/rest/v1/sections?user_id=eq.${me.id}&select=id&limit=${MAXSECS + 1}`);
  const have = (mine && mine.length) || 0;
  if (have >= MAXSECS) return done(res, 400, { ok: false, e: 'limit' });
  const room = MAXSECS - have;

  const used = new Set(), usedSlug = new Set();
  try {
    const all = await sb('/rest/v1/sections?select=sub_key,slug&limit=5000');
    (all || []).forEach(r => { if (r && r.sub_key) used.add(r.sub_key); if (r && r.slug) usedSlug.add(r.slug); });
  } catch (e) {}

  const clean = [];
  for (const s of d.sections) {
    if (clean.length >= room) break;
    if (!s || typeof s.content !== 'string' || s.content.length > MAXLEN) continue;
    const title = String(s.title || '').slice(0, 60);
    let subKey = (R.isKey(s.sub_key) && !used.has(s.sub_key)) ? s.sub_key : null;
    if (!subKey) {
      for (let i = 0; i < 10; i++) {
        const cand = rand(8);
        if (!used.has(cand)) { subKey = cand; break; }
      }
      if (!subKey) continue;
    }
    used.add(subKey);
    const slug = R.normSlug(s.slug);
    const slugOk = slug && !R.slugError(slug) && !usedSlug.has(slug);
    if (slugOk) usedSlug.add(slug);
    const exp = s.expires_at && Number.isFinite(Date.parse(s.expires_at)) ? new Date(s.expires_at).toISOString() : null;
    clean.push({ title, content: s.content, sub_key: subKey, slug: slugOk ? slug : null, expires_at: exp });
  }

  let base = have;
  try {
    const mx = await sb(`/rest/v1/sections?user_id=eq.${me.id}&order=sort_no.desc&select=sort_no&limit=1`);
    if (mx && mx.length && Number.isFinite(mx[0].sort_no)) base = mx[0].sort_no + 1;
  } catch (e) {}

  let added = 0;
  let failed = 0;
  for (let i = 0; i < clean.length; i++) {
    try {
      await sbPost('/rest/v1/sections', Object.assign({ user_id: me.id, sort_no: base + i }, clean[i]));
      added++;
    } catch (e) { failed++; }
  }

  if (failed) return done(res, 207, { ok: false, e: 'restore_partial', added, failed, requested: clean.length });
  done(res, 200, { ok: true, added, requested: clean.length });
}

async function allRows(path, pageSize = 500) {
  const rows = [];
  for (let offset = 0; ; offset += pageSize) {
    const sep = path.includes('?') ? '&' : '?';
    const page = await sb(`${path}${sep}limit=${pageSize}&offset=${offset}`);
    if (!Array.isArray(page) || !page.length) break;
    rows.push(...page);
    if (page.length < pageSize) break;
  }
  return rows;
}

function meOf(tok) {
  return sb(`/rest/v1/sessions?token=eq.${tok}&select=user_id,expires_at`)
    .then(async rows => {
      if (!rows || !rows.length) return null;
      if (new Date(rows[0].expires_at) < new Date()) { try { await sbDel('/rest/v1/sessions?token=eq.' + tok); } catch (e) {} return null; }
      const u = await sb(`/rest/v1/users?id=eq.${rows[0].user_id}&select=id,username,role,pass_hash`);
      return (u && u.length) ? u[0] : null;
    });
}

function rand(n) {
  return require('crypto').randomBytes(n).toString('hex');
}
const enc = s => encodeURIComponent(s);

async function sb(path) {
  return supabaseRequest(path);
}
async function sbPost(path, obj, ret) {
  return supabaseRequest(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(ret ? { Prefer: 'return=representation' } : {}) },
    body: JSON.stringify(obj),
  });
}
async function sbPatch(path, obj) {
  return supabaseRequest(path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(obj),
  });
}
async function sbPatchRet(path, obj) {
  const j = await supabaseRequest(path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Prefer: 'return=representation' },
    body: JSON.stringify(obj),
  });
  if (!j || !j.length) return null;
  return j;
}
async function sbDel(path) {
  return supabaseRequest(path, { method: 'DELETE' });
}

function body(req) {
  return new Promise((ok, no) => {
    let d = '';
    let rejected = false;
    req.on('data', c => {
      if (rejected) return;
      d += c;
      if (Buffer.byteLength(d, 'utf8') > BODY_LIMIT) {
        rejected = true;
        const err = new Error('body_too_large');
        err.code = 'BODY_TOO_LARGE';
        no(err);
        req.resume();
      }
    });
    req.on('end', () => ok(d));
    req.on('error', no);
  });
}

function done(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
module.exports.shorten = shorten;
