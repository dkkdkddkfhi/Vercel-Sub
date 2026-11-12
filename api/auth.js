const { getSupabaseConfig, supabaseRequest } = require('../lib/supabase');
const CONFIG = getSupabaseConfig();
const ALLOW_REGISTER = String(process.env.ALLOW_REGISTER || '0') === '1';

const USER_RE = /^[a-z0-9_.-]+$/;
const USER_MIN = 3, USER_MAX = 32;
const PASS_MIN = 5, PASS_MAX = 128;

const _hits = new Map();
function rateOk(ip) {
  const now = Date.now();
  const h = _hits.get(ip) || { n: 0, t: now };
  if (now - h.t > 60000) { h.n = 0; h.t = now; }
  h.n++;
  _hits.set(ip, h);
  if (_hits.size > 2000) { const k = _hits.keys().next().value; _hits.delete(k); }
  return h.n <= 20;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return done(res, 405, { ok: false, e: 'method' });
  if (!CONFIG.ok) return done(res, 503, { ok: false, e: 'env', missing: CONFIG.missing });

  const forwarded = String(req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || '');
  const ip = forwarded.split(',').map(x => x.trim()).filter(Boolean).pop() || 'x';
  if (!rateOk(ip)) {
    res.setHeader('Retry-After', '60');
    return done(res, 429, { ok: false, e: 'rate' });
  }

  let b = null;
  try { b = JSON.parse(await body(req)); }
  catch (err) {
    if (err && err.code === 'BODY_TOO_LARGE') return done(res, 413, { ok: false, e: 'size' });
    b = null;
  }
  if (!b || typeof b !== 'object') return done(res, 400, { ok: false, e: 'body' });

  const action = String(b.action || '');
  const user   = String(b.u || '').trim().toLowerCase();
  const pass   = String(b.p || '');
  if (action === 'login' && !rateOk('user:' + user)) {
    res.setHeader('Retry-After', '60');
    return done(res, 429, { ok: false, e: 'rate' });
  }

  try {
    if (action === 'login')     return await login(res, user, pass);
    if (action === 'setup')     return await setup(res, b);
    if (action === 'register')  return await register(res, user, pass);
    if (action === 'logout')    return await logout(res, b);
    if (action === 'pass')      return await changePass(res, b);
    return done(res, 400, { ok: false, e: 'action' });
  } catch (err) {
    return done(res, 500, { ok: false, e: 'db' });
  }
};

function badUser(u) {
  if (!u || u.length < USER_MIN) return true;
  if (u.length > USER_MAX) return true;
  if (!USER_RE.test(u)) return true;
  return false;
}
function badPass(p) {
  if (!p || p.length < PASS_MIN) return 'short';
  if (p.length > PASS_MAX) return 'long';
  return null;
}

async function login(res, user, pass) {
  if (badUser(user) || !pass) return done(res, 400, { ok: false, e: 'input' });
  if (pass.length > PASS_MAX) return done(res, 400, { ok: false, e: 'input' });

  const r = await sb(`/rest/v1/users?username=eq.${enc(user)}&select=id,username,pass_hash,salt,role`);
  const rows = (r && Array.isArray(r)) ? r : [];
  if (!rows.length) return done(res, 401, { ok: false, e: 'no' });

  const u = rows[0];

  if (u.username === 'admin' && u.pass_hash === 'DEFAULT') {
    if (pass !== 'admin') return done(res, 401, { ok: false, e: 'no' });
    const tok = rand(24);
    await sbPost('/rest/v1/sessions', { token: tok, user_id: u.id, expires_at: futureMinutes(15) }, true);
    return done(res, 200, { ok: true, mustSetup: true, s: tok, role: 'admin', u: 'admin' });
  }

  const v = await verifyPass(pass, u.salt, u.pass_hash);
  if (!v.ok) return done(res, 401, { ok: false, e: 'no' });
  if (v.legacy) {
    // Old fast SHA-256 hash: upgrade it to scrypt now that we know the password.
    try { await sbPatch('/rest/v1/users?id=eq.' + u.id, await makeHash(pass)); } catch (e) {}
  }

  const tok = rand(24);
  await sbPost('/rest/v1/sessions', { token: tok, user_id: u.id, expires_at: futureDays(30) }, true);
  done(res, 200, { ok: true, s: tok, role: u.role, u: u.username });
}

async function setup(res, b) {
  const tok = String(b.s || '');
  const p1  = String(b.p1 || '');
  const p2  = String(b.p2 || '');
  if (!/^[a-f0-9]{48}$/.test(tok)) return done(res, 400, { ok: false, e: 'input' });
  const bp = badPass(p1);
  if (bp) return done(res, 400, { ok: false, e: bp === 'long' ? 'long' : 'short' });
  if (p1 !== p2)      return done(res, 400, { ok: false, e: 'match' });

  const me = await meOf(tok);
  if (!me) return done(res, 401, { ok: false, e: 'sess' });
  if (me.username !== 'admin') return done(res, 403, { ok: false, e: 'forb' });

  const r = await sb(`/rest/v1/users?username=eq.admin&select=id,pass_hash`);
  if (!r || !r.length || r[0].pass_hash !== 'DEFAULT') return done(res, 400, { ok: false, e: 'done' });

  await sbPatch('/rest/v1/users?id=eq.' + me.id, await makeHash(p1));
  try { await sbDel('/rest/v1/sessions?token=eq.' + tok); } catch (e) {}
  done(res, 200, { ok: true });
}

async function register(res, user, pass) {
  if (!ALLOW_REGISTER) return done(res, 403, { ok: false, e: 'closed' });
  if (badUser(user))  return done(res, 400, { ok: false, e: 'user' });
  const bp = badPass(pass);
  if (bp) return done(res, 400, { ok: false, e: bp === 'long' ? 'long' : 'short' });

  let isFirst = false;
  try {
    const one = await sb('/rest/v1/users?select=id&order=created_at.asc&limit=1');
    isFirst = !(one && one.length);
  } catch (e) { isFirst = false; }
  const role = isFirst ? 'admin' : 'user';

  const ex = await sb(`/rest/v1/users?username=eq.${enc(user)}&select=id`);
  if (ex && ex.length) return done(res, 409, { ok: false, e: 'exists' });

  const ins = await sbPost('/rest/v1/users', Object.assign({ username: user, role }, await makeHash(pass)), true);
  const id = ins && ins[0] && ins[0].id;
  if (!id) return done(res, 500, { ok: false, e: 'db' });

  let finalRole = role;
  if (role === 'admin') {
    try {
      const oldest = await sb('/rest/v1/users?select=id&order=created_at.asc&limit=1');
      if (oldest && oldest.length && oldest[0].id !== id) {
        await sbPatch('/rest/v1/users?id=eq.' + id, { role: 'user' });
        finalRole = 'user';
      }
    } catch (e) {}
  }

  const tok = rand(24);
  await sbPost('/rest/v1/sessions', { token: tok, user_id: id, expires_at: futureDays(30) }, true);
  return done(res, 200, { ok: true, s: tok, role: finalRole, u: user });
}

async function logout(res, b) {
  const tok = String(b.s || '');
  if (!/^[a-f0-9]{48}$/.test(tok)) return done(res, 400, { ok: false, e: 'input' });
  try { await sbDel('/rest/v1/sessions?token=eq.' + tok); } catch (e) {}
  done(res, 200, { ok: true });
}

async function changePass(res, b) {
  const tok  = String(b.s || '');
  const old  = String(b.old || '');
  const p1   = String(b.p1 || '');
  const p2   = String(b.p2 || '');
  if (!/^[a-f0-9]{48}$/.test(tok)) return done(res, 400, { ok: false, e: 'input' });
  const bp = badPass(p1);
  if (bp) return done(res, 400, { ok: false, e: bp === 'long' ? 'long' : 'short' });
  if (p1 !== p2)      return done(res, 400, { ok: false, e: 'match' });
  if (String(old).length > PASS_MAX) return done(res, 400, { ok: false, e: 'input' });

  const me = await meOf(tok);
  if (!me) return done(res, 401, { ok: false, e: 'sess' });

  const r = await sb(`/rest/v1/users?id=eq.${enc(me.id)}&select=pass_hash,salt`);
  if (!r || !r.length) return done(res, 404, { ok: false, e: 'no' });
  if (r[0].pass_hash !== 'DEFAULT') {
    const v = await verifyPass(old, r[0].salt, r[0].pass_hash);
    if (!v.ok) return done(res, 401, { ok: false, e: 'old' });
  } else if (old !== 'admin') {
    return done(res, 401, { ok: false, e: 'old' });
  }

  await sbPatch('/rest/v1/users?id=eq.' + me.id, await makeHash(p1));
  try { await sbDel(`/rest/v1/sessions?user_id=eq.${enc(me.id)}&token=neq.${tok}`); } catch (e) {}
  done(res, 200, { ok: true });
}

function meOf(tok) {
  return sb(`/rest/v1/sessions?token=eq.${tok}&select=user_id,expires_at`)
    .then(async rows => {
      if (!rows || !rows.length) return null;
      if (new Date(rows[0].expires_at) < new Date()) { try { await sbDel('/rest/v1/sessions?token=eq.' + tok); } catch (e) {} return null; }
      const u = await sb(`/rest/v1/users?id=eq.${rows[0].user_id}&select=id,username,role`);
      return (u && u.length) ? u[0] : null;
    });
}

function futureDays(days) {
  return new Date(Date.now() + days * 86400000).toISOString();
}
function futureMinutes(min) {
  return new Date(Date.now() + min * 60000).toISOString();
}
const enc = s => encodeURIComponent(s);

const crypto = require('crypto');
const scryptAsync = (pass, salt) => new Promise((ok, no) =>
  crypto.scrypt(String(pass), String(salt), 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 },
    (err, key) => (err ? no(err) : ok(key.toString('hex')))));

// New passwords: "s2:" + scrypt hash. Older rows keep a salted SHA-256 hash until the next login.
async function makeHash(pass) {
  const salt = rand(16);
  return { salt, pass_hash: 's2:' + await scryptAsync(pass, salt) };
}
async function verifyPass(pass, salt, stored) {
  stored = String(stored || '');
  if (stored.startsWith('s2:')) return { ok: safeEq('s2:' + await scryptAsync(pass, salt || ''), stored), legacy: false };
  return { ok: safeEq(sha256((salt || '') + '\u0000' + pass), stored), legacy: true };
}
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function sha256(str) {
  return crypto.createHash('sha256').update(String(str), 'utf8').digest('hex');
}
function rand(n) {
  return crypto.randomBytes(n).toString('hex');
}

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
      if (Buffer.byteLength(d, 'utf8') > 500000) {
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
