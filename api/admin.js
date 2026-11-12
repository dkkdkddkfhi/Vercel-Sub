const { getSupabaseConfig, supabaseRequest } = require('../lib/supabase');
const CONFIG = getSupabaseConfig();

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
    if (me.pass_hash === 'DEFAULT') return done(res, 403, { ok: false, e: 'setup' });
    if (me.role !== 'admin') return done(res, 403, { ok: false, e: 'forb' });

    if (action === 'users') return await users(res);
    if (action === 'role')  return await role(res, me, b);
    if (action === 'del')   return await del(res, me, b);
    return done(res, 400, { ok: false, e: 'action' });
  } catch (err) {
    return done(res, 500, { ok: false, e: 'db' });
  }
};

async function users(res) {
  const rows = await sb('/rest/v1/users?order=created_at.asc&select=id,username,role,created_at&limit=500');
  const safe = (rows || []).map(u => ({ id: u.id, username: u.username, role: u.role, created_at: u.created_at }));
  done(res, 200, { ok: true, list: safe });
}

async function role(res, me, b) {
  const id   = String(b.id || '');
  const role_ = String(b.r || '');
  if (!/^[0-9a-f-]{36}$/.test(id))              return done(res, 400, { ok: false, e: 'id' });
  if (role_ !== 'admin' && role_ !== 'user')    return done(res, 400, { ok: false, e: 'role' });
  if (id === me.id)                             return done(res, 400, { ok: false, e: 'self' });

  const ex = await sb(`/rest/v1/users?id=eq.${id}&select=id,role`);
  if (!ex || !ex.length) return done(res, 404, { ok: false, e: 'no' });

  if (ex[0].role === 'admin' && role_ === 'user') {
    const admins = await sb('/rest/v1/users?role=eq.admin&select=id&limit=2');
    if (admins && admins.length <= 1) return done(res, 400, { ok: false, e: 'last' });
  }

  await sbPatch(`/rest/v1/users?id=eq.${id}`, { role: role_ });
  done(res, 200, { ok: true });
}

async function del(res, me, b) {
  const id = String(b.id || '');
  if (!/^[0-9a-f-]{36}$/.test(id)) return done(res, 400, { ok: false, e: 'id' });
  if (id === me.id)                return done(res, 400, { ok: false, e: 'self' });

  const ex = await sb(`/rest/v1/users?id=eq.${id}&select=id,role`);
  if (!ex || !ex.length) return done(res, 404, { ok: false, e: 'no' });

  if (ex[0].role === 'admin') {
    const admins = await sb('/rest/v1/users?role=eq.admin&select=id&limit=2');
    if (admins && admins.length <= 1) return done(res, 400, { ok: false, e: 'last' });
  }

  try { await sbDel(`/rest/v1/sections?user_id=eq.${id}`); } catch (e) {}
  try { await sbDel(`/rest/v1/sessions?user_id=eq.${id}`); } catch (e) {}
  await sbDel(`/rest/v1/users?id=eq.${id}`);
  done(res, 200, { ok: true });
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

const enc = s => encodeURIComponent(s);

async function sb(path) {
  return supabaseRequest(path);
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
      if (Buffer.byteLength(d, 'utf8') > 200000) {
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
