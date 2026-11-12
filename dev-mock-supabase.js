const { randomUUID } = require('crypto');
const now = () => new Date().toISOString();

const db = {
  users: [
    { id: randomUUID(), username: 'admin', pass_hash: 'DEFAULT', salt: '', role: 'admin', created_at: now() },
  ],
  sessions: [],
  sections: [],
};

function parseQ(search) {
  const p = new URLSearchParams(search);
  const filters = [], order = [];
  let limit = 0, offset = 0;
  for (const [k, v] of p) {
    if (k === 'select') continue;
    if (k === 'order') {
      v.split(',').forEach(o => {
        const [f, d] = o.split('.');
        if (f) order.push({ f, desc: d === 'desc' });
      });
      continue;
    }
    if (k === 'limit') { limit = parseInt(v, 10) || 0; continue; }
    if (k === 'offset') { offset = parseInt(v, 10) || 0; continue; }
    const m = String(v).match(/^(eq|neq)\.(.*)$/s);
    if (m) filters.push({ f: k, op: m[1], v: decodeURIComponent(m[2]) });
  }
  return { filters, order, limit, offset };
}

function match(row, filters) {
  return filters.every(({ f, op, v }) => {
    const rv = row[f] == null ? '' : String(row[f]);
    return op === 'eq' ? rv === v : rv !== v;
  });
}

function tableHandler(table) {
  return async (req, res, search) => {
    const { filters, order, limit, offset } = parseQ(search);
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'GET') {
      let rows = db[table].filter(r => match(r, filters));
      if (order.length) rows = [...rows].sort((a, b) => {
        for (const { f, desc } of order) {
          const av = a[f] ?? '', bv = b[f] ?? '';
          if (av < bv) return desc ? 1 : -1;
          if (av > bv) return desc ? -1 : 1;
        }
        return 0;
      });
      if (offset > 0) rows = rows.slice(offset);
      if (limit > 0) rows = rows.slice(0, limit);
      res.end(JSON.stringify(rows));
    } else if (req.method === 'POST') {
      const body = await readBody(req);
      const obj = JSON.parse(body || '{}');
      const row = { ...obj };
      if (table === 'users' && !row.id) row.id = randomUUID();
      if (table === 'sections' && !row.id) row.id = randomUUID();
      if (!row.created_at) row.created_at = now();
      db[table].push(row);
      res.end(JSON.stringify([row]));
    } else if (req.method === 'PATCH') {
      const body = await readBody(req);
      const obj = JSON.parse(body || '{}');
      const rows = db[table].filter(r => match(r, filters));
      rows.forEach(r => Object.assign(r, obj));
      res.end(JSON.stringify(rows));
    } else if (req.method === 'DELETE') {
      const kept = [];
      const gone = [];
      db[table].forEach(r => (match(r, filters) ? gone.push(r) : kept.push(r)));
      db[table] = kept;

      if (table === 'users') {
        const ids = new Set(gone.map(g => g.id));
        db.sections = db.sections.filter(s => !ids.has(s.user_id));
        db.sessions = db.sessions.filter(s => !ids.has(s.user_id));
      }
      res.end(JSON.stringify(gone));
    } else {
      res.statusCode = 405; res.end('[]');
    }
  };
}

function readBody(req) {
  return new Promise((ok, no) => {
    let d = '';
    req.on('data', c => { d += c; });
    req.on('end', () => ok(d));
    req.on('error', no);
  });
}

module.exports = { db, tableHandler };
