const http = require('http');
const fs = require('fs');
const path = require('path');
const { db, tableHandler } = require('./dev-mock-supabase.js');

const ROOT = __dirname;
const PORT = parseInt(process.argv[2] || process.env.PORT || '8080', 10);

const useMock = !process.env.SUPABASE_URL;
const MOCK_BASE = `http://127.0.0.1:${PORT}/__mock`;
if (useMock) {
  process.env.SUPABASE_URL = MOCK_BASE;
  process.env.SUPABASE_SERVICE_KEY = 'test-key';
  console.log('[dev] no SUPABASE_URL -> using in-memory mock. seed admin/admin');
}

const auth = require(path.join(ROOT, 'api/auth.js'));
const admin = require(path.join(ROOT, 'api/admin.js'));
const sections = require(path.join(ROOT, 'api/sections.js'));
const health = require(path.join(ROOT, 'api/health.js'));
const sub = require(path.join(ROOT, 'api/sub/[data].js'));

const usersH = tableHandler('users');
const sessionsH = tableHandler('sessions');
const sectionsH = tableHandler('sections');

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.json': 'application/json', '.css': 'text/css' };

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');

    if (u.pathname.startsWith('/__mock/rest/v1/')) {
      const t = u.pathname.split('/').pop();
      if (t === 'users') return usersH(req, res, u.search.slice(1));
      if (t === 'sessions') return sessionsH(req, res, u.search.slice(1));
      if (t === 'sections') return sectionsH(req, res, u.search.slice(1));
      res.statusCode = 404; return res.end('[]');
    }
    if (u.pathname === '/__mock/db') {
      res.setHeader('Content-Type', 'application/json');
      return res.end(JSON.stringify({ users: db.users.length, sessions: db.sessions.length, sections: db.sections.length }));
    }

    if (u.pathname === '/api/auth') return auth(req, res);
    if (u.pathname === '/api/admin') return admin(req, res);
    if (u.pathname === '/api/sections') return sections(req, res);
    if (u.pathname === '/api/health') return health(req, res);
    if (u.pathname.startsWith('/api/sub/') || u.pathname.startsWith('/s/')) {
      req.url = u.pathname + u.search;
      return sub(req, res);
    }

    let f = u.pathname === '/' ? '/public/index.html' : u.pathname;
    let fp = path.join(ROOT, decodeURIComponent(f.split('?')[0]));
    const rel = path.relative(ROOT, fp);
    if (rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) { res.statusCode = 403; return res.end('no'); }
    if (fs.existsSync(fp) && fs.statSync(fp).isFile()) {
      res.setHeader('Content-Type', MIME[path.extname(fp)] || 'application/octet-stream');
      return fs.createReadStream(fp).pipe(res);
    }
    res.statusCode = 404; res.end('not found');
  } catch (e) {
    console.error(e);
    try { res.statusCode = 500; res.end('error'); } catch (_) {}
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[dev] up on http://127.0.0.1:${PORT}  (mock:${useMock ? 'on' : 'off'})`);
});
