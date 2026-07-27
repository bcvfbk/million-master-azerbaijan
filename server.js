'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const ENV_FILE = path.join(ROOT, '.env');
if (fs.existsSync(ENV_FILE)) {
  for (const line of fs.readFileSync(ENV_FILE, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
    const index = trimmed.indexOf('=');
    const key = trimmed.slice(0, index).trim();
    const value = trimmed.slice(index + 1).trim().replace(/^['\"]|['\"]$/g, '');
    if (!(key in process.env)) process.env[key] = value;
  }
}

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'private.json');
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || '2020202икслмилионмастераз';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const loginAttempts = new Map();

fs.mkdirSync(DATA_DIR, { recursive: true });

function defaultData() {
  return {
    payoutSettings: {
      provider: 'iyzico', recipientName: '', iban: '', payoutEmail: '',
      businessName: 'Million Master', taxNumber: '', note: ''
    },
    stats: { activePlan: 'Demo', totalXp: 0, completedTasks: 0, prizeWins: 0 }
  };
}
function readData() {
  try {
    if (!fs.existsSync(DATA_FILE)) writeData(defaultData());
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch { return defaultData(); }
}
function writeData(data) {
  const temp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(temp, DATA_FILE);
}
function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    ...extraHeaders
  });
  res.end(JSON.stringify(body));
}
function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(v => {
    const i = v.indexOf('=');
    return [v.slice(0, i).trim(), decodeURIComponent(v.slice(i + 1))];
  }));
}
function base64url(input) { return Buffer.from(input).toString('base64url'); }
function signSession(payload) {
  const body = base64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifySession(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (payload.exp < Date.now() || payload.role !== 'owner') return null;
  return payload;
}
function passwordMatches(input) {
  const salt = 'million-master-owner-v7';
  const a = crypto.scryptSync(String(input), salt, 64);
  const b = crypto.scryptSync(OWNER_PASSWORD, salt, 64);
  return crypto.timingSafeEqual(a, b);
}
function readBody(req, limit = 100_000) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > limit) { reject(new Error('Payload too large')); req.destroy(); }
    });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Invalid JSON')); }
    });
  });
}
function requireOwner(req, res) {
  const session = verifySession(parseCookies(req).mm_owner_session);
  if (!session) { json(res, 401, { error: 'Требуется вход владельца.' }); return null; }
  return session;
}
function secureCookie(token) {
  return `mm_owner_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${IS_PRODUCTION ? '; Secure' : ''}`;
}
function clean(value, max = 300) { return String(value || '').trim().slice(0, max); }

async function handleApi(req, res, url) {
  const ip = req.socket.remoteAddress || 'unknown';
  if (req.method === 'POST' && url.pathname === '/api/owner/login') {
    const now = Date.now();
    const recent = (loginAttempts.get(ip) || []).filter(t => now - t < 15 * 60 * 1000);
    if (recent.length >= 8) return json(res, 429, { error: 'Слишком много попыток. Повторите позже.' });
    let body; try { body = await readBody(req); } catch { return json(res, 400, { error: 'Некорректный запрос.' }); }
    if (!passwordMatches(body.password)) {
      recent.push(now); loginAttempts.set(ip, recent);
      return json(res, 401, { error: 'Неверный код владельца.' });
    }
    loginAttempts.delete(ip);
    const token = signSession({ sub: 'owner', role: 'owner', exp: now + 8 * 60 * 60 * 1000 });
    return json(res, 200, { ok: true }, { 'Set-Cookie': secureCookie(token) });
  }
  if (req.method === 'POST' && url.pathname === '/api/owner/logout') {
    return json(res, 200, { ok: true }, { 'Set-Cookie': 'mm_owner_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }
  if (req.method === 'GET' && url.pathname === '/api/owner/dashboard') {
    if (!requireOwner(req, res)) return;
    const data = readData();
    return json(res, 200, { stats: data.stats, payoutSettings: data.payoutSettings });
  }
  if (req.method === 'PUT' && url.pathname === '/api/owner/payout-settings') {
    if (!requireOwner(req, res)) return;
    let body; try { body = await readBody(req); } catch { return json(res, 400, { error: 'Некорректный запрос.' }); }
    const providers = ['iyzico', 'Stripe', 'PayPal', 'Paddle', 'Банковский эквайринг'];
    if (!providers.includes(body.provider)) return json(res, 400, { error: 'Неизвестный платёжный провайдер.' });
    const data = readData();
    data.payoutSettings = {
      provider: body.provider,
      recipientName: clean(body.recipientName),
      iban: clean(body.iban, 42).replace(/[^A-Za-z0-9 ]/g, ''),
      payoutEmail: clean(body.payoutEmail),
      businessName: clean(body.businessName),
      taxNumber: clean(body.taxNumber),
      note: clean(body.note)
    };
    writeData(data);
    return json(res, 200, { ok: true });
  }
  if (req.method === 'GET' && url.pathname === '/api/health') return json(res, 200, { ok: true });
  return json(res, 404, { error: 'API endpoint not found.' });
}

const mime = { '.html':'text/html; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.css':'text/css; charset=utf-8', '.json':'application/json; charset=utf-8', '.png':'image/png', '.jpg':'image/jpeg', '.svg':'image/svg+xml', '.ico':'image/x-icon' };
function serveStatic(req, res, url) {
  let relative = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
  let file = path.normalize(path.join(ROOT, relative));
  if (!file.startsWith(ROOT) || file.includes(`${path.sep}data${path.sep}`) || path.basename(file).startsWith('.')) {
    res.writeHead(403); return res.end('Forbidden');
  }
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(ROOT, 'index.html');
  const ext = path.extname(file).toLowerCase();
  res.writeHead(200, {
    'Content-Type': mime[ext] || 'application/octet-stream',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
  });
  fs.createReadStream(file).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    return serveStatic(req, res, url);
  } catch (error) {
    console.error(error);
    return json(res, 500, { error: 'Внутренняя ошибка сервера.' });
  }
});
server.listen(PORT, () => {
  console.log(`Million Master: http://localhost:${PORT}`);
  if (!process.env.SESSION_SECRET) console.warn('Для публикации задайте SESSION_SECRET в переменных окружения.');
});
