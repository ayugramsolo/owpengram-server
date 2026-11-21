import crypto from 'node:crypto';

const { BOT_TOKEN, BOT_API, SESSION_SECRET } = process.env;
const API = `${BOT_API}/bot${BOT_TOKEN}`;
const codes = new Map();   // code -> {userId, name, exp}
const hits = new Map();    // ip -> {n, reset}

async function bot(method, body = {}) {
  const r = await fetch(`${API}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return r.json();
}

export async function pollBot(log) {
  let offset = 0;
  for (;;) {
    try {
      const res = await bot('getUpdates', { offset, timeout: 25 });
      for (const u of res.result ?? []) {
        offset = u.update_id + 1;
        const m = u.message;
        if (!m?.text || !m.text.startsWith('/start')) continue;
        const code = String(crypto.randomInt(100000, 1000000));
        codes.set(code, { userId: m.from.id, name: m.from.first_name || '', exp: Date.now() + 300000 });
        await bot('sendMessage', {
          chat_id: m.chat.id,
          text: `Код для входа на ExMent: ${code}\nДействует 5 минут. Никому его не сообщайте.`,
        });
      }
    } catch (e) {
      log.error(e);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
}

const sign = p => crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('base64url');

export function readSession(req) {
  const c = /(?:^|; )exment_session=([^;]+)/.exec(req.headers.cookie || '')?.[1];
  if (!c) return null;
  const [p, s] = c.split('.');
  if (!p || !s || sign(p) !== s) return null;
  const d = JSON.parse(Buffer.from(p, 'base64url').toString());
  return d.exp > Date.now() ? d : null;
}

export function registerAuth(app) {
  app.post('/api/auth/verify', async (req, reply) => {
    const ip = req.ip, now = Date.now();
    const h = hits.get(ip);
    if (!h || h.reset < now) hits.set(ip, { n: 1, reset: now + 60000 });
    else if (++h.n > 5) return reply.code(429).send({ error: 'too many attempts' });

    const code = String(req.body?.code || '').trim();
    const e = codes.get(code);
    if (!e || e.exp < now) return reply.code(401).send({ error: 'invalid code' });
    codes.delete(code);

    const p = Buffer.from(JSON.stringify({ uid: e.userId, name: e.name, exp: now + 7 * 864e5 })).toString('base64url');
    reply.header('set-cookie', `exment_session=${p}.${sign(p)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7 * 86400}`);
    return { ok: true };
  });

  app.get('/api/me', async (req, reply) => {
    const s = readSession(req);
    return s ? { uid: s.uid, name: s.name } : reply.code(401).send({ error: 'unauthorized' });
  });

  app.post('/api/auth/logout', async (_q, reply) => {
    reply.header('set-cookie', 'exment_session=; HttpOnly; Path=/; Max-Age=0');
    return { ok: true };
  });
}
