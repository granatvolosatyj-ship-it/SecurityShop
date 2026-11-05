const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const BOT_TOKEN = process.env.BOT_TOKEN || '';
const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
const MANAGER = (process.env.MANAGER_USERNAME || '').replace('@', '').trim();
const TIKTOK_URL = process.env.TIKTOK_URL || '';
const SHOP_NAME = process.env.SHOP_NAME || 'SecurityShop';
const BASE_URL = (process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || '').replace(/\/$/, '');
const PORT = process.env.PORT || 3000;
const HOOK = crypto.createHash('sha256').update(BOT_TOKEN).digest('hex').slice(0, 32);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    create table if not exists products (
      id serial primary key,
      title_ru text not null default '',
      title_en text not null default '',
      desc_ru text not null default '',
      desc_en text not null default '',
      price integer not null default 0,
      category text not null default '',
      sizes text not null default '',
      sold boolean not null default false,
      created_at timestamptz not null default now()
    );
    create table if not exists photos (
      id serial primary key,
      product_id integer not null references products(id) on delete cascade,
      position integer not null default 0,
      mime text not null,
      data bytea not null
    );
    create index if not exists photos_product_idx on photos(product_id);
    create table if not exists favorites (
      user_id bigint not null,
      product_id integer not null references products(id) on delete cascade,
      primary key (user_id, product_id)
    );
  `);
}

// ---------- Telegram auth ----------
function verifyInitData(raw) {
  if (!raw || !BOT_TOKEN) return null;
  const p = new URLSearchParams(raw);
  const hash = p.get('hash');
  if (!hash) return null;
  p.delete('hash');
  const str = [...p.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const calc = crypto.createHmac('sha256', secret).update(str).digest('hex');
  if (calc.length !== hash.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(hash))) return null;
  const age = Date.now() / 1000 - Number(p.get('auth_date') || 0);
  if (age > 7 * 86400) return null;
  try {
    return JSON.parse(p.get('user'));
  } catch {
    return null;
  }
}

const h = fn => (req, res, next) => fn(req, res, next).catch(next);

function auth(req, _res, next) {
  req.user = verifyInitData(req.get('X-Init-Data'));
  next();
}
function requireUser(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'auth' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user || !ADMIN_IDS.includes(String(req.user.id))) return res.status(403).json({ error: 'forbidden' });
  next();
}

// ---------- helpers ----------
async function listProducts() {
  const { rows } = await pool.query(`
    select p.*,
      coalesce((select array_agg(id order by position, id) from photos where product_id = p.id), '{}') as photos
    from products p
    order by p.sold asc, p.created_at desc, p.id desc
  `);
  return rows.map(r => ({
    id: r.id,
    title_ru: r.title_ru,
    title_en: r.title_en,
    desc_ru: r.desc_ru,
    desc_en: r.desc_en,
    price: r.price,
    category: r.category,
    sizes: r.sizes,
    sold: r.sold,
    photos: r.photos,
  }));
}

async function saveProduct(id, b) {
  const c = await pool.connect();
  try {
    await c.query('begin');
    const f = [
      String(b.title_ru || '').trim(),
      String(b.title_en || '').trim(),
      String(b.desc_ru || '').trim(),
      String(b.desc_en || '').trim(),
      Math.max(0, parseInt(b.price, 10) || 0),
      String(b.category || '').trim(),
      String(b.sizes || '').trim(),
      !!b.sold,
    ];
    if (!f[0] && !f[1]) throw new Error('title required');
    if (id) {
      await c.query(
        'update products set title_ru=$1,title_en=$2,desc_ru=$3,desc_en=$4,price=$5,category=$6,sizes=$7,sold=$8 where id=$9',
        [...f, id]
      );
    } else {
      const r = await c.query(
        'insert into products(title_ru,title_en,desc_ru,desc_en,price,category,sizes,sold) values($1,$2,$3,$4,$5,$6,$7,$8) returning id',
        f
      );
      id = r.rows[0].id;
    }
    const list = Array.isArray(b.photos) ? b.photos.slice(0, 10) : [];
    const keep = list.filter(x => x && x.id).map(x => Number(x.id));
    await c.query('delete from photos where product_id=$1 and not (id = any($2::int[]))', [id, keep]);
    let pos = 0;
    for (const ph of list) {
      if (ph && ph.id) {
        await c.query('update photos set position=$1 where id=$2 and product_id=$3', [pos, Number(ph.id), id]);
      } else if (ph && ph.data) {
        const m = /^data:(image\/[a-z+]+);base64,(.+)$/.exec(ph.data);
        if (!m) continue;
        await c.query('insert into photos(product_id,position,mime,data) values($1,$2,$3,$4)', [
          id,
          pos,
          m[1],
          Buffer.from(m[2], 'base64'),
        ]);
      } else {
        continue;
      }
      pos++;
    }
    await c.query('commit');
    return id;
  } catch (e) {
    await c.query('rollback');
    throw e;
  } finally {
    c.release();
  }
}

// ---------- app ----------
const app = express();
app.use(express.json({ limit: '60mb' }));
app.use(auth);

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/health', (_req, res) => res.send('ok'));

app.get('/img/:id', h(async (req, res) => {
  const { rows } = await pool.query('select mime, data from photos where id=$1', [Number(req.params.id)]);
  if (!rows[0]) return res.sendStatus(404);
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.type(rows[0].mime).send(rows[0].data);
}));

app.get('/api/bootstrap', h(async (req, res) => {
  const products = await listProducts();
  let favorites = [];
  if (req.user) {
    const r = await pool.query('select product_id from favorites where user_id=$1', [req.user.id]);
    favorites = r.rows.map(x => x.product_id);
  }
  res.json({
    config: { shop: SHOP_NAME, manager: MANAGER, tiktok: TIKTOK_URL },
    isAdmin: !!req.user && ADMIN_IDS.includes(String(req.user.id)),
    favorites,
    products,
  });
}));

app.get('/api/products', h(async (_req, res) => res.json(await listProducts())));

app.post('/api/favorites/:id', requireUser, h(async (req, res) => {
  const pid = Number(req.params.id);
  const del = await pool.query('delete from favorites where user_id=$1 and product_id=$2', [req.user.id, pid]);
  if (!del.rowCount) {
    await pool.query('insert into favorites(user_id, product_id) values($1,$2) on conflict do nothing', [req.user.id, pid]);
  }
  res.json({ ok: true, on: !del.rowCount });
}));

app.post('/api/admin/products', requireAdmin, h(async (req, res) => res.json({ id: await saveProduct(null, req.body) })));
app.put('/api/admin/products/:id', requireAdmin, h(async (req, res) =>
  res.json({ id: await saveProduct(Number(req.params.id), req.body) })));
app.patch('/api/admin/products/:id/sold', requireAdmin, h(async (req, res) => {
  await pool.query('update products set sold = not sold where id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
}));
app.delete('/api/admin/products/:id', requireAdmin, h(async (req, res) => {
  await pool.query('delete from products where id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

// ---------- bot (webhook) ----------
const tg = (method, body) =>
  fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }).then(r => r.json());

app.post('/tg/' + HOOK, async (req, res) => {
  res.sendStatus(200);
  try {
    const m = req.body && req.body.message;
    if (m && typeof m.text === 'string' && m.text.startsWith('/start')) {
      await tg('sendMessage', {
        chat_id: m.chat.id,
        text: `👋 Добро пожаловать в ${SHOP_NAME}!\nОдежда в наличии — листайте и пишите менеджеру.\n\nWelcome to ${SHOP_NAME}! Browse the items in stock and message the manager.`,
        reply_markup: {
          inline_keyboard: [[{ text: '🛍 Открыть магазин / Open shop', web_app: { url: BASE_URL } }]],
        },
      });
    }
  } catch (e) {
    console.error('bot error', e);
  }
});

async function setupBot() {
  const a = await tg('setWebhook', { url: `${BASE_URL}/tg/${HOOK}`, allowed_updates: ['message'] });
  const b = await tg('setChatMenuButton', {
    menu_button: { type: 'web_app', text: 'Магазин', web_app: { url: BASE_URL } },
  });
  console.log('webhook:', JSON.stringify(a), 'menu:', JSON.stringify(b));
}

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: String(err.message || err) });
});

(async () => {
  await initDb();
  app.listen(PORT, () => console.log('listening on', PORT));
  if (BOT_TOKEN && BASE_URL) await setupBot().catch(e => console.error('setupBot', e));
  else console.log('BOT_TOKEN or BASE_URL missing: bot webhook not configured');
})();
