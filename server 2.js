const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const BOT_TOKEN = process.env.BOT_TOKEN || '';
const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
const MANAGER = (process.env.MANAGER_USERNAME || '').replace('@', '').trim();
const TIKTOK_DEFAULT = 'https://www.tiktok.com/@security_store1';
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
    alter table products add column if not exists brand text not null default '';
    alter table products add column if not exists old_price integer not null default 0;
    create table if not exists brands (
      id serial primary key, name text not null unique, position integer not null default 0
    );
    create table if not exists assets (
      id serial primary key, mime text not null, data bytea not null
    );
    create table if not exists banners (
      id serial primary key, position integer not null default 0,
      title_ru text not null default '', title_en text not null default '',
      text_ru text not null default '', text_en text not null default '',
      target text not null default '',
      asset_id integer references assets(id) on delete set null
    );
    create table if not exists settings (key text primary key, value text not null default '');
    create table if not exists prizes (
      id serial primary key, kind text not null, value integer not null,
      weight integer not null default 1, active boolean not null default true
    );
    create table if not exists spins (
      id serial primary key, user_id bigint not null, user_name text not null default '',
      prize_kind text not null, prize_value integer not null,
      product_id integer references products(id) on delete set null,
      product_title text not null default '', code text not null,
      test boolean not null default false, redeemed boolean not null default false,
      created_at timestamptz not null default now(), expires_at timestamptz not null
    );
    create index if not exists spins_user_idx on spins(user_id, created_at desc);
  `);
  const b = await pool.query('select count(*)::int n from brands');
  if (!b.rows[0].n) {
    const names = ['Raf Simons', 'Jeremy Scott', 'Nike', 'Off-White', 'Jordan', 'Saint Laurent', 'BAPE', 'Maison Margiela'];
    for (let i = 0; i < names.length; i++) await pool.query('insert into brands(name,position) values($1,$2)', [names[i], i]);
  }
  const p = await pool.query('select count(*)::int n from prizes');
  if (!p.rows[0].n) {
    const d = [['rub', 100, 40], ['rub', 200, 25], ['rub', 500, 12], ['rub', 1000, 5], ['percent', 5, 10], ['percent', 10, 6], ['percent', 25, 2]];
    for (const x of d) await pool.query('insert into prizes(kind,value,weight) values($1,$2,$3)', x);
  }
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
    old_price: r.old_price,
    brand: r.brand,
    created_at: r.created_at,
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
      String(b.brand || '').trim(),
      Math.max(0, parseInt(b.old_price, 10) || 0),
    ];
    if (!f[0] && !f[1]) throw new Error('title required');
    if (id) {
      await c.query(
        'update products set title_ru=$1,title_en=$2,desc_ru=$3,desc_en=$4,price=$5,category=$6,sizes=$7,sold=$8,brand=$9,old_price=$10 where id=$11',
        [...f, id]
      );
    } else {
      const r = await c.query(
        'insert into products(title_ru,title_en,desc_ru,desc_en,price,category,sizes,sold,brand,old_price) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning id',
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

const isAdminUser = u => !!u && ADMIN_IDS.includes(String(u.id));

function parseData(d) {
  const m = /^data:(image\/[a-z+]+);base64,(.+)$/.exec(d || '');
  return m ? { mime: m[1], buf: Buffer.from(m[2], 'base64') } : null;
}
async function newAsset(d) {
  const p = parseData(d);
  if (!p) return null;
  const r = await pool.query('insert into assets(mime,data) values($1,$2) returning id', [p.mime, p.buf]);
  return r.rows[0].id;
}
async function getSettings() {
  const r = await pool.query('select key,value from settings');
  const o = {};
  r.rows.forEach(x => (o[x.key] = x.value));
  return o;
}
const setSetting = (k, v) =>
  pool.query('insert into settings(key,value) values($1,$2) on conflict (key) do update set value=excluded.value', [k, v]);

const spinOut = r => r && ({
  id: r.id, prize_kind: r.prize_kind, prize_value: r.prize_value, product_id: r.product_id,
  product_title: r.product_title, code: r.code, test: r.test, redeemed: r.redeemed,
  created_at: r.created_at, expires_at: r.expires_at, user_name: r.user_name,
});
async function lastSpin(uid) {
  const r = await pool.query('select * from spins where user_id=$1 order by created_at desc, id desc limit 1', [uid]);
  return spinOut(r.rows[0]) || null;
}

app.get('/asset/:id', h(async (req, res) => {
  const { rows } = await pool.query('select mime, data from assets where id=$1', [Number(req.params.id)]);
  if (!rows[0]) return res.sendStatus(404);
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.type(rows[0].mime).send(rows[0].data);
}));

app.get('/api/bootstrap', h(async (req, res) => {
  const [products, brands, banners, prizes, st] = await Promise.all([
    listProducts(),
    pool.query('select id,name from brands order by position, id'),
    pool.query('select id,title_ru,title_en,text_ru,text_en,target,asset_id from banners order by position, id'),
    pool.query('select id,kind,value from prizes where active order by value desc, id'),
    getSettings(),
  ]);
  let favorites = [];
  let spin = null;
  if (req.user) {
    const r = await pool.query('select product_id from favorites where user_id=$1', [req.user.id]);
    favorites = r.rows.map(x => x.product_id);
    spin = await lastSpin(req.user.id);
  }
  const wp = Number(st.wheel_product) || 0;
  res.json({
    config: { shop: SHOP_NAME, manager: MANAGER, tiktok: st.tiktok || TIKTOK_DEFAULT },
    isAdmin: isAdminUser(req.user),
    favorites,
    products,
    brands: brands.rows,
    banners: banners.rows,
    prizes: prizes.rows,
    home: { cover: Number(st.cover) || null, wheelProduct: products.some(p => p.id === wp) ? wp : null },
    spin,
  });
}));

// ---------- prize wheel ----------
app.get('/api/wheel/me', requireUser, h(async (req, res) => res.json({ spin: await lastSpin(req.user.id) })));

app.post('/api/wheel/spin', requireUser, h(async (req, res) => {
  const uid = req.user.id;
  const adm = isAdminUser(req.user);
  const c = await pool.connect();
  try {
    await c.query('begin');
    await c.query('select pg_advisory_xact_lock($1)', [uid]);
    const st = await c.query("select value from settings where key='wheel_product'");
    const pid = Number(st.rows[0] && st.rows[0].value) || 0;
    const pr = pid ? (await c.query('select id,title_ru,title_en,sold from products where id=$1', [pid])).rows[0] : null;
    if (!pr || pr.sold) { await c.query('rollback'); return res.status(409).json({ error: 'closed' }); }
    if (!adm) {
      const l = await c.query('select created_at from spins where user_id=$1 and not test order by created_at desc limit 1', [uid]);
      if (l.rows[0] && Date.now() - new Date(l.rows[0].created_at).getTime() < 86400000) {
        await c.query('rollback');
        return res.status(429).json({ error: 'cooldown' });
      }
    }
    const pz = (await c.query('select * from prizes where active')).rows;
    if (!pz.length) { await c.query('rollback'); return res.status(409).json({ error: 'closed' }); }
    const total = pz.reduce((s, p) => s + p.weight, 0);
    let r = crypto.randomInt(total);
    let pick = pz[pz.length - 1];
    for (const p of pz) { if (r < p.weight) { pick = p; break; } r -= p.weight; }
    const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 6; i++) code += A[crypto.randomInt(A.length)];
    const u = req.user;
    const name = ([u.first_name, u.last_name].filter(Boolean).join(' ') + (u.username ? ' @' + u.username : '')).trim();
    const ins = await c.query(
      `insert into spins(user_id,user_name,prize_kind,prize_value,product_id,product_title,code,test,expires_at)
       values($1,$2,$3,$4,$5,$6,$7,$8, now() + interval '24 hours') returning *`,
      [uid, name, pick.kind, pick.value, pr.id, pr.title_ru || pr.title_en, code, adm]
    );
    await c.query('commit');
    res.json({ spin: spinOut(ins.rows[0]), prizeId: pick.id });
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
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

// ---------- admin: home, brands, banners, wheel ----------
app.put('/api/admin/settings', requireAdmin, h(async (req, res) => {
  const b = req.body || {};
  if (typeof b.tiktok === 'string') await setSetting('tiktok', b.tiktok.trim());
  if ('wheel_product' in b) await setSetting('wheel_product', String(Number(b.wheel_product) || ''));
  if (b.cover !== undefined) {
    const old = Number((await getSettings()).cover) || 0;
    let nid = '';
    if (b.cover) nid = String((await newAsset(b.cover)) || '');
    if (b.cover === null || nid) {
      await setSetting('cover', nid);
      if (old) await pool.query('delete from assets where id=$1', [old]);
    }
  }
  res.json({ ok: true });
}));

app.post('/api/admin/brands', requireAdmin, h(async (req, res) => {
  const name = String((req.body || {}).name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'name' });
  await pool.query(
    'insert into brands(name,position) values($1,(select coalesce(max(position),0)+1 from brands)) on conflict do nothing', [name]);
  res.json({ ok: true });
}));
app.delete('/api/admin/brands/:id', requireAdmin, h(async (req, res) => {
  await pool.query('delete from brands where id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

async function saveBanner(id, b) {
  const f = ['title_ru', 'title_en', 'text_ru', 'text_en'].map(k => String(b[k] || '').trim().slice(0, 200));
  const target = ['catalog', 'sale', 'wheel', 'tiktok'].includes(b.target) ? b.target : '';
  const aid = b.image ? await newAsset(b.image) : null;
  if (id) {
    const old = (await pool.query('select asset_id from banners where id=$1', [id])).rows[0];
    await pool.query('update banners set title_ru=$1,title_en=$2,text_ru=$3,text_en=$4,target=$5 where id=$6', [...f, target, id]);
    if (aid || b.removeImage) {
      await pool.query('update banners set asset_id=$1 where id=$2', [aid, id]);
      if (old && old.asset_id) await pool.query('delete from assets where id=$1', [old.asset_id]);
    }
  } else {
    await pool.query(
      `insert into banners(title_ru,title_en,text_ru,text_en,target,asset_id,position)
       values($1,$2,$3,$4,$5,$6,(select coalesce(max(position),0)+1 from banners))`, [...f, target, aid]);
  }
}
app.post('/api/admin/banners', requireAdmin, h(async (req, res) => { await saveBanner(null, req.body || {}); res.json({ ok: true }); }));
app.put('/api/admin/banners/:id', requireAdmin, h(async (req, res) => { await saveBanner(Number(req.params.id), req.body || {}); res.json({ ok: true }); }));
app.delete('/api/admin/banners/:id', requireAdmin, h(async (req, res) => {
  const old = (await pool.query('delete from banners where id=$1 returning asset_id', [Number(req.params.id)])).rows[0];
  if (old && old.asset_id) await pool.query('delete from assets where id=$1', [old.asset_id]);
  res.json({ ok: true });
}));

app.get('/api/admin/prizes', requireAdmin, h(async (_req, res) =>
  res.json((await pool.query('select id,kind,value,weight,active from prizes order by value desc, id')).rows)));
app.post('/api/admin/prizes', requireAdmin, h(async (req, res) => {
  const b = req.body || {};
  const kind = b.kind === 'percent' ? 'percent' : 'rub';
  const value = Math.max(1, parseInt(b.value, 10) || 0);
  const weight = Math.max(1, parseInt(b.weight, 10) || 1);
  await pool.query('insert into prizes(kind,value,weight) values($1,$2,$3)', [kind, value, weight]);
  res.json({ ok: true });
}));
app.patch('/api/admin/prizes/:id/active', requireAdmin, h(async (req, res) => {
  await pool.query('update prizes set active = not active where id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
}));
app.delete('/api/admin/prizes/:id', requireAdmin, h(async (req, res) => {
  await pool.query('delete from prizes where id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
}));
app.get('/api/admin/spins', requireAdmin, h(async (_req, res) =>
  res.json((await pool.query('select * from spins order by created_at desc, id desc limit 200')).rows.map(spinOut))));
app.patch('/api/admin/spins/:id/redeem', requireAdmin, h(async (req, res) => {
  await pool.query('update spins set redeemed = not redeemed where id=$1', [Number(req.params.id)]);
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
