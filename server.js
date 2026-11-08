const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const BOT_TOKEN = process.env.BOT_TOKEN || '';
const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
const MANAGER = (process.env.MANAGER_USERNAME || '').replace('@', '').trim();
const TIKTOK_DEFAULT = 'https://www.tiktok.com/@security_store1';
const SHOP_NAME = process.env.SHOP_NAME || 'SecurityShop';
let BOT_USERNAME = process.env.BOT_USERNAME || 'securityshop_nalichie_bot';
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
    create table if not exists events (
      id serial primary key, user_id bigint not null, user_name text not null default '',
      kind text not null, product_id integer, created_at timestamptz not null default now()
    );
    create index if not exists events_kind_idx on events(kind, created_at desc);
    alter table favorites add column if not exists price_at integer;
    update favorites f set price_at = p.price from products p where f.product_id = p.id and f.price_at is null;
    alter table products add column if not exists cond text not null default '';
    create table if not exists referrals (
      invitee bigint primary key, inviter bigint not null, created_at timestamptz not null default now()
    );
    create table if not exists coupons (
      id serial primary key, code text not null unique, user_id bigint not null,
      kind text not null, amount integer not null default 500, friend_name text not null default '',
      used boolean not null default false, created_at timestamptz not null default now()
    );
    create index if not exists coupons_user_idx on coupons(user_id);
    create table if not exists bot_users (
      user_id bigint primary key, name text not null default '', blocked boolean not null default false,
      created_at timestamptz not null default now()
    );
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
    cond: r.cond,
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
      ['new', 'excellent', 'good', 'fair'].includes(b.cond) ? b.cond : '',
    ];
    if (!f[0] && !f[1]) throw new Error('title required');
    if (id) {
      await c.query(
        'update products set title_ru=$1,title_en=$2,desc_ru=$3,desc_en=$4,price=$5,category=$6,sizes=$7,sold=$8,brand=$9,old_price=$10,cond=$11 where id=$12',
        [...f, id]
      );
    } else {
      const r = await c.query(
        'insert into products(title_ru,title_en,desc_ru,desc_en,price,category,sizes,sold,brand,old_price,cond) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) returning id',
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
  let favPrices = {};
  let spin = null;
  let coupons = [];
  if (req.user) {
    coupons = (await pool.query('select code,kind,amount,friend_name from coupons where user_id=$1 and not used order by id', [req.user.id])).rows;
    const r = await pool.query('select product_id, price_at from favorites where user_id=$1', [req.user.id]);
    favorites = r.rows.map(x => x.product_id);
    favPrices = Object.fromEntries(r.rows.map(x => [x.product_id, x.price_at]));
    spin = await lastSpin(req.user.id);
  }
  const wp = Number(st.wheel_product) || 0;
  res.json({
    config: { shop: SHOP_NAME, manager: MANAGER, tiktok: st.tiktok || TIKTOK_DEFAULT, bot: BOT_USERNAME },
    isAdmin: isAdminUser(req.user),
    favorites,
    favPrices,
    products,
    brands: brands.rows,
    banners: banners.rows,
    prizes: prizes.rows,
    home: { saleMax: Number(st.sale_max) || 80, cover: Number(st.cover) || null, coverSale: Number(st.cover_sale) || null, coverWheel: Number(st.cover_wheel) || null, bnTiktok: Number(st.bn_tiktok) || null, bnWheel: Number(st.bn_wheel) || null, bnInvite: Number(st.bn_invite) || null, wheelProduct: products.some(p => p.id === wp) ? wp : null },
    spin,
    coupons,
    refAmount: Number(st.ref_amount) || 500,
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
    if (!adm) notifyAdmins(`🎡 ${name || 'Покупатель'} выиграл ${pick.kind === 'percent' ? '-' + pick.value + '%' : '-' + pick.value + ' ₽'} на «${pr.title_ru || pr.title_en}». Код: ${code}`);
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
    await pool.query('insert into favorites(user_id, product_id, price_at) select $1, id, price from products where id=$2 on conflict do nothing', [req.user.id, pid]);
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

app.patch('/api/admin/products/:id/price', requireAdmin, h(async (req, res) => {
  const p = Math.max(0, parseInt((req.body || {}).price, 10) || 0);
  const o = Math.max(0, parseInt((req.body || {}).old_price, 10) || 0);
  await pool.query('update products set price=$1, old_price=$2 where id=$3', [p, o, Number(req.params.id)]);
  res.json({ ok: true });
}));

// ---------- tracking, stats, notifications ----------
function userName(u) {
  return ([u.first_name, u.last_name].filter(Boolean).join(' ') + (u.username ? ' @' + u.username : '')).trim();
}
function notifyAdmins(text) {
  if (!BOT_TOKEN) return;
  for (const id of ADMIN_IDS) tg('sendMessage', { chat_id: id, text }).catch(() => {});
}
app.post('/api/track', requireUser, h(async (req, res) => {
  const b = req.body || {};
  const kind = ['open', 'view', 'msg', 'share'].includes(b.kind) ? b.kind : null;
  if (!kind) return res.json({ ok: true });
  const pid = Number(b.product_id) || null;
  const u = req.user;
  let dup = false;
  if (kind === 'msg' && pid) {
    const d = await pool.query(
      "select 1 from events where user_id=$1 and kind='msg' and product_id=$2 and created_at > now() - interval '10 minutes' limit 1", [u.id, pid]);
    dup = !!d.rowCount;
  }
  await pool.query('insert into events(user_id,user_name,kind,product_id) values($1,$2,$3,$4)', [u.id, userName(u), kind, pid]);
  if (kind === 'open' && u.allows_write_to_pm) {
    await pool.query('insert into bot_users(user_id,name) values($1,$2) on conflict (user_id) do nothing', [u.id, userName(u)]).catch(() => {});
  }
  if (kind === 'msg' && pid && !dup && !isAdminUser(u)) {
    const p = (await pool.query('select title_ru,title_en from products where id=$1', [pid])).rows[0];
    const size = String(b.size || '').slice(0, 20);
    if (p) notifyAdmins(`💬 ${userName(u) || 'Покупатель'} хочет написать менеджеру по товару «${p.title_ru || p.title_en}»${size ? ', размер ' + size : ''}`);
  }
  res.json({ ok: true });
}));

app.get('/api/admin/stats', requireAdmin, h(async (_req, res) => {
  const ex = ADMIN_IDS.length ? ADMIN_IDS : ['0'];
  const q = sql => pool.query(sql, [ex]);
  const T = "coalesce(nullif(p.title_ru,''), p.title_en)";
  const [u, tv, tm, tf, sp] = await Promise.all([
    q(`select count(distinct user_id) filter (where created_at > now() - interval '24 hours')::int d,
              count(distinct user_id) filter (where created_at > now() - interval '7 days')::int w,
              count(distinct user_id)::int t, count(*)::int opens
       from events where kind='open' and user_id <> all($1::bigint[])`),
    q(`select p.id, ${T} title, count(*)::int n from events e join products p on p.id=e.product_id
       where e.kind='view' and e.created_at > now() - interval '7 days' and e.user_id <> all($1::bigint[])
       group by p.id order by n desc limit 10`),
    q(`select p.id, ${T} title, count(*)::int n from events e join products p on p.id=e.product_id
       where e.kind='msg' and e.created_at > now() - interval '7 days' and e.user_id <> all($1::bigint[])
       group by p.id order by n desc limit 5`),
    q(`select p.id, ${T} title, count(*)::int n from favorites f join products p on p.id=f.product_id
       where f.user_id <> all($1::bigint[]) group by p.id order by n desc limit 5`),
    q(`select count(*)::int total, (count(*) filter (where redeemed))::int red from spins where not test and user_id <> all($1::bigint[])`),
  ]);
  const dl = (await q(`select to_char(created_at at time zone '${TZ}','YYYY-MM-DD') d, count(distinct user_id)::int n, count(*)::int o
    from events where kind='open' and created_at > now() - interval '16 days' and user_id <> all($1::bigint[]) group by 1`)).rows;
  const map = Object.fromEntries(dl.map(r => [r.d, r]));
  const daily = [];
  for (let i = 13; i >= 0; i--) {
    const k = new Date(Date.now() - i * 864e5).toLocaleDateString('sv-SE', { timeZone: TZ });
    daily.push({ d: k.slice(8) + '.' + k.slice(5, 7), n: map[k] ? map[k].n : 0 });
  }
  const refs = (await pool.query('select count(*)::int n from referrals')).rows[0].n;
  const set = await getSettings();
  res.json({ users: u.rows[0], views: tv.rows, msgs: tm.rows, favs: tf.rows, spins: sp.rows[0], daily, refs, dailyOn: set.daily !== '0', refAmount: Number(set.ref_amount) || 500 });
}));

app.patch('/api/admin/banners/:id/move', requireAdmin, h(async (req, res) => {
  const id = Number(req.params.id), dir = Number((req.body || {}).dir) < 0 ? -1 : 1;
  const ids = (await pool.query('select id from banners order by position, id')).rows.map(r => r.id);
  const i = ids.indexOf(id), j = i + dir;
  if (i < 0 || j < 0 || j >= ids.length) return res.json({ ok: true });
  [ids[i], ids[j]] = [ids[j], ids[i]];
  for (let k = 0; k < ids.length; k++) await pool.query('update banners set position=$1 where id=$2', [k, ids[k]]);
  res.json({ ok: true });
}));

let broadcasting = false;
app.get('/api/admin/audience', requireAdmin, h(async (_req, res) => {
  const r = await pool.query('select count(*)::int n from bot_users where not blocked');
  res.json({ count: r.rows[0].n });
}));
app.post('/api/admin/broadcast', requireAdmin, h(async (req, res) => {
  const b = req.body || {};
  const text = String(b.text || '').trim().slice(0, 1000);
  if (!text) return res.status(400).json({ error: 'text' });
  const kb = { inline_keyboard: [[{ text: '🛍 Открыть магазин', web_app: { url: BASE_URL } }]] };
  if (b.test) {
    const r = await tg('sendMessage', { chat_id: req.user.id, text, reply_markup: kb });
    return res.json({ ok: !!r.ok });
  }
  if (broadcasting) return res.status(409).json({ error: 'busy' });
  const users = (await pool.query('select user_id from bot_users where not blocked')).rows.map(r => r.user_id);
  broadcasting = true;
  res.json({ queued: users.length });
  (async () => {
    let ok = 0, fail = 0;
    for (const id of users) {
      try {
        const r = await tg('sendMessage', { chat_id: id, text, reply_markup: kb });
        if (r.ok) ok++;
        else { fail++; if (r.error_code === 403) await pool.query('update bot_users set blocked=true where user_id=$1', [id]); }
      } catch (e) { fail++; }
      await new Promise(r => setTimeout(r, 70));
    }
    broadcasting = false;
    notifyAdmins(`📣 Рассылка завершена: доставлено ${ok}, не доставлено ${fail}`);
  })();
}));

// ---------- admin: home, brands, banners, wheel ----------
app.put('/api/admin/settings', requireAdmin, h(async (req, res) => {
  const b = req.body || {};
  if (typeof b.tiktok === 'string') await setSetting('tiktok', b.tiktok.trim());
  if ('sale_max' in b) await setSetting('sale_max', String(Math.min(99, Math.max(1, parseInt(b.sale_max, 10) || 80))));
  if ('daily' in b) await setSetting('daily', b.daily ? '1' : '0');
  if ('ref_amount' in b) await setSetting('ref_amount', String(Math.min(100000, Math.max(1, parseInt(b.ref_amount, 10) || 500))));
  if ('wheel_product' in b) await setSetting('wheel_product', String(Number(b.wheel_product) || ''));
  for (const k of ['cover', 'cover_sale', 'cover_wheel', 'bn_tiktok', 'bn_wheel', 'bn_invite']) {
    if (b[k] === undefined) continue;
    const old = Number((await getSettings())[k]) || 0;
    let nid = '';
    if (b[k]) nid = String((await newAsset(b[k])) || '');
    if (b[k] === null || nid) {
      await setSetting(k, nid);
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

// ---------- referrals (invite a friend) ----------
const genCode = () => crypto.randomBytes(3).toString('hex').toUpperCase();
app.post('/api/ref', requireUser, h(async (req, res) => {
  const inviter = Number((req.body || {}).inviter), me = req.user.id;
  if (!inviter || inviter === me || ADMIN_IDS.includes(String(me))) return res.json({ created: false });
  const old = await pool.query("select 1 from events where user_id=$1 and created_at < now() - interval '2 minutes' limit 1", [me]);
  const has = await pool.query('select 1 from referrals where invitee=$1', [me]);
  const inv = await pool.query('select 1 from events where user_id=$1 limit 1', [inviter]);
  if (old.rowCount || has.rowCount || !inv.rowCount) return res.json({ created: false });
  const amount = Number((await getSettings()).ref_amount) || 500;
  const name = userName(req.user) || 'Друг';
  await pool.query('insert into referrals(invitee,inviter) values($1,$2) on conflict do nothing', [me, inviter]);
  await pool.query("insert into coupons(code,user_id,kind,amount,friend_name) values($1,$2,'friend',$3,'')", ['F' + genCode(), me, amount]);
  await pool.query("insert into coupons(code,user_id,kind,amount,friend_name) values($1,$2,'inviter',$3,$4)", ['I' + genCode(), inviter, amount, name]);
  notifyAdmins(`🤝 ${name} пришёл по приглашению. Выданы два купона на ${amount} ₽ (ему и пригласившему).`);
  tg('sendMessage', { chat_id: inviter, text: `🎁 ${name} зашёл по вашей ссылке! Вам скидка ${amount} ₽ — откройте магазин, купон уже там.` }).catch(() => {});
  res.json({ created: true, amount });
}));
app.get('/api/admin/coupons', requireAdmin, h(async (_req, res) => {
  const r = await pool.query(`select c.id,c.code,c.kind,c.amount,c.used,c.created_at,c.friend_name,
    coalesce((select user_name from events e where e.user_id=c.user_id order by id desc limit 1),'') uname
    from coupons c order by c.id desc limit 100`);
  res.json(r.rows);
}));
app.patch('/api/admin/coupons/:id/use', requireAdmin, h(async (req, res) => {
  await pool.query('update coupons set used = not used where id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

// ---------- daily summary + weekly backup ----------
const TZ = 'Asia/Yekaterinburg';
const localParts = () => {
  const f = new Intl.DateTimeFormat('sv-SE', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', weekday: 'short', hour12: false });
  const o = {};
  f.formatToParts(new Date()).forEach(x => (o[x.type] = x.value));
  return { day: `${o.year}-${o.month}-${o.day}`, hour: Number(o.hour) % 24, wd: o.weekday };
};
async function dailySummaryText() {
  const ex = ADMIN_IDS.length ? ADMIN_IDS : ['0'];
  const day = "(created_at at time zone '" + TZ + "')::date = (now() at time zone '" + TZ + "')::date";
  const ev = (await pool.query(`select count(distinct user_id) filter (where kind='open')::int u, count(*) filter (where kind='open')::int o,
      count(*) filter (where kind='view')::int v, count(*) filter (where kind='msg')::int m
      from events where ${day} and user_id <> all($1::bigint[])`, [ex])).rows[0];
  const top = (await pool.query(`select coalesce(nullif(p.title_ru,''),p.title_en) t, count(*)::int n from events e join products p on p.id=e.product_id
      where e.kind='view' and (e.created_at at time zone '${TZ}')::date = (now() at time zone '${TZ}')::date and e.user_id <> all($1::bigint[])
      group by p.id order by n desc limit 3`, [ex])).rows;
  const refs = (await pool.query(`select count(*)::int n from referrals where (created_at at time zone '${TZ}')::date = (now() at time zone '${TZ}')::date`)).rows[0].n;
  return `📊 Итоги дня · ${SHOP_NAME}\n👥 Посетителей: ${ev.u}\n🚪 Открытий магазина: ${ev.o}\n👀 Просмотров товаров: ${ev.v}\n💬 Нажали «Написать менеджеру»: ${ev.m}\n🤝 Пришло по приглашениям: ${refs}` +
    (top.length ? '\n\n🔥 Чаще смотрели:\n' + top.map((x, i) => `${i + 1}. ${x.t} — ${x.n}`).join('\n') : '');
}
async function sendBackup(toIds) {
  const [products, photos, brands, banners, prizes, st] = await Promise.all([
    pool.query('select * from products order by id'),
    pool.query("select id, product_id, position, mime, encode(data,'base64') b64 from photos order by id"),
    pool.query('select * from brands order by id'),
    pool.query('select id,title_ru,title_en,text_ru,text_en,target,position from banners order by id'),
    pool.query('select * from prizes order by id'),
    getSettings(),
  ]);
  const full = { at: new Date().toISOString(), products: products.rows, brands: brands.rows, banners: banners.rows, prizes: prizes.rows, settings: st, photos: photos.rows };
  let body = JSON.stringify(full);
  let note = 'с фото';
  if (body.length > 45 * 1024 * 1024) { full.photos = photos.rows.map(p => ({ id: p.id, product_id: p.product_id, position: p.position, mime: p.mime })); body = JSON.stringify(full); note = 'БЕЗ фото (слишком большой файл)'; }
  for (const id of toIds) {
    const fd = new FormData();
    fd.append('chat_id', String(id));
    fd.append('caption', `💾 Резервная копия магазина (${note}). Товаров: ${products.rowCount}, фото: ${photos.rowCount}. Сохраните файл.`);
    fd.append('document', new Blob([body], { type: 'application/json' }), `securityshop-backup-${localParts().day}.json`);
    await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendDocument`, { method: 'POST', body: fd }).catch(e => console.error('backup', e.message));
  }
}
app.get('/api/admin/daily', requireAdmin, h(async (_req, res) => res.json({ on: (await getSettings()).daily !== '0' })));
app.post('/api/admin/daily-test', requireAdmin, h(async (_req, res) => { notifyAdmins(await dailySummaryText()); res.json({ ok: true }); }));
app.post('/api/admin/backup-send', requireAdmin, h(async (req, res) => { await sendBackup([req.user.id]); res.json({ ok: true }); }));
async function scheduler() {
  if (!BOT_TOKEN || !ADMIN_IDS.length) return;
  const { day, hour, wd } = localParts();
  if (hour < 21) return;
  const st = await getSettings();
  if (st.daily !== '0' && st.last_daily !== day) {
    await setSetting('last_daily', day);
    notifyAdmins(await dailySummaryText());
  }
  if (wd.toLowerCase().startsWith('вс') || wd.toLowerCase().startsWith('sun')) {
    if (st.last_backup !== day) { await setSetting('last_backup', day); await sendBackup(ADMIN_IDS); }
  }
}
setInterval(() => scheduler().catch(e => console.error('scheduler', e.message)), 60 * 1000);

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
    if (m && m.from && m.chat && m.chat.type === 'private') {
      await pool.query('insert into bot_users(user_id,name) values($1,$2) on conflict (user_id) do update set blocked=false', [m.from.id, userName(m.from)]).catch(() => {});
    }
    const mc = req.body && req.body.my_chat_member;
    if (mc && mc.chat && mc.chat.type === 'private' && mc.new_chat_member) {
      const st = mc.new_chat_member.status;
      if (st === 'kicked') await pool.query('update bot_users set blocked=true where user_id=$1', [mc.chat.id]).catch(() => {});
      else if (st === 'member') await pool.query('insert into bot_users(user_id,name) values($1,$2) on conflict (user_id) do update set blocked=false', [mc.chat.id, userName(mc.from || {})]).catch(() => {});
    }
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
  const a = await tg('setWebhook', { url: `${BASE_URL}/tg/${HOOK}`, allowed_updates: ['message', 'my_chat_member'] });
  const b = await tg('setChatMenuButton', {
    menu_button: { type: 'web_app', text: 'Магазин', web_app: { url: BASE_URL } },
  });
  const me = await tg('getMe', {}).catch(() => null);
  if (me && me.result && me.result.username) BOT_USERNAME = me.result.username;
  console.log('webhook:', JSON.stringify(a), 'menu:', JSON.stringify(b), 'bot:', BOT_USERNAME);
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
