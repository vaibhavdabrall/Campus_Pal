const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), path = require('path');
const app = express(); app.use(express.json({ limit: '100kb' }));
const DB = process.env.DATABASE_URL, SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const pool = new Pool({ connectionString: DB, ssl: DB && !/localhost|127\.0\.0\.1/.test(DB) ? { rejectUnauthorized: false } : false });
const q = (s, p) => pool.query(s, p).then(r => r.rows);
const clip = s => String(s || '').trim().slice(0, 600);
const QUESTS = { post: 20, res: 30, conn: 15, event: 15, task: 25, skill: 15 };
const h = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); });
const auth = (req, res, next) => { try { req.uid = jwt.verify((req.headers.authorization || '').slice(7), SECRET).uid; next(); } catch (e) { res.status(401).json({ error: 'Please log in again.' }); } };
const token = id => jwt.sign({ uid: id }, SECRET, { expiresIn: '30d' });

async function award(uid, k) {
  const [r] = await q('update users set xp=xp+$2, done=array_append(done,$3::text) where id=$1 and not ($3::text = any(done)) returning xp', [uid, QUESTS[k], k]);
  return r ? `Quest complete! +${QUESTS[k]} XP` : undefined;
}

app.post('/api/signup', h(async (req, res) => {
  const name = clip(req.body.name), email = clip(req.body.email).toLowerCase(), pw = String(req.body.password || '');
  if (!name || !/^\S+@\S+\.\S+$/.test(email) || pw.length < 6) return res.status(400).json({ error: 'Enter your name, a valid email and a password of 6+ characters.' });
  if ((await q('select 1 from users where email=$1', [email])).length) return res.status(409).json({ error: 'This email already has an account. Log in instead.' });
  const [u] = await q('insert into users(name,email,pw) values($1,$2,$3) returning id', [name, email, await bcrypt.hash(pw, 10)]);
  res.json({ token: token(u.id) });
}));

app.post('/api/login', h(async (req, res) => {
  const [u] = await q('select id,pw from users where email=$1', [clip(req.body.email).toLowerCase()]);
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.pw))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  res.json({ token: token(u.id) });
}));

app.get('/api/state', auth, h(async (req, res) => {
  const uid = req.uid;
  const users = await q('select id::text, name, course, sem, bio, interests, subjects, xp, done, conn::text[] as conn, tasks, case when id=$1 then email end as email from users order by xp desc', [uid]);
  const items = await q('select id, kind, uid::text as owner, data from items order by id desc limit 300');
  const k = x => items.filter(i => i.kind === x).map(i => ({ id: i.id, by: i.owner, ...i.data }));
  const msgs = await q('select frm::text, too::text, t from msgs where frm=$1 or too=$1 order by id', [uid]);
  res.json({ me: String(uid), users, posts: k('post'), res: k('res'), ev: k('ev'), sk: k('sk'), msgs });
}));

const F = { post: ['cat', 't'], res: ['title', 'cat', 'sub', 'd'], ev: ['title', 'date', 'loc', 'd'], sk: ['type', 's'] };
const REQ = { post: 't', res: 'title', ev: 'title', sk: 's' }, QK = { post: 'post', res: 'res', ev: 'event', sk: 'skill' };
app.post('/api/items/:kind', auth, h(async (req, res) => {
  const kind = req.params.kind, f = F[kind];
  if (!f) return res.status(400).json({ error: 'Bad request' });
  const d = {}; f.forEach(x => d[x] = clip(req.body[x]));
  if (!d[REQ[kind]]) return res.status(400).json({ error: 'Please fill in the required field.' });
  if (kind === 'post') { d.likes = []; d.cm = []; }
  if (kind === 'ev') d.reg = [String(req.uid)];
  await q('insert into items(kind,uid,data) values($1,$2,$3)', [kind, req.uid, d]);
  res.json({ toast: (await award(req.uid, QK[kind])) || 'Saved' });
}));

app.post('/api/items/:id/act', auth, h(async (req, res) => {
  const [it] = await q('select * from items where id=$1', [+req.params.id]);
  if (!it) return res.status(404).json({ error: 'Not found' });
  const d = it.data, me = String(req.uid), { op, t } = req.body; let toast;
  if (op === 'like' && it.kind === 'post') d.likes = d.likes.includes(me) ? d.likes.filter(x => x !== me) : [...d.likes, me];
  else if (op === 'comment' && it.kind === 'post' && clip(t)) d.cm.push({ by: me, t: clip(t) });
  else if (op === 'reg' && it.kind === 'ev') {
    if (d.reg.includes(me)) d.reg = d.reg.filter(x => x !== me); else { d.reg.push(me); toast = await award(req.uid, 'event'); }
  } else return res.status(400).json({ error: 'Bad request' });
  await q('update items set data=$2 where id=$1', [it.id, d]);
  res.json({ toast });
}));

app.put('/api/profile', auth, h(async (req, res) => {
  const b = req.body, name = clip(b.name);
  if (!name) return res.status(400).json({ error: 'Name cannot be empty.' });
  await q('update users set name=$2,course=$3,sem=$4,bio=$5,interests=$6,subjects=$7 where id=$1', [req.uid, name, clip(b.course), clip(b.sem), clip(b.bio), clip(b.interests), clip(b.subjects)]);
  res.json({ toast: 'Profile saved' });
}));

app.post('/api/connect/:id', auth, h(async (req, res) => {
  const o = +req.params.id;
  if (!o || o === req.uid || !(await q('select 1 from users where id=$1', [o])).length) return res.status(400).json({ error: 'Bad request' });
  const sql = 'update users set conn=(select array(select distinct unnest(conn || array[$2::int]))) where id=$1';
  await q(sql, [req.uid, o]); await q(sql, [o, req.uid]);
  res.json({ toast: (await award(req.uid, 'conn')) || 'Connected' });
}));

app.post('/api/msg', auth, h(async (req, res) => {
  const to = +req.body.to, t = clip(req.body.t);
  if (!to || to === req.uid || !t || !(await q('select 1 from users where id=$1', [to])).length) return res.status(400).json({ error: 'Bad request' });
  await q('insert into msgs(frm,too,t) values($1,$2,$3)', [req.uid, to, t]);
  res.json({});
}));

app.post('/api/task', auth, h(async (req, res) => {
  await q('update users set xp=xp+5, tasks=tasks+1 where id=$1', [req.uid]);
  res.json({ toast: (await award(req.uid, 'task')) || '+5 XP' });
}));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

async function init() {
  await q(`create table if not exists users(id serial primary key, name text not null, email text unique not null, pw text not null,
    course text default '', sem text default '', bio text default '', interests text default '', subjects text default '',
    xp int default 10, done text[] default '{}', conn int[] default '{}', tasks int default 0)`);
  await q('create table if not exists items(id serial primary key, kind text not null, uid int not null, data jsonb not null, created timestamptz default now())');
  await q('create table if not exists msgs(id serial primary key, frm int not null, too int not null, t text not null, created timestamptz default now())');
}
init().then(() => app.listen(process.env.PORT || 3000, () => console.log('Campus Pal running')))
  .catch(e => { console.error('Database error. Check DATABASE_URL.', e.message); process.exit(1); });
