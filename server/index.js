// index.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import morgan from 'morgan';
import pg from 'pg';
import { randomUUID } from 'crypto';

// -------------------- CONFIG/CONSTS --------------------
const ADMIN_EMAIL = 'caroline@gmail.com';
// hash de "123456" (troque quando quiser)
const ADMIN_PASSWORD_HASH = '$2a$10$SwOJj1.JWCL7wUBTX4BdYePR4zLkOb/rLpLVT1fDCNRoWkkrY7omW';

// perfil padrão (mantém o contrato da API)
const defaultProfile = {
  id: 'profile',
  name: '',
  title: '',
  bio: '',
  photo_url: '',
  email: '',
  linkedin: '',
  phone: '',
  languages: [],
  skills: [],
  education: '',
  created_at: '',
  updated_at: '',
};

// -------------------- DB (POSTGRES) --------------------
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Render/Neon exigem SSL
});

async function initDb() {
  await pool.query(`
    create table if not exists users (
      id text primary key,
      email text unique not null,
      username text,
      password_hash text not null,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );

    create table if not exists profile (
      id text primary key,
      name text,
      title text,
      bio text,
      photo_url text,
      email text,
      linkedin text,
      phone text,
      languages jsonb default '[]'::jsonb,
      skills jsonb default '[]'::jsonb,
      education text,
      created_at timestamptz,
      updated_at timestamptz
    );

    create table if not exists projects (
      id text primary key,
      title text not null,
      description text not null,
      category text not null,
      date text,
      image_url text,
      external_link text,
      order_position int default 0,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );

    -- armazenamento de arquivos (imagens) no próprio Postgres
    create table if not exists uploads (
      id text primary key,
      filename text not null,
      mime text not null,
      data bytea not null,
      created_at timestamptz not null default now()
    );
  `);
}

async function ensureAdminUser() {
  const { rows } = await pool.query(
    'select 1 from users where lower(email)=lower($1) limit 1',
    [ADMIN_EMAIL]
  );
  if (!rows.length) {
    await pool.query(
      'insert into users (id,email,username,password_hash) values ($1,$2,$3,$4)',
      [randomUUID(), ADMIN_EMAIL, ADMIN_EMAIL, ADMIN_PASSWORD_HASH]
    );
  }
}

await initDb();
await ensureAdminUser();

// -------------------- UPLOAD (agora em memória, salvando no DB) --------------------
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// -------------------- APP / MIDDLEWARES --------------------
const app = express();

const ALLOWED = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // curl/postman
    if (ALLOWED.length === 0 || ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error('CORS bloqueado: ' + origin));
  },
  credentials: true,
}));

app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use((_, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  next();
});

// -------------------- ROTAS --------------------
app.get('/health', (_req, res) =>
  res.json({ ok: true, time: new Date().toISOString() })
);

// AUTH
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'E-mail e senha são obrigatórios.' });
    }
    const q = await pool.query(
      'select * from users where lower(email)=lower($1) limit 1',
      [String(email).toLowerCase()]
    );
    const user = q.rows[0];
    if (!user) return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });

    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });

    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error?.message || 'Erro ao realizar login.',
    });
  }
});

// PROFILE - GET
app.get('/api/profile', async (_req, res) => {
  try {
    const { rows } = await pool.query('select * from profile where id=$1', ['profile']);
    if (!rows.length) return res.json(defaultProfile);
    const p = rows[0];
    return res.json({
      id: 'profile',
      name: p.name || '',
      title: p.title || '',
      bio: p.bio || '',
      photo_url: p.photo_url || '',
      email: p.email || '',
      linkedin: p.linkedin || '',
      phone: p.phone || '',
      languages: p.languages || [],
      skills: p.skills || [],
      education: p.education || '',
      created_at: p.created_at || '',
      updated_at: p.updated_at || '',
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error?.message || 'Erro ao carregar perfil.',
    });
  }
});

// PROFILE - PUT
app.put('/api/profile', async (req, res) => {
  try {
    const now = new Date().toISOString();
    const b = req.body ?? {};

    const languages = Array.isArray(b.languages)
      ? b.languages.map(String)
      : typeof b.languages === 'string'
        ? String(b.languages).split(',').map(s => s.trim()).filter(Boolean)
        : [];

    const skills = Array.isArray(b.skills)
      ? b.skills.map(String)
      : typeof b.skills === 'string'
        ? String(b.skills).split(',').map(s => s.trim()).filter(Boolean)
        : [];

    const exists = await pool.query('select 1 from profile where id=$1', ['profile']);
    if (exists.rowCount) {
      await pool.query(
        `update profile set
           name=$1, title=$2, bio=$3, photo_url=$4, email=$5, linkedin=$6, phone=$7,
           languages=$8::jsonb, skills=$9::jsonb, education=$10, updated_at=$11
         where id='profile'`,
        [
          String(b.name ?? ''), String(b.title ?? ''), String(b.bio ?? ''),
          String(b.photo_url ?? ''), String(b.email ?? ''), String(b.linkedin ?? ''),
          String(b.phone ?? ''), JSON.stringify(languages), JSON.stringify(skills),
          String(b.education ?? ''), now
        ]
      );
    } else {
      await pool.query(
        `insert into profile
          (id,name,title,bio,photo_url,email,linkedin,phone,languages,skills,education,created_at,updated_at)
         values
          ('profile',$1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$11)`,
        [
          String(b.name ?? ''), String(b.title ?? ''), String(b.bio ?? ''),
          String(b.photo_url ?? ''), String(b.email ?? ''), String(b.linkedin ?? ''),
          String(b.phone ?? ''), JSON.stringify(languages), JSON.stringify(skills),
          String(b.education ?? ''), now
        ]
      );
    }

    return res.json({
      id: 'profile',
      name: String(b.name ?? ''),
      title: String(b.title ?? ''),
      bio: String(b.bio ?? ''),
      photo_url: String(b.photo_url ?? ''),
      email: String(b.email ?? ''),
      linkedin: String(b.linkedin ?? ''),
      phone: String(b.phone ?? ''),
      languages, skills,
      education: String(b.education ?? ''),
      created_at: exists.rowCount ? undefined : now,
      updated_at: now,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error?.message || 'Erro ao atualizar perfil.',
    });
  }
});

// PROJECTS - GET
app.get('/api/projects', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      select * from projects
      order by coalesce(order_position,0) asc, updated_at desc
    `);
    return res.json(rows);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error?.message || 'Erro ao carregar projetos.',
    });
  }
});

// PROJECTS - POST
app.post('/api/projects', async (req, res) => {
  try {
    const { title, description, category, date, image_url, external_link, order_position } = req.body ?? {};
    if (!title || !description || !category) {
      return res.status(400).json({ success: false, message: 'Título, descrição e categoria são obrigatórios.' });
    }

    const id = randomUUID();
    const now = new Date().toISOString();
    const position = Number(order_position);

    const q = await pool.query(
      `insert into projects
        (id,title,description,category,date,image_url,external_link,order_position,created_at,updated_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
       returning *`,
      [
        id, String(title), String(description), String(category),
        date ? String(date) : now,
        image_url ? String(image_url) : '',
        external_link ? String(external_link) : null,
        Number.isFinite(position) ? position : 0,
        now
      ]
    );

    return res.status(201).json(q.rows[0]);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error?.message || 'Erro ao adicionar projeto.',
    });
  }
});

// PROJECTS - PUT
app.put('/api/projects/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const cur = await pool.query('select * from projects where id=$1', [id]);
    if (!cur.rowCount) {
      return res.status(404).json({ success: false, message: 'Projeto não encontrado.' });
    }
    const c = cur.rows[0];
    const now = new Date().toISOString();
    const position = Number(req.body?.order_position);

    const updated = {
      title: req.body?.title ?? c.title,
      description: req.body?.description ?? c.description,
      category: req.body?.category ?? c.category,
      date: req.body?.date ?? c.date,
      image_url: req.body?.image_url ?? c.image_url,
      external_link: req.body?.external_link ?? c.external_link,
      order_position: Number.isFinite(position) ? position : c.order_position,
    };

    const q = await pool.query(
      `update projects set
         title=$2, description=$3, category=$4, date=$5, image_url=$6,
         external_link=$7, order_position=$8, updated_at=$9
       where id=$1 returning *`,
      [ id, updated.title, updated.description, updated.category, updated.date,
        updated.image_url, updated.external_link, updated.order_position, now ]
    );

    return res.json(q.rows[0]);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error?.message || 'Erro ao atualizar projeto.',
    });
  }
});

// PROJECTS - DELETE
app.delete('/api/projects/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const r = await pool.query('delete from projects where id=$1', [id]);
    if (!r.rowCount) {
      return res.status(404).json({ success: false, message: 'Projeto não encontrado.' });
    }
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error?.message || 'Erro ao remover projeto.',
    });
  }
});

// UPLOADS → salvando no Postgres e servindo por /files/:id
app.post('/api/uploads', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Nenhum arquivo enviado.' });
    }
    // (Opcional) restringir a imagens:
    // if (!/^image\//.test(req.file.mimetype)) return res.status(400).json({ success:false, message:'Apenas imagens.' });

    const id = randomUUID();
    const filename = req.file.originalname || `${id}.bin`;
    const mime = req.file.mimetype || 'application/octet-stream';

    await pool.query(
      'insert into uploads (id, filename, mime, data) values ($1,$2,$3,$4)',
      [id, filename, mime, req.file.buffer]
    );

    // IMPORTANTE: salve este `path` na sua tabela (profile.photo_url / projects.image_url)
    const path = `/files/${id}`;
    return res.status(201).json({ success: true, path, id, filename, mime });
  } catch (e) {
    console.error('Erro no upload:', e);
    return res.status(500).json({ success: false, message: 'Falha no upload' });
  }
});

// Servindo os arquivos armazenados no DB
app.get('/files/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const q = await pool.query('select filename, mime, data from uploads where id=$1', [id]);
    if (!q.rowCount) return res.status(404).send('Arquivo não encontrado');
    const { filename, mime, data } = q.rows[0];

    res.setHeader('Content-Type', mime || 'application/octet-stream');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(filename)}"`);
    return res.status(200).end(data);
  } catch (e) {
    console.error('Erro ao servir arquivo:', e);
    return res.status(500).send('Erro ao servir arquivo');
  }
});

// -------------------- ERRO GENÉRICO --------------------
app.use((err, _req, res, _next) => {
  console.error('Erro global:', err);
  if (err?.message?.startsWith?.('CORS bloqueado')) {
    return res.status(403).json({ success: false, message: err.message });
  }
  return res.status(500).json({ success: false, message: 'Erro interno.' });
});

// -------------------- START --------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Servidor em execução na porta ${PORT}`);
});
