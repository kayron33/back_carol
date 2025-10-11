// index.js
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import { promises as fs } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';

// -------------------- paths básicos --------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');

const dataFiles = {
  users: path.join(dataDir, 'users.txt'),
  profile: path.join(dataDir, 'profile.txt'),
  projects: path.join(dataDir, 'projects.txt'),
};

// -------------------- admin padrão --------------------
const ADMIN_EMAIL = 'caroline@gmail.com';
// hash de "123456" (exemplo). Troque quando quiser.
const ADMIN_PASSWORD_HASH = '$2a$10$SwOJj1.JWCL7wUBTX4BdYePR4zLkOb/rLpLVT1fDCNRoWkkrY7omW';

// -------------------- perfil padrão --------------------
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

// -------------------- helpers de arquivo --------------------
async function ensureFile(filePath, defaultValue) {
  try {
    await fs.access(filePath);
  } catch {
    await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2), 'utf-8');
  }
}

async function ensureDataFiles() {
  await fs.mkdir(dataDir, { recursive: true });
  await fs.mkdir(uploadsDir, { recursive: true });
  await ensureFile(dataFiles.users, []);
  await ensureFile(dataFiles.projects, []);
  await ensureFile(dataFiles.profile, defaultProfile);
}

async function readJson(filePath, defaultValue) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    if (!content) return defaultValue;
    return JSON.parse(content);
  } catch (error) {
    if (error.code === 'ENOENT') {
      await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2), 'utf-8');
      return defaultValue;
    }
    throw error;
  }
}

async function writeJson(filePath, data) {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

async function ensureAdminUser() {
  const users = await readJson(dataFiles.users, []);
  const now = new Date().toISOString();
  const adminLower = ADMIN_EMAIL.toLowerCase();

  const existingAdmin = users.find((user) => {
    const identifier = String(user.email ?? user.username ?? '').toLowerCase();
    return identifier === adminLower;
  });

  const adminUser = {
    id: existingAdmin?.id ?? 'admin',
    username: ADMIN_EMAIL,
    email: ADMIN_EMAIL,
    passwordHash: ADMIN_PASSWORD_HASH,
    created_at: existingAdmin?.created_at ?? now,
    updated_at: existingAdmin?.updated_at ?? now,
  };

  let finalUsers;
  if (existingAdmin) {
    // mantém apenas um admin (e remove duplicados antigos)
    finalUsers = [adminUser];
  } else {
    finalUsers = [adminUser, ...users.filter(u => String(u.email ?? u.username ?? '').toLowerCase() !== adminLower)];
  }

  await writeJson(dataFiles.users, finalUsers);
}

// cria estrutura inicial antes de subir o servidor
await ensureDataFiles();
await ensureAdminUser();

// -------------------- upload (multer) --------------------
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const ext = path.extname(file.originalname) || '.bin';
    cb(null, `${unique}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// -------------------- app / middlewares --------------------
const app = express();

// CORS com whitelist por env (ex.: "https://seu-front.vercel.app,https://www.seudominio.com")
const ALLOWED = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // permite curl/postman (sem origin) e whitelista as origins de navegador
    if (!origin) return cb(null, true);
    if (ALLOWED.length === 0 || ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error('CORS bloqueado: ' + origin));
  },
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(uploadsDir));

// -------------------- rotas --------------------
app.get('/health', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// Auth simples (compara com admin padrão)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'E-mail e senha são obrigatórios.' });
    }

    const users = await readJson(dataFiles.users, []);
    const normalizedEmail = String(email).trim().toLowerCase();
    const user = users.find((item) => String(item.email ?? item.username).toLowerCase() === normalizedEmail);

    if (!user) {
      return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });
    }

    const valid = await bcrypt.compare(String(password), user.passwordHash);
    if (!valid) {
      return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });
    }

    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Erro ao realizar login.',
    });
  }
});

// Profile - GET
app.get('/api/profile', async (_req, res) => {
  try {
    const profile = await readJson(dataFiles.profile, defaultProfile);
    return res.json(profile);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Erro ao carregar perfil.',
    });
  }
});

// Profile - PUT
app.put('/api/profile', async (req, res) => {
  try {
    const profile = await readJson(dataFiles.profile, defaultProfile);
    const now = new Date().toISOString();

    const languages = Array.isArray(req.body?.languages)
      ? req.body.languages.map(String)
      : typeof req.body?.languages === 'string'
        ? String(req.body.languages).split(',').map(s => s.trim()).filter(Boolean)
        : profile.languages ?? [];

    const skills = Array.isArray(req.body?.skills)
      ? req.body.skills.map(String)
      : typeof req.body?.skills === 'string'
        ? String(req.body.skills).split(',').map(s => s.trim()).filter(Boolean)
        : profile.skills ?? [];

    const updatedProfile = {
      ...defaultProfile,
      ...profile,
      id: 'profile',
      languages,
      skills,
      name: req.body?.name !== undefined ? String(req.body.name) : profile.name,
      title: req.body?.title !== undefined ? String(req.body.title) : profile.title,
      bio: req.body?.bio !== undefined ? String(req.body.bio) : profile.bio,
      photo_url: req.body?.photo_url !== undefined ? String(req.body.photo_url) : profile.photo_url,
      email: req.body?.email !== undefined ? String(req.body.email) : profile.email,
      linkedin: req.body?.linkedin !== undefined ? String(req.body.linkedin) : profile.linkedin,
      phone: req.body?.phone !== undefined ? String(req.body.phone) : profile.phone,
      education: req.body?.education !== undefined ? String(req.body.education) : profile.education,
      created_at: profile.created_at || now,
      updated_at: now,
    };

    await writeJson(dataFiles.profile, updatedProfile);
    return res.json(updatedProfile);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Erro ao atualizar perfil.',
    });
  }
});

// Projects - GET
app.get('/api/projects', async (_req, res) => {
  try {
    const projects = await readJson(dataFiles.projects, []);
    const sorted = [...projects].sort((a, b) => {
      if ((a.order_position ?? 0) !== (b.order_position ?? 0)) {
        return (a.order_position ?? 0) - (b.order_position ?? 0);
      }
      return new Date(b.date).getTime() - new Date(a.date).getTime();
    });
    return res.json(sorted);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Erro ao carregar projetos.',
    });
  }
});

// Projects - POST
app.post('/api/projects', async (req, res) => {
  try {
    const { title, description, category, date, image_url, external_link, order_position } = req.body ?? {};
    if (!title || !description || !category) {
      return res.status(400).json({ success: false, message: 'Título, descrição e categoria são obrigatórios.' });
    }

    const projects = await readJson(dataFiles.projects, []);
    const now = new Date().toISOString();
    const position = Number(order_position);

    const newProject = {
      id: randomUUID(),
      title: String(title),
      description: String(description),
      category: String(category),
      date: date ? String(date) : now,
      image_url: image_url ? String(image_url) : '',
      external_link: external_link !== undefined ? (external_link ? String(external_link) : null) : null,
      order_position: Number.isFinite(position) ? position : 0,
      created_at: now,
      updated_at: now,
    };

    projects.push(newProject);
    await writeJson(dataFiles.projects, projects);
    return res.status(201).json(newProject);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Erro ao adicionar projeto.',
    });
  }
});

// Projects - PUT
app.put('/api/projects/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const projects = await readJson(dataFiles.projects, []);
    const index = projects.findIndex((p) => p.id === id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Projeto não encontrado.' });
    }

    const current = projects[index];
    const now = new Date().toISOString();
    const position = Number(req.body?.order_position);

    projects[index] = {
      ...current,
      title: req.body?.title !== undefined ? String(req.body.title) : current.title,
      description: req.body?.description !== undefined ? String(req.body.description) : current.description,
      category: req.body?.category !== undefined ? String(req.body.category) : current.category,
      date: req.body?.date !== undefined ? String(req.body.date) : current.date,
      image_url: req.body?.image_url !== undefined ? String(req.body.image_url) : current.image_url,
      external_link: req.body?.external_link !== undefined
        ? (req.body.external_link ? String(req.body.external_link) : null)
        : current.external_link,
      order_position: Number.isFinite(position) ? position : (current.order_position ?? 0),
      updated_at: now,
    };

    await writeJson(dataFiles.projects, projects);
    return res.json(projects[index]);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Erro ao atualizar projeto.',
    });
  }
});

// Projects - DELETE
app.delete('/api/projects/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const projects = await readJson(dataFiles.projects, []);
    const filtered = projects.filter((p) => p.id !== id);
    if (filtered.length === projects.length) {
      return res.status(404).json({ success: false, message: 'Projeto não encontrado.' });
    }
    await writeJson(dataFiles.projects, filtered);
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error instanceof Error ? error.message : 'Erro ao remover projeto.',
    });
  }
});

// Uploads
app.post('/api/uploads', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'Nenhum arquivo enviado.' });
  }
  const relativePath = `/uploads/${req.file.filename}`;
  return res.status(201).json({ success: true, path: relativePath });
});

// -------------------- erro genérico --------------------
app.use((err, _req, res, _next) => {
  if (err?.message?.startsWith?.('CORS bloqueado')) {
    return res.status(403).json({ success: false, message: err.message });
  }
  return res.status(500).json({ success: false, message: 'Erro interno.' });
});

// -------------------- start --------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Servidor em execução na porta ${PORT}`);
});
