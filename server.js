require('dotenv').config()

const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { Pool } = require('pg')

const {
  PORT = 3000,
  DATABASE_URL = "postgresql://postgres:[@nedamiki75N]@db.rqgntskjkootgtgmmeyi.supabase.co:5432/postgres",
  ADMIN_USER = "admin",
  ADMIN_PASS = "rp123",
  JWT_SECRET = "cigara",
  CORS_ORIGIN = '*'
} = process.env

if (!DATABASE_URL) {
  throw new Error('Missing DATABASE_URL environment variable')
}
if (!ADMIN_USER || !ADMIN_PASS) {
  throw new Error('Missing ADMIN_USER or ADMIN_PASS environment variables')
}
if (!JWT_SECRET) {
  throw new Error('Missing JWT_SECRET environment variable')
}

const app = express()
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false }
})

app.use(helmet())
app.use(cors({ origin: CORS_ORIGIN }))
app.use(express.json({ limit: '1mb' }))

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200
})

app.use(authLimiter)

async function initSchema() {
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    CREATE TABLE IF NOT EXISTS offline_accounts (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      uuid TEXT NOT NULL,
      skin_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `)
}

function signAdminToken() {
  return jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' })
}

function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization || ''
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
  if (!token) {
    return res.status(401).json({ error: 'Missing token' })
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    if (payload?.role !== 'admin') {
      return res.status(403).json({ error: 'Invalid token' })
    }
    return next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

app.get('/health', async (_req, res) => {
  res.json({ ok: true })
})

app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body || {}
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' })
  }
  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  return res.json({ token: signAdminToken() })
})

app.post('/admin/offline-accounts', requireAdmin, async (req, res) => {
  const { username, password, uuid, skinUrl } = req.body || {}
  if (!username || !password || !uuid) {
    return res.status(400).json({ error: 'Missing username, password, or uuid' })
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10)
    const result = await pool.query(
      'INSERT INTO offline_accounts (username, password_hash, uuid, skin_url) VALUES ($1, $2, $3, $4) RETURNING id, username, uuid, skin_url',
      [username.trim(), passwordHash, uuid.trim(), skinUrl || null]
    )
    return res.status(201).json(result.rows[0])
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already exists' })
    }
    return res.status(500).json({ error: 'Failed to create account' })
  }
})

app.get('/offline-accounts', async (_req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, uuid, skin_url FROM offline_accounts ORDER BY created_at DESC'
    )
    return res.json(result.rows)
  } catch (err) {
    return res.status(500).json({ error: 'Failed to load accounts' })
  }
})

app.post('/offline-accounts/login', async (req, res) => {
  const { username, password } = req.body || {}
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' })
  }
  try {
    const result = await pool.query(
      'SELECT id, username, uuid, password_hash, skin_url FROM offline_accounts WHERE username = $1',
      [username.trim()]
    )
    if (result.rowCount === 0) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    const account = result.rows[0]
    const ok = await bcrypt.compare(password, account.password_hash)
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    return res.json({
      id: account.id,
      username: account.username,
      uuid: account.uuid,
      skinUrl: account.skin_url
    })
  } catch (err) {
    return res.status(500).json({ error: 'Login failed' })
  }
})

app.delete('/admin/offline-accounts/:id', requireAdmin, async (req, res) => {
  const { id } = req.params
  try {
    const result = await pool.query('DELETE FROM offline_accounts WHERE id = $1', [id])
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Account not found' })
    }
    return res.json({ ok: true })
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete account' })
  }
})

initSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Backend listening on :${PORT}`)
    })
  })
  .catch((err) => {
    console.error('Failed to init schema', err)
    process.exit(1)
  })
