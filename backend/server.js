import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import http from 'http';
import https from 'https';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

dotenv.config();

// Fix __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Database setup
const dbPath = path.join(__dirname, 'users.db');
const db = new Database(dbPath);

console.log('Connected to the SQLite database.');

// Create table
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )
`).run();

const app = express();

// ✅ IMPORTANT: Use Render PORT
const PORT = process.env.PORT || 3001;

// ⚠️ Use env variable in production
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-face-finder';

app.use(cors());
app.use(express.json());


// ================= AUTH APIs =================

// Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
    const info = stmt.run(username, passwordHash);

    res.status(201).json({
      message: 'User registered successfully',
      userId: info.lastInsertRowid,
    });
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    const user = stmt.get(username);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});


// ================= CAMERA PROXY =================

app.get('/api/proxy-stream', (req, res) => {
  const targetUrl = req.query.url;

  if (!targetUrl) {
    return res.status(400).send('Missing camera URL');
  }

  const client = targetUrl.startsWith('https') ? https : http;

  const proxyReq = client.get(targetUrl, (proxyRes) => {
    if (proxyRes.headers['content-type']) {
      res.setHeader('Content-Type', proxyRes.headers['content-type']);
    }

    res.setHeader('Access-Control-Allow-Origin', '*');
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error('Proxy Error:', err.message);
    res.status(500).send('Proxy error');
  });

  req.on('close', () => {
    proxyReq.destroy();
  });
});


// ================= SERVE FRONTEND =================

// Serve React build (Vite dist folder)
app.use(express.static(path.join(__dirname, '../dist')));

// Handle React routes
app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});


// ================= START SERVER =================

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});