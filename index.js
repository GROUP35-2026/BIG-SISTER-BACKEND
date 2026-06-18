// index.js — Big Sister backend (MariaDB edition)
// Run: node index.js
// Requires: .env file with DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, JWT_SECRET

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { nanoid } = require('nanoid');
const pool     = require('./db');

const app  = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';

app.use(cors());
app.use(express.json());

// ── Request logger ────────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  console.log(`${new Date().toISOString()}  ${req.method} ${req.url}`);
  next();
});

// ── JWT middleware (used on protected session routes) ─────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, message: 'Not authenticated.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Token invalid or expired.' });
  }
}

// =============================================================================
// AUTH ROUTES
// =============================================================================

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  const { fullName, email, password, agreeToTerms } = req.body;
  if (!fullName || !email || !password) {
    return res.json({ success: false, message: 'Full name, email and password are required.' });
  }

  try {
    const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (rows.length > 0) {
      return res.json({ success: false, message: 'An account with this email already exists.' });
    }

    const hash = await bcrypt.hash(password, 10);
    const id   = nanoid();
    await pool.query(
      'INSERT INTO users (id, full_name, email, password, agree_terms) VALUES (?, ?, ?, ?, ?)',
      [id, fullName, email, hash, agreeToTerms ? 1 : 0]
    );

    console.log('✅ New user registered:', email);
    return res.json({ success: true, message: 'Account created! Please log in.' });
  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ success: false, message: 'Server error during signup.' });
  }
});

// POST /api/auth/signin
app.post('/api/auth/signin', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.json({ success: false, message: 'Email and password required.' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.json({ success: false, message: 'Invalid email or password.' });
    }

    const user = rows[0];
    if (!user.password) {
      return res.json({ success: false, message: 'This account uses Google sign-in. Please use that instead.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.json({ success: false, message: 'Invalid email or password.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, fullName: user.full_name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('🔑 User signed in:', email);
    return res.json({
      success: true,
      message: 'Login successful!',
      token,
      user: { id: user.id, fullName: user.full_name, email: user.email }
    });
  } catch (err) {
    console.error('Signin error:', err);
    return res.status(500).json({ success: false, message: 'Server error during signin.' });
  }
});

// POST /api/auth/google-sync
app.post('/api/auth/google-sync', async (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.json({ success: false, message: 'No email provided.' });

  try {
    let [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    let user;

    if (rows.length === 0) {
      // First time — create account (no password for Google users)
      const id = nanoid();
      await pool.query(
        'INSERT INTO users (id, full_name, email, password, agree_terms) VALUES (?, ?, ?, NULL, 1)',
        [id, name || 'Google User', email]
      );
      [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
      user = rows[0];
      console.log('✅ Google user created:', email);
    } else {
      user = rows[0];
      console.log('🔑 Google user signed in:', email);
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, fullName: user.full_name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      success: true,
      token,
      user: { id: user.id, fullName: user.full_name, email: user.email }
    });
  } catch (err) {
    console.error('Google sync error:', err);
    return res.status(500).json({ success: false, message: 'Server error during Google sync.' });
  }
});

// =============================================================================
// SESSION ROUTES (all protected — require JWT)
// =============================================================================

// GET /api/sessions  — get all sessions for the logged-in user
app.get('/api/sessions', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );

    // Map snake_case DB columns → camelCase for the frontend
    const sessions = rows.map(dbRowToSession);
    return res.json({ success: true, sessions });
  } catch (err) {
    console.error('Fetch sessions error:', err);
    return res.status(500).json({ success: false, message: 'Could not fetch sessions.' });
  }
});

// POST /api/sessions  — book a new session
app.post('/api/sessions', requireAuth, async (req, res) => {
  const {
    counsellorId, counsellorName, counsellorRole,
    counsellorColor, counsellorAvatar, time, note, anonymous
  } = req.body;

  if (!counsellorId || !time) {
    return res.status(400).json({ success: false, message: 'counsellorId and time are required.' });
  }

  try {
    const id = `session_${nanoid()}`;
    await pool.query(
      `INSERT INTO sessions
         (id, user_id, counsellor_id, counsellor_name, counsellor_role,
          counsellor_color, counsellor_avatar, time_slot, note, anonymous)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id, req.user.id, counsellorId, counsellorName, counsellorRole,
        counsellorColor, counsellorAvatar, time, note || '', anonymous ? 1 : 0
      ]
    );

    const [rows] = await pool.query('SELECT * FROM sessions WHERE id = ?', [id]);
    console.log('✅ Session booked:', id, counsellorName, time);
    return res.status(201).json({ success: true, session: dbRowToSession(rows[0]) });
  } catch (err) {
    console.error('Book session error:', err);
    return res.status(500).json({ success: false, message: 'Could not book session.' });
  }
});

// PUT /api/sessions/:id  — edit an existing session
app.put('/api/sessions/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { time, note, anonymous } = req.body;

  try {
    // Make sure this session belongs to the logged-in user
    const [rows] = await pool.query(
      'SELECT * FROM sessions WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Session not found.' });
    }

    await pool.query(
      'UPDATE sessions SET time_slot = ?, note = ?, anonymous = ? WHERE id = ?',
      [time ?? rows[0].time_slot, note ?? rows[0].note, anonymous ? 1 : 0, id]
    );

    const [updated] = await pool.query('SELECT * FROM sessions WHERE id = ?', [id]);
    console.log('✏️  Session updated:', id);
    return res.json({ success: true, session: dbRowToSession(updated[0]) });
  } catch (err) {
    console.error('Edit session error:', err);
    return res.status(500).json({ success: false, message: 'Could not update session.' });
  }
});

// DELETE /api/sessions/:id  — delete a session
app.delete('/api/sessions/:id', requireAuth, async (req, res) => {
  const { id } = req.params;

  try {
    const [rows] = await pool.query(
      'SELECT id FROM sessions WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Session not found.' });
    }

    await pool.query('DELETE FROM sessions WHERE id = ?', [id]);
    console.log('🗑️  Session deleted:', id);
    return res.json({ success: true, deletedId: id });
  } catch (err) {
    console.error('Delete session error:', err);
    return res.status(500).json({ success: false, message: 'Could not delete session.' });
  }
});

// =============================================================================
// HELPERS
// =============================================================================

// Converts a DB row (snake_case) into the camelCase shape the frontend expects
function dbRowToSession(row) {
  return {
    id:              row.id,
    userId:          row.user_id,
    counsellorId:    row.counsellor_id,
    counsellorName:  row.counsellor_name,
    counsellorRole:  row.counsellor_role,
    counsellorColor: row.counsellor_color,
    counsellorAvatar:row.counsellor_avatar,
    time:            row.time_slot,
    note:            row.note,
    anonymous:       row.anonymous === 1,
    createdAt:       row.created_at,
    updatedAt:       row.updated_at
  };
}

// =============================================================================
app.get('/', (_req, res) => res.send('Big Sister API is running.'));

app.listen(PORT, () => {
  console.log(`\n🚀 Big Sister backend running at http://localhost:${PORT}`);
  console.log(`🗄️  Connected to MariaDB database: ${process.env.DB_NAME || 'bigsister'}\n`);
});
