// index.js
// Big Sister backend — minimal Express API.
//
// Run with:  node index.js
// Server listens on http://localhost:5000
//
// Endpoints relevant to "Talk to Counsellor":
//   GET    /api/sessions            -> list all booked sessions
//   POST   /api/sessions            -> create (book) a new session
//   PUT    /api/sessions/:id        -> update (edit) a session
//   DELETE /api/sessions/:id        -> delete a session
//
// Plus the auth endpoints your frontend already calls
// (signup / signin / google-sync) as simple working stubs so the whole
// app runs end-to-end locally.

const express = require('express');
const cors = require('cors');
const { nanoid } = require('nanoid');
const { readDb, writeDb } = require('./db');

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

// ---------------------------------------------------------------------------
// Simple request logger — handy while you're testing the integration, since
// you'll see every booking/edit/delete hit the terminal in real time.
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()}  ${req.method} ${req.url}`);
  next();
});

// =============================================================================
// AUTH (stubs matching what your frontend already calls)
// =============================================================================

app.post('/api/auth/signup', (req, res) => {
  const { fullName, email, password, agreeToTerms } = req.body;

  if (!fullName || !email || !password) {
    return res.json({ success: false, message: 'Missing required fields.' });
  }

  const db = readDb();
  const existing = db.users.find((u) => u.email === email);
  if (existing) {
    return res.json({ success: false, message: 'An account with this email already exists.' });
  }

  const newUser = {
    id: nanoid(),
    fullName,
    email,
    password, // NOTE: plaintext for local dev only. Hash this (e.g. bcrypt) before any real deployment.
    agreeToTerms: !!agreeToTerms,
    createdAt: new Date().toISOString()
  };
  db.users.push(newUser);
  writeDb(db);

  return res.json({ success: true, message: 'Account created successfully! Please log in.' });
});

app.post('/api/auth/signin', (req, res) => {
  const { email, password } = req.body;
  const db = readDb();
  const user = db.users.find((u) => u.email === email && u.password === password);

  if (!user) {
    return res.json({ success: false, message: 'Invalid email or password.' });
  }

  return res.json({
    success: true,
    message: 'Login successful!',
    token: `dev-token-${user.id}`,
    user: { id: user.id, fullName: user.fullName, email: user.email }
  });
});

app.post('/api/auth/google-sync', (req, res) => {
  const { email, name } = req.body;
  if (!email) {
    return res.json({ success: false, message: 'No email provided by Google account.' });
  }

  const db = readDb();
  let user = db.users.find((u) => u.email === email);
  if (!user) {
    user = {
      id: nanoid(),
      fullName: name || 'Google User',
      email,
      password: null,
      agreeToTerms: true,
      createdAt: new Date().toISOString()
    };
    db.users.push(user);
    writeDb(db);
  }

  return res.json({
    success: true,
    token: `dev-token-${user.id}`,
    user: { id: user.id, fullName: user.fullName, email: user.email }
  });
});

// =============================================================================
// COUNSELLOR SESSIONS — booking / editing / deleting
// =============================================================================

// GET /api/sessions
// Optionally filter by ?userId=xxx once you wire real auth through.
app.get('/api/sessions', (req, res) => {
  const db = readDb();
  const { userId } = req.query;

  let sessions = db.sessions;
  if (userId) {
    sessions = sessions.filter((s) => s.userId === userId);
  }

  res.json({ success: true, sessions });
});

// POST /api/sessions  -> book a new session
app.post('/api/sessions', (req, res) => {
  const {
    userId,
    counsellorId,
    counsellorName,
    counsellorRole,
    counsellorColor,
    counsellorAvatar,
    time,
    note,
    anonymous
  } = req.body;

  if (!counsellorId || !time) {
    return res.status(400).json({ success: false, message: 'counsellorId and time are required.' });
  }

  const db = readDb();

  const newSession = {
    id: `session_${nanoid()}`,
    userId: userId || null,
    counsellorId,
    counsellorName,
    counsellorRole,
    counsellorColor,
    counsellorAvatar,
    time,
    note: note || '',
    anonymous: !!anonymous,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  db.sessions.push(newSession);
  writeDb(db);

  console.log('✅ Session booked:', newSession.id, newSession.counsellorName, newSession.time);

  res.status(201).json({ success: true, session: newSession });
});

// PUT /api/sessions/:id -> edit an existing session
app.put('/api/sessions/:id', (req, res) => {
  const { id } = req.params;
  const { time, note, anonymous } = req.body;

  const db = readDb();
  const index = db.sessions.findIndex((s) => s.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: 'Session not found.' });
  }

  db.sessions[index] = {
    ...db.sessions[index],
    time: time ?? db.sessions[index].time,
    note: note ?? db.sessions[index].note,
    anonymous: anonymous ?? db.sessions[index].anonymous,
    updatedAt: new Date().toISOString()
  };

  writeDb(db);

  console.log('✏️  Session updated:', id);

  res.json({ success: true, session: db.sessions[index] });
});

// DELETE /api/sessions/:id -> delete a session
app.delete('/api/sessions/:id', (req, res) => {
  const { id } = req.params;

  const db = readDb();
  const index = db.sessions.findIndex((s) => s.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: 'Session not found.' });
  }

  const [removed] = db.sessions.splice(index, 1);
  writeDb(db);

  console.log('🗑️  Session deleted:', id);

  res.json({ success: true, deletedId: removed.id });
});

// =============================================================================

app.get('/', (req, res) => {
  res.send('Big Sister backend is running. Try GET /api/sessions');
});

app.listen(PORT, () => {
  console.log(`\n🚀 Big Sister backend running at http://localhost:${PORT}`);
  console.log(`📄 Data is stored in ${__dirname}/db.json — open it anytime to see live changes.\n`);
});
