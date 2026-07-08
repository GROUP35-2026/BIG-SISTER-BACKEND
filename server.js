import 'dotenv/config'; 
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from './db.js'; // Imports your actual MariaDB pool connection

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Middleware Configuration
app.use(cors({ origin: ['http://localhost:5173', 'http://localhost:5174'] })); // Seamless connection with React frontend
app.use(express.json());

// ── Auth Middleware: verifies the JWT and attaches req.userId ──────────────
const requireAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided.' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (_) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
};

// Base System Status Route
app.get('/', (req, res) => {
  res.json({ message: 'Big Sister API Node Backend running smoothly.' });
});

/* ==========================================================================
   ROUTE 1: USER REGISTRATION (SIGN UP)
   ========================================================================== */
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { fullName, email, password, agreeToTerms } = req.body;

    // Validation checks
    if (!fullName || !email || !password) {
      return res.status(400).json({ success: false, message: 'All input fields are required.' });
    }

    if (!agreeToTerms) {
      return res.status(400).json({ success: false, message: 'You must accept the Terms & Conditions.' });
    }

    // 1. Check MariaDB if user entry already exists
    const [existingUsers] = await db.execute('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ success: false, message: 'An account with this email already exists.' });
    }

    // 2. Hash user password securely
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 3. Generate a distinct ID (Matches VARCHAR(36) in your HeidiSQL setup)
    const userId = Date.now().toString();

    // 4. Save user record into MariaDB
    // FIX: 'id' was previously omitted from the INSERT column list/values,
    // which threw ER_NO_DEFAULT_FOR_FIELD since users.id has no default.
    await db.execute(
      'INSERT INTO users (id, full_name, email, password, agree_terms) VALUES (?, ?, ?, ?, ?)',
      [userId, fullName, email.toLowerCase(), hashedPassword, agreeToTerms ? 1 : 0]
    );

    return res.status(201).json({
      success: true,
      message: 'Account registered successfully!'
    });

  } catch (error) {
    console.error('Signup Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Internal server initialization fault.' });
  }
});

/* ==========================================================================
   ROUTE 2: USER LOGIN (SIGN IN)
   ========================================================================== */
app.post('/api/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Please enter both email and password.' });
    }

    // 1. Locate the user record inside MariaDB
    const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (users.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid credentials. User not found.' });
    }

    const user = users[0];

    // 2. Match password hash verify
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials. Password incorrect.' });
    }

    // 3. Issue Secure Session JSON Web Token (JWT)
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    return res.json({
      success: true,
      message: 'Logged in successfully!',
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Signin Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Internal server authentication fault.' });
  }
});

/* ==========================================================================
   ROUTE 3: GOOGLE OAUTH CONTINUATION VERIFICATION FLOW
   ========================================================================== */
app.post('/api/auth/google-sync', async (req, res) => {
  try {
    const { email, name } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Google integration profile identity error.' });
    }

    // Check if user profile already exists in MariaDB
    const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    let user;

    if (users.length === 0) {
      // Register them automatically on the fly inside MariaDB
      const userId = Date.now().toString();
      await db.execute(
        'INSERT INTO users (id, full_name, email, password, agree_terms) VALUES (?, ?, ?, NULL, 1)',
        [userId, name || 'Google User', email.toLowerCase()]
      );

      user = { id: userId, full_name: name || 'Google User', email: email.toLowerCase() };
    } else {
      user = users[0];
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    return res.json({
      success: true,
      message: 'Authenticated via Google successfully!',
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Google Sync Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Internal server Google sync fault.' });
  }
});

/* ==========================================================================
   ROUTE 4: CREATE COUNSELLOR SESSION (BOOKING)
   ========================================================================== */
app.post('/api/sessions', async (req, res) => {
  try {
    const { 
      userId, user_id,
      counsellorId, counsellor_id,
      counsellorName, counsellor_name,
      counsellorRole, counsellor_role,
      counsellorColor, counsellor_color,
      counsellorAvatar, counsellor_avatar,
      time, timeSlot, time_slot,
      note,
      anonymous
    } = req.body;

    const finalUserId = userId || user_id || null;
    const finalCounsellorId = counsellorId || counsellor_id || 'sarah';
    const finalCounsellorName = counsellorName || counsellor_name || 'Sarah Johnson';
    const finalCounsellorRole = counsellorRole || counsellor_role || 'Mental Health Educator';
    const finalCounsellorColor = counsellorColor || counsellor_color || '#e91e63';
    const finalCounsellorAvatar = counsellorAvatar || counsellor_avatar || '👩‍⚕️';
    const finalTimeSlot = time || timeSlot || time_slot || '12:00 PM'; // Maps frontend 'time'
    const finalAnonymous = anonymous !== undefined ? (anonymous ? 1 : 0) : 0;

    const sessionId = Date.now().toString();

    // FIX: 'id' was previously omitted from the INSERT, so the returned
    // sessionId never matched what MariaDB actually stored — same
    // ER_NO_DEFAULT_FOR_FIELD risk as the signup route, and it silently
    // broke later PUT/DELETE lookups by id.
    await db.execute(
      `INSERT INTO sessions (
        id, user_id, counsellor_id, counsellor_name, counsellor_role, 
        counsellor_color, counsellor_avatar, time_slot, note, anonymous
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [sessionId, finalUserId, finalCounsellorId, finalCounsellorName, finalCounsellorRole, finalCounsellorColor, finalCounsellorAvatar, finalTimeSlot, note || '', finalAnonymous]
    );

    // Formatted structure matching what your React state maps over
    const newSessionObj = {
      id: sessionId,
      userId: finalUserId,
      counsellorId: finalCounsellorId,
      counsellorName: finalCounsellorName,
      counsellorRole: finalCounsellorRole,
      counsellorColor: finalCounsellorColor,
      counsellorAvatar: finalCounsellorAvatar,
      time: finalTimeSlot,
      note: note || '',
      anonymous: Boolean(finalAnonymous)
    };

    // Return exactly what React line 68 expects: data.success and data.session
    return res.status(201).json({
      success: true,
      session: newSessionObj
    });

  } catch (error) {
    console.error('Database Booking Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Internal server booking fault.' });
  }
});

/* ==========================================================================
   ROUTE 5: GET ALL SESSIONS (VIEW)
   ========================================================================== */
app.get('/api/sessions', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM sessions ORDER BY created_at DESC');

    const formattedSessions = rows.map(session => ({
      id: session.id,
      userId: session.user_id,
      counsellorId: session.counsellor_id,
      counsellorName: session.counsellor_name,
      counsellorRole: session.counsellor_role,
      counsellorColor: session.counsellor_color,
      counsellorAvatar: session.counsellor_avatar,
      time: session.time_slot, // Map time_slot column to frontend 'time' key
      note: session.note,
      anonymous: Boolean(session.anonymous),
      createdAt: session.created_at
    }));

    // Return exactly what React line 42 expects: data.success and data.sessions
    return res.status(200).json({
      success: true,
      sessions: formattedSessions
    });

  } catch (error) {
    console.error('Error fetching sessions:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to retrieve sessions.' });
  }
});

/* ==========================================================================
   ROUTE 6: UPDATE SESSION (EDIT)
   ========================================================================== */
app.put('/api/sessions/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { time, note, anonymous } = req.body;

    const [currentRows] = await db.execute('SELECT * FROM sessions WHERE id = ?', [id]);
    if (currentRows.length === 0) {
      return res.status(404).json({ success: false, message: 'Session not found.' });
    }
    const currentSession = currentRows[0];

    const finalTime = time || currentSession.time_slot;
    const finalNote = note !== undefined ? note : currentSession.note;
    const finalAnon = anonymous !== undefined ? (anonymous ? 1 : 0) : currentSession.anonymous;

    await db.execute(
      'UPDATE sessions SET time_slot = ?, note = ?, anonymous = ? WHERE id = ?',
      [finalTime, finalNote, finalAnon, id]
    );

    const updatedSessionObj = {
      id,
      userId: currentSession.user_id,
      counsellorId: currentSession.counsellor_id,
      counsellorName: currentSession.counsellor_name,
      counsellorRole: currentSession.counsellor_role,
      counsellorColor: currentSession.counsellor_color,
      counsellorAvatar: currentSession.counsellor_avatar,
      time: finalTime,
      note: finalNote,
      anonymous: Boolean(finalAnon)
    };

    // Return exactly what React line 53 expects: data.success and data.session
    return res.status(200).json({
      success: true,
      session: updatedSessionObj
    });
  } catch (error) {
    console.error('Error updating session:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to edit session.' });
  }
});

/* ==========================================================================
   ROUTE 7: CANCEL SESSION (DELETE)
   ========================================================================== */
app.delete('/api/sessions/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await db.execute('DELETE FROM sessions WHERE id = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Session not found.' });
    }

    // Return exactly what React line 87 expects: data.success
    return res.status(200).json({ success: true, message: 'Session deleted successfully.' });
  } catch (error) {
    console.error('Error deleting session:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to cancel session.' });
  }
});

/* ==========================================================================
   ROUTE 8: SUBMIT SUPPORT REQUEST (CREATE)
   ========================================================================== */
app.post('/api/support-requests', async (req, res) => {
  try {
    // Pull userId from the JWT token attached to the request
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    let userId = null;
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.userId;
      } catch (_) { /* token invalid — still allow anonymous submit */ }
    }
 
    const { category, categoryLabel, firstName, schoolName } = req.body;
 
    if (!category || !firstName || !schoolName) {
      return res.status(400).json({ success: false, message: 'Category, first name, and school name are required.' });
    }
 
    const requestId = Date.now().toString();
 
    await db.execute(
      `INSERT INTO support_requests (id, user_id, category, category_label, first_name, school_name, status)
       VALUES (?, ?, ?, ?, ?, ?, 'submitted')`,
      [requestId, userId, category, categoryLabel || category, firstName, schoolName]
    );
 
    const newRequest = {
      id:            requestId,
      userId,
      category,
      categoryLabel: categoryLabel || category,
      firstName,
      schoolName,
      status:        'submitted',
      createdAt:     new Date().toISOString()
    };
 
    return res.status(201).json({ success: true, request: newRequest });
 
  } catch (error) {
    console.error('Support Request Create Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Internal server error creating request.' });
  }
});
 
/* ==========================================================================
   ROUTE 9: GET ALL SUPPORT REQUESTS FOR LOGGED-IN USER
   ========================================================================== */
app.get('/api/support-requests', async (req, res) => {
  try {
    // Verify JWT and extract userId
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'No token provided.' });
 
    let userId;
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.userId;
    } catch (_) {
      return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
    }
 
    const [rows] = await db.execute(
      'SELECT * FROM support_requests WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );
 
    const requests = rows.map(r => ({
      id:            r.id,
      userId:        r.user_id,
      category:      r.category,
      categoryLabel: r.category_label,
      firstName:     r.first_name,
      schoolName:    r.school_name,
      status:        r.status,
      createdAt:     r.created_at
    }));
 
    return res.status(200).json({ success: true, requests });
 
  } catch (error) {
    console.error('Support Request Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to retrieve support requests.' });
  }
});
 
/* ==========================================================================
   ROUTE 10: DELETE SUPPORT REQUEST
   ========================================================================== */
app.delete('/api/support-requests/:id', async (req, res) => {
  try {
    const { id } = req.params;
 
    // Verify JWT
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'No token provided.' });
 
    let userId;
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.userId;
    } catch (_) {
      return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
    }
 
    // Only allow deletion of own requests
    const [check] = await db.execute(
      'SELECT * FROM support_requests WHERE id = ? AND user_id = ?',
      [id, userId]
    );
    if (check.length === 0) {
      return res.status(404).json({ success: false, message: 'Request not found or not yours to delete.' });
    }
 
    const [result] = await db.execute('DELETE FROM support_requests WHERE id = ?', [id]);
 
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Request not found.' });
    }
 
    return res.status(200).json({ success: true, message: 'Support request removed successfully.' });
 
  } catch (error) {
    console.error('Support Request Delete Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to remove support request.' });
  }
});

/* ==========================================================================
   ROUTE 11: UPDATE MY PROFILE EMAIL
   ========================================================================== */
app.put('/api/users/me', requireAuth, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !email.trim()) {
      return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Make sure no other account is already using this email
    const [existing] = await db.execute(
      'SELECT id FROM users WHERE email = ? AND id != ?',
      [normalizedEmail, req.userId]
    );
    if (existing.length > 0) {
      return res.status(400).json({ success: false, message: 'This email is already in use by another account.' });
    }

    await db.execute('UPDATE users SET email = ? WHERE id = ?', [normalizedEmail, req.userId]);

    const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [req.userId]);
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }
    const user = rows[0];

    return res.status(200).json({
      success: true,
      message: 'Email updated successfully.',
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Update Email Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Internal server error updating email.' });
  }
});

/* ==========================================================================
   ROUTE 12: DELETE MY ACCOUNT
   ========================================================================== */
app.delete('/api/users/me', requireAuth, async (req, res) => {
  try {
    // Clean up everything tied to this user first, then the account itself
    await db.execute('DELETE FROM sessions WHERE user_id = ?', [req.userId]);
    await db.execute('DELETE FROM support_requests WHERE user_id = ?', [req.userId]);

    const [result] = await db.execute('DELETE FROM users WHERE id = ?', [req.userId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.status(200).json({ success: true, message: 'Account deleted successfully.' });
  } catch (error) {
    console.error('Delete Account Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to delete account.' });
  }
});

// Launch Server
app.listen(PORT, () => {
  console.log(`🚀 Big Sister Backend Server running on: http://localhost:${PORT}`);
});