import 'dotenv/config'; 
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from './db.js';

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

// Middleware Configuration
app.use(cors({ origin: ['http://localhost:5173', 'http://localhost:5174', 'https://big-sister-frontend-6uyxg1sxq-kirumira-jordan-s-projects.vercel.app'] }));
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
    req.userRole = decoded.role; // Attach role for authorization
    next();
  } catch (_) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
};

// ── Admin Auth Middleware ────────────────────────────────────────────────────
const requireAdmin = (req, res, next) => {
  requireAuth(req, res, (err) => {
    if (err) return;
    if (req.userRole !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied. Admins only.' });
    }
    next();
  });
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

    if (!fullName || !email || !password) {
      return res.status(400).json({ success: false, message: 'All input fields are required.' });
    }
    if (!agreeToTerms) {
      return res.status(400).json({ success: false, message: 'You must accept the Terms & Conditions.' });
    }

    const normalizedEmail = email.toLowerCase();
    const [existingUsers] = await db.execute('SELECT * FROM users WHERE email = ?', [normalizedEmail]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ success: false, message: 'An account with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const userId = Date.now().toString();

    // 🔥 NEW: Automatically assign admin role if email ends with @admin.com
    let role = 'user';
    if (normalizedEmail.endsWith('@admin.com')) {
      role = 'admin';
    }

    await db.execute(
      'INSERT INTO users (id, full_name, email, password, agree_terms, role) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, fullName, normalizedEmail, hashedPassword, agreeToTerms ? 1 : 0, role]
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

    // Locate user, fetching role as well
    const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (users.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid credentials. User not found.' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials. Password incorrect.' });
    }

    // Include role in the JWT payload
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role || 'user' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.json({
      success: true,
      message: 'Logged in successfully!',
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role || 'user' // Critical for frontend redirection
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

    const normalizedEmail = email.toLowerCase();
    const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [normalizedEmail]);
    let user;

    if (users.length === 0) {
      const userId = Date.now().toString();
      
      // 🔥 NEW: Auto-detect admin for Google sign-in as well
      let role = 'user';
      if (normalizedEmail.endsWith('@admin.com')) {
        role = 'admin';
      }

      await db.execute(
        'INSERT INTO users (id, full_name, email, password, agree_terms, role) VALUES (?, ?, ?, NULL, 1, ?)',
        [userId, name || 'Google User', normalizedEmail, role]
      );
      user = { id: userId, full_name: name || 'Google User', email: normalizedEmail, role: role };
    } else {
      user = users[0];
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role || 'user' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.json({
      success: true,
      message: 'Authenticated via Google successfully!',
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role || 'user'
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
    const finalTimeSlot = time || timeSlot || time_slot || '12:00 PM';
    const finalAnonymous = anonymous !== undefined ? (anonymous ? 1 : 0) : 0;

    const sessionId = Date.now().toString();

    await db.execute(
      `INSERT INTO sessions (
        id, user_id, counsellor_id, counsellor_name, counsellor_role, 
        counsellor_color, counsellor_avatar, time_slot, note, anonymous
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [sessionId, finalUserId, finalCounsellorId, finalCounsellorName, finalCounsellorRole, finalCounsellorColor, finalCounsellorAvatar, finalTimeSlot, note || '', finalAnonymous]
    );

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
      time: session.time_slot,
      note: session.note,
      anonymous: Boolean(session.anonymous),
      createdAt: session.created_at
    }));

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
        email: user.email,
        role: user.role || 'user'
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
    await db.execute('DELETE FROM sessions WHERE user_id = ?', [req.userId]);
    await db.execute('DELETE FROM support_requests WHERE user_id = ?', [req.userId]);
    await db.execute('DELETE FROM ai_chat_messages WHERE user_id = ?', [req.userId]);
    await db.execute('DELETE FROM period_logs WHERE user_id = ?', [req.userId]);
    await db.execute('DELETE FROM symptom_logs WHERE user_id = ?', [req.userId]);
    await db.execute('DELETE FROM cycle_settings WHERE user_id = ?', [req.userId]);
    await db.execute('DELETE FROM course_progress WHERE user_id = ?', [req.userId]);

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

/* ==========================================================================
   ROUTE 13: ADMIN - DASHBOARD OVERVIEW
   ========================================================================== */
app.get('/api/admin/overview', requireAdmin, async (req, res) => {
  try {
    const [totalUsers] = await db.execute('SELECT COUNT(*) as count FROM users WHERE role != "admin"');
    const [activeSessions] = await db.execute('SELECT COUNT(*) as count FROM sessions');
    const [supportRequests] = await db.execute('SELECT COUNT(*) as count FROM support_requests WHERE status="submitted"');
    const [healthTips] = await db.execute('SELECT COUNT(*) as count FROM content WHERE category="Health Tips" AND status="Live"');
    const [logs] = await db.execute('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 10');

    res.json({
      success: true,
      stats: {
        totalUsers: totalUsers[0].count,
        activeSessions: activeSessions[0].count,
        supportRequests: supportRequests[0].count,
        healthTipsLive: healthTips[0].count
      },
      activity: logs,
      featureHealth: [
        { name: 'AI Health Bot', status: 'Operational' },
        { name: 'Get Support', status: 'Operational' },
        { name: 'Talk to Counsellor', status: 'Degraded' },
        { name: 'Learn Skills', status: 'Operational' },
      ]
    });
  } catch (error) {
    console.error('Admin Overview Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch admin overview.' });
  }
});

/* ==========================================================================
   ROUTE 14: ADMIN - CONTENT MANAGEMENT (GET)
   ========================================================================== */
app.get('/api/admin/content', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM content ORDER BY created_at DESC');
    res.json({ success: true, content: rows });
  } catch (error) {
    console.error('Admin Content Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch content.' });
  }
});

/* ==========================================================================
   ROUTE 15: ADMIN - CREATE CONTENT
   ========================================================================== */
app.post('/api/admin/content', requireAdmin, async (req, res) => {
  try {
    const { title, category, status, body } = req.body;
    const id = Date.now().toString();
    await db.execute('INSERT INTO content (id, title, category, status, body) VALUES (?, ?, ?, ?, ?)', [id, title, category, status, body]);
    
    // Log the action
    await db.execute('INSERT INTO activity_logs (id, admin_id, category, action, details) VALUES (?, ?, ?, ?, ?)',
      [Date.now().toString() + 'a', req.userId, 'Content', `Published health tip: "${title}"`, `Category: ${category}`]);

    res.status(201).json({ success: true, message: 'Content created successfully.' });
  } catch (error) {
    console.error('Admin Content Create Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to create content.' });
  }
});

/* ==========================================================================
   ROUTE 16: ADMIN - DELETE CONTENT
   ========================================================================== */
app.delete('/api/admin/content/:id', requireAdmin, async (req, res) => {
  try {
    await db.execute('DELETE FROM content WHERE id = ?', [req.params.id]);
    await db.execute('INSERT INTO activity_logs (id, admin_id, category, action) VALUES (?, ?, ?, ?)',
      [Date.now().toString() + 'b', req.userId, 'Content', `Deleted content ID: ${req.params.id}`]);
    res.json({ success: true, message: 'Content deleted.' });
  } catch (error) {
    console.error('Admin Content Delete Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to delete content.' });
  }
});

/* ==========================================================================
   ROUTE 16B: ADMIN - UPDATE CONTENT (used by content edit modal)
   ========================================================================== */
app.put('/api/admin/content/:id', requireAdmin, async (req, res) => {
  try {
    const { title, category, status, body } = req.body;
    await db.execute('UPDATE content SET title = ?, category = ?, status = ?, body = ? WHERE id = ?',
      [title, category, status, body, req.params.id]);
    await db.execute('INSERT INTO activity_logs (id, admin_id, category, action, details) VALUES (?, ?, ?, ?, ?)',
      [Date.now().toString() + 'f', req.userId, 'Content', `Updated content: "${title}"`, `Category: ${category}`]);
    res.json({ success: true, message: 'Content updated.' });
  } catch (error) {
    console.error('Admin Content Update Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to update content.' });
  }
});

/* ==========================================================================
   ROUTE 17: ADMIN - GET ALL USERS
   ========================================================================== */
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT id, full_name, email, role, created_at FROM users WHERE role != "admin" ORDER BY created_at DESC');
    res.json({ success: true, users: rows });
  } catch (error) {
    console.error('Admin Users Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch users.' });
  }
});

/* ==========================================================================
   ROUTE 18: ADMIN - UPDATE USER STATUS (Flag / Suspend / Active)
   ========================================================================== */
app.put('/api/admin/users/:id/status', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body; // Active, Flagged, Suspended
    await db.execute('UPDATE users SET status = ? WHERE id = ?', [status, req.params.id]);
    await db.execute('INSERT INTO activity_logs (id, admin_id, category, action, details) VALUES (?, ?, ?, ?, ?)', 
      [Date.now().toString() + 'c', req.userId, 'Users', `Updated user status to ${status}`, `User ID: ${req.params.id}`]);
    res.json({ success: true, message: `User status updated to ${status}.` });
  } catch (error) {
    console.error('Admin User Status Update Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to update user status.' });
  }
});

/* ==========================================================================
   ROUTE 19: ADMIN - GET SUPPORT STAFF ROSTER
   ========================================================================== */
app.get('/api/admin/staff', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM support_staff');
    res.json({ success: true, staff: rows });
  } catch (error) {
    console.error('Admin Staff Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch support staff.' });
  }
});

/* ==========================================================================
   ROUTE 20: ADMIN - GET ACTIVITY LOGS
   ========================================================================== */
app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM activity_logs ORDER BY created_at DESC');
    res.json({ success: true, logs: rows });
  } catch (error) {
    console.error('Admin Logs Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch logs.' });
  }
});

/* ==========================================================================
   ROUTE 21: ADMIN - GET APP APPEARANCE SETTINGS
   ========================================================================== */
app.get('/api/admin/appearance', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM app_settings');
    const settings = rows.reduce((acc, r) => ({ ...acc, [r.setting_key]: r.setting_value }), {});
    res.json({ success: true, settings });
  } catch (error) {
    console.error('Admin Appearance Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch appearance settings.' });
  }
});

/* ==========================================================================
   ROUTE 22: ADMIN - UPDATE APP APPEARANCE SETTINGS
   ========================================================================== */
app.put('/api/admin/appearance', requireAdmin, async (req, res) => {
  try {
    const { primary, accent, background, appName, tagline, welcomeBanner } = req.body;
    const updates = { primary, accent, background, appName, tagline, welcomeBanner };
    
    for (const [key, val] of Object.entries(updates)) {
      if (val !== undefined) {
        await db.execute('INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?', [key, val, val]);
      }
    }

    await db.execute('INSERT INTO activity_logs (id, admin_id, category, action) VALUES (?, ?, ?, ?)',
      [Date.now().toString() + 'd', req.userId, 'Appearance', `Updated app theme and text settings`]);

    res.json({ success: true, message: 'Appearance settings updated successfully.' });
  } catch (error) {
    console.error('Admin Appearance Update Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to update appearance settings.' });
  }
});

/* ==========================================================================
   ROUTE 23: ADMIN - RUN MAINTENANCE TASKS
   ========================================================================== */
app.post('/api/admin/maintenance/:task', requireAdmin, async (req, res) => {
  try {
    const { task } = req.params;
    
    // Simulate a background task (replace with actual DB backup logic later)
    await new Promise(resolve => setTimeout(resolve, 1000));

    await db.execute('INSERT INTO activity_logs (id, admin_id, category, action, details) VALUES (?, ?, ?, ?, ?)', 
      [Date.now().toString() + 'e', req.userId, 'Backend', `Ran ${task} task`, `Executed by admin: ${req.userId}`]);

    res.json({ success: true, message: `${task} completed successfully.` });
  } catch (error) {
    console.error('Admin Maintenance Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: `Failed to run ${req.params.task}.` });
  }
});

/* ==========================================================================
   ROUTE 24: AI HEALTH BOT — SEND MESSAGE (calls Anthropic API)
   ========================================================================== */
app.post('/api/ai/chat', requireAuth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ success: false, message: 'Message cannot be empty.' });
    }

    // Save the user's message
    const userMsgId = Date.now().toString();
    await db.execute(
      'INSERT INTO ai_chat_messages (id, user_id, role, content) VALUES (?, ?, ?, ?)',
      [userMsgId, req.userId, 'user', message]
    );

    // Pull recent history for context (last 10 messages)
    const [historyRows] = await db.execute(
      'SELECT role, content FROM ai_chat_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
      [req.userId]
    );
    const history = historyRows.reverse().map(r => ({ role: r.role, content: r.content }));

    let botReply = "I'm sorry, I couldn't process that right now. Please try again shortly.";

    if (ANTHROPIC_API_KEY) {
      const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-6',
          max_tokens: 500,
          system: "You are Big Sister's AI Health Bot, a warm, supportive, private assistant for teenage girls in Uganda. Answer questions about puberty, menstruation, reproductive health, nutrition, and emotional wellbeing in simple, non-judgmental, age-appropriate language. Never share personal identifying info. Encourage seeking a doctor or counsellor for serious concerns. Keep responses concise (under 150 words).",
          messages: history
        })
      });
      const data = await apiRes.json();
      if (data?.content?.length) {
        botReply = data.content.map(b => b.text || '').join('\n').trim() || botReply;
      } else if (data?.error) {
        console.error('Anthropic API error:', data.error);
      }
    } else {
      botReply = "The AI Health Bot isn't fully configured yet (missing API key), but I'm here! For urgent concerns, please use Emergency Help or Talk to a Counsellor.";
    }

    const botMsgId = Date.now().toString() + '-bot';
    await db.execute(
      'INSERT INTO ai_chat_messages (id, user_id, role, content) VALUES (?, ?, ?, ?)',
      [botMsgId, req.userId, 'assistant', botReply]
    );

    return res.status(200).json({
      success: true,
      reply: { id: botMsgId, role: 'assistant', content: botReply }
    });
  } catch (error) {
    console.error('AI Chat Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Could not reach the AI Health Bot right now.' });
  }
});

/* ==========================================================================
   ROUTE 25: AI HEALTH BOT — GET CHAT HISTORY
   ========================================================================== */
app.get('/api/ai/chat/history', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT id, role, content, created_at FROM ai_chat_messages WHERE user_id = ? ORDER BY created_at ASC',
      [req.userId]
    );
    res.json({ success: true, messages: rows });
  } catch (error) {
    console.error('AI Chat History Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to load chat history.' });
  }
});

/* ==========================================================================
   ROUTE 26: AI HEALTH BOT — CLEAR CHAT HISTORY
   ========================================================================== */
app.delete('/api/ai/chat/history', requireAuth, async (req, res) => {
  try {
    await db.execute('DELETE FROM ai_chat_messages WHERE user_id = ?', [req.userId]);
    res.json({ success: true, message: 'Chat history cleared.' });
  } catch (error) {
    console.error('AI Chat Clear Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to clear chat history.' });
  }
});

/* ==========================================================================
   ROUTE 27: TRACK HEALTH — GET CYCLE SETTINGS + LOGS FOR A MONTH
   ========================================================================== */
app.get('/api/health/cycle', requireAuth, async (req, res) => {
  try {
    const [settingsRows] = await db.execute('SELECT * FROM cycle_settings WHERE user_id = ?', [req.userId]);
    let settings = settingsRows[0];
    if (!settings) {
      await db.execute(
        'INSERT INTO cycle_settings (user_id, avg_cycle_length, avg_period_length) VALUES (?, 28, 5)',
        [req.userId]
      );
      settings = { user_id: req.userId, avg_cycle_length: 28, avg_period_length: 5, last_period_start: null };
    }

    const [periodRows] = await db.execute(
      'SELECT log_date, flow, is_period_day FROM period_logs WHERE user_id = ? ORDER BY log_date ASC',
      [req.userId]
    );
    const [symptomRows] = await db.execute(
      'SELECT log_date, symptom, severity FROM symptom_logs WHERE user_id = ? ORDER BY log_date DESC LIMIT 60',
      [req.userId]
    );

    // Basic derived stats
    let cycleDay = null;
    let nextPeriodInDays = null;
    if (settings.last_period_start) {
      const start = new Date(settings.last_period_start);
      const today = new Date();
      const diffDays = Math.floor((today - start) / (1000 * 60 * 60 * 24));
      cycleDay = (diffDays % settings.avg_cycle_length) + 1;
      nextPeriodInDays = settings.avg_cycle_length - (diffDays % settings.avg_cycle_length);
    }

    res.json({
      success: true,
      settings: {
        avgCycleLength: settings.avg_cycle_length,
        avgPeriodLength: settings.avg_period_length,
        lastPeriodStart: settings.last_period_start
      },
      cycleDay,
      nextPeriodInDays,
      periodLogs: periodRows,
      symptomLogs: symptomRows
    });
  } catch (error) {
    console.error('Cycle Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch cycle data.' });
  }
});

/* ==========================================================================
   ROUTE 28: TRACK HEALTH — LOG / UPDATE A PERIOD DAY
   ========================================================================== */
app.post('/api/health/period-log', requireAuth, async (req, res) => {
  try {
    const { date, flow, isPeriodDay } = req.body;
    if (!date) return res.status(400).json({ success: false, message: 'Date is required.' });

    const logId = `${req.userId}-${date}`;
    await db.execute(
      `INSERT INTO period_logs (id, user_id, log_date, flow, is_period_day)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE flow = VALUES(flow), is_period_day = VALUES(is_period_day)`,
      [logId, req.userId, date, flow || null, isPeriodDay ? 1 : 0]
    );

    // If marking the first day of a new period, update last_period_start if this date is more recent
    if (isPeriodDay) {
      const [settingsRows] = await db.execute('SELECT * FROM cycle_settings WHERE user_id = ?', [req.userId]);
      const current = settingsRows[0];
      if (!current || !current.last_period_start || new Date(date) > new Date(current.last_period_start)) {
        await db.execute(
          `INSERT INTO cycle_settings (user_id, last_period_start) VALUES (?, ?)
           ON DUPLICATE KEY UPDATE last_period_start = VALUES(last_period_start)`,
          [req.userId, date]
        );
      }
    }

    res.status(200).json({ success: true, message: 'Period log saved.' });
  } catch (error) {
    console.error('Period Log Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to save period log.' });
  }
});

/* ==========================================================================
   ROUTE 29: TRACK HEALTH — LOG A SYMPTOM
   ========================================================================== */
app.post('/api/health/symptom-log', requireAuth, async (req, res) => {
  try {
    const { date, symptom, severity } = req.body;
    if (!date || !symptom) return res.status(400).json({ success: false, message: 'Date and symptom are required.' });

    const logId = Date.now().toString();
    await db.execute(
      'INSERT INTO symptom_logs (id, user_id, log_date, symptom, severity) VALUES (?, ?, ?, ?, ?)',
      [logId, req.userId, date, symptom, severity || 'mild']
    );

    res.status(201).json({ success: true, message: 'Symptom logged.' });
  } catch (error) {
    console.error('Symptom Log Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to log symptom.' });
  }
});

/* ==========================================================================
   ROUTE 30: TRACK HEALTH — UPDATE CYCLE SETTINGS
   ========================================================================== */
app.put('/api/health/cycle-settings', requireAuth, async (req, res) => {
  try {
    const { avgCycleLength, avgPeriodLength, lastPeriodStart } = req.body;
    await db.execute(
      `INSERT INTO cycle_settings (user_id, avg_cycle_length, avg_period_length, last_period_start)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         avg_cycle_length = VALUES(avg_cycle_length),
         avg_period_length = VALUES(avg_period_length),
         last_period_start = VALUES(last_period_start)`,
      [req.userId, avgCycleLength || 28, avgPeriodLength || 5, lastPeriodStart || null]
    );
    res.json({ success: true, message: 'Cycle settings updated.' });
  } catch (error) {
    console.error('Cycle Settings Update Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to update cycle settings.' });
  }
});

/* ==========================================================================
   ROUTE 31: LEARN SKILLS — GET ALL COURSES (+ user progress if logged in)
   ========================================================================== */
app.get('/api/courses', async (req, res) => {
  try {
    const [courses] = await db.execute('SELECT * FROM courses WHERE status = "Live" ORDER BY created_at ASC');

    let progressMap = {};
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [progressRows] = await db.execute('SELECT * FROM course_progress WHERE user_id = ?', [decoded.userId]);
        progressRows.forEach(p => { progressMap[p.course_id] = p; });
      } catch (_) { /* not logged in or invalid token — just skip progress */ }
    }

    const formatted = courses.map(c => ({
      id: c.id,
      title: c.title,
      description: c.description,
      icon: c.icon_emoji,
      color: c.color_hex,
      durationWeeks: c.duration_weeks,
      percentComplete: progressMap[c.id]?.percent_complete || 0,
      completed: Boolean(progressMap[c.id]?.completed)
    }));

    res.json({ success: true, courses: formatted });
  } catch (error) {
    console.error('Courses Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch courses.' });
  }
});

/* ==========================================================================
   ROUTE 32: LEARN SKILLS — UPDATE MY PROGRESS ON A COURSE
   ========================================================================== */
app.put('/api/courses/:id/progress', requireAuth, async (req, res) => {
  try {
    const { percentComplete } = req.body;
    const clamped = Math.max(0, Math.min(100, Number(percentComplete) || 0));
    const progressId = `${req.userId}-${req.params.id}`;
    await db.execute(
      `INSERT INTO course_progress (id, user_id, course_id, percent_complete, completed)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE percent_complete = VALUES(percent_complete), completed = VALUES(completed)`,
      [progressId, req.userId, req.params.id, clamped, clamped >= 100 ? 1 : 0]
    );
    res.json({ success: true, message: 'Progress updated.' });
  } catch (error) {
    console.error('Course Progress Update Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to update progress.' });
  }
});

/* ==========================================================================
   ROUTE 33: LEARN SKILLS — ADMIN CREATE/LIST COURSES
   ========================================================================== */
app.get('/api/admin/courses', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM courses ORDER BY created_at DESC');
    res.json({ success: true, courses: rows });
  } catch (error) {
    console.error('Admin Courses Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch courses.' });
  }
});

app.post('/api/admin/courses', requireAdmin, async (req, res) => {
  try {
    const { title, description, icon, color, durationWeeks, status } = req.body;
    const id = Date.now().toString();
    await db.execute(
      'INSERT INTO courses (id, title, description, icon_emoji, color_hex, duration_weeks, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [id, title, description || '', icon || '📘', color || '#9333ea', durationWeeks || 4, status || 'Draft']
    );
    res.status(201).json({ success: true, message: 'Course created.' });
  } catch (error) {
    console.error('Admin Course Create Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to create course.' });
  }
});

app.delete('/api/admin/courses/:id', requireAdmin, async (req, res) => {
  try {
    await db.execute('DELETE FROM courses WHERE id = ?', [req.params.id]);
    res.json({ success: true, message: 'Course deleted.' });
  } catch (error) {
    console.error('Admin Course Delete Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to delete course.' });
  }
});

/* ==========================================================================
   ROUTE 34: EXPLORE TOPICS — GET ALL TOPICS
   ========================================================================== */
app.get('/api/topics', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM topics WHERE status = "Live" ORDER BY created_at ASC');
    const formatted = rows.map(t => ({
      id: t.id,
      title: t.title,
      subtitle: t.subtitle,
      body: t.body,
      icon: t.icon_emoji,
      color: t.color_hex,
      readMinutes: t.read_minutes,
      articleCount: t.article_count
    }));
    res.json({ success: true, topics: formatted });
  } catch (error) {
    console.error('Topics Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch topics.' });
  }
});

/* ==========================================================================
   ROUTE 35: EXPLORE TOPICS — ADMIN CREATE/DELETE
   ========================================================================== */
app.get('/api/admin/topics', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM topics ORDER BY created_at DESC');
    res.json({ success: true, topics: rows });
  } catch (error) {
    console.error('Admin Topics Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch topics.' });
  }
});

app.post('/api/admin/topics', requireAdmin, async (req, res) => {
  try {
    const { title, subtitle, body, icon, color, readMinutes, articleCount, status } = req.body;
    const id = Date.now().toString();
    await db.execute(
      'INSERT INTO topics (id, title, subtitle, body, icon_emoji, color_hex, read_minutes, article_count, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, title, subtitle || '', body || '', icon || '📖', color || '#9023F0', readMinutes || 5, articleCount || 1, status || 'Draft']
    );
    res.status(201).json({ success: true, message: 'Topic created.' });
  } catch (error) {
    console.error('Admin Topic Create Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to create topic.' });
  }
});

app.delete('/api/admin/topics/:id', requireAdmin, async (req, res) => {
  try {
    await db.execute('DELETE FROM topics WHERE id = ?', [req.params.id]);
    res.json({ success: true, message: 'Topic deleted.' });
  } catch (error) {
    console.error('Admin Topic Delete Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to delete topic.' });
  }
});

/* ==========================================================================
   ROUTE 36: EMERGENCY HELP — GET CONTACTS
   ========================================================================== */
app.get('/api/emergency-contacts', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM emergency_contacts ORDER BY sort_order ASC');
    const formatted = rows.map(c => ({
      id: c.id,
      name: c.name,
      phone: c.phone,
      hours: c.hours,
      icon: c.icon_emoji,
      color: c.color_hex
    }));
    res.json({ success: true, contacts: formatted });
  } catch (error) {
    console.error('Emergency Contacts Fetch Error:', error.sqlMessage || error.message || error);
    res.status(500).json({ success: false, message: 'Failed to fetch emergency contacts.' });
  }
});

// Launch Server// at the very bottom, replace app.listen(...) with:
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`🚀 Big Sister Backend Server running on: http://localhost:${PORT}`);
  });
}

export default app;