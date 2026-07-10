import 'dotenv/config'; 
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from './db.js';

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Middleware Configuration
app.use(cors({ origin: ['http://localhost:5173', 'http://localhost:5174'] }));
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

// Launch Server// at the very bottom, replace app.listen(...) with:
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`🚀 Big Sister Backend Server running on: http://localhost:${PORT}`);
  });
}

export default app;