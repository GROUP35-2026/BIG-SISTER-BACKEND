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
app.use(cors({ origin: 'http://localhost:5173' })); // Seamless connection with React frontend
app.use(express.json());

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
    await db.execute(
      'INSERT INTO users (id, full_name, email, password, agree_terms) VALUES (?, ?, ?, ?, ?)',
      [userId, fullName, email.toLowerCase(), hashedPassword, agreeToTerms ? 1 : 0]
    );

    return res.status(201).json({
      success: true,
      message: 'Account registered successfully!'
    });

  } catch (error) {
    console.error('Signup Error:', error);
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
    console.error('Signin Error:', error);
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
    console.error('Google Sync Error:', error);
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
    console.error('Database Booking Error:', error);
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
    console.error('Error fetching sessions:', error);
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
    console.error('Error updating session:', error);
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
    console.error('Error deleting session:', error);
    res.status(500).json({ success: false, message: 'Failed to cancel session.' });
  }
});

// Launch Server
app.listen(PORT, () => {
  console.log(`🚀 Big Sister Backend Server running on: http://localhost:${PORT}`);
});