import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Middleware Configuration
app.use(cors({ origin: 'http://localhost:5173' })); // Seamless connection with React frontend
app.use(express.json());

// In-Memory Database Simulation (Resets when server restarts)
const usersDatabase = [];

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

    // Check if user entry already exists
    const userExists = usersDatabase.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (userExists) {
      return res.status(400).json({ success: false, message: 'An account with this email already exists.' });
    }

    // Hash user password securely
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save user record
    const newUser = {
      id: Date.now().toString(),
      fullName,
      email: email.toLowerCase(),
      password: hashedPassword,
      createdAt: new Date()
    };
    usersDatabase.push(newUser);

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

    // Locate the user record
    const user = usersDatabase.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid credentials. User not found.' });
    }

    // Match password hash verify
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials. Password incorrect.' });
    }

    // Issue Secure Session JSON Web Token (JWT)
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    return res.json({
      success: true,
      message: 'Logged in successfully!',
      token,
      user: {
        id: user.id,
        fullName: user.fullName,
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
app.post('/api/auth/google-sync', (req, res) => {
  const { email, name } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: 'Google integration profile identity error.' });
  }

  // If user profile doesn't exist, register them automatically on the fly
  let user = usersDatabase.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) {
    user = {
      id: Date.now().toString(),
      fullName: name || 'Google User',
      email: email.toLowerCase(),
      createdAt: new Date()
    };
    usersDatabase.push(user);
  }

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

  return res.json({
    success: true,
    message: 'Authenticated via Google successfully!',
    token,
    user: {
      id: user.id,
      fullName: user.fullName,
      email: user.email
    }
  });
});

// Launch Server
app.listen(PORT, () => {
  console.log(`🚀 Big Sister Backend Server running on: http://localhost:${PORT}`);
});