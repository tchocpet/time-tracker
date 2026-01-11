import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import pool from './db.js';
import authenticateToken from './authMiddleware.js';
import dotenv from 'dotenv';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { sendEmail } from './emailService.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

app.use(express.json());

const refreshTokens = [];

// Enable CORS with dynamic frontend URL
app.use(cors({
  origin: FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));

// Role-based authorization middleware
function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
    }
    next();
  };
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts. Please try again later.',
});

// Login API Endpoint
app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const conn = await pool.getConnection();
    const rows = await conn.query('SELECT * FROM users WHERE email = $1', [email]);
    conn.release();

    if (rows.length === 0) {
      console.error('User not found:', email);
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.error('Invalid password for user:', email);
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const refreshToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET
    );
    refreshTokens.push(refreshToken);

    res.status(200).json({ message: 'Login successful.', token, refreshToken });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Verify Token Endpoint
app.post('/api/verify-token', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: 'Token is required.' });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    res.status(200).json({ message: 'Token is valid.', user });
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).json({ message: 'Invalid token.' });
  }
});

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'This is a protected route.', user: req.user });
});

// Admin-only route
app.get('/api/admin', authenticateToken, authorizeRole('admin'), (req, res) => {
  res.status(200).json({ message: 'Welcome, Admin!', user: req.user });
});

// Employee-only route
app.get('/api/employee', authenticateToken, authorizeRole('employee'), (req, res) => {
  res.status(200).json({ message: 'Welcome, Employee!', user: req.user });
});

// Refresh token route
app.post('/api/refresh', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(401).json({ message: 'Refresh token required.' });
  }

  if (!refreshTokens.includes(token)) {
    return res.status(403).json({ message: 'Invalid refresh token.' });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    const newToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.status(200).json({ token: newToken });
  } catch (error) {
    res.status(403).json({ message: 'Invalid refresh token.' });
  }
});

// Reset password route
app.post('/api/reset-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }

  try {
    const conn = await pool.getConnection();
    const rows = await conn.query('SELECT * FROM users WHERE email = $1', [email]);

    if (rows.length === 0) {
      conn.release();
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = rows[0];

    const resetToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '10m' }
    );

    await conn.query('UPDATE users SET reset_token = $1 WHERE email = $2', [resetToken, email]);
    conn.release();

    const resetLink = `${FRONTEND_URL}/update-password?token=${resetToken}`;
    await sendEmail(
      email,
      'Password Reset Request',
      `Click the link to reset your password: ${resetLink}. The link is only valid for 10 minutes.`
    );

    res.status(200).json({ message: 'Password reset link sent to your email.' });
  } catch (error) {
    console.error('Error in reset-password:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Update password route
app.post('/api/update-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const conn = await pool.getConnection();
    const result = await conn.query(
      'UPDATE users SET password = $1, reset_token = NULL WHERE id = $2',
      [hashedPassword, decoded.id]
    );
    conn.release();

    if (result.length === 0) {
      return res.status(404).json({ message: 'User not found or token invalid.' });
    }

    res.status(200).json({ message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Error in update-password:', error);
    res.status(500).json({ message: 'Invalid or expired token.' });
  }
});

// Log work route
app.post('/api/log-work', authenticateToken, async (req, res) => {
  const { employeeId, type } = req.body;

  if (!employeeId || !type) {
    return res.status(400).json({ message: 'Employee ID and action type are required.' });
  }

  try {
    const currentTime = new Date();
    const conn = await pool.getConnection();
    const currentDate = currentTime.toISOString().split('T')[0];

    const existingWorkLog = await conn.query(
      'SELECT * FROM work_logs WHERE employee_id = $1 AND date = $2',
      [employeeId, currentDate]
    );

    if (existingWorkLog.length > 0) {
      const workLog = existingWorkLog[0];
      let updatedFields = {};

      if (type === 'Start Work') updatedFields.start_time = currentTime;
      if (type === 'Break Start') updatedFields.break_start = currentTime;
      if (type === 'Break End') updatedFields.break_end = currentTime;
      if (type === 'Finish Work') updatedFields.finish_time = currentTime;

      const keys = Object.keys(updatedFields);
      const values = Object.values(updatedFields);
      const setClause = keys.map((key, i) => `${key} = $${i + 1}`).join(', ');

      await conn.query(
        `UPDATE work_logs SET ${setClause} WHERE id = $${keys.length + 1}`,
        [...values, workLog.id]
      );
      conn.release();

      return res.status(200).json({ message: 'Work log updated successfully.', updatedFields });
    } else {
      if (type !== 'Start Work') {
        conn.release();
        return res.status(400).json({ message: 'Start Work is required to create a new work log.' });
      }

      await conn.query(
        'INSERT INTO work_logs (employee_id, date, start_time) VALUES ($1, $2, $3)',
        [employeeId, currentDate, currentTime]
      );
      conn.release();

      return res.status(200).json({ message: 'Work log created successfully.', start_time: currentTime });
    }
  } catch (error) {
    console.error('Error logging work:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Get work logs by employee ID
app.get('/api/work-logs/:employeeId', authenticateToken, async (req, res) => {
  const { employeeId } = req.params;

  try {
    const conn = await pool.getConnection();
    const rows = await conn.query('SELECT * FROM work_logs WHERE employee_id = $1', [employeeId]);
    conn.release();

    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching work logs:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Get all work logs (admin)
app.get('/api/work-logs', authenticateToken, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const rows = await conn.query('SELECT * FROM work_logs');
    conn.release();

    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching work logs:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Update work log
app.put('/api/work-logs/:id', async (req, res) => {
  const { id } = req.params;
  const { start_time, break_start, break_end, finish_time } = req.body;

  try {
    const conn = await pool.getConnection();

    const existingWorkLog = await conn.query('SELECT * FROM work_logs WHERE id = $1', [id]);
    if (existingWorkLog.length === 0) {
      conn.release();
      return res.status(404).json({ error: 'Work log not found' });
    }

    const workLog = existingWorkLog[0];
    const updatedStartTime = start_time !== undefined ? start_time : workLog.start_time;
    const updatedBreakStart = break_start !== undefined ? break_start : workLog.break_start;
    const updatedBreakEnd = break_end !== undefined ? break_end : workLog.break_end;
    const updatedFinishTime = finish_time !== undefined ? finish_time : workLog.finish_time;

    await conn.query(
      'UPDATE work_logs SET start_time = $1, break_start = $2, break_end = $3, finish_time = $4 WHERE id = $5',
      [updatedStartTime, updatedBreakStart, updatedBreakEnd, updatedFinishTime, id]
    );
    conn.release();

    res.status(200).json({ message: 'Work log updated successfully.' });
  } catch (error) {
    console.error('Error updating work log:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get work logs for authenticated employee
app.get('/api/employee/work-logs', authenticateToken, async (req, res) => {
  const employeeId = req.user.id;

  try {
    const conn = await pool.getConnection();
    const rows = await conn.query('SELECT * FROM work_logs WHERE employee_id = $1', [employeeId]);
    conn.release();

    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching employee work logs:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Get current day work log for authenticated employee
app.get('/api/work-log', authenticateToken, async (req, res) => {
  const employeeId = req.user.id;

  try {
    const currentDate = new Date().toISOString().split('T')[0];
    const conn = await pool.getConnection();

    const workLog = await conn.query(
      'SELECT * FROM work_logs WHERE employee_id = $1 AND date = $2',
      [employeeId, currentDate]
    );
    conn.release();

    if (workLog.length > 0) {
      return res.status(200).json(workLog[0]);
    } else {
      return res.status(404).json({ message: 'No work log found for today.' });
    }
  } catch (error) {
    console.error('Error fetching work log:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(err.status || 500).json({ message: err.message || 'Internal server error.' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});