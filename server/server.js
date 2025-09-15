require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const cors = require('cors');
const path = require('path');
const { hashPassword, verifyPassword, generateResetToken } = require('./password-utils');
const config = require('./config');

const app = express();
const PORT = config.port;

// Database setup
const db = new sqlite3.Database('communication_ltd_vulnerable.db');

// Helper function to check password history
async function checkPasswordHistory(userId, newPassword, historyLimit) {
  return new Promise((resolve, reject) => {
    if (!historyLimit || historyLimit <= 0) {
      resolve(false); // No history check required, so no password reuse detected
      return;
    }
    
    // Safety limit to prevent memory issues
    const safeHistoryLimit = Math.min(historyLimit, 100);
    if (safeHistoryLimit !== historyLimit) {
      console.warn(`History limit ${historyLimit} exceeds safety limit, using ${safeHistoryLimit} instead`);
    }

    console.log("Checking password history for user:", userId, "with limit:", safeHistoryLimit);
    console.log("SQL Query: SELECT password_hash, salt FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?");
    console.log("Parameters:", [userId, safeHistoryLimit]);

    // First, let's check if there are any password history entries at all
    db.get('SELECT COUNT(*) as total FROM password_history WHERE user_id = ?', [userId], (countErr, countResult) => {
      if (countErr) {
        console.error('Error counting password history entries:', countErr);
        reject(countErr);
        return;
      }
      
      console.log(`Total password history entries for user ${userId}:`, countResult.total);

      db.all(
        'SELECT password_hash, salt FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
        [userId, safeHistoryLimit],
        (err, rows) => {
          if (err) {
            console.error('Database error in checkPasswordHistory:', err);
            reject(err);
            return;
          }

          console.log(`Found ${rows.length} password history entries`);
          
          // Debug: Log the actual data being returned
          rows.forEach((row, index) => {
            console.log(`Row ${index + 1}:`, {
              id: row.id,
              user_id: row.user_id,
              password_hash: row.password_hash ? row.password_hash.substring(0, 20) + '...' : 'null',
              salt: row.salt ? row.salt.substring(0, 20) + '...' : 'null',
              created_at: row.created_at
            });
          });

          // Check if new password matches any of the recent passwords by verifying against each stored hash
          const isPasswordReused = rows.some((row, index) => {
            console.log(`Checking password history entry ${index + 1}/${rows.length}`);
            const isReused = verifyPassword(newPassword, row.password_hash, row.salt);
            console.log(`Password reuse check result:`, isReused);
            return isReused;
          });

          console.log(`Final password reuse result:`, isPasswordReused);
          resolve(isPasswordReused);
        }
      );
    });
  });
}

// Helper function to add password to history
async function addPasswordToHistory(userId, passwordHash, salt) {
  return new Promise((resolve, reject) => {
    console.log(`Adding password to history for user ${userId}:`, {
      passwordHash: passwordHash ? passwordHash.substring(0, 20) + '...' : 'null',
      salt: salt ? salt.substring(0, 20) + '...' : 'null'
    });
    
    db.run(
      'INSERT INTO password_history (user_id, password_hash, salt) VALUES (?, ?, ?)',
      [userId, passwordHash, salt],
      (err) => {
        if (err) {
          console.error('Error adding password to history:', err);
          reject(err);
        } else {
          console.log(`Password successfully added to history for user ${userId}`);
          resolve();
        }
      }
    );
  });
}

// Helper function to validate password strength 
async function validatePassword(userId, password) {
  const errors = [];

  if (password.length < config.passwordLength) {
    errors.push(`Password must be at least ${config.passwordLength} characters long`);
  }
  if (config.passwordLimitation.includeUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must include at least one uppercase letter');
  }
  if (config.passwordLimitation.includeLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must include at least one lowercase letter');
  }
  if (config.passwordLimitation.includeNumbers && !/[0-9]/.test(password)) {
    errors.push('Password must include at least one number');
  }
  if (config.passwordLimitation.includeSpecial && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must include at least one special character');
  }
  if (config.dictionary.includes(password.toLowerCase())) {
    errors.push('Password is too common or forbidden');
  }

  if (userId !== null) {
    const isReused = await checkPasswordHistory(userId, password, config.passwordHistoryLimit + 1);
    if (isReused) {
      errors.push(`Password cannot be the same as the last ${config.passwordHistoryLimit} passwords`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

// In-memory object to track login attempts
const loginAttemptsMap = {};

// Duration (30 minutes) after which a user's failed login attempts are cleared
const ATTEMPT_RESET_TIME = 30 * 60 * 1000; 

// Helper function to handle failed login attempt 
function handleFailedAttempt(username, res) {
  const userAttempts = loginAttemptsMap[username];

  userAttempts.attempts += 1;
  userAttempts.lastAttempt = new Date();

  if (userAttempts.attempts >= config.loginAttempts) {
    userAttempts.blockedUntil = new Date(Date.now() + 30 * 60 * 1000);
    return res.status(403).json('Too many login attempts. Try again in 30 minutes.');
  }

  return res.status(401).json('Invalid credentials');
}

// Escape function for XSS prevention
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Global error handler middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json('Internal server error');
});

// Create tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    reset_token TEXT,
    reset_token_expiry DATETIME
  )`);

  // Password history table
  db.run(`CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // Clients table
  db.run(`CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullName VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20),
    packageName VARCHAR(50),
    sector VARCHAR(50),
    address VARCHAR(255)
  )`);
});

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Communication LTD API',
      version: '1.0.0',
      description: 'Simple API for Communication LTD app with intentional security vulnerabilities for educational purposes',
    },
    servers: [
      {
        url: 'http://localhost:5000',
        description: 'Development server',
      },
    ],
  },
  apis: ['./server.js'],
};

const specs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

// Email configuration (for password reset)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
  // Additional Gmail-specific settings for better reliability
  secure: true,
  port: 465,
  tls: {
    rejectUnauthorized: false
  }
});

// Verify transporter configuration
transporter.verify(function(error, success) {
  if (error) {
    console.log('Email transporter error:', error);
  } else {
    console.log('Email server is ready to send messages');
  }
});

/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - email
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: Must be unique
 *               email:
 *                 type: string
 *                 description: User's email address
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Registration failed - Invalid input or username exists
 *       500:
 *         description: Server/database error
 */
// ❌ Vulnerable Register (SQL Injection)
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  // Input validation
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    return res.status(400).json('Username is required and must be a non-empty string');
  }
  
  if (!email || typeof email !== 'string' || email.trim().length === 0) {
    return res.status(400).json('Email is required and must be a non-empty string');
  }
  
  if (!password || typeof password !== 'string' || password.trim().length === 0) {
    return res.status(400).json('Password is required and must be a non-empty string');
  }

  const { isValid, errors } = await validatePassword(null, password); 
  if (!isValid) {
    return res.status(400).json(errors.join(', '));
  }
  
  try {
    // Hash password using HMAC + Salt
    const { hash, salt } = hashPassword(password);

    // SQLi vulnerability: building query with string concatenation
    const query = `INSERT INTO users (username, email, password, salt) 
    VALUES ('${username}', '${email}', '${password}', '${salt}')`;
    
    db.run(query,
      async function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json('Username already exists');
          }
          console.error('Database error during registration:', err);
          return res.status(500).json('Registration failed');
        }
        
        try {
          // Add the initial password to history immediately
          await addPasswordToHistory(this.lastID, hash, salt);
          res.status(201).json({ message: 'User registered successfully', userId: this.lastID });
        } catch (historyError) {
          console.error('Error adding password to history:', historyError);
          // User was created but history failed - still return success
          res.status(201).json({ message: 'User registered successfully (history update failed)', userId: this.lastID });
        }
      }
    );
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json('Registration failed');
  }
});

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Login user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 *       403:
 *         description: Too many attempts, temporarily blocked
 *       500:
 *         description: Server error
 */
// ❌ Vulnerable Login (SQL Injection)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Initialize user attempts if not exists
  if (!loginAttemptsMap[username]) {
    loginAttemptsMap[username] = { attempts: 0, lastAttempt: null, blockedUntil: null };
  }

  const userAttempts = loginAttemptsMap[username];

  // Reset attempts if last attempt was too long ago
  if (userAttempts.lastAttempt && (Date.now() - userAttempts.lastAttempt.getTime()) > ATTEMPT_RESET_TIME) {
    userAttempts.attempts = 0;
    userAttempts.blockedUntil = null;
  }

  // Check if user is currently blocked
  if (userAttempts.blockedUntil) {
    if (new Date() >= userAttempts.blockedUntil) {
      // Block expired – reset attempts
      userAttempts.attempts = 0;
      userAttempts.blockedUntil = null;
    } else {
      const minutesLeft = Math.ceil((userAttempts.blockedUntil - new Date()) / 60000);
      return res.status(403).json(`Too many login attempts. Try again in ${minutesLeft} minute(s).`);
    }
  }

  // SQLi vulnerability: building query with string concatenation
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  db.get(query, async (err, user) => {
    if (err) {
      return res.status(500).json('Login failed');
    }
    
    if (!user) {
      return res.status(401).json('Invalid credentials');
    }
    
    // Successful login - reset attempts
    loginAttemptsMap[username] = { attempts: 0, lastAttempt: null, blockedUntil: null };
    
    res.json({ message: 'Login successful', userId: user.id, username: user.username, email: user.email });
  });
});


/**
 * @swagger
 * /api/change-password:
 *   post:
 *     summary: Change user password
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - oldPassword
 *               - newPassword
 *             properties:
 *               username:
 *                 type: string
 *               oldPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       400:
 *         description: Password reused or invalid data
 *       401:
 *         description: User not found
 *       500:
 *         description: Server error
 */
app.post('/api/change-password', async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  
  // Input validation
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    return res.status(400).json('Username is required and must be a non-empty string');
  }
  
  if (!oldPassword || typeof oldPassword !== 'string') {
    return res.status(400).json('Old password is required');
  }
  
  if (!newPassword || typeof newPassword !== 'string' || newPassword.trim().length === 0) {
    return res.status(400).json('New password is required and must be a non-empty string');
  }
  
  if (oldPassword === newPassword) {
    return res.status(400).json('New password must be different from old password');
  }
  
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error('Database error during password change:', err);
      return res.status(500).json('Password change failed');
    }
    
    if (!user) {
      return res.status(401).json('User not found');
    }

    // Verify old password using HMAC + Salt
    const isValidPassword = verifyPassword(oldPassword, user.password, user.salt);
    if (!isValidPassword) {
      return res.status(400).json('Invalid old password');
    }
    
    // Validate new password requirements
    const { isValid, errors } = await validatePassword(user.id, newPassword);
    if (!isValid) {
      return res.status(400).json(errors.join(', '));
    }
  
    
    // Hash new password using HMAC + Salt
    const { hash: newHash, salt: newSalt } = hashPassword(newPassword);
    
    db.run('UPDATE users SET password = ?, salt = ? WHERE username = ?', [newHash, newSalt, username], async (err) => {
      if (err) {
        console.error('Database error updating password:', err);
        return res.status(500).json('Password change failed');
      }
      
      try {
        // Add new password to history
        await addPasswordToHistory(user.id, newHash, newSalt);
        
        res.json({ message: 'Password changed successfully' });
      } catch (historyError) {
        console.error('Error updating password history:', historyError);
        // Password was changed but history update failed - still return success
        res.json({ message: 'Password changed successfully (history update failed)' });
      }
    });
  });
});

/**
 * @swagger
 * /api/request-reset-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *             properties:
 *               username:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reset token sent to email
 *       400:
 *         description: Invalid username
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error or email sending failed
 */
app.post('/api/request-reset-password', (req, res) => {
  const { username } = req.body;
  
  // Input validation
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    return res.status(400).json('Username is required and must be a non-empty string');
  }
  
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error('Database error during password reset request:', err);
      return res.status(500).json('Request failed');
    }
    
    if (!user) {
      return res.status(404).json('User not found');
    }
    
    const resetToken = generateResetToken();
    const expiry = new Date(Date.now() + 3600000); // 1 hour
    
    db.run('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE username = ?', 
      [resetToken, expiry.toISOString(), username], (err) => {
      if (err) {
        console.error('Database error updating reset token:', err);
        return res.status(500).json('Request failed');
      }
      
      // Send email with reset token
      const mailOptions = {
        from: process.env.GMAIL_USER,
        to: user.email,
        subject: 'Password Reset Token',
        text: `Your password reset token is: ${resetToken}. This token expires in 1 hour.`
      };
      
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.log('Email error:', error);
          console.log('Email error details:', {
            code: error.code,
            command: error.command,
            response: error.response,
            responseCode: error.responseCode
          });
          return res.status(500).json('Failed to send email');
        }
        
        console.log('Email sent successfully:', info.messageId);
        res.json({ message: 'Reset token sent to email' });
      });
    });
  });
});

/**
 * @swagger
 * /api/reset-password:
 *   post:
 *     summary: Reset password using token
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - token
 *               - newPassword
 *             properties:
 *               username:
 *                 type: string
 *               token:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password reset successfully
 *       400:
 *         description:  Invalid/expired token or password invalid/reused 
 *       500:
 *         description: Server error during reset
 */
app.post('/api/reset-password', async (req, res) => {
  const { username, token, newPassword } = req.body;
  
  // Input validation
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    return res.status(400).json('Username is required and must be a non-empty string');
  }
  
  if (!token || typeof token !== 'string' || token.trim().length === 0) {
    return res.status(400).json('Reset token is required');
  }
  
  if (!newPassword || typeof newPassword !== 'string' || newPassword.trim().length === 0) {
    return res.status(400).json('New password is required and must be a non-empty string');
  }

  db.get('SELECT * FROM users WHERE username = ? AND reset_token = ? AND reset_token_expiry > ?', 
    [username, token, new Date().toISOString()], async (err, user) => {
    if (err) {
      console.error('Database error during password reset:', err);
      return res.status(500).json('Reset failed');
    }
    
    if (!user) {
      return res.status(400).json('Invalid or expired token');
    }
    
    // Validate new password requirements
    const { isValid, errors } = await validatePassword(user.id, newPassword);
    if (!isValid) {
      return res.status(400).json(errors.join(', '));
    }
    
    // Hash new password using HMAC + Salt
    const { hash: newHash, salt: newSalt } = hashPassword(newPassword);
    
    db.run('UPDATE users SET password = ?, salt = ?, reset_token = NULL, reset_token_expiry = NULL WHERE username = ?', 
      [newHash, newSalt, username], async (err) => {
      if (err) {
        console.error('Database error updating password during reset:', err);
        return res.status(500).json('Reset failed');
      }
      
      try {
        // Add new password to history
        await addPasswordToHistory(user.id, newHash, newSalt);
        
        res.json({ message: 'Password reset successfully' });
      } catch (historyError) {
        console.error('Error updating password history:', historyError);
        // Password was reset but history update failed - still return success
        res.json({ message: 'Password reset successfully (history update failed)' });
      }
    });
  });
});

/**
 * @swagger
 * /api/config:
 *   get:
 *     summary: Get password configuration
 *     tags: [Configuration]
 *     responses:
 *       200:
 *         description: Password configuration settings
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 passwordLength:
 *                   type: integer
 *                 passwordLimitation:
 *                   type: object
 *                   properties:
 *                     includeUppercase:
 *                       type: boolean
 *                     includeLowercase:
 *                       type: boolean
 *                     includeNumbers:
 *                       type: boolean
 *                     includeSpecial:
 *                       type: boolean
 *                 passwordHistoryLimit:
 *                   type: integer
 */
app.get('/api/config', (req, res) => {
  res.json({
    passwordLength: config.passwordLength,
    passwordLimitation: config.passwordLimitation,
    passwordHistoryLimit: config.passwordHistoryLimit
  });
});

/**
 * @swagger
 * /api/clients:
 *   get:
 *     summary: Get all clients
 *     tags: [Clients]
 *     responses:
 *       200:
 *         description: List of all clients
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   fullName:
 *                     type: string
 *                   email:
 *                     type: string
 *                   phone:
 *                     type: string
 *                   packageName:
 *                     type: string
 *                   sector:
 *                     type: string
 *                   address:
 *                     type: string
 */
app.get('/api/clients', (req, res) => {
  db.all('SELECT * FROM clients', (err, clients) => {
    if (err) {
      console.error('Database error fetching clients:', err);
      return res.status(500).json('Failed to fetch clients');
    }
    
    // Ensure clients is always an array
    if (!clients) {
      clients = [];
    }
    
    res.json(clients);
  });
});

/**
 * @swagger
 * /api/clients:
 *   post:
 *     summary: Add new client
 *     tags: [Clients]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - fullName
 *             properties:
 *               fullName:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               packageName:
 *                 type: string
 *               sector:
 *                 type: string
 *               address:
 *                 type: string
 *     responses:
 *       201:
 *         description: Client added successfully
 *       400:
 *         description: Invalid data
 */
// ❌ Vulnerable Add Client (SQL Injection + Stored XSS)
app.post('/api/clients', (req, res) => {
  const { fullName, email, phone, packageName, sector, address } = req.body;
  
  if (!fullName || typeof fullName !== 'string' || fullName.trim().length === 0) {
    return res.status(400).json('Full name is required and must be a non-empty string');
  }
  
  // SQLi vulnerability + XSS (user input is stored as-is)
  const query = `INSERT INTO clients (fullName, email, phone, packageName, sector, address) 
  VALUES ('${fullName}', '${email}', '${phone}', '${packageName}', '${sector}', '${address}')`;
   
  db.run(query, function(err) {
    if (err) {
      console.error('Database error adding client:', err);
      return res.status(500).json('Failed to add client');
    }
    
   // Vulnerable — stored XSS (returns unsanitized user input as HTML)
    res.status(201).json({message: `Client added: ${fullName}`, clientId: this.lastID });
  });
});

// 404 handler for undefined routes - must be placed after all other routes
app.use('*', (req, res) => {
  res.status(404).json('Route not found');
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Swagger documentation available at http://localhost:${PORT}/api-docs`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nReceived SIGINT. Closing server gracefully...');
  server.close(() => {
    console.log('Server closed. Closing database connection...');
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err);
        process.exit(1);
      }
      console.log('Database connection closed. Exiting...');
      process.exit(0);
    });
  });
});

process.on('SIGTERM', () => {
  console.log('\nReceived SIGTERM. Closing server gracefully...');
  server.close(() => {
    console.log('Server closed. Closing database connection...');
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err);
        process.exit(1);
      }
      console.log('Database connection closed. Exiting...');
      process.exit(0);
    });
  });
});
