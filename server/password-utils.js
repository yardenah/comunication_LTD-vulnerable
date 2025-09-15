const crypto = require('crypto');

/**
 * Password utility functions using HMAC + Salt
 * This provides strong cryptographic security for password storage
 */
 
// Configuration
const HMAC_ALGORITHM = 'sha256';
const SALT_LENGTH = 32; // 32 bytes = 256 bits
const ITERATIONS = 10000; // Number of HMAC iterations for additional security

/**
 * Generate a cryptographically secure random salt
 * @returns {string} Base64 encoded salt
 */
function generateSalt() {  
  return crypto.randomBytes(SALT_LENGTH).toString('base64');
}

/**
 * Hash a password using HMAC + Salt
 * @param {string} password - Plain text password
 * @param {string} salt - Salt to use (if not provided, will generate new one)
 * @returns {object} Object containing hash and salt
 */
function hashPassword(password, salt = null) {
  if (!password || typeof password !== 'string') {
    throw new Error('Password is required and must be a string');
  }
  
  if (password.length === 0) {
    throw new Error('Password cannot be empty');
  }
  
  // Generate new salt if not provided
  const usedSalt = salt || generateSalt();
  
  // Perform multiple iterations for additional security
  let hash = password;
  for (let i = 0; i < ITERATIONS; i++) {
    // Create a new HMAC instance for each iteration
    const hmac = crypto.createHmac(HMAC_ALGORITHM, usedSalt);
    hmac.update(hash);
    hash = hmac.digest('hex');
  }
  
  return {
    hash: hash,
    salt: usedSalt
  };
}

/**
 * Verify a password against a stored hash and salt
 * @param {string} password - Plain text password to verify
 * @param {string} storedHash - Stored hash from database
 * @param {string} storedSalt - Stored salt from database
 * @returns {boolean} True if password matches, false otherwise
 */
function verifyPassword(password, storedHash, storedSalt) {
  if (!password || typeof password !== 'string' || password.length === 0) {
    return false;
  }
  
  if (!storedHash || typeof storedHash !== 'string' || storedHash.length === 0) {
    return false;
  }
  
  if (!storedSalt || typeof storedSalt !== 'string' || storedSalt.length === 0) {
    return false;
  }
  
  try {
    const { hash } = hashPassword(password, storedSalt);
    return crypto.timingSafeEqual(
      Buffer.from(hash, 'hex'),
      Buffer.from(storedHash, 'hex')
    );
  } catch (error) {
    console.error('Password verification error:', error);
    return false;
  }
}

/**
 * Generate a secure random token for password reset using SHA-1
 * @param {number} length - Length of token in bytes (default: 32)
 * @returns {string} SHA-1 hashed token
 */
function generateResetToken(length = 32) {
  // Generate random bytes as input for SHA-1
  const randomBytes = crypto.randomBytes(length);
  // Create SHA-1 hash of the random bytes
  const hash = crypto.createHash('sha1');
  hash.update(randomBytes);
  return hash.digest('hex');
}

module.exports = {
  generateSalt,
  hashPassword,
  verifyPassword,
  generateResetToken
};
