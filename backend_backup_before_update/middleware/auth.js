require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET must be defined in .env');
}

const BCRYPT_SALT_ROUNDS = 12;

/**
 * Validate plaintext password against security requirements:
 * - Must be a string
 * - Minimum 12 characters
 * - Maximum 72 UTF-8 bytes (bcrypt truncation boundary)
 * @param {string} plainPassword
 * @returns {{ valid: boolean, error?: string }}
 */
function validatePassword(plainPassword) {
  if (typeof plainPassword !== 'string') {
    return { valid: false, error: 'Password must be a string' };
  }
  if (plainPassword.length < 12) {
    return { valid: false, error: 'Password must be at least 12 characters long' };
  }
  const byteLength = Buffer.byteLength(plainPassword, 'utf8');
  if (byteLength > 72) {
    return { valid: false, error: 'Password exceeds maximum length of 72 UTF-8 bytes' };
  }
  return { valid: true };
}

/**
 * Securely hash a plaintext password with bcrypt (cost factor 12).
 * Validates password rules before hashing.
 * Never stores or returns plaintext passwords.
 * @param {string} plainPassword
 * @returns {Promise<string>}
 */
async function hashPassword(plainPassword) {
  const validation = validatePassword(plainPassword);
  if (!validation.valid) {
    throw new Error(validation.error);
  }
  const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
  return bcrypt.hash(plainPassword, salt);
}

/**
 * Compare a plaintext password against a stored bcrypt hash.
 */
async function comparePassword(plainPassword, hashedPassword) {
  return bcrypt.compare(plainPassword, hashedPassword);
}

/**
 * Generate a signed JWT token for an authenticated user.
 * @param {Object} payload - User information (role, id, student_id/warden_id/technician_id, hostel_id)
 * @param {string} expiresIn - Token lifetime (e.g., '24h')
 */
function generateToken(payload, expiresIn = '24h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

/**
 * Express middleware to authenticate JWT tokens from Authorization header.
 * Header format: Authorization: Bearer <token>
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return res.status(401).json({ error: 'Authorization header format must be: Bearer <token>' });
  }

  const token = parts[1];

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired authentication token' });
    }
    req.user = user;
    next();
  });
}

/**
 * Express middleware to enforce allowed user roles.
 * @param {...string} allowedRoles - e.g. 'student', 'warden', 'technician'
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied. Allowed roles: ${allowedRoles.join(', ')}`,
      });
    }

    next();
  };
}

module.exports = {
  JWT_SECRET,
  BCRYPT_SALT_ROUNDS,
  generateToken,
  authenticateToken,
  requireRole,
  validatePassword,
  hashPassword,
  comparePassword,
};
