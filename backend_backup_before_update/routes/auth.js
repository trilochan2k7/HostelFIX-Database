const express = require('express');
const router = express.Router();
const pool = require('../db');
const { generateToken, comparePassword } = require('../middleware/auth');

// Constant dummy bcrypt hash (cost 12) used to perform constant-time comparison
// when user or password_hash is missing, mitigating timing side-channels and user enumeration.
const DUMMY_HASH = '$2b$12$e80MvQv5m4kH6u7Zq7vF0.yX7o1Zq7vF0.yX7o1Zq7vF0.yX7o1Zq';

/**
 * Authenticate user credentials and return JWT token and safe user profile.
 * Separated for testability and dependency injection.
 *
 * @param {Object} params
 * @param {string} params.role - 'student' | 'warden' | 'technician'
 * @param {string} [params.identifier] - General identifier (ID, email, or phone)
 * @param {string} [params.student_id]
 * @param {string|number} [params.warden_id]
 * @param {string|number} [params.technician_id]
 * @param {string} [params.email]
 * @param {string} [params.phone]
 * @param {string} params.password - Plaintext password to verify
 * @param {Object} [params.db] - PostgreSQL client/pool (defaults to shared pool)
 * @returns {Promise<{ status: number, body: Object }>}
 */
async function authenticateUser({
  role,
  identifier,
  student_id,
  warden_id,
  technician_id,
  email,
  phone,
  password,
  db = pool,
}) {
  // 1. Role validation
  if (!role || !['student', 'warden', 'technician'].includes(role)) {
    return {
      status: 400,
      body: { error: "role is required and must be 'student', 'warden', or 'technician'" },
    };
  }

  // 2. Password validation
  if (!password || typeof password !== 'string' || !password.trim()) {
    return {
      status: 400,
      body: { error: 'password is required and must be a non-empty string' },
    };
  }

  let queryWithHash;
  let queryWithoutHash;
  let values;

  // 3. Resolve role-specific identifiers and queries
  if (role === 'student') {
    const rawId = student_id || (!email ? identifier : null);
    const rawEmail = email || (!student_id ? identifier : null);

    if (!rawId && !rawEmail) {
      return {
        status: 400,
        body: { error: 'student_id or email is required for student login' },
      };
    }

    if (rawId && rawEmail && rawId !== rawEmail) {
      queryWithHash = `
        SELECT student_id, name, email, phone, hostel_id, password_hash
        FROM student
        WHERE student_id = $1 AND email = $2
      `;
      queryWithoutHash = `
        SELECT student_id, name, email, phone, hostel_id
        FROM student
        WHERE student_id = $1 AND email = $2
      `;
      values = [String(rawId).trim(), String(rawEmail).trim()];
    } else {
      const target = String(rawId || rawEmail).trim();
      queryWithHash = `
        SELECT student_id, name, email, phone, hostel_id, password_hash
        FROM student
        WHERE student_id = $1 OR email = $1
      `;
      queryWithoutHash = `
        SELECT student_id, name, email, phone, hostel_id
        FROM student
        WHERE student_id = $1 OR email = $1
      `;
      values = [target];
    }
  } else if (role === 'warden') {
    const rawWId = warden_id || (identifier && /^\d+$/.test(String(identifier).trim()) ? identifier : null);
    const rawWEmail = email || (identifier && !/^\d+$/.test(String(identifier).trim()) ? identifier : null);

    if (!rawWId && !rawWEmail) {
      return {
        status: 400,
        body: { error: 'warden_id or email is required for warden login' },
      };
    }

    if (rawWId && rawWEmail) {
      queryWithHash = `
        SELECT warden_id, name, email, phone, hostel_id, password_hash
        FROM warden
        WHERE warden_id = $1 AND email = $2
      `;
      queryWithoutHash = `
        SELECT warden_id, name, email, phone, hostel_id
        FROM warden
        WHERE warden_id = $1 AND email = $2
      `;
      values = [parseInt(rawWId, 10), String(rawWEmail).trim()];
    } else if (rawWId) {
      queryWithHash = `
        SELECT warden_id, name, email, phone, hostel_id, password_hash
        FROM warden
        WHERE warden_id = $1
      `;
      queryWithoutHash = `
        SELECT warden_id, name, email, phone, hostel_id
        FROM warden
        WHERE warden_id = $1
      `;
      values = [parseInt(rawWId, 10)];
    } else {
      queryWithHash = `
        SELECT warden_id, name, email, phone, hostel_id, password_hash
        FROM warden
        WHERE email = $1
      `;
      queryWithoutHash = `
        SELECT warden_id, name, email, phone, hostel_id
        FROM warden
        WHERE email = $1
      `;
      values = [String(rawWEmail).trim()];
    }
  } else if (role === 'technician') {
    const rawTId = technician_id || (identifier && /^\d+$/.test(String(identifier).trim()) ? identifier : null);
    const rawTPhone = phone || (identifier && !/^\d+$/.test(String(identifier).trim()) ? identifier : null);

    if (!rawTId && !rawTPhone) {
      return {
        status: 400,
        body: { error: 'technician_id or phone is required for technician login' },
      };
    }

    if (rawTId && rawTPhone) {
      queryWithHash = `
        SELECT technician_id, name, phone, specialization, warden_id, password_hash
        FROM technician
        WHERE technician_id = $1 AND phone = $2
      `;
      queryWithoutHash = `
        SELECT technician_id, name, phone, specialization, warden_id
        FROM technician
        WHERE technician_id = $1 AND phone = $2
      `;
      values = [parseInt(rawTId, 10), String(rawTPhone).trim()];
    } else if (rawTId) {
      queryWithHash = `
        SELECT technician_id, name, phone, specialization, warden_id, password_hash
        FROM technician
        WHERE technician_id = $1
      `;
      queryWithoutHash = `
        SELECT technician_id, name, phone, specialization, warden_id
        FROM technician
        WHERE technician_id = $1
      `;
      values = [parseInt(rawTId, 10)];
    } else {
      queryWithHash = `
        SELECT technician_id, name, phone, specialization, warden_id, password_hash
        FROM technician
        WHERE phone = $1
      `;
      queryWithoutHash = `
        SELECT technician_id, name, phone, specialization, warden_id
        FROM technician
        WHERE phone = $1
      `;
      values = [String(rawTPhone).trim()];
    }
  }

  // 4. Query user from database safely
  let userRecord = null;
  try {
    const result = await db.query(queryWithHash, values);
    if (result && result.rows && result.rows.length > 0) {
      userRecord = result.rows[0];
    }
  } catch (err) {
    if (err.code === '42703') {
      // undefined_column: password_hash column not yet present in database
      // Fallback query to verify user presence, but treat account as having NULL password_hash
      try {
        const fallbackRes = await db.query(queryWithoutHash, values);
        if (fallbackRes && fallbackRes.rows && fallbackRes.rows.length > 0) {
          userRecord = { ...fallbackRes.rows[0], password_hash: null };
        }
      } catch (fallbackErr) {
        console.error('Fallback query error during login:', fallbackErr.message);
        return { status: 500, body: { error: 'Authentication failed due to server error' } };
      }
    } else {
      console.error('Database query error during login:', err.message);
      return { status: 500, body: { error: 'Authentication failed due to server error' } };
    }
  }

  // 5. User not found OR account has NULL password_hash (unactivated account)
  // Constant-time dummy comparison mitigates timing side-channels and user enumeration.
  if (!userRecord || userRecord.password_hash === null || userRecord.password_hash === undefined || !userRecord.password_hash) {
    await comparePassword(password, DUMMY_HASH);
    return {
      status: 401,
      body: { error: 'Invalid credentials' },
    };
  }

  // 6. Verify password against stored bcrypt hash
  const isMatch = await comparePassword(password, userRecord.password_hash);
  if (!isMatch) {
    return {
      status: 401,
      body: { error: 'Invalid credentials' },
    };
  }

  // 7. Issue JWT with matching role and account ID claims
  let token;
  let safeUser;

  if (role === 'student') {
    token = generateToken({
      role: 'student',
      id: userRecord.student_id,
      student_id: userRecord.student_id,
      hostel_id: userRecord.hostel_id,
      name: userRecord.name,
    });
    safeUser = {
      role: 'student',
      student_id: userRecord.student_id,
      name: userRecord.name,
      email: userRecord.email,
      phone: userRecord.phone,
      hostel_id: userRecord.hostel_id,
    };
  } else if (role === 'warden') {
    token = generateToken({
      role: 'warden',
      id: userRecord.warden_id,
      warden_id: userRecord.warden_id,
      hostel_id: userRecord.hostel_id,
      name: userRecord.name,
    });
    safeUser = {
      role: 'warden',
      warden_id: userRecord.warden_id,
      name: userRecord.name,
      email: userRecord.email,
      phone: userRecord.phone,
      hostel_id: userRecord.hostel_id,
    };
  } else if (role === 'technician') {
    token = generateToken({
      role: 'technician',
      id: userRecord.technician_id,
      technician_id: userRecord.technician_id,
      name: userRecord.name,
    });
    safeUser = {
      role: 'technician',
      technician_id: userRecord.technician_id,
      name: userRecord.name,
      phone: userRecord.phone,
      specialization: userRecord.specialization,
    };
  }

  return {
    status: 200,
    body: {
      message: 'Login successful',
      token,
      user: safeUser,
    },
  };
}

/**
 * POST /api/auth/login
 * Secure authentication endpoint verifying credentials with bcrypt and issuing JWTs.
 */
router.post('/login', async (req, res) => {
  try {
    const { status, body } = await authenticateUser({
      ...req.body,
      db: pool,
    });
    return res.status(status).json(body);
  } catch (err) {
    console.error('Unhandled error during login:', err.message);
    return res.status(500).json({ error: 'Authentication service encountered an error' });
  }
});

module.exports = router;
module.exports.authenticateUser = authenticateUser;
module.exports.DUMMY_HASH = DUMMY_HASH;
