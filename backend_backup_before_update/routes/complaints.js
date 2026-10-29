const express = require('express');
const router = express.Router();
const pool = require('../db');
const { authenticateToken } = require('../middleware/auth');

const VALID_PRIORITIES = ['Low', 'Medium', 'High', 'Urgent'];
const VALID_STATUSES = ['Pending', 'Assigned', 'In Progress', 'Resolved', 'Rejected'];

// Enforce authentication on all complaint routes
router.use(authenticateToken);

/**
 * GET /api/complaints
 * List complaints with optional query filters (student_id, status, priority).
 * Enforces role-based data isolation:
 * - Students only see their own complaints
 * - Wardens only see complaints from their assigned hostel
 */
router.get('/', async (req, res) => {
  try {
    const student_id = req.query.student_id || req.query.registration_number;
    const { status, priority } = req.query;
    const conditions = [];
    const values = [];

    // Enforce data boundary based on user role
    if (req.user && req.user.role === 'student') {
      values.push(req.user.student_id);
      conditions.push(`c.student_id = $${values.length}`);
    } else if (req.user && req.user.role === 'warden') {
      values.push(req.user.hostel_id);
      conditions.push(`l.hostel_id = $${values.length}`);
    } else {
      return res.status(403).json({ error: 'Access denied: allowed roles are student and warden' });
    }

    if (status) {
      if (!VALID_STATUSES.includes(status)) {
        return res.status(400).json({
          error: `Invalid status filter. Allowed values: ${VALID_STATUSES.join(', ')}`,
        });
      }
      values.push(status);
      conditions.push(`c.status = $${values.length}`);
    }

    if (priority) {
      if (!VALID_PRIORITIES.includes(priority)) {
        return res.status(400).json({
          error: `Invalid priority filter. Allowed values: ${VALID_PRIORITIES.join(', ')}`,
        });
      }
      values.push(priority);
      conditions.push(`c.priority = $${values.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const query = `
      SELECT 
        c.complaint_id,
        c.student_id,
        s.name AS student_name,
        s.email AS student_email,
        c.location_id,
        l.location_name,
        l.floor_no,
        l.location_type,
        l.hostel_id,
        c.asset_id,
        a.asset_name,
        a.asset_type,
        c.description,
        c.complaint_date,
        c.priority,
        c.status
      FROM complaints c
      LEFT JOIN student s ON c.student_id = s.student_id
      LEFT JOIN location l ON c.location_id = l.location_id
      LEFT JOIN asset a ON c.asset_id = a.asset_id
      ${whereClause}
      ORDER BY c.complaint_date DESC
    `;

    const result = await pool.query(query, values);
    return res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error fetching complaints:', err.message);
    return res.status(500).json({ error: 'Failed to retrieve complaints' });
  }
});

/**
 * GET /api/complaints/:id
 * Retrieve a single complaint by complaint_id.
 */
router.get('/:id', async (req, res) => {
  const { id } = req.params;

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid complaint ID. Must be an integer.' });
  }

  try {
    const query = `
      SELECT 
        c.complaint_id,
        c.student_id,
        s.name AS student_name,
        s.email AS student_email,
        c.location_id,
        l.location_name,
        l.floor_no,
        l.location_type,
        l.hostel_id,
        c.asset_id,
        a.asset_name,
        a.asset_type,
        c.description,
        c.complaint_date,
        c.priority,
        c.status
      FROM complaints c
      LEFT JOIN student s ON c.student_id = s.student_id
      LEFT JOIN location l ON c.location_id = l.location_id
      LEFT JOIN asset a ON c.asset_id = a.asset_id
      WHERE c.complaint_id = $1
    `;

    const result = await pool.query(query, [parseInt(id, 10)]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Complaint not found' });
    }

    const complaint = result.rows[0];

    // Enforce data access boundary: students cannot view other students' complaints; wardens cannot view other hostels'
    if (req.user && req.user.role === 'student') {
      if (complaint.student_id !== req.user.student_id) {
        return res.status(403).json({ error: 'Access denied: complaint does not belong to you' });
      }
    } else if (req.user && req.user.role === 'warden') {
      if (complaint.hostel_id !== req.user.hostel_id) {
        return res.status(403).json({ error: "Access denied to another hostel's complaint" });
      }
    } else {
      return res.status(403).json({ error: 'Access denied: allowed roles are student and warden' });
    }

    const historyQuery = `
      SELECT history_id, complaint_id, status, changed_date, changed_by, remarks
      FROM status_history
      WHERE complaint_id = $1
      ORDER BY changed_date ASC, history_id ASC
    `;
    const historyResult = await pool.query(historyQuery, [parseInt(id, 10)]);
    complaint.status_history = historyResult.rows;

    return res.status(200).json(complaint);
  } catch (err) {
    console.error(`Error retrieving complaint ${id}:`, err.message);
    return res.status(500).json({ error: 'Failed to retrieve complaint' });
  }
});

/**
 * POST /api/complaints
 * Register a new complaint and create the initial matching status_history record in a single transaction.
 * Enforces role restriction (student only), impersonation prevention, and cross-hostel protection.
 * Required: location_id, description
 * Optional: priority (defaults to 'Medium'), asset_id (nullable), remarks (nullable)
 */
router.post('/', async (req, res) => {
  // Role verification: only students can lodge complaints
  if (req.user && req.user.role !== 'student') {
    return res.status(403).json({ error: 'Access denied: only students can register complaints' });
  }

  const requestedStudentId = req.body.student_id || req.body.registration_number;

  // Validate student_id in body
  if (!requestedStudentId || typeof requestedStudentId !== 'string' || !requestedStudentId.trim()) {
    return res.status(400).json({ error: 'student_id is required and must be a non-empty string' });
  }

  // Prevent acting as another student
  if (req.user && requestedStudentId.trim() !== req.user.student_id) {
    return res.status(403).json({ error: 'Forbidden: cannot lodge complaint for another student' });
  }

  const student_id = requestedStudentId.trim();
  const { location_id, description, priority = 'Medium', asset_id = null, remarks = null } = req.body;

  // Validate location_id
  if (location_id === undefined || location_id === null || !Number.isInteger(Number(location_id))) {
    return res.status(400).json({ error: 'location_id is required and must be an integer' });
  }
  const parsedLocationId = parseInt(location_id, 10);

  // Validate description
  if (!description || typeof description !== 'string' || !description.trim()) {
    return res.status(400).json({ error: 'description is required and must be a non-empty string' });
  }

  // Validate priority
  if (!VALID_PRIORITIES.includes(priority)) {
    return res.status(400).json({
      error: `Invalid priority. Allowed values: ${VALID_PRIORITIES.join(', ')}`,
    });
  }

  // Cross-hostel validation: verify location belongs to student's assigned hostel
  if (req.user && req.user.hostel_id) {
    const locCheck = await pool.query('SELECT hostel_id FROM location WHERE location_id = $1', [parsedLocationId]);
    if (locCheck.rows.length > 0 && locCheck.rows[0].hostel_id !== req.user.hostel_id) {
      return res.status(403).json({ error: "Forbidden: cannot lodge complaint for another hostel's location" });
    }
  }

  // Validate asset_id if provided
  let parsedAssetId = null;
  if (asset_id !== undefined && asset_id !== null) {
    if (!Number.isInteger(Number(asset_id))) {
      return res.status(400).json({ error: 'asset_id must be an integer or null' });
    }
    parsedAssetId = parseInt(asset_id, 10);
  }

  const sanitizedStudentId = student_id.trim();
  const sanitizedDescription = description.trim();
  const initialStatus = 'Pending';
  const initialRemarks = remarks !== null && typeof remarks === 'string' ? remarks.trim() : 'Complaint registered';

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // 1. Insert complaint
    const insertComplaintQuery = `
      INSERT INTO complaints (student_id, location_id, description, priority, status, asset_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING complaint_id, student_id, location_id, description, complaint_date, priority, status, asset_id
    `;

    const complaintResult = await client.query(insertComplaintQuery, [
      sanitizedStudentId,
      parsedLocationId,
      sanitizedDescription,
      priority,
      initialStatus,
      parsedAssetId,
    ]);

    const createdComplaint = complaintResult.rows[0];

    // 2. Insert initial status_history record matching the complaint
    const insertHistoryQuery = `
      INSERT INTO status_history (complaint_id, status, changed_by, remarks)
      VALUES ($1, $2, $3, $4)
      RETURNING history_id, complaint_id, status, changed_date, changed_by, remarks
    `;

    const historyResult = await client.query(insertHistoryQuery, [
      createdComplaint.complaint_id,
      initialStatus,
      sanitizedStudentId,
      initialRemarks,
    ]);

    await client.query('COMMIT');

    return res.status(201).json({
      ...createdComplaint,
      status_history: [historyResult.rows[0]],
    });
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      console.error('Rollback error:', rollbackErr.message);
    }

    // Handle foreign key constraint violations
    if (err.code === '23503') {
      if (err.constraint && (err.constraint.includes('student_id') || err.constraint.includes('student') || err.constraint.includes('registration_number'))) {
        return res.status(400).json({ error: 'Referenced student_id does not exist' });
      }
      if (err.constraint && err.constraint.includes('location_id')) {
        return res.status(400).json({ error: 'Referenced location_id does not exist' });
      }
      if (err.constraint && err.constraint.includes('asset_id')) {
        return res.status(400).json({ error: 'Referenced asset_id does not exist' });
      }
      return res.status(400).json({
        error: 'Foreign key constraint violated: referenced entity does not exist',
      });
    }

    // Handle check constraint violations
    if (err.code === '23514') {
      if (err.constraint && (err.constraint.includes('student_id') || err.constraint.includes('student') || err.constraint.includes('registration_number'))) {
        return res.status(400).json({ error: 'Invalid student_id provided' });
      }
      return res.status(400).json({ error: 'Check constraint violated. Invalid input values.' });
    }

    console.error('Error registering complaint:', err.message);
    return res.status(500).json({ error: 'Failed to register complaint' });
  } finally {
    client.release();
  }
});

// Alias for assigning complaint: POST /api/complaints/:id/assign
const { handleAssignComplaint } = require('./warden');
router.post('/:id/assign', handleAssignComplaint);

module.exports = router;
