const express = require('express');
const router = express.Router();
const pool = require('../db');
const { authenticateToken, requireRole } = require('../middleware/auth');

// Allowed status updates for technicians supported by both complaints and status_history constraints
const ALLOWED_TECHNICIAN_STATUSES = ['In Progress', 'Resolved', 'Assigned'];

// Enforce authentication and technician role on all technician routes
router.use(authenticateToken);
router.use(requireRole('technician'));

/**
 * GET /api/technician/assignments
 * View assigned complaints for technicians, with optional filtering by technician_id and status.
 * Enforces data isolation so technicians only see their own assignments.
 */
router.get('/', async (req, res) => {
  try {
    const { technician_id, status } = req.query;
    const conditions = [];
    const values = [];

    // Enforce data boundary: technician can only view their own assignments
    const authTechId = req.user && req.user.technician_id;
    if (authTechId) {
      if (technician_id) {
        if (!Number.isInteger(Number(technician_id))) {
          return res.status(400).json({ error: 'technician_id must be an integer' });
        }
        if (parseInt(technician_id, 10) !== authTechId) {
          return res.status(403).json({
            error: 'Access denied: you can only view your own assignments',
          });
        }
      }
      values.push(authTechId);
      conditions.push(`ass.technician_id = $${values.length}`);
    } else {
      return res.status(403).json({ error: 'Access denied: technician identity not found in token' });
    }

    if (status) {
      if (!ALLOWED_TECHNICIAN_STATUSES.includes(status)) {
        return res.status(400).json({
          error: `Invalid status filter. Allowed values: ${ALLOWED_TECHNICIAN_STATUSES.join(', ')}`,
        });
      }
      values.push(status);
      conditions.push(`c.status = $${values.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const query = `
      SELECT 
        ass.assignment_id,
        ass.complaint_id,
        ass.technician_id,
        t.name AS technician_name,
        t.phone AS technician_phone,
        t.specialization AS technician_specialization,
        ass.assigned_date,
        ass.completed_date,
        c.student_id,
        s.name AS student_name,
        s.email AS student_email,
        s.phone AS student_phone,
        c.location_id,
        l.location_name,
        l.floor_no,
        l.location_type,
        l.hostel_id,
        h.name AS hostel_name,
        c.asset_id,
        a.asset_name,
        a.asset_type,
        c.description,
        c.complaint_date,
        c.priority,
        c.status AS complaint_status
      FROM assignment ass
      JOIN complaints c ON ass.complaint_id = c.complaint_id
      LEFT JOIN technician t ON ass.technician_id = t.technician_id
      LEFT JOIN student s ON c.student_id = s.student_id
      LEFT JOIN location l ON c.location_id = l.location_id
      LEFT JOIN hostel h ON l.hostel_id = h.hostel_id
      LEFT JOIN asset a ON c.asset_id = a.asset_id
      ${whereClause}
      ORDER BY ass.assigned_date DESC, ass.assignment_id DESC
    `;

    const result = await pool.query(query, values);
    return res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error fetching technician assignments:', err.message);
    return res.status(500).json({ error: 'Failed to retrieve assignments' });
  }
});

/**
 * GET /api/technician/assignments/:id
 * View single assignment with full details and status history.
 */
router.get('/:id', async (req, res) => {
  const { id } = req.params;

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid assignment ID. Must be an integer.' });
  }

  const assignmentId = parseInt(id, 10);

  try {
    const query = `
      SELECT 
        ass.assignment_id,
        ass.complaint_id,
        ass.technician_id,
        t.name AS technician_name,
        t.phone AS technician_phone,
        t.specialization AS technician_specialization,
        ass.assigned_date,
        ass.completed_date,
        c.student_id,
        s.name AS student_name,
        s.email AS student_email,
        s.phone AS student_phone,
        c.location_id,
        l.location_name,
        l.floor_no,
        l.location_type,
        l.hostel_id,
        h.name AS hostel_name,
        c.asset_id,
        a.asset_name,
        a.asset_type,
        c.description,
        c.complaint_date,
        c.priority,
        c.status AS complaint_status
      FROM assignment ass
      JOIN complaints c ON ass.complaint_id = c.complaint_id
      LEFT JOIN technician t ON ass.technician_id = t.technician_id
      LEFT JOIN student s ON c.student_id = s.student_id
      LEFT JOIN location l ON c.location_id = l.location_id
      LEFT JOIN hostel h ON l.hostel_id = h.hostel_id
      LEFT JOIN asset a ON c.asset_id = a.asset_id
      WHERE ass.assignment_id = $1
    `;

    const result = await pool.query(query, [assignmentId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Assignment not found' });
    }

    const assignment = result.rows[0];

    // Enforce data boundary: technician can only view their own assignment
    if (!req.user || !req.user.technician_id || assignment.technician_id !== req.user.technician_id) {
      return res.status(403).json({ error: 'Access denied: you can only view your own assignment' });
    }

    // Fetch status history for the underlying complaint
    const historyQuery = `
      SELECT history_id, complaint_id, status, changed_date, changed_by, remarks
      FROM status_history
      WHERE complaint_id = $1
      ORDER BY changed_date ASC, history_id ASC
    `;
    const historyResult = await pool.query(historyQuery, [assignment.complaint_id]);
    assignment.status_history = historyResult.rows;

    return res.status(200).json(assignment);
  } catch (err) {
    console.error(`Error retrieving assignment ${id}:`, err.message);
    return res.status(500).json({ error: 'Failed to retrieve assignment details' });
  }
});

/**
 * PATCH /api/technician/assignments/:id/status
 * Update complaint status (and completed_date if Resolved) in a single transaction.
 * Required in body: status ('In Progress', 'Resolved', 'Assigned')
 * Optional in body: remarks (string), technician_id (integer for actor verification)
 */
router.patch('/:id/status', async (req, res) => {
  const { id } = req.params;

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid assignment ID. Must be an integer.' });
  }

  const assignmentId = parseInt(id, 10);
  const { status, remarks = null, technician_id = null } = req.body;

  // Validate status
  if (!status || typeof status !== 'string') {
    return res.status(400).json({
      error: `status is required. Allowed values: ${ALLOWED_TECHNICIAN_STATUSES.join(', ')}`,
    });
  }

  if (!ALLOWED_TECHNICIAN_STATUSES.includes(status)) {
    return res.status(400).json({
      error: `Invalid status. Allowed values: ${ALLOWED_TECHNICIAN_STATUSES.join(', ')}`,
    });
  }

  // Validate technician_id if provided
  if (technician_id !== null && technician_id !== undefined && !Number.isInteger(Number(technician_id))) {
    return res.status(400).json({ error: 'technician_id must be an integer' });
  }

  // Prevent acting as another technician
  if (req.user && req.user.technician_id && technician_id !== null && technician_id !== undefined) {
    if (parseInt(technician_id, 10) !== req.user.technician_id) {
      return res.status(403).json({ error: 'Access denied: cannot update status as another technician' });
    }
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // 1. Lock and fetch assignment
    const assignResult = await client.query(
      `SELECT assignment_id, complaint_id, technician_id
       FROM assignment
       WHERE assignment_id = $1
       FOR UPDATE`,
      [assignmentId]
    );

    if (assignResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Assignment not found' });
    }

    const assignment = assignResult.rows[0];

    // Enforce data boundary: technician can only update their own assignment
    if (!req.user || !req.user.technician_id || assignment.technician_id !== req.user.technician_id) {
      await client.query('ROLLBACK');
      return res.status(403).json({
        error: "Access denied: you cannot update another technician's assignment",
      });
    }

    // Fetch technician name for status_history logging
    let technicianName = null;
    const techResult = await client.query(
      'SELECT name FROM technician WHERE technician_id = $1',
      [assignment.technician_id]
    );
    if (techResult.rows.length > 0) {
      technicianName = techResult.rows[0].name;
    }

    // Optional verification: if technician_id is provided in body, verify it matches assignment.technician_id
    if (technician_id !== null && technician_id !== undefined) {
      if (parseInt(technician_id, 10) !== assignment.technician_id) {
        await client.query('ROLLBACK');
        return res.status(403).json({
          error: 'Assignment does not belong to the specified technician',
        });
      }
    }

    // 2. Lock complaint record
    const compResult = await client.query(
      'SELECT complaint_id, status FROM complaints WHERE complaint_id = $1 FOR UPDATE',
      [assignment.complaint_id]
    );

    if (compResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Referenced complaint not found' });
    }

    // 3. Update complaint status
    const updateCompQuery = `
      UPDATE complaints
      SET status = $1
      WHERE complaint_id = $2
      RETURNING complaint_id, status
    `;
    const updatedComp = await client.query(updateCompQuery, [status, assignment.complaint_id]);

    // 4. Update assignment completed_date (set to CURRENT_TIMESTAMP if Resolved, null otherwise)
    const updateAssignQuery = `
      UPDATE assignment
      SET completed_date = ${status === 'Resolved' ? 'CURRENT_TIMESTAMP' : 'NULL'}
      WHERE assignment_id = $1
      RETURNING assignment_id, complaint_id, technician_id, assigned_date, completed_date
    `;
    const updatedAssign = await client.query(updateAssignQuery, [assignmentId]);

    // 5. Insert audit log into status_history
    const changedBy = technicianName
      ? `${technicianName} (Tech #${assignment.technician_id})`
      : `Tech #${assignment.technician_id}`;

    const updateRemarks = remarks && typeof remarks === 'string' && remarks.trim()
      ? remarks.trim()
      : `Technician updated status to ${status}`;

    const insertHistoryQuery = `
      INSERT INTO status_history (complaint_id, status, changed_by, remarks)
      VALUES ($1, $2, $3, $4)
      RETURNING history_id, complaint_id, status, changed_date, changed_by, remarks
    `;
    const historyResult = await client.query(insertHistoryQuery, [
      assignment.complaint_id,
      status,
      changedBy.slice(0, 100), // Fit character varying(100)
      updateRemarks,
    ]);

    await client.query('COMMIT');

    return res.status(200).json({
      message: `Assignment status updated to ${status}`,
      assignment_id: assignmentId,
      complaint_id: assignment.complaint_id,
      status: updatedComp.rows[0].status,
      assignment: updatedAssign.rows[0],
      status_history: historyResult.rows[0],
    });
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      console.error('Rollback error on status update:', rollbackErr.message);
    }

    if (err.code === '23514') {
      return res.status(400).json({ error: 'Status rejected by database constraint' });
    }

    console.error('Error updating assignment status:', err.message);
    return res.status(500).json({ error: 'Failed to update assignment status' });
  } finally {
    client.release();
  }
});

module.exports = router;
