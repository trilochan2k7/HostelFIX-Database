const express = require('express');
const router = express.Router();
const pool = require('../db');
const { authenticateToken, requireRole } = require('../middleware/auth');

const VALID_PRIORITIES = ['Low', 'Medium', 'High', 'Urgent'];
const VALID_STATUSES = ['Pending', 'Assigned', 'In Progress', 'Resolved', 'Rejected'];

// Enforce authentication and warden role on all warden routes
router.use(authenticateToken);
router.use(requireRole('warden'));

/**
 * GET /api/warden/complaints
 * View and filter complaints by status, priority, and hostel_id.
 * Enforces hostel-based data isolation so wardens cannot view other hostels' complaints.
 */
router.get('/', async (req, res) => {
  try {
    const { status, priority, hostel_id } = req.query;
    const conditions = [];
    const values = [];

    // Enforce hostel scoping for wardens
    if (req.user && req.user.hostel_id) {
      if (hostel_id) {
        if (!Number.isInteger(Number(hostel_id))) {
          return res.status(400).json({ error: 'hostel_id must be an integer' });
        }
        if (parseInt(hostel_id, 10) !== req.user.hostel_id) {
          return res.status(403).json({
            error: "Access denied: you can only view complaints for your assigned hostel",
          });
        }
      }
      values.push(req.user.hostel_id);
      conditions.push(`l.hostel_id = $${values.length}`);
    } else {
      return res.status(403).json({ error: 'Access denied: warden has no assigned hostel' });
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
        c.status,
        curr_assign.assignment_id,
        curr_assign.technician_id,
        t.name AS technician_name,
        t.phone AS technician_phone,
        t.specialization AS technician_specialization,
        curr_assign.assigned_date
      FROM complaints c
      LEFT JOIN student s ON c.student_id = s.student_id
      LEFT JOIN location l ON c.location_id = l.location_id
      LEFT JOIN hostel h ON l.hostel_id = h.hostel_id
      LEFT JOIN asset a ON c.asset_id = a.asset_id
      LEFT JOIN LATERAL (
        SELECT assignment_id, technician_id, assigned_date 
        FROM assignment 
        WHERE complaint_id = c.complaint_id 
        ORDER BY assigned_date DESC, assignment_id DESC 
        LIMIT 1
      ) curr_assign ON true
      LEFT JOIN technician t ON curr_assign.technician_id = t.technician_id
      ${whereClause}
      ORDER BY c.complaint_date DESC
    `;

    const result = await pool.query(query, values);
    return res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error fetching warden complaints:', err.message);
    return res.status(500).json({ error: 'Failed to retrieve complaints' });
  }
});

/**
 * GET /api/warden/complaints/:id
 * View full complaint details, assignment history, and status history.
 */
router.get('/:id', async (req, res) => {
  const { id } = req.params;

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid complaint ID. Must be an integer.' });
  }

  const complaintId = parseInt(id, 10);

  try {
    const complaintQuery = `
      SELECT 
        c.complaint_id,
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
        c.status
      FROM complaints c
      LEFT JOIN student s ON c.student_id = s.student_id
      LEFT JOIN location l ON c.location_id = l.location_id
      LEFT JOIN hostel h ON l.hostel_id = h.hostel_id
      LEFT JOIN asset a ON c.asset_id = a.asset_id
      WHERE c.complaint_id = $1
    `;

    const result = await pool.query(complaintQuery, [complaintId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Complaint not found' });
    }

    const complaint = result.rows[0];

    // Enforce cross-hostel protection
    if (!req.user || !req.user.hostel_id || complaint.hostel_id !== req.user.hostel_id) {
      return res.status(403).json({ error: "Access denied to another hostel's complaint" });
    }

    // Fetch status history
    const historyQuery = `
      SELECT history_id, complaint_id, status, changed_date, changed_by, remarks
      FROM status_history
      WHERE complaint_id = $1
      ORDER BY changed_date ASC, history_id ASC
    `;
    const historyResult = await pool.query(historyQuery, [complaintId]);
    complaint.status_history = historyResult.rows;

    // Fetch assignment history
    const assignmentQuery = `
      SELECT 
        ass.assignment_id,
        ass.complaint_id,
        ass.technician_id,
        t.name AS technician_name,
        t.phone AS technician_phone,
        t.specialization AS technician_specialization,
        ass.assigned_date,
        ass.completed_date
      FROM assignment ass
      LEFT JOIN technician t ON ass.technician_id = t.technician_id
      WHERE ass.complaint_id = $1
      ORDER BY ass.assigned_date DESC, ass.assignment_id DESC
    `;
    const assignmentResult = await pool.query(assignmentQuery, [complaintId]);
    complaint.assignments = assignmentResult.rows;

    return res.status(200).json(complaint);
  } catch (err) {
    console.error(`Error retrieving complaint ${id}:`, err.message);
    return res.status(500).json({ error: 'Failed to retrieve complaint details' });
  }
});

/**
 * POST /api/warden/complaints/:id/assign
 * Assign complaint to a technician and update status to 'Assigned' in a transaction.
 * Required in body: technician_id (integer)
 * Optional in body: warden_id (integer), remarks (string)
 */
async function handleAssignComplaint(req, res) {
  // Role check: only wardens can assign
  if (req.user && req.user.role !== 'warden') {
    return res.status(403).json({ error: 'Access denied: only wardens can assign complaints' });
  }

  const { id } = req.params;

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid complaint ID. Must be an integer.' });
  }

  const complaintId = parseInt(id, 10);
  const { technician_id, warden_id = null, remarks = null } = req.body;

  // Prevent acting as another warden
  if (req.user && req.user.warden_id && warden_id !== undefined && warden_id !== null) {
    if (parseInt(warden_id, 10) !== req.user.warden_id) {
      return res.status(403).json({ error: 'Access denied: cannot assign complaint as another warden' });
    }
  }

  // Validate technician_id
  if (technician_id === undefined || technician_id === null || !Number.isInteger(Number(technician_id))) {
    return res.status(400).json({ error: 'technician_id is required and must be an integer' });
  }
  const parsedTechnicianId = parseInt(technician_id, 10);

  // Validate warden_id if provided
  let parsedWardenId = null;
  if (warden_id !== undefined && warden_id !== null) {
    if (!Number.isInteger(Number(warden_id))) {
      return res.status(400).json({ error: 'warden_id must be an integer' });
    }
    parsedWardenId = parseInt(warden_id, 10);
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // 1. Lock and check complaint existence and hostel ownership
    const complaintCheck = await client.query(
      `SELECT c.complaint_id, c.status, l.hostel_id 
       FROM complaints c 
       JOIN location l ON c.location_id = l.location_id 
       WHERE c.complaint_id = $1 
       FOR UPDATE OF c`,
      [complaintId]
    );

    if (complaintCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Complaint not found' });
    }

    const complaintRow = complaintCheck.rows[0];

    // Enforce cross-hostel protection on assignment
    if (!req.user || !req.user.hostel_id || complaintRow.hostel_id !== req.user.hostel_id) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: "Access denied to another hostel's complaint" });
    }

    const currentStatus = complaintRow.status;
    if (currentStatus === 'Resolved') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Cannot assign a complaint that is already Resolved' });
    }

    // 2. Verify technician existence
    const techCheck = await client.query(
      'SELECT technician_id, name, specialization FROM technician WHERE technician_id = $1',
      [parsedTechnicianId]
    );

    if (techCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Referenced technician_id does not exist' });
    }
    const technician = techCheck.rows[0];

    // 3. Verify warden existence if warden_id provided
    let changedBy = req.user && req.user.warden_id ? String(req.user.warden_id) : 'Warden';
    if (parsedWardenId !== null) {
      const wardenCheck = await client.query(
        'SELECT warden_id, name FROM warden WHERE warden_id = $1',
        [parsedWardenId]
      );
      if (wardenCheck.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Referenced warden_id does not exist' });
      }
      changedBy = String(parsedWardenId);
    } else if (req.body.changed_by && typeof req.body.changed_by === 'string') {
      changedBy = req.body.changed_by.trim();
    }

    // 4. Insert assignment record
    const insertAssignQuery = `
      INSERT INTO assignment (complaint_id, technician_id)
      VALUES ($1, $2)
      RETURNING assignment_id, complaint_id, technician_id, assigned_date, completed_date
    `;
    const assignResult = await client.query(insertAssignQuery, [complaintId, parsedTechnicianId]);

    // 5. Update complaint status to 'Assigned'
    const updateComplaintQuery = `
      UPDATE complaints
      SET status = 'Assigned'
      WHERE complaint_id = $1
      RETURNING complaint_id, status
    `;
    await client.query(updateComplaintQuery, [complaintId]);

    // 6. Insert into status_history
    const assignRemarks = remarks && typeof remarks === 'string' && remarks.trim()
      ? remarks.trim()
      : `Assigned to technician ${technician.name} (${technician.specialization || 'General'})`;

    const insertHistoryQuery = `
      INSERT INTO status_history (complaint_id, status, changed_by, remarks)
      VALUES ($1, $2, $3, $4)
      RETURNING history_id, complaint_id, status, changed_date, changed_by, remarks
    `;
    const historyResult = await client.query(insertHistoryQuery, [
      complaintId,
      'Assigned',
      changedBy,
      assignRemarks,
    ]);

    await client.query('COMMIT');

    return res.status(200).json({
      message: 'Complaint assigned successfully',
      complaint_id: complaintId,
      status: 'Assigned',
      assignment: assignResult.rows[0],
      status_history: historyResult.rows[0],
    });
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      console.error('Rollback error on assign:', rollbackErr.message);
    }

    if (err.code === '23503') {
      if (err.constraint && err.constraint.includes('technician')) {
        return res.status(400).json({ error: 'Referenced technician_id does not exist' });
      }
      if (err.constraint && err.constraint.includes('complaint')) {
        return res.status(404).json({ error: 'Referenced complaint_id does not exist' });
      }
      return res.status(400).json({ error: 'Foreign key constraint violated on assignment' });
    }

    console.error('Error assigning complaint:', err.message);
    return res.status(500).json({ error: 'Failed to assign complaint' });
  } finally {
    client.release();
  }
}

router.post('/:id/assign', handleAssignComplaint);

module.exports = {
  router,
  handleAssignComplaint,
};
