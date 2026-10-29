const app = require('../server');
const pool = require('../db');
const jwt = require('jsonwebtoken');
const {
  generateToken,
  validatePassword,
  hashPassword,
  comparePassword,
  BCRYPT_SALT_ROUNDS,
  JWT_SECRET,
} = require('../middleware/auth');
const { setUserPassword } = require('../scripts/set-user-password');
const { authenticateUser } = require('../routes/auth');

async function runTests() {
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  console.log(`Test server running at ${baseUrl}`);

  // Warm up pool connection with retry for transient initial DNS resolution
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await pool.query('SELECT 1');
      break;
    } catch (e) {
      if (attempt === 2) throw e;
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`[PASS] ${message}`);
      passed++;
    } else {
      console.error(`[FAIL] ${message}`);
      failed++;
    }
  }

  // Generate test JWT tokens
  const studentToken = generateToken({
    role: 'student',
    id: 'S101',
    student_id: 'S101',
    hostel_id: 1,
    name: 'Test Student',
  });

  const wardenToken = generateToken({
    role: 'warden',
    id: 2,
    warden_id: 2,
    hostel_id: 1,
    name: 'Test Warden Hostel 1',
  });

  const otherHostelWardenToken = generateToken({
    role: 'warden',
    id: 6,
    warden_id: 6,
    hostel_id: 2,
    name: 'Test Warden Hostel 2',
  });

  const technicianToken = generateToken({
    role: 'technician',
    id: 1,
    technician_id: 1,
    name: 'Test Technician 1',
  });

  const otherTechnicianToken = generateToken({
    role: 'technician',
    id: 2,
    technician_id: 2,
    name: 'Test Technician 2',
  });

  try {
    // 1. GET /health - must remain public without auth
    {
      const res = await fetch(`${baseUrl}/health`);
      const body = await res.json();
      assert(res.status === 200, 'GET /health returns 200 without authentication');
      assert(body.status === 'ok' && body.database === 'connected', 'GET /health reports ok and connected');
    }

    // 2. Authentication enforcement: Missing token returns 401
    {
      const compRes = await fetch(`${baseUrl}/api/complaints`);
      assert(compRes.status === 401, 'GET /api/complaints without token returns 401');

      const wardenRes = await fetch(`${baseUrl}/api/warden/complaints`);
      assert(wardenRes.status === 401, 'GET /api/warden/complaints without token returns 401');

      const techRes = await fetch(`${baseUrl}/api/technician/assignments`);
      assert(techRes.status === 401, 'GET /api/technician/assignments without token returns 401');
    }

    // 3. Authentication enforcement: Invalid token returns 403
    {
      const res = await fetch(`${baseUrl}/api/complaints`, {
        headers: { Authorization: 'Bearer invalid.token.payload' },
      });
      assert(res.status === 403, 'GET /api/complaints with invalid token returns 403');
    }

    // 4. Role-based authorization enforcement
    {
      // Student cannot access warden routes
      const sToW = await fetch(`${baseUrl}/api/warden/complaints`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });
      assert(sToW.status === 403, 'Student token cannot access /api/warden/complaints (403)');

      // Student cannot access technician routes
      const sToT = await fetch(`${baseUrl}/api/technician/assignments`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });
      assert(sToT.status === 403, 'Student token cannot access /api/technician/assignments (403)');

      // Warden cannot access technician routes
      const wToT = await fetch(`${baseUrl}/api/technician/assignments`, {
        headers: { Authorization: `Bearer ${wardenToken}` },
      });
      assert(wToT.status === 403, 'Warden token cannot access /api/technician/assignments (403)');

      // Warden cannot register complaints (student only)
      const wPostComp = await fetch(`${baseUrl}/api/complaints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${wardenToken}`,
        },
        body: JSON.stringify({ student_id: 'S101', location_id: 1, description: 'Test' }),
      });
      assert(wPostComp.status === 403, 'Warden token cannot POST /api/complaints (403)');

      // Technician cannot access warden routes
      const tToW = await fetch(`${baseUrl}/api/warden/complaints`, {
        headers: { Authorization: `Bearer ${technicianToken}` },
      });
      assert(tToW.status === 403, 'Technician token cannot access /api/warden/complaints (403)');

      // Technician cannot access complaints list route
      const tToC = await fetch(`${baseUrl}/api/complaints`, {
        headers: { Authorization: `Bearer ${technicianToken}` },
      });
      assert(tToC.status === 403, 'Technician token cannot access /api/complaints (403)');

      // Technician cannot POST /api/complaints
      const tPostComp = await fetch(`${baseUrl}/api/complaints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${technicianToken}`,
        },
        body: JSON.stringify({ student_id: 'S101', location_id: 1, description: 'Test' }),
      });
      assert(tPostComp.status === 403, 'Technician token cannot POST /api/complaints (403)');

      // Student cannot access warden assign route
      const sAssign = await fetch(`${baseUrl}/api/warden/complaints/1/assign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${studentToken}`,
        },
        body: JSON.stringify({ technician_id: 1 }),
      });
      assert(sAssign.status === 403, 'Student token cannot access /api/warden/complaints/:id/assign (403)');
    }

    // 5. POST /api/auth/login tests: secure bcrypt authentication, role claims, and safe rejection
    {
      // 5.1 Validation: missing role
      const noRoleLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ student_id: 'S101', password: 'ValidPassword123!' }),
      });
      assert(noRoleLogin.status === 400, 'POST /api/auth/login without role returns 400');

      // 5.2 Validation: invalid role
      const invalidRoleLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'admin', student_id: 'S101', password: 'ValidPassword123!' }),
      });
      assert(invalidRoleLogin.status === 400, 'POST /api/auth/login with invalid role returns 400');

      // 5.3 Validation: missing password
      const noPassLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'warden', warden_id: 2 }),
      });
      assert(noPassLogin.status === 400, 'POST /api/auth/login without password returns 400');

      // 5.4 Validation: missing identifier
      const noIdLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'warden', password: 'ValidPassword123!' }),
      });
      assert(noIdLogin.status === 400, 'POST /api/auth/login without identifier returns 400');

      // 5.5 Rejection: non-existent account returns 401 without leaking account existence
      const nonExistentLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'warden', warden_id: 999999, password: 'ValidPassword123!' }),
      });
      const nonExistentBody = await nonExistentLogin.json();
      assert(nonExistentLogin.status === 401, 'POST /api/auth/login for non-existent account returns 401');
      assert(nonExistentBody.error === 'Invalid credentials', 'Rejection error is generic (Invalid credentials)');

      // 5.6 Rejection: account with NULL password_hash returns 401 without leaking unactivated state
      // (Warden ID 2 exists in Neon, but has no password_hash set)
      const unactivatedLogin = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'warden', warden_id: 2, password: 'SomePassword123!' }),
      });
      const unactivatedBody = await unactivatedLogin.json();
      assert(unactivatedLogin.status === 401, 'POST /api/auth/login for unactivated account (NULL password_hash) returns 401');
      assert(unactivatedBody.error === 'Invalid credentials', 'NULL password_hash returns identical generic 401 message');

      // 5.7 Full authentication & claims verification with valid bcrypt password (simulated records)
      const validPlainPass = 'CorrectPassword#2026';
      const realBcryptHash = await hashPassword(validPlainPass);

      // Student login flow
      const mockStudentDb = {
        query: async () => ({
          rows: [
            {
              student_id: 'S101',
              name: 'Alice Student',
              email: 'alice@hostel.test',
              phone: '9876543210',
              hostel_id: 1,
              password_hash: realBcryptHash,
            },
          ],
        }),
      };

      const studentAuthRes = await authenticateUser({
        role: 'student',
        student_id: 'S101',
        password: validPlainPass,
        db: mockStudentDb,
      });
      assert(studentAuthRes.status === 200, 'Student login with matching password returns 200');
      assert(!!studentAuthRes.body.token, 'Student login returns signed JWT');
      assert(studentAuthRes.body.user && studentAuthRes.body.user.password_hash === undefined, 'Student response does not expose password_hash');
      const decodedStudent = jwt.verify(studentAuthRes.body.token, JWT_SECRET);
      assert(decodedStudent.role === 'student' && decodedStudent.student_id === 'S101' && decodedStudent.hostel_id === 1, 'Student JWT has matching role, student_id, and hostel_id claims');

      // Warden login flow
      const mockWardenDb = {
        query: async () => ({
          rows: [
            {
              warden_id: 2,
              name: 'Bob Warden',
              email: 'bob@hostel.test',
              phone: '9876543211',
              hostel_id: 1,
              password_hash: realBcryptHash,
            },
          ],
        }),
      };

      const wardenAuthRes = await authenticateUser({
        role: 'warden',
        warden_id: 2,
        password: validPlainPass,
        db: mockWardenDb,
      });
      assert(wardenAuthRes.status === 200, 'Warden login with matching password returns 200');
      assert(!!wardenAuthRes.body.token, 'Warden login returns signed JWT');
      assert(wardenAuthRes.body.user && wardenAuthRes.body.user.password_hash === undefined, 'Warden response does not expose password_hash');
      const decodedWarden = jwt.verify(wardenAuthRes.body.token, JWT_SECRET);
      assert(decodedWarden.role === 'warden' && decodedWarden.warden_id === 2 && decodedWarden.hostel_id === 1, 'Warden JWT has matching role, warden_id, and hostel_id claims');

      // Technician login flow
      const mockTechDb = {
        query: async () => ({
          rows: [
            {
              technician_id: 1,
              name: 'Charlie Tech',
              phone: '9876543212',
              specialization: 'Electrical',
              warden_id: 2,
              password_hash: realBcryptHash,
            },
          ],
        }),
      };

      const techAuthRes = await authenticateUser({
        role: 'technician',
        technician_id: 1,
        password: validPlainPass,
        db: mockTechDb,
      });
      assert(techAuthRes.status === 200, 'Technician login with matching password returns 200');
      assert(!!techAuthRes.body.token, 'Technician login returns signed JWT');
      assert(techAuthRes.body.user && techAuthRes.body.user.password_hash === undefined, 'Technician response does not expose password_hash');
      const decodedTech = jwt.verify(techAuthRes.body.token, JWT_SECRET);
      assert(decodedTech.role === 'technician' && decodedTech.technician_id === 1, 'Technician JWT has matching role and technician_id claims');

      // Incorrect password fails with 401
      const wrongPassRes = await authenticateUser({
        role: 'student',
        student_id: 'S101',
        password: 'WrongPassword123!',
        db: mockStudentDb,
      });
      assert(wrongPassRes.status === 401, 'Incorrect password returns 401');
      assert(wrongPassRes.body.error === 'Invalid credentials', 'Incorrect password returns generic Invalid credentials');

      // Account with NULL password_hash fails with 401
      const mockNullHashDb = {
        query: async () => ({
          rows: [
            {
              student_id: 'S101',
              name: 'Alice Student',
              email: 'alice@hostel.test',
              hostel_id: 1,
              password_hash: null,
            },
          ],
        }),
      };
      const nullHashRes = await authenticateUser({
        role: 'student',
        student_id: 'S101',
        password: validPlainPass,
        db: mockNullHashDb,
      });
      assert(nullHashRes.status === 401, 'Account with NULL password_hash returns 401');
      assert(nullHashRes.body.error === 'Invalid credentials', 'NULL password_hash returns generic Invalid credentials');
    }

    // 6. Impersonation prevention tests
    {
      // Student cannot lodge complaint as another student
      const imposterStudent = await fetch(`${baseUrl}/api/complaints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${studentToken}`,
        },
        body: JSON.stringify({
          student_id: 'ANOTHER_STUDENT_ID',
          location_id: 1,
          description: 'Impersonation attempt',
        }),
      });
      assert(imposterStudent.status === 403, 'Student lodging complaint for another student returns 403');

      // Warden cannot assign complaint as another warden
      const imposterWarden = await fetch(`${baseUrl}/api/warden/complaints/1/assign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${wardenToken}`,
        },
        body: JSON.stringify({
          technician_id: 1,
          warden_id: 9999, // Mismatched warden_id
        }),
      });
      assert(imposterWarden.status === 403, 'Warden assigning complaint as another warden returns 403');

      // Technician cannot update status as another technician
      const imposterTech = await fetch(`${baseUrl}/api/technician/assignments/1/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${technicianToken}`,
        },
        body: JSON.stringify({
          status: 'In Progress',
          technician_id: 9999, // Mismatched technician_id
        }),
      });
      assert(imposterTech.status === 403, 'Technician updating status as another technician returns 403');
    }

    // 7. Cross-hostel data isolation tests
    {
      // Warden cannot query complaints outside their assigned hostel
      const crossHostelWarden = await fetch(`${baseUrl}/api/warden/complaints?hostel_id=2`, {
        headers: { Authorization: `Bearer ${wardenToken}` }, // Warden is for hostel 1
      });
      assert(crossHostelWarden.status === 403, 'Warden querying another hostel complaints returns 403');

      // Technician cannot view another technician assignments
      const crossTech = await fetch(`${baseUrl}/api/technician/assignments?technician_id=2`, {
        headers: { Authorization: `Bearer ${technicianToken}` }, // Tech 1 querying Tech 2
      });
      assert(crossTech.status === 403, 'Technician querying another technician assignments returns 403');
    }

    // 8. GET /api/complaints with student token
    {
      const res = await fetch(`${baseUrl}/api/complaints`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });
      const body = await res.json();
      assert(res.status === 200, 'GET /api/complaints returns 200 with student token');
      assert(Array.isArray(body), 'GET /api/complaints returns an array');
    }

    // 9. GET /api/complaints/:id with non-numeric ID
    {
      const res = await fetch(`${baseUrl}/api/complaints/not-a-number`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });
      const body = await res.json();
      assert(res.status === 400, 'GET /api/complaints/not-a-number returns 400');
      assert(body.error && body.error.includes('integer'), 'GET /api/complaints/not-a-number error clarifies integer requirement');
    }

    // 10. GET /api/complaints/:id with non-existent ID
    {
      const res = await fetch(`${baseUrl}/api/complaints/999999`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });
      const body = await res.json();
      assert(res.status === 404, 'GET /api/complaints/999999 returns 404');
      assert(body.error === 'Complaint not found', 'GET /api/complaints/999999 returns not found error');
    }

    // 11. POST /api/complaints - validation: missing student_id
    {
      const res = await fetch(`${baseUrl}/api/complaints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${studentToken}`,
        },
        body: JSON.stringify({
          location_id: 1,
          description: 'Broken window',
        }),
      });
      const body = await res.json();
      assert(res.status === 400, 'POST /api/complaints without student_id returns 400');
      assert(body.error && body.error.includes('student_id'), 'Validation error mentions student_id');
    }

    // 12. POST /api/complaints - validation: missing location_id
    {
      const res = await fetch(`${baseUrl}/api/complaints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${studentToken}`,
        },
        body: JSON.stringify({
          student_id: 'S101',
          description: 'Broken window',
        }),
      });
      const body = await res.json();
      assert(res.status === 400, 'POST /api/complaints without location_id returns 400');
      assert(body.error && body.error.includes('location_id'), 'Validation error mentions location_id');
    }

    // 13. POST /api/complaints - validation: empty description
    {
      const res = await fetch(`${baseUrl}/api/complaints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${studentToken}`,
        },
        body: JSON.stringify({
          student_id: 'S101',
          location_id: 1,
          description: '   ',
        }),
      });
      const body = await res.json();
      assert(res.status === 400, 'POST /api/complaints with empty description returns 400');
      assert(body.error && body.error.includes('description'), 'Validation error mentions description');
    }

    // 14. POST /api/complaints - validation: invalid priority
    {
      const res = await fetch(`${baseUrl}/api/complaints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${studentToken}`,
        },
        body: JSON.stringify({
          student_id: 'S101',
          location_id: 1,
          description: 'Broken tap',
          priority: 'SuperUrgent',
        }),
      });
      const body = await res.json();
      assert(res.status === 400, 'POST /api/complaints with invalid priority returns 400');
      assert(body.error && body.error.includes('Invalid priority'), 'Validation error mentions priority');
    }

    // 15. POST /api/complaints - validation: invalid asset_id
    {
      const res = await fetch(`${baseUrl}/api/complaints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${studentToken}`,
        },
        body: JSON.stringify({
          student_id: 'S101',
          location_id: 1,
          description: 'Broken tap',
          asset_id: 'invalid-id',
        }),
      });
      const body = await res.json();
      assert(res.status === 400, 'POST /api/complaints with invalid asset_id returns 400');
      assert(body.error && body.error.includes('asset_id'), 'Validation error mentions asset_id');
    }

    // 16. POST /api/complaints - FK constraint rejection rolls back transaction
    {
      const res = await fetch(`${baseUrl}/api/complaints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${studentToken}`,
        },
        body: JSON.stringify({
          student_id: 'S101',
          location_id: 999999,
          description: 'Water leak',
          priority: 'High',
        }),
      });
      const body = await res.json();
      assert(res.status === 400, 'POST /api/complaints with non-existent foreign key returns 400');
      assert(body.error && (body.error.includes('Referenced') || body.error.includes('Foreign key')), 'Safe error message returned for foreign key rejection');
    }

    // 17. Transactional atomicity & status_history verification with clean ROLLBACK (leaves 0 records in Neon)
    {
      const testClient = await pool.connect();
      try {
        await testClient.query('BEGIN');

        // Fetch valid hostel
        const hostelRes = await testClient.query('SELECT hostel_id FROM hostel LIMIT 1');
        assert(hostelRes.rows.length > 0, 'Found existing hostel for transaction test');
        const hostelId = hostelRes.rows[0].hostel_id;

        // Create student & location inside the transaction
        const tempStudentId = 'STU_' + Date.now().toString().slice(-10);
        await testClient.query(
          'INSERT INTO student (student_id, name, email, hostel_id) VALUES ($1, $2, $3, $4)',
          [tempStudentId, 'Transaction Test Student', `${tempStudentId}@hostel.test`, hostelId]
        );

        const locRes = await testClient.query(
          'INSERT INTO location (location_name, floor_no, location_type, hostel_id) VALUES ($1, $2, $3, $4) RETURNING location_id',
          ['Tx Test Room', 2, 'Room', hostelId]
        );
        const tempLocationId = locRes.rows[0].location_id;

        // Insert complaint inside transaction
        const compRes = await testClient.query(
          `INSERT INTO complaints (student_id, location_id, description, priority, status)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING complaint_id, student_id, priority, status`,
          [tempStudentId, tempLocationId, 'Transaction test complaint', 'Medium', 'Pending']
        );
        assert(compRes.rows[0].status === 'Pending', 'Complaint inserted with status Pending');
        const tempComplaintId = compRes.rows[0].complaint_id;

        // Insert status_history matching record inside transaction
        const histRes = await testClient.query(
          `INSERT INTO status_history (complaint_id, status, changed_by, remarks)
           VALUES ($1, $2, $3, $4)
           RETURNING history_id, complaint_id, status, changed_by, remarks`,
          [tempComplaintId, 'Pending', tempStudentId, 'Complaint registered']
        );
        assert(histRes.rows[0].status === 'Pending', 'status_history record has status Pending');
        assert(histRes.rows[0].changed_by === tempStudentId, 'status_history changed_by matches student_id');
        assert(histRes.rows[0].complaint_id === tempComplaintId, 'status_history references complaint_id');

        // Test constraint violation inside transaction triggers error and rollbacks properly
        let checkViolated = false;
        try {
          // 'InvalidStatus' violates status_history_status_check
          await testClient.query(
            `INSERT INTO status_history (complaint_id, status, changed_by, remarks)
             VALUES ($1, $2, $3, $4)`,
            [tempComplaintId, 'InvalidStatus', tempStudentId, 'Should fail check']
          );
        } catch (err) {
          checkViolated = err.code === '23514';
        }
        assert(checkViolated, 'status_history check constraint rejects invalid status (23514)');

        // ROLLBACK everything cleanly so no records are left in Neon
        await testClient.query('ROLLBACK');
        console.log('[PASS] Transaction rolled back cleanly without committing');
        passed++;
      } catch (err) {
        try {
          await testClient.query('ROLLBACK');
        } catch (_) {}
        console.error('[FAIL] Transaction test failed:', err.message);
        failed++;
      } finally {
        testClient.release();
      }
    }

    // 18. GET /api/warden/complaints with warden token
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints`, {
        headers: { Authorization: `Bearer ${wardenToken}` },
      });
      const body = await res.json();
      assert(res.status === 200, 'GET /api/warden/complaints returns 200');
      assert(Array.isArray(body), 'GET /api/warden/complaints returns an array');
    }

    // 19. GET /api/warden/complaints with valid filters
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints?status=Pending&priority=High&hostel_id=1`, {
        headers: { Authorization: `Bearer ${wardenToken}` },
      });
      const body = await res.json();
      assert(res.status === 200, 'GET /api/warden/complaints with valid filters returns 200');
      assert(Array.isArray(body), 'GET /api/warden/complaints filtered returns an array');
    }

    // 20. GET /api/warden/complaints with invalid status filter
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints?status=NonExistentStatus`, {
        headers: { Authorization: `Bearer ${wardenToken}` },
      });
      const body = await res.json();
      assert(res.status === 400, 'GET /api/warden/complaints with invalid status returns 400');
      assert(body.error && body.error.includes('status'), 'Error specifies invalid status filter');
    }

    // 21. GET /api/warden/complaints with invalid priority filter
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints?priority=UnknownPriority`, {
        headers: { Authorization: `Bearer ${wardenToken}` },
      });
      const body = await res.json();
      assert(res.status === 400, 'GET /api/warden/complaints with invalid priority returns 400');
      assert(body.error && body.error.includes('priority'), 'Error specifies invalid priority filter');
    }

    // 22. GET /api/warden/complaints with invalid hostel_id
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints?hostel_id=invalid-hostel`, {
        headers: { Authorization: `Bearer ${wardenToken}` },
      });
      const body = await res.json();
      assert(res.status === 400, 'GET /api/warden/complaints with invalid hostel_id returns 400');
      assert(body.error && body.error.includes('hostel_id'), 'Error specifies invalid hostel_id');
    }

    // 23. GET /api/warden/complaints/:id non-numeric ID
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints/abc`, {
        headers: { Authorization: `Bearer ${wardenToken}` },
      });
      const body = await res.json();
      assert(res.status === 400, 'GET /api/warden/complaints/abc returns 400');
      assert(body.error && body.error.includes('integer'), 'Error specifies integer requirement');
    }

    // 24. GET /api/warden/complaints/:id non-existent ID
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints/999999`, {
        headers: { Authorization: `Bearer ${wardenToken}` },
      });
      const body = await res.json();
      assert(res.status === 404, 'GET /api/warden/complaints/999999 returns 404');
      assert(body.error === 'Complaint not found', 'Error reports complaint not found');
    }

    // 25. POST /api/warden/complaints/:id/assign invalid complaint ID
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints/not-an-id/assign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${wardenToken}`,
        },
        body: JSON.stringify({ technician_id: 1 }),
      });
      assert(res.status === 400, 'POST /api/warden/complaints/not-an-id/assign returns 400');
    }

    // 26. POST /api/warden/complaints/:id/assign missing technician_id
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints/999999/assign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${wardenToken}`,
        },
        body: JSON.stringify({}),
      });
      const body = await res.json();
      assert(res.status === 400, 'POST /api/warden/complaints/:id/assign without technician_id returns 400');
      assert(body.error && body.error.includes('technician_id'), 'Validation error mentions technician_id');
    }

    // 27. POST /api/warden/complaints/:id/assign with non-numeric technician_id
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints/999999/assign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${wardenToken}`,
        },
        body: JSON.stringify({ technician_id: 'tech_one' }),
      });
      assert(res.status === 400, 'POST /api/warden/complaints/:id/assign with string technician_id returns 400');
    }

    // 28. POST /api/warden/complaints/:id/assign non-existent complaint
    {
      const res = await fetch(`${baseUrl}/api/warden/complaints/999999/assign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${wardenToken}`,
        },
        body: JSON.stringify({ technician_id: 1 }),
      });
      const body = await res.json();
      assert(res.status === 404, 'POST /api/warden/complaints/999999/assign returns 404 for non-existent complaint');
      assert(body.error === 'Complaint not found', 'Returns Complaint not found error');
    }

    // 29. Complete Assignment Transaction & Rollback test (leaves 0 records in Neon)
    {
      const testClient = await pool.connect();
      try {
        await testClient.query('BEGIN');

        // Fetch existing hostel & technician
        const hostelRes = await testClient.query('SELECT hostel_id FROM hostel LIMIT 1');
        const hostelId = hostelRes.rows[0].hostel_id;

        const techRes = await testClient.query('SELECT technician_id FROM technician LIMIT 1');
        assert(techRes.rows.length > 0, 'Found existing technician for assignment test');
        const technicianId = techRes.rows[0].technician_id;

        const wardenRes = await testClient.query('SELECT warden_id FROM warden LIMIT 1');
        assert(wardenRes.rows.length > 0, 'Found existing warden for assignment test');
        const wardenId = wardenRes.rows[0].warden_id;

        // Create student & location inside the transaction
        const tempStudentId = 'STU_' + Date.now().toString().slice(-10);
        await testClient.query(
          'INSERT INTO student (student_id, name, email, hostel_id) VALUES ($1, $2, $3, $4)',
          [tempStudentId, 'Warden Assign Test', `${tempStudentId}@hostel.test`, hostelId]
        );

        const locRes = await testClient.query(
          'INSERT INTO location (location_name, floor_no, location_type, hostel_id) VALUES ($1, $2, $3, $4) RETURNING location_id',
          ['Assign Test Room', 1, 'Room', hostelId]
        );
        const tempLocationId = locRes.rows[0].location_id;

        // Insert complaint with status 'Pending'
        const compRes = await testClient.query(
          `INSERT INTO complaints (student_id, location_id, description, priority, status)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING complaint_id, status`,
          [tempStudentId, tempLocationId, 'Assign test complaint', 'High', 'Pending']
        );
        const tempComplaintId = compRes.rows[0].complaint_id;
        assert(compRes.rows[0].status === 'Pending', 'Initial complaint is Pending');

        // Multi-write assignment transaction:
        // 1. Insert into assignment
        const assignRes = await testClient.query(
          `INSERT INTO assignment (complaint_id, technician_id)
           VALUES ($1, $2)
           RETURNING assignment_id, complaint_id, technician_id, assigned_date`,
          [tempComplaintId, technicianId]
        );
        assert(assignRes.rows[0].technician_id === technicianId, 'Assignment references correct technician');

        // 2. Update complaint status to 'Assigned'
        const updateRes = await testClient.query(
          `UPDATE complaints SET status = 'Assigned' WHERE complaint_id = $1 RETURNING status`,
          [tempComplaintId]
        );
        assert(updateRes.rows[0].status === 'Assigned', 'Complaint status updated to Assigned');

        // 3. Insert status_history record with status 'Assigned' and changed_by = wardenId
        const historyRes = await testClient.query(
          `INSERT INTO status_history (complaint_id, status, changed_by, remarks)
           VALUES ($1, $2, $3, $4)
           RETURNING history_id, status, changed_by`,
          [tempComplaintId, 'Assigned', String(wardenId), 'Assigned to technician']
        );
        assert(historyRes.rows[0].status === 'Assigned', 'status_history recorded with status Assigned');
        assert(historyRes.rows[0].changed_by === String(wardenId), 'status_history changed_by matches warden_id');

        // 4. Test foreign key rejection on invalid technician_id
        let assignFkFailed = false;
        try {
          await testClient.query(
            `INSERT INTO assignment (complaint_id, technician_id) VALUES ($1, $2)`,
            [tempComplaintId, 99999999]
          );
        } catch (err) {
          assignFkFailed = err.code === '23503';
        }
        assert(assignFkFailed, 'Assignment rejects non-existent technician_id (FK 23503)');

        // ROLLBACK all changes cleanly
        await testClient.query('ROLLBACK');
        console.log('[PASS] Assignment transaction rolled back cleanly without committing');
        passed++;
      } catch (err) {
        try {
          await testClient.query('ROLLBACK');
        } catch (_) {}
        console.error('[FAIL] Assignment transaction test failed:', err.message);
        failed++;
      } finally {
        testClient.release();
      }
    }

    // 30. GET /api/technician/assignments with technician token
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments`, {
        headers: { Authorization: `Bearer ${technicianToken}` },
      });
      const body = await res.json();
      assert(res.status === 200, 'GET /api/technician/assignments returns 200');
      assert(Array.isArray(body), 'GET /api/technician/assignments returns an array');
    }

    // 31. GET /api/technician/assignments with valid filters
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments?technician_id=1&status=In%20Progress`, {
        headers: { Authorization: `Bearer ${technicianToken}` },
      });
      const body = await res.json();
      assert(res.status === 200, 'GET /api/technician/assignments with valid filters returns 200');
      assert(Array.isArray(body), 'GET /api/technician/assignments filtered returns array');
    }

    // 32. GET /api/technician/assignments with invalid technician_id format
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments?technician_id=not-an-int`, {
        headers: { Authorization: `Bearer ${technicianToken}` },
      });
      assert(res.status === 400, 'GET /api/technician/assignments with non-int technician_id returns 400');
    }

    // 33. GET /api/technician/assignments with invalid status
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments?status=Rejected`, {
        headers: { Authorization: `Bearer ${technicianToken}` },
      });
      const body = await res.json();
      assert(res.status === 400, 'GET /api/technician/assignments with unsupported status returns 400');
      assert(body.error && body.error.includes('status'), 'Error specifies status error');
    }

    // 34. GET /api/technician/assignments/:id non-numeric ID
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments/abc`, {
        headers: { Authorization: `Bearer ${technicianToken}` },
      });
      assert(res.status === 400, 'GET /api/technician/assignments/abc returns 400');
    }

    // 35. GET /api/technician/assignments/:id non-existent ID
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments/999999`, {
        headers: { Authorization: `Bearer ${technicianToken}` },
      });
      const body = await res.json();
      assert(res.status === 404, 'GET /api/technician/assignments/999999 returns 404');
      assert(body.error === 'Assignment not found', 'Returns Assignment not found');
    }

    // 36. PATCH /api/technician/assignments/:id/status non-numeric ID
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments/abc/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${technicianToken}`,
        },
        body: JSON.stringify({ status: 'In Progress' }),
      });
      assert(res.status === 400, 'PATCH /api/technician/assignments/abc/status returns 400');
    }

    // 37. PATCH /api/technician/assignments/:id/status missing status
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments/999999/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${technicianToken}`,
        },
        body: JSON.stringify({}),
      });
      const body = await res.json();
      assert(res.status === 400, 'PATCH /api/technician/assignments/:id/status without status returns 400');
      assert(body.error && body.error.includes('status'), 'Mentions status is required');
    }

    // 38. PATCH /api/technician/assignments/:id/status invalid status value (e.g. Rejected)
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments/999999/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${technicianToken}`,
        },
        body: JSON.stringify({ status: 'Rejected' }),
      });
      const body = await res.json();
      assert(res.status === 400, 'PATCH /api/technician/assignments/:id/status with Rejected returns 400');
      assert(body.error && body.error.includes('Invalid status'), 'Reports Invalid status');
    }

    // 39. PATCH /api/technician/assignments/:id/status non-existent assignment
    {
      const res = await fetch(`${baseUrl}/api/technician/assignments/999999/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${technicianToken}`,
        },
        body: JSON.stringify({ status: 'In Progress' }),
      });
      const body = await res.json();
      assert(res.status === 404, 'PATCH /api/technician/assignments/999999/status returns 404 for non-existent assignment');
      assert(body.error === 'Assignment not found', 'Reports Assignment not found');
    }

    // 40. Transactional Technician Status Update Test (with clean ROLLBACK, 0 records in Neon)
    {
      const testClient = await pool.connect();
      try {
        await testClient.query('BEGIN');

        // Fetch existing hostel and technician
        const hostelRes = await testClient.query('SELECT hostel_id FROM hostel LIMIT 1');
        const hostelId = hostelRes.rows[0].hostel_id;

        const techRes = await testClient.query('SELECT technician_id, name FROM technician LIMIT 1');
        const technician = techRes.rows[0];

        // Setup temp student, location, and complaint
        const tempStudentId = 'STU_' + Date.now().toString().slice(-10);
        await testClient.query(
          'INSERT INTO student (student_id, name, email, hostel_id) VALUES ($1, $2, $3, $4)',
          [tempStudentId, 'Tech Test Student', `${tempStudentId}@hostel.test`, hostelId]
        );

        const locRes = await testClient.query(
          'INSERT INTO location (location_name, floor_no, location_type, hostel_id) VALUES ($1, $2, $3, $4) RETURNING location_id',
          ['Tech Room 1', 1, 'Room', hostelId]
        );
        const tempLocationId = locRes.rows[0].location_id;

        const compRes = await testClient.query(
          `INSERT INTO complaints (student_id, location_id, description, priority, status)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING complaint_id, status`,
          [tempStudentId, tempLocationId, 'Fan making noise', 'Medium', 'Pending']
        );
        const tempComplaintId = compRes.rows[0].complaint_id;

        // Assign complaint to technician
        const assignRes = await testClient.query(
          `INSERT INTO assignment (complaint_id, technician_id)
           VALUES ($1, $2)
           RETURNING assignment_id, complaint_id, technician_id, completed_date`,
          [tempComplaintId, technician.technician_id]
        );
        const tempAssignmentId = assignRes.rows[0].assignment_id;
        assert(assignRes.rows[0].completed_date === null, 'Initial completed_date is null');

        // 1. Transactional update to 'In Progress'
        await testClient.query('UPDATE complaints SET status = $1 WHERE complaint_id = $2', [
          'In Progress',
          tempComplaintId,
        ]);
        await testClient.query(
          `INSERT INTO status_history (complaint_id, status, changed_by, remarks)
           VALUES ($1, $2, $3, $4)`,
          [tempComplaintId, 'In Progress', technician.name, 'Started fixing fan']
        );

        const checkInProgress = await testClient.query(
          'SELECT status FROM complaints WHERE complaint_id = $1',
          [tempComplaintId]
        );
        assert(checkInProgress.rows[0].status === 'In Progress', 'Complaint updated to In Progress');

        // 2. Transactional update to 'Resolved'
        await testClient.query('UPDATE complaints SET status = $1 WHERE complaint_id = $2', [
          'Resolved',
          tempComplaintId,
        ]);
        await testClient.query(
          'UPDATE assignment SET completed_date = CURRENT_TIMESTAMP WHERE assignment_id = $1 RETURNING completed_date',
          [tempAssignmentId]
        );
        await testClient.query(
          `INSERT INTO status_history (complaint_id, status, changed_by, remarks)
           VALUES ($1, $2, $3, $4)`,
          [tempComplaintId, 'Resolved', technician.name, 'Fan replaced and working']
        );

        const checkResolvedComp = await testClient.query(
          'SELECT status FROM complaints WHERE complaint_id = $1',
          [tempComplaintId]
        );
        assert(checkResolvedComp.rows[0].status === 'Resolved', 'Complaint updated to Resolved');

        const checkResolvedAssign = await testClient.query(
          'SELECT completed_date FROM assignment WHERE assignment_id = $1',
          [tempAssignmentId]
        );
        assert(checkResolvedAssign.rows[0].completed_date !== null, 'completed_date set when Resolved');

        const checkHistory = await testClient.query(
          'SELECT status, changed_by FROM status_history WHERE complaint_id = $1 ORDER BY history_id ASC',
          [tempComplaintId]
        );
        assert(checkHistory.rows.length === 2, '2 status history entries recorded');
        assert(checkHistory.rows[0].status === 'In Progress', 'First history is In Progress');
        assert(checkHistory.rows[1].status === 'Resolved', 'Second history is Resolved');

        // ROLLBACK all changes cleanly
        await testClient.query('ROLLBACK');
        console.log('[PASS] Technician transactional update rolled back cleanly without committing');
        passed++;
      } catch (err) {
        try {
          await testClient.query('ROLLBACK');
        } catch (_) {}
        console.error('[FAIL] Technician transaction test failed:', err.message);
        failed++;
      } finally {
        testClient.release();
      }
    }

    // 41. Verify complaints, status_history, and assignment table row counts remain 0 in Neon
    {
      const compCountRes = await pool.query('SELECT count(*) FROM complaints');
      const compCount = parseInt(compCountRes.rows[0].count, 10);
      assert(compCount === 0, `Complaints table row count is 0 (actual: ${compCount})`);

      const histCountRes = await pool.query('SELECT count(*) FROM status_history');
      const histCount = parseInt(histCountRes.rows[0].count, 10);
      assert(histCount === 0, `status_history table row count is 0 (actual: ${histCount})`);

      const assignCountRes = await pool.query('SELECT count(*) FROM assignment');
      const assignCount = parseInt(assignCountRes.rows[0].count, 10);
      assert(assignCount === 0, `assignment table row count is 0 (actual: ${assignCount})`);
    }

    // 42. Phase 2: Password validation, hashing (cost 12), and CLI script security tests
    {
      // Password validation rules
      assert(!validatePassword(123456789012).valid, 'validatePassword rejects non-string');
      assert(!validatePassword('short').valid, 'validatePassword rejects < 12 characters');
      assert(!validatePassword('12345678901').valid, 'validatePassword rejects 11 characters');
      assert(validatePassword('123456789012').valid, 'validatePassword accepts exactly 12 characters');
      assert(validatePassword('SecureP@ssw0rd2026!').valid, 'validatePassword accepts strong 18-char password');

      // 72 UTF-8 bytes limit
      const exactly72Bytes = 'A'.repeat(72);
      assert(validatePassword(exactly72Bytes).valid, 'validatePassword accepts 72 ASCII bytes');
      const over72Bytes = 'A'.repeat(73);
      assert(!validatePassword(over72Bytes).valid, 'validatePassword rejects 73 ASCII bytes');
      // Multi-byte UTF-8 test (each '€' is 3 bytes in UTF-8: 25 * 3 = 75 bytes)
      const over72MultiByte = '€'.repeat(25);
      assert(!validatePassword(over72MultiByte).valid, 'validatePassword rejects multi-byte UTF-8 exceeding 72 bytes');

      // Cost factor 12 and hashing verification
      assert(BCRYPT_SALT_ROUNDS === 12, 'BCRYPT_SALT_ROUNDS is configured to 12');
      const testPlain = 'SecurePassphrase#2026';
      const hash = await hashPassword(testPlain);
      assert(typeof hash === 'string', 'hashPassword returns a string');
      assert(hash.startsWith('$2a$12$') || hash.startsWith('$2b$12$'), 'bcrypt hash uses cost factor 12 ($2b$12$)');
      assert(await comparePassword(testPlain, hash), 'comparePassword validates correct password against hash');
      assert(!(await comparePassword('WrongPassword123!', hash)), 'comparePassword rejects incorrect password');

      // hashPassword boundary rejection
      let hashThrewShort = false;
      try {
        await hashPassword('short');
      } catch (e) {
        hashThrewShort = true;
      }
      assert(hashThrewShort, 'hashPassword throws on password < 12 characters');

      let hashThrewLong = false;
      try {
        await hashPassword('A'.repeat(75));
      } catch (e) {
        hashThrewLong = true;
      }
      assert(hashThrewLong, 'hashPassword throws on password > 72 bytes');

      // Admin CLI setUserPassword validation tests (without executing writes against Neon)
      const invalidRoleRes = await setUserPassword({
        role: 'superuser',
        id: '1',
        password: 'ValidPassword123!',
      });
      assert(!invalidRoleRes.success, 'setUserPassword rejects unauthorized role');
      assert(invalidRoleRes.error && invalidRoleRes.error.includes('role'), 'Error mentions invalid role');

      const invalidWardenIdRes = await setUserPassword({
        role: 'warden',
        id: 'not-an-integer',
        password: 'ValidPassword123!',
      });
      assert(!invalidWardenIdRes.success, 'setUserPassword rejects non-integer warden_id');

      const invalidStudentIdRes = await setUserPassword({
        role: 'student',
        id: '   ',
        password: 'ValidPassword123!',
      });
      assert(!invalidStudentIdRes.success, 'setUserPassword rejects empty student_id');

      const weakPassRes = await setUserPassword({
        role: 'warden',
        id: 2,
        password: 'weak',
      });
      assert(!weakPassRes.success, 'setUserPassword rejects weak password before querying DB');

      // Simulated client testing safe error handling and verifying zero secret leakage
      const mockClientNotFound = {
        query: async () => ({ rows: [] }),
      };
      const notFoundRes = await setUserPassword({
        role: 'warden',
        id: 99999,
        password: 'ValidPassword123!',
        client: mockClientNotFound,
      });
      assert(!notFoundRes.success, 'setUserPassword handles non-existent user safely');
      assert(notFoundRes.error && notFoundRes.error.includes('not found'), 'Error specifies user not found');
      assert(!JSON.stringify(notFoundRes).includes('ValidPassword123!'), 'Plaintext password is never leaked in error response');

      const mockClientDbError = {
        query: async () => {
          throw new Error('connection to server at "ep-xyz.neon.tech" failed: password authentication failed');
        },
      };
      const dbErrRes = await setUserPassword({
        role: 'warden',
        id: 2,
        password: 'ValidPassword123!',
        client: mockClientDbError,
      });
      assert(!dbErrRes.success, 'setUserPassword catches DB error safely');
      assert(!JSON.stringify(dbErrRes).includes('ValidPassword123!'), 'Plaintext password is never leaked during database error');
    }

    console.log(`\nTest Summary: ${passed} passed, ${failed} failed.`);
    server.close();
    process.exit(failed > 0 ? 1 : 0);
  } catch (err) {
    console.error('Test run error:', err);
    server.close();
    process.exit(1);
  }
}

runTests();
