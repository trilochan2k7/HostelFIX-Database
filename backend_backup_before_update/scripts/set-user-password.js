#!/usr/bin/env node
/**
 * ============================================================================
 * HostelFix Admin CLI: Set User Password
 * 
 * Secure CLI script to set or update passwords for existing student,
 * warden, and technician accounts in Neon PostgreSQL.
 *
 * Security Requirements:
 * - Passwords hashed using bcryptjs with cost factor 12.
 * - Password length: minimum 12 characters, maximum 72 UTF-8 bytes.
 * - Plaintext passwords and hashes are NEVER printed or logged.
 * - Uses parameterized SQL exclusively.
 * - Role and ID existence verified before updating.
 * - Safe error handling: never leaks database credentials.
 * ============================================================================
 */

require('dotenv').config();
const readline = require('readline');
const pool = require('../db');
const { validatePassword, hashPassword } = require('../middleware/auth');

const ROLE_CONFIG = {
  student: {
    table: 'student',
    idColumn: 'student_id',
    parseId: (id) => {
      if (typeof id !== 'string' || !id.trim()) {
        throw new Error('student_id must be a non-empty string');
      }
      return id.trim();
    },
  },
  warden: {
    table: 'warden',
    idColumn: 'warden_id',
    parseId: (id) => {
      const num = Number(id);
      if (!Number.isInteger(num) || num <= 0) {
        throw new Error('warden_id must be a positive integer');
      }
      return num;
    },
  },
  technician: {
    table: 'technician',
    idColumn: 'technician_id',
    parseId: (id) => {
      const num = Number(id);
      if (!Number.isInteger(num) || num <= 0) {
        throw new Error('technician_id must be a positive integer');
      }
      return num;
    },
  },
};

/**
 * Validate inputs and update user password_hash in database using parameterized SQL.
 * Never logs or returns plaintext password or password hash.
 *
 * @param {Object} params
 * @param {string} params.role - 'student' | 'warden' | 'technician'
 * @param {string|number} params.id - User ID matching the role
 * @param {string} params.password - Plaintext password (>= 12 chars, <= 72 bytes)
 * @param {Object} [params.client] - Optional pg client or pool (defaults to shared pool)
 * @returns {Promise<{ success: boolean, message?: string, error?: string }>}
 */
async function setUserPassword({ role, id, password, client = pool }) {
  // 1. Role validation
  if (!role || typeof role !== 'string' || !ROLE_CONFIG[role.toLowerCase().trim()]) {
    return {
      success: false,
      error: "Invalid role. Allowed roles: 'student', 'warden', 'technician'",
    };
  }
  const normalizedRole = role.toLowerCase().trim();
  const config = ROLE_CONFIG[normalizedRole];

  // 2. ID validation
  let parsedId;
  try {
    parsedId = config.parseId(id);
  } catch (idErr) {
    return {
      success: false,
      error: idErr.message,
    };
  }

  // 3. Password policy validation (12 chars min, 72 UTF-8 bytes max)
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return {
      success: false,
      error: passwordValidation.error,
    };
  }

  try {
    // 4. Verify user record exists in database using parameterized query
    const checkQuery = `SELECT 1 FROM ${config.table} WHERE ${config.idColumn} = $1`;
    const checkResult = await client.query(checkQuery, [parsedId]);

    if (checkResult.rows.length === 0) {
      return {
        success: false,
        error: `User not found in '${config.table}' with ${config.idColumn}: ${parsedId}`,
      };
    }

    // 5. Generate bcrypt hash with cost factor 12
    const hashedPassword = await hashPassword(password);

    // 6. Update password_hash using parameterized query
    const updateQuery = `UPDATE ${config.table} SET password_hash = $1 WHERE ${config.idColumn} = $2`;
    await client.query(updateQuery, [hashedPassword, parsedId]);

    return {
      success: true,
      message: `Password set successfully for ${normalizedRole} (${config.idColumn}: ${parsedId}).`,
    };
  } catch (dbErr) {
    // Safe error message without exposing credentials or internal errors
    if (dbErr.code === '42703' && dbErr.message && dbErr.message.includes('password_hash')) {
      return {
        success: false,
        error: "Column 'password_hash' does not exist yet. Run migration 001_add_password_hash.sql first.",
      };
    }
    return {
      success: false,
      error: `Database update failed: ${dbErr.message || 'Internal database error'}`,
    };
  }
}

/**
 * Prompt user for masked password input without echoing characters to screen/logs.
 */
function promptMasked(promptText) {
  return new Promise((resolve) => {
    const stdin = process.stdin;

    process.stdout.write(promptText);

    if (stdin.isTTY) {
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding('utf8');

      let input = '';
      const onData = (char) => {
        if (char === '\n' || char === '\r' || char === '\u0004') {
          stdin.removeListener('data', onData);
          stdin.setRawMode(false);
          stdin.pause();
          process.stdout.write('\n');
          resolve(input);
        } else if (char === '\u0003') {
          // Ctrl+C
          process.stdout.write('\n[ABORTED] Operation cancelled by admin.\n');
          process.exit(1);
        } else if (char === '\u007f' || char === '\b') {
          // Backspace
          if (input.length > 0) {
            input = input.slice(0, -1);
            process.stdout.write('\b \b');
          }
        } else {
          input += char;
          process.stdout.write('*');
        }
      };
      stdin.on('data', onData);
    } else {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      rl.question('', (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    }
  });
}

/**
 * Standard question prompt
 */
function promptQuestion(rl, questionText) {
  return new Promise((resolve) => {
    rl.question(questionText, (answer) => {
      resolve(answer.trim());
    });
  });
}

/**
 * CLI Argument Parser
 */
function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--role' && argv[i + 1]) {
      args.role = argv[++i];
    } else if (argv[i] === '--id' && argv[i + 1]) {
      args.id = argv[++i];
    } else if (argv[i] === '--password' && argv[i + 1]) {
      args.password = argv[++i];
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      args.help = true;
    }
  }
  return args;
}

/**
 * CLI Entrypoint
 */
async function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    console.log(`
HostelFix Admin Password Setup CLI
Usage:
  node scripts/set-user-password.js [options]

Options:
  --role <student|warden|technician>   Target user role
  --id <user_id>                       Target user identifier (e.g. S101, 2, 1)
  --password <password>                New password (min 12 chars, max 72 bytes)
  --help, -h                           Show this help menu

Interactive Mode:
  Run without options to be guided through masked input prompts:
  node scripts/set-user-password.js
`);
    process.exit(0);
  }

  let role = args.role;
  let id = args.id;
  let password = args.password || process.env.NEW_PASSWORD;

  if (args.password) {
    console.warn(
      '\n[SECURITY WARNING] Supplying passwords via command-line arguments (--password) may expose them in process listings (ps/proc). Use interactive masked input or environment variables for production security.\n'
    );
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  try {
    if (!role) {
      role = await promptQuestion(rl, 'Enter role (student, warden, technician): ');
    }
    if (!id) {
      id = await promptQuestion(rl, `Enter ${role || 'user'} ID: `);
    }
    rl.close();

    if (!password) {
      password = await promptMasked('Enter new password (min 12 characters, masked): ');
      const confirmPassword = await promptMasked('Confirm new password: ');
      if (password !== confirmPassword) {
        console.error('\n[ERROR] Passwords do not match. Aborting.');
        process.exit(1);
      }
    }

    const result = await setUserPassword({ role, id, password });

    if (result.success) {
      console.log(`\n[SUCCESS] ${result.message}`);
      process.exit(0);
    } else {
      console.error(`\n[ERROR] ${result.error}`);
      process.exit(1);
    }
  } catch (err) {
    console.error(`\n[ERROR] An unexpected error occurred: ${err.message}`);
    process.exit(1);
  } finally {
    pool.end();
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  setUserPassword,
  ROLE_CONFIG,
};
