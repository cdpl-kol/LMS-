// Run this once: node add-default-student.js
require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function run() {
  try {
    const hash = await bcrypt.hash('student123', 10);

    // Get first course and batch IDs
    const crs = await pool.query('SELECT id FROM courses LIMIT 1');
    const bat = await pool.query('SELECT id FROM batches LIMIT 1');
    const courseId = crs.rows[0]?.id || null;
    const batchId  = bat.rows[0]?.id || null;

    await pool.query(`
      INSERT INTO students(name, email, password_hash, contact, course_id, batch_id, status)
      VALUES($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT(email) DO UPDATE SET password_hash=$3
    `, ['Student Demo', 'student@123gmail.com', hash, '9000000003', courseId, batchId, 'Active']);

    console.log('✅ Default student added/updated:');
    console.log('   Email   : student@123gmail.com');
    console.log('   Password: student123');
  } catch(e) {
    console.error('Error:', e.message);
  } finally {
    await pool.end();
  }
}

run();
