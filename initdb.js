require('dotenv').config();
const bcrypt = require('bcryptjs');
const pool = require('./db');

async function main() {
  const hash = bcrypt.hashSync('changeme123', 10);
  try {
    await pool.query(
      'INSERT INTO super_admins (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING',
      ['superadmin', hash]
    );
    console.log('Super admin ready.');
    console.log('  username: superadmin');
    console.log('  password: changeme123   <-- CHANGE THIS before going live');
  } catch (err) {
    console.error('Failed to seed super admin:', err.message);
    console.error('Make sure you ran schema.sql in the Supabase SQL editor first, and that DATABASE_URL in .env is correct.');
  } finally {
    await pool.end();
  }
}

main();