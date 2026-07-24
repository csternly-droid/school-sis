const { Pool } = require('pg');

// DATABASE_URL comes from your .env file
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // required for Supabase
});

module.exports = pool;