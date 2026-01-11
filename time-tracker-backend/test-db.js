import mariadb from 'mariadb';
import dotenv from 'dotenv';
dotenv.config();

const pool = mariadb.createPool({
  host: '127.0.0.1',
  port: 3306,
  user: 'root',
  password: 'JBgPMw-_8vVp]57K',
  database: 'diallo_time_tracker',
  connectionLimit: 5,
  allowPublicKeyRetrieval: true,
  trace: true // Enable for debugging
});

async function testConnection() {
  let conn;
  try {
    conn = await pool.getConnection();
    console.log('Successfully connected to database');
    const rows = await conn.query('SHOW DATABASES');
    console.log('Available databases:', rows);
  } catch (err) {
    console.error('Database connection failed:', err.message);
    if (err.cause) {
      console.error('Cause:', err.cause.message);
    }
  } finally {
    if (conn) await conn.release();
    await pool.end();
  }
}

testConnection();