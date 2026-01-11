import pkg from 'pg';
const { Pool } = pkg;
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: { rejectUnauthorized: false },
  // Add these for faster timeout on local dev
  connectionTimeoutMillis: 10000, // 10 seconds
  idleTimeoutMillis: 30000,
  max: 20,
  family: 4,
});

// Test connection on startup
pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

pool.on('connect', () => {
  console.log('✓ Connected to Supabase PostgreSQL');
});

export default {
  getConnection: async () => {
    const client = await pool.connect();
    return {
      query: async (sql, params) => {
        try {
          const result = await client.query(sql, params);
          return result.rows;
        } catch (error) {
          console.error('Query error:', error);
          throw error;
        }
      },
      release: () => client.release(),
    };
  },
};