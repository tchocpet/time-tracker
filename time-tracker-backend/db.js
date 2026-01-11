// import mariadb from 'mariadb';
// import dotenv from 'dotenv';

// // Load environment variables from .env file
// dotenv.config();

// const pool = mariadb.createPool({
//   host: process.env.DB_HOST,
//   user: process.env.DB_USER,
//   password: process.env.DB_PASSWORD,
//   database: process.env.DB_NAME,
//   connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT, 10), // Convert to integer
// });

// export default pool;

import pkg from 'pg';
const { Pool } = pkg;
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: 5432,
  ssl: { rejectUnauthorized: false }, // Required for Supabase
});

// Wrapper to mimic MariaDB pool interface
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