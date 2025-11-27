import pkg from "pg";
const { Pool } = pkg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Railway erfordert SSL
});

// Testfunktion (optional)
export async function testDB() {
  const res = await pool.query("SELECT NOW()");
  console.log("DB verbunden:", res.rows[0].now);
}
