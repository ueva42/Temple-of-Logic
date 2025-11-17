// db.js
import pg from "pg";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : false
});

export async function query(text, params) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

export async function migrate() {
  console.log("Starte Migration…");

  // -- USERS
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','student')),
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  // -- CLASSES
  await query(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE
    );
  `);

  // -- SETTINGS
  await query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);

  // aktive Klasse initialisieren
  const r2 = await query(`SELECT * FROM settings WHERE key='active_class'`);
  if (r2.rows.length === 0) {
    await query(`INSERT INTO settings (key, value) VALUES ('active_class', NULL)`);
  }

  // -- ADMIN USER
  const adminCheck = await query(`SELECT * FROM users WHERE name = $1`, ["admin"]);
  if (adminCheck.rows.length === 0) {
    await query(
      `INSERT INTO users (name, password, role) VALUES ('admin', 'admin123', 'admin')`
    );
    console.log("Admin: admin / admin123 wurde erstellt.");
  } else {
    console.log("Admin existiert bereits.");
  }

  console.log("Migration abgeschlossen.");
}
