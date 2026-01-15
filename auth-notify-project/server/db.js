const Database = require("better-sqlite3");
const db = new Database("app.db");
function hasColumn(table, col) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  return cols.some(c => c.name === col);
}

function addColumnIfMissing(table, colDef) {
  const col = colDef.split(/\s+/)[0];
  if (!hasColumn(table, col)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${colDef};`);
  }
}


db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT,
  email TEXT UNIQUE NOT NULL,
  dob TEXT,
  phone TEXT,
  password_hash TEXT,
  oauth_provider TEXT,
  oauth_id TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_oauth ON users(oauth_provider, oauth_id);
`);
// add new user columns safely
addColumnIfMissing("users", "email_verified INTEGER DEFAULT 0");
addColumnIfMissing("users", "email_verified_at TEXT");
addColumnIfMissing("users", "pii_phone_enc TEXT");
addColumnIfMissing("users", "pii_dob_enc TEXT");

// token tables
db.exec(`
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  replaced_by_token_hash TEXT,
  ip TEXT,
  user_agent TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

module.exports = db;
