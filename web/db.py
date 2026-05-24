# web/db.py
from pathlib import Path
import sqlite3

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "privana.db"

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  account_number      TEXT NOT NULL UNIQUE,
  recovery_hash       TEXT NOT NULL UNIQUE,
  subscription_plan   TEXT NOT NULL DEFAULT 'trial',
  subscription_status TEXT NOT NULL DEFAULT 'active',
  device_limit        INTEGER NOT NULL DEFAULT 1,
  token               TEXT UNIQUE,
  trial_started_at    TEXT,
  trial_expires_at    TEXT,
  trial_consumed_at   TEXT,
  created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name              TEXT NOT NULL,
  platform          TEXT NOT NULL,
  is_connected      INTEGER NOT NULL DEFAULT 0,
  has_config        INTEGER NOT NULL DEFAULT 0,
  config_created_at TEXT,
  last_connected    TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- private_key is intentionally absent: keypairs are generated in the browser
-- and the private key never leaves the client device.
-- config stores the template with PrivateKey = PLACEHOLDER, assembled into
-- the final .conf client-side before download.
CREATE TABLE IF NOT EXISTS device_configs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id   INTEGER UNIQUE NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  public_key  TEXT NOT NULL,
  assigned_ip TEXT NOT NULL,
  config      TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- WebAuthn authenticators are handled in web/routes/auth.py and web/routes/webauthn.py


CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER,
  kind        TEXT NOT NULL,
  challenge   TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_account_number ON users(account_number);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_recovery_hash ON users(recovery_hash);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

"""

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(SCHEMA_SQL)

def reset_db():
    """Drop known tables so we can recreate the schema without deleting the file."""
    drops = """
    PRAGMA foreign_keys = OFF;
    DROP TABLE IF EXISTS device_configs;
    DROP TABLE IF EXISTS webauthn_challenges;
    DROP TABLE IF EXISTS devices;
    DROP TABLE IF EXISTS users;
    PRAGMA foreign_keys = ON;
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(drops)