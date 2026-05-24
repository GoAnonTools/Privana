# web/db.py
from pathlib import Path
import sqlite3

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "privana.db"

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  email              TEXT NOT NULL UNIQUE,
  confirmed          INTEGER NOT NULL DEFAULT 0,
  subscription_plan  TEXT NOT NULL DEFAULT 'trial',
  subscription_status TEXT NOT NULL DEFAULT 'active',
  device_limit       INTEGER NOT NULL DEFAULT 3,
  token              TEXT UNIQUE,
  created_at         TEXT NOT NULL DEFAULT (datetime('now'))
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

-- WebAuthn
CREATE TABLE IF NOT EXISTS passkeys (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id  TEXT NOT NULL UNIQUE,
  public_key     BLOB NOT NULL,
  sign_count     INTEGER NOT NULL DEFAULT 0,
  transports     TEXT,
  attestation_fmt TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER,
  kind        TEXT NOT NULL,
  challenge   TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_passkeys_cred ON passkeys(credential_id);
"""

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA_SQL)

def reset_db():
    """Drop known tables so we can recreate the schema without deleting the file."""
    drops = """
    PRAGMA foreign_keys = OFF;
    DROP TABLE IF EXISTS device_configs;
    DROP TABLE IF EXISTS webauthn_challenges;
    DROP TABLE IF EXISTS devices;
    DROP TABLE IF EXISTS passkeys;
    DROP TABLE IF EXISTS users;
    PRAGMA foreign_keys = ON;
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(drops)