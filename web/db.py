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
  subscription_plan  TEXT NOT NULL DEFAULT 'trial',     -- 'trial'|'personal'|'family'|'small team'...
  subscription_status TEXT NOT NULL DEFAULT 'active',   -- 'active'|'past_due'|'canceled' ...
  device_limit       INTEGER NOT NULL DEFAULT 3,
  token              TEXT UNIQUE,                       -- account token shown on dashboard
  created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name              TEXT NOT NULL,
  platform          TEXT NOT NULL,                      -- 'windows'|'macos'|'linux'|'android'|'ios'
  is_connected      INTEGER NOT NULL DEFAULT 0,
  has_config        INTEGER NOT NULL DEFAULT 0,
  config_created_at TEXT,
  last_connected    TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- WebAuthn (kept minimal so your precheck endpoints don't 500)
CREATE TABLE IF NOT EXISTS passkeys (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id  TEXT NOT NULL UNIQUE,                  -- base64url
  public_key     BLOB NOT NULL,                         -- COSE key
  sign_count     INTEGER NOT NULL DEFAULT 0,
  transports     TEXT,
  attestation_fmt TEXT,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Optional, but many flows store pending challenges; harmless to have:
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER,                                  -- nullable for precheck/assert
  kind        TEXT NOT NULL,                            -- 'register'|'assert'|'precheck'
  challenge   TEXT NOT NULL,                            -- base64url
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
    DROP TABLE IF EXISTS webauthn_challenges;
    DROP TABLE IF EXISTS devices;
    DROP TABLE IF EXISTS passkeys;
    DROP TABLE IF EXISTS users;
    PRAGMA foreign_keys = ON;
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(drops)