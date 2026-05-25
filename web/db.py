# web/db.py
from pathlib import Path
import os
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

-- WebAuthn authenticators
CREATE TABLE IF NOT EXISTS authenticators (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id            INTEGER REFERENCES users(id) ON DELETE CASCADE,
  credential_id      BLOB UNIQUE NOT NULL,
  credential_id_hash TEXT UNIQUE,
  public_key         BLOB NOT NULL,
  sign_count         INTEGER NOT NULL DEFAULT 0,
  aaguid             TEXT,
  first_seen_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS security_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  user_id    INTEGER,
  details    TEXT,
  ip         TEXT,
  severity   TEXT NOT NULL DEFAULT 'info',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS suspicious_ips (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ip       TEXT UNIQUE NOT NULL,
  noted_at TEXT NOT NULL DEFAULT (datetime('now'))
);


CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER,
  kind        TEXT NOT NULL,
  challenge   TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT
);


CREATE TABLE IF NOT EXISTS config_download_tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  token      TEXT NOT NULL UNIQUE,
  requester_ip TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_account_number ON users(account_number);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_recovery_hash ON users(recovery_hash);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS ix_users_account ON users(account_number);
CREATE INDEX IF NOT EXISTS ix_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS ix_sec_ip ON security_events(ip);
CREATE INDEX IF NOT EXISTS ix_sec_time ON security_events(created_at);
CREATE INDEX IF NOT EXISTS ix_sec_event_time ON security_events(event_type, created_at);
CREATE INDEX IF NOT EXISTS ix_config_download_tokens_token ON config_download_tokens(token);
CREATE INDEX IF NOT EXISTS ix_config_download_tokens_expiry ON config_download_tokens(expires_at);

"""

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(SCHEMA_SQL)

        # Migration: config_download_tokens.requester_ip was added after the
        # original token table. Existing local dev DBs may not have it yet.
        cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(config_download_tokens)").fetchall()
        }
        if "requester_ip" not in cols:
            conn.execute("ALTER TABLE config_download_tokens ADD COLUMN requester_ip TEXT NOT NULL DEFAULT ''")

    cleanup_privacy_retention()


def cleanup_privacy_retention():
    """
    Minimize retained IP data.

    Privana needs recent IPs for anti-abuse, rate limiting, token binding, and
    security review, but raw IPs should not remain linked to anonymous accounts
    indefinitely.

    Defaults:
    - security_events.ip is nulled after 24 hours.
    - used/old config download tokens are deleted after 24 hours.
    """
    security_ip_hours = int(os.getenv("PRIVANA_SECURITY_IP_RETENTION_HOURS", "24"))
    token_hours = int(os.getenv("PRIVANA_CONFIG_TOKEN_RETENTION_HOURS", "24"))

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA busy_timeout=5000")

        if security_ip_hours >= 0:
            conn.execute(
                """
                UPDATE security_events
                SET ip = NULL
                WHERE ip IS NOT NULL
                  AND created_at < DATETIME('now', ?)
                """,
                (f"-{security_ip_hours} hours",),
            )

        if token_hours >= 0:
            conn.execute(
                """
                DELETE FROM config_download_tokens
                WHERE (used = 1 AND created_at < DATETIME('now', ?))
                   OR expires_at < DATETIME('now', ?)
                """,
                (f"-{token_hours} hours", f"-{token_hours} hours"),
            )

        conn.commit()



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

def get_db():
    """
    Centralized SQLite connection factory.

    All web routes must use this function so every module resolves the same
    absolute database path regardless of current working directory.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn
