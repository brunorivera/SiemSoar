"""SQLite schema and seed data for the thesis prototype.

The table names follow the thesis schema in ``Database/01_database_setup.sql``
(``detection_rules``, ``parsed_events``, ``alerts``, ``attack_patterns`` and
``pipeline_runs``) plus a small ``blocked_ips`` table needed to expose the
active-response TTL (R6) through the API.

The prototype is self-contained: it uses SQLite and never touches the
PostgreSQL/n8n lab, nor the ``lab/``, ``analysis/`` or ``Database/`` folders.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("PROTOTYPE_DATA_DIR", str(BASE_DIR / "data")))
DB_PATH = Path(os.environ.get("PROTOTYPE_DB", str(DATA_DIR / "prototype.db")))

# R5: critical addresses that must never be blocked (gateway / loopback).
EXCLUDED_IPS = ("10.50.0.1", "127.0.0.1")

# The post-campaign values documented in lab/post_campana/README.md: the
# ingestion horizon (GRACE) covers the longest correlation window (600 s) and
# the active-response block lives for 600 s (R6).
GRACE_SECONDS = int(os.environ.get("PROTOTYPE_GRACE", "600"))
BLOCK_TTL_SECONDS = int(os.environ.get("PROTOTYPE_TTL", "600"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS detection_rules (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    pattern     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    threshold   INTEGER NOT NULL DEFAULT 1,
    time_window INTEGER NOT NULL DEFAULT 300,
    enabled     INTEGER NOT NULL DEFAULT 1,
    category    TEXT NOT NULL DEFAULT 'general',
    action      TEXT NOT NULL DEFAULT 'block',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS parsed_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_ts   TEXT NOT NULL,
    rule_id    INTEGER,
    rule_name  TEXT,
    src_ip     TEXT,
    raw_log    TEXT,
    ingest_ts  TEXT NOT NULL DEFAULT (datetime('now')),
    source     TEXT,
    category   TEXT,
    username   TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT NOT NULL DEFAULT (datetime('now')),
    severity         TEXT NOT NULL,
    category         TEXT NOT NULL,
    rule_id          INTEGER,
    rule_name        TEXT,
    source_host      TEXT,
    source_ip        TEXT,
    target_host      TEXT,
    event_count      INTEGER NOT NULL DEFAULT 1,
    description      TEXT,
    raw_log          TEXT,
    status           TEXT NOT NULL DEFAULT 'new',
    assigned_to      TEXT,
    notes            TEXT,
    resolved_at      TEXT,
    first_occurrence TEXT,
    last_occurrence  TEXT
);

CREATE TABLE IF NOT EXISTS attack_patterns (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type     TEXT NOT NULL,
    source_ip        TEXT NOT NULL,
    target_host      TEXT,
    first_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen        TEXT NOT NULL DEFAULT (datetime('now')),
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    is_blocked       INTEGER NOT NULL DEFAULT 0,
    UNIQUE (source_ip, pattern_type)
);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_ts         TEXT NOT NULL DEFAULT (datetime('now')),
    arm            TEXT NOT NULL DEFAULT 'prototype',
    lines_read     INTEGER NOT NULL DEFAULT 0,
    events_parsed  INTEGER NOT NULL DEFAULT 0,
    alerts_created INTEGER NOT NULL DEFAULT 0,
    duration_ms    INTEGER NOT NULL DEFAULT 0,
    trigger        TEXT NOT NULL DEFAULT 'manual',
    status         TEXT NOT NULL DEFAULT 'ok',
    notes          TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT NOT NULL,
    rule_name    TEXT,
    reason       TEXT,
    alert_id     INTEGER,
    blocked_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    ttl_seconds  INTEGER NOT NULL DEFAULT 600,
    active       INTEGER NOT NULL DEFAULT 1,
    unblocked_at TEXT,
    blocked_by   TEXT NOT NULL DEFAULT 'SOAR'
);

CREATE TABLE IF NOT EXISTS lab_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_rule_ingest ON parsed_events (rule_id, ingest_ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON parsed_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts (rule_name);
CREATE INDEX IF NOT EXISTS idx_patterns_ip ON attack_patterns (source_ip);
CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips (active, expires_at);
"""

# Table 7 of the report / lab/scripts/seed_rules.sql (exactly 5 rules).
RULES = [
    {
        "id": 1,
        "name": "SSH Brute Force",
        "description": "Intentos fallidos de autenticación SSH",
        "pattern": r"Failed password.*ssh",
        "severity": "high",
        "threshold": 5,
        "time_window": 300,
        "category": "auth_failure",
        "action": "block",
    },
    {
        "id": 2,
        "name": "Sudo Abuse",
        "description": "Uso abusivo de sudo (comandos privilegiados)",
        "pattern": r"sudo.*COMMAND=.*",
        "severity": "medium",
        "threshold": 10,
        "time_window": 600,
        "category": "privilege_abuse",
        "action": "block",
    },
    {
        "id": 3,
        "name": "Port Scan Detection",
        "description": "Escaneo de puertos: paquetes descartados por iptables (DROP)",
        "pattern": r"iptables.*DROP.*DPT",
        "severity": "medium",
        "threshold": 20,
        "time_window": 60,
        "category": "reconnaissance",
        "action": "block",
    },
    {
        "id": 4,
        "name": "Root Login Attempt",
        "description": "Intento de login como root",
        "pattern": r"Failed password for root",
        "severity": "critical",
        "threshold": 1,
        "time_window": 1,
        "category": "auth_failure",
        "action": "block",
    },
    {
        "id": 5,
        "name": "SQL Injection Pattern",
        "description": "Patrón de inyección SQL en peticiones web",
        "pattern": r"(union.*select|drop.*table)",
        "severity": "high",
        "threshold": 1,
        "time_window": 1,
        "category": "web_attack",
        "action": "block",
    },
]

DEFAULT_CONFIG = {
    "arm": "prototype",
    "grace": str(GRACE_SECONDS),
    "ttl": str(BLOCK_TTL_SECONDS),
    "pending_lines": "0",
    "pending_events": "0",
    "total_lines_received": "0",
}


def _seed(conn: sqlite3.Connection) -> None:
    for rule in RULES:
        conn.execute(
            """
            INSERT OR IGNORE INTO detection_rules
                (id, name, description, pattern, severity, threshold,
                 time_window, enabled, category, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                rule["id"],
                rule["name"],
                rule["description"],
                rule["pattern"],
                rule["severity"],
                rule["threshold"],
                rule["time_window"],
                rule["category"],
                rule["action"],
            ),
        )
    for key, value in DEFAULT_CONFIG.items():
        conn.execute(
            "INSERT OR IGNORE INTO lab_config (key, value) VALUES (?, ?)",
            (key, value),
        )


def init_db() -> None:
    """Create the SQLite database and seed the rule catalogue (idempotent)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _seed(conn)


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    """Open a short-lived connection with row access by column name."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def reset_demo() -> None:
    """Clear demo data but keep the detection-rule catalogue intact."""
    with get_conn() as conn:
        tables = (
            "parsed_events",
            "alerts",
            "attack_patterns",
            "pipeline_runs",
            "blocked_ips",
        )
        for table in tables:
            conn.execute(f"DELETE FROM {table}")
        placeholders = ",".join("?" for _ in tables)
        conn.execute(
            f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})",
            tables,
        )
        conn.execute(
            "UPDATE lab_config SET value = '0' "
            "WHERE key IN ('pending_lines', 'pending_events', 'total_lines_received')"
        )
        conn.execute("UPDATE lab_config SET value = 'prototype' WHERE key = 'arm'")
