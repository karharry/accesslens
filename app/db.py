"""SQLite storage: connection handling, schema and key/value settings."""
import os
import sqlite3
import threading
from contextlib import contextmanager

DATA_DIR = os.environ.get("DATA_DIR", "/config")
DB_PATH = os.path.join(DATA_DIR, "accesslens.db")
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    source TEXT NOT NULL,
    service TEXT NOT NULL,
    ip TEXT NOT NULL,
    is_local INTEGER NOT NULL DEFAULT 0,
    country TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0,
    ua TEXT NOT NULL DEFAULT '',
    device TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    app TEXT NOT NULL DEFAULT '',
    bytes INTEGER NOT NULL DEFAULT 0,
    referrer TEXT NOT NULL DEFAULT '',
    count INTEGER NOT NULL DEFAULT 1,
    network TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_service_ts ON events(service, ts);
CREATE INDEX IF NOT EXISTS ix_events_ip_ts ON events(ip, ts);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    sess_epoch INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_login INTEGER
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS file_state (
    path TEXT PRIMARY KEY, inode INTEGER, offset INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS service_meta (service TEXT PRIMARY KEY, category TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS aliases (ip TEXT PRIMARY KEY, label TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS probes (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    interval_s INTEGER NOT NULL DEFAULT 60,
    verify_tls INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS probe_results (
    probe_id INTEGER NOT NULL, ts INTEGER NOT NULL,
    ok INTEGER NOT NULL, status INTEGER, ms INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS ix_probe_results ON probe_results(probe_id, ts);
"""

DEFAULTS = {
    "local_cidrs": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,127.0.0.0/8,fc00::/7,fe80::/10,::1/128",
    "log_sources": "npm||/logs/npm/proxy-host-*_access.log\nnpm||/logs/npm/fallback_http_access.log",
    "ignore_ips": "",
    "ignore_paths": "",
    "ignore_services": "",
    "retention_days": "365",
    "cf_token": "",
    "cf_zones": "",
    "cf_interval": "300",
    "cf_status": "",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_security": "starttls",
    "smtp_user": "",
    "smtp_pass": "",
    "mail_from": "",
    "mail_to": "",
    "report_enabled": "0",
    "report_day": "0",
    "report_hour": "8",
    "report_last_key": "",
    "api_token": "",
    "backfill_done": "0",
    "tailscale_cidrs": "100.64.0.0/10,fd7a:115c:a1e0::/48",
    "conn_enabled": "1",
    "conn_protocols": "tcp",
    "conn_ports_ignore": "80,443",
    "conn_ports_only": "",
    "conn_labels": "",
    "conn_ignore_src": "127.0.0.0/8,::1/128",
    "conn_host_ips": "",
    "conn_poll": "5",
    "conn_status": "",
}


def conn() -> sqlite3.Connection:
    c = getattr(_local, "c", None)
    if c is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        c = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        _local.c = c
    return c


@contextmanager
def tx():
    c = conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        yield c
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise


def q(sql, params=()):
    return conn().execute(sql, params).fetchall()


def one(sql, params=()):
    return conn().execute(sql, params).fetchone()


def ex(sql, params=()):
    return conn().execute(sql, params)


def init():
    conn().executescript(SCHEMA)
    cols = {r["name"] for r in q("PRAGMA table_info(events)")}
    if "network" not in cols:  # upgrade from 1.0.0
        ex("ALTER TABLE events ADD COLUMN network TEXT NOT NULL DEFAULT ''")


def get(key, default=""):
    r = one("SELECT value FROM settings WHERE key=?", (key,))
    if r is not None:
        return r["value"]
    return DEFAULTS.get(key, default)


def put(key, value):
    ex("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
       (key, str(value)))


def lines(key):
    return [l.strip() for l in get(key).splitlines() if l.strip() and not l.strip().startswith("#")]
