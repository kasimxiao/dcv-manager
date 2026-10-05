"""SQLite 数据层：定时任务、DCV 权限规格、实例元数据。"""
import sqlite3
import json
import threading
import time
from contextlib import contextmanager

from config import DB_PATH

_lock = threading.Lock()


@contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db():
    with _conn() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id TEXT NOT NULL,
                name TEXT,
                action TEXT NOT NULL,            -- start / stop / reboot
                cron TEXT NOT NULL,              -- 分 时 日 月 周 (5 段)
                timezone TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS permissions (
                instance_id TEXT PRIMARY KEY,
                spec_json TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS instance_meta (
                instance_id TEXT PRIMARY KEY,
                owner TEXT,
                note TEXT
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                instance_id TEXT NOT NULL,
                action TEXT NOT NULL,      -- start/stop/reboot/permissions/snapshot/launch
                operator TEXT,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_inst ON audit(instance_id, ts);
            """
        )


# ---------------- audit ----------------

def add_audit(instance_id, action, operator, detail=""):
    with _lock, _conn() as con:
        con.execute(
            "INSERT INTO audit(ts,instance_id,action,operator,detail) VALUES(?,?,?,?,?)",
            (time.time(), instance_id, action, operator, detail),
        )


def list_audit(instance_id, since_ts):
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM audit WHERE instance_id=? AND ts>=? ORDER BY ts",
            (instance_id, since_ts),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------- schedules ----------------

def list_schedules(instance_id=None):
    with _conn() as con:
        if instance_id:
            rows = con.execute(
                "SELECT * FROM schedules WHERE instance_id=? ORDER BY id DESC",
                (instance_id,),
            ).fetchall()
        else:
            rows = con.execute("SELECT * FROM schedules ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def get_schedule(sid):
    with _conn() as con:
        r = con.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
        return dict(r) if r else None


def create_schedule(instance_id, name, action, cron, timezone, enabled=True):
    with _lock, _conn() as con:
        cur = con.execute(
            "INSERT INTO schedules(instance_id,name,action,cron,timezone,enabled,created_at) VALUES(?,?,?,?,?,?,?)",
            (instance_id, name, action, cron, timezone, 1 if enabled else 0, time.time()),
        )
        return cur.lastrowid


def update_schedule(sid, **fields):
    if not fields:
        return
    allowed = {"name", "action", "cron", "timezone", "enabled"}
    sets, vals = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k}=?")
            vals.append(1 if (k == "enabled" and v) else (0 if k == "enabled" else v))
    if not sets:
        return
    vals.append(sid)
    with _lock, _conn() as con:
        con.execute(f"UPDATE schedules SET {','.join(sets)} WHERE id=?", vals)


def delete_schedule(sid):
    with _lock, _conn() as con:
        con.execute("DELETE FROM schedules WHERE id=?", (sid,))


# ---------------- permissions ----------------

def get_permission_spec(instance_id):
    with _conn() as con:
        r = con.execute(
            "SELECT spec_json FROM permissions WHERE instance_id=?", (instance_id,)
        ).fetchone()
        return json.loads(r["spec_json"]) if r else None


def save_permission_spec(instance_id, spec):
    with _lock, _conn() as con:
        con.execute(
            "INSERT INTO permissions(instance_id,spec_json,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(instance_id) DO UPDATE SET spec_json=excluded.spec_json, updated_at=excluded.updated_at",
            (instance_id, json.dumps(spec), time.time()),
        )


# ---------------- instance meta ----------------

def get_meta(instance_id):
    with _conn() as con:
        r = con.execute(
            "SELECT * FROM instance_meta WHERE instance_id=?", (instance_id,)
        ).fetchone()
        return dict(r) if r else None


def save_meta(instance_id, owner=None, note=None):
    with _lock, _conn() as con:
        con.execute(
            "INSERT INTO instance_meta(instance_id,owner,note) VALUES(?,?,?) "
            "ON CONFLICT(instance_id) DO UPDATE SET owner=COALESCE(excluded.owner,instance_meta.owner), "
            "note=COALESCE(excluded.note,instance_meta.note)",
            (instance_id, owner, note),
        )
