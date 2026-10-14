import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("FURBY_DB_PATH", "data/furby.sqlite3")

def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            result_json TEXT NOT NULL
        )""")

def save_scan(scan_type, target, result):
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO scans(created_at, scan_type, target, result_json) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), scan_type, target,
             json.dumps(result, ensure_ascii=False))
        )

def list_scans(limit=100):
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, created_at, scan_type, target FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [{"id": r[0], "fecha_utc": r[1], "tipo": r[2], "objetivo": r[3]} for r in rows]
