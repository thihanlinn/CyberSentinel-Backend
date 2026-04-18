import sqlite3
from datetime import datetime, UTC
from config import DB_FILE


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            user_id TEXT,
            risk TEXT,
            score INTEGER,
            findings TEXT,
            vt_flag INTEGER,
            google_flag INTEGER,
            timestamp TEXT
        )
        """)


def get_cached_result(url):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute(
            "SELECT score, risk, findings FROM scans WHERE url=?",
            (url,)
        )
        row = cur.fetchone()
        if row:
            return {
                "score": row[0],
                "risk": row[1],
                "findings": row[2].split(" | ")
            }
    return None


def save_result(url: str, user_id: str, score: int, risk: str,
                findings: list, vt_flag: bool, google_flag: bool):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """INSERT INTO scans 
            (url, user_id, risk, score, findings, vt_flag, google_flag, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (url, user_id, risk, score, " | ".join(findings),
             int(vt_flag), int(google_flag),
             datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S%z"))
        )


def get_recent_logs(limit: int = 50):
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            "SELECT id, url, user_id, risk, score, timestamp FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [
        {
            "id": r[0],
            "url": r[1],
            "user_id": r[2],
            "risk": r[3],
            "score": r[4],
            "timestamp": r[5]
        }
        for r in rows
    ]
