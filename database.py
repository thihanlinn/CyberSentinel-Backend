"""
Async SQLite helper via aiosqlite.
"""

from __future__ import annotations

import aiosqlite
from datetime import datetime, timezone
from typing import Optional
import json

from config import DB_FILE
from utils.logger import get_logger

logger = get_logger("scanner.database")

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    risk            TEXT NOT NULL,
    rule_score      INTEGER NOT NULL,
    ml_score        INTEGER NOT NULL,
    final_score     INTEGER NOT NULL,
    ml_prediction   TEXT    NOT NULL,
    external_checks TEXT    NOT NULL,
    findings        TEXT,
    explanation     TEXT    NOT NULL,
    dialoger        TEXT    NOT NULL,
    ml_explanation  TEXT    NOT NULL,
    timestamp       TEXT
)
"""

_CREATE_FEEDBACK = """
CREATE TABLE IF NOT EXISTS feedback (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT NOT NULL,
    predicted_risk TEXT NOT NULL,
    actual_risk    TEXT NOT NULL,
    feedback       TEXT NOT NULL,
    timestamp      TEXT NOT NULL
)
"""


class Database:

    def __init__(self) -> None:
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        # Open connection and ensure schema exists. Call once at startup.
        self._conn = await aiosqlite.connect(DB_FILE)
        await self._conn.execute("PRAGMA journal_mode=WAL")  # better concurrency
        await self._conn.execute(_CREATE_SCANS)
        await self._conn.execute(_CREATE_FEEDBACK)
        await self._conn.commit()
        logger.info("Database initialised at %s", DB_FILE)

    async def close(self) -> None:
        # Close connection. Call once at shutdown.
        if self._conn:
            await self._conn.close()
            self._conn = None

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    async def save_scan(
            self,
            url: str,
            user_id: str,
            risk: str,
            rule_score: int,
            ml_score: int,
            final_score: int,
            ml_prediction: str,
            external_checks: dict[str, bool],
            findings: list[str],
            explanation: str,
            dialoger: str,
            ml_explanation: str,

    ) -> None:
        assert self._conn, "Database.connect() was not awaited"
        await self._conn.execute(
            """
            INSERT INTO scans
            (url, user_id, risk, rule_score, ml_score, final_score, ml_prediction, external_checks, findings,
             explanation, dialoger, ml_explanation, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                url,
                user_id,
                risk,
                rule_score,
                ml_score,
                final_score,
                ml_prediction,
                json.dumps(external_checks),
                " | ".join(findings),
                explanation,
                dialoger,
                ml_explanation if ml_explanation else "",
                self._now(),
            ),
        )
        await self._conn.commit()


    async def get_cached_scan(self, url: str) -> dict | None:

        assert self._conn, "Database.connect() was not awaited"
        async with self._conn.execute(
                """
                SELECT risk,
                       rule_score,
                       ml_score,
                       final_score,
                       ml_prediction,
                       external_checks,
                       findings,
                       explanation,
                       dialoger,
                       ml_explanation
                FROM scans
                WHERE url = ?
                ORDER BY id DESC LIMIT 1
                """,
                (url,),
        ) as cur:
            row = await cur.fetchone()

        if row is None:
            return None

        risk, rule_score, ml_score, final_score, ml_prediction, external_checks, findings_raw, explanation, dialoger, ml_explanation = row

        checks = json.loads(external_checks)

        ml_reasons = ml_explanation

        return {
            "url": url,
            "risk": risk,
            "scores": {"rule_based": rule_score, "ml_based": ml_score, "final": final_score},
            "ml_prediction": ml_prediction,
            "external_checks": checks,
            "findings": findings_raw.split(" | ") if findings_raw else [],
            "explanation": explanation,
            "dialoger": dialoger,
            "ml_explanation": ml_reasons
        }


    async def save_feedback(
        self,
        url:            str,
        predicted_risk: str,
        actual_risk:    str,
        feedback:       str,
    ) -> None:
        assert self._conn, "Database.connect() was not awaited"
        await self._conn.execute(
            """
            INSERT INTO feedback
                (url, predicted_risk, actual_risk, feedback, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (url, predicted_risk, actual_risk, feedback, self._now()),
        )
        await self._conn.commit()


    async def get_recent_logs(self, limit: int = 50):
        async with aiosqlite.connect(DB_FILE) as conn:
            cursor = await conn.execute(
                "SELECT id, url, user_id, risk, final_score, timestamp FROM scans ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            rows = await cursor.fetchall()

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

    async def get_feedbacks(self, limit: int = 50):
        async with self._conn.execute(
                "SELECT id, url, predicted_risk, actual_risk, feedback, timestamp "
                "FROM feedback ORDER BY id DESC LIMIT ?",
                (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [
            {"id": r[0], "url": r[1], "predicted_risk": r[2],
             "actual_risk": r[3], "feedback": r[4], "timestamp": r[5]}
            for r in rows
        ]


db = Database()