from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

import aiosqlite

from config import get_setting


class Database:
    def __init__(self):
        self.db_path = get_setting("DB_PATH", "itsec_cord_bot.db")
        self.connection: Optional[aiosqlite.Connection] = None

    async def connect(self):
        """Anslut till SQLite och skapa tabeller/index."""
        self.connection = await aiosqlite.connect(self.db_path)
        self.connection.row_factory = aiosqlite.Row

        await self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS published_cves (
                cve_id TEXT PRIMARY KEY,
                title TEXT,
                summary TEXT,
                cvss REAL,
                severity TEXT,
                exploit_status TEXT,
                is_kev INTEGER DEFAULT 0,
                affected TEXT,
                action_text TEXT,
                source_url TEXT,
                published_at TEXT,
                posted_channel TEXT,
                fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS user_subscriptions (
                user_id TEXT,
                vendor TEXT,
                PRIMARY KEY (user_id, vendor)
            )
            """
        )
        await self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS source_state (
                source_name TEXT PRIMARY KEY,
                last_fetch_at TEXT
            )
            """
        )
        await self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS published_news (
                item_url TEXT PRIMARY KEY,
                title TEXT,
                source_name TEXT,
                published_at TEXT,
                fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_published_cves_cvss ON published_cves(cvss)"
        )
        await self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_published_cves_fetched_at ON published_cves(fetched_at)"
        )
        await self.connection.commit()

    def _require_conn(self) -> aiosqlite.Connection:
        if not self.connection:
            raise RuntimeError("Databasanslutning saknas. Kor connect() forst.")
        return self.connection

    async def is_cve_published(self, cve_id: str) -> bool:
        conn = self._require_conn()
        cursor = await conn.execute("SELECT 1 FROM published_cves WHERE cve_id = ?", (cve_id,))
        result = await cursor.fetchone()
        await cursor.close()
        return result is not None

    async def insert_cve_if_new(self, cve: dict[str, Any], posted_channel: str) -> bool:
        """Spara CVE om den inte finns; returnerar True om ny rad skapades."""
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            INSERT OR IGNORE INTO published_cves (
                cve_id, title, summary, cvss, severity, exploit_status, is_kev,
                affected, action_text, source_url, published_at, posted_channel
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve.get("cve_id"),
                cve.get("title"),
                cve.get("summary"),
                cve.get("cvss"),
                cve.get("severity"),
                cve.get("exploit_status"),
                1 if cve.get("is_kev") else 0,
                cve.get("affected"),
                cve.get("action"),
                cve.get("url"),
                cve.get("published_at"),
                posted_channel,
            ),
        )
        await conn.commit()
        return cursor.rowcount > 0

    async def get_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        conn = self._require_conn()
        cursor = await conn.execute("SELECT * FROM published_cves WHERE cve_id = ?", (cve_id.upper(),))
        row = await cursor.fetchone()
        await cursor.close()
        return dict(row) if row else None

    async def latest_cves(self, limit: int = 5) -> list[dict[str, Any]]:
        conn = self._require_conn()
        cursor = await conn.execute(
            "SELECT * FROM published_cves ORDER BY fetched_at DESC LIMIT ?",
            (max(1, min(limit, 20)),),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [dict(row) for row in rows]

    async def search_cves(self, term: str, limit: int = 10) -> list[dict[str, Any]]:
        conn = self._require_conn()
        pattern = f"%{term.lower()}%"
        cursor = await conn.execute(
            """
            SELECT *
            FROM published_cves
            WHERE lower(cve_id) LIKE ?
               OR lower(title) LIKE ?
               OR lower(summary) LIKE ?
               OR lower(affected) LIKE ?
            ORDER BY fetched_at DESC
            LIMIT ?
            """,
            (pattern, pattern, pattern, pattern, max(1, min(limit, 20))),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [dict(row) for row in rows]

    async def add_subscription(self, user_id: str, vendor: str):
        conn = self._require_conn()
        await conn.execute(
            "INSERT OR IGNORE INTO user_subscriptions (user_id, vendor) VALUES (?, ?)",
            (str(user_id), vendor.strip().lower()),
        )
        await conn.commit()

    async def remove_subscription(self, user_id: str, vendor: str):
        conn = self._require_conn()
        await conn.execute(
            "DELETE FROM user_subscriptions WHERE user_id = ? AND vendor = ?",
            (str(user_id), vendor.strip().lower()),
        )
        await conn.commit()

    async def get_user_subscriptions(self, user_id: str) -> list[str]:
        conn = self._require_conn()
        cursor = await conn.execute(
            "SELECT vendor FROM user_subscriptions WHERE user_id = ? ORDER BY vendor ASC",
            (str(user_id),),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [row[0] for row in rows]

    async def set_last_fetch(self, source_name: str, when: Optional[datetime] = None):
        conn = self._require_conn()
        timestamp = (when or datetime.utcnow()).isoformat()
        await conn.execute(
            """
            INSERT INTO source_state (source_name, last_fetch_at)
            VALUES (?, ?)
            ON CONFLICT(source_name) DO UPDATE SET last_fetch_at = excluded.last_fetch_at
            """,
            (source_name, timestamp),
        )
        await conn.commit()

    async def get_last_fetch(self, source_name: str) -> Optional[str]:
        conn = self._require_conn()
        cursor = await conn.execute(
            "SELECT last_fetch_at FROM source_state WHERE source_name = ?", (source_name,)
        )
        row = await cursor.fetchone()
        await cursor.close()
        return row[0] if row else None

    async def mark_news_as_published(
        self,
        item_url: str,
        title: str,
        source_name: str,
        published_at: Optional[str],
    ) -> bool:
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            INSERT OR IGNORE INTO published_news (item_url, title, source_name, published_at)
            VALUES (?, ?, ?, ?)
            """,
            (item_url, title, source_name, published_at),
        )
        await conn.commit()
        return cursor.rowcount > 0

    async def get_weekly_stats(self) -> dict[str, int]:
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            SELECT
                SUM(CASE WHEN cvss >= 9.0 THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN cvss >= 7.0 AND cvss < 9.0 THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN is_kev = 1 THEN 1 ELSE 0 END) AS kev_count,
                SUM(CASE WHEN lower(exploit_status) = 'aktiv' THEN 1 ELSE 0 END) AS active_exploit_count
            FROM published_cves
            WHERE datetime(fetched_at) >= datetime('now', '-7 day')
            """
        )
        row = await cursor.fetchone()
        await cursor.close()
        if not row:
            return {
                "critical_count": 0,
                "high_count": 0,
                "kev_count": 0,
                "active_exploit_count": 0,
            }
        return {
            "critical_count": row["critical_count"] or 0,
            "high_count": row["high_count"] or 0,
            "kev_count": row["kev_count"] or 0,
            "active_exploit_count": row["active_exploit_count"] or 0,
        }

    async def get_weekly_news_headlines(self, limit: int = 3) -> list[dict[str, Any]]:
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            SELECT title, item_url, source_name
            FROM published_news
            WHERE datetime(fetched_at) >= datetime('now', '-7 day')
            ORDER BY fetched_at DESC
            LIMIT ?
            """,
            (max(1, min(limit, 10)),),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [dict(row) for row in rows]

    async def close(self):
        if self.connection:
            await self.connection.close()
            self.connection = None
