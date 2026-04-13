from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

import aiosqlite

from config import get_setting


class Database:
    def __init__(self):
        self.db_path = get_setting("DB_PATH", "itsec_cord_bot.db")
        self.connection: Optional[aiosqlite.Connection] = None
        self.has_news_fingerprint = False

    async def connect(self):
        """Connect to SQLite and ensure schema/tables exist."""
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
                news_fingerprint TEXT,
                published_at TEXT,
                fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS delivery_log (
                item_type TEXT,
                item_key TEXT,
                channel_key TEXT,
                delivered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (item_type, item_key, channel_key)
            )
            """
        )
        await self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS feed_health (
                source_name TEXT PRIMARY KEY,
                last_ok_at TEXT,
                last_error_at TEXT,
                last_status_code INTEGER,
                last_error_message TEXT,
                error_count INTEGER DEFAULT 0,
                last_entries INTEGER DEFAULT 0
            )
            """
        )
        # Migration/index are best-effort for legacy DBs. Startup must not fail.
        await self._ensure_news_fingerprint_column()
        self.has_news_fingerprint = await self._has_column("published_news", "news_fingerprint")
        if self.has_news_fingerprint:
            try:
                await self.connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_published_news_fingerprint ON published_news(news_fingerprint)"
                )
            except aiosqlite.OperationalError:
                self.has_news_fingerprint = False
        await self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_published_cves_cvss ON published_cves(cvss)"
        )
        await self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_published_cves_fetched_at ON published_cves(fetched_at)"
        )
        await self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_subscriptions_vendor ON user_subscriptions(vendor)"
        )
        await self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_delivery_log_delivered_at ON delivery_log(delivered_at)"
        )
        await self.connection.commit()

    async def _ensure_news_fingerprint_column(self):
        conn = self._require_conn()
        col_names = await self._get_column_names("published_news")
        if "news_fingerprint" not in col_names:
            await conn.execute("ALTER TABLE published_news ADD COLUMN news_fingerprint TEXT")

    async def _get_column_names(self, table_name: str) -> set[str]:
        conn = self._require_conn()
        cursor = await conn.execute(f"PRAGMA table_info({table_name})")
        rows = await cursor.fetchall()
        await cursor.close()
        return {str(row[1]) for row in rows}

    async def _has_column(self, table_name: str, column_name: str) -> bool:
        return column_name in await self._get_column_names(table_name)

    def _require_conn(self) -> aiosqlite.Connection:
        if not self.connection:
            raise RuntimeError("Database connection missing. Run connect() first.")
        return self.connection

    async def is_cve_published(self, cve_id: str) -> bool:
        conn = self._require_conn()
        cursor = await conn.execute("SELECT 1 FROM published_cves WHERE cve_id = ?", (cve_id,))
        result = await cursor.fetchone()
        await cursor.close()
        return result is not None

    async def insert_cve_if_new(self, cve: dict[str, Any], posted_channel: str) -> bool:
        """Store CVE if new; return True if inserted."""
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

    async def is_news_published(self, item_url: str, news_fingerprint: Optional[str]) -> bool:
        conn = self._require_conn()
        if self.has_news_fingerprint and news_fingerprint:
            cursor = await conn.execute(
                """
                SELECT 1
                FROM published_news
                WHERE item_url = ? OR news_fingerprint = ?
                LIMIT 1
                """,
                (item_url, news_fingerprint),
            )
        else:
            cursor = await conn.execute(
                """
                SELECT 1
                FROM published_news
                WHERE item_url = ?
                LIMIT 1
                """,
                (item_url,),
            )
        row = await cursor.fetchone()
        await cursor.close()
        return row is not None

    async def mark_news_as_published(
        self,
        item_url: str,
        title: str,
        source_name: str,
        news_fingerprint: Optional[str],
        published_at: Optional[str],
    ) -> bool:
        conn = self._require_conn()
        if self.has_news_fingerprint:
            cursor = await conn.execute(
                """
                INSERT OR IGNORE INTO published_news (item_url, title, source_name, news_fingerprint, published_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (item_url, title, source_name, news_fingerprint, published_at),
            )
        else:
            cursor = await conn.execute(
                """
                INSERT OR IGNORE INTO published_news (item_url, title, source_name, published_at)
                VALUES (?, ?, ?, ?)
                """,
                (item_url, title, source_name, published_at),
            )
        await conn.commit()
        return cursor.rowcount > 0

    async def record_delivery(self, item_type: str, item_key: str, channel_key: str):
        conn = self._require_conn()
        await conn.execute(
            """
            INSERT OR IGNORE INTO delivery_log (item_type, item_key, channel_key)
            VALUES (?, ?, ?)
            """,
            (item_type, item_key, channel_key),
        )
        await conn.commit()

    async def update_feed_health(
        self,
        source_name: str,
        ok: bool,
        status_code: int | None,
        entries: int,
        error_message: str | None,
    ):
        conn = self._require_conn()
        now_iso = datetime.utcnow().isoformat()
        await conn.execute(
            """
            INSERT INTO feed_health (
                source_name, last_ok_at, last_error_at, last_status_code,
                last_error_message, error_count, last_entries
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_name) DO UPDATE SET
                last_ok_at = CASE WHEN excluded.last_ok_at IS NOT NULL THEN excluded.last_ok_at ELSE feed_health.last_ok_at END,
                last_error_at = CASE WHEN excluded.last_error_at IS NOT NULL THEN excluded.last_error_at ELSE feed_health.last_error_at END,
                last_status_code = excluded.last_status_code,
                last_error_message = excluded.last_error_message,
                error_count = CASE WHEN excluded.last_error_at IS NOT NULL THEN feed_health.error_count + 1 ELSE feed_health.error_count END,
                last_entries = excluded.last_entries
            """,
            (
                source_name,
                now_iso if ok else None,
                None if ok else now_iso,
                status_code,
                None if ok else (error_message or "unknown error"),
                0 if ok else 1,
                entries,
            ),
        )
        await conn.commit()

    async def get_all_subscriptions(self) -> list[tuple[str, str]]:
        conn = self._require_conn()
        cursor = await conn.execute("SELECT user_id, vendor FROM user_subscriptions")
        rows = await cursor.fetchall()
        await cursor.close()
        return [(str(row[0]), str(row[1])) for row in rows]

    async def get_feed_health_summary(self) -> dict[str, int]:
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            SELECT
                COUNT(*) AS total_sources,
                SUM(CASE WHEN datetime(last_error_at) >= datetime('now', '-1 day') THEN 1 ELSE 0 END) AS error_sources_24h,
                SUM(CASE WHEN datetime(last_ok_at) >= datetime('now', '-1 day') THEN 1 ELSE 0 END) AS ok_sources_24h
            FROM feed_health
            """
        )
        row = await cursor.fetchone()
        await cursor.close()
        return {
            "total_sources": (row["total_sources"] or 0) if row else 0,
            "error_sources_24h": (row["error_sources_24h"] or 0) if row else 0,
            "ok_sources_24h": (row["ok_sources_24h"] or 0) if row else 0,
        }

    async def get_weekly_stats(self) -> dict[str, int]:
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            SELECT
                SUM(CASE WHEN cvss >= 9.0 THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN cvss >= 7.0 AND cvss < 9.0 THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN is_kev = 1 THEN 1 ELSE 0 END) AS kev_tagged_count,
                SUM(CASE WHEN lower(exploit_status) IN ('active', 'aktiv') THEN 1 ELSE 0 END) AS active_exploit_count,
                SUM(CASE WHEN lower(exploit_status) = 'poc' THEN 1 ELSE 0 END) AS poc_count
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
                "kev_tagged_count": 0,
                "active_exploit_count": 0,
                "poc_count": 0,
            }
        return {
            "critical_count": row["critical_count"] or 0,
            "high_count": row["high_count"] or 0,
            "kev_tagged_count": row["kev_tagged_count"] or 0,
            "active_exploit_count": row["active_exploit_count"] or 0,
            "poc_count": row["poc_count"] or 0,
        }

    async def close(self):
        if self.connection:
            await self.connection.close()
            self.connection = None
