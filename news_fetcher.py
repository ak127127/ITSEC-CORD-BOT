from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser

from config import NEWS_FEEDS

logger = logging.getLogger(__name__)


class NewsFetcher:
    def __init__(self):
        self.feeds = NEWS_FEEDS

    @staticmethod
    def _to_iso8601(entry: Any) -> str | None:
        if getattr(entry, "published", None):
            try:
                return parsedate_to_datetime(entry.published).astimezone(timezone.utc).isoformat()
            except Exception:
                return None
        if getattr(entry, "updated", None):
            try:
                return parsedate_to_datetime(entry.updated).astimezone(timezone.utc).isoformat()
            except Exception:
                return None
        return None

    @staticmethod
    def _is_recent(published_iso: str | None, hours: int) -> bool:
        if not published_iso:
            return True
        try:
            published = datetime.fromisoformat(published_iso)
            return datetime.now(timezone.utc) - published <= timedelta(hours=hours)
        except Exception:
            return False

    @staticmethod
    def _guess_category(title: str, summary: str) -> str:
        blob = f"{title} {summary}".lower()
        if any(k in blob for k in ["apt", "campaign", "espionage", "threat intel", "lazarus"]):
            return "threat_intel"
        if any(k in blob for k in ["nis2", "gdpr", "regulation", "policy"]):
            return "regulatory"
        if any(k in blob for k in ["tool", "release", "scanner", "framework"]):
            return "tooling"
        return "news"

    def fetch_recent_news(self, hours: int = 30) -> list[dict[str, str]]:
        """Hamta nyheter fran RSS-floden."""
        collected: list[dict[str, str]] = []
        cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=hours)

        for feed_url in self.feeds:
            try:
                parsed = feedparser.parse(feed_url)
            except Exception as exc:
                logger.exception("Fel vid RSS-hamtning %s: %s", feed_url, exc)
                continue

            source_title = parsed.feed.get("title", feed_url)
            for entry in parsed.entries[:15]:
                published_iso = self._to_iso8601(entry)
                if published_iso:
                    try:
                        published = datetime.fromisoformat(published_iso)
                        if published < cutoff:
                            continue
                    except ValueError:
                        pass
                elif not self._is_recent(published_iso, hours):
                    continue

                title = getattr(entry, "title", "Untitled")
                summary = getattr(entry, "summary", "").strip()
                link = getattr(entry, "link", "")
                if not link:
                    continue

                collected.append(
                    {
                        "title": title,
                        "summary": summary,
                        "url": link,
                        "published_at": published_iso,
                        "source_name": source_title,
                        "category": self._guess_category(title, summary),
                    }
                )

            # Enkel throttling mellan feeds.
            time.sleep(0.2)

        # Deduplicera pa URL i minnet innan DB-kontroll.
        seen: set[str] = set()
        unique: list[dict[str, str]] = []
        for item in collected:
            url = item["url"]
            if url in seen:
                continue
            seen.add(url)
            unique.append(item)
        return unique
