from __future__ import annotations

import logging
import re
import time
from hashlib import sha1
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser

from config import NEWS_FEEDS, _env_bool, get_int_setting

logger = logging.getLogger(__name__)


class NewsFetcher:
    def __init__(self):
        self.feeds = NEWS_FEEDS
        self.max_published_age_hours = max(1, get_int_setting("NEWS_MAX_PUBLISHED_AGE_HOURS", 36))
        self.include_undated_entries = _env_bool("NEWS_INCLUDE_UNDATED_ENTRIES", False)
        self.last_feed_reports: list[dict[str, Any]] = []

    @staticmethod
    def _normalize_text(value: str) -> str:
        value = (value or "").lower()
        value = re.sub(r"https?://\S+", " ", value)
        value = re.sub(r"[^a-z0-9\s-]", " ", value)
        value = re.sub(r"\s+", " ", value).strip()
        return value

    @classmethod
    def _extract_cve_ids(cls, *parts: str) -> list[str]:
        blob = " ".join(parts).upper()
        return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", blob)))

    @classmethod
    def _build_news_fingerprint(cls, title: str, summary: str, url: str) -> str:
        cve_ids = cls._extract_cve_ids(title, summary, url)
        if cve_ids:
            return f"cve:{'|'.join(cve_ids)}"

        normalized = cls._normalize_text(title)
        if not normalized:
            normalized = cls._normalize_text(url)
        return "title:" + sha1(normalized.encode("utf-8")).hexdigest()

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
        """Fetch news from RSS feeds."""
        collected: list[dict[str, str]] = []
        feed_reports: list[dict[str, Any]] = []
        max_age_hours = min(max(1, hours), self.max_published_age_hours)
        cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=max_age_hours)

        for feed_url in self.feeds:
            try:
                parsed = feedparser.parse(feed_url)
            except Exception as exc:
                logger.exception("Error fetching RSS feed %s: %s", feed_url, exc)
                feed_reports.append(
                    {
                        "source": feed_url,
                        "ok": False,
                        "status": None,
                        "entries": 0,
                        "error": str(exc),
                    }
                )
                continue

            source_title = parsed.feed.get("title", feed_url)
            status = getattr(parsed, "status", None)
            total_entries = len(getattr(parsed, "entries", []))
            bozo_error = str(parsed.bozo_exception) if getattr(parsed, "bozo", False) else None

            feed_reports.append(
                {
                    "source": source_title,
                    "ok": bozo_error is None,
                    "status": status,
                    "entries": total_entries,
                    "error": bozo_error,
                }
            )

            for entry in parsed.entries[:15]:
                published_iso = self._to_iso8601(entry)
                if published_iso:
                    try:
                        published = datetime.fromisoformat(published_iso)
                        if published < cutoff:
                            continue
                    except ValueError:
                        continue
                elif not self.include_undated_entries:
                    continue
                elif not self._is_recent(published_iso, max_age_hours):
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
                        "news_fingerprint": self._build_news_fingerprint(title, summary, link),
                    }
                )

            # Enkel throttling mellan feeds.
            time.sleep(0.2)

        # Deduplicera pa URL i minnet innan DB-kontroll.
        seen: set[str] = set()
        seen_fingerprints: set[str] = set()
        unique: list[dict[str, str]] = []
        for item in collected:
            url = item["url"]
            if url in seen:
                continue
            fingerprint = item.get("news_fingerprint")
            if fingerprint and fingerprint in seen_fingerprints:
                continue
            seen.add(url)
            if fingerprint:
                seen_fingerprints.add(fingerprint)
            unique.append(item)

        self.last_feed_reports = feed_reports
        return unique

    def get_last_feed_reports(self) -> list[dict[str, Any]]:
        return list(self.last_feed_reports)
