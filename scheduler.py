from __future__ import annotations

import logging
from typing import Awaitable, Callable

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from config import TZ_STOCKHOLM

logger = logging.getLogger(__name__)


class BotScheduler:
    def __init__(
        self,
        cve_job: Callable[[], Awaitable[None]],
        kev_job: Callable[[], Awaitable[None]],
        news_job: Callable[[], Awaitable[None]],
    ):
        self.scheduler = AsyncIOScheduler(timezone=TZ_STOCKHOLM)
        self.cve_job = cve_job
        self.kev_job = kev_job
        self.news_job = news_job

    def start(self):
        """Registrera alla jobb och starta schedulern."""
        self.scheduler.add_job(
            self.cve_job,
            IntervalTrigger(minutes=15),
            id="cve_check",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        self.scheduler.add_job(
            self.kev_job,
            IntervalTrigger(hours=6),
            id="kev_refresh",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        self.scheduler.add_job(
            self.news_job,
            IntervalTrigger(minutes=30),
            id="news_check",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        self.scheduler.start()
        logger.info("Scheduler started with CVE/KEV/news jobs")

    def shutdown(self):
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
