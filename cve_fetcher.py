from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from config import BROAD_IMPACT_KEYWORDS, get_setting

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CVEFetcher:
    def __init__(self):
        self.session = requests.Session()
        self.nvd_api_key = get_setting("NVD_API_KEY")
        if self.nvd_api_key:
            self.session.headers.update({"apiKey": self.nvd_api_key})

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        try:
            parsed = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return None

    def _is_recent(self, date_str: str | None, hours: int) -> bool:
        parsed = self._parse_date(date_str)
        if not parsed:
            return False
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        return now - parsed <= timedelta(hours=hours)

    @staticmethod
    def _extract_description(cve: dict[str, Any]) -> str:
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "")
        descriptions = cve.get("descriptions", [])
        return descriptions[0].get("value", "") if descriptions else "No description available."

    @staticmethod
    def _extract_cvss(cve: dict[str, Any]) -> float:
        metrics = cve.get("metrics", {})
        metric_sets = [
            metrics.get("cvssMetricV31", []),
            metrics.get("cvssMetricV30", []),
            metrics.get("cvssMetricV2", []),
        ]
        for metric_group in metric_sets:
            if metric_group:
                cvss_data = metric_group[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                if isinstance(score, (int, float)):
                    return float(score)
        return 0.0

    @staticmethod
    def _extract_title(cve_id: str, description: str) -> str:
        short = description.split(".")[0].strip()
        if len(short) > 90:
            short = short[:87] + "..."
        return f"{cve_id} - {short}" if short else cve_id

    @staticmethod
    def _extract_affected(cve: dict[str, Any]) -> str:
        cpes: list[str] = []
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    criteria = cpe.get("criteria")
                    if criteria:
                        cpes.append(criteria)
                    if len(cpes) >= 3:
                        return ", ".join(cpes)
        return ", ".join(cpes) if cpes else "See vendor advisory for exact scope"

    @staticmethod
    def _extract_references(cve: dict[str, Any]) -> list[str]:
        refs = cve.get("references", [])
        urls: list[str] = []
        for item in refs:
            url = item.get("url")
            if url:
                urls.append(url)
        return urls

    @staticmethod
    def _is_broad_impact(cve: dict[str, Any], description: str, affected: str) -> bool:
        blob = f"{cve.get('id', '')} {description} {affected}".lower()
        return any(keyword in blob for keyword in BROAD_IMPACT_KEYWORDS)

    @staticmethod
    def _severity_from_cvss(cvss: float) -> str:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"

    @staticmethod
    def _exploit_status(reference_urls: list[str], is_kev: bool) -> str:
        if is_kev:
            return "Active"
        blob = " ".join(reference_urls).lower()
        if any(token in blob for token in ["exploit-db", "metasploit", "poc", "github.com"]):
            return "PoC"
        return "None"

    def fetch_recent_nvd_cves(self, hours: int = 24) -> list[dict[str, Any]]:
        """Fetch recently published/updated CVEs from NVD."""
        now_utc = datetime.now(tz=timezone.utc)
        start_utc = now_utc - timedelta(hours=hours)
        params = {
            "pubStartDate": start_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": now_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "resultsPerPage": 200,
        }
        try:
            response = self.session.get(NVD_API_BASE, params=params, timeout=30)
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            logger.exception("Error fetching NVD data: %s", exc)
            return []

        parsed: list[dict[str, Any]] = []
        for item in payload.get("vulnerabilities", []):
            parsed_item = self._parse_nvd_item(item)
            if not parsed_item:
                continue

            if not self._is_recent(parsed_item.get("published_at"), hours):
                continue

            parsed.append(parsed_item)

        return parsed

    def _parse_nvd_item(self, item: dict[str, Any]) -> dict[str, Any] | None:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            return None

        published_at = cve.get("published") or cve.get("lastModified")
        description = self._extract_description(cve)
        cvss = self._extract_cvss(cve)
        severity = self._severity_from_cvss(cvss)
        affected = self._extract_affected(cve)
        refs = self._extract_references(cve)

        return {
            "cve_id": cve_id.upper(),
            "title": self._extract_title(cve_id.upper(), description),
            "summary": description,
            "cvss": cvss,
            "severity": severity,
            "is_kev": False,
            "exploit_status": self._exploit_status(refs, False),
            "affected": affected,
            "action": "Patch to the latest vendor-recommended version.",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}",
            "vendor_url": refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}",
            "exploit_url": refs[0] if refs else None,
            "published_at": published_at,
            "is_broad_impact": self._is_broad_impact(cve, description, affected),
        }

    def fetch_cve_by_id(self, cve_id: str) -> dict[str, Any] | None:
        """Fetch a single CVE from NVD using CVE ID."""
        cve_id = cve_id.upper().strip()
        try:
            response = self.session.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                timeout=30,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            logger.exception("Error fetching CVE %s: %s", cve_id, exc)
            return None

        vulns = payload.get("vulnerabilities", [])
        if not vulns:
            return None

        return self._parse_nvd_item(vulns[0])

    def fetch_cisa_kev_set(self) -> set[str]:
        """Fetch CISA KEV list as a set of CVE IDs."""
        try:
            response = self.session.get(CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            logger.exception("Error fetching CISA KEV: %s", exc)
            return set()

        kev_ids: set[str] = set()
        for item in payload.get("vulnerabilities", []):
            cve_id = item.get("cveID")
            if cve_id:
                kev_ids.add(cve_id.upper())
        return kev_ids

    def merge_with_kev(self, cves: list[dict[str, Any]], kev_ids: set[str]) -> list[dict[str, Any]]:
        for cve in cves:
            if cve["cve_id"] in kev_ids:
                cve["is_kev"] = True
                cve["exploit_status"] = "Active"
        return cves

    @staticmethod
    def should_publish_critical(cve: dict[str, Any]) -> bool:
        return (
            cve.get("cvss", 0.0) >= 9.0
            or cve.get("is_kev", False)
            or cve.get("exploit_status") == "Active"
            or cve.get("is_broad_impact", False)
        )

    @staticmethod
    def should_publish_high(cve: dict[str, Any]) -> bool:
        return (
            7.0 <= cve.get("cvss", 0.0) < 9.0
            and cve.get("is_broad_impact", False)
        )

    def classify_channel(self, cve: dict[str, Any]) -> str | None:
        if self.should_publish_critical(cve):
            return "critical"
        if self.should_publish_high(cve):
            return "high"
        return None
