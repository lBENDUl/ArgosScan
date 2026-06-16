"""
ArgosScan - CVE Matcher (NVD API v2)
"""

import logging
import time
from typing import Dict, List, Optional

import requests

from utils.cache import cache_get, cache_set

logger = logging.getLogger("argosScan.cve_matcher")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS_PER_SERVICE = 5
REQUEST_DELAY = 0.6  # NVD public rate limit: ~5 req/s without API key


class CVEMatcher:
    """
    Matches detected services against the NVD CVE database.

    Results are cached per (product, version) pair to avoid hammering the API
    on repeated scans.
    """

    _SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}

    def __init__(self, api_key: Optional[str] = None, results_per_service: int = MAX_RESULTS_PER_SERVICE):
        self._api_key = api_key
        self._results_per_service = results_per_service
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "ArgosScan/0.1.0"
        if api_key:
            self._session.headers["apiKey"] = api_key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match_services(self, services: List[Dict]) -> List[Dict]:
        """
        Match a list of services against known CVEs.

        Args:
            services: Output of ServiceIdentifier.identify_batch().

        Returns:
            Sorted list of vulnerability dicts (CRITICAL first).
        """
        vulnerabilities: List[Dict] = []
        seen_cves: set = set()

        for service in services:
            product = service.get("product") or ""
            if not product:
                logger.debug(f"Skipping port {service.get('port')} — no product detected")
                continue

            cves = self._lookup(product, service.get("version"))

            for cve in cves:
                cve_id = cve.get("id")
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                vulnerabilities.append(self._format(cve, service))

        vulnerabilities.sort(
            key=lambda v: self._SEVERITY_ORDER.get(v.get("severity", "UNKNOWN"), 0),
            reverse=True,
        )
        return vulnerabilities

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _lookup(self, product: str, version: Optional[str]) -> List[Dict]:
        """Query NVD (with caching) for a product."""
        cache_key = f"nvd:{product}:{version or ''}"
        cached = cache_get(cache_key)
        if cached is not None:
            logger.debug(f"NVD cache hit: {cache_key}")
            return cached

        results = self._query_nvd(product, version)
        cache_set(cache_key, results, ttl=43200)  # 12 h cache
        return results

    def _query_nvd(self, product: str, version: Optional[str]) -> List[Dict]:
        """Perform the actual HTTP request to NVD."""
        keyword = f"{product} {version}".strip() if version else product
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": self._results_per_service,
        }

        time.sleep(REQUEST_DELAY)  # respect rate limit

        try:
            resp = self._session.get(NVD_API_URL, params=params, timeout=15)
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            logger.warning(f"NVD API timeout for '{keyword}'")
            return []
        except requests.exceptions.HTTPError as exc:
            logger.warning(f"NVD API HTTP error {exc.response.status_code} for '{keyword}'")
            return []
        except requests.exceptions.RequestException as exc:
            logger.warning(f"NVD API error for '{keyword}': {exc}")
            return []

        cves: List[Dict] = []
        for item in resp.json().get("vulnerabilities", []):
            vuln = item.get("cve", {})
            cves.append(
                {
                    "id": vuln.get("id"),
                    "description": self._extract_description(vuln),
                    "severity": self._extract_severity(vuln),
                    "cvss_score": self._extract_cvss_score(vuln),
                    "published": vuln.get("published", ""),
                    "url": f"https://nvd.nist.gov/vuln/detail/{vuln.get('id')}",
                }
            )

        return cves

    def _format(self, cve: Dict, service: Dict) -> Dict:
        """Combine CVE data with the affected service into a vulnerability record."""
        product = service.get("product", "")
        return {
            "cve_id": cve["id"],
            "description": cve["description"],
            "severity": cve["severity"],
            "cvss_score": cve["cvss_score"],
            "affected_product": product,
            "affected_version": service.get("version", ""),
            "port": service["port"],
            "published": cve["published"],
            "url": cve["url"],
            "remediation": f"Update {product} to the latest stable version and review vendor advisories.",
        }

    # ------------------------------------------------------------------
    # NVD response parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_description(vuln: Dict) -> str:
        for desc in vuln.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc["value"]
        descriptions = vuln.get("descriptions", [])
        return descriptions[0]["value"] if descriptions else "No description available."

    @staticmethod
    def _extract_severity(vuln: Dict) -> str:
        metrics = vuln.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric in metrics.get(key, []):
                sev = metric.get("cvssData", {}).get("baseSeverity")
                if sev:
                    return sev.upper()
        return "UNKNOWN"

    @staticmethod
    def _extract_cvss_score(vuln: Dict) -> float:
        metrics = vuln.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric in metrics.get(key, []):
                score = metric.get("cvssData", {}).get("baseScore")
                if score is not None:
                    return float(score)
        return 0.0
