"""
cve_lookup.py
-------------
Queries the NVD (National Vulnerability Database) REST API v2.0 for
CVEs matching a product/version string, with basic rate-limiting and
in-memory caching so identical service versions across multiple hosts
only get looked up once.

NVD public rate limits (as of API v2.0):
    - No API key:  5 requests per rolling 30 seconds
    - With key:    50 requests per rolling 30 seconds
Request a free key at https://nvd.nist.gov/developers/request-an-api-key
"""

import time
import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVELookup:
    def __init__(self, api_key: str = None, results_per_query: int = 20):
        self.api_key = api_key
        self.results_per_query = results_per_query
        self.cache = {}  # keyword -> list of CVE dicts
        self._last_request_time = 0
        # Stay comfortably under NVD's published limits
        self._min_interval = 0.7 if api_key else 6.5

    def _throttle(self):
        elapsed = time.time() - self._last_request_time
        wait = self._min_interval - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request_time = time.time()

    def _extract_cvss(self, cve_obj: dict):
        """Prefer CVSS v3.1, then v3.0, then v2 — return (score, severity)."""
        metrics = cve_obj.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0].get("cvssData", {})
                score = data.get("baseScore")
                severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
                return score, severity
        return None, None

    def _extract_description(self, cve_obj: dict) -> str:
        for desc in cve_obj.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return ""

    def search(self, keyword: str):
        """Query NVD for a keyword (e.g. 'vsftpd 2.3.4') and return a list of CVE summaries."""
        if keyword in self.cache:
            return self.cache[keyword]

        self._throttle()

        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"keywordSearch": keyword, "resultsPerPage": self.results_per_query}

        try:
            resp = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=20)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"    [!] NVD lookup failed for '{keyword}': {e}")
            self.cache[keyword] = []
            return []

        data = resp.json()
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve_obj = vuln.get("cve", {})
            score, severity = self._extract_cvss(cve_obj)
            results.append({
                "id": cve_obj.get("id", "UNKNOWN"),
                "description": self._extract_description(cve_obj),
                "cvss_score": score if score is not None else 0.0,
                "severity": severity or "UNKNOWN",
            })

        # Highest severity first
        results.sort(key=lambda c: c["cvss_score"], reverse=True)
        self.cache[keyword] = results
        return results

    def enrich_hosts(self, hosts, max_cves: int = 8):
        """
        Attach a 'cves' list to each service dict in `hosts`, mutating and
        returning the same structure that scanner.parse_nmap_xml produces.
        """
        for host in hosts:
            for svc in host["services"]:
                product = svc.get("product", "")
                version = svc.get("version", "")
                keyword = f"{product} {version}".strip()

                if not keyword:
                    svc["cves"] = []
                    continue

                print(f"    -> checking {host['ip']}:{svc['port']} ({keyword or svc['service']})")
                matches = self.search(keyword)
                svc["cves"] = matches[:max_cves]

        return hosts
