"""
scraper.py
==========
Automated Threat Intelligence Scraper.

Periodically queries:
1. NIST National Vulnerability Database (NVD) REST API 2.0.
2. Exploit-DB RSS / Git Commit Feeds.
3. CISA Known Exploited Vulnerabilities (KEV) Catalog.
4. Includes built-in synthetic threat fixtures for offline/isolated simulation.
"""

import time
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class RawThreatAdvisory:
    """Represents an unstructured threat bulletin or CVE report."""
    source: str                    # NVD, ExploitDB, CISA_KEV, SYNTHETIC
    cve_id: str                    # e.g., CVE-2024-38856
    title: str                     # Short summary
    description: str               # Unstructured technical text
    cvss_score: float = 7.5        # Base CVSS severity score
    published_date: str = ""       # ISO format date
    references: List[str] = field(default_factory=list)
    raw_payload: Dict[str, Any] = field(default_factory=dict)


class AutomatedThreatScraper:
    """
    Scrapes external threat intelligence repositories for zero-day disclosures
    and newly weaponized network exploit advisories.
    """

    def __init__(
        self,
        nvd_api_key: Optional[str] = None,
        request_timeout: int = 10,
        offline_fallback: bool = True,
    ):
        """
        Initialize scraper.

        Args:
            nvd_api_key: Optional API key for NIST NVD 2.0 to bypass rate limits.
            request_timeout: HTTP request timeout in seconds.
            offline_fallback: Whether to return realistic threat fixtures if network is unavailable.
        """
        self.nvd_api_key = nvd_api_key
        self.request_timeout = request_timeout
        self.offline_fallback = offline_fallback
        self.headers = {"User-Agent": "SDN-Threat-Intel-Bot/1.0"}
        if self.nvd_api_key:
            self.headers["apiKey"] = self.nvd_api_key

    def fetch_nvd_recent_cves(self, hours_back: int = 24) -> List[RawThreatAdvisory]:
        """Query NIST NVD 2.0 API for recent CVEs."""
        advisories: List[RawThreatAdvisory] = []
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        try:
            logger.info("Polling NIST NVD API for recent network CVEs...")
            params = {"resultsPerPage": 20}
            resp = requests.get(nvd_url, headers=self.headers, params=params, timeout=self.request_timeout)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "UNKNOWN")
                    descriptions = cve.get("descriptions", [])
                    desc_text = descriptions[0].get("value", "") if descriptions else ""
                    
                    # Extract CVSS
                    metrics = cve.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 7.5))

                    advisories.append(RawThreatAdvisory(
                        source="NVD",
                        cve_id=cve_id,
                        title=f"NVD Vulnerability: {cve_id}",
                        description=desc_text,
                        cvss_score=cvss_score,
                        published_date=cve.get("published", ""),
                        raw_payload=cve,
                    ))
                logger.info("Successfully fetched %d CVEs from NVD.", len(advisories))
                return advisories
        except Exception as e:
            logger.warning("NVD API fetch failed (%s). Falling back if enabled.", e)

        if self.offline_fallback:
            return self.get_synthetic_threat_fixtures()
        return []

    def fetch_cisa_kev(self) -> List[RawThreatAdvisory]:
        """Fetch actively exploited vulnerabilities from CISA KEV JSON catalog."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.request_timeout)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])[:10]
                return [
                    RawThreatAdvisory(
                        source="CISA_KEV",
                        cve_id=v.get("cveID", ""),
                        title=v.get("vulnerabilityName", ""),
                        description=v.get("shortDescription", ""),
                        cvss_score=9.0,
                        published_date=v.get("dateAdded", ""),
                        raw_payload=v,
                    )
                    for v in vulns
                ]
        except Exception as e:
            logger.warning("CISA KEV fetch failed: %s", e)

        return self.get_synthetic_threat_fixtures() if self.offline_fallback else []

    def get_synthetic_threat_fixtures(self) -> List[RawThreatAdvisory]:
        """
        Pre-configured realistic threat advisories for testing zero-day signature
        synthesis, continuous retraining, and Mininet attack emulation.
        """
        return [
            RawThreatAdvisory(
                source="SYNTHETIC",
                cve_id="CVE-2024-21413",
                title="Microsoft Outlook Moniker Link Remote Code Execution Vulnerability",
                description="High severity RCE exploit sending crafted malicious payloads over TCP port 443 with binary regex \\x4d\\x53\\x53\\x50\\x4c\\x4b. Traffic rate exceeds 300 packets/sec with payload size between 1200 and 1500 bytes.",
                cvss_score=9.8,
                published_date="2024-02-13",
            ),
            RawThreatAdvisory(
                source="SYNTHETIC",
                cve_id="CVE-2024-38856",
                title="Apache OFBiz Authentication Bypass & RCE Vulnerability",
                description="Critical vulnerability targeting HTTP REST endpoints on TCP port 8443 and port 8080. Involves URL traversal path /webtools/control/main with anomalous request burst rates > 500 pps.",
                cvss_score=9.8,
                published_date="2024-08-05",
            ),
            RawThreatAdvisory(
                source="SYNTHETIC",
                cve_id="CVE-2024-6387",
                title="regreSSHion: OpenSSH Remote Code Execution in glibc-based systems",
                description="Signal handler race condition vulnerability in OpenSSH sshd daemon listening on TCP port 22. Attackers generate over 1000 failed authentication handshakes within short durations.",
                cvss_score=8.1,
                published_date="2024-07-01",
            ),
            RawThreatAdvisory(
                source="SYNTHETIC",
                cve_id="CVE-2024-28995",
                title="SolarWinds Serv-U Directory Traversal Vulnerability",
                description="Unauthenticated path traversal exploit on TCP port 80 and UDP port 5060 targeting sensitive configuration files via specific hexadecimal byte streams.",
                cvss_score=8.6,
                published_date="2024-06-05",
            ),
        ]
