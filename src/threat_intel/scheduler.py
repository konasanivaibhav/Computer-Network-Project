"""
scheduler.py
============
Threat Intelligence Orchestrator & Periodic Scraper Daemon.
"""

import time
import argparse
import logging
from typing import Optional

from src.threat_intel.scraper import AutomatedThreatScraper
from src.threat_intel.nlp_parser import ThreatNLPParser
from src.threat_intel.retrainer import ContinuousModelRetrainer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class ThreatIntelScheduler:
    """
    Orchestrates periodic threat scraping, NLP parsing, and retraining triggers.
    """

    def __init__(
        self,
        interval_seconds: int = 3600,
        model_path: str = "models/ids_rf_calibrated.joblib",
    ):
        self.interval_seconds = interval_seconds
        self.scraper = AutomatedThreatScraper(offline_fallback=True)
        self.parser = ThreatNLPParser()
        self.retrainer = ContinuousModelRetrainer(active_model_path=model_path)
        self.seen_cves = set()

    def run_polling_cycle(self) -> int:
        """Run single sweep: scrape -> parse -> retrain if new threats found."""
        logger.info("Running Threat Intelligence Polling Cycle...")
        advisories = self.scraper.fetch_nvd_recent_cves() + self.scraper.fetch_cisa_kev()
        new_threats = 0

        for adv in advisories:
            if adv.cve_id not in self.seen_cves:
                self.seen_cves.add(adv.cve_id)
                sig = self.parser.parse_advisory(adv)
                self.retrainer.add_emerging_signature(sig)
                new_threats += 1

        if new_threats > 0:
            logger.info("Discovered %d new threat vectors. Triggering continuous retraining...", new_threats)
            success, _ = self.retrainer.execute_retraining_cycle()
            return new_threats

        logger.info("No new threat vectors discovered in this cycle.")
        return 0

    def start_daemon(self, max_cycles: Optional[int] = None) -> None:
        """Start daemon loop."""
        logger.info("Starting Threat Intelligence Daemon (Interval: %d seconds)...", self.interval_seconds)
        cycles = 0
        try:
            while max_cycles is None or cycles < max_cycles:
                self.run_polling_cycle()
                cycles += 1
                if max_cycles and cycles >= max_cycles:
                    break
                time.sleep(self.interval_seconds)
        except KeyboardInterrupt:
            logger.info("Threat Intelligence Daemon terminated by user.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intelligence Daemon")
    parser.add_argument("--interval_hours", type=float, default=1.0, help="Polling interval in hours")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    interval_sec = int(args.interval_hours * 3600)
    scheduler = ThreatIntelScheduler(interval_seconds=interval_sec)

    if args.once:
        scheduler.run_polling_cycle()
    else:
        scheduler.start_daemon()
