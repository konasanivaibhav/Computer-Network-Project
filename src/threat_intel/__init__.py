"""
threat_intel subpackage: Automated Threat Scraper, NLP Signature Extractor, Scapy Traffic Generator, Continuous Retrainer, and APScheduler Daemon.
"""
from src.threat_intel.scraper import AutomatedThreatScraper, RawThreatAdvisory
from src.threat_intel.nlp_parser import ThreatNLPParser, ThreatSignature
from src.threat_intel.traffic_gen import SyntheticTrafficGenerator
from src.threat_intel.retrainer import ContinuousModelRetrainer
from src.threat_intel.scheduler import ThreatIntelScheduler

__all__ = [
    "AutomatedThreatScraper",
    "RawThreatAdvisory",
    "ThreatNLPParser",
    "ThreatSignature",
    "SyntheticTrafficGenerator",
    "ContinuousModelRetrainer",
    "ThreatIntelScheduler",
]
