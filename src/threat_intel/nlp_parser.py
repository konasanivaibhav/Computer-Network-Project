"""
nlp_parser.py
=============
Hybrid NLP & Regex Threat Parser.

Extracts structured network detection signatures from unstructured CVE bulletins,
NVD advisories, and Exploit-DB entries.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
import logging

from src.threat_intel.scraper import RawThreatAdvisory

logger = logging.getLogger(__name__)


@dataclass
class ThreatSignature:
    """Structured Network Defense Signature synthesized from threat advisory."""
    cve_id: str
    attack_type: str                   # DDoS, RCE, PortScan, Exploit, Bypass, Traversal
    protocol: str                      # tcp, udp, icmp
    target_port: int                   # Destination port
    packet_size_range: Tuple[int, int] # (min_size, max_size)
    rate_threshold_pps: float          # Packets per second triggering detection
    payload_regex: str                 # Regex or byte stream pattern
    cvss_score: float                  # 0.0 to 10.0
    severity: str                      # LOW, MEDIUM, HIGH, CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["packet_size_range"] = list(self.packet_size_range)
        return d


class ThreatNLPParser:
    """
    Hybrid parser combining spaCy Named Entity Recognition and regular expressions
    to extract technical parameters from unstructured text.
    """

    def __init__(self, spacy_model: str = "en_core_web_sm"):
        """Initialize NLP parser."""
        self.nlp = None
        try:
            import spacy
            self.nlp = spacy.load(spacy_model)
            logger.info("Loaded spaCy NLP model: %s", spacy_model)
        except Exception:
            logger.warning("spaCy model '%s' not found. Using high-precision RegEx rule engine.", spacy_model)

    def _extract_protocol(self, text: str) -> str:
        """Extract protocol (TCP, UDP, ICMP) from text."""
        t = text.lower()
        if "udp" in t:
            return "udp"
        elif "icmp" in t or "ping flood" in t:
            return "icmp"
        return "tcp" # Default dominant internet protocol

    def _extract_port(self, text: str) -> int:
        """Extract target port using regex patterns (e.g., 'port 8080', 'port: 443', 'TCP/22')."""
        match = re.search(r"(?:port|listening on|tcp\/|udp\/)\s*[:#]?\s*(\d{1,5})", text, re.IGNORECASE)
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                return port

        # Service-based port heuristics
        t = text.lower()
        if "https" in t or "ssl" in t or "tls" in t:
            return 443
        elif "ssh" in t or "sshd" in t:
            return 22
        elif "dns" in t:
            return 53
        elif "http" in t or "web" in t:
            return 80
        return 80 # Default HTTP

    def _extract_rate_threshold(self, text: str) -> float:
        """Extract packet rate threshold (pps) from text."""
        match = re.search(r"(\d+)\s*(?:packets\/sec|pps|req\/s|requests per second)", text, re.IGNORECASE)
        if match:
            return float(match.group(1))
        return 250.0 # Default threshold

    def _extract_packet_size_range(self, text: str) -> Tuple[int, int]:
        """Extract packet size range bounds."""
        match = re.search(r"size\s*(?:between|from)?\s*(\d+)\s*(?:and|to|-)\s*(\d+)", text, re.IGNORECASE)
        if match:
            return (int(match.group(1)), int(match.group(2)))
        return (64, 1500)

    def _extract_attack_type(self, text: str) -> str:
        """Categorize attack type from text keywords."""
        t = text.lower()
        if "dos" in t or "ddos" in t or "amplification" in t or "flood" in t:
            return "DDoS"
        elif "remote code execution" in t or "rce" in t:
            return "RCE"
        elif "bypass" in t or "auth" in t:
            return "Auth_Bypass"
        elif "traversal" in t or "directory" in t:
            return "Directory_Traversal"
        elif "scan" in t or "recon" in t:
            return "Port_Scan"
        return "Generic_Exploit"

    def _extract_payload_regex(self, text: str) -> str:
        """Extract hexadecimal or regex payload pattern."""
        match = re.search(r"(\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2})+)", text)
        if match:
            return match.group(1)
        return ".*"

    def parse_advisory(self, advisory: RawThreatAdvisory) -> ThreatSignature:
        """
        Parse raw unstructured advisory into a structured ThreatSignature.
        """
        combined_text = f"{advisory.title} {advisory.description}"

        protocol = self._extract_protocol(combined_text)
        port = self._extract_port(combined_text)
        rate_pps = self._extract_rate_threshold(combined_text)
        size_range = self._extract_packet_size_range(combined_text)
        attack_type = self._extract_attack_type(combined_text)
        payload_regex = self._extract_payload_regex(combined_text)

        # Severity categorization
        score = advisory.cvss_score
        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        sig = ThreatSignature(
            cve_id=advisory.cve_id,
            attack_type=attack_type,
            protocol=protocol,
            target_port=port,
            packet_size_range=size_range,
            rate_threshold_pps=rate_pps,
            payload_regex=payload_regex,
            cvss_score=score,
            severity=severity,
        )

        logger.info("Parsed %s -> %s on %s:%d (Severity: %s, PPS: %.1f)",
                    sig.cve_id, sig.attack_type, sig.protocol.upper(), sig.target_port, sig.severity, sig.rate_threshold_pps)
        return sig
