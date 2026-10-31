"""
test_threat_intel.py
====================
Unit and integration tests for Automated Threat Intelligence, NLP Parsing,
Synthetic Traffic Generation, and Continuous Retraining.
"""

import pytest
import os
import pandas as pd
import numpy as np

from src.threat_intel.scraper import AutomatedThreatScraper, RawThreatAdvisory
from src.threat_intel.nlp_parser import ThreatNLPParser, ThreatSignature
from src.threat_intel.traffic_gen import SyntheticTrafficGenerator
from src.threat_intel.retrainer import ContinuousModelRetrainer


def test_threat_scraper_fixtures():
    """Verify scraper retrieves structured raw advisories."""
    scraper = AutomatedThreatScraper(offline_fallback=True)
    fixtures = scraper.get_synthetic_threat_fixtures()
    
    assert len(fixtures) >= 3
    for f in fixtures:
        assert f.cve_id.startswith("CVE-")
        assert f.cvss_score > 0.0
        assert len(f.description) > 20


def test_nlp_threat_parser():
    """Verify hybrid NLP/Regex engine parses unstructured advisory into structured signature."""
    parser = ThreatNLPParser()
    advisory = RawThreatAdvisory(
        source="TEST",
        cve_id="CVE-2024-99999",
        title="Critical Zero-Day UDP Amplification Exploit",
        description="High volume UDP amplification flood targeting UDP port 11211 with packets > 1200 bytes at rate 600 packets/sec.",
        cvss_score=9.8,
    )

    sig = parser.parse_advisory(advisory)
    assert sig.cve_id == "CVE-2024-99999"
    assert sig.protocol == "udp"
    assert sig.target_port == 11211
    assert sig.rate_threshold_pps == 600.0
    assert sig.severity == "CRITICAL"
    assert sig.attack_type == "DDoS"


def test_synthetic_traffic_generator():
    """Verify generator translates ThreatSignature into canonical 28-feature DataFrame."""
    gen = SyntheticTrafficGenerator(random_seed=42)
    sig = ThreatSignature(
        cve_id="CVE-2024-1234",
        attack_type="RCE",
        protocol="tcp",
        target_port=443,
        packet_size_range=(1000, 1400),
        rate_threshold_pps=300.0,
        payload_regex=".*",
        cvss_score=9.0,
        severity="CRITICAL",
    )

    df, y = gen.generate_flow_dataframe(sig, n_samples=200)
    assert len(df) == 200
    assert len(y) == 200
    assert (y == 1).all()
    assert df["proto"].iloc[0] == "tcp"
    assert df["service"].iloc[0] == "ssl"


def test_continuous_retraining_canary_cycle(tmp_path):
    """Verify dual-buffer retraining and canary shadow evaluation."""
    model_path = str(tmp_path / "test_active_ids.joblib")
    
    retrainer = ContinuousModelRetrainer(
        active_model_path=model_path,
        anchor_samples=1000,
        random_seed=42,
    )

    new_sig = ThreatSignature(
        cve_id="CVE-2024-TEST",
        attack_type="DDoS",
        protocol="udp",
        target_port=53,
        packet_size_range=(500, 1000),
        rate_threshold_pps=400.0,
        payload_regex=".*",
        cvss_score=9.5,
        severity="CRITICAL",
    )
    retrainer.add_emerging_signature(new_sig)

    success, results = retrainer.execute_retraining_cycle(
        samples_per_signature=500,
        n_estimators=20, # Fast for unit test
    )

    assert success is True
    assert os.path.exists(model_path)
    assert results["sla_compliance"]["overall_sla_pass"] is True
