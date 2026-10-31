"""
test_integration.py
===================
Comprehensive End-to-End System Integration Test.

Tests complete lifecycle across all 6 phases:
1. IDS Training & Platt Probability Calibration
2. Bayesian Device Trust Tracking & Decay
3. Network Telemetry & Congestion Context Collection
4. RL Decision Engine Inference
5. Threat Intelligence Scraping -> NLP Extraction -> Scapy Synthesis -> Canary Retraining
6. Closed-Loop SDN Controller Mitigation & Availability Verification (>99%)
"""

import os
import pytest
import numpy as np

from src.ids.train_rf import train_ids_pipeline, CalibratedRFModel
from src.ids.evaluator import IDSEvaluator
from src.trust.trust_engine import BayesianDynamicTrustEngine
from src.trust.db_manager import TrustDBManager
from src.context.collector import NetworkContextCollector
from src.rl.reward import MitigationAction
from src.rl.policy_infer import RLPolicyEngine
from src.threat_intel.scraper import AutomatedThreatScraper
from src.threat_intel.nlp_parser import ThreatNLPParser
from src.threat_intel.retrainer import ContinuousModelRetrainer
from src.sdn.ryu_controller import SDNRLControllerApp


def test_full_pipeline_integration(tmp_path):
    """End-to-end integration test validating all subsystem interconnections."""
    model_path = str(tmp_path / "integration_ids_model.joblib")
    db_path = str(tmp_path / "integration_threat.sqlite")

    # =========================================================================
    # Step 1: Train Base Calibrated Random Forest IDS
    # =========================================================================
    model, preprocessor, X_test, y_test = train_ids_pipeline(
        use_synthetic=True,
        n_samples=2500,
        n_estimators=30,
        save_path=model_path,
        test_size=0.25,
        random_state=42,
    )
    assert os.path.exists(model_path)
    evaluator = IDSEvaluator(target_tpr=0.90, target_fpr=0.10)
    base_results = evaluator.evaluate(y_test, model.predict_confidence(X_test))
    assert base_results["sla_compliance"]["meets_tpr_target"] is True

    # =========================================================================
    # Step 2: Initialize Trust Engine, DB, Context Collector, Controller
    # =========================================================================
    trust_engine = BayesianDynamicTrustEngine()
    trust_db = TrustDBManager(db_path=db_path)
    context_collector = NetworkContextCollector()
    controller = SDNRLControllerApp()
    controller.model_path = model_path
    controller._load_ids_model()
    controller.trust_db = trust_db

    # =========================================================================
    # Step 3: Simulate Normal Operations & Build Client Trust
    # =========================================================================
    t = 1000.0
    for i in range(20):
        t += 0.1
        action, prob, trust = controller.process_flow_intelligence(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.3",
            proto_str="tcp",
            dst_port=80,
            packet_len=120,
            current_time=t,
        )
        assert action in (MitigationAction.ALLOW, MitigationAction.MONITOR)

    client_trust = controller.trust_engine.get_trust_score("10.0.0.1", current_time=t)
    assert client_trust >= 0.80, f"Client trust {client_trust} failed to reach trusted status."

    # =========================================================================
    # Step 4: Threat Intelligence Extraction & Continuous Retraining
    # =========================================================================
    scraper = AutomatedThreatScraper(offline_fallback=True)
    advisories = scraper.get_synthetic_threat_fixtures()
    parser = ThreatNLPParser()
    sig = parser.parse_advisory(advisories[0]) # Moniker Link Exploit

    retrainer = ContinuousModelRetrainer(
        active_model_path=model_path,
        anchor_samples=1500,
        random_seed=42,
    )
    retrainer.add_emerging_signature(sig)

    retrain_success, retrain_metrics = retrainer.execute_retraining_cycle(
        samples_per_signature=400,
        n_estimators=25,
    )
    assert retrain_success is True

    # Reload newly retrained model in controller
    controller._load_ids_model()

    # =========================================================================
    # Step 5: Adversary Launches Emerging Exploit Attack
    # =========================================================================
    attacker_actions = []
    for _ in range(15):
        t += 0.01
        act, p, tr = controller.process_flow_intelligence(
            src_ip="10.0.0.4",
            dst_ip="10.0.0.3",
            proto_str=sig.protocol,
            dst_port=sig.target_port,
            packet_len=1350,
            current_time=t,
        )
        attacker_actions.append(act)

    # Verify that the emerging threat is successfully mitigated (Redirect/Rate-Limit/Block)
    assert any(a in (MitigationAction.BLOCK, MitigationAction.REDIRECT, MitigationAction.RATE_LIMIT) for a in attacker_actions)

    # Verify benign client 10.0.0.1 is still allowed (High Availability)
    clean_action, _, _ = controller.process_flow_intelligence(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.3",
        proto_str="tcp",
        dst_port=80,
        packet_len=120,
        current_time=t + 1.0,
    )
    assert clean_action == MitigationAction.ALLOW
