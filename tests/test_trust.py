"""
test_trust.py
=============
Unit tests for Bayesian Dynamic Trust Engine and SQLite Persistence.
"""

import time
import os
import pytest
import numpy as np

from src.trust.trust_engine import BayesianDynamicTrustEngine, DeviceTrustState
from src.trust.db_manager import TrustDBManager


def test_initial_trust_prior():
    """Verify newly registered device starts with expected uninformative prior (0.5)."""
    engine = BayesianDynamicTrustEngine(prior_alpha=2.0, prior_beta=2.0)
    state = engine.get_or_create_device("10.0.0.1", current_time=1000.0)
    
    assert state.alpha == 2.0
    assert state.beta == 2.0
    assert pytest.approx(state.score, 0.01) == 0.50
    assert state.category == "SUSPICIOUS"
    assert state.total_flows == 0


def test_benign_trust_accumulation():
    """Verify series of benign flows raises trust score to HIGHLY_TRUSTED tier (>0.85)."""
    engine = BayesianDynamicTrustEngine()
    current_time = 1000.0

    for _ in range(25):
        current_time += 1.0
        state = engine.update_flow_observation(
            device_id="10.0.0.2",
            attack_confidence=0.05, # Benign flow
            flow_weight=1.0,
            current_time=current_time,
        )

    assert state.score >= 0.85
    assert state.category == "HIGHLY_TRUSTED"
    assert state.total_violations == 0
    assert state.total_flows == 25


def test_asymmetric_malicious_penalty():
    """Verify malicious flow penalizes trust much faster than benign flows reward it."""
    engine = BayesianDynamicTrustEngine(penalty_multiplier=3.5)
    current_time = 1000.0

    # Build moderate trust with 10 benign flows
    for _ in range(10):
        current_time += 1.0
        engine.update_flow_observation("10.0.0.3", attack_confidence=0.05, current_time=current_time)

    pre_attack_score = engine.get_trust_score("10.0.0.3", current_time=current_time)
    assert pre_attack_score > 0.70

    # Single severe attack flow
    current_time += 1.0
    state = engine.update_flow_observation("10.0.0.3", attack_confidence=0.98, current_time=current_time)
    post_attack_score = state.score

    # Score should drop significantly
    assert post_attack_score < pre_attack_score - 0.25
    assert state.total_violations == 1


def test_exponential_time_decay():
    """Verify inactive device trust decays towards baseline prior (0.5) over time."""
    engine = BayesianDynamicTrustEngine(decay_rate_lambda=0.01)
    start_time = 1000.0

    # Elevate trust
    for _ in range(15):
        start_time += 1.0
        engine.update_flow_observation("10.0.0.4", attack_confidence=0.02, current_time=start_time)

    high_score = engine.get_trust_score("10.0.0.4", current_time=start_time)
    assert high_score > 0.80

    # Advance time by 300 seconds without activity
    decayed_score = engine.get_trust_score("10.0.0.4", current_time=start_time + 300.0)
    assert decayed_score < high_score
    assert pytest.approx(decayed_score, abs=0.15) == 0.50


def test_sqlite_persistence(tmp_path):
    """Verify saving, loading, and audit trail logging in SQLite DB."""
    db_file = str(tmp_path / "test_trust.sqlite")
    db_mgr = TrustDBManager(db_path=db_file)

    test_state = DeviceTrustState(
        device_id="10.0.0.99",
        alpha=15.0,
        beta=2.0,
        last_updated=time.time(),
        total_flows=15,
        total_violations=0,
    )

    db_mgr.save_device_state(test_state)
    loaded_state = db_mgr.load_device_state("10.0.0.99")

    assert loaded_state is not None
    assert loaded_state.device_id == "10.0.0.99"
    assert loaded_state.alpha == 15.0
    assert pytest.approx(loaded_state.score, 0.01) == test_state.score

    # Audit logging
    db_mgr.log_audit_event(
        device_id="10.0.0.99",
        attack_confidence=0.10,
        action_taken="ALLOW",
        previous_score=0.85,
        new_score=0.88,
    )
