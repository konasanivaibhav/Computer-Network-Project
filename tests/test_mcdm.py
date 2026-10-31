"""
test_mcdm.py
============
Tests for the Multi-Criteria Decision Making layer (AHP + TOPSIS) and the
context-aware adaptive decision engine.
"""

import numpy as np
import pytest

from src.mcdm.ahp import ahp_weights, default_weights
from src.mcdm.topsis import topsis
from src.mcdm.decision_engine import AdaptiveDecisionEngine, DecisionContext, build_decision_matrix
from src.rl.reward import MitigationAction
from src.rl.policy_infer import RLPolicyEngine


def test_ahp_default_weights_are_consistent():
    res = default_weights()
    assert res.is_consistent, f"CR={res.consistency_ratio:.3f} should be < 0.10"
    assert np.isclose(res.weights.sum(), 1.0)
    # Threat containment is judged most important
    assert res.criteria[int(np.argmax(res.weights))] == "threat_containment"


def test_ahp_rejects_non_reciprocal_matrix():
    with pytest.raises(ValueError):
        ahp_weights(["a", "b"], [[1, 3], [3, 1]])


def test_ahp_detects_inconsistent_judgements():
    # a > b (9), b > c (9), but c > a (9): circular preferences
    res = ahp_weights(["a", "b", "c"], [[1, 9, 1 / 9], [1 / 9, 1, 9], [9, 1 / 9, 1]])
    assert not res.is_consistent


def test_topsis_textbook_ordering():
    # Alternative 0 dominates on every criterion -> must rank first
    m = np.array([[9, 1], [5, 5], [1, 9]], dtype=float)
    res = topsis(m, [0.5, 0.5], [True, False])
    assert res.ranking[0] == 0 and res.ranking[-1] == 2
    assert np.all((res.closeness >= 0) & (res.closeness <= 1))


def test_decision_matrix_shape_and_positivity():
    m = build_decision_matrix(DecisionContext(attack_confidence=0.7, trust_score=0.3))
    assert m.shape == (5, 5)
    assert np.all(m > 0)


def test_pure_mcdm_graded_response():
    engine = AdaptiveDecisionEngine(policy_engine=None)
    cases = [
        (0.02, 0.95, {MitigationAction.ALLOW}),
        (0.97, 0.08, {MitigationAction.BLOCK}),
        (0.60, 0.50, {MitigationAction.RATE_LIMIT, MitigationAction.REDIRECT}),
    ]
    for p, t, expected in cases:
        action = engine.decide(DecisionContext(attack_confidence=p, trust_score=t)).action
        assert action in expected, (p, t, action)


def test_severity_is_monotonic_in_attack_confidence():
    engine = AdaptiveDecisionEngine(policy_engine=None)
    sev = [int(engine.decide(DecisionContext(attack_confidence=p, trust_score=0.3)).action)
           for p in np.linspace(0.0, 1.0, 11)]
    assert all(b >= a for a, b in zip(sev, sev[1:])), sev


def test_hard_block_guardrail_overrides():
    class AlwaysAllow:
        def action_probabilities(self, **_):
            return np.array([1.0, 0, 0, 0, 0])
    engine = AdaptiveDecisionEngine(policy_engine=AlwaysAllow(), fusion_lambda=0.99)
    d = engine.decide(DecisionContext(attack_confidence=0.99, trust_score=0.05))
    assert d.action == MitigationAction.BLOCK
    assert d.guardrail and "hard block" in d.guardrail


def test_allow_list_never_blocked():
    engine = AdaptiveDecisionEngine(policy_engine=None, allow_list={"10.0.0.53"})
    d = engine.decide(DecisionContext(attack_confidence=0.99, trust_score=0.05, src_ip="10.0.0.53"))
    assert d.action != MitigationAction.BLOCK


def test_fusion_with_policy_engine_returns_explanation():
    engine = AdaptiveDecisionEngine(policy_engine=RLPolicyEngine())
    d = engine.decide(DecisionContext(attack_confidence=0.9, trust_score=0.2))
    out = d.to_dict()
    assert len(out["final_scores"]) == 5 and len(out["topsis"]) == 5 and len(out["ppo"]) == 5
    assert np.isclose(sum(d.ppo_probabilities), 1.0)
    assert d.action in (MitigationAction.BLOCK, MitigationAction.REDIRECT)


def test_trusted_host_is_throttled_not_blocked():
    class AlwaysBlock:
        def action_probabilities(self, **_):
            return np.array([0, 0, 0, 0, 1.0])
    engine = AdaptiveDecisionEngine(policy_engine=AlwaysBlock(), fusion_lambda=0.99)
    d = engine.decide(DecisionContext(attack_confidence=0.9, trust_score=0.92))
    assert d.action == MitigationAction.RATE_LIMIT
    assert "trusted host" in d.guardrail


def test_zero_day_forensics_redirects_to_honeypot():
    class AlwaysBlock:
        def action_probabilities(self, **_):
            return np.array([0, 0, 0, 0, 1.0])
    on = AdaptiveDecisionEngine(policy_engine=AlwaysBlock(), fusion_lambda=0.99, zero_day_forensics=True)
    d = on.decide(DecisionContext(attack_confidence=0.99, trust_score=0.05, is_emerging_threat=True))
    assert d.action == MitigationAction.REDIRECT and "honeypot" in d.guardrail
    off = AdaptiveDecisionEngine(policy_engine=AlwaysBlock(), fusion_lambda=0.99)
    assert off.decide(DecisionContext(attack_confidence=0.99, trust_score=0.05, is_emerging_threat=True)).action == MitigationAction.BLOCK


def test_monitoring_of_uncertain_devices_and_ambiguous_scores():
    eng = AdaptiveDecisionEngine(policy_engine=None, monitor_uncertain=True)
    # brand-new device: Beta(2,2) prior variance 0.05 -> monitored, not simply allowed
    d = eng.decide(DecisionContext(attack_confidence=0.02, trust_score=0.5, trust_variance=0.05))
    assert d.action == MitigationAction.MONITOR
    # high trust but very little history: TOPSIS would allow, the guardrail monitors instead
    d = eng.decide(DecisionContext(attack_confidence=0.02, trust_score=0.95, trust_variance=0.05))
    assert d.action == MitigationAction.MONITOR and "new" in d.guardrail
    # established, trusted device with a clean flow -> allowed
    assert eng.decide(DecisionContext(attack_confidence=0.02, trust_score=0.95, trust_variance=0.005)).action == MitigationAction.ALLOW
    # monitoring never weakens a stronger action
    assert eng.decide(DecisionContext(attack_confidence=0.99, trust_score=0.05, trust_variance=0.05)).action == MitigationAction.BLOCK
    # off by default
    off = AdaptiveDecisionEngine(policy_engine=None)
    assert off.decide(DecisionContext(attack_confidence=0.02, trust_score=0.95, trust_variance=0.05)).action == MitigationAction.ALLOW
