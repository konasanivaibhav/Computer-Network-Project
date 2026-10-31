"""
test_rl_env.py
==============
Unit tests for Reinforcement Learning SDN Intrusion Environment, Multi-Objective Reward,
and Policy Inference Engine.
"""

import pytest
import numpy as np

from src.rl.reward import MultiObjectiveRewardCalculator, MitigationAction
from src.rl.sdn_env import SDNIntrusionEnv
from src.rl.policy_infer import RLPolicyEngine


def test_reward_payoff_matrix():
    """Verify security, availability, and QoS balance across the payoff matrix."""
    calc = MultiObjectiveRewardCalculator()

    # 1. Correct Attack Block (High positive reward)
    r_block_atk, _ = calc.compute_reward(
        action=MitigationAction.BLOCK,
        is_attack=True,
        trust_score=0.2,
        congestion_index=0.2,
    )
    assert r_block_atk > 1.0

    # 2. Severe False Negative (Allowing an attack yields heavy penalty)
    r_allow_atk, _ = calc.compute_reward(
        action=MitigationAction.ALLOW,
        is_attack=True,
        trust_score=0.5,
        congestion_index=0.2,
    )
    assert r_allow_atk < -2.0

    # 3. Correct Benign Allow (Reward scales with trust)
    r_allow_benign_high_trust, _ = calc.compute_reward(
        action=MitigationAction.ALLOW,
        is_attack=False,
        trust_score=0.95,
        congestion_index=0.1,
    )
    r_allow_benign_low_trust, _ = calc.compute_reward(
        action=MitigationAction.ALLOW,
        is_attack=False,
        trust_score=0.20,
        congestion_index=0.1,
    )
    assert r_allow_benign_high_trust > r_allow_benign_low_trust

    # 4. Severe False Positive (Blocking a highly trusted benign user is heavily penalized)
    r_block_benign, _ = calc.compute_reward(
        action=MitigationAction.BLOCK,
        is_attack=False,
        trust_score=0.90,
        congestion_index=0.1,
    )
    assert r_block_benign < -3.0


def test_sdn_gym_env_lifecycle():
    """Verify environment initialization, stepping, and metric recording."""
    env = SDNIntrusionEnv(max_steps=50, random_seed=42)
    obs, info = env.reset(seed=42)

    assert obs.shape == (12,)
    assert not np.isnan(obs).any()
    assert np.all((obs >= 0.0) & (obs <= 1.0))

    total_reward = 0.0
    for step in range(50):
        # Choose action
        action = env.action_space.sample() if hasattr(env.action_space, "sample") else 0
        next_obs, reward, terminated, truncated, step_info = env.step(action)
        
        assert next_obs.shape == (12,)
        assert isinstance(reward, float)
        assert "availability_rate" in step_info
        total_reward += reward

        if terminated:
            assert step == 49
            break


def test_rl_policy_inference_latency():
    """Verify RL policy engine satisfies sub-5ms latency constraint."""
    policy = RLPolicyEngine()
    bench = policy.benchmark_latency(n_iterations=500)

    assert bench["mean_latency_ms"] < 2.0
    assert bench["p99_latency_ms"] < 5.0
    assert bench["target_met"] is True


def test_adaptive_mitigation_actions():
    """Verify policy selects nuanced mitigation actions based on multidimensional state."""
    policy = RLPolicyEngine()

    # 1. Clean benign traffic -> ALLOW
    act1 = policy.predict_action(attack_confidence=0.05, trust_score=0.90)
    assert act1 == MitigationAction.ALLOW

    # 2. Confirmed malicious low-trust attack -> BLOCK
    act2 = policy.predict_action(attack_confidence=0.95, trust_score=0.15)
    assert act2 == MitigationAction.BLOCK

    # 3. Burst from trusted server -> RATE_LIMIT (preserves availability)
    act3 = policy.predict_action(attack_confidence=0.88, trust_score=0.85)
    assert act3 == MitigationAction.RATE_LIMIT

    # 4. Zero-Day Threat -> REDIRECT (honeypot telemetry)
    act4 = policy.predict_action(attack_confidence=0.70, trust_score=0.50, is_emerging_threat=True)
    assert act4 == MitigationAction.REDIRECT
