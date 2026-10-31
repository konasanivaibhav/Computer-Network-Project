"""
reward.py
=========
Multi-Objective Reward Function Formulation for SDN Intrusion Mitigation.

Balances:
1. Security Posture: Prompt mitigation of true attacks (Block/Redirect/Rate-Limit).
2. Availability Preservation: Strict penalty for false positives against legitimate/trusted users.
3. QoS / Network Overhead: Minimizing telemetry costs and avoiding unnecessary throttling.
4. Threat Adaptation: Special bonus for preemptively containing emerging 0-day exploits.
"""

from enum import IntEnum
from typing import Dict, Any, Tuple
import numpy as np


class MitigationAction(IntEnum):
    """Discrete Mitigation Actions available to the SDN Controller."""
    ALLOW = 0       # High-throughput forwarding
    MONITOR = 1     # Port mirroring to analyzer / Honeypot telemetry
    RATE_LIMIT = 2  # OpenFlow 1.3 meter band throttling
    REDIRECT = 3    # Quarantine VLAN / Honeynet sinkhole
    BLOCK = 4       # Hard drop flow rule


class MultiObjectiveRewardCalculator:
    """
    Computes scalarized reward R(s, a, y) based on the multi-objective payoff matrix:
    R = R_sec(y, a) + R_avail(y, a, T) + R_qos(a, C_net) + R_threat(y_emerging, a)
    """

    def __init__(
        self,
        w_sec: float = 1.0,
        w_avail: float = 1.2,
        w_qos: float = 0.5,
        w_threat: float = 1.0,
    ):
        """
        Initialize Reward Calculator with tunable objective weights.
        """
        self.w_sec = w_sec
        self.w_avail = w_avail
        self.w_qos = w_qos
        self.w_threat = w_threat

    def compute_reward(
        self,
        action: int,
        is_attack: bool,
        trust_score: float,
        congestion_index: float,
        is_emerging_threat: bool = False,
    ) -> Tuple[float, Dict[str, float]]:
        """
        Compute step reward and individual component breakdown.

        Args:
            action: Selected action integer in [0, 4].
            is_attack: True ground truth (True = Malicious, False = Benign).
            trust_score: Device Bayesian trust score T in [0, 1].
            congestion_index: Network congestion index C_net in [0, 1].
            is_emerging_threat: Flag indicating flow matches an active 0-day signature.

        Returns:
            Tuple of (total_reward, breakdown_dictionary).
        """
        action = MitigationAction(action)
        t = float(np.clip(trust_score, 0.0, 1.0))
        c_net = float(np.clip(congestion_index, 0.0, 1.0))

        r_sec = 0.0
        r_avail = 0.0
        r_qos = 0.0
        r_threat = 0.0

        if is_attack:
            # ==========================================
            # ATTACK FLOW GROUND TRUTH (y = 1)
            # ==========================================
            if action == MitigationAction.BLOCK:
                r_sec = 1.5
                r_avail = 0.0
                r_qos = 0.1 # Relieves network congestion
            elif action == MitigationAction.REDIRECT:
                r_sec = 1.2 # Useful for honeypot telemetry
                r_avail = 0.0
                r_qos = 0.0
            elif action == MitigationAction.RATE_LIMIT:
                r_sec = 0.5 # Partially mitigates attack volume
                r_avail = -0.2 # Small leak risk
                r_qos = 0.0
            elif action == MitigationAction.MONITOR:
                r_sec = -0.8 # Attack allowed to traverse network
                r_avail = 0.0
                r_qos = -0.1 # Consumes monitoring mirror bandwidth
            elif action == MitigationAction.ALLOW:
                r_sec = -2.5 # Catastrophic False Negative
                r_avail = 0.0
                r_qos = -0.5 # Severe impact if DoS traverses switch
        else:
            # ==========================================
            # BENIGN FLOW GROUND TRUTH (y = 0)
            # ==========================================
            if action == MitigationAction.ALLOW:
                r_sec = 1.0
                r_avail = 0.5 * t # Reward scales with user trust
                r_qos = 0.2
            elif action == MitigationAction.MONITOR:
                r_sec = 0.8
                r_avail = -0.05 # Minor inspection overhead
                r_qos = -0.05
            elif action == MitigationAction.RATE_LIMIT:
                r_sec = -0.4
                # If network is heavily congested, rate-limiting benign traffic is less penalized
                r_avail = -0.5 * (1.0 - c_net)
                r_qos = 0.3 * c_net # Helps congestion control
            elif action == MitigationAction.REDIRECT:
                r_sec = -1.2
                r_avail = -1.0 # High workflow disruption
                r_qos = -0.2
            elif action == MitigationAction.BLOCK:
                r_sec = -2.5
                # Severe False Positive penalty, penalized heavier for trusted hosts
                r_avail = -1.5 * t
                r_qos = 0.0

        # Emerging 0-day threat modifiers
        if is_emerging_threat:
            if is_attack:
                if action in (MitigationAction.BLOCK, MitigationAction.REDIRECT):
                    r_threat = 1.0 # Rapid zero-day containment bonus
                elif action == MitigationAction.ALLOW:
                    r_threat = -2.0 # Heavy penalty for zero-day breach
            else:
                if action == MitigationAction.ALLOW:
                    r_threat = 0.3

        total_reward = (
            (self.w_sec * r_sec)
            + (self.w_avail * r_avail)
            + (self.w_qos * r_qos)
            + (self.w_threat * r_threat)
        )

        breakdown = {
            "r_sec": float(r_sec),
            "r_avail": float(r_avail),
            "r_qos": float(r_qos),
            "r_threat": float(r_threat),
            "total_reward": float(total_reward),
        }

        return float(total_reward), breakdown
