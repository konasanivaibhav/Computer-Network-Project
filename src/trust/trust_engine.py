"""
trust_engine.py
===============
Bayesian Dynamic Device Trust Scoring Engine.

Models per-host security reputation as a conjugate Beta distribution Beta(alpha, beta).
Features:
- Closed-form Bayesian posterior updates based on flow classification confidence.
- Asymmetric penalty weighting (trust is slow to gain, rapid to lose).
- Exponential time-decay for inactive devices decaying towards baseline prior.
- Epistemic uncertainty / variance estimation.
- Trust tier categorization (Untrusted, Suspicious, Trusted, Highly Trusted).
"""

import time
import math
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class DeviceTrustState:
    """Represents the instantaneous Bayesian trust belief of a network host."""
    device_id: str                   # IP address or MAC address
    alpha: float = 2.0               # Positive evidence parameter (prior = 2.0)
    beta: float = 2.0                # Negative evidence parameter (prior = 2.0)
    last_updated: float = 0.0        # Timestamp of last state transition (epoch seconds)
    total_flows: int = 0             # Total evaluated flows
    total_violations: int = 0        # Total detected malicious flows

    @property
    def score(self) -> float:
        """Expected trust value: E[Beta(alpha, beta)] = alpha / (alpha + beta)."""
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        """Uncertainty in trust score: Var[Beta(alpha, beta)]."""
        total = self.alpha + self.beta
        return (self.alpha * self.beta) / ((total ** 2) * (total + 1.0))

    @property
    def category(self) -> str:
        """Categorical reputation classification."""
        s = self.score
        if s < 0.30:
            return "UNTRUSTED"
        elif s < 0.60:
            return "SUSPICIOUS"
        elif s < 0.85:
            return "TRUSTED"
        else:
            return "HIGHLY_TRUSTED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "alpha": float(self.alpha),
            "beta": float(self.beta),
            "score": float(self.score),
            "variance": float(self.variance),
            "category": self.category,
            "last_updated": float(self.last_updated),
            "total_flows": int(self.total_flows),
            "total_violations": int(self.total_violations),
        }


class BayesianDynamicTrustEngine:
    """
    Dynamic Bayesian Trust Engine for SDN Device Profiling.
    Tracks, updates, and persists trust scores in real-time.
    """

    def __init__(
        self,
        prior_alpha: float = 2.0,
        prior_beta: float = 2.0,
        decay_rate_lambda: float = 0.001,
        penalty_multiplier: float = 3.5,
        benign_threshold: float = 0.35,
        attack_threshold: float = 0.65,
    ):
        """
        Initialize the Trust Engine.

        Args:
            prior_alpha: Prior positive belief pseudo-count.
            prior_beta: Prior negative belief pseudo-count.
            decay_rate_lambda: Exponential time decay parameter per second.
            penalty_multiplier: Multiplier for malicious observations (asymmetric loss).
            benign_threshold: Attack probability below which flow is deemed benign.
            attack_threshold: Attack probability above which flow is penalized.
        """
        self.prior_alpha = prior_alpha
        self.prior_beta = prior_beta
        self.decay_rate_lambda = decay_rate_lambda
        self.penalty_multiplier = penalty_multiplier
        self.benign_threshold = benign_threshold
        self.attack_threshold = attack_threshold

        self._devices: Dict[str, DeviceTrustState] = {}

    def get_or_create_device(self, device_id: str, current_time: Optional[float] = None) -> DeviceTrustState:
        """Retrieve existing device trust state or initialize a new uninformative prior."""
        now = current_time if current_time is not None else time.time()
        if device_id not in self._devices:
            self._devices[device_id] = DeviceTrustState(
                device_id=device_id,
                alpha=self.prior_alpha,
                beta=self.prior_beta,
                last_updated=now,
                total_flows=0,
                total_violations=0,
            )
        return self._devices[device_id]

    def apply_time_decay(self, state: DeviceTrustState, current_time: Optional[float] = None) -> DeviceTrustState:
        """
        Apply continuous exponential time-decay towards baseline uninformative prior:
        alpha(t) = alpha_0 + (alpha(t-1) - alpha_0) * exp(-lambda * delta_t)
        beta(t) = beta_0 + (beta(t-1) - beta_0) * exp(-lambda * delta_t)
        """
        now = current_time if current_time is not None else time.time()
        delta_t = max(0.0, now - state.last_updated)

        if delta_t > 0.1: # Only decay if elapsed time is meaningful
            decay_factor = math.exp(-self.decay_rate_lambda * delta_t)
            state.alpha = self.prior_alpha + (state.alpha - self.prior_alpha) * decay_factor
            state.beta = self.prior_beta + (state.beta - self.prior_beta) * decay_factor
            state.last_updated = now

        return state

    def update_flow_observation(
        self,
        device_id: str,
        attack_confidence: float,
        flow_weight: float = 1.0,
        current_time: Optional[float] = None,
    ) -> DeviceTrustState:
        """
        Update device Bayesian trust based on an evaluated network flow.

        Args:
            device_id: Host identifier (IP / MAC).
            attack_confidence: P(Attack | flow) calibrated probability in [0, 1].
            flow_weight: Transaction impact weight (e.g., volume/rate multiplier).
            current_time: Optional mock time for simulation/testing.

        Returns:
            Updated DeviceTrustState instance.
        """
        now = current_time if current_time is not None else time.time()
        state = self.get_or_create_device(device_id, current_time=now)
        
        # 1. Apply time-decay from last interaction
        self.apply_time_decay(state, current_time=now)

        # 2. Update flow counters
        state.total_flows += 1

        # 3. Bayesian Evidence Accumulation
        if attack_confidence >= self.attack_threshold:
            # Significant attack evidence -> steep penalty
            severity = (attack_confidence - self.attack_threshold) / (1.0 - self.attack_threshold + 1e-6)
            penalty = flow_weight * self.penalty_multiplier * (1.0 + severity)
            state.beta += penalty
            state.total_violations += 1
            logger.debug("Device %s penalized with beta += %.3f (P=%.3f, New Score=%.3f)",
                         device_id, penalty, attack_confidence, state.score)
        elif attack_confidence <= self.benign_threshold:
            # Verified benign flow -> moderate trust gain
            reward = flow_weight * (1.0 - attack_confidence)
            state.alpha += reward
            logger.debug("Device %s rewarded with alpha += %.3f (P=%.3f, New Score=%.3f)",
                         device_id, reward, attack_confidence, state.score)
        else:
            # Ambiguous zone: minor evidence apportioning
            state.alpha += flow_weight * (1.0 - attack_confidence) * 0.5
            state.beta += flow_weight * attack_confidence * 0.5

        state.last_updated = now
        return state

    def get_trust_score(self, device_id: str, current_time: Optional[float] = None) -> float:
        """Get decayed trust score for a device."""
        now = current_time if current_time is not None else time.time()
        state = self.get_or_create_device(device_id, current_time=now)
        self.apply_time_decay(state, current_time=now)
        return state.score

    def get_all_device_states(self, current_time: Optional[float] = None) -> List[DeviceTrustState]:
        """Return snapshot of all registered device trust states."""
        now = current_time if current_time is not None else time.time()
        result = []
        for state in self._devices.values():
            self.apply_time_decay(state, current_time=now)
            result.append(state)
        return result
