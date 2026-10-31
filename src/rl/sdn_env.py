"""
sdn_env.py
==========
Custom Gymnasium Environment for Reinforcement Learning SDN Intrusion Mitigation.

Simulates the closed-loop dynamics between:
1. Calibrated Random Forest IDS attack confidence.
2. Bayesian dynamic device trust scoring and decay.
3. SDN data-plane network telemetry and congestion.
4. Active emerging threat intelligence signatures.
"""

from typing import Dict, Any, Tuple, Optional
import numpy as np
try:
    import gymnasium as gym
    from gymnasium import spaces
except ImportError:
    # Minimal fallback mock for pure Python compatibility if gym not installed
    class gym:
        class Env:
            pass
    class spaces:
        class Box:
            def __init__(self, low, high, shape, dtype=np.float32):
                self.low = low
                self.high = high
                self.shape = shape
                self.dtype = dtype
            def sample(self):
                return np.random.uniform(self.low, self.high, self.shape).astype(self.dtype)
        class Discrete:
            def __init__(self, n):
                self.n = n
            def sample(self):
                return np.random.randint(0, self.n)

from src.rl.reward import MultiObjectiveRewardCalculator, MitigationAction


class SDNIntrusionEnv(gym.Env):
    """
    Gymnasium Environment modeling SDN OpenFlow Mitigation Decision Making.

    Observation Space (12-dim continuous in [0, 1]):
    0: attack_confidence  - Calibrated IDS attack probability P(Attack | x) in [0, 1]
    1: trust_score        - Device Bayesian trust score T in [0, 1]
    2: trust_variance     - Epistemic uncertainty in trust score Var(T) in [0, 0.25]
    3: congestion_index   - Network congestion index C_net in [0, 1]
    4: packet_loss_rate   - Real-time packet loss rate in [0, 1]
    5: flow_rate_norm     - Packets per second (normalized)
    6: byte_rate_norm     - Bytes per second (normalized)
    7: proto_encoded      - Protocol type (TCP=0.33, UDP=0.66, ICMP=1.0)
    8: dst_port_norm      - Target port normalized (port / 65535)
    9: is_emerging_threat - Binary flag (1 if matching newly scraped 0-day CVE signature)
    10: prev_action       - Previous mitigation action normalized (action / 4.0)
    11: burst_factor      - Traffic acceleration index in [0, 1]

    Action Space (Discrete 5):
    0: ALLOW
    1: MONITOR
    2: RATE_LIMIT
    3: REDIRECT
    4: BLOCK
    """

    metadata = {"render_modes": ["human"]}

    def __init__(
        self,
        max_steps: int = 1000,
        attack_ratio: float = 0.30,
        zero_day_ratio: float = 0.05,
        random_seed: int = 42,
        fp_burst_ratio: float = 0.12,
        stealth_ratio: float = 0.15,
    ):
        super().__init__()
        self.max_steps = max_steps
        self.attack_ratio = attack_ratio
        self.zero_day_ratio = zero_day_ratio
        self.random_seed = random_seed
        # Realistic IDS noise: without overlap between benign and malicious
        # confidence, a fixed 0.5 threshold is already perfect and no adaptive
        # policy can be meaningfully evaluated.
        self.fp_burst_ratio = fp_burst_ratio    # benign flows the IDS scores as suspicious
        self.stealth_ratio = stealth_ratio      # attacks the IDS scores as only mildly suspicious
        np.random.seed(random_seed)

        self.reward_calc = MultiObjectiveRewardCalculator()

        # Observation and Action Spaces
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(12,), dtype=np.float32
        )
        self.action_space = spaces.Discrete(5)

        # Internal state tracking
        self.current_step = 0
        self.current_state = np.zeros(12, dtype=np.float32)
        self.current_ground_truth_attack = False
        self.current_is_emerging = False

        # Cumulative Metrics
        self.total_benign_flows = 0
        self.total_attack_flows = 0
        self.tp_count = 0
        self.fp_count = 0
        self.tn_count = 0
        self.fn_count = 0
        self.blocked_benign_count = 0

    def _generate_synthetic_state(self) -> Tuple[np.ndarray, bool, bool]:
        """
        Generate domain-randomized network state with realistic correlations:
        - True attacks correlate with high attack confidence, low trust, high burst.
        - Trusted devices occasionally generate benign bursts without high attack confidence.
        """
        is_attack = bool(np.random.rand() < self.attack_ratio)
        is_emerging = bool(is_attack and (np.random.rand() < self.zero_day_ratio))

        if is_attack:
            # Attack traffic profile
            is_stealth = bool(np.random.rand() < self.stealth_ratio)
            if is_emerging:
                # 0-day: IDS may be slightly less certain (0.50 - 0.85)
                attack_conf = float(np.random.uniform(0.55, 0.90))
            elif is_stealth:
                # Low-and-slow / evasive attack: IDS is unsure
                attack_conf = float(np.random.uniform(0.30, 0.65))
            else:
                attack_conf = float(np.random.uniform(0.70, 0.99))

            # Attacking devices usually have lower trust; stealthy ones less so
            if is_stealth:
                trust_score = float(np.clip(np.random.beta(a=2.5, b=3.0), 0.10, 0.85))
            else:
                trust_score = float(np.clip(np.random.beta(a=1.5, b=4.0), 0.05, 0.80))
            burst_factor = float(np.random.uniform(0.4, 1.0))
            proto_val = float(np.random.choice([0.33, 0.66, 1.0])) # TCP, UDP, ICMP
            flow_rate = float(np.random.uniform(0.3, 1.0))
            byte_rate = float(np.random.uniform(0.2, 0.9))
        else:
            # Benign traffic profile
            if np.random.rand() < self.fp_burst_ratio:
                # Legitimate burst (backup, flash crowd) that the IDS finds suspicious
                attack_conf = float(np.random.uniform(0.45, 0.88))
            else:
                attack_conf = float(np.random.uniform(0.01, 0.35))
            # Benign devices have higher trust
            trust_score = float(np.clip(np.random.beta(a=4.0, b=1.5), 0.30, 0.98))
            burst_factor = float(np.random.uniform(0.0, 0.4))
            proto_val = float(np.random.choice([0.33, 0.66], p=[0.75, 0.25]))
            flow_rate = float(np.random.uniform(0.01, 0.4))
            byte_rate = float(np.random.uniform(0.01, 0.5))

        trust_var = float(trust_score * (1.0 - trust_score) / 5.0) # Approx Beta variance
        congestion = float(np.clip(np.random.uniform(0.05, 0.85), 0.0, 1.0))
        loss_rate = float(np.clip(congestion * np.random.uniform(0.0, 0.08), 0.0, 1.0))
        dst_port = float(np.random.choice([80, 443, 22, 53, 8080, 5000]) / 65535.0)
        prev_act = float(self.current_state[10]) if hasattr(self, "current_state") else 0.0

        state = np.array([
            attack_conf,
            trust_score,
            trust_var,
            congestion,
            loss_rate,
            flow_rate,
            byte_rate,
            proto_val,
            dst_port,
            1.0 if is_emerging else 0.0,
            prev_act,
            burst_factor,
        ], dtype=np.float32)

        return state, is_attack, is_emerging

    def reset(self, seed: Optional[int] = None, options: Optional[Dict[str, Any]] = None):
        """Reset environment to initial state."""
        if seed is not None:
            self.random_seed = seed
            np.random.seed(seed)

        self.current_step = 0
        self.tp_count = 0
        self.fp_count = 0
        self.tn_count = 0
        self.fn_count = 0
        self.total_benign_flows = 0
        self.total_attack_flows = 0
        self.blocked_benign_count = 0

        state, is_attack, is_emerging = self._generate_synthetic_state()
        self.current_state = state
        self.current_ground_truth_attack = is_attack
        self.current_is_emerging = is_emerging

        info = {"initial_state": state.tolist()}
        return state, info

    def step(self, action: int):
        """
        Execute one mitigation decision step.
        """
        action = int(action)
        is_attack = self.current_ground_truth_attack
        is_emerging = self.current_is_emerging
        trust_score = float(self.current_state[1])
        congestion = float(self.current_state[3])

        # Track statistics
        if is_attack:
            self.total_attack_flows += 1
            if action in (MitigationAction.BLOCK, MitigationAction.REDIRECT, MitigationAction.RATE_LIMIT):
                self.tp_count += 1
            else:
                self.fn_count += 1
        else:
            self.total_benign_flows += 1
            if action in (MitigationAction.BLOCK, MitigationAction.REDIRECT):
                self.fp_count += 1
                if action == MitigationAction.BLOCK:
                    self.blocked_benign_count += 1
            else:
                self.tn_count += 1

        # Compute multi-objective reward
        reward, breakdown = self.reward_calc.compute_reward(
            action=action,
            is_attack=is_attack,
            trust_score=trust_score,
            congestion_index=congestion,
            is_emerging_threat=is_emerging,
        )

        self.current_step += 1
        terminated = self.current_step >= self.max_steps
        truncated = False

        # Generate next state
        next_state, next_is_attack, next_is_emerging = self._generate_synthetic_state()
        next_state[10] = float(action / 4.0) # Update prev_action feature
        self.current_state = next_state
        self.current_ground_truth_attack = next_is_attack
        self.current_is_emerging = next_is_emerging

        availability_rate = (
            1.0 - (self.blocked_benign_count / max(1, self.total_benign_flows))
        )
        tpr = self.tp_count / max(1, self.total_attack_flows)
        fpr = self.fp_count / max(1, self.total_benign_flows)

        info = {
            "reward_breakdown": breakdown,
            "availability_rate": availability_rate,
            "tpr": tpr,
            "fpr": fpr,
            "is_attack": is_attack,
            "is_emerging": is_emerging,
            "action_taken": action,
        }

        return next_state, reward, terminated, truncated, info

    def render(self):
        """Render current state status."""
        print(f"Step {self.current_step}/{self.max_steps} | "
              f"P(Atk): {self.current_state[0]:.2f} | Trust: {self.current_state[1]:.2f} | "
              f"Ground Truth: {'ATTACK' if self.current_ground_truth_attack else 'BENIGN'}")
