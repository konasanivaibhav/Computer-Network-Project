"""
decision_engine.py
==================
Context-Aware Adaptive Decision Engine (PPO + AHP-TOPSIS + safety guardrails).

For every flow the engine:
  1. Builds a 5 x 5 decision matrix: the five mitigation actions scored against
     five criteria, using the live state (attack probability, trust, context).
  2. Weights the criteria with AHP and ranks the actions with TOPSIS.
  3. Fuses the TOPSIS closeness with the PPO policy's action probabilities.
  4. Applies operator guardrails (optional zero-day forensic redirect, hard
     block, trusted hosts, optional monitoring of uncertain devices and
     ambiguous scores, allow-list, protected assets).

The result carries every intermediate number, so each decision is explainable.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import numpy as np

from src.mcdm.ahp import AHPResult, default_weights
from src.mcdm.topsis import topsis
from src.rl.reward import MitigationAction

ACTIONS = list(MitigationAction)

# Per-action characteristics (index = MitigationAction value)
CONTAINMENT = np.array([0.00, 0.15, 0.65, 0.90, 1.00])   # share of attack impact stopped
SERVICE = np.array([1.00, 0.97, 0.60, 0.10, 0.00])        # share of legitimate service kept
SEVERITY = np.array([0.00, 0.25, 0.50, 0.75, 1.00])       # how restrictive the action is
OVERHEAD = np.array([0.02, 0.30, 0.12, 0.35, 0.05])       # controller / mirroring / rewrite cost
PASSTHROUGH = np.array([1.00, 1.00, 0.35, 0.00, 0.00])    # share of the flow's load still forwarded
FORENSIC = np.array([0.00, 0.60, 0.20, 1.00, 0.05])       # intelligence gained about the source

BENEFIT = [True, True, True, False, True]
EPS = 1e-3


@dataclass
class DecisionContext:
    attack_confidence: float
    trust_score: float
    trust_variance: float = 0.02
    congestion_index: float = 0.1
    packet_loss_rate: float = 0.0
    flow_rate_norm: float = 0.1
    byte_rate_norm: float = 0.1
    proto_encoded: float = 0.33
    dst_port_norm: float = 0.0
    is_emerging_threat: bool = False
    prev_action: int = 0
    burst_factor: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""


@dataclass
class Decision:
    action: MitigationAction
    proposed_by_fusion: MitigationAction
    guardrail: Optional[str]
    final_scores: List[float]
    topsis_closeness: List[float]
    ppo_probabilities: List[float]
    decision_matrix: List[List[float]]
    criteria_weights: Dict[str, float]
    consistency_ratio: float
    fusion_lambda: float

    def to_dict(self) -> Dict:
        return {
            "action": self.action.name,
            "proposed": self.proposed_by_fusion.name,
            "guardrail": self.guardrail,
            "final_scores": [round(x, 4) for x in self.final_scores],
            "topsis": [round(x, 4) for x in self.topsis_closeness],
            "ppo": [round(x, 4) for x in self.ppo_probabilities],
        }


def build_decision_matrix(ctx: DecisionContext) -> np.ndarray:
    """Score every action against every criterion for this particular flow."""
    p = float(np.clip(ctx.attack_confidence, 0.0, 1.0))
    t = float(np.clip(ctx.trust_score, 0.0, 1.0))
    c = float(np.clip(ctx.congestion_index, 0.0, 1.0))
    # Risk blends the IDS evidence with the device's history
    risk = float(np.clip(0.65 * p + 0.35 * (1.0 - t), 0.0, 1.0))
    emerging = 1.0 if ctx.is_emerging_threat else 0.0

    containment = risk * CONTAINMENT
    availability = (1.0 - risk) * SERVICE + risk * 0.05
    trust_fit = 1.0 - np.abs(SEVERITY - risk)
    net_cost = OVERHEAD + c * risk * PASSTHROUGH + c * 0.1 * (1.0 - risk) * (1.0 - PASSTHROUGH)
    forensic = risk * FORENSIC * (1.0 + emerging)

    m = np.column_stack([containment, availability, trust_fit, net_cost, forensic])
    return m + EPS  # keep strictly positive for normalisation


class AdaptiveDecisionEngine:
    """Hybrid PPO + AHP-TOPSIS decision engine with guardrails."""

    def __init__(
        self,
        policy_engine=None,
        ahp: Optional[AHPResult] = None,
        fusion_lambda: float = 0.4,
        hard_block_confidence: float = 0.95,
        hard_block_trust: float = 0.20,
        allow_list: Optional[Set[str]] = None,
        protected_assets: Optional[Set[str]] = None,
        trusted_host_threshold: float = 0.80,
        zero_day_forensics: bool = False,
        monitor_uncertain: bool = False,
        monitor_variance: float = 0.02,
        monitor_band: tuple = (0.35, 0.65),
    ):
        """
        Args:
            policy_engine: RLPolicyEngine providing action probabilities (optional).
            ahp: Criterion weights; defaults to the built-in AHP judgements.
            fusion_lambda: Weight of the PPO policy in the final score (0 = pure TOPSIS).
        """
        self.policy_engine = policy_engine
        self.ahp = ahp or default_weights()
        self.fusion_lambda = float(fusion_lambda) if policy_engine is not None else 0.0
        self.hard_block_confidence = hard_block_confidence
        self.hard_block_trust = hard_block_trust
        self.allow_list = set(allow_list or [])
        self.protected_assets = set(protected_assets or [])
        self.trusted_host_threshold = trusted_host_threshold
        self.zero_day_forensics = zero_day_forensics
        # Monitoring: watch what cannot be judged yet instead of simply allowing it
        self.monitor_uncertain = monitor_uncertain
        self.monitor_variance = monitor_variance
        self.monitor_band = monitor_band

    def _ppo_probabilities(self, ctx: DecisionContext) -> np.ndarray:
        if self.policy_engine is None:
            return np.full(len(ACTIONS), 1.0 / len(ACTIONS))
        return np.asarray(self.policy_engine.action_probabilities(
            attack_confidence=ctx.attack_confidence,
            trust_score=ctx.trust_score,
            trust_variance=ctx.trust_variance,
            congestion_index=ctx.congestion_index,
            loss_rate=ctx.packet_loss_rate,
            flow_rate_norm=ctx.flow_rate_norm,
            byte_rate_norm=ctx.byte_rate_norm,
            proto_encoded=ctx.proto_encoded,
            dst_port_norm=ctx.dst_port_norm,
            is_emerging_threat=ctx.is_emerging_threat,
            prev_action=ctx.prev_action,
            burst_factor=ctx.burst_factor,
        ), dtype=float)

    def decide(self, ctx: DecisionContext) -> Decision:
        matrix = build_decision_matrix(ctx)
        ranked = topsis(matrix, self.ahp.weights, BENEFIT, normalization="none")
        ppo = self._ppo_probabilities(ctx)

        lam = self.fusion_lambda
        final = (1.0 - lam) * ranked.closeness + lam * ppo
        proposed = MitigationAction(int(np.argmax(final)))
        action, guardrail = self._apply_guardrails(proposed, ctx)

        return Decision(
            action=action,
            proposed_by_fusion=proposed,
            guardrail=guardrail,
            final_scores=final.tolist(),
            topsis_closeness=ranked.closeness.tolist(),
            ppo_probabilities=ppo.tolist(),
            decision_matrix=matrix.round(4).tolist(),
            criteria_weights=self.ahp.as_dict(),
            consistency_ratio=self.ahp.consistency_ratio,
            fusion_lambda=lam,
        )

    def _apply_guardrails(self, proposed: MitigationAction, ctx: DecisionContext):
        p, t = ctx.attack_confidence, ctx.trust_score
        if ctx.src_ip and ctx.src_ip in self.allow_list:
            if proposed == MitigationAction.BLOCK:
                return MitigationAction.RATE_LIMIT, "allow-list: never auto-block infrastructure"
            return proposed, None
        if self.zero_day_forensics and ctx.is_emerging_threat and p >= 0.5 and proposed != MitigationAction.REDIRECT:
            # A flow matching a newly registered CVE is contained in the honeypot rather than
            # dropped: the server is still protected and the exploit payload is captured for
            # threat intelligence and IDS retraining.
            return MitigationAction.REDIRECT, "zero-day: redirect to honeypot for forensic capture"
        if p >= self.hard_block_confidence and t < self.hard_block_trust and proposed != MitigationAction.BLOCK:
            return MitigationAction.BLOCK, "hard block: very high confidence and untrusted source"
        if t >= self.trusted_host_threshold and proposed == MitigationAction.BLOCK and not ctx.is_emerging_threat:
            return MitigationAction.RATE_LIMIT, "trusted host: throttle instead of hard block"
        if self.monitor_uncertain and proposed == MitigationAction.ALLOW:
            if ctx.trust_variance > self.monitor_variance:
                return MitigationAction.MONITOR, "monitor: new or long-idle device, too little history to trust yet"
            if self.monitor_band[0] <= p < self.monitor_band[1]:
                return MitigationAction.MONITOR, "monitor: ambiguous IDS score"
        if ctx.dst_ip and ctx.dst_ip in self.protected_assets and p >= 0.5 and proposed == MitigationAction.ALLOW:
            return MitigationAction.MONITOR, "protected asset: suspicious flow is at least monitored"
        return proposed, None
