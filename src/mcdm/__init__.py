"""
mcdm subpackage: Multi-Criteria Decision Making (AHP weighting + TOPSIS ranking)
and the context-aware adaptive decision engine that fuses it with the PPO policy.
"""
from src.mcdm.ahp import ahp_weights, default_weights, AHPResult, DEFAULT_CRITERIA
from src.mcdm.topsis import topsis, TOPSISResult
from src.mcdm.decision_engine import AdaptiveDecisionEngine, DecisionContext, Decision, build_decision_matrix

__all__ = [
    "ahp_weights", "default_weights", "AHPResult", "DEFAULT_CRITERIA",
    "topsis", "TOPSISResult",
    "AdaptiveDecisionEngine", "DecisionContext", "Decision", "build_decision_matrix",
]
