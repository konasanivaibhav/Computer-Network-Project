"""
ahp.py
======
Analytic Hierarchy Process (AHP) for deriving criterion weights.

The security operator states how much more important one criterion is than
another on Saaty's 1-9 scale. AHP turns that pairwise comparison matrix into a
weight vector (principal eigenvector) and checks that the judgements are
consistent (Consistency Ratio < 0.10).
"""

from dataclasses import dataclass
from typing import Dict, List, Sequence

import numpy as np

# Saaty's Random Consistency Index for matrices of size n
RANDOM_INDEX = {1: 0.0, 2: 0.0, 3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45, 10: 1.49}


@dataclass
class AHPResult:
    criteria: List[str]
    weights: np.ndarray
    lambda_max: float
    consistency_index: float
    consistency_ratio: float

    @property
    def is_consistent(self) -> bool:
        return self.consistency_ratio < 0.10

    def as_dict(self) -> Dict[str, float]:
        return {c: float(w) for c, w in zip(self.criteria, self.weights)}


def ahp_weights(criteria: Sequence[str], pairwise: Sequence[Sequence[float]]) -> AHPResult:
    """
    Compute AHP weights from a reciprocal pairwise comparison matrix.

    Args:
        criteria: Names of the n criteria.
        pairwise: n x n matrix where a[i][j] = importance of i over j (a[j][i] = 1/a[i][j]).
    """
    a = np.asarray(pairwise, dtype=float)
    n = a.shape[0]
    if a.shape != (n, n) or n != len(criteria):
        raise ValueError("Pairwise matrix must be square and match the number of criteria.")
    if np.any(a <= 0):
        raise ValueError("Pairwise judgements must be positive.")
    if not np.allclose(a * a.T, 1.0, atol=1e-6):
        raise ValueError("Pairwise matrix must be reciprocal: a[i][j] * a[j][i] == 1.")

    eigvals, eigvecs = np.linalg.eig(a)
    k = int(np.argmax(eigvals.real))
    lambda_max = float(eigvals[k].real)
    w = np.abs(eigvecs[:, k].real)
    w = w / w.sum()

    ci = (lambda_max - n) / (n - 1) if n > 2 else 0.0
    ri = RANDOM_INDEX.get(n, 1.49)
    cr = ci / ri if ri > 0 else 0.0
    return AHPResult(list(criteria), w, lambda_max, float(ci), float(cr))


# ------------------------------------------------------------------------------
# Default judgements for the SDN mitigation problem
# ------------------------------------------------------------------------------
DEFAULT_CRITERIA = [
    "threat_containment",     # benefit: how much of the expected attack the action stops
    "service_availability",   # benefit: how much expected legitimate service is preserved
    "trust_consistency",      # benefit: how well action severity matches device distrust
    "network_cost",           # cost:    control-plane overhead + congestion impact
    "forensic_value",         # benefit: intelligence gained (mirroring / honeypot)
]

# Row criterion vs column criterion (Saaty 1-9 scale)
DEFAULT_PAIRWISE = [
    #  contain  avail  trust   cost   forensic
    [1.0,     2.0,   3.0,    5.0,   6.0],   # threat_containment
    [1 / 2,   1.0,   2.0,    4.0,   5.0],   # service_availability
    [1 / 3,   1 / 2, 1.0,    3.0,   4.0],   # trust_consistency
    [1 / 5,   1 / 4, 1 / 3,  1.0,   2.0],   # network_cost
    [1 / 6,   1 / 5, 1 / 4,  1 / 2, 1.0],   # forensic_value
]


def default_weights() -> AHPResult:
    return ahp_weights(DEFAULT_CRITERIA, DEFAULT_PAIRWISE)
