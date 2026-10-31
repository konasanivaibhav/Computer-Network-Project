"""
topsis.py
=========
TOPSIS (Technique for Order of Preference by Similarity to Ideal Solution).

Ranks alternatives (here: the five mitigation actions) by their relative
closeness to an ideal best action and distance from an ideal worst action.
"""

from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass
class TOPSISResult:
    closeness: np.ndarray        # C_i in [0, 1] for each alternative (higher is better)
    ranking: np.ndarray          # alternative indices, best first
    ideal_best: np.ndarray
    ideal_worst: np.ndarray
    dist_best: np.ndarray
    dist_worst: np.ndarray


def topsis(
    matrix: np.ndarray,
    weights: Sequence[float],
    benefit: Sequence[bool],
    normalization: str = "vector",
) -> TOPSISResult:
    """
    Args:
        matrix: m x n decision matrix (m alternatives, n criteria), non-negative.
        weights: n criterion weights (normalised internally).
        benefit: n flags; True if larger is better, False for cost criteria.
        normalization: "vector" (classic TOPSIS) or "none" when every criterion is
            already on a common absolute scale such as [0, 1]. Vector normalisation
            rescales each column independently, which discards how large a
            criterion's spread is in absolute terms (e.g. containment differences
            matter little when the attack probability is tiny).
    """
    x = np.asarray(matrix, dtype=float)
    w = np.asarray(weights, dtype=float)
    b = np.asarray(benefit, dtype=bool)
    if x.ndim != 2 or x.shape[1] != w.size or w.size != b.size:
        raise ValueError("Decision matrix, weights and benefit flags have inconsistent shapes.")
    if np.any(x < 0):
        raise ValueError("TOPSIS expects a non-negative decision matrix.")
    w = w / w.sum()

    # 1. Normalisation (guard all-zero columns)
    if normalization == "vector":
        norms = np.sqrt((x ** 2).sum(axis=0))
        norms[norms == 0] = 1.0
        r = x / norms
    elif normalization == "none":
        r = x
    else:
        raise ValueError("normalization must be 'vector' or 'none'")

    # 2. Weighting
    v = r * w

    # 3. Ideal best / worst
    best = np.where(b, v.max(axis=0), v.min(axis=0))
    worst = np.where(b, v.min(axis=0), v.max(axis=0))

    # 4. Separation measures and relative closeness
    d_best = np.sqrt(((v - best) ** 2).sum(axis=1))
    d_worst = np.sqrt(((v - worst) ** 2).sum(axis=1))
    denom = d_best + d_worst
    closeness = np.where(denom > 0, d_worst / np.where(denom > 0, denom, 1.0), 0.5)

    return TOPSISResult(
        closeness=closeness,
        ranking=np.argsort(-closeness, kind="stable"),
        ideal_best=best,
        ideal_worst=worst,
        dist_best=d_best,
        dist_worst=d_worst,
    )
