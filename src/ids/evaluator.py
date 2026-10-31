"""
evaluator.py
============
Comprehensive Evaluation Suite for the Calibrated Random Forest IDS.

Computes:
- True Positive Rate (TPR / Sensitivity / Recall)
- False Positive Rate (FPR / Fall-out)
- Specificity, Precision, Accuracy, F1-Score
- Area Under ROC Curve (ROC-AUC) and PR-AUC
- Brier Score Loss & Expected Calibration Error (ECE) for probability reliability
- Detailed Confusion Matrix & Formatted Performance Reports
"""

from typing import Dict, Any, Tuple, Optional
import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc,
    brier_score_loss,
    classification_report,
)
from sklearn.calibration import calibration_curve
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class IDSEvaluator:
    """
    Evaluation engine for Network Intrusion Detection models.
    Validates compliance against target SLA requirements (TPR >= 95%, FPR <= 5%).
    """

    def __init__(self, target_tpr: float = 0.95, target_fpr: float = 0.05):
        """
        Initialize evaluator with target performance bounds.
        
        Args:
            target_tpr: Minimum acceptable True Positive Rate (default: 0.95).
            target_fpr: Maximum acceptable False Positive Rate (default: 0.05).
        """
        self.target_tpr = target_tpr
        self.target_fpr = target_fpr

    @staticmethod
    def compute_expected_calibration_error(
        y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10
    ) -> float:
        """
        Compute Expected Calibration Error (ECE) to quantify probability calibration quality.
        
        ECE = sum_b (|B_b| / N) * |acc(B_b) - conf(B_b)|
        """
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        ece = 0.0
        n_samples = len(y_true)

        for i in range(n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]

            if i == n_bins - 1:
                in_bin = (y_prob >= bin_lower) & (y_prob <= bin_upper)
            else:
                in_bin = (y_prob >= bin_lower) & (y_prob < bin_upper)

            prop_in_bin = np.mean(in_bin)
            if prop_in_bin > 0:
                accuracy_in_bin = np.mean(y_true[in_bin])
                avg_confidence_in_bin = np.mean(y_prob[in_bin])
                ece += (np.sum(in_bin) / n_samples) * np.abs(accuracy_in_bin - avg_confidence_in_bin)

        return float(ece)

    def evaluate(
        self, y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5
    ) -> Dict[str, Any]:
        """
        Compute full suite of classification and calibration metrics.
        
        Args:
            y_true: Binary ground truth labels (0 = Benign, 1 = Attack).
            y_prob: Predicted calibrated attack probabilities in range [0, 1].
            threshold: Classification decision boundary (default: 0.5).
            
        Returns:
            Dictionary containing metrics, confusion matrix, and SLA compliance status.
        """
        y_true = np.asarray(y_true, dtype=int)
        y_prob = np.asarray(y_prob, dtype=float)
        y_pred = (y_prob >= threshold).astype(int)

        # 1. Confusion Matrix Elements
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        # 2. Rate Calculations
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0 # Sensitivity / Recall
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0 # Fall-out
        tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0 # Specificity
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0
        f1_score = (2 * precision * tpr) / (precision + tpr) if (precision + tpr) > 0 else 0.0

        # 3. Curve Metrics
        roc_auc = float(roc_auc_score(y_true, y_prob))
        precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_prob)
        pr_auc = float(auc(recall_curve, precision_curve))

        # 4. Calibration Metrics
        brier_score = float(brier_score_loss(y_true, y_prob))
        ece = self.compute_expected_calibration_error(y_true, y_prob, n_bins=10)

        # 5. Check SLA Compliance
        meets_tpr = tpr >= self.target_tpr
        meets_fpr = fpr <= self.target_fpr
        meets_sla = meets_tpr and meets_fpr

        results = {
            "tpr": float(tpr),
            "fpr": float(fpr),
            "specificity": float(tnr),
            "precision": float(precision),
            "accuracy": float(accuracy),
            "f1_score": float(f1_score),
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "brier_score": brier_score,
            "ece": ece,
            "confusion_matrix": {
                "tp": int(tp),
                "fp": int(fp),
                "tn": int(tn),
                "fn": int(fn),
            },
            "sla_compliance": {
                "meets_tpr_target": bool(meets_tpr),
                "meets_fpr_target": bool(meets_fpr),
                "overall_sla_pass": bool(meets_sla),
                "target_tpr": self.target_tpr,
                "target_fpr": self.target_fpr,
            },
        }

        return results

    def print_report(self, results: Dict[str, Any]) -> None:
        """
        Print formatted performance audit report.
        """
        cm = results["confusion_matrix"]
        sla = results["sla_compliance"]

        logger.info("=" * 70)
        logger.info("IDS CLASSIFICATION & CALIBRATION EVALUATION REPORT")
        logger.info("=" * 70)
        logger.info("  • True Positive Rate (TPR / Recall) : %6.2f%% (Target: >= %4.1f%%) [%s]",
                    results["tpr"] * 100, sla["target_tpr"] * 100, "PASS" if sla["meets_tpr_target"] else "FAIL")
        logger.info("  • False Positive Rate (FPR)          : %6.2f%% (Target: <= %4.1f%%) [%s]",
                    results["fpr"] * 100, sla["target_fpr"] * 100, "PASS" if sla["meets_fpr_target"] else "FAIL")
        logger.info("  • Precision                          : %6.2f%%", results["precision"] * 100)
        logger.info("  • Specificity (TNR)                  : %6.2f%%", results["specificity"] * 100)
        logger.info("  • Overall Accuracy                   : %6.2f%%", results["accuracy"] * 100)
        logger.info("  • F1-Score                           : %6.4f", results["f1_score"])
        logger.info("  • ROC-AUC Score                      : %6.4f", results["roc_auc"])
        logger.info("  • PR-AUC Score                       : %6.4f", results["pr_auc"])
        logger.info("  • Brier Score Loss (Calibration)     : %6.4f", results["brier_score"])
        logger.info("  • Expected Calibration Error (ECE)   : %6.4f", results["ece"])
        logger.info("-" * 70)
        logger.info("Confusion Matrix: [TP: %d, FP: %d, TN: %d, FN: %d]",
                    cm["tp"], cm["fp"], cm["tn"], cm["fn"])
        logger.info("Overall SLA Status: %s", "PASSED" if sla["overall_sla_pass"] else "FAILED")
        logger.info("=" * 70)
