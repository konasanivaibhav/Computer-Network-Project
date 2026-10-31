"""
retrainer.py
============
Continuous Model Retraining & Shadow Evaluation Engine.

Provides:
- Dual-buffer experience replay (Anchor Core + Emerging Threat Buffer) to prevent
  catastrophic forgetting of baseline network behavior.
- Automated Canary / Shadow validation enforcing TPR >= 95% and FPR <= 5%.
- Atomic thread-safe model replacement for the active SDN controller.
"""

import os
import shutil
import logging
from typing import Dict, Any, Tuple, Optional, List
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src.ids.preprocess import NetworkPreprocessor, generate_synthetic_flow_dataset
from src.ids.train_rf import CalibratedRFModel
from src.ids.evaluator import IDSEvaluator
from src.threat_intel.nlp_parser import ThreatSignature
from src.threat_intel.traffic_gen import SyntheticTrafficGenerator

logger = logging.getLogger(__name__)


class ContinuousModelRetrainer:
    """
    Manages background continuous retraining and A/B canary validation.
    """

    def __init__(
        self,
        active_model_path: str = "models/ids_rf_calibrated.joblib",
        anchor_samples: int = 15000,
        random_seed: int = 42,
    ):
        self.active_model_path = active_model_path
        self.anchor_samples = anchor_samples
        self.random_seed = random_seed
        self.evaluator = IDSEvaluator(target_tpr=0.95, target_fpr=0.05)
        self.traffic_gen = SyntheticTrafficGenerator(random_seed=random_seed)

        # Dual Buffer Storage
        self.anchor_df: Optional[pd.DataFrame] = None
        self.anchor_y: Optional[pd.Series] = None
        self.emerging_signatures: List[ThreatSignature] = []
        self._init_anchor_buffer()

    def _init_anchor_buffer(self) -> None:
        """Initialize fixed anchor memory core of baseline benign and canonical attack flows."""
        logger.info("Initializing Anchor Memory Buffer with %d baseline flows...", self.anchor_samples)
        df, y = generate_synthetic_flow_dataset(
            n_samples=self.anchor_samples, attack_ratio=0.25, random_state=self.random_seed
        )
        self.anchor_df = df
        self.anchor_y = y

    def add_emerging_signature(self, signature: ThreatSignature) -> None:
        """Register a newly extracted threat signature for upcoming retraining cycle."""
        self.emerging_signatures.append(signature)
        logger.info("Registered emerging signature %s (%s) to retrainer queue.",
                    signature.cve_id, signature.attack_type)

    def execute_retraining_cycle(
        self,
        samples_per_signature: int = 2000,
        n_estimators: int = 100,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Execute full continuous retraining and shadow canary validation cycle.

        Steps:
        1. Combine Anchor Memory Buffer with synthesized emerging threat flows.
        2. Fit preprocessor and train candidate shadow model.
        3. Evaluate shadow model on holdout test set (containing old + new attacks).
        4. If shadow passes SLA (TPR >= 95%, FPR <= 5%), atomically swap production model.
        """
        logger.info("=" * 70)
        logger.info("STARTING CONTINUOUS RETRAINING & CANARY VALIDATION CYCLE")
        logger.info("=" * 70)

        # 1. Synthesize emerging threat flows
        emerging_dfs = []
        emerging_ys = []
        for sig in self.emerging_signatures:
            df_sig, y_sig = self.traffic_gen.generate_flow_dataframe(sig, n_samples=samples_per_signature)
            emerging_dfs.append(df_sig)
            emerging_ys.append(y_sig)

        if emerging_dfs:
            combined_emerging_df = pd.concat(emerging_dfs, ignore_index=True)
            combined_emerging_y = pd.concat(emerging_ys, ignore_index=True)
            full_df = pd.concat([self.anchor_df, combined_emerging_df], ignore_index=True)
            full_y = pd.concat([self.anchor_y, combined_emerging_y], ignore_index=True)
        else:
            full_df = self.anchor_df.copy()
            full_y = self.anchor_y.copy()

        # 2. Partition holdout evaluation set
        X_train_df, X_test_df, y_train, y_test = train_test_split(
            full_df, full_y, test_size=0.25, stratify=full_y, random_state=self.random_seed
        )

        # 3. Fit Candidate Shadow Preprocessor and Model
        shadow_preprocessor = NetworkPreprocessor(apply_smote=True, random_state=self.random_seed)
        X_train_proc, y_train_res = shadow_preprocessor.fit_transform_resample(X_train_df, y_train)
        X_test_proc = shadow_preprocessor.transform(X_test_df)

        shadow_model = CalibratedRFModel(n_estimators=n_estimators, random_state=self.random_seed)
        shadow_model.fit(X_train_proc, y_train_res, preprocessor=shadow_preprocessor)

        # 4. Canary Evaluation
        probs = shadow_model.predict_confidence(X_test_proc)
        eval_results = self.evaluator.evaluate(y_test.values, probs, threshold=0.5)
        self.evaluator.print_report(eval_results)

        sla = eval_results["sla_compliance"]
        if sla["overall_sla_pass"]:
            logger.info("CANARY VALIDATION PASSED: Shadow model meets all SLA constraints.")
            # Atomic file swap
            shadow_save_path = self.active_model_path + ".shadow"
            shadow_model.save(shadow_save_path)
            shutil.move(shadow_save_path, self.active_model_path)
            logger.info("HOT-SWAP COMPLETE: Updated active production model at %s", self.active_model_path)
            return True, eval_results
        else:
            logger.warning("CANARY VALIDATION FAILED: Shadow model rejected. Retaining current active model.")
            return False, eval_results
