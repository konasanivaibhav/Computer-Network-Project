"""
train_rf.py
===========
Module for training the Random Forest Intrusion Detection System with Platt Scaling
Probability Calibration (via CalibratedClassifierCV with Sigmoid mapping).

Produces mathematically calibrated attack confidence scores P(Attack | flow) in [0, 1]
optimized for real-time inference within the SDN controller pipeline.
"""

import os
import argparse
from typing import Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
import joblib
import logging

from src.ids.preprocess import NetworkPreprocessor, generate_synthetic_flow_dataset, ALL_CANONICAL_FEATURES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class CalibratedRFModel:
    """
    Calibrated Random Forest IDS Model.
    Combines an ensemble of decision trees with Platt Scaling (sigmoid calibration)
    to output genuine posterior probabilities for the RL agent and trust engine.
    """

    def __init__(
        self,
        n_estimators: int = 150,
        max_depth: int = 18,
        min_samples_split: int = 4,
        min_samples_leaf: int = 2,
        max_features: str = "sqrt",
        class_weight: str = "balanced_subsample",
        calibration_method: str = "sigmoid",
        cv_folds: int = 5,
        n_jobs: int = -1,
        random_state: int = 42,
    ):
        """
        Initialize Calibrated RF Model.
        
        Args:
            n_estimators: Number of trees in the forest.
            max_depth: Maximum tree depth (prevents memorization and keeps inference fast).
            min_samples_split: Minimum samples required to split an internal node.
            min_samples_leaf: Minimum samples required at a leaf node.
            class_weight: Weighting strategy for class imbalance.
            calibration_method: 'sigmoid' (Platt scaling) or 'isotonic'.
            cv_folds: Number of cross-validation folds for calibration.
            n_jobs: CPU cores for parallel training.
            random_state: Deterministic seed.
        """
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.class_weight = class_weight
        self.calibration_method = calibration_method
        self.cv_folds = cv_folds
        self.n_jobs = n_jobs
        self.random_state = random_state

        # Initialize Base Random Forest
        self.base_rf = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            min_samples_split=self.min_samples_split,
            min_samples_leaf=self.min_samples_leaf,
            max_features=self.max_features,
            class_weight=self.class_weight,
            n_jobs=self.n_jobs,
            random_state=self.random_state,
        )

        # Calibrated Wrapper
        self.calibrated_clf = CalibratedClassifierCV(
            estimator=self.base_rf,
            method=self.calibration_method,
            cv=self.cv_folds,
            n_jobs=self.n_jobs,
        )
        self.is_fitted = False
        self.preprocessor: Optional[NetworkPreprocessor] = None

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        preprocessor: Optional[NetworkPreprocessor] = None,
    ) -> "CalibratedRFModel":
        """
        Fit the base Random Forest and calibrate its posterior probabilities.
        
        Args:
            X_train: Scaled feature matrix of shape (n_samples, n_features).
            y_train: Binary labels (0 = Benign, 1 = Malicious).
            preprocessor: Associated NetworkPreprocessor instance (for bundled saving).
        """
        logger.info("Training Calibrated Random Forest (Trees: %d, Max Depth: %d, Folds: %d)...",
                    self.n_estimators, self.max_depth, self.cv_folds)
        
        self.calibrated_clf.fit(X_train, y_train)
        self.is_fitted = True
        self.preprocessor = preprocessor
        logger.info("Calibrated Random Forest training completed successfully.")
        return self

    def predict_confidence(self, X: np.ndarray) -> np.ndarray:
        """
        Compute calibrated attack confidence score P(Attack=1 | X).
        
        Args:
            X: Scaled feature matrix of shape (n_samples, n_features) or (n_features,).
            
        Returns:
            1D array of calibrated attack confidence scores in range [0.0, 1.0].
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predict_confidence().")

        if X.ndim == 1:
            X = X.reshape(1, -1)

        # Output column 1 corresponds to probability of class 1 (Attack)
        probabilities = self.calibrated_clf.predict_proba(X)
        return probabilities[:, 1]

    def predict_label(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """
        Predict binary attack classification based on confidence threshold.
        """
        confidences = self.predict_confidence(X)
        return (confidences >= threshold).astype(int)

    def get_feature_importances(self) -> Dict[str, float]:
        """
        Extract averaged feature importances across all calibration folds.
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before extracting feature importances.")

        # Extract importances from calibrated base estimators
        importances_list = []
        for cal_clf in self.calibrated_clf.calibrated_classifiers_:
            base_est = cal_clf.estimator
            if hasattr(base_est, "feature_importances_"):
                importances_list.append(base_est.feature_importances_)

        if not importances_list:
            return {}

        avg_importances = np.mean(importances_list, axis=0)
        feature_names = ALL_CANONICAL_FEATURES
        
        if len(feature_names) != len(avg_importances):
            feature_names = [f"feature_{i}" for i in range(len(avg_importances))]

        importance_dict = {
            name: float(imp) for name, imp in zip(feature_names, avg_importances)
        }
        return dict(sorted(importance_dict.items(), key=lambda item: item[1], reverse=True))

    def save(self, filepath: str) -> None:
        """
        Bundle and save calibrated model and preprocessor to disk.
        """
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        bundle = {
            "model": self,
            "preprocessor": self.preprocessor,
        }
        joblib.dump(bundle, filepath)
        logger.info("Saved Calibrated RF pipeline bundle to %s", filepath)

    @classmethod
    def load(cls, filepath: str) -> "CalibratedRFModel":
        """
        Load calibrated model and bundled preprocessor from disk.
        """
        bundle = joblib.load(filepath)
        if isinstance(bundle, dict) and "model" in bundle:
            model = bundle["model"]
            model.preprocessor = bundle.get("preprocessor")
            logger.info("Loaded Calibrated RF pipeline bundle from %s", filepath)
            return model
        elif isinstance(bundle, CalibratedRFModel):
            logger.info("Loaded Calibrated RF model from %s", filepath)
            return bundle
        else:
            raise TypeError(f"Invalid model artifact structure in {filepath}")


def train_ids_pipeline(
    data_path: Optional[str] = None,
    use_synthetic: bool = True,
    n_samples: int = 20000,
    n_estimators: int = 150,
    save_path: str = "models/ids_rf_calibrated.joblib",
    test_size: float = 0.25,
    random_state: int = 42,
) -> Tuple[CalibratedRFModel, NetworkPreprocessor, np.ndarray, np.ndarray]:
    """
    End-to-end IDS training pipeline execution:
    1. Ingest real/synthetic network flow dataset.
    2. Split into train & test sets.
    3. Fit NetworkPreprocessor with RobustScaler and SMOTE-TomekLinks.
    4. Fit CalibratedRFModel with Platt Scaling.
    5. Persist the pipeline bundle.
    """
    logger.info("=" * 70)
    logger.info("STARTING CALIBRATED RANDOM FOREST IDS TRAINING PIPELINE")
    logger.info("=" * 70)

    # 1. Dataset Ingestion
    if use_synthetic or data_path is None or not os.path.exists(data_path):
        logger.info("Generating %d synthetic network flow samples (CICIDS/UNSW distribution)...", n_samples)
        df, y = generate_synthetic_flow_dataset(n_samples=n_samples, attack_ratio=0.25, random_state=random_state)
    else:
        logger.info("Loading network dataset from %s...", data_path)
        df = pd.read_csv(data_path)
        y = df["label"] if "label" in df.columns else df["Label"]

    # 2. Partition Train / Test
    X_train_df, X_test_df, y_train, y_test = train_test_split(
        df, y, test_size=test_size, stratify=y, random_state=random_state
    )
    logger.info("Dataset partitioned: Train size = %d, Test size = %d", len(X_train_df), len(X_test_df))

    # 3. Preprocess & Scale
    preprocessor = NetworkPreprocessor(apply_smote=True, random_state=random_state)
    X_train_proc, y_train_res = preprocessor.fit_transform_resample(X_train_df, y_train)
    X_test_proc = preprocessor.transform(X_test_df)

    # 4. Train Calibrated Random Forest
    model = CalibratedRFModel(n_estimators=n_estimators, random_state=random_state)
    model.fit(X_train_proc, y_train_res, preprocessor=preprocessor)

    # 5. Persist Pipeline Artifact
    model.save(save_path)
    return model, preprocessor, X_test_proc, y_test.values


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Calibrated Random Forest IDS")
    parser.add_argument("--data_path", type=str, default=None, help="Path to raw dataset CSV")
    parser.add_argument("--synthetic", action="store_true", default=True, help="Use synthetic benchmark dataset")
    parser.add_argument("--n_samples", type=int, default=20000, help="Number of synthetic samples")
    parser.add_argument("--n_estimators", type=int, default=150, help="Number of trees in Random Forest")
    parser.add_argument("--save_path", type=str, default="models/ids_rf_calibrated.joblib", help="Output path")
    args = parser.parse_args()

    train_ids_pipeline(
        data_path=args.data_path,
        use_synthetic=args.synthetic,
        n_samples=args.n_samples,
        n_estimators=args.n_estimators,
        save_path=args.save_path,
    )
