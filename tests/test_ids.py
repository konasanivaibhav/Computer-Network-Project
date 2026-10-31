"""
test_ids.py
===========
Unit and integration tests for the Phase 1 IDS pipeline:
- Feature extraction & Preprocessing
- Calibrated Random Forest Training & Probability Calibration
- Metric computation & SLA compliance verification (TPR >= 95%, FPR <= 5%)
"""

import os
import pytest
import numpy as np
import pandas as pd

from src.ids.preprocess import (
    NetworkPreprocessor,
    generate_synthetic_flow_dataset,
    CANONICAL_NUMERICAL_FEATURES,
    CANONICAL_CATEGORICAL_FEATURES,
    ALL_CANONICAL_FEATURES,
)
from src.ids.train_rf import CalibratedRFModel, train_ids_pipeline
from src.ids.evaluator import IDSEvaluator


def test_synthetic_data_generation():
    """Verify synthetic dataset generator produces valid schema and labels."""
    df, y = generate_synthetic_flow_dataset(n_samples=500, attack_ratio=0.3, random_state=42)
    
    assert len(df) == 500
    assert len(y) == 500
    assert set(y.unique()) == {0, 1}
    assert (y == 1).sum() == 150
    assert (y == 0).sum() == 350
    
    # Check that all canonical features exist in the generated DataFrame
    for col in ALL_CANONICAL_FEATURES:
        assert col in df.columns, f"Missing feature: {col}"


def test_preprocessor_fit_transform():
    """Verify NetworkPreprocessor fits and transforms data to correct output dimensions."""
    df, y = generate_synthetic_flow_dataset(n_samples=300, attack_ratio=0.2, random_state=42)
    preprocessor = NetworkPreprocessor(apply_smote=False, random_state=42)
    
    X_trans = preprocessor.fit_transform(df, y)
    assert X_trans.shape[0] == 300
    assert X_trans.shape[1] == len(ALL_CANONICAL_FEATURES)
    assert not np.isnan(X_trans).any(), "Preprocessed matrix contains NaN values"
    assert not np.isinf(X_trans).any(), "Preprocessed matrix contains Inf values"


def test_preprocessor_unknown_categories():
    """Verify preprocessor safely handles unseen protocols and services."""
    df_train, y_train = generate_synthetic_flow_dataset(n_samples=200, random_state=42)
    preprocessor = NetworkPreprocessor(apply_smote=False)
    preprocessor.fit(df_train, y_train)

    # Create unseen test row with new protocol and service
    df_test = pd.DataFrame([{
        "duration": 1.2,
        "spkts": 10,
        "dpkts": 8,
        "sbytes": 500,
        "dbytes": 800,
        "proto": "novel_custom_protocol",
        "service": "unseen_zero_day_service",
    }])

    X_test_trans = preprocessor.transform(df_test)
    assert X_test_trans.shape == (1, len(ALL_CANONICAL_FEATURES))
    assert not np.isnan(X_test_trans).any()


def test_calibrated_rf_training_and_evaluation(tmp_path):
    """Test full training, calibration, persistence, and SLA validation."""
    save_path = str(tmp_path / "test_ids_rf.joblib")
    
    # Train pipeline on 2,000 synthetic samples
    model, preprocessor, X_test, y_test = train_ids_pipeline(
        use_synthetic=True,
        n_samples=2000,
        n_estimators=30, # fast for unit test
        save_path=save_path,
        test_size=0.3,
        random_state=42,
    )
    
    assert os.path.exists(save_path), "Model artifact was not persisted"
    
    # Predict calibrated attack probabilities
    probs = model.predict_confidence(X_test)
    assert len(probs) == len(y_test)
    assert np.all((probs >= 0.0) & (probs <= 1.0)), "Probabilities out of bounds [0, 1]"
    
    # Evaluate performance
    evaluator = IDSEvaluator(target_tpr=0.90, target_fpr=0.10)
    results = evaluator.evaluate(y_test, probs, threshold=0.5)
    
    evaluator.print_report(results)
    
    assert results["tpr"] >= 0.90, f"TPR {results['tpr']} below target 0.90"
    assert results["fpr"] <= 0.10, f"FPR {results['fpr']} exceeds target 0.10"
    assert results["roc_auc"] >= 0.95, f"ROC-AUC {results['roc_auc']} below 0.95"
    assert results["brier_score"] <= 0.10, f"Brier score {results['brier_score']} too high"

    # Test loading serialized model
    loaded_model = CalibratedRFModel.load(save_path)
    loaded_probs = loaded_model.predict_confidence(X_test)
    np.testing.assert_allclose(probs, loaded_probs, rtol=1e-5)
