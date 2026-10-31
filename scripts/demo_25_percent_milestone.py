"""
demo_25_percent_milestone.py
============================
25% milestone demonstration: Calibrated Random Forest IDS + Bayesian Device Trust.

1. Train the calibrated RF IDS on the 28-feature schema and report real metrics.
2. Classify sample flows.
3. Track trust for four device profiles and persist them to SQLite.
"""

import logging
import os
import sys

import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)
logging.disable(logging.INFO)

from src.ids.train_rf import train_ids_pipeline  # noqa: E402
from src.ids.evaluator import IDSEvaluator  # noqa: E402
from src.trust.trust_engine import BayesianDynamicTrustEngine  # noqa: E402
from src.trust.db_manager import TrustDBManager  # noqa: E402


def banner(t):
    print("\n" + "=" * 78 + f"\n {t}\n" + "=" * 78)


def main():
    banner("Phase 1: Calibrated Random Forest IDS (28 features, Platt scaling)")
    model, _, X_test, y_test = train_ids_pipeline(
        use_synthetic=True, n_samples=8000, n_estimators=100,
        save_path="models/ids_rf_calibrated.joblib", random_state=42)
    probs = model.predict_confidence(X_test)
    ev = IDSEvaluator(target_tpr=0.95, target_fpr=0.05)
    logging.disable(logging.NOTSET)          # the evaluator reports through logging
    ev.print_report(ev.evaluate(y_test, probs))
    logging.disable(logging.INFO)

    print("\nSample classifications:")
    for i in np.random.default_rng(0).choice(len(y_test), 6, replace=False):
        label = "MALICIOUS" if probs[i] >= 0.5 else "BENIGN"
        print(f"  flow #{i:<5} P(attack)={probs[i]:.3f} -> {label:<9} (ground truth: {'attack' if y_test[i] else 'benign'})")

    banner("Phase 2: Bayesian Dynamic Device Trust (Beta distribution + time decay)")
    engine = BayesianDynamicTrustEngine(decay_rate_lambda=0.005)
    db = TrustDBManager(db_path="data/threat_db.sqlite")
    profiles = [
        ("10.0.0.1", "Trusted enterprise workstation", 20, 0.04, 0),
        ("10.0.0.2", "Bursting web application server", 25, 0.35, 0),
        ("10.0.0.4", "Compromised attacker node", 15, 0.95, 0),
        ("10.0.0.5", "Inactive edge node", 5, 0.05, 1800),
    ]
    rng = np.random.default_rng(42)
    now = 1000.0
    print(f"{'Device':<10} {'Profile':<34} {'alpha':>7} {'beta':>7} {'Trust':>7} {'Var':>8}  Tier")
    for ip, name, n, mean_p, idle in profiles:
        for _ in range(n):
            now += 0.5
            engine.update_flow_observation(ip, float(np.clip(rng.normal(mean_p, 0.05), 0.01, 0.99)), current_time=now)
        now += idle
        st = engine.get_or_create_device(ip, current_time=now)
        engine.apply_time_decay(st, current_time=now)
        db.save_device_state(st)
        print(f"{ip:<10} {name:<34} {st.alpha:7.2f} {st.beta:7.2f} {st.score:7.3f} {st.variance:8.4f}  {st.category}")
    print("\nTrust states persisted to data/threat_db.sqlite")


if __name__ == "__main__":
    main()
