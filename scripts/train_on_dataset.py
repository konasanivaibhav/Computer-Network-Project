"""
train_on_dataset.py
===================
Train and evaluate the calibrated Random Forest IDS on a real public dataset
(UNSW-NB15 or CICIDS2017), mapped onto the project's 28-feature schema.

Examples
--------
UNSW-NB15 with its official train/test split:
    python scripts/train_on_dataset.py ^
        --train data/raw/UNSW_NB15_training-set.csv ^
        --test  data/raw/UNSW_NB15_testing-set.csv --name unsw_nb15

CICIDS2017, all eight day files in one folder, sampled to 300k rows, 25 % held out:
    python scripts/train_on_dataset.py --train data/raw/CICIDS2017 --max_rows 300000 --name cicids2017

Add --activate to make the new model the one used by the Ryu controller and the
simulation (it is copied to models/ids_rf_calibrated.joblib).

Outputs
-------
models/ids_rf_<name>.joblib          trained model + fitted preprocessor
results/ids_<name>_report.json       metrics, per-attack-type detection, feature importances
"""

import argparse
import json
import logging
import os
import shutil
import sys
import time

import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

from sklearn.model_selection import train_test_split  # noqa: E402

from src.ids.datasets import load_dataset, summarize, stratified_sample  # noqa: E402
from src.ids.preprocess import NetworkPreprocessor, ALL_CANONICAL_FEATURES  # noqa: E402
from src.ids.train_rf import CalibratedRFModel  # noqa: E402
from src.ids.evaluator import IDSEvaluator  # noqa: E402


def per_category_detection(cat: pd.Series, y_true: np.ndarray, y_pred: np.ndarray) -> pd.DataFrame:
    rows = []
    for c, idx in cat.groupby(cat).groups.items():
        idx = np.asarray(idx)
        is_attack = int(y_true[idx].max()) == 1
        hit = (y_pred[idx] == 1) if is_attack else (y_pred[idx] == 0)
        rows.append({"category": c, "type": "attack" if is_attack else "benign",
                     "flows": int(len(idx)), "correct_pct": round(float(hit.mean()) * 100, 2)})
    return pd.DataFrame(rows).sort_values(["type", "flows"], ascending=[True, False])


def main():
    ap = argparse.ArgumentParser(description="Train the calibrated RF IDS on UNSW-NB15 / CICIDS2017")
    ap.add_argument("--train", required=True, help="CSV file, folder of CSVs, or glob")
    ap.add_argument("--test", default=None, help="Separate test CSV(s); if omitted, a stratified split is used")
    ap.add_argument("--name", default="dataset", help="Short name used in output file names")
    ap.add_argument("--format", default="auto", choices=["auto", "unsw_nb15", "cicids2017", "canonical"])
    ap.add_argument("--max_rows", type=int, default=300_000, help="Stratified sample size for training (0 = all)")
    ap.add_argument("--max_test_rows", type=int, default=200_000, help="Cap on test rows (0 = all)")
    ap.add_argument("--rows_per_file", type=int, default=None, help="Read at most this many rows per CSV")
    ap.add_argument("--test_size", type=float, default=0.25)
    ap.add_argument("--n_estimators", type=int, default=100)
    ap.add_argument("--cv_folds", type=int, default=3, help="Folds for Platt calibration")
    ap.add_argument("--smote", action="store_true", help="Apply SMOTE-Tomek (slow on large data)")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--activate", action="store_true", help="Use this model in the controller and simulation")
    args = ap.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    t0 = time.time()
    print("=" * 78)
    print(f" TRAINING THE CALIBRATED RF IDS ON: {args.name}")
    print("=" * 78)

    # 1. Load
    max_rows = args.max_rows or None
    if args.test:
        X_tr, y_tr, c_tr = load_dataset(args.train, args.format, max_rows, args.rows_per_file, args.seed)
        X_te, y_te, c_te = load_dataset(args.test, args.format, None, args.rows_per_file, args.seed)
    else:
        X_all, y_all, c_all = load_dataset(args.train, args.format, None, args.rows_per_file, args.seed)
        X_tr, X_te, y_tr, y_te, c_tr, c_te = train_test_split(
            X_all, y_all, c_all, test_size=args.test_size, stratify=c_all, random_state=args.seed)
        X_tr, y_tr, c_tr = [d.reset_index(drop=True) for d in (X_tr, y_tr, c_tr)]
        X_te, y_te, c_te = [d.reset_index(drop=True) for d in (X_te, y_te, c_te)]
        if max_rows and len(X_tr) > max_rows:
            X_tr, y_tr, c_tr = stratified_sample(X_tr, y_tr, c_tr, max_rows, args.seed)
    if args.max_test_rows and len(X_te) > args.max_test_rows:
        X_te, y_te, c_te = stratified_sample(X_te, y_te, c_te, args.max_test_rows, args.seed)

    missing = [c for c in ALL_CANONICAL_FEATURES if X_tr[c].isna().all()]
    print(f"Train rows: {len(X_tr):,} ({int(y_tr.sum()):,} attacks) | Test rows: {len(X_te):,} ({int(y_te.sum()):,} attacks)")
    if missing:
        print(f"Not measured by this dataset (imputed): {', '.join(missing)}")
    print("\nTraining set composition:")
    print(summarize(y_tr, c_tr).to_string(index=False))

    # 2. Preprocess + train
    t1 = time.time()
    pre = NetworkPreprocessor(apply_smote=args.smote, random_state=args.seed)
    Xtr, ytr = pre.fit_transform_resample(X_tr, y_tr)
    model = CalibratedRFModel(n_estimators=args.n_estimators, cv_folds=args.cv_folds, random_state=args.seed)
    model.fit(Xtr, ytr, preprocessor=pre)
    train_s = time.time() - t1

    # 3. Evaluate
    Xte = pre.transform(X_te)
    t2 = time.time()
    prob = model.predict_confidence(Xte)
    infer_ms = (time.time() - t2) / max(len(Xte), 1) * 1000
    yte = y_te.to_numpy()
    pred = (prob >= args.threshold).astype(int)
    m = IDSEvaluator(target_tpr=0.95, target_fpr=0.05).evaluate(yte, prob)
    cats = per_category_detection(c_te, yte, pred)
    importances = sorted(model.get_feature_importances().items(), key=lambda kv: -kv[1])[:10]

    print("\n" + "-" * 78)
    print(" RESULTS ON THE HELD-OUT TEST SET")
    print("-" * 78)
    for k, label in [("accuracy", "Accuracy"), ("precision", "Precision"), ("tpr", "Recall / TPR"),
                     ("fpr", "False positive rate"), ("f1_score", "F1-score"), ("roc_auc", "ROC-AUC"),
                     ("pr_auc", "PR-AUC"), ("brier_score", "Brier score"), ("ece", "Calibration error (ECE)")]:
        v = m[k]
        print(f"  {label:<26}{v*100:8.2f}%" if k in ("accuracy", "precision", "tpr", "fpr", "f1_score") else f"  {label:<26}{v:8.4f}")
    cm = m["confusion_matrix"]
    print(f"  Confusion matrix          TP {cm['tp']:,}  FP {cm['fp']:,}  TN {cm['tn']:,}  FN {cm['fn']:,}")
    print(f"  Training time             {train_s:8.1f} s")
    print(f"  Inference                 {infer_ms:8.4f} ms per flow")
    print("\nDetection by traffic type (benign rows show the share correctly allowed):")
    print(cats.to_string(index=False))
    print("\nTop features:")
    for f, v in importances:
        print(f"  {f:<14}{v:.4f}")

    # 4. Save
    os.makedirs("models", exist_ok=True)
    os.makedirs("results", exist_ok=True)
    model_path = f"models/ids_rf_{args.name}.joblib"
    model.save(model_path)
    report = {
        "dataset": args.name, "train_source": args.train, "test_source": args.test or f"{int(args.test_size*100)}% stratified split",
        "train_rows": int(len(X_tr)), "test_rows": int(len(X_te)), "features_not_measured": missing,
        "settings": {"n_estimators": args.n_estimators, "cv_folds": args.cv_folds, "smote": args.smote,
                     "threshold": args.threshold, "seed": args.seed},
        "metrics": {k: (round(v, 6) if isinstance(v, float) else v) for k, v in m.items()},
        "per_category": cats.to_dict(orient="records"),
        "top_features": [{"feature": f, "importance": round(float(v), 5)} for f, v in importances],
        "training_seconds": round(train_s, 1), "inference_ms_per_flow": round(infer_ms, 5),
    }
    report_path = f"results/ids_{args.name}_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved model  -> {model_path}")
    print(f"Saved report -> {report_path}")
    if args.activate:
        shutil.copyfile(model_path, "models/ids_rf_calibrated.joblib")
        print("Activated: models/ids_rf_calibrated.joblib now uses this model")
    print(f"Total time: {time.time() - t0:.1f} s")


if __name__ == "__main__":
    main()
