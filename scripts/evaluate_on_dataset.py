"""
evaluate_on_dataset.py
======================
Run the full decision pipeline on real dataset flows:

    real flow features -> trained RF IDS -> Bayesian device trust
    -> PPO + AHP-TOPSIS decision engine -> mitigation action

and compare it with a static "block if P(attack) >= 0.5" rule on the same flows.

UNSW-NB15 and CICIDS2017 CSVs do not say which device sent each flow in a form
usable here, so flows are assigned to simulated devices: benign flows to
`--devices` normal hosts and attack flows to `--attackers` malicious hosts,
interleaved in random order. The flow features and IDS scores are real; the
device grouping is simulated and is reported as such.

Example:
    python scripts/evaluate_on_dataset.py --data data/raw/UNSW_NB15_testing-set.csv ^
        --model models/ids_rf_unsw_nb15.joblib --name unsw_nb15
"""

import argparse
import json
import logging
import os
import sys
import time

import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

from src.ids.datasets import load_dataset, stratified_sample  # noqa: E402
from src.ids.train_rf import CalibratedRFModel  # noqa: E402
from src.trust.trust_engine import BayesianDynamicTrustEngine  # noqa: E402
from src.rl.policy_infer import RLPolicyEngine  # noqa: E402
from src.rl.reward import MitigationAction  # noqa: E402
from src.mcdm.decision_engine import AdaptiveDecisionEngine, DecisionContext  # noqa: E402

MITIGATE = {2, 3, 4}     # rate limit, redirect, block
DISRUPT = {3, 4}         # redirect, block


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Dataset CSV(s) to replay (use the test split)")
    ap.add_argument("--model", required=True, help="IDS model trained with train_on_dataset.py")
    ap.add_argument("--name", default="dataset")
    ap.add_argument("--max_flows", type=int, default=40_000)
    ap.add_argument("--devices", type=int, default=200, help="Simulated benign hosts")
    ap.add_argument("--attackers", type=int, default=20, help="Simulated malicious hosts")
    ap.add_argument("--congestion", type=float, default=0.3)
    ap.add_argument("--ppo", default="models/rl_ppo_agent.zip")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--penalty", type=float, default=3.5,
                    help="Trust penalty multiplier for flagged flows (trust_engine default 3.5)")
    args = ap.parse_args()
    logging.disable(logging.INFO)
    rng = np.random.default_rng(args.seed)

    df, y, cat = load_dataset(args.data, max_rows=None)
    if len(df) > args.max_flows:
        df, y, cat = stratified_sample(df, y, cat, args.max_flows, args.seed)
    model = CalibratedRFModel.load(args.model)
    t0 = time.time()
    p = model.predict_confidence(model.preprocessor.transform(df))
    y = y.to_numpy()

    # Assign flows to simulated devices and shuffle into one arrival order
    dev = np.where(y == 1, rng.integers(0, args.attackers, len(y)) + 10_000, rng.integers(0, args.devices, len(y)))
    order = rng.permutation(len(y))

    trust = BayesianDynamicTrustEngine(decay_rate_lambda=0.001, penalty_multiplier=args.penalty)
    ppo = RLPolicyEngine(model_path=args.ppo if os.path.exists(args.ppo) else None)
    engine = AdaptiveDecisionEngine(policy_engine=ppo)
    prev = {}
    actions = np.zeros(len(y), dtype=int)
    rate = (df["packet_rate"].fillna(0).to_numpy() / 1000).clip(0, 1)
    now = 0.0
    for i in order:
        now += 0.05
        d = int(dev[i])
        st = trust.update_flow_observation(str(d), float(p[i]), current_time=now)
        dec = engine.decide(DecisionContext(
            attack_confidence=float(p[i]), trust_score=st.score, trust_variance=st.variance,
            congestion_index=args.congestion, flow_rate_norm=float(rate[i]), burst_factor=float(min(1, rate[i] * 2)),
            prev_action=prev.get(d, 0)))
        actions[i] = int(dec.action)
        prev[d] = int(dec.action)
    run_s = time.time() - t0

    atk, ben = y == 1, y == 0
    static = (p >= 0.5).astype(int)

    def row(name, mitig, disrupt):
        return {"strategy": name,
                "attacks_mitigated_pct": round(100 * mitig[atk].mean(), 2),
                "benign_disrupted_pct": round(100 * disrupt[ben].mean(), 2),
                "benign_served_pct": round(100 * (1 - disrupt[ben].mean()), 2)}

    res = [
        row("IDS alone, static block at P >= 0.5", static == 1, static == 1),
        row("Proposed: trust + PPO + AHP-TOPSIS", np.isin(actions, list(MITIGATE)), np.isin(actions, list(DISRUPT))),
    ]
    dist = {MitigationAction(a).name: int((actions == a).sum()) for a in range(5)}
    per_cat = []
    for c in sorted(set(cat)):
        m = (cat == c).to_numpy()
        is_atk = bool(y[m].max())
        good = np.isin(actions[m], list(MITIGATE)) if is_atk else ~np.isin(actions[m], list(DISRUPT))
        per_cat.append({"category": c, "flows": int(m.sum()), "handled_correctly_pct": round(100 * good.mean(), 2)})

    print("=" * 78)
    print(f" FULL PIPELINE ON REAL FLOWS: {args.name}")
    print("=" * 78)
    print(f"{len(y):,} real flows ({int(atk.sum()):,} attack, {int(ben.sum()):,} benign) | "
          f"simulated devices: {args.devices} benign, {args.attackers} attackers | PPO: {ppo.use_sb3} | trust penalty: {args.penalty}")
    print(f"\n{'Strategy':<40}{'Attacks mitigated':>18}{'Benign disrupted':>18}{'Benign served':>15}")
    for r in res:
        print(f"{r['strategy']:<40}{r['attacks_mitigated_pct']:>17.2f}%{r['benign_disrupted_pct']:>17.2f}%{r['benign_served_pct']:>14.2f}%")
    print("\nAction distribution:", dist)
    print("\nBy traffic type (attacks: share mitigated; Normal: share not disrupted):")
    for r in per_cat:
        print(f"  {r['category']:<16}{r['flows']:>8,}  {r['handled_correctly_pct']:6.2f}%")
    print(f"\nRun time: {run_s:.1f} s")
    print("Note: flow features and IDS scores are real; the assignment of flows to devices is simulated.")

    os.makedirs("results", exist_ok=True)
    out = f"results/pipeline_{args.name}_penalty{args.penalty:g}_report.json"
    with open(out, "w") as f:
        json.dump({"dataset": args.name, "flows": int(len(y)), "devices": args.devices, "attackers": args.attackers,
                   "ppo_model": bool(ppo.use_sb3), "trust_penalty": args.penalty, "comparison": res, "action_distribution": dist,
                   "per_category": per_cat, "device_assignment": "simulated"}, f, indent=2)
    print(f"Saved {out}")


if __name__ == "__main__":
    main()
