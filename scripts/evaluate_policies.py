"""
evaluate_policies.py
====================
Compare mitigation strategies on held-out episodes of SDNIntrusionEnv:

  1. Static detect-and-block  (BLOCK if P(attack) >= 0.5, else ALLOW)
  2. Rule-based trust policy  (the hand-written decision core in policy_infer.py)
  3. PPO agent                (models/rl_ppo_agent.zip)
  4. AHP-TOPSIS (MCDM only)
  5. Hybrid: PPO + AHP-TOPSIS + guardrails   (proposed framework)

Usage:
    python scripts/evaluate_policies.py --steps 5000 --seed 2026
Writes results/policy_comparison.json
"""

import argparse
import json
import os
import sys

import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.rl.sdn_env import SDNIntrusionEnv
from src.rl.reward import MitigationAction
from src.rl.policy_infer import RLPolicyEngine
from src.mcdm.decision_engine import AdaptiveDecisionEngine, DecisionContext

MITIGATING = (MitigationAction.RATE_LIMIT, MitigationAction.REDIRECT, MitigationAction.BLOCK)


def obs_to_kwargs(obs):
    return dict(
        attack_confidence=float(obs[0]), trust_score=float(obs[1]), trust_variance=float(obs[2]),
        congestion_index=float(obs[3]), loss_rate=float(obs[4]), flow_rate_norm=float(obs[5]),
        byte_rate_norm=float(obs[6]), proto_encoded=float(obs[7]), dst_port_norm=float(obs[8]),
        is_emerging_threat=bool(obs[9] > 0.5), prev_action=int(round(obs[10] * 4)), burst_factor=float(obs[11]),
    )


def obs_to_ctx(obs):
    k = obs_to_kwargs(obs)
    k["packet_loss_rate"] = k.pop("loss_rate")
    return DecisionContext(**k)


def run(policy_fn, steps, seed):
    env = SDNIntrusionEnv(max_steps=steps, random_seed=seed)
    obs, _ = env.reset(seed=seed)
    total_r, counts = 0.0, np.zeros(5, dtype=int)
    atk = atk_mitigated = ben = ben_blocked = ben_disrupted = 0
    for _ in range(steps):
        is_attack = env.current_ground_truth_attack
        a = int(policy_fn(obs))
        obs, r, term, trunc, info = env.step(a)
        total_r += r
        counts[a] += 1
        if is_attack:
            atk += 1
            atk_mitigated += a in MITIGATING
        else:
            ben += 1
            ben_blocked += a == MitigationAction.BLOCK
            ben_disrupted += a in (MitigationAction.REDIRECT, MitigationAction.BLOCK)
        if term or trunc:
            break
    return {
        "mean_reward": round(total_r / steps, 4),
        "attack_mitigation_rate": round(atk_mitigated / max(atk, 1), 4),
        "benign_availability": round(1 - ben_blocked / max(ben, 1), 4),
        "benign_disruption_rate": round(ben_disrupted / max(ben, 1), 4),
        "action_distribution": {MitigationAction(i).name: int(c) for i, c in enumerate(counts)},
        "flows": {"attack": atk, "benign": ben},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--steps", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--ppo", default="models/rl_ppo_agent.zip")
    ap.add_argument("--out", default="results/policy_comparison.json")
    args = ap.parse_args()

    rules = RLPolicyEngine()
    ppo = RLPolicyEngine(model_path=args.ppo) if os.path.exists(args.ppo) else None
    mcdm = AdaptiveDecisionEngine(policy_engine=None)
    hybrid = AdaptiveDecisionEngine(policy_engine=ppo or rules)

    policies = {
        "Static detect-and-block": lambda o: MitigationAction.BLOCK if o[0] >= 0.5 else MitigationAction.ALLOW,
        "Rule-based trust policy": lambda o: rules.predict_action(**obs_to_kwargs(o)),
        "AHP-TOPSIS (MCDM only)": lambda o: mcdm.decide(obs_to_ctx(o)).action,
    }
    if ppo is not None and ppo.use_sb3:
        policies["PPO agent"] = lambda o: ppo.predict_action(**obs_to_kwargs(o))
    policies["Hybrid PPO + AHP-TOPSIS (proposed)"] = lambda o: hybrid.decide(obs_to_ctx(o)).action

    results = {}
    print(f"{'Strategy':<38}{'Reward':>8}{'Attacks stopped':>17}{'Availability':>14}{'Benign disrupted':>18}")
    for name, fn in policies.items():
        res = run(fn, args.steps, args.seed)
        results[name] = res
        print(f"{name:<38}{res['mean_reward']:>8.3f}{res['attack_mitigation_rate']*100:>16.1f}%"
              f"{res['benign_availability']*100:>13.1f}%{res['benign_disruption_rate']*100:>17.1f}%")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump({"steps": args.steps, "seed": args.seed, "results": results}, f, indent=2)
    print(f"\nSaved {args.out}")


if __name__ == "__main__":
    main()
