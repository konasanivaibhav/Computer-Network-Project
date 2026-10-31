"""
show_results.py
===============
Print the final results of every algorithm and simulation in the terminal.

Reads the JSON files in results/ (written by the training, evaluation and
simulation scripts) and prints one table per experiment. Missing files are
skipped with a note saying which command creates them.

    python scripts/show_results.py
"""

import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RES = os.path.join(ROOT, "results")
W = 92


def load(name):
    p = os.path.join(RES, name)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def title(text):
    print("\n" + "=" * W)
    print(" " + text)
    print("=" * W)


def table(headers, rows, aligns=None):
    cols = list(zip(*([headers] + rows))) if rows else [[h] for h in headers]
    widths = [max(len(str(x)) for x in c) for c in cols]
    aligns = aligns or (["<"] + [">"] * (len(headers) - 1))
    line = lambda r: "  ".join(f"{str(x):{a}{w}}" for x, a, w in zip(r, aligns, widths))
    print(line(headers))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(line(r))


def missing(what, cmd):
    print(f"  (no results yet for {what}; create them with: {cmd})")


def pct(x, digits=2):
    return "-" if x is None else f"{x:.{digits}f}%"


def ids_section():
    title("1. RANDOM FOREST IDS ON REAL DATASETS")
    rows = []
    for f, name in (("ids_unsw_nb15_report.json", "UNSW-NB15 (official split)"),
                    ("ids_cicids2017_friday_ddos_report.json", "CICIDS2017 Friday DDoS")):
        d = load(f)
        if not d:
            continue
        m = d["metrics"]
        rows.append([name, f"{d['train_rows']:,}/{d['test_rows']:,}", pct(m["accuracy"] * 100), pct(m["precision"] * 100),
                     pct(m["tpr"] * 100), pct(m["fpr"] * 100), pct(m["f1_score"] * 100), f"{m['roc_auc']:.3f}"])
    if rows:
        table(["Dataset", "Train/Test", "Accuracy", "Precision", "Recall", "FPR", "F1", "ROC-AUC"], rows)
    else:
        missing("the real datasets", "python scripts/train_on_dataset.py --dataset unsw_nb15 ...")


def policy_section():
    title("2. DECISION ALGORITHMS COMPARED (same traffic for every algorithm)")
    d = load("policy_comparison.json")
    if not d:
        return missing("the policy comparison", "python scripts/evaluate_policies.py")
    rows = []
    for name, r in d["results"].items():
        rows.append([name, pct(r["attack_mitigation_rate"] * 100, 1), pct(r["benign_availability"] * 100, 1),
                     pct(r["benign_disruption_rate"] * 100, 2), f"{r['mean_reward']:.3f}"])
    table(["Algorithm", "Attacks stopped", "Normal served", "Normal disrupted", "Mean reward"], rows)
    print(f"  ({d['steps']:,} steps, seed {d['seed']})")
    s = load("simulation_trace.json")
    if s:
        w = s["summary"]["ahp_weights"]
        print("\n  AHP criterion weights: " + ", ".join(f"{k.replace('_', ' ')} {v:.3f}" for k, v in w.items()))
        print(f"  AHP consistency ratio: {s['summary']['ahp_consistency_ratio']} (below 0.10 = consistent)")


def pipeline_section():
    title("3. FULL PIPELINE ON REAL UNSW-NB15 TRAFFIC (by trust penalty)")
    rows, base = [], None
    for p in ("0.5", "1", "2", "3.5"):
        d = load(f"pipeline_unsw_nb15_penalty{p}_report.json")
        if not d:
            continue
        ids, prop = d["comparison"][0], d["comparison"][1]
        base = base or ["IDS alone (block at P >= 0.5)", pct(ids["attacks_mitigated_pct"]), pct(ids["benign_served_pct"])]
        label = f"Proposed, trust penalty {d['trust_penalty']}" + (" (default)" if d["trust_penalty"] == 3.5 else "")
        rows.append([label, pct(prop["attacks_mitigated_pct"]), pct(prop["benign_served_pct"])])
    if rows:
        table(["Strategy", "Attacks stopped", "Normal served"], [base] + rows)
    else:
        missing("the real-data pipeline", "python scripts/evaluate_on_dataset.py --penalty 1.0 ...")


SIMS = [
    ("simulation_trace.json", "Main scenario (6 hosts)", "python scripts/run_sdn_simulation.py"),
    ("simulation_trace_large.json", "3 networks", "python scripts/run_sdn_simulation.py --hosts_per_network 500,200,50 --switches_per_network 12,6,2"),
    ("simulation_trace_agent.json", "3 networks + AI agent", "... --agent offline --out results/simulation_trace_agent.json"),
    ("simulation_trace_attacks.json", "10 attack types", "... --attack_types all --out results/simulation_trace_attacks.json"),
    ("simulation_trace_unseen.json", "Unseen attack (slowloris)", "... --unseen_attacks slowloris --out results/simulation_trace_unseen.json"),
    ("simulation_trace_unseen_agent.json", "Unseen attack + AI agent", "... --unseen_attacks slowloris --agent offline --out results/simulation_trace_unseen_agent.json"),
]


def sim_section():
    title("4. SDN SIMULATIONS (proposed framework vs static block at P >= 0.5)")
    rows, actions = [], []
    for f, name, cmd in SIMS:
        d = load(f)
        if not d:
            print(f"  {name}: not run yet ({cmd})")
            continue
        s = d["summary"]
        hosts = len(d["topology"]["hosts"])
        P, B = s["proposed"], s["static_threshold_0_5"]
        rows.append([name, f"{hosts:,}", f"{s['flows_total']:,}", pct(P["attack_mitigation_pct"]), pct(P["benign_served_pct"]),
                     f"{P['benign_blocked']:,}", f"{pct(B['attack_mitigation_pct'])} / {pct(B['benign_served_pct'])}"])
        ac = s.get("action_counts", {})
        actions.append([name] + [f"{ac.get(a, 0):,}" for a in ("ALLOW", "MONITOR", "RATE_LIMIT", "REDIRECT", "BLOCK")])
    if rows:
        table(["Simulation", "Hosts", "Flows", "Attacks stopped", "Normal served", "Normal blocked", "Static: stopped / served"], rows)
        print("\n  Actions chosen (host-seconds in the large runs, flows in the main scenario):")
        table(["Simulation", "Allow", "Monitor", "Rate limit", "Redirect", "Block"], actions)


def attack_section():
    for f, name in (("simulation_trace_attacks.json", "10 ATTACK TYPES"),
                    ("simulation_trace_unseen.json", "UNSEEN ATTACK, FRAMEWORK ALONE"),
                    ("simulation_trace_unseen_agent.json", "UNSEEN ATTACK, WITH AI AGENT")):
        d = load(f)
        if not d or not d["summary"].get("by_attack"):
            continue
        title(f"5. RESULTS BY ATTACK TYPE: {name}")
        rows = [[r["label"] + (" (never seen by IDS)" if r["unseen_by_ids"] else ""), r["attacker_hosts"] + r.get("compromised_hosts", 0),
                 f"{r['flows']:,}", pct(r["mitigated_pct"], 1), f"{r['mean_p_attack']:.2f}"] for r in d["summary"]["by_attack"]]
        table(["Attack", "Hosts", "Flows", "Stopped", "Mean IDS score"], rows)


def agent_section():
    d = load("simulation_trace_agent.json")
    if not d or not d.get("agent"):
        return
    title("6. AI AGENT (offline planner, 3-network run)")
    ag = d["agent"]
    print(f"  Reviews: {ag['reviews']}   Overrides: {ag['overrides']}   Incidents: {len(ag['incidents'])}   "
          f"Waiting for human approval: {len(ag['pending_approvals'])}")
    base = load("simulation_trace_large.json")
    if base:
        b, a = base["summary"]["proposed"]["benign_blocked"], d["summary"]["proposed"]["benign_blocked"]
        print(f"  Normal flows wrongly blocked: {b:,} without agent -> {a:,} with agent ({round(100 * (1 - a / b))}% fewer)")
    print()
    table(["Incident", "Severity", "Title", "Hosts"],
          [[i["id"], i["severity"], i["title"], len(i["hosts"])] for i in ag["incidents"]], ["<", "<", "<", ">"])


def main():
    if not os.path.isdir(RES):
        sys.exit("No results/ folder found. Run this from the project folder after running the simulations.")
    print("=" * W)
    print(" FINAL RESULTS: Context-Aware Adaptive Trust-Based Intrusion Mitigation Framework for SDN")
    print("=" * W)
    ids_section()
    policy_section()
    pipeline_section()
    sim_section()
    attack_section()
    agent_section()
    print()


if __name__ == "__main__":
    main()
