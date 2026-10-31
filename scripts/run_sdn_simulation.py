"""
run_sdn_simulation.py
=====================
Run the end-to-end SDN simulation.

Default: the project's Mininet topology (3 switches, 6 hosts) and its scripted
scenario. Writes results/simulation_trace.json; build the 3D page with
scripts/build_3d_view.py.

Large-network mode: pass --hosts and/or --networks. Builds one or more leaf-spine
SDN networks (each with its own Ryu controller) with randomly assigned host roles,
writes results/simulation_trace_large.json and the 3D page
visualization/sdn_3d_large.html in one go.

Examples:
    python scripts/run_sdn_simulation.py
    python scripts/run_sdn_simulation.py --hosts 200 --switches 8
    python scripts/run_sdn_simulation.py --networks 5 --hosts 1000 --switches 8 --attackers 0.08
    python scripts/run_sdn_simulation.py --hosts_per_network 500,200,50 --switches_per_network 12,6,2

More attack types and 200+ attackers (UDP/ICMP flood, DNS amplification, SSH brute force,
slowloris, data exfiltration, C2 beacons, plus scan / SYN flood / CVE exploit):
    python scripts/run_sdn_simulation.py --hosts_per_network 800,500,300 --attackers 0.13 --attack_types all
    python scripts/run_sdn_simulation.py --hosts 600 --attack_types all --unseen_attacks slowloris

With the agentic AI analyst (writes results/agent_report.md):
    python scripts/run_sdn_simulation.py --hosts 300 --agent offline
    set GROQ_API_KEY=...        (Windows)   /   export GROQ_API_KEY=...   (Linux/macOS)
    python scripts/run_sdn_simulation.py --hosts 300 --agent groq
    python scripts/run_sdn_simulation.py --hosts 300 --agent claude      (needs ANTHROPIC_API_KEY)
    python scripts/run_sdn_simulation.py --hosts 300 --agent ollama --agent_model llama3.1
"""

import argparse
import logging
import os
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)
logging.disable(logging.WARNING)

from src.simulation.network_sim import run_and_save  # noqa: E402
from src.simulation.large_network_sim import run_and_save_large  # noqa: E402
from src.agent import make_agent, write_report  # noqa: E402


def run_small(args):
    trace = run_and_save(args.out or "results/simulation_trace.json", seed=args.seed or 7)
    s = trace["summary"]
    print("=" * 78)
    print(" END-TO-END SDN SIMULATION")
    print("=" * 78)
    for e in trace["events"]:
        print(f"t={e['t']:>3}s  {e['text']}")
    print("-" * 78)
    print(f"Flows evaluated: {s['flows_total']} (attack {s['flows_attack']}, benign {s['flows_benign']})")
    print(f"PPO model loaded: {s['ppo_model']} | AHP consistency ratio: {s['ahp_consistency_ratio']}")
    print(f"{'':<28}{'Attacks mitigated':>20}{'Benign served':>16}{'Benign blocked':>16}")
    for name, key in (("Proposed framework", "proposed"), ("Static threshold (0.5)", "static_threshold_0_5")):
        r = s[key]
        print(f"{name:<28}{r['attack_mitigation_pct']:>19.1f}%{r['benign_served_pct']:>15.1f}%{r['benign_blocked']:>16}")
    print(f"Final trust: {s['final_trust']}")
    print(f"Trace written to {args.out or 'results/simulation_trace.json'}")


def int_list(text):
    try:
        vals = [int(x) for x in text.replace(" ", "").split(",") if x]
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected comma-separated whole numbers, e.g. 300,100,50 (got '{text}')")
    if not vals or min(vals) < 1:
        raise argparse.ArgumentTypeError("every value must be 1 or more")
    return vals


def run_large(args):
    out = args.out or "results/simulation_trace_large.json"
    hpn, spn = args.hosts_per_network, args.switches_per_network
    networks = len(hpn) if hpn else (len(spn) if spn else args.networks)
    if hpn and spn and len(hpn) != len(spn):
        sys.exit(f"--hosts_per_network has {len(hpn)} values but --switches_per_network has {len(spn)}; give one value per network.")
    hosts = sum(hpn) if hpn else (args.hosts or 200 * networks)
    sizes = ", ".join(f"N{i + 1}: {h} hosts / {(spn[i] if spn else args.switches)} switches" for i, h in enumerate(hpn)) if hpn else \
        f"{(spn if spn else args.switches)} access switches per network"
    print("=" * 78)
    print(f" LARGE-NETWORK SDN SIMULATION: {networks} network(s), {hosts} hosts")
    print(f" {sizes}")
    print("=" * 78)
    t0 = time.time()
    trace = run_and_save_large(
        out, progress=True, n_hosts=hosts, n_switches=args.switches, n_networks=networks,
        hosts_per_network=hpn, switches_per_network=spn,
        attacker_ratio=args.attackers, compromised_ratio=args.compromised, bursty_ratio=args.bursty,
        duration=args.duration, trust_penalty=args.penalty, seed=args.seed or 11,
        agent=make_agent(args.agent, args.agent_model, args.agent_base_url), agent_interval=args.agent_interval,
        attack_types=args.attack_types, unseen_attacks=args.unseen_attacks)
    s = trace["summary"]
    print("-" * 78)
    print(f"Flows evaluated: {s['flows_total']:,} (attack {s['flows_attack']:,}, benign {s['flows_benign']:,}) in {time.time() - t0:.0f} s")
    print(f"{'':<28}{'Attacks mitigated':>20}{'Benign served':>16}{'Benign blocked':>16}")
    for name, key in (("Proposed framework", "proposed"), ("Static threshold (0.5)", "static_threshold_0_5")):
        r = s[key]
        print(f"{name:<28}{r['attack_mitigation_pct']:>19.2f}%{r['benign_served_pct']:>15.2f}%{r['benign_blocked']:>16,}")
    print("\nBy network:")
    for r in s["by_network"]:
        print(f"  {r['network']:<5} {r['hosts']:>6} hosts {r['switches']:>3} switches  {r['malicious_hosts']:>4} malicious  "
              f"attacks stopped {r['attack_mitigation_pct'] if r['attack_mitigation_pct'] is not None else '-':>6}%  "
              f"benign served {r['benign_served_pct']:>6}%")
    if s.get("by_attack"):
        print("\nBy attack type:")
        print(f"  {'Attack':<20}{'Hosts':>8}{'Flows':>9}{'Mitigated':>11}{'Mean P(attack)':>16}")
        for r in s["by_attack"]:
            hosts = r["attacker_hosts"] + r.get("compromised_hosts", 0)
            note = "  (never seen by the IDS)" if r["unseen_by_ids"] else ""
            print(f"  {r['label']:<20}{hosts:>8}{r['flows']:>9,}{r['mitigated_pct']:>10.1f}%{r['mean_p_attack']:>16.2f}{note}")
    tt = s["time_to_mitigate_s"]
    print(f"\nMalicious hosts: {tt['malicious_hosts']} | never contained: {tt['never_mitigated']} | "
          f"mean time to first mitigation: {tt['mean']} s")
    print(f"Mean final trust by role: {s['mean_final_trust']}")
    print(f"Trace written to {out}")
    ag = trace.get("agent")
    if ag:
        print(f"\nAgent ({ag['backend']}): {ag['reviews']} reviews, {ag['overrides']} overrides, "
              f"{len(ag['incidents'])} incidents, {len(ag['pending_approvals'])} actions waiting for human approval")
        for inc in ag["incidents"]:
            print(f"  {inc['id']} [{inc['severity'].upper()}] {inc['title']} ({len(inc['hosts'])} hosts)")
        for e in ag["errors"][:3]:
            print(f"  note: {e}")
        print(f"Incident report written to {write_report(trace, 'results/agent_report.md')}")
    if not args.no_view:
        sys.path.insert(0, os.path.join(PROJECT_ROOT, "scripts"))
        from build_3d_view import build
        stem = os.path.splitext(os.path.basename(out))[0].replace("simulation_trace_", "")
        page_name = "sdn_3d_large.html" if stem in ("large", "simulation_trace") else f"sdn_3d_{stem}.html"
        page = build(out, os.path.join(PROJECT_ROOT, "visualization", "sdn_3d_scale_template.html"),
                     os.path.join(PROJECT_ROOT, "visualization", page_name))
        print(f"3D view written to {page}")


def main():
    ap = argparse.ArgumentParser(description="End-to-end SDN intrusion-mitigation simulation")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--out", default=None)
    g = ap.add_argument_group("large-network mode (enabled by --hosts or --networks)")
    g.add_argument("--hosts", type=int, default=None, help="Total client hosts across all networks")
    g.add_argument("--networks", type=int, default=1, help="Number of separate SDN networks")
    g.add_argument("--switches", type=int, default=8, help="Access switches per network")
    g.add_argument("--hosts_per_network", type=int_list, default=None,
                   help="Hosts in each network, comma-separated, e.g. 500,200,50 (sets the number of networks)")
    g.add_argument("--switches_per_network", type=int_list, default=None,
                   help="Access switches in each network, comma-separated, e.g. 12,6,2")
    g.add_argument("--attackers", type=float, default=0.08, help="Share of hosts that are attackers")
    g.add_argument("--compromised", type=float, default=0.04, help="Share of hosts compromised mid-run")
    g.add_argument("--bursty", type=float, default=0.10, help="Share of benign hosts with a flash crowd")
    g.add_argument("--duration", type=int, default=120, help="Simulated seconds")
    g.add_argument("--penalty", type=float, default=3.5, help="Trust penalty multiplier")
    g.add_argument("--no_view", action="store_true", help="Skip building the 3D page")
    g.add_argument("--attack_types", default="classic",
                   help="classic (scan, SYN flood, CVE exploit), all (10 types), or a comma list, e.g. udp_flood,ssh_bruteforce,slowloris")
    g.add_argument("--unseen_attacks", type=lambda x: [k.strip() for k in x.split(",") if k.strip()], default=None,
                   help="Attack types left out of IDS training, to test attacks the IDS has never seen")
    a = ap.add_argument_group("agentic AI analyst (large-network mode)")
    a.add_argument("--agent", default="none", choices=["none", "offline", "claude", "groq", "openai", "ollama"],
                   help="Agent backend. API keys come from ANTHROPIC_API_KEY / GROQ_API_KEY / OPENAI_API_KEY")
    a.add_argument("--agent_model", default=None, help="Model name (defaults: claude-sonnet-5-5, openai/gpt-oss-120b, gpt-4o-mini)")
    a.add_argument("--agent_base_url", default=None, help="Custom OpenAI-compatible endpoint")
    a.add_argument("--agent_interval", type=int, default=10, help="Seconds between agent reviews")
    args = ap.parse_args()
    if args.agent != "none" and not (args.hosts or args.networks > 1 or args.hosts_per_network or args.switches_per_network):
        args.hosts = 200     # the agent runs in large-network mode
    if args.attack_types != "classic" and not (args.hosts or args.networks > 1 or args.hosts_per_network or args.switches_per_network):
        args.hosts = 300     # the attack mix runs in large-network mode
    if args.hosts is not None or args.networks > 1 or args.hosts_per_network or args.switches_per_network:
        run_large(args)
    else:
        run_small(args)


if __name__ == "__main__":
    main()
