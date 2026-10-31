"""
large_network_sim.py
====================
Large-network mode of the end-to-end SDN simulation.

Generates a leaf-spine network of any size and runs every flow through the same
pipeline as network_sim.py:

    flow features -> calibrated RF IDS (batched per tick) -> Bayesian trust
    -> network context -> PPO + AHP-TOPSIS decision engine -> OpenFlow action

Topology
    `n_networks` independent SDN networks (sites). Each has its own Ryu
    controller, one spine switch, its access switches holding its client hosts, and a service leaf with a web/DB server and a honeypot.
    Every network keeps its own trust state and network context; all networks
    share one threat-intelligence feed. Networks can differ in size:
    `hosts_per_network=[300, 100, 50]` and `switches_per_network=[10, 4, 2]`;
    otherwise hosts are split evenly and every network has `n_switches`. With one network, switches are named
    s1 (spine), s2... (access) as in the Mininet topology; with several they are
    prefixed N1-, N2-, ...

Host roles (assigned at random with a fixed seed)
    normal       steady benign browsing
    bursty       benign, with one legitimate flash-crowd window
    attacker     idle, then a port scan, then a SYN flood
    compromised  light benign traffic, then exploits a CVE that threat intel
                 registers part-way through the run

Output: a compact trace (one array entry per host per tick) that
visualization/sdn_3d_scale_template.html replays in 3D.
"""

import json
import os
from collections import deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from src.ids.train_rf import CalibratedRFModel, train_ids_pipeline
from src.trust.trust_engine import BayesianDynamicTrustEngine
from src.context.collector import NetworkContextCollector
from src.rl.reward import MitigationAction
from src.rl.policy_infer import RLPolicyEngine
from src.mcdm.decision_engine import AdaptiveDecisionEngine, DecisionContext
from src.threat_intel.scraper import AutomatedThreatScraper
from src.threat_intel.nlp_parser import ThreatNLPParser
from src.simulation.network_sim import OF_RULE
from src.simulation.attack_library import (sample as sample_flow, ALL_ATTACKS, CLASSIC_ATTACKS, NEW_ATTACKS,
                                           ATTACK_PORT, ATTACK_LABEL, generate_training_set)

# Order matters: traces store an index into this list (first six kept for older traces)
KINDS = ["idle", "benign", "flash_crowd", "port_scan", "syn_flood", "web_exploit"] + NEW_ATTACKS
FLOWS_PER_TICK = {"ssh_bruteforce": 3, "c2_beacon": 1, "data_exfiltration": 1}
ROLES = ["normal", "bursty", "attacker", "compromised"]
SERVER_IP, HONEYPOT_IP = "10.255.0.3", "10.255.0.100"


@dataclass
class ScaleHost:
    name: str
    ip: str
    switch: str
    role: str
    network: int = 0
    # schedule (ticks); -1 when unused
    burst_start: int = -1
    scan_start: int = -1
    flood_start: int = -1
    exploit_start: int = -1
    activity: float = 0.6     # probability of sending a benign flow in a tick
    attack: str = ""          # main attack type for attackers ("" = classic SYN flood)
    followups: bool = False   # compromised host goes on to C2 beaconing and data exfiltration


def switch_name(net: int, j: int, n_networks: int) -> str:
    return f"s{2 + j}" if n_networks == 1 else f"N{net + 1}-s{2 + j}"


def build_topology(n_hosts: int, n_switches, attacker_ratio: float, compromised_ratio: float,
                   bursty_ratio: float, duration: int, intel_tick: int, rng: np.random.Generator,
                   n_networks: int = 1, hosts_per_network: Optional[List[int]] = None,
                   attack_types: Optional[List[str]] = None) -> List[ScaleHost]:
    """
    n_switches: one int for every network, or a list with one entry per network.
    hosts_per_network: host count per network; if omitted, hosts are split evenly.
    """
    sw_per_net = list(n_switches) if isinstance(n_switches, (list, tuple)) else [int(n_switches)] * n_networks
    if hosts_per_network is None:
        base, extra = divmod(n_hosts, n_networks)
        hosts_per_network = [base + (1 if n < extra else 0) for n in range(n_networks)]
    if len(hosts_per_network) != n_networks or len(sw_per_net) != n_networks:
        raise ValueError("hosts_per_network and switches_per_network need one entry per network")
    n_hosts = int(sum(hosts_per_network))
    n_att = int(round(n_hosts * attacker_ratio))
    n_cmp = int(round(n_hosts * compromised_ratio))
    n_bur = int(round(n_hosts * bursty_ratio))
    roles = (["attacker"] * n_att + ["compromised"] * n_cmp + ["bursty"] * n_bur
             + ["normal"] * max(0, n_hosts - n_att - n_cmp - n_bur))[:n_hosts]
    rng.shuffle(roles)
    net_of = np.repeat(np.arange(n_networks), hosts_per_network)
    hosts = []
    per_net = [0] * n_networks
    for i, role in enumerate(roles):
        net = int(net_of[i])
        k = per_net[net]; per_net[net] += 1
        sw = switch_name(net, k % sw_per_net[net], n_networks)
        third, last = divmod(k, 250)
        h = ScaleHost(name=f"h{i + 1}", ip=f"10.{net + 1}.{third}.{last + 1}", switch=sw, role=role, network=net,
                      activity=float(rng.uniform(0.35, 0.85)))
        if role == "bursty":
            h.burst_start = int(rng.integers(int(duration * 0.1), int(duration * 0.7)))
        elif role == "attacker":
            h.scan_start = int(rng.integers(int(duration * 0.1), int(duration * 0.55)))
            h.flood_start = h.scan_start + int(rng.integers(8, 20))
        elif role == "compromised":
            h.exploit_start = int(rng.integers(intel_tick + 5, max(intel_tick + 6, int(duration * 0.85))))
        hosts.append(h)
    if attack_types:
        # spread the main attack types evenly over the attackers (deterministic order)
        mains = [k for k in attack_types if k not in ("port_scan", "web_exploit")] or ["syn_flood"]
        follow = any(k in attack_types for k in ("c2_beacon", "data_exfiltration"))
        n = 0
        for h in hosts:
            if h.role == "attacker":
                h.attack = mains[n % len(mains)]
                n += 1
            elif h.role == "compromised":
                h.followups = follow
    return hosts


def activity(h: ScaleHost, t: int, rng: np.random.Generator, duration: int) -> List[tuple]:
    """List of (kind, dst_port) flows the host sends at tick t."""
    if h.role == "attacker":
        if h.scan_start <= t < h.flood_start:
            return [("port_scan", 22)] * 2
        if t >= h.flood_start and t < min(duration, h.flood_start + 40):
            kind = h.attack or "syn_flood"
            n = FLOWS_PER_TICK.get(kind, 2)
            if kind == "c2_beacon":
                n = 1 if t % 2 == 0 else 0
            return [(kind, ATTACK_PORT.get(kind, 80))] * n
        return []
    if h.role == "compromised":
        if h.exploit_start >= 0 and h.exploit_start <= t < h.exploit_start + 20:
            return [("web_exploit", 8443)] * 2
        if h.followups and h.exploit_start >= 0:
            if h.exploit_start + 20 <= t < h.exploit_start + 30:
                return [("c2_beacon", ATTACK_PORT["c2_beacon"])] if t % 2 == 0 else []
            if h.exploit_start + 30 <= t < h.exploit_start + 40:
                return [("data_exfiltration", ATTACK_PORT["data_exfiltration"])]
        return [("benign", 80)] if (t < h.exploit_start and rng.random() < h.activity * 0.4) else []
    if h.role == "bursty" and h.burst_start <= t < h.burst_start + 12:
        return [("flash_crowd", 80)] * 2
    return [("benign", 443 if rng.random() < 0.4 else 80)] if rng.random() < h.activity else []


def resolve_attack_types(spec) -> Optional[List[str]]:
    """'classic' / None -> original scenario; 'all' -> every type; or a list / comma string of names."""
    if spec is None or spec == "classic" or spec == ["classic"]:
        return None
    if isinstance(spec, str):
        spec = ALL_ATTACKS if spec == "all" else [x.strip() for x in spec.split(",") if x.strip()]
    bad = [k for k in spec if k not in ALL_ATTACKS]
    if bad:
        raise ValueError(f"unknown attack types {bad}; choose from {ALL_ATTACKS}")
    return list(spec)


def ensure_extended_ids(unseen: Optional[List[str]] = None, models_dir: str = "models",
                        n_samples: int = 20000) -> str:
    """Train (once) an IDS on every attack type except `unseen`, and return its path."""
    unseen = sorted(unseen or [])
    name = "ids_rf_extended" + ("_without_" + "_".join(unseen) if unseen else "") + ".joblib"
    path = os.path.join(models_dir, name)
    if not os.path.exists(path):
        from src.ids.preprocess import NetworkPreprocessor
        X, y, _ = generate_training_set(n_samples, 0.35, [k for k in ALL_ATTACKS if k not in unseen], seed=7)
        pre = NetworkPreprocessor(apply_smote=False)
        Xt, yt = pre.fit_transform_resample(X, y)
        os.makedirs(models_dir, exist_ok=True)
        CalibratedRFModel(n_estimators=100, cv_folds=3).fit(Xt, yt, preprocessor=pre).save(path)
    return path


class LargeSDNSimulation:
    def __init__(
        self,
        n_hosts: int = 200,
        n_switches: int = 8,
        n_networks: int = 1,
        hosts_per_network: Optional[List[int]] = None,
        switches_per_network: Optional[List[int]] = None,
        attacker_ratio: float = 0.08,
        compromised_ratio: float = 0.04,
        bursty_ratio: float = 0.10,
        duration: int = 120,
        uplink_mbps: float = 1000.0,
        core_mbps: float = 10000.0,
        trust_penalty: float = 3.5,
        ids_model_path: str = "models/ids_rf_calibrated.joblib",
        ppo_model_path: str = "models/rl_ppo_agent.zip",
        seed: int = 11,
        agent=None,
        agent_interval: int = 10,
        attack_types=None,
        unseen_attacks: Optional[List[str]] = None,
    ):
        if hosts_per_network:
            n_networks, n_hosts = len(hosts_per_network), int(sum(hosts_per_network))
        if switches_per_network:
            if len(switches_per_network) != n_networks:
                raise ValueError("switches_per_network needs one entry per network")
            sw_list = [int(x) for x in switches_per_network]
        else:
            sw_list = [int(n_switches)] * n_networks
        if n_hosts < 2 or min(sw_list) < 1 or n_networks < 1:
            raise ValueError("Need at least 2 hosts, 1 access switch per network and 1 network")
        if (hosts_per_network and min(hosts_per_network) < 1) or n_hosts < n_networks:
            raise ValueError("Need at least one host per network")
        self.rng = np.random.default_rng(seed)
        self.duration, self.n_networks = duration, n_networks
        self.sw_list = sw_list
        self.sw_offset = np.concatenate([[0], np.cumsum(sw_list)]).astype(int)
        self.uplink_mbps, self.core_mbps = uplink_mbps, core_mbps
        self.intel_tick = int(duration * 0.4)
        self.attack_types = resolve_attack_types(attack_types)
        self.unseen_attacks = sorted(unseen_attacks or [])
        self.hosts = build_topology(n_hosts, sw_list, attacker_ratio, compromised_ratio, bursty_ratio,
                                    duration, self.intel_tick, self.rng, n_networks, hosts_per_network,
                                    self.attack_types)
        if self.attack_types and ids_model_path == "models/ids_rf_calibrated.joblib":
            # The original IDS never saw most of these attacks: use an IDS trained on the
            # extended attack set (optionally leaving some types out to test unseen attacks).
            ids_model_path = ensure_extended_ids(self.unseen_attacks)
        self.ids_model_path = ids_model_path
        if not os.path.exists(ids_model_path):
            train_ids_pipeline(use_synthetic=True, n_samples=8000, n_estimators=100, save_path=ids_model_path)
        self.ids = CalibratedRFModel.load(ids_model_path)
        # One controller per network: separate trust state and network context
        self.trusts = [BayesianDynamicTrustEngine(decay_rate_lambda=0.01, penalty_multiplier=trust_penalty)
                       for _ in range(n_networks)]
        self.contexts = [NetworkContextCollector(link_capacity_bps=core_mbps * 1e6) for _ in range(n_networks)]
        self.policy = RLPolicyEngine(model_path=ppo_model_path if os.path.exists(ppo_model_path) else None)
        self.engine = AdaptiveDecisionEngine(policy_engine=self.policy, protected_assets={SERVER_IP},
                                             monitor_uncertain=True, zero_day_forensics=True)
        self.signatures = []
        # Agentic supervisor (optional): see src/agent
        self.agent, self.agent_interval = agent, max(1, int(agent_interval))
        self.overrides: Dict[int, Dict] = {}
        self.agent_log: List[Dict] = []
        self.incidents: List[Dict] = []
        self.pending_approvals: List[Dict] = []
        self.review_summaries: List[Dict] = []
        self.last_ctx: List[Dict] = []
        self.obs = [{"p": deque(maxlen=40), "acts": deque(maxlen=60), "pps": deque(maxlen=40), "bps": deque(maxlen=40),
                     "ports": deque(maxlen=40), "trust_hist": deque(maxlen=30), "cve": None, "last_decision": None}
                    for _ in self.hosts]
        self.counters = [{"bytes": 0.0, "pkts": 0.0, "drops": 0.0} for _ in range(n_networks)]
        self.settings = dict(n_hosts=n_hosts, switches_per_network=sw_list, n_networks=n_networks,
                             hosts_per_network=[sum(h.network == n for h in self.hosts) for n in range(n_networks)], attacker_ratio=attacker_ratio,
                             compromised_ratio=compromised_ratio, bursty_ratio=bursty_ratio, duration=duration,
                             uplink_mbps=uplink_mbps, core_mbps=core_mbps, trust_penalty=trust_penalty, seed=seed,
                             attack_types=self.attack_types or "classic", unseen_attacks=self.unseen_attacks,
                             ids_model=os.path.basename(self.ids_model_path))

    def run(self, progress: bool = False) -> Dict:
        H = len(self.hosts)
        idx = {h.name: i for i, h in enumerate(self.hosts)}
        N = self.n_networks
        sw_names = [switch_name(n, j, N) for n in range(N) for j in range(self.sw_list[n])]
        sw_index = {name: g for g, name in enumerate(sw_names)}
        prev = np.zeros(H, dtype=int)
        self.prev = prev
        self.trust_now = np.full(H, 0.5)
        overridden_flows = 0
        first_attack = np.full(H, -1)
        first_mitigation = np.full(H, -1)
        frames, events = [], []
        log_attack, log_p, log_a, log_role, log_net, log_kind = [], [], [], [], [], []
        t0 = 1_000.0

        for t in range(self.duration + 1):
            now = t0 + t
            ctxs = [c.get_current_context() for c in self.contexts]
            if t == self.intel_tick:
                adv = AutomatedThreatScraper(offline_fallback=True).get_synthetic_threat_fixtures()
                sig = ThreatNLPParser().parse_advisory(adv[1])
                self.signatures.append(sig)
                events.append({"t": t, "type": "intel", "text": f"Threat intel: {sig.cve_id} -> {sig.attack_type} on "
                               f"{sig.protocol.upper()}/{sig.target_port} (CVSS {sig.cvss_score}). Signature registered."})

            # 1. Generate this tick's flows for every host, score them with the IDS in one batch
            recs, owners, truth, ports, kinds = [], [], [], [], []
            for h in self.hosts:
                for kind, port in activity(h, t, self.rng, self.duration):
                    rec, is_atk = sample_flow(kind, self.rng, port)
                    recs.append(rec); owners.append(idx[h.name]); truth.append(is_atk)
                    ports.append(port); kinds.append(kind)
            probs = (self.ids.predict_confidence(self.ids.preprocessor.transform(pd.DataFrame(recs)))
                     if recs else np.array([]))

            # 2. Sequential trust + decision per flow (state carries across flows)
            p_sum = np.zeros(H); n_flows = np.zeros(H, dtype=int)
            kind_now = np.zeros(H, dtype=int)
            offered = np.zeros(H); to_srv = np.zeros(H); to_honey = np.zeros(H)
            for j, i in enumerate(owners):
                h = self.hosts[i]
                ctx = ctxs[h.network]
                rec, p, port = recs[j], float(probs[j]), ports[j]
                st = self.trusts[h.network].update_flow_observation(h.ip, p, current_time=now)
                window = max(1.0, rec["duration"])
                pps = (rec["spkts"] + rec["dpkts"]) / window
                bps = (rec["sbytes"] + rec["dbytes"]) * 8 / window
                cve = next((s.cve_id for s in self.signatures if s.target_port == port and s.protocol == rec["proto"]), None)
                d = self.engine.decide(DecisionContext(
                    attack_confidence=p, trust_score=st.score, trust_variance=st.variance,
                    congestion_index=ctx.congestion_index, packet_loss_rate=ctx.packet_loss_rate,
                    flow_rate_norm=min(1.0, pps / 1000), byte_rate_norm=min(1.0, bps / 10e6),
                    proto_encoded=0.33, dst_port_norm=port / 65535, is_emerging_threat=cve is not None,
                    prev_action=int(prev[i]), burst_factor=min(1.0, pps / 500), src_ip=h.ip, dst_ip=SERVER_IP))
                a = int(d.action)
                ov = self.overrides.get(i)
                if ov is not None:
                    if ov["until"] < t:
                        del self.overrides[i]
                    elif d.guardrail and d.guardrail.startswith("hard block"):
                        del self.overrides[i]          # the controller's hard-block guardrail always wins
                    else:
                        a = ov["action"]
                        overridden_flows += 1
                o = self.obs[i]
                o["p"].append(p); o["acts"].append((t, a)); o["pps"].append(pps); o["bps"].append(bps); o["ports"].append(port)
                if cve:
                    o["cve"] = cve
                o["last_decision"] = {"t": t, "p_attack": round(p, 3), "trust": round(st.score, 3),
                                      "topsis": [round(x, 3) for x in d.topsis_closeness],
                                      "ppo": [round(x, 3) for x in d.ppo_probabilities],
                                      "final": [round(x, 3) for x in d.final_scores],
                                      "controller_choice": d.action.name, "guardrail": d.guardrail,
                                      "agent_override": MitigationAction(a).name if a != int(d.action) else None}
                mbps = bps / 1e6
                offered[i] += mbps
                if a in (0, 1):
                    to_srv[i] += mbps
                elif a == 2:
                    to_srv[i] += min(mbps, 0.5)
                elif a == 3:
                    to_honey[i] += mbps
                if truth[j] and first_attack[i] < 0:
                    first_attack[i] = t
                if truth[j] and a in (2, 3, 4) and first_mitigation[i] < 0:
                    first_mitigation[i] = t
                if a != prev[i]:
                    prio, idle, acts = OF_RULE[MitigationAction(a)]
                    events.append({"t": t, "type": "decision", "host": h.name, "role": h.role, "action": MitigationAction(a).name,
                                   "p": round(p, 3), "trust": round(st.score, 3), "guardrail": d.guardrail, "emerging": cve,
                                   "rule": f"{h.switch} priority={prio} idle_timeout={idle} match=ipv4_src={h.ip} actions={acts.format(port='uplink')}"})
                prev[i] = a
                p_sum[i] += p; n_flows[i] += 1
                kind_now[i] = KINDS.index(kinds[j])
                log_attack.append(truth[j]); log_p.append(p); log_a.append(a); log_role.append(h.role); log_net.append(h.network); log_kind.append(kinds[j])

            # 3. Data plane per network: access uplinks -> spine -> service leaf
            up = np.zeros(len(sw_names))
            for i, h in enumerate(self.hosts):
                up[sw_index[h.switch]] += to_srv[i] + to_honey[i]
            up_eff = np.minimum(up, self.uplink_mbps)
            core = np.zeros(N); net_ctx = []
            for n in range(N):
                seg = slice(self.sw_offset[n], self.sw_offset[n + 1])
                core[n] = float(up_eff[seg].sum())
                core_eff = min(core[n], self.core_mbps)
                drop = float((up[seg] - up_eff[seg]).sum()) + (core[n] - core_eff)
                c = self.counters[n]
                c["bytes"] += core_eff * 1e6 / 8
                c["pkts"] += core_eff * 1e6 / 8 / 700
                c["drops"] += drop * 1e6 / 8 / 700
                self.contexts[n].record_port_stats(1, 1, int(c["pkts"]), 0, int(c["bytes"]), 0, int(c["drops"]), 0, timestamp=now)
                nc = self.contexts[n].compute_network_context(current_time=now)
                net_ctx.append({"congestion": round(nc.congestion_index, 4), "utilization": round(nc.bandwidth_utilization, 4),
                                "loss": round(nc.packet_loss_rate, 4)})

            trust_now = np.array([self.trusts[h.network].get_trust_score(h.ip, current_time=now) for h in self.hosts])
            self.trust_now = trust_now
            self.last_ctx = net_ctx
            for i in range(H):
                self.obs[i]["trust_hist"].append(trust_now[i])
            if self.agent is not None and t > 0 and t % self.agent_interval == 0:
                from src.agent.tools import SDNToolbox
                summary = self.agent.step(SDNToolbox(self, t, events))
                self.review_summaries.append({"t": t, "summary": summary})
            active = n_flows > 0
            frames.append({
                "t": t,
                "trust": np.round(trust_now, 3).tolist(),
                "action": prev.tolist(),
                "active": active.astype(int).tolist(),
                "kind": np.where(active, kind_now, 0).tolist(),
                "p": np.round(np.where(active, p_sum / np.maximum(n_flows, 1), -1), 3).tolist(),
                "uplink_mbps": np.round(up, 2).tolist(),
                "core_mbps": np.round(core, 2).tolist(),
                "context": net_ctx,
            })
            if progress and t % 10 == 0:
                print(f"  t={t:>4}s  flows this tick: {len(recs):>6}  total core load: {core.sum():9.1f} Mbps", flush=True)

        self._log_net = np.array(log_net)
        self._log_kind = np.array(log_kind)
        self._overridden_flows = overridden_flows
        return self._package(frames, events, np.array(log_attack, bool), np.array(log_p), np.array(log_a),
                             np.array(log_role), first_attack, first_mitigation)

    def _by_attack(self, atk, p, mit) -> List[Dict]:
        out = []
        for kind in ALL_ATTACKS:
            m = (self._log_kind == kind) & atk
            if not m.any():
                continue
            if kind == "port_scan":
                hosts = sum(h.role == "attacker" for h in self.hosts)
            else:
                hosts = sum(1 for h in self.hosts if h.role == "attacker" and (h.attack or "syn_flood") == kind)
            comp = sum(1 for h in self.hosts if h.role == "compromised" and
                       (kind == "web_exploit" or (h.followups and kind in ("c2_beacon", "data_exfiltration"))))
            out.append({"attack": kind, "label": ATTACK_LABEL[kind], "flows": int(m.sum()),
                        "mitigated_pct": round(float(mit[m].mean()) * 100, 2),
                        "mean_p_attack": round(float(p[m].mean()), 3),
                        "unseen_by_ids": kind in self.unseen_attacks, "attacker_hosts": hosts,
                        "compromised_hosts": comp})
        return out

    def _package(self, frames, events, atk, p, a, role, first_attack, first_mitigation) -> Dict:
        def pct(x):
            return round(float(np.mean(x)) * 100, 2) if len(x) else None
        mit, dis, stat = np.isin(a, [2, 3, 4]), np.isin(a, [3, 4]), p >= 0.5
        ttm = [int(m - f) for f, m in zip(first_attack, first_mitigation) if f >= 0 and m >= 0]
        unmitigated = int(sum(1 for f, m in zip(first_attack, first_mitigation) if f >= 0 and m < 0))
        by_role = {}
        for r in ROLES:
            m = role == r
            if m.any():
                by_role[r] = {"flows": int(m.sum()),
                              "attack_flows_mitigated_pct": pct(mit[m & atk]),
                              "benign_flows_served_pct": pct(~dis[m & ~atk])}
        final_trust = frames[-1]["trust"]
        by_network = []
        for n in range(self.n_networks):
            m = self._log_net == n
            hn = [h for h in self.hosts if h.network == n]
            by_network.append({"network": f"N{n + 1}", "hosts": len(hn), "switches": self.sw_list[n],
                               "malicious_hosts": sum(h.role in ("attacker", "compromised") for h in hn),
                               "flows": int(m.sum()), "attack_mitigation_pct": pct(mit[m & atk]),
                               "benign_served_pct": pct(~dis[m & ~atk])})
        summary = {
            "flows_total": int(len(a)), "flows_attack": int(atk.sum()), "flows_benign": int((~atk).sum()),
            "proposed": {"attack_mitigation_pct": pct(mit[atk]), "benign_served_pct": pct(~dis[~atk]),
                         "benign_blocked": int(((a == 4) & ~atk).sum())},
            "static_threshold_0_5": {"attack_mitigation_pct": pct(stat[atk]), "benign_served_pct": pct(~stat[~atk]),
                                     "benign_blocked": int((stat & ~atk).sum())},
            "by_role": by_role,
            "by_network": by_network,
            "by_attack": self._by_attack(atk, p, mit),
            "action_counts": {MitigationAction(i).name: int((a == i).sum()) for i in range(5)},
            "time_to_mitigate_s": {"mean": round(float(np.mean(ttm)), 2) if ttm else None,
                                   "max": int(max(ttm)) if ttm else None, "malicious_hosts": len(ttm) + unmitigated,
                                   "never_mitigated": unmitigated},
            "mean_final_trust": {r: round(float(np.mean([t for t, h in zip(final_trust, self.hosts) if h.role == r])), 3)
                                 for r in ROLES if any(h.role == r for h in self.hosts)},
            "ppo_model": bool(self.policy.use_sb3),
            "ahp_consistency_ratio": round(self.engine.ahp.consistency_ratio, 4),
        }
        return {
            "meta": {"mode": "scale", "title": "Context-Aware Adaptive Trust-Based Intrusion Mitigation Framework for SDN using MCDM",
                     "tick_seconds": 1, "duration": self.duration, "settings": self.settings,
                     "kinds": KINDS, "kind_labels": {k: ATTACK_LABEL.get(k, k.replace("_", " ")) for k in KINDS},
                     "actions": [x.name for x in MitigationAction], "intel_tick": self.intel_tick},
            "topology": {"hosts": [asdict(h) for h in self.hosts], "n_networks": self.n_networks,
                         "access_switches": [switch_name(n, j, self.n_networks) for n in range(self.n_networks) for j in range(self.sw_list[n])],
                         "switches_per_network": self.sw_list,
                         "hosts_per_network": self.settings["hosts_per_network"],
                         "server_ip": SERVER_IP, "honeypot_ip": HONEYPOT_IP, "controller": "one Ryu controller per network"},
            "frames": frames, "events": events, "summary": summary,
            "agent": None if self.agent is None else {
                "backend": getattr(self.agent, "name", type(self.agent).__name__),
                "interval_s": self.agent_interval, "reviews": len(self.review_summaries),
                "overrides": sum(1 for e in self.agent_log if e["kind"] == "override"),
                "flows_overridden": int(getattr(self, "_overridden_flows", 0)),
                "incidents": self.incidents, "pending_approvals": self.pending_approvals,
                "review_summaries": self.review_summaries,
                "llm_calls": getattr(self.agent, "calls", 0), "errors": getattr(self.agent, "errors", []),
            },
        }


def run_and_save_large(out_path: str = "results/simulation_trace_large.json", progress: bool = False, **kw) -> Dict:
    trace = LargeSDNSimulation(**kw).run(progress=progress)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(trace, f, separators=(",", ":"))
    return trace
