"""
network_sim.py
==============
End-to-end SDN intrusion-mitigation simulation (no Mininet or root required).

Emulates the project's Mininet topology and runs every flow through the real
pipeline modules:

    Flow features -> Calibrated RF IDS -> Bayesian trust -> Network context
    -> PPO + AHP-TOPSIS decision engine -> OpenFlow rule -> data-plane effect

Timeline (1 tick = 1 simulated second):
    0-20    normal operation
    20-35   h2 legitimate flash crowd (benign, but the IDS finds it suspicious)
    35-55   h_atk reconnaissance port scan
    55-95   h_atk TCP SYN flood (saturates the spine link if not mitigated)
    75      threat-intel pipeline ingests a new CVE and registers a signature
    85-105  dormant IoT node h_edge is compromised and exploits that CVE
    105-120 recovery

Every decision, trust value, link load and installed rule is written to a JSON
trace that the 3D visualisation replays.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

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

LINK_CAPACITY_MBPS = 100.0
RATE_LIMIT_MBPS = 0.5      # OpenFlow meter band configured by the controller (500 kbps)
SERVER_IP = "10.0.0.3"
HONEYPOT_IP = "10.0.0.100"

# OpenFlow priority / idle timeout used by ryu_controller.py for each action
OF_RULE = {
    MitigationAction.ALLOW: (10, 60, "output:{port}"),
    MitigationAction.MONITOR: (15, 30, "output:{port},output:mirror"),
    MitigationAction.RATE_LIMIT: (20, 30, "meter:1,output:{port}"),
    MitigationAction.REDIRECT: (25, 45, "set_field:10.0.0.100->ipv4_dst,output:honeypot"),
    MitigationAction.BLOCK: (30, 120, "drop"),
}


@dataclass
class Host:
    name: str
    ip: str
    role: str
    switch: str
    is_malicious_actor: bool = False


HOSTS = [
    Host("h1", "10.0.0.1", "Trusted workstation", "s2"),
    Host("h2", "10.0.0.2", "Web app (bursty)", "s2"),
    Host("h_atk", "10.0.0.4", "Attacker", "s2", True),
    Host("h_edge", "10.0.0.5", "IoT edge node", "s2", True),
    Host("h_srv", "10.0.0.3", "Web / DB server", "s3"),
    Host("h_honey", "10.0.0.100", "Honeypot", "s3"),
]
SWITCHES = ["s1", "s2", "s3"]
LINKS = [
    ("h1", "s2"), ("h2", "s2"), ("h_atk", "s2"), ("h_edge", "s2"),
    ("s2", "s1"), ("s1", "s3"), ("s3", "h_srv"), ("s3", "h_honey"),
]
PHASES = [
    (0, 20, "Normal operation"),
    (20, 35, "Flash crowd on h2 (legitimate burst)"),
    (35, 55, "Reconnaissance: port scan from h_atk"),
    (55, 75, "TCP SYN flood from h_atk"),
    (75, 85, "Threat intel: new CVE signature registered"),
    (85, 105, "Compromised IoT node exploits the new CVE"),
    (105, 121, "Recovery"),
]


# ------------------------------------------------------------------------------
# Flow feature samplers (same distributions as generate_synthetic_flow_dataset)
# ------------------------------------------------------------------------------
def _row(**kw) -> Dict:
    dur = kw["duration"]
    kw.setdefault("sload", kw["sbytes"] * 8 / dur)
    kw.setdefault("dload", kw["dbytes"] * 8 / dur)
    kw.setdefault("smeansz", kw["sbytes"] / max(kw["spkts"], 1))
    kw.setdefault("dmeansz", kw["dbytes"] / max(kw["dpkts"], 1) if kw["dpkts"] else 0.0)
    kw["tcprtt"] = kw["synack"] + kw["ackdat"]
    kw["packet_rate"] = (kw["spkts"] + kw["dpkts"]) / dur
    kw["byte_rate"] = (kw["sbytes"] + kw["dbytes"]) / dur
    return kw


def sample_flow(kind: str, rng: np.random.Generator, dst_port: int = 80) -> Tuple[Dict, bool]:
    """Return (raw 28-feature flow record, ground_truth_is_attack)."""
    if kind == "benign":
        dur = float(rng.exponential(2.5) + 0.01)
        spkts, dpkts = int(rng.poisson(15) + 2), int(rng.poisson(20) + 2)
        sbytes = int(max(spkts * rng.normal(120, 30) + 64, 64))
        dbytes = int(max(dpkts * rng.normal(800, 200) + 128, 64))
        return _row(
            duration=dur, spkts=spkts, dpkts=dpkts, sbytes=sbytes, dbytes=dbytes,
            sttl=int(rng.choice([64, 128])), dttl=int(rng.choice([64, 56])),
            sloss=int(rng.binomial(spkts, 0.01)), dloss=int(rng.binomial(dpkts, 0.01)),
            trans_depth=int(rng.choice([1, 2, 3], p=[0.8, 0.15, 0.05])), res_bdy_len=int(rng.exponential(1500)),
            sjit=float(rng.exponential(5.0)), djit=float(rng.exponential(6.0)),
            synack=float(rng.uniform(0.01, 0.05)), ackdat=float(rng.uniform(0.01, 0.04)),
            swin=65535, dwin=65535, stcpb=int(rng.integers(100000, 99999999)), dtcpb=int(rng.integers(100000, 99999999)),
            proto="tcp", service="http",
        ), False
    if kind == "flash_crowd":
        # Legitimate surge (e.g. a sale or a backup job): complete HTTP sessions with
        # real server responses, but far more packets, bytes and jitter than usual.
        dur = float(rng.uniform(0.6, 2.5))
        spkts, dpkts = int(rng.integers(40, 160)), int(rng.integers(50, 220))
        sbytes = int(spkts * rng.normal(160, 40))
        dbytes = int(dpkts * rng.normal(1100, 200))
        if rng.random() < 0.35:
            # Server falls behind: handshakes time out and few responses come back.
            # These sessions resemble a flood, which is what makes flash crowds hard.
            dur = float(rng.uniform(0.2, 0.9))
            spkts = int(rng.integers(300, 900))
            dpkts = int(rng.integers(0, 6))
            sbytes, dbytes = spkts * int(rng.choice([128, 512])), dpkts * 64
            return _row(
                duration=dur, spkts=spkts, dpkts=dpkts, sbytes=sbytes, dbytes=dbytes,
                sttl=64, dttl=int(rng.choice([64, 0])), sloss=int(rng.binomial(spkts, 0.08)), dloss=0,
                trans_depth=1, res_bdy_len=0, sjit=float(rng.exponential(12.0)), djit=float(rng.exponential(14.0)),
                synack=0.0, ackdat=0.0, swin=65535, dwin=int(rng.choice([0, 65535])),
                stcpb=int(rng.integers(100000, 99999999)), dtcpb=int(rng.integers(100000, 99999999)),
                proto="tcp", service="http",
            ), False
        return _row(
            duration=dur, spkts=spkts, dpkts=dpkts, sbytes=max(sbytes, 64), dbytes=max(dbytes, 64),
            sttl=64, dttl=64, sloss=int(rng.binomial(spkts, 0.05)), dloss=int(rng.binomial(dpkts, 0.04)),
            trans_depth=int(rng.integers(2, 5)), res_bdy_len=int(rng.exponential(6000)),
            sjit=float(rng.exponential(12.0)), djit=float(rng.exponential(14.0)),
            synack=float(rng.uniform(0.02, 0.09)), ackdat=float(rng.uniform(0.02, 0.08)),
            swin=65535, dwin=65535, stcpb=int(rng.integers(100000, 99999999)), dtcpb=int(rng.integers(100000, 99999999)),
            proto="tcp", service="http",
        ), False
    if kind == "port_scan":
        dur = float(rng.uniform(0.001, 0.05))
        spkts = int(rng.integers(1, 3))
        return _row(
            duration=dur, spkts=spkts, dpkts=0, sbytes=spkts * 40, dbytes=0,
            sttl=int(rng.choice([64, 255, 32])), dttl=int(rng.choice([64, 0])),
            sloss=0, dloss=0, trans_depth=0, res_bdy_len=0,
            sjit=float(rng.exponential(15.0)), djit=float(rng.exponential(20.0)), synack=0.0, ackdat=0.0,
            swin=int(rng.choice([0, 1024, 65535])), dwin=int(rng.choice([0, 65535])),
            stcpb=int(rng.integers(100000, 99999999)), dtcpb=int(rng.integers(100000, 99999999)),
            proto="tcp", service="none",
        ), True
    if kind == "syn_flood":
        dur = float(rng.uniform(0.1, 1.0))
        spkts = int(rng.integers(500, 3000))
        sbytes = spkts * int(rng.choice([64, 128, 1400]))
        return _row(
            duration=dur, spkts=spkts, dpkts=int(rng.integers(0, 5)), sbytes=sbytes, dbytes=0,
            sttl=int(rng.choice([64, 255, 32])), dttl=int(rng.choice([64, 0])),
            sloss=int(rng.binomial(spkts, 0.1)), dloss=0, trans_depth=0, res_bdy_len=0,
            sjit=float(rng.exponential(15.0)), djit=float(rng.exponential(20.0)), synack=0.0, ackdat=0.0,
            swin=int(rng.choice([0, 1024, 65535])), dwin=int(rng.choice([0, 65535])),
            stcpb=int(rng.integers(100000, 99999999)), dtcpb=int(rng.integers(100000, 99999999)),
            proto="tcp", service="http",
        ), True
    if kind == "web_exploit":
        dur = float(rng.uniform(1.0, 5.0))
        spkts, dpkts = int(rng.integers(20, 80)), int(rng.integers(15, 60))
        return _row(
            duration=dur, spkts=spkts, dpkts=dpkts, sbytes=int(rng.integers(3000, 15000)), dbytes=int(rng.integers(500, 2000)),
            sttl=int(rng.choice([64, 255, 32])), dttl=int(rng.choice([64, 0])),
            sloss=int(rng.binomial(spkts, 0.1)), dloss=int(rng.binomial(dpkts, 0.05)),
            trans_depth=int(rng.integers(4, 10)), res_bdy_len=int(rng.integers(5000, 50000)),
            sjit=float(rng.exponential(15.0)), djit=float(rng.exponential(20.0)),
            synack=float(rng.uniform(0.02, 0.08)), ackdat=float(rng.uniform(0.02, 0.08)),
            swin=int(rng.choice([0, 1024, 65535])), dwin=int(rng.choice([0, 65535])),
            stcpb=int(rng.integers(100000, 99999999)), dtcpb=int(rng.integers(100000, 99999999)),
            proto="tcp", service="ssl" if dst_port in (443, 8443) else "http",
        ), True
    raise ValueError(kind)


def host_activity(host: str, t: int) -> List[Tuple[str, int, int]]:
    """Scenario script: list of (flow kind, number of flows, dst_port) for a host at tick t."""
    if host == "h1":
        return [("benign", 2, 80)]
    if host == "h2":
        return [("flash_crowd", 2, 80)] if 20 <= t < 35 else [("benign", 2, 443)]
    if host == "h_atk":
        if 35 <= t < 55:
            return [("port_scan", 3, 22)]
        if 55 <= t < 95:
            return [("syn_flood", 3, 80)]
        return []
    if host == "h_edge":
        if t < 12 and t % 3 == 0:
            return [("benign", 1, 80)]
        if 85 <= t < 105:
            return [("web_exploit", 2, 8443)]
        return []
    return []


# ------------------------------------------------------------------------------
# Simulation
# ------------------------------------------------------------------------------
class SDNSimulation:
    def __init__(
        self,
        ids_model_path: str = "models/ids_rf_calibrated.joblib",
        ppo_model_path: str = "models/rl_ppo_agent.zip",
        seed: int = 7,
        duration: int = 120,
    ):
        self.rng = np.random.default_rng(seed)
        self.duration = duration
        if not os.path.exists(ids_model_path):
            train_ids_pipeline(use_synthetic=True, n_samples=8000, n_estimators=100, save_path=ids_model_path)
        self.ids = CalibratedRFModel.load(ids_model_path)
        self.trust = BayesianDynamicTrustEngine(decay_rate_lambda=0.01)
        self.context = NetworkContextCollector(link_capacity_bps=LINK_CAPACITY_MBPS * 1e6)
        self.policy = RLPolicyEngine(model_path=ppo_model_path if os.path.exists(ppo_model_path) else None)
        # Main simulator: zero-day exploit traffic is redirected to the honeypot (h_honey)
        # so the CVE payload is captured instead of simply dropped.
        self.engine = AdaptiveDecisionEngine(policy_engine=self.policy, protected_assets={SERVER_IP},
                                             zero_day_forensics=True, monitor_uncertain=True)
        self.signatures = []           # active threat-intel signatures
        self.port_counters: Dict[Tuple[int, int], Dict[str, float]] = {}
        self.prev_action: Dict[str, int] = {}

    # -- data plane --------------------------------------------------------
    def _feed_port(self, dpid: int, port: int, mbps: float, dropped_mbps: float, t: float):
        c = self.port_counters.setdefault((dpid, port), {"bytes": 0.0, "pkts": 0.0, "drops": 0.0})
        c["bytes"] += mbps * 1e6 / 8
        c["pkts"] += mbps * 1e6 / 8 / 700
        c["drops"] += dropped_mbps * 1e6 / 8 / 700
        self.context.record_port_stats(dpid, port, int(c["pkts"]), 0, int(c["bytes"]), 0, int(c["drops"]), 0, timestamp=t)

    def _matches_signature(self, dst_port: int, proto: str) -> Optional[str]:
        for s in self.signatures:
            if s.target_port == dst_port and s.protocol == proto:
                return s.cve_id
        return None

    def run(self) -> Dict:
        frames, events = [], []
        flow_log = []  # (is_attack, p, action) for metrics and the static baseline
        t0 = 1_000.0
        host_ips = {h.name: h.ip for h in HOSTS}
        clients = [h for h in HOSTS if h.switch == "s2"]

        for t in range(self.duration + 1):
            now = t0 + t
            ctx = self.context.get_current_context()   # controller acts on last polled context

            if t == 75:
                adv = AutomatedThreatScraper(offline_fallback=True).get_synthetic_threat_fixtures()
                sig = ThreatNLPParser().parse_advisory(adv[1])
                self.signatures.append(sig)
                events.append({"t": t, "type": "intel", "host": None,
                               "text": f"Threat intel: {sig.cve_id} parsed -> {sig.attack_type} on "
                                       f"{sig.protocol.upper()}/{sig.target_port} (CVSS {sig.cvss_score}). Signature registered."})

            host_frames = {}
            offered = {}
            delivered_srv = delivered_honey = 0.0
            packets = []
            for h in clients:
                acts = host_activity(h.name, t)
                if not acts:
                    score = self.trust.get_trust_score(h.ip, current_time=now)
                    host_frames[h.name] = {"active": False, "trust": round(score, 4),
                                           "action": MitigationAction(self.prev_action.get(h.ip, 0)).name}
                    continue
                probs, mbps_offered, mbps_srv, mbps_honey = [], 0.0, 0.0, 0.0
                last_decision, kinds = None, []
                for kind, n, port in acts:
                    for _ in range(n):
                        rec, is_attack = sample_flow(kind, self.rng, port)
                        p = float(self.ids.predict_confidence(self.ids.preprocessor.transform(pd.DataFrame([rec])))[0])
                        prev_trust = self.trust.get_trust_score(h.ip, current_time=now)
                        st = self.trust.update_flow_observation(h.ip, p, current_time=now)
                        cve = self._matches_signature(port, rec["proto"])
                        # Same rate estimate as the Ryu controller: at least a 1 s window
                        window = max(1.0, rec["duration"])
                        pps = (rec["spkts"] + rec["dpkts"]) / window
                        bps = (rec["sbytes"] + rec["dbytes"]) * 8 / window
                        d = self.engine.decide(DecisionContext(
                            attack_confidence=p, trust_score=st.score, trust_variance=st.variance,
                            congestion_index=ctx.congestion_index, packet_loss_rate=ctx.packet_loss_rate,
                            flow_rate_norm=min(1.0, pps / 1000.0),
                            byte_rate_norm=min(1.0, bps / 10e6),
                            proto_encoded=0.33, dst_port_norm=port / 65535.0,
                            is_emerging_threat=cve is not None,
                            prev_action=self.prev_action.get(h.ip, 0),
                            burst_factor=min(1.0, pps / 500.0),
                            src_ip=h.ip, dst_ip=SERVER_IP,
                        ))
                        a = d.action
                        mbps = rec["byte_rate"] * 8 / 1e6
                        mbps_offered += mbps
                        if a in (MitigationAction.ALLOW, MitigationAction.MONITOR):
                            mbps_srv += mbps
                        elif a == MitigationAction.RATE_LIMIT:
                            mbps_srv += min(mbps, RATE_LIMIT_MBPS)
                        elif a == MitigationAction.REDIRECT:
                            mbps_honey += mbps
                        flow_log.append((is_attack, p, int(a), h.name))
                        probs.append(p)
                        kinds.append(kind)
                        if self.prev_action.get(h.ip) != int(a):
                            prio, idle, acts_s = OF_RULE[a]
                            events.append({
                                "t": t, "type": "decision", "host": h.name, "action": a.name,
                                "p": round(p, 3), "trust": round(st.score, 3), "prev_trust": round(prev_trust, 3),
                                "congestion": round(ctx.congestion_index, 3), "guardrail": d.guardrail,
                                "emerging": cve,
                                "topsis": [round(x, 3) for x in d.topsis_closeness],
                                "ppo": [round(x, 3) for x in d.ppo_probabilities],
                                "final": [round(x, 3) for x in d.final_scores],
                                "rule": f"s2 priority={prio} idle_timeout={idle} match=ipv4_src={h.ip},ipv4_dst={SERVER_IP} "
                                        f"actions={acts_s.format(port=2)}",
                                "text": f"{h.name} ({h.ip}) {kind.replace('_', ' ')}: P(attack)={p:.2f}, trust {prev_trust:.2f}->{st.score:.2f} "
                                        f"=> {a.name}" + (f" [guardrail: {d.guardrail}]" if d.guardrail else "")
                                        + (f" [matches {cve}]" if cve else ""),
                            })
                        self.prev_action[h.ip] = int(a)
                        last_decision = d
                offered[h.name] = mbps_offered
                delivered_srv += mbps_srv
                delivered_honey += mbps_honey
                a_last = MitigationAction(self.prev_action[h.ip])
                host_frames[h.name] = {
                    "active": True, "kind": kinds[-1], "flows": len(probs),
                    "p": round(float(np.mean(probs)), 4), "trust": round(self.trust.get_trust_score(h.ip, now), 4),
                    "action": a_last.name, "offered_mbps": round(mbps_offered, 3),
                    "to_server_mbps": round(mbps_srv, 3), "to_honeypot_mbps": round(mbps_honey, 3),
                    "final": [round(x, 3) for x in last_decision.final_scores],
                }
                packets.append({"src": h.name, "action": a_last.name, "kind": kinds[-1],
                                "rate": round(min(1.0, mbps_offered / 40.0) + 0.15, 3)})

            # Link loads (Mbps) and drops: uplink s2->s1 carries everything not dropped at s2
            up = delivered_srv + delivered_honey
            up_drop = max(0.0, up - LINK_CAPACITY_MBPS)
            up_eff = min(up, LINK_CAPACITY_MBPS)
            scale = up_eff / up if up > 0 else 1.0
            link_load = {f"{a}-{b}": 0.0 for a, b in LINKS}
            for h in clients:
                link_load[f"{h.name}-s2"] = offered.get(h.name, 0.0)
            link_load["s2-s1"] = up
            link_load["s1-s3"] = up_eff
            link_load["s3-h_srv"] = delivered_srv * scale
            link_load["s3-h_honey"] = delivered_honey * scale
            self._feed_port(2, 1, up_eff, up_drop, now)        # s2 uplink
            self._feed_port(1, 2, up_eff, 0.0, now)            # s1 -> s3
            self._feed_port(3, 1, delivered_srv * scale, 0.0, now)
            new_ctx = self.context.compute_network_context(current_time=now)

            # Legitimate service quality: share of benign demand that reached the server
            benign_offer = sum(offered.get(n, 0.0) for n in ("h1", "h2"))
            for h in ("h_srv", "h_honey"):
                host_frames[h] = {"active": True, "trust": None, "action": None}

            phase = next(lbl for a, b, lbl in PHASES if a <= t < b)
            frames.append({
                "t": t, "phase": phase,
                "hosts": host_frames,
                "links": {k: round(v, 3) for k, v in link_load.items()},
                "context": {"congestion": round(new_ctx.congestion_index, 4),
                            "utilization": round(new_ctx.bandwidth_utilization, 4),
                            "loss": round(new_ctx.packet_loss_rate, 4)},
                "packets": packets,
                "benign_offered_mbps": round(benign_offer, 3),
                "uplink_drop_mbps": round(up_drop, 3),
            })

        return self._package(frames, events, flow_log)

    def _package(self, frames, events, flow_log) -> Dict:
        arr = np.array([(a, p, act) for a, p, act, _ in flow_log], dtype=float)
        atk = arr[:, 0] == 1
        mitig = np.isin(arr[:, 2], [2, 3, 4])
        blocked_or_redir = np.isin(arr[:, 2], [3, 4])
        static_block = arr[:, 1] >= 0.5

        def pct(x):
            return round(float(x) * 100, 2)

        summary = {
            "flows_total": int(len(arr)), "flows_attack": int(atk.sum()), "flows_benign": int((~atk).sum()),
            "proposed": {
                "attack_mitigation_pct": pct(mitig[atk].mean()),
                "benign_served_pct": pct(1 - blocked_or_redir[~atk].mean()),
                "benign_blocked": int(((arr[:, 2] == 4) & ~atk).sum()),
            },
            "static_threshold_0_5": {
                "attack_mitigation_pct": pct(static_block[atk].mean()),
                "benign_served_pct": pct(1 - static_block[~atk].mean()),
                "benign_blocked": int((static_block & ~atk).sum()),
            },
            "action_counts": {MitigationAction(i).name: int((arr[:, 2] == i).sum()) for i in range(5)},
            "final_trust": {h.name: frames[-1]["hosts"][h.name]["trust"] for h in HOSTS if h.switch == "s2"},
            "ppo_model": bool(self.policy.use_sb3),
            "ahp_weights": {k: round(v, 4) for k, v in self.engine.ahp.as_dict().items()},
            "ahp_consistency_ratio": round(self.engine.ahp.consistency_ratio, 4),
        }
        return {
            "meta": {"title": "Context-Aware Adaptive Trust-Based Intrusion Mitigation Framework for SDN using MCDM",
                     "tick_seconds": 1, "duration": self.duration, "link_capacity_mbps": LINK_CAPACITY_MBPS},
            "topology": {
                "hosts": [h.__dict__ for h in HOSTS], "switches": SWITCHES,
                "links": [list(l) for l in LINKS], "controller": "c0 (Ryu)",
            },
            "phases": [{"start": a, "end": b, "label": l} for a, b, l in PHASES],
            "frames": frames, "events": events, "summary": summary,
        }


def run_and_save(out_path: str = "results/simulation_trace.json", **kw) -> Dict:
    trace = SDNSimulation(**kw).run()
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(trace, f, separators=(",", ":"))
    return trace
