"""
attack_library.py
=================
Flow-level models of ten attack types (plus benign traffic) in the project's
28-feature schema, used by the large-network simulator and to train the
extended IDS model.

Attack types
------------
Classic (also in the original scenario)
    port_scan          reconnaissance: tiny SYN-only probes across ports
    syn_flood          TCP SYN flood: thousands of SYNs, no handshake completion
    web_exploit        RCE / injection payloads against the web service (CVE)
Volumetric
    udp_flood          high-rate UDP datagrams to random ports
    icmp_flood         ping flood
    dns_amplification  small spoofed DNS queries that trigger large responses
Credential / application
    ssh_bruteforce     many short SSH sessions with failed logins
    slowloris          low-rate DoS: long, almost idle HTTP connections kept open
Post-compromise
    data_exfiltration  large, long outbound transfers to an unusual port
    c2_beacon          small periodic check-ins with a command-and-control server

Each sampler returns (record, is_attack). Records match
src.ids.preprocess.CANONICAL_NUMERICAL_FEATURES + proto/service.
"""

from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from src.simulation.network_sim import sample_flow as _classic_sample, _row

CLASSIC_ATTACKS = ["port_scan", "syn_flood", "web_exploit"]
NEW_ATTACKS = ["udp_flood", "icmp_flood", "dns_amplification", "ssh_bruteforce",
               "slowloris", "data_exfiltration", "c2_beacon"]
ALL_ATTACKS = CLASSIC_ATTACKS + NEW_ATTACKS
BENIGN_KINDS = ["benign", "flash_crowd"]

# destination port used by each kind in the simulator
ATTACK_PORT = {"port_scan": 22, "syn_flood": 80, "web_exploit": 8443, "udp_flood": 123, "icmp_flood": 0,
               "dns_amplification": 53, "ssh_bruteforce": 22, "slowloris": 80, "data_exfiltration": 4443,
               "c2_beacon": 4444}

ATTACK_LABEL = {
    "port_scan": "Port scan", "syn_flood": "SYN flood", "web_exploit": "CVE exploit", "udp_flood": "UDP flood",
    "icmp_flood": "ICMP flood", "dns_amplification": "DNS amplification", "ssh_bruteforce": "SSH brute force",
    "slowloris": "Slowloris", "data_exfiltration": "Data exfiltration", "c2_beacon": "C2 beacon",
}


def _seq(rng):
    return int(rng.integers(100000, 99999999))


def sample(kind: str, rng: np.random.Generator, dst_port: Optional[int] = None) -> Tuple[Dict, bool]:
    """Sample one flow record of the given kind."""
    port = ATTACK_PORT.get(kind, 80) if dst_port is None else dst_port
    if kind in ("benign", "flash_crowd") or kind in CLASSIC_ATTACKS:
        return _classic_sample(kind, rng, port)

    if kind == "udp_flood":
        dur = float(rng.uniform(0.2, 1.0)); spkts = int(rng.integers(800, 4000))
        sbytes = spkts * int(rng.choice([512, 1024, 1400]))
        return _row(duration=dur, spkts=spkts, dpkts=0, sbytes=sbytes, dbytes=0,
                    sttl=int(rng.choice([64, 128, 255])), dttl=0, sloss=int(rng.binomial(spkts, 0.12)), dloss=0,
                    trans_depth=0, res_bdy_len=0, sjit=float(rng.exponential(2.0)), djit=0.0, synack=0.0, ackdat=0.0,
                    swin=0, dwin=0, stcpb=0, dtcpb=0, proto="udp", service="none"), True
    if kind == "icmp_flood":
        dur = float(rng.uniform(0.2, 1.0)); spkts = int(rng.integers(600, 3000))
        dpkts = int(spkts * rng.uniform(0.0, 0.3))
        return _row(duration=dur, spkts=spkts, dpkts=dpkts, sbytes=spkts * 84, dbytes=dpkts * 84,
                    sttl=int(rng.choice([64, 128, 255])), dttl=int(rng.choice([0, 64])), sloss=int(rng.binomial(spkts, 0.1)),
                    dloss=0, trans_depth=0, res_bdy_len=0, sjit=float(rng.exponential(1.5)), djit=float(rng.exponential(3.0)),
                    synack=0.0, ackdat=0.0, swin=0, dwin=0, stcpb=0, dtcpb=0, proto="icmp", service="none"), True
    if kind == "dns_amplification":
        dur = float(rng.uniform(0.5, 2.0)); spkts = int(rng.integers(80, 400)); dpkts = int(spkts * rng.uniform(0.8, 1.0))
        return _row(duration=dur, spkts=spkts, dpkts=dpkts, sbytes=spkts * int(rng.integers(60, 80)),
                    dbytes=dpkts * int(rng.integers(2500, 4000)), sttl=int(rng.choice([64, 255])), dttl=int(rng.choice([64, 128])),
                    sloss=0, dloss=int(rng.binomial(dpkts, 0.05)), trans_depth=0, res_bdy_len=0,
                    sjit=float(rng.exponential(1.0)), djit=float(rng.exponential(1.0)), synack=0.0, ackdat=0.0,
                    swin=0, dwin=0, stcpb=0, dtcpb=0, proto="udp", service="dns"), True
    if kind == "ssh_bruteforce":
        dur = float(rng.uniform(0.4, 3.0)); spkts = int(rng.integers(8, 22)); dpkts = int(rng.integers(8, 20))
        return _row(duration=dur, spkts=spkts, dpkts=dpkts, sbytes=int(rng.integers(900, 2600)), dbytes=int(rng.integers(1400, 3200)),
                    sttl=int(rng.choice([64, 128])), dttl=64, sloss=0, dloss=0, trans_depth=0, res_bdy_len=0,
                    sjit=float(rng.exponential(4.0)), djit=float(rng.exponential(4.0)),
                    synack=float(rng.uniform(0.01, 0.05)), ackdat=float(rng.uniform(0.01, 0.04)),
                    swin=int(rng.choice([29200, 64240])), dwin=int(rng.choice([28960, 65160])), stcpb=_seq(rng), dtcpb=_seq(rng),
                    proto="tcp", service="ssh"), True
    if kind == "slowloris":
        dur = float(rng.uniform(30.0, 120.0)); spkts = int(rng.integers(10, 45)); dpkts = int(rng.integers(2, 8))
        return _row(duration=dur, spkts=spkts, dpkts=dpkts, sbytes=spkts * int(rng.integers(20, 60)), dbytes=dpkts * 60,
                    sttl=int(rng.choice([64, 128])), dttl=64, sloss=0, dloss=0, trans_depth=1, res_bdy_len=0,
                    sjit=float(rng.uniform(2000, 15000)), djit=float(rng.exponential(50.0)),
                    synack=float(rng.uniform(0.01, 0.05)), ackdat=float(rng.uniform(0.01, 0.05)),
                    swin=int(rng.choice([1024, 2048])), dwin=65535, stcpb=_seq(rng), dtcpb=_seq(rng),
                    proto="tcp", service="http"), True
    if kind == "data_exfiltration":
        dur = float(rng.uniform(5.0, 30.0)); spkts = int(rng.integers(2000, 9000)); dpkts = int(spkts * rng.uniform(0.3, 0.5))
        return _row(duration=dur, spkts=spkts, dpkts=dpkts, sbytes=spkts * int(rng.integers(1200, 1460)), dbytes=dpkts * 66,
                    sttl=int(rng.choice([64, 128])), dttl=int(rng.choice([52, 64])), sloss=int(rng.binomial(spkts, 0.01)),
                    dloss=0, trans_depth=0, res_bdy_len=0, sjit=float(rng.exponential(3.0)), djit=float(rng.exponential(3.0)),
                    synack=float(rng.uniform(0.05, 0.25)), ackdat=float(rng.uniform(0.02, 0.1)),
                    swin=65535, dwin=65535, stcpb=_seq(rng), dtcpb=_seq(rng), proto="tcp", service="ssl"), True
    if kind == "c2_beacon":
        dur = float(rng.uniform(0.05, 0.4)); spkts = int(rng.integers(3, 7)); dpkts = int(rng.integers(3, 7))
        return _row(duration=dur, spkts=spkts, dpkts=dpkts, sbytes=int(rng.integers(200, 600)), dbytes=int(rng.integers(150, 900)),
                    sttl=int(rng.choice([64, 128])), dttl=int(rng.choice([48, 52])), sloss=0, dloss=0, trans_depth=1,
                    res_bdy_len=int(rng.integers(0, 600)), sjit=float(rng.exponential(2.0)), djit=float(rng.exponential(2.0)),
                    synack=float(rng.uniform(0.08, 0.3)), ackdat=float(rng.uniform(0.01, 0.05)),
                    swin=65535, dwin=65535, stcpb=_seq(rng), dtcpb=_seq(rng), proto="tcp", service="ssl"), True
    raise ValueError(f"unknown kind {kind}")


def generate_training_set(n_samples: int = 20000, attack_ratio: float = 0.3, attack_types: Optional[List[str]] = None,
                          seed: int = 42) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Labelled training data drawn from the same samplers the simulator uses."""
    rng = np.random.default_rng(seed)
    types = list(attack_types or ALL_ATTACKS)
    n_att = int(n_samples * attack_ratio)
    rows, labels, cats = [], [], []
    for _ in range(n_samples - n_att):
        kind = "flash_crowd" if rng.random() < 0.08 else "benign"
        r, _ = sample(kind, rng)
        rows.append(r); labels.append(0); cats.append("Normal")
    for i in range(n_att):
        kind = types[i % len(types)]
        r, _ = sample(kind, rng)
        rows.append(r); labels.append(1); cats.append(kind)
    return pd.DataFrame(rows), pd.Series(labels, name="label"), pd.Series(cats, name="attack_cat")
