"""
traffic_gen.py
==============
Scapy-based Synthetic Traffic & Flow Feature Vector Generator.

Translates structured ThreatSignature specifications into:
1. 28-dimensional canonical flow samples for IDS retraining.
2. Live Scapy network packet streams for Mininet testbed injection.
"""

from typing import List, Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd
import logging

from src.threat_intel.nlp_parser import ThreatSignature

logger = logging.getLogger(__name__)


class SyntheticTrafficGenerator:
    """
    Synthesizes realistic packet traces and flow feature records conforming
    to newly extracted threat signatures.
    """

    def __init__(self, random_seed: int = 42):
        self.random_seed = random_seed
        np.random.seed(random_seed)

    def generate_flow_dataframe(
        self, signature: ThreatSignature, n_samples: int = 1000
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Synthesize canonical 28-feature DataFrame rows for a given ThreatSignature.
        """
        rows = []
        min_size, max_size = signature.packet_size_range

        for _ in range(n_samples):
            # Duration based on attack type
            if signature.attack_type == "DDoS":
                dur = float(np.random.uniform(0.1, 1.5))
                spkts = int(signature.rate_threshold_pps * dur * np.random.uniform(0.9, 1.3))
                dpkts = int(np.random.randint(0, 5))
                smeansz = float(np.random.uniform(min_size, max_size))
                sbytes = int(spkts * smeansz)
                dbytes = int(dpkts * 64)
                res_bdy_len = 0
                trans_depth = 0
                synack = 0.0
                ackdat = 0.0
            elif signature.attack_type in ("RCE", "Auth_Bypass", "Directory_Traversal"):
                dur = float(np.random.uniform(0.5, 3.0))
                spkts = int(np.random.randint(15, 60))
                dpkts = int(np.random.randint(10, 40))
                smeansz = float(np.random.uniform(min_size, max_size))
                sbytes = int(spkts * smeansz)
                dbytes = int(dpkts * np.random.uniform(200, 1000))
                res_bdy_len = int(np.random.randint(2000, 25000))
                trans_depth = int(np.random.randint(3, 8))
                synack = float(np.random.uniform(0.01, 0.05))
                ackdat = float(np.random.uniform(0.01, 0.04))
            else: # Port Scan / Generic
                dur = float(np.random.uniform(0.01, 0.2))
                spkts = int(np.random.randint(1, 5))
                dpkts = 0
                smeansz = 40.0
                sbytes = int(spkts * smeansz)
                dbytes = 0
                res_bdy_len = 0
                trans_depth = 0
                synack = 0.0
                ackdat = 0.0

            service_map = {80: "http", 443: "ssl", 8080: "http", 8443: "ssl", 22: "ssh", 53: "dns"}
            service = service_map.get(signature.target_port, "none")

            row = {
                "duration": dur,
                "spkts": max(spkts, 1),
                "dpkts": max(dpkts, 0),
                "sbytes": max(sbytes, 40),
                "dbytes": max(dbytes, 0),
                "sttl": int(np.random.choice([64, 128, 255])),
                "dttl": int(np.random.choice([64, 0])),
                "sloss": int(np.random.binomial(n=max(spkts, 1), p=0.05)),
                "dloss": int(np.random.binomial(n=max(dpkts, 1), p=0.02)),
                "sload": float((sbytes * 8) / dur),
                "dload": float((dbytes * 8) / dur),
                "smeansz": smeansz,
                "dmeansz": float(dbytes / max(dpkts, 1)) if dpkts > 0 else 0.0,
                "trans_depth": trans_depth,
                "res_bdy_len": res_bdy_len,
                "sjit": float(np.random.exponential(scale=10.0)),
                "djit": float(np.random.exponential(scale=12.0)),
                "synack": synack,
                "ackdat": ackdat,
                "swin": int(np.random.choice([1024, 65535])),
                "dwin": int(np.random.choice([0, 65535])),
                "stcpb": int(np.random.randint(100000, 99999999)),
                "dtcpb": int(np.random.randint(100000, 99999999)),
                "proto": signature.protocol,
                "service": service,
            }
            rows.append(row)

        df = pd.DataFrame(rows)
        y = pd.Series(np.ones(n_samples, dtype=int), name="label")
        logger.info("Generated %d synthetic flow samples for %s (%s)", n_samples, signature.cve_id, signature.attack_type)
        return df, y

    def build_scapy_packets(
        self,
        signature: ThreatSignature,
        src_ip: str = "10.0.0.1",
        dst_ip: str = "10.0.0.2",
        count: int = 10,
    ) -> List[Any]:
        """
        Build live Scapy packet objects conforming to threat signature for Mininet transmission.
        """
        packets = []
        try:
            from scapy.all import IP, TCP, UDP, ICMP, Raw
            for _ in range(count):
                if signature.protocol == "tcp":
                    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=np.random.randint(1024, 65535), dport=signature.target_port, flags="PA")
                elif signature.protocol == "udp":
                    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=np.random.randint(1024, 65535), dport=signature.target_port)
                else:
                    pkt = IP(src=src_ip, dst=dst_ip) / ICMP()

                payload_bytes = b"SYNTHETIC_EXPLOIT_PAYLOAD_" + signature.cve_id.encode() + b"\x00" * 32
                pkt = pkt / Raw(load=payload_bytes)
                packets.append(pkt)
        except ImportError:
            logger.debug("Scapy not installed. Synthetic packets generated as metadata dictionaries.")
            for i in range(count):
                packets.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "proto": signature.protocol,
                    "dport": signature.target_port,
                    "payload_len": signature.packet_size_range[0],
                })
        return packets
