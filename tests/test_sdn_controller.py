"""
test_sdn_controller.py
======================
Unit tests for the Ryu SDN Controller intelligence processing pipeline.
"""

import pytest
import time

from src.sdn.ryu_controller import SDNRLControllerApp
from src.rl.reward import MitigationAction


def test_controller_flow_intelligence_processing():
    """Verify controller executes full closed-loop intelligence on PacketIn data."""
    app = SDNRLControllerApp()
    t = 1000.0

    # 1. First Benign Flow from Client 1
    action1, p1, trust1 = app.process_flow_intelligence(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.3",
        proto_str="tcp",
        dst_port=80,
        packet_len=128,
        current_time=t,
    )
    assert action1 in (MitigationAction.ALLOW, MitigationAction.MONITOR)
    assert trust1 >= 0.50

    # 2. Burst of benign flows to establish high trust
    for _ in range(15):
        t += 0.5
        app.process_flow_intelligence(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.3",
            proto_str="tcp",
            dst_port=80,
            packet_len=128,
            current_time=t,
        )

    # 3. High-Rate Attack from Attacker (10.0.0.4)
    for _ in range(20):
        t += 0.005 # Rapid 200 pps burst
        act_atk, p_atk, trust_atk = app.process_flow_intelligence(
            src_ip="10.0.0.4",
            dst_ip="10.0.0.3",
            proto_str="udp",
            dst_port=11211,
            packet_len=1400,
            current_time=t,
        )

    # Attacker should be classified as BLOCK or REDIRECT and trust should decay
    assert act_atk in (MitigationAction.BLOCK, MitigationAction.RATE_LIMIT, MitigationAction.REDIRECT)
    assert trust_atk < 0.40
