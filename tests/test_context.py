"""
test_context.py
===============
Unit tests for NetworkContextCollector and OpenFlow telemetry aggregation.
"""

import time
import pytest
import numpy as np

from src.context.collector import NetworkContextCollector, SwitchPortStats, NetworkContextState


def test_context_collector_empty():
    """Verify default initial context state when no ports are registered."""
    collector = NetworkContextCollector()
    ctx = collector.compute_network_context()
    
    assert ctx.congestion_index >= 0.0
    assert ctx.packet_loss_rate == 0.0
    vec = ctx.to_vector()
    assert vec.shape == (4,)
    assert not np.isnan(vec).any()


def test_context_collector_throughput_and_congestion():
    """Verify throughput and non-linear congestion index ramp under heavy link load."""
    collector = NetworkContextCollector(link_capacity_bps=10_000_000.0, congestion_threshold_util=0.70)
    
    t0 = 1000.0
    # Initial sample at t=0
    collector.record_port_stats(
        dpid=1, port_no=1,
        rx_packets=1000, tx_packets=1000,
        rx_bytes=100_000, tx_bytes=100_000,
        rx_dropped=0, tx_dropped=0,
        timestamp=t0,
    )

    # Heavy burst at t=1.0 second (9 Mbps load on 10 Mbps link -> 90% utilization)
    t1 = t0 + 1.0
    collector.record_port_stats(
        dpid=1, port_no=1,
        rx_packets=8000, tx_packets=8000,
        rx_bytes=600_000, tx_bytes=600_000, # Delta = 1,000,000 bytes = 8 Mbps
        rx_dropped=50, tx_dropped=50,
        timestamp=t1,
    )

    ctx = collector.compute_network_context(current_time=t1)
    
    assert ctx.bandwidth_utilization > 0.70
    assert ctx.congestion_index > 0.70 # Saturated link triggers high congestion
    assert ctx.packet_loss_rate > 0.0
    
    vec = ctx.to_vector()
    assert vec[0] > 0.70 # Congestion element
