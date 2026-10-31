"""
collector.py
============
Real-time SDN Network Context & Telemetry Collector.

Monitors:
- Port-level bandwidth utilization and link capacity saturation.
- Network Congestion Index C_net in [0, 1].
- Switch flow table occupancy and active flow count.
- Packet drop / loss rates across OpenFlow switches.
- Telemetry rolling window statistics for RL state conditioning.
"""

import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class SwitchPortStats:
    """Telemetry snapshot for an individual OpenFlow switch port."""
    dpid: int
    port_no: int
    rx_packets: int = 0
    tx_packets: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    timestamp: float = field(default_factory=time.time)


@dataclass
class NetworkContextState:
    """Aggregated network health and QoS telemetry."""
    congestion_index: float = 0.0     # C_net in [0, 1]
    packet_loss_rate: float = 0.0     # Dropped packets / total packets
    active_flow_count: int = 0        # Total active flow table entries
    bandwidth_utilization: float = 0.0 # Ratio of consumed to max link capacity
    avg_latency_ms: float = 2.0       # Estimated control/data plane RTT
    timestamp: float = field(default_factory=time.time)

    def to_vector(self) -> np.ndarray:
        """Normalized 4-dim context vector for RL state input."""
        return np.array([
            float(np.clip(self.congestion_index, 0.0, 1.0)),
            float(np.clip(self.packet_loss_rate, 0.0, 1.0)),
            float(np.clip(self.active_flow_count / 1000.0, 0.0, 1.0)),
            float(np.clip(self.bandwidth_utilization, 0.0, 1.0)),
        ], dtype=np.float32)


class NetworkContextCollector:
    """
    Collector and rolling-window aggregator for SDN data-plane statistics.
    Processes OpenFlow OFPPortStatsReply and OFPFlowStatsReply events.
    """

    def __init__(
        self,
        link_capacity_bps: float = 100_000_000.0, # 100 Mbps standard Mininet link
        window_size_seconds: float = 5.0,
        congestion_threshold_util: float = 0.75,
    ):
        """
        Initialize Collector.

        Args:
            link_capacity_bps: Default capacity of physical/virtual SDN links (bps).
            window_size_seconds: Rolling window interval for delta computations.
            congestion_threshold_util: Bandwidth ratio above which link is congested.
        """
        self.link_capacity_bps = link_capacity_bps
        self.window_size_seconds = window_size_seconds
        self.congestion_threshold_util = congestion_threshold_util

        # Historical port snapshots: (dpid, port_no) -> List[SwitchPortStats]
        self._port_history: Dict[Tuple[int, int], List[SwitchPortStats]] = {}
        self._active_flows: Dict[int, int] = {} # dpid -> count
        self._current_context = NetworkContextState()

    def record_port_stats(
        self,
        dpid: int,
        port_no: int,
        rx_packets: int,
        tx_packets: int,
        rx_bytes: int,
        tx_bytes: int,
        rx_dropped: int,
        tx_dropped: int,
        timestamp: Optional[float] = None,
    ) -> None:
        """Record raw OpenFlow port statistics reply from a switch."""
        now = timestamp if timestamp is not None else time.time()
        key = (dpid, port_no)
        stat = SwitchPortStats(
            dpid=dpid,
            port_no=port_no,
            rx_packets=rx_packets,
            tx_packets=tx_packets,
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
            rx_dropped=rx_dropped,
            tx_dropped=tx_dropped,
            timestamp=now,
        )

        if key not in self._port_history:
            self._port_history[key] = []
        self._port_history[key].append(stat)

        # Evict samples older than window_size_seconds
        cutoff = now - (self.window_size_seconds * 2)
        self._port_history[key] = [s for s in self._port_history[key] if s.timestamp >= cutoff]

    def update_flow_count(self, dpid: int, active_count: int) -> None:
        """Update active flow table count for a switch."""
        self._active_flows[dpid] = active_count

    def compute_network_context(self, current_time: Optional[float] = None) -> NetworkContextState:
        """
        Compute aggregate real-time network context metrics across all active ports.
        """
        now = current_time if current_time is not None else time.time()
        total_delta_bytes = 0.0
        total_delta_packets = 0.0
        total_delta_drops = 0.0
        active_ports = 0

        for (dpid, port_no), history in self._port_history.items():
            if len(history) < 2:
                continue

            # Compute delta between oldest and newest in window
            oldest = history[0]
            newest = history[-1]
            dt = max(0.001, newest.timestamp - oldest.timestamp)

            delta_bytes = max(0, (newest.tx_bytes + newest.rx_bytes) - (oldest.tx_bytes + oldest.rx_bytes))
            delta_pkts = max(0, (newest.tx_packets + newest.rx_packets) - (oldest.tx_packets + oldest.rx_packets))
            delta_drops = max(0, (newest.tx_dropped + newest.rx_dropped) - (oldest.tx_dropped + oldest.rx_dropped))

            total_delta_bytes += delta_bytes / dt
            total_delta_packets += delta_pkts / dt
            total_delta_drops += delta_drops / dt
            active_ports += 1

        # Aggregate metrics
        if active_ports > 0:
            avg_throughput_bps = (total_delta_bytes / active_ports) * 8.0
            utilization = avg_throughput_bps / self.link_capacity_bps
            loss_rate = (total_delta_drops / (total_delta_packets + 1e-6))
        else:
            utilization = 0.05 # Baseline nominal utilization
            loss_rate = 0.0

        # Congestion Index calculation: non-linear sigmoidal ramp
        congestion_index = 1.0 / (1.0 + np.exp(-10.0 * (utilization - self.congestion_threshold_util)))

        total_active_flows = sum(self._active_flows.values()) if self._active_flows else 10

        self._current_context = NetworkContextState(
            congestion_index=float(np.clip(congestion_index, 0.0, 1.0)),
            packet_loss_rate=float(np.clip(loss_rate, 0.0, 1.0)),
            active_flow_count=int(total_active_flows),
            bandwidth_utilization=float(np.clip(utilization, 0.0, 1.0)),
            avg_latency_ms=float(1.5 + (congestion_index * 15.0)),
            timestamp=now,
        )
        return self._current_context

    def get_current_context(self) -> NetworkContextState:
        """Retrieve latest cached network context state."""
        return self._current_context
