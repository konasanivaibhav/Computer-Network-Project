"""
mininet_topo.py
===============
Custom Mininet Multi-Switch SDN Testbed Topology for Intrusion Mitigation.

Topology Architecture:
- Core / Aggregation Switches: s1, s2, s3 (Open vSwitch with OpenFlow 1.3)
- Host 1 (h1): Legitimate client workstation (10.0.0.1)
- Host 2 (h2): Legitimate client workstation (10.0.0.2)
- Host 3 (h_srv): Enterprise Web & Database Server (10.0.0.3)
- Host 4 (h_atk): Malicious Threat Actor Injector (10.0.0.4)
- Host 6 (h_edge): IoT edge node, dormant then compromised in the demo scenario (10.0.0.5)
- Host 5 (h_honey): Honeynet / Quarantine Sinkhole (10.0.0.100)
"""

import sys
import os
import time
import logging

logger = logging.getLogger(__name__)

try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    from mininet.link import TCLink
    MININET_AVAILABLE = True
except ImportError:
    MININET_AVAILABLE = False
    class Topo:
        def __init__(self, *args, **kwargs):
            pass
        def addSwitch(self, name, **opts):
            return name
        def addHost(self, name, **opts):
            return name
        def addLink(self, node1, node2, **opts):
            return (node1, node2)


class SDNIntrusionTopo(Topo):
    """
    Custom 3-Switch Leaf-Spine SDN Topology with isolated Honeyport and Attacker.
    """

    def build(self):
        # 1. Add OpenFlow 1.3 Switches
        s1 = self.addSwitch("s1", protocols="OpenFlow13") # Spine / Aggregation
        s2 = self.addSwitch("s2", protocols="OpenFlow13") # Access Switch 1 (Clients & Attacker)
        s3 = self.addSwitch("s3", protocols="OpenFlow13") # Access Switch 2 (Server & Honeypot)

        # 2. Add Hosts with static IP / MAC assignments
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h_atk = self.addHost("h_atk", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
        h_edge = self.addHost("h_edge", ip="10.0.0.5/24", mac="00:00:00:00:00:05")
        
        h_srv = self.addHost("h_srv", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
        h_honey = self.addHost("h_honey", ip="10.0.0.100/24", mac="00:00:00:00:00:99")

        # 3. Add High-Performance Links with Bandwidth & Delay Constraints
        # Inter-switch links (Spine <-> Leaf): 100 Mbps, 2ms delay
        self.addLink(s1, s2, bw=100, delay="2ms", loss=0)
        self.addLink(s1, s3, bw=100, delay="2ms", loss=0)

        # Host links: 100 Mbps, 1ms delay
        self.addLink(h1, s2, bw=100, delay="1ms")
        self.addLink(h2, s2, bw=100, delay="1ms")
        self.addLink(h_atk, s2, bw=100, delay="1ms")
        self.addLink(h_edge, s2, bw=100, delay="1ms")

        self.addLink(h_srv, s3, bw=100, delay="1ms")
        self.addLink(h_honey, s3, bw=100, delay="1ms")


class ScalableSDNTopo(Topo):
    """
    Leaf-spine topology of any size for one SDN network:
    spine s1, `n_switches` access switches (s2...) sharing `n_hosts` client hosts,
    and a service leaf with the web server (10.0.0.3 style address 10.255.0.3)
    and the honeypot (10.255.0.100). Matches large-network mode of the simulation.
    """

    def build(self, n_hosts: int = 50, n_switches: int = 4):
        spine = self.addSwitch("s1", protocols="OpenFlow13")
        service = self.addSwitch(f"s{n_switches + 2}", protocols="OpenFlow13")
        self.addLink(spine, service, bw=1000, delay="1ms")
        access = []
        for j in range(n_switches):
            sw = self.addSwitch(f"s{j + 2}", protocols="OpenFlow13")
            self.addLink(sw, spine, bw=1000, delay="1ms")
            access.append(sw)
        for i in range(n_hosts):
            third, last = divmod(i, 250)
            h = self.addHost(f"h{i + 1}", ip=f"10.1.{third}.{last + 1}/8")
            self.addLink(h, access[i % n_switches], bw=100, delay="1ms")
        srv = self.addHost("h_srv", ip="10.255.0.3/8")
        honey = self.addHost("h_honey", ip="10.255.0.100/8")
        self.addLink(srv, service, bw=1000, delay="1ms")
        self.addLink(honey, service, bw=1000, delay="1ms")


def run_mininet_network(controller_ip="127.0.0.1", controller_port=6653, n_hosts=None, n_switches=4):
    """Start Mininet simulation connected to Ryu controller.

    With n_hosts set, builds ScalableSDNTopo(n_hosts, n_switches) instead of the
    default 6-host topology."""
    if not MININET_AVAILABLE:
        print("Mininet is not installed in the current environment. Please run inside Docker on Linux.")
        return

    setLogLevel("info")
    info("*** Building SDN Intrusion Mitigation Network Topology...\n")
    topo = ScalableSDNTopo(n_hosts=n_hosts, n_switches=n_switches) if n_hosts else SDNIntrusionTopo()
    
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip=controller_ip, port=controller_port),
        link=TCLink,
        autoSetMacs=True,
    )

    info("*** Starting Network & Connecting to Controller...\n")
    net.start()

    # Start simple HTTP server on h_srv
    h_srv = net.get("h_srv")
    h_srv.cmd("python3 -m http.server 80 &")
    info("*** Started HTTP Web Server on h_srv (10.0.0.3:80)\n")

    info("*** Running Interactive CLI (type 'exit' to stop)...\n")
    CLI(net)

    info("*** Stopping Network...\n")
    net.stop()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Start the Mininet SDN testbed")
    ap.add_argument("controller_ip", nargs="?", default="127.0.0.1")
    ap.add_argument("controller_port", nargs="?", type=int, default=6653)
    ap.add_argument("--hosts", type=int, default=None, help="Build a leaf-spine network with this many hosts")
    ap.add_argument("--switches", type=int, default=4, help="Access switches (with --hosts)")
    a = ap.parse_args()
    run_mininet_network(controller_ip=a.controller_ip, controller_port=a.controller_port,
                        n_hosts=a.hosts, n_switches=a.switches)
