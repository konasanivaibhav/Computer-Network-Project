"""
test_large_simulation.py
========================
Large-network mode: topology generation, multiple SDN networks, trace layout for
the 3D viewer, and the scalable Mininet topology.
"""

import json
import os
import sys

import numpy as np

from src.simulation.large_network_sim import LargeSDNSimulation, build_topology, run_and_save_large
from src.sdn.mininet_topo import ScalableSDNTopo

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_topology_roles_and_networks():
    hosts = build_topology(100, 4, 0.1, 0.05, 0.1, 120, 48, np.random.default_rng(0), n_networks=3)
    assert len(hosts) == 100
    assert sum(h.role == "attacker" for h in hosts) == 10
    assert sum(h.role == "compromised" for h in hosts) == 5
    assert {h.network for h in hosts} == {0, 1, 2}
    assert all(h.switch.startswith(f"N{h.network + 1}-s") for h in hosts)
    assert len({h.ip for h in hosts}) == 100
    for h in hosts:
        if h.role == "compromised":
            assert h.exploit_start > 48        # exploits only after threat intel registers the CVE


def test_single_network_uses_mininet_switch_names():
    hosts = build_topology(20, 3, 0.1, 0.0, 0.0, 60, 24, np.random.default_rng(1))
    assert {h.switch for h in hosts} <= {"s2", "s3", "s4"}


def test_two_network_run(tmp_path):
    sim = LargeSDNSimulation(n_hosts=40, n_switches=3, n_networks=2, attacker_ratio=0.1, compromised_ratio=0.05,
                             duration=50, ids_model_path=str(tmp_path / "ids.joblib"),
                             ppo_model_path=str(tmp_path / "none.zip"), seed=5)
    trace = sim.run()
    assert trace["meta"]["mode"] == "scale"
    assert len(trace["frames"]) == 51
    f = trace["frames"][-1]
    assert len(f["trust"]) == len(f["action"]) == 40
    assert len(f["uplink_mbps"]) == 6 and len(f["context"]) == 2
    s = trace["summary"]
    assert [r["network"] for r in s["by_network"]] == ["N1", "N2"]
    assert s["proposed"]["attack_mitigation_pct"] > 90
    assert s["mean_final_trust"]["normal"] > s["mean_final_trust"]["attacker"]
    assert any(e["type"] == "intel" for e in trace["events"])


def test_build_view_picks_scale_template(tmp_path):
    out = tmp_path / "trace.json"
    run_and_save_large(str(out), n_hosts=12, n_switches=2, duration=8,
                       ids_model_path=str(tmp_path / "ids.joblib"), ppo_model_path=str(tmp_path / "none.zip"))
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    from build_3d_view import build
    page = build(str(out), os.path.join(ROOT, "visualization", "sdn_3d_template.html"), str(tmp_path / "view.html"))
    html = open(page, encoding="utf-8").read()
    assert "Adaptive Trust SDN at Scale" in html and "__TRACE_JSON__" not in html
    data = html.split('<script id="trace" type="application/json">')[1].split("</script>")[0]
    assert json.loads(data)["meta"]["mode"] == "scale"


def test_scalable_mininet_topology_builds():
    links = []
    topo = ScalableSDNTopo()
    topo.addLink = lambda a, b, **kw: links.append((a, b))
    topo.build(n_hosts=10, n_switches=3)
    hosts_links = [l for l in links if l[0].startswith("h")]
    assert len(hosts_links) == 12                     # 10 clients + server + honeypot
    assert ("s1", "s5") in links                      # spine to service leaf


def test_networks_with_different_sizes(tmp_path):
    sim = LargeSDNSimulation(hosts_per_network=[30, 12, 6], switches_per_network=[4, 2, 1], duration=30,
                             attacker_ratio=0.1, ids_model_path=str(tmp_path / "ids.joblib"),
                             ppo_model_path=str(tmp_path / "none.zip"), seed=2)
    trace = sim.run()
    topo = trace["topology"]
    assert topo["n_networks"] == 3
    assert topo["hosts_per_network"] == [30, 12, 6]
    assert topo["switches_per_network"] == [4, 2, 1]
    assert len(topo["access_switches"]) == 7
    assert len(trace["frames"][0]["uplink_mbps"]) == 7
    for h in topo["hosts"]:
        assert h["switch"].startswith(f"N{h['network'] + 1}-")
    assert [r["hosts"] for r in trace["summary"]["by_network"]] == [30, 12, 6]
    assert [r["switches"] for r in trace["summary"]["by_network"]] == [4, 2, 1]


def test_rejects_mismatched_per_network_lists(tmp_path):
    try:
        LargeSDNSimulation(hosts_per_network=[10, 10], switches_per_network=[2],
                           ids_model_path=str(tmp_path / "ids.joblib"))
    except ValueError:
        return
    raise AssertionError("expected ValueError for one switch count with two networks")
