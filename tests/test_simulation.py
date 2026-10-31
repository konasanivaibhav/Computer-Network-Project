"""
test_simulation.py
==================
End-to-end simulation: every module runs together over the emulated topology and
produces a trace the 3D viewer can replay.
"""

import json
import os

from src.simulation.network_sim import SDNSimulation, run_and_save


def test_simulation_trace_structure_and_attacker_mitigated(tmp_path):
    model_path = str(tmp_path / "ids.joblib")
    sim = SDNSimulation(ids_model_path=model_path, ppo_model_path=str(tmp_path / "none.zip"), duration=45, seed=3)
    trace = sim.run()

    assert len(trace["frames"]) == 46
    f = trace["frames"][-1]
    for key in ("hosts", "links", "context", "packets", "phase"):
        assert key in f
    # The attacker's port scan starts at t=35 and must be contained
    assert f["hosts"]["h_atk"]["action"] in ("RATE_LIMIT", "REDIRECT", "BLOCK")
    # The trusted workstation keeps high trust and is never blocked
    assert f["hosts"]["h1"]["trust"] > 0.8
    assert not any(e.get("host") == "h1" and e.get("action") == "BLOCK" for e in trace["events"])
    assert trace["summary"]["proposed"]["attack_mitigation_pct"] > 90


def test_run_and_save_writes_json(tmp_path):
    out = tmp_path / "trace.json"
    run_and_save(str(out), ids_model_path=str(tmp_path / "ids.joblib"),
                 ppo_model_path=str(tmp_path / "none.zip"), duration=10, seed=1)
    with open(out) as fh:
        data = json.load(fh)
    assert data["topology"]["switches"] == ["s1", "s2", "s3"]
    assert len(data["frames"]) == 11
