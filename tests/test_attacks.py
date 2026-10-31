"""
test_attacks.py
===============
Attack library (10 attack types), attack-mix scenarios in the large simulator,
IDS trained with unseen attack types, and the agent's probation rule.
"""

import numpy as np

from src.ids.preprocess import CANONICAL_NUMERICAL_FEATURES
from src.simulation.attack_library import sample, ALL_ATTACKS, generate_training_set
from src.simulation.large_network_sim import LargeSDNSimulation, resolve_attack_types, ensure_extended_ids
from src.agent import OfflinePlanner


def test_every_attack_type_produces_a_valid_flow():
    rng = np.random.default_rng(0)
    for kind in ALL_ATTACKS + ["benign", "flash_crowd"]:
        rec, is_attack = sample(kind, rng)
        assert is_attack == (kind in ALL_ATTACKS)
        for f in CANONICAL_NUMERICAL_FEATURES:
            assert f in rec and np.isfinite(rec[f]), (kind, f)
        assert rec["proto"] in ("tcp", "udp", "icmp")


def test_training_set_covers_requested_types():
    X, y, cat = generate_training_set(1000, 0.4, ["udp_flood", "slowloris"], seed=1)
    assert set(cat[y == 1]) == {"udp_flood", "slowloris"}
    assert int(y.sum()) == 400


def test_resolve_attack_types():
    assert resolve_attack_types("classic") is None
    assert resolve_attack_types("all") == ALL_ATTACKS
    assert resolve_attack_types("udp_flood, ssh_bruteforce") == ["udp_flood", "ssh_bruteforce"]
    try:
        resolve_attack_types("udp_flood,laser_beam")
    except ValueError:
        return
    raise AssertionError("unknown attack type accepted")


def _run(tmp_path, agent=None):
    path = ensure_extended_ids(["slowloris"], models_dir=str(tmp_path), n_samples=4000)
    sim = LargeSDNSimulation(n_hosts=80, n_switches=3, duration=70, attacker_ratio=0.25, compromised_ratio=0.0,
                             bursty_ratio=0.0, attack_types="port_scan,slowloris", unseen_attacks=["slowloris"],
                             ids_model_path=path, ppo_model_path=str(tmp_path / "none.zip"), agent=agent, seed=3)
    return sim.run()


def test_attack_mix_and_unseen_attack_with_probation(tmp_path):
    base = _run(tmp_path)
    s = {r["attack"]: r for r in base["summary"]["by_attack"]}
    assert set(s) == {"port_scan", "slowloris"}
    assert s["port_scan"]["mitigated_pct"] > 95
    assert s["slowloris"]["unseen_by_ids"] is True
    assert all(h["attack"] == "slowloris" for h in base["topology"]["hosts"] if h["role"] == "attacker")
    with_agent = _run(tmp_path, OfflinePlanner())
    a = {r["attack"]: r for r in with_agent["summary"]["by_attack"]}
    # the probation rule must catch more of the unseen low-rate attack than the framework alone
    assert a["slowloris"]["mitigated_pct"] > s["slowloris"]["mitigated_pct"]
    assert any("probation" in i["title"].lower() or "recently blocked" in i["title"].lower()
               for i in with_agent["agent"]["incidents"])
