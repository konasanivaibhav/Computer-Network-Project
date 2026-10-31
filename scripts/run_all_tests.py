"""
run_all_tests.py
================
Standalone test runner for the SDN Trust-Score RL Intrusion Mitigation System.
Executes all unit and integration tests across IDS, Trust, Context, RL, Threat Intel, and Controller.
"""

import sys
import os
import time
import traceback
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def run_test_suite():
    """Execute all tests in sequence."""
    print("=" * 80)
    print("      SDN TRUST-SCORE RL INTRUSION MITIGATION - FULL TEST SUITE")
    print("=" * 80)

    test_modules = [
        ("Phase 1: IDS Feature Preprocessing & Calibration", "tests.test_ids"),
        ("Phase 2: Bayesian Dynamic Trust Engine & SQLite DB", "tests.test_trust"),
        ("Phase 3: Network Context & Telemetry Aggregator", "tests.test_context"),
        ("Phase 4: RL Gymnasium Environment & Multi-Objective Reward", "tests.test_rl_env"),
        ("Phase 5: Threat Intelligence NLP & Canary Retraining", "tests.test_threat_intel"),
        ("Phase 6: Ryu SDN Controller Flow Intelligence", "tests.test_sdn_controller"),
        ("Phase 7: MCDM (AHP + TOPSIS) Adaptive Decision Engine", "tests.test_mcdm"),
        ("Phase 8: End-to-End SDN Simulation & 3D Trace Export", "tests.test_simulation"),
        ("Phase 9: Real Dataset Loaders (UNSW-NB15, CICIDS2017)", "tests.test_datasets"),
        ("Phase 10: Large-Network & Multi-Network Simulation", "tests.test_large_simulation"),
        ("Phase 11: Agentic AI Security Analyst", "tests.test_agent"),
        ("Phase 12: Attack Library & Unseen Attacks", "tests.test_attacks"),
        ("End-to-End System Integration Pipeline", "tests.test_integration"),
    ]

    passed_count = 0
    failed_count = 0
    start_total = time.time()

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        tmp_path = Path(tmp_dir)

        for suite_name, mod_path in test_modules:
            print(f"\n[*] Running Suite: {suite_name} ({mod_path})")
            print("-" * 80)
            
            try:
                mod = __import__(mod_path, fromlist=["*"])
                # Discover test functions
                test_funcs = [
                    getattr(mod, name) for name in dir(mod)
                    if name.startswith("test_") and callable(getattr(mod, name))
                ]

                for func in test_funcs:
                    t_start = time.perf_counter()
                    try:
                        # Check if function takes tmp_path argument
                        import inspect
                        sig = inspect.signature(func)
                        if "tmp_path" in sig.parameters:
                            func(tmp_path)
                        else:
                            func()
                        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
                        print(f"  [PASS] {func.__name__:<45} ({elapsed_ms:6.1f} ms)")
                        passed_count += 1
                    except Exception as e:
                        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
                        print(f"  [FAIL] {func.__name__:<45} ({elapsed_ms:6.1f} ms)")
                        print(f"         Error: {e}")
                        traceback.print_exc()
                        failed_count += 1

            except Exception as e:
                print(f"  [ERROR] Failed to load module {mod_path}: {e}")
                traceback.print_exc()
                failed_count += 1

    total_time = time.time() - start_total
    print("\n" + "=" * 80)
    print("                           TEST RUN SUMMARY")
    print("=" * 80)
    print(f"  Total Test Cases Executed : {passed_count + failed_count}")
    print(f"  Passed                    : {passed_count} [OK]")
    print(f"  Failed                    : {failed_count}")
    print(f"  Total Duration            : {total_time:.2f} seconds")
    print("=" * 80)

    if failed_count > 0:
        print("OVERALL STATUS: FAILED (Some assertions did not pass)")
        sys.exit(1)
    else:
        print("OVERALL STATUS: ALL TESTS PASSED SUCCESSFULLY! [100% SLA COMPLIANT]")
        sys.exit(0)


if __name__ == "__main__":
    run_test_suite()
