# Incident report: Context-Aware Adaptive Trust-Based Intrusion Mitigation Framework for SDN using MCDM

Agent backend: **offline** · reviews: 12 · overrides: 184 · incidents: 6 · pending approvals: 90

## Outcome

| | Attacks mitigated | Benign flows served | Benign flows blocked |
| --- | --- | --- | --- |
| Framework + agent | 100.0% | 99.11% | 434 |
| Static block at P ≥ 0.5 | 100.0% | 98.73% | 623 |

## Incidents

### INC-001 · LOW · opened t=20s (updated t=90s) · Suspected false positives on bursty hosts

**Hosts (71):** h587, h151, h588, h592, h136, h681, h468, h747, h150, h425, h34, h143 …

**Findings:** Hosts alternate between ALLOW and BLOCK while most of their flows are clean; the pattern matches a legitimate surge in which some sessions time out.

**Recommendation:** Temporary rate limiting applied instead of hard blocks. Review IDS behaviour for overloaded-server sessions.

### INC-002 · HIGH · opened t=20s (updated t=70s) · Coordinated malicious activity in N1

**Hosts (47):** h74, h52, h187, h8, h281, h134, h284, h358, h452, h498, h351, h379 …

**Findings:** Untrusted hosts restricted in N1; most targeted ports {80: 796, 22: 4}.

**Recommendation:** Keep blocks in place; check these hosts for a shared infection vector.

### INC-003 · HIGH · opened t=30s (updated t=70s) · Coordinated malicious activity in N2

**Hosts (15):** h655, h691, h503, h501, h660, h628, h518, h698, h511, h589, h607, h692 …

**Findings:** Untrusted hosts restricted in N2; most targeted ports {80: 422, 22: 98}.

**Recommendation:** Keep blocks in place; check these hosts for a shared infection vector.

### INC-004 · HIGH · opened t=50s (updated t=90s) · Recently blocked hosts getting through with low IDS scores

**Hosts (5):** h90, h422, h628, h373, h404

**Findings:** Hosts blocked moments ago are now sending traffic the IDS rates as harmless while their trust rebuilds. This fits low-rate or previously unseen attacks (e.g. slowloris).

**Recommendation:** Keep them throttled; capture samples of this traffic and retrain the IDS on it.

### INC-005 · CRITICAL · opened t=60s (updated t=110s) · Exploitation of CVE-2024-38856

**Hosts (30):** h486, h188, h253, h263, h638, h399, h560, h463, h101, h128, h636, h605 …

**Findings:** Hosts sending traffic that matches the CVE-2024-38856 signature with high IDS confidence.

**Recommendation:** Patch the target service; keep affected hosts quarantined pending approval.

### INC-006 · HIGH · opened t=60s · Coordinated malicious activity in N3

**Hosts (3):** h712, h724, h732

**Findings:** Untrusted hosts restricted in N3; most targeted ports {80: 70, 22: 14}.

**Recommendation:** Keep blocks in place; check these hosts for a shared infection vector.

## Waiting for human approval

- t=20s · h74 (10.1.0.74): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=20s · h52 (10.1.0.52): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=20s · h187 (10.1.0.187): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=20s · h8 (10.1.0.8): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=20s · h281 (10.1.1.31): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=30s · h134 (10.1.0.134): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=30s · h284 (10.1.1.34): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=30s · h358 (10.1.1.108): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=30s · h452 (10.1.1.202): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=30s · h498 (10.1.1.248): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=30s · h351 (10.1.1.101): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=30s · h379 (10.1.1.129): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=30s · h94 (10.1.0.94): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=30s · h111 (10.1.0.111): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=30s · h131 (10.1.0.131): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=30s · h655 (10.2.0.155): **Permanent block at the access port** · Trust 0.009 and repeated blocks
- t=30s · h691 (10.2.0.191): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=30s · h503 (10.2.0.3): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=30s · h501 (10.2.0.1): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=40s · h292 (10.1.1.42): **Permanent block at the access port** · Trust 0.012 and repeated blocks
- t=40s · h82 (10.1.0.82): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=40s · h370 (10.1.1.120): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=40s · h405 (10.1.1.155): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=40s · h477 (10.1.1.227): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=40s · h132 (10.1.0.132): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=40s · h247 (10.1.0.247): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=40s · h660 (10.2.0.160): **Permanent block at the access port** · Trust 0.012 and repeated blocks
- t=40s · h518 (10.2.0.18): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=40s · h698 (10.2.0.198): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=40s · h511 (10.2.0.11): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=40s · h589 (10.2.0.89): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=50s · h222 (10.1.0.222): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=50s · h189 (10.1.0.189): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=50s · h306 (10.1.1.56): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=50s · h484 (10.1.1.234): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=50s · h360 (10.1.1.110): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=50s · h257 (10.1.1.7): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=50s · h469 (10.1.1.219): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=50s · h59 (10.1.0.59): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=50s · h155 (10.1.0.155): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=50s · h295 (10.1.1.45): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=50s · h359 (10.1.1.109): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=50s · h607 (10.2.0.107): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=50s · h692 (10.2.0.192): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=60s · h486 (10.1.1.236): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=60s · h188 (10.1.0.188): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=60s · h474 (10.1.1.224): **Permanent block at the access port** · Trust 0.012 and repeated blocks
- t=60s · h64 (10.1.0.64): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=60s · h26 (10.1.0.26): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=60s · h315 (10.1.1.65): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=60s · h466 (10.1.1.216): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=60s · h386 (10.1.1.136): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=60s · h390 (10.1.1.140): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=60s · h510 (10.2.0.10): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=60s · h524 (10.2.0.24): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=60s · h712 (10.3.0.12): **Permanent block at the access port** · Trust 0.006 and repeated blocks
- t=60s · h724 (10.3.0.24): **Permanent block at the access port** · Trust 0.006 and repeated blocks
- t=70s · h253 (10.1.1.3): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=70s · h263 (10.1.1.13): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=70s · h455 (10.1.1.205): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=70s · h22 (10.1.0.22): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=70s · h197 (10.1.0.197): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=70s · h699 (10.2.0.199): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=70s · h732 (10.3.0.32): **Permanent block at the access port** · Trust 0.012 and repeated blocks
- t=80s · h638 (10.2.0.138): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=80s · h399 (10.1.1.149): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=80s · h560 (10.2.0.60): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h463 (10.1.1.213): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h101 (10.1.0.101): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h128 (10.1.0.128): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h636 (10.2.0.136): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h605 (10.2.0.105): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h170 (10.1.0.170): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h679 (10.2.0.179): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h305 (10.1.1.55): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h490 (10.1.1.240): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h119 (10.1.0.119): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h473 (10.1.1.223): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h32 (10.1.0.32): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h447 (10.1.1.197): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h739 (10.3.0.39): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h371 (10.1.1.121): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h442 (10.1.1.192): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h334 (10.1.1.84): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h728 (10.3.0.28): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h606 (10.2.0.106): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h91 (10.1.0.91): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h750 (10.3.0.50): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h345 (10.1.1.95): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h354 (10.1.1.104): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device

## Review log

- t=10s: no action needed
- t=20s: throttled 3 flapping host(s); 7 untrusted hosts restricted in N1
- t=30s: throttled 9 flapping host(s); 17 untrusted hosts restricted in N1; 6 untrusted hosts restricted in N2
- t=40s: throttled 18 flapping host(s); 26 untrusted hosts restricted in N1; 9 untrusted hosts restricted in N2
- t=50s: throttled 24 flapping host(s); 35 untrusted hosts restricted in N1; 12 untrusted hosts restricted in N2; throttled 2 host(s) on probation
- t=60s: throttled 25 flapping host(s); 2 host(s) exploiting CVE-2024-38856; 41 untrusted hosts restricted in N1; 13 untrusted hosts restricted in N2; 3 untrusted hosts restricted in N3; throttled 1 host(s) on probation
- t=70s: throttled 22 flapping host(s); 4 host(s) exploiting CVE-2024-38856; 43 untrusted hosts restricted in N1; 14 untrusted hosts restricted in N2; 3 untrusted hosts restricted in N3; throttled 3 host(s) on probation
- t=80s: throttled 17 flapping host(s); 7 host(s) exploiting CVE-2024-38856; 43 untrusted hosts restricted in N1; 14 untrusted hosts restricted in N2; 3 untrusted hosts restricted in N3; throttled 3 host(s) on probation
- t=90s: throttled 14 flapping host(s); 13 host(s) exploiting CVE-2024-38856; 43 untrusted hosts restricted in N1; 14 untrusted hosts restricted in N2; 3 untrusted hosts restricted in N3; throttled 2 host(s) on probation
- t=100s: throttled 6 flapping host(s); 21 host(s) exploiting CVE-2024-38856; 43 untrusted hosts restricted in N1; 14 untrusted hosts restricted in N2; 3 untrusted hosts restricted in N3
- t=110s: 30 host(s) exploiting CVE-2024-38856; 43 untrusted hosts restricted in N1; 14 untrusted hosts restricted in N2; 3 untrusted hosts restricted in N3
- t=120s: 30 host(s) exploiting CVE-2024-38856; 43 untrusted hosts restricted in N1; 14 untrusted hosts restricted in N2; 3 untrusted hosts restricted in N3; throttled 3 host(s) on probation
