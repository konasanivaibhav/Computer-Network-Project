# Incident report: Context-Aware Adaptive Trust-Based Intrusion Mitigation Framework for SDN using MCDM

Agent backend: **offline** · reviews: 12 · overrides: 58 · incidents: 3 · pending approvals: 114

## Outcome

| | Attacks mitigated | Benign flows served | Benign flows blocked |
| --- | --- | --- | --- |
| Framework + agent | 97.85% | 100.0% | 0 |
| Static block at P ≥ 0.5 | 91.38% | 100.0% | 0 |

## Incidents

### INC-001 · HIGH · opened t=20s (updated t=70s) · Coordinated malicious activity in N1

**Hosts (90):** h292, h367, h387, h137, h600, h249, h452, h164, h204, h552, h334, h4 …

**Findings:** Untrusted hosts restricted in N1; most targeted ports {0: 200, 123: 200, 53: 160}.

**Recommendation:** Keep blocks in place; check these hosts for a shared infection vector.

### INC-002 · HIGH · opened t=30s (updated t=80s) · Recently blocked hosts getting through with low IDS scores

**Hosts (11):** h387, h452, h164, h47, h285, h310, h333, h522, h225, h97, h579

**Findings:** Hosts blocked moments ago are now sending traffic the IDS rates as harmless while their trust rebuilds. This fits low-rate or previously unseen attacks (e.g. slowloris).

**Recommendation:** Keep them throttled; capture samples of this traffic and retrain the IDS on it.

### INC-003 · CRITICAL · opened t=60s (updated t=110s) · Exploitation of CVE-2024-38856

**Hosts (24):** h425, h67, h471, h368, h219, h65, h262, h60, h429, h364, h560, h430 …

**Findings:** Hosts sending traffic that matches the CVE-2024-38856 signature with high IDS confidence.

**Recommendation:** Patch the target service; keep affected hosts quarantined pending approval.

## Waiting for human approval

- t=20s · h292 (10.1.1.42): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=20s · h367 (10.1.1.117): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=20s · h387 (10.1.1.137): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=20s · h137 (10.1.0.137): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=20s · h600 (10.1.2.100): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=20s · h249 (10.1.0.249): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=20s · h452 (10.1.1.202): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=20s · h164 (10.1.0.164): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=20s · h204 (10.1.0.204): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=20s · h552 (10.1.2.52): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=20s · h334 (10.1.1.84): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=30s · h4 (10.1.0.4): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=30s · h76 (10.1.0.76): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=30s · h156 (10.1.0.156): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=30s · h193 (10.1.0.193): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=30s · h319 (10.1.1.69): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=30s · h557 (10.1.2.57): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=30s · h462 (10.1.1.212): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=30s · h376 (10.1.1.126): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=30s · h326 (10.1.1.76): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=30s · h357 (10.1.1.107): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=30s · h503 (10.1.2.3): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=30s · h584 (10.1.2.84): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=40s · h47 (10.1.0.47): **Permanent block at the access port** · Trust 0.012 and repeated blocks
- t=40s · h369 (10.1.1.119): **Permanent block at the access port** · Trust 0.012 and repeated blocks
- t=40s · h454 (10.1.1.204): **Permanent block at the access port** · Trust 0.012 and repeated blocks
- t=40s · h323 (10.1.1.73): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=40s · h40 (10.1.0.40): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=40s · h294 (10.1.1.44): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=40s · h285 (10.1.1.35): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=40s · h491 (10.1.1.241): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=40s · h551 (10.1.2.51): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=40s · h558 (10.1.2.58): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=40s · h426 (10.1.1.176): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=40s · h231 (10.1.0.231): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=40s · h310 (10.1.1.60): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=40s · h354 (10.1.1.104): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=40s · h70 (10.1.0.70): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=40s · h104 (10.1.0.104): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=40s · h496 (10.1.1.246): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=50s · h89 (10.1.0.89): **Permanent block at the access port** · Trust 0.012 and repeated blocks
- t=50s · h13 (10.1.0.13): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=50s · h200 (10.1.0.200): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=50s · h385 (10.1.1.135): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=50s · h299 (10.1.1.49): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=50s · h391 (10.1.1.141): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=50s · h218 (10.1.0.218): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=50s · h306 (10.1.1.56): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=50s · h569 (10.1.2.69): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=50s · h66 (10.1.0.66): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=50s · h235 (10.1.0.235): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=50s · h297 (10.1.1.47): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=50s · h199 (10.1.0.199): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=50s · h316 (10.1.1.66): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=50s · h95 (10.1.0.95): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=50s · h223 (10.1.0.223): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=50s · h333 (10.1.1.83): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=50s · h324 (10.1.1.74): **Permanent block at the access port** · Trust 0.028 and repeated blocks
- t=50s · h239 (10.1.0.239): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=50s · h399 (10.1.1.149): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=50s · h332 (10.1.1.82): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=50s · h418 (10.1.1.168): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=50s · h468 (10.1.1.218): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=60s · h425 (10.1.1.175): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=60s · h451 (10.1.1.201): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=60s · h44 (10.1.0.44): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=60s · h448 (10.1.1.198): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=60s · h527 (10.1.2.27): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=60s · h129 (10.1.0.129): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=60s · h186 (10.1.0.186): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=60s · h277 (10.1.1.27): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=60s · h42 (10.1.0.42): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=60s · h75 (10.1.0.75): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=60s · h522 (10.1.2.22): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=60s · h225 (10.1.0.225): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=60s · h228 (10.1.0.228): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=60s · h286 (10.1.1.36): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=60s · h506 (10.1.2.6): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=60s · h581 (10.1.2.81): **Permanent block at the access port** · Trust 0.034 and repeated blocks
- t=60s · h541 (10.1.2.41): **Permanent block at the access port** · Trust 0.044 and repeated blocks
- t=70s · h67 (10.1.0.67): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=70s · h471 (10.1.1.221): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=70s · h368 (10.1.1.118): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=70s · h280 (10.1.1.30): **Permanent block at the access port** · Trust 0.012 and repeated blocks
- t=70s · h71 (10.1.0.71): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=70s · h590 (10.1.2.90): **Permanent block at the access port** · Trust 0.013 and repeated blocks
- t=70s · h437 (10.1.1.187): **Permanent block at the access port** · Trust 0.015 and repeated blocks
- t=70s · h115 (10.1.0.115): **Permanent block at the access port** · Trust 0.016 and repeated blocks
- t=70s · h97 (10.1.0.97): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=70s · h307 (10.1.1.57): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=70s · h313 (10.1.1.63): **Permanent block at the access port** · Trust 0.018 and repeated blocks
- t=70s · h579 (10.1.2.79): **Permanent block at the access port** · Trust 0.02 and repeated blocks
- t=70s · h116 (10.1.0.116): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=70s · h132 (10.1.0.132): **Permanent block at the access port** · Trust 0.023 and repeated blocks
- t=80s · h219 (10.1.0.219): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=80s · h65 (10.1.0.65): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=80s · h262 (10.1.1.12): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=80s · h60 (10.1.0.60): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=80s · h429 (10.1.1.179): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=80s · h364 (10.1.1.114): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h560 (10.1.2.60): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h430 (10.1.1.180): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h565 (10.1.2.65): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h422 (10.1.1.172): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h248 (10.1.0.248): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=90s · h537 (10.1.2.37): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h25 (10.1.0.25): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h238 (10.1.0.238): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=100s · h539 (10.1.2.39): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h428 (10.1.1.178): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h206 (10.1.0.206): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h142 (10.1.0.142): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h257 (10.1.1.7): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device
- t=110s · h259 (10.1.1.9): **Quarantine VLAN and re-image** · Host exploited CVE-2024-38856; likely compromised device

## Review log

- t=10s: no action needed
- t=20s: 17 untrusted hosts restricted in N1
- t=30s: 23 untrusted hosts restricted in N1; throttled 3 host(s) on probation
- t=40s: 41 untrusted hosts restricted in N1
- t=50s: 58 untrusted hosts restricted in N1; throttled 3 host(s) on probation
- t=60s: 1 host(s) exploiting CVE-2024-38856; 76 untrusted hosts restricted in N1; throttled 1 host(s) on probation
- t=70s: 4 host(s) exploiting CVE-2024-38856; 81 untrusted hosts restricted in N1; throttled 5 host(s) on probation
- t=80s: 10 host(s) exploiting CVE-2024-38856; 79 untrusted hosts restricted in N1; throttled 2 host(s) on probation
- t=90s: 16 host(s) exploiting CVE-2024-38856; 79 untrusted hosts restricted in N1; throttled 2 host(s) on probation
- t=100s: 19 host(s) exploiting CVE-2024-38856; 79 untrusted hosts restricted in N1; throttled 1 host(s) on probation
- t=110s: 24 host(s) exploiting CVE-2024-38856; 79 untrusted hosts restricted in N1; throttled 5 host(s) on probation
- t=120s: 24 host(s) exploiting CVE-2024-38856; 79 untrusted hosts restricted in N1; throttled 2 host(s) on probation
