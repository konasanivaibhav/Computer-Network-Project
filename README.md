# Context-Aware Adaptive Trust-Based Intrusion Mitigation Framework for Software Defined Networks using Multi-Criteria Decision Making

> **An adaptive Software-Defined Networking security framework that combines Machine Learning-based Intrusion Detection, Bayesian Device Trust Scoring, real-time network context, Reinforcement Learning (PPO), Multi-Criteria Decision Making (AHP + TOPSIS) and Automated Threat Intelligence.**

**Team:** Konasani Vaibhav (24BCE0419) · Surya Dev Mor (24BCE2004) · Narayan (24BCE0712)

▶ **3D simulation:** open `visualization/sdn_3d_simulation.html` in a browser (see Module 8 below).

---

First, we have a Calibrated Random Forest IDS. It takes 28 network-flow features and predicts whether traffic is benign or malicious. Instead of only giving a yes/no result, Platt calibration gives us a reliable attack probability. We evaluate it using Accuracy, Precision, Recall, Specificity, FPR, F1, ROC-AUC, PR-AUC, Brier Score and ECE.

Second, we have implemented a Bayesian Dynamic Device Trust Engine. The IDS gives us the current attack confidence, while the trust engine maintains the historical behaviour of each device using a Beta distribution. Good behaviour increases trust, malicious behaviour decreases trust, and exponential time decay ensures that old behaviour becomes less important over time.

We demonstrate this using four different device profiles: a trusted workstation, a web server with bursty traffic, a compromised attacker, and an inactive device. Their trust scores dynamically converge differently.

We also store the trust history and audit information in SQLite. Therefore, the 25% milestone is computable: we can train the IDS, calculate actual performance metrics, classify sample traffic, update device trust scores, and display the results.

The next phases will use these two outputs—attack confidence and device trust—as inputs to the SDN context and PPO reinforcement-learning system, which will eventually select adaptive actions such as Allow, Monitor, Rate Limit, Redirect, or Block.”

## 📌 Project Overview

Modern networks face continuously changing cyber threats, making traditional **detect-and-block** security mechanisms insufficient.

This project proposes an adaptive SDN security architecture that:

1. Detects malicious network traffic using a **Calibrated Random Forest Intrusion Detection System (IDS)**.
2. Maintains a dynamic **Bayesian trust score for every host/device**.
3. Collects real-time **network context** such as bandwidth, active flows, and packet loss.
4. Uses **Proximal Policy Optimization (PPO)** to learn a mitigation policy.
5. Ranks the five mitigation actions with **AHP-weighted TOPSIS (Multi-Criteria Decision Making)** and fuses that ranking with the PPO policy, under operator guardrails.
6. Automatically collects new threat intelligence and supports **continuous model retraining**.
7. Applies the selected mitigation action through a **Ryu OpenFlow 1.3 SDN controller** in a **Mininet** network environment.
8. Replays the whole closed loop in an **interactive 3D simulation**.

The overall objective is to move from a static:

```text
Attack → Block
```

approach toward:

```text
Network Traffic
      ↓
Attack Detection
      ↓
Device Trust
      ↓
Network Context
      ↓
Adaptive Decision
      ↓
Allow / Monitor / Rate Limit / Redirect / Block
```

---

# 🎯 Project Objectives

### Primary Objectives

* Develop a machine-learning-based network intrusion detection system.
* Generate calibrated attack probabilities rather than only binary predictions.
* Maintain dynamic trust scores for individual network devices.
* Incorporate network conditions into security decisions.
* Train a PPO reinforcement-learning agent for adaptive mitigation.
* Integrate the security intelligence with an SDN controller.
* Support automated threat-intelligence collection and model updates.
* Provide a reproducible simulation environment using Mininet.

---

# 🏗️ System Architecture

```text
                         ┌──────────────────────────┐
                         │      Network Traffic     │
                         │   Real / Mininet Flows   │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                    ┌────────────────────────────────┐
                    │ MODULE 1: CALIBRATED IDS       │
                    │                                │
                    │ Random Forest + Platt          │
                    │ Probability Calibration        │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                         Attack Probability
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │ MODULE 2: DEVICE TRUST         │
                    │                                │
                    │ Bayesian Beta Distribution     │
                    │ + Exponential Time Decay       │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                              Trust Score
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │ MODULE 3: NETWORK CONTEXT      │
                    │                                │
                    │ Bandwidth / Active Flows /     │
                    │ Packet Loss / QoS              │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │ MODULE 4: PPO RL AGENT         │
                    │                                │
                    │ Adaptive Mitigation Decision   │
                    └───────────────┬────────────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 ▼                  ▼                  ▼
              ALLOW              MONITOR             BLOCK
                 │                  │                  │
                 └──────────────────┼──────────────────┘
                                    ▼
                    ┌────────────────────────────────┐
                    │ MODULE 6: RYU SDN CONTROLLER   │
                    │          + MININET              │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                              SDN SWITCHES


        ┌─────────────────────────────────────────────┐
        │ MODULE 5: AUTOMATED THREAT INTELLIGENCE    │
        │                                             │
        │ CVEs → NLP → Attack Signatures → Testing   │
        │ → Validation → Model Retraining             │
        └─────────────────────────────────────────────┘
```

---

# 🔬 Six Core Modules

## Module 1 — Calibrated Random Forest IDS

### Purpose

Detect whether a network flow is benign or malicious and produce a **calibrated attack probability**.

### Pipeline

```text
Raw Network Data
      ↓
Preprocessing
      ↓
28 Network Features
      ↓
Feature Scaling / Balancing
      ↓
Random Forest
      ↓
Platt Sigmoid Calibration
      ↓
Attack Probability
```

### Main files

```text
src/ids/
├── preprocess.py
├── train_rf.py
└── evaluator.py
```

### Key output

```text
Attack Probability = 0.94
Classification = MALICIOUS
```

The IDS is evaluated using:

* Accuracy
* Precision
* Recall / TPR
* Specificity / TNR
* False Positive Rate
* F1-score
* ROC-AUC
* PR-AUC
* Brier Score
* Expected Calibration Error (ECE)

---

# 🔐 Module 2 — Bayesian Dynamic Device Trust

### Purpose

Determine how trustworthy a device is based on its historical and current behaviour.

The trust engine uses a **Beta distribution**:

$$
T = \frac{\alpha}{\alpha+\beta}
$$

where:

* `α` represents evidence of trustworthy behaviour.
* `β` represents evidence of suspicious/malicious behaviour.

### Example

```text
Normal behaviour
       ↓
Trust increases

Malicious behaviour
       ↓
Trust decreases
```

### Time Decay

Old observations gradually lose influence.

This allows the system to respond when a previously trusted device becomes compromised.

### Main files

```text
src/trust/
├── trust_engine.py
└── db_manager.py
```

### Database

SQLite stores:

* Device identity
* Timestamp
* Attack probability
* Alpha
* Beta
* Trust score
* Trust history/audit information

---

# 📊 Module 3 — Real-Time Network Context

### Purpose

Security decisions should not depend only on the IDS.

The system also considers the current state of the network.

### Collected information

* Available bandwidth
* Active flows
* Packet loss
* Network/QoS conditions

### Main file

```text
src/context/
└── collector.py
```

### Example

```text
Attack Probability = 90%
Trust Score         = 20%
Network Load        = High
Packet Loss         = Increasing
```

These values are provided to the decision-making layer.

---

# 🤖 Module 4 — PPO Reinforcement Learning

### Purpose

Select the most appropriate mitigation action instead of automatically blocking every suspicious flow.

### PPO

**Proximal Policy Optimization (PPO)** is used as the reinforcement-learning algorithm.

### Possible actions

| Action | Meaning    |
| ------ | ---------- |
| `0`    | Allow      |
| `1`    | Monitor    |
| `2`    | Rate Limit |
| `3`    | Redirect   |
| `4`    | Block      |

### Decision example

```text
Attack Probability = 0.35
Trust Score = 0.70
Network = Normal

             ↓

           PPO

             ↓

          MONITOR
```

Another example:

```text
Attack Probability = 0.99
Trust Score = 0.05

             ↓

           PPO

             ↓

           BLOCK
```

### Main files

```text
src/rl/
├── sdn_env.py
├── reward.py
├── train_ppo.py
└── policy_infer.py
```

---

# 🌐 Module 5 — Automated Threat Intelligence

### Purpose

Keep the security system aware of newly discovered vulnerabilities and attacks.

### Pipeline

```text
Threat Intelligence Sources
          ↓
       Scraping
          ↓
     NLP / Regex
          ↓
 Attack Signature Extraction
          ↓
   Synthetic Traffic
          ↓
       Testing
          ↓
 Model Validation
          ↓
      Retraining
```

### Sources

The system is designed to work with threat-intelligence sources including:

* NVD
* CISA KEV
* Exploit-DB

### Main files

```text
src/threat_intel/
├── scraper.py
├── nlp_parser.py
├── traffic_gen.py
├── retrainer.py
└── scheduler.py
```

---

# 🖧 Module 6 — Ryu SDN Controller & Mininet

### Purpose

Connect the security intelligence to an actual SDN network simulation.

### Components

**Ryu**

Acts as the SDN controller and communicates with switches using OpenFlow.

**Mininet**

Provides the virtual network environment containing hosts and switches.

### Main files

```text
src/sdn/
├── ryu_controller.py
├── mininet_topo.py
└── traffic_injector.py
```

### Complete flow

```text
Mininet Host
     ↓
Network Traffic
     ↓
Flow Statistics
     ↓
IDS
     ↓
Trust Engine
     ↓
PPO
     ↓
Ryu Controller
     ↓
OpenFlow Rule
     ↓
SDN Switch
```

---

# 🧮 Module 7 — Multi-Criteria Decision Making (AHP + TOPSIS)

### Purpose

Choose the mitigation action by weighing several criteria explicitly, so every decision can be explained, and combine that with what the PPO agent has learned.

### How a decision is made

```text
Attack probability, trust, congestion, emerging-threat flag
                         ↓
        5 × 5 decision matrix (actions × criteria)
                         ↓
       AHP criterion weights  →  TOPSIS closeness C(a)
                         ↓
   Final(a) = (1 − λ) · C(a) + λ · π_PPO(a | s)     (λ = 0.4)
                         ↓
                    Guardrails
                         ↓
   Allow / Monitor / Rate Limit / Redirect / Block
```

### Criteria and AHP weights

Risk combines both evidence sources: `risk = 0.65 · P(attack) + 0.35 · (1 − trust)`.

| Criterion | Type | Meaning | AHP weight |
| --- | --- | --- | --- |
| `threat_containment` | benefit | Share of the expected attack the action stops (risk × containment) | 0.427 |
| `service_availability` | benefit | Expected legitimate service the action preserves | 0.273 |
| `trust_consistency` | benefit | How well the action's severity matches the device's distrust | 0.173 |
| `network_cost` | cost | Controller / mirroring overhead plus load forwarded during congestion | 0.076 |
| `forensic_value` | benefit | Intelligence gained (mirroring, honeypot), doubled for emerging threats | 0.051 |

The pairwise judgements (Saaty 1–9 scale) give a **consistency ratio of 0.0218** (it must be below 0.10).

TOPSIS uses the criterion values directly (`normalization="none"`) because they already share a 0–1 scale. Classic vector normalisation rescales each column on its own, which removes the risk level and recommends Block even at a 2 % attack probability.

### Guardrails

| Rule | Effect |
| --- | --- |
| Zero-day forensics (optional, `zero_day_forensics=True`; on in both simulators) | Flow matches a newly registered CVE and P ≥ 0.5 → Redirect to the honeypot, so the exploit is contained and its payload captured |
| Hard block | P(attack) ≥ 0.95 and trust < 0.20 → Block |
| Trusted host | trust ≥ 0.80 and the fusion picks Block (no zero-day match) → Rate Limit |
| Monitoring (optional, `monitor_uncertain=True`; on in both simulators) | a flow the framework would Allow is Monitored instead when (a) the device is new or long idle (trust variance > 0.02, i.e. too little history to trust yet) or (b) the IDS score is ambiguous (0.35 ≤ P < 0.65) |
| Protected asset | a suspicious flow (P ≥ 0.5) to the server is never simply allowed → at least Monitor |
| Allow-list | infrastructure on the allow-list is never auto-blocked |

**What Monitor does.** The flow is forwarded normally, and the switch also mirrors a copy to a capture/analysis port (`output:<port>, output:4` in the Ryu controller, priority 15, idle timeout 30 s), while the IDS keeps scoring the flow and the trust engine keeps building history. Nothing is dropped or slowed, so monitoring never hurts legitimate users. In the 3D views a monitored host is blue and sends extra blue (mirrored) packets towards the analyser. Monitoring only ever replaces an Allow, so the attacks-stopped and benign-served numbers are unchanged.

In the main simulation every host starts in Monitor (no history yet) and moves to Allow after a few seconds of clean traffic; during the flash crowd, h2's ambiguous flows are monitored rather than blocked. In the 750-host run of Module 10, 412 of 750 hosts are monitored at t = 0, 43 after 10 s and none after 40 s (2,795 monitored host-seconds in total: 2,350 normal, 308 bursty, 121 later-compromised hosts).

**Honeypot in the 3D views.** When a flow matches a newly registered CVE, the switch rewrites its destination to the honeypot (`h_honey`, 10.0.0.100) instead of dropping it, so the server stays safe and the exploit is recorded. In the main view, h_honey glows purple and a side-panel card shows the source host, flows captured and data recorded (t = 85–104 s, h_edge's exploit). In the large views every network has its own honeypot next to its server; it glows while capturing, and a table lists the hosts being redirected per network (e.g. up to 32 compromised hosts at once in the 1,600-host run).

### Main files

```text
src/mcdm/
├── ahp.py               # AHP weights + consistency ratio
├── topsis.py            # TOPSIS ranking
└── decision_engine.py   # PPO + AHP-TOPSIS fusion and guardrails
```

### Policy comparison (held-out episodes)

`python scripts/evaluate_policies.py --steps 5000 --seed 2026` on the RL environment, which now includes realistic IDS noise (12 % of benign flows are scored as suspicious, 15 % of attacks are stealthy):

| Strategy | Mean reward | Attacks stopped | Benign availability | Benign disrupted |
| --- | --- | --- | --- | --- |
| Static detect-and-block | 1.038 | 92.5% | 88.7% | 11.3% |
| Rule-based trust policy | 1.225 | 78.6% | 98.9% | 1.1% |
| AHP-TOPSIS (MCDM only) | 0.654 | 99.8% | 100.0% | 5.6% |
| PPO agent | 1.552 | 99.8% | 99.9% | 0.1% |
| Hybrid PPO + AHP-TOPSIS (proposed) | 1.540 | 99.9% | 99.9% | 0.4% |

The trained PPO agent and the hybrid both stop almost all attacks while keeping legitimate traffic flowing; the fixed 0.5 threshold disrupts about 11 % of benign flows. AHP-TOPSIS alone is safe but cautious: it prefers Monitor and Rate Limit in uncertain cases, which the reward function scores lower.

---

# 🎬 Module 8 — End-to-End Simulation & 3D Visualisation

### Purpose

Run every module together over the project's topology without needing Mininet or root, and show the outcome in 3D.

`src/simulation/network_sim.py` emulates the Mininet topology (s1 spine, s2/s3 access, h1, h2, h_atk, h_edge, h_srv, h_honey) and pushes every flow through the real modules: calibrated RF IDS → Bayesian trust → network-context collector (fed with port counters) → PPO + AHP-TOPSIS decision engine → OpenFlow rule → data-plane effect (drop, meter, redirect, mirror).

### Scenario (1 tick = 1 simulated second)

| Time | Event |
| --- | --- |
| 0–20 s | Normal operation |
| 20–35 s | h2 flash crowd: legitimate, but a third of its sessions look like a flood |
| 35–55 s | h_atk port scan |
| 55–95 s | h_atk TCP SYN flood |
| 75 s | Threat intel parses CVE-2024-38856 and registers a TCP/8443 signature |
| 85–105 s | Dormant IoT node h_edge is compromised and exploits that CVE; its exploit traffic is redirected to the honeypot h_honey for forensic capture |
| 105–120 s | Recovery |

### Result of the default run (seed 7)

| | Attacks mitigated | Benign flows served | Benign flows blocked |
| --- | --- | --- | --- |
| Proposed framework | 100.0% | 98.16% | 9 |
| Static block at P ≥ 0.5 | 100.0% | 97.95% | 10 |

708 flows were scored (220 attack, 488 benign). On this scenario both strategies are close because the IDS is almost perfectly confident on the synthetic flows; the benchmark above, with realistic IDS noise, is where the adaptive policy separates from a fixed threshold.

### Run it

```bash
python scripts/run_sdn_simulation.py   # writes results/simulation_trace.json and prints every decision
python scripts/build_3d_view.py        # writes visualization/sdn_3d_simulation.html
```

Open `visualization/sdn_3d_simulation.html` in a browser (it loads three.js from a CDN). Drag to orbit, scroll to zoom, and use the timeline to jump between phases. Packets are coloured by the action applied to them: blocked packets burst at s2, redirected ones go to the honeypot, and each new rule sends a pulse from the Ryu controller to the switch.

---

# 📂 Module 9 — Training on Real Datasets (UNSW-NB15, CICIDS2017)

### Purpose

Train and evaluate the IDS on public datasets instead of the synthetic generator, and run the whole decision pipeline on real flows.

`src/ids/datasets.py` detects the dataset from its columns and maps it onto the 28-feature schema:

| Dataset | Files | Notes |
| --- | --- | --- |
| UNSW-NB15 (partitioned) | `UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv` | All 28 features available |
| UNSW-NB15 (original) | `UNSW-NB15_1.csv` … `_4.csv` (no header row) | Header added automatically |
| CICIDS2017 | `*.pcap_ISCX.csv` (MachineLearningCVE or TrafficLabelling) | TTL, loss, handshake timing, HTTP depth and sequence numbers are not measured; they are imputed with training medians. Durations converted from µs to s; `Infinity` values handled |
| Canonical | any CSV with the project's column names + `label` | |

Large datasets are handled with `--max_rows` (stratified sample that keeps every attack type), `--rows_per_file`, and a folder or glob for multiple CSVs.

### Get the data

* UNSW-NB15: [official page](https://research.unsw.edu.au/projects/unsw-nb15-dataset). The two partitioned CSVs are also mirrored on GitHub, e.g. [Nir-J/ML-Projects](https://github.com/Nir-J/ML-Projects/tree/master/UNSW-Network_Packet_Classification).
* CICIDS2017: [official page](https://www.unb.ca/cic/datasets/ids-2017.html) (download `MachineLearningCSV.zip`).

Put the files in `data/raw/` (ignored by git), or download the same files used for the results below with one command:

```bash
python scripts/download_datasets.py            # UNSW-NB15 train + test (~46 MB)
python scripts/download_datasets.py --cicids   # also the CICIDS2017 Friday DDoS file (~92 MB)
```

### Run

```bash
# Train + evaluate on UNSW-NB15 with its official train/test split
python scripts/train_on_dataset.py --train data/raw/UNSW_NB15_training-set.csv --test data/raw/UNSW_NB15_testing-set.csv --name unsw_nb15

# CICIDS2017: a whole folder of day files, sampled to 300k rows, 25 % held out
python scripts/train_on_dataset.py --train data/raw/CICIDS2017 --max_rows 300000 --name cicids2017

# Full pipeline (IDS -> trust -> PPO + AHP-TOPSIS) on the real UNSW-NB15 test flows
python scripts/evaluate_on_dataset.py --data data/raw/UNSW_NB15_testing-set.csv --model models/ids_rf_unsw_nb15.joblib --name unsw_nb15 --penalty 1.0
```

Add `--activate` to `train_on_dataset.py` to make the new model the one the Ryu controller uses.

### Results: IDS on UNSW-NB15 (official split)

Trained on 175,341 flows, tested on 82,332. 100 trees, 3-fold Platt calibration, no SMOTE, threshold 0.5. Training took 26.8 s; inference 0.0091 ms per flow.

| Accuracy | Precision | Recall | FPR | F1 | ROC-AUC | PR-AUC | ECE |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 83.79% | 77.73% | 98.89% | 34.71% | 87.05% | 0.9676 | 0.9724 | 0.1000 |

| Traffic type | Kind | Test flows | Correctly handled |
| --- | --- | --- | --- |
| Generic | attack | 18,871 | 99.98% |
| Exploits | attack | 11,132 | 99.87% |
| Fuzzers | attack | 6,062 | 92.26% |
| DoS | attack | 4,089 | 99.88% |
| Reconnaissance | attack | 3,496 | 100.00% |
| Analysis | attack | 677 | 100.00% |
| Backdoor | attack | 583 | 100.00% |
| Shellcode | attack | 378 | 97.35% |
| Worms | attack | 44 | 100.00% |
| Normal | benign | 37,000 | 65.29% |

The IDS catches almost every attack but flags about a third of normal traffic. The official test set is known to differ in distribution from the training set, and published Random Forest results on this split fall in a similar range.

### Results: IDS on CICIDS2017 (Friday afternoon, DDoS)

169,308 training / 56,437 test flows (25 % stratified split of one day file): accuracy 99.99%, FPR 0.01%, ROC-AUC 1.0000. DDoS traffic in this file is very distinctive and a random split of one day is an easy test; UNSW-NB15's official split is the more demanding benchmark.

### Results: full pipeline on real UNSW-NB15 flows

`evaluate_on_dataset.py` replays 40,000 real test flows. The datasets do not identify devices in a usable form, so flows are assigned to simulated devices (200 benign hosts, 20 attackers). Flow features and IDS scores are real; the device grouping is simulated.

| Strategy | Attacks mitigated | Benign flows disrupted (redirect/block) |
| --- | --- | --- |
| IDS alone, block at P ≥ 0.5 | 98.88% | 34.78% |
| Full pipeline, trust penalty 3.5 | 98.18% | 57.56% |
| Full pipeline, trust penalty 2 | 98.15% | 46.65% |
| Full pipeline, trust penalty 1 | 98.13% | 21.13% |
| Full pipeline, trust penalty 0.5 | 98.05% | 13.31% |

**Finding:** the trust engine's default asymmetric penalty (3.5× for a flagged flow) was tuned on synthetic data, where the IDS is almost never wrong. With a real IDS that falsely flags about a third of a normal host's flows, benign hosts lose trust and get blocked, and the pipeline does worse than the IDS alone. With symmetric evidence (penalty 1.0, the standard Beta reputation model) the trust layer separates hosts whose flows are occasionally flagged from hosts whose flows are almost always flagged, and false disruptions drop by about 40 % for under one point of detection. The penalty is configurable (`BayesianDynamicTrustEngine(penalty_multiplier=...)`, `--penalty`). It should be chosen on validation data, not the test set; a lower penalty also gives slow, mostly-benign-looking attackers more room.

---

# 🌐 Module 10 — Large and Multi-Network Simulation

### Purpose

Run the same pipeline over networks of any size, and over several separate SDN networks at once, each with its own number of hosts and switches.

`src/simulation/large_network_sim.py` generates the topology and scenario:

* **Networks:** separate SDN sites. Each has its own Ryu controller, spine switch, access switches and a service leaf (web/DB server + honeypot). Each controller keeps its own trust state and network context; all networks share one threat-intelligence feed.
* **Sizes:** either the same size for every network (`--networks`, `--hosts`, `--switches`) or a size per network (`--hosts_per_network`, `--switches_per_network`).
* **Roles** (random, fixed seed): normal; bursty (one legitimate flash crowd); attacker (port scan, then SYN flood); compromised (light benign traffic, then exploits the CVE that threat intel registers at 40 % of the run).
* **Speed:** IDS scoring is batched per tick; trust and decisions run per flow. Roughly 75 flows per host per 120 s; 1,000 hosts take about a minute.

### Run

```bash
# one network
python scripts/run_sdn_simulation.py --hosts 200 --switches 8

# five networks of equal size (1,000 hosts in total, 8 access switches each)
python scripts/run_sdn_simulation.py --networks 5 --hosts 1000 --switches 8

# networks of different sizes: a campus, a branch office and a small lab
python scripts/run_sdn_simulation.py --hosts_per_network 500,200,50 --switches_per_network 12,6,2
```

| Option | Meaning |
| --- | --- |
| `--networks N` | Number of equal-sized networks |
| `--hosts H` | Total hosts, split evenly across the networks |
| `--switches K` | Access switches in every network |
| `--hosts_per_network a,b,c` | Hosts in each network (sets the number of networks) |
| `--switches_per_network x,y,z` | Access switches in each network (one value per network) |
| `--attackers`, `--compromised`, `--bursty` | Shares of hosts with each role (defaults 0.08, 0.04, 0.10) |
| `--duration` | Simulated seconds (default 120) |
| `--penalty` | Trust penalty multiplier (default 3.5; see Module 9) |
| `--seed`, `--no_view` | Random seed; skip building the 3D page |

Each run writes `results/simulation_trace_large.json` and the 3D page `visualization/sdn_3d_large.html`. In the page, each network's ring is sized to its own switches and hosts. Hosts are towers (colour = current action, height = trust) with a floor marker for their role; hover a host for its IP, role, trust and action; use the network buttons to fly to one network. The side panel shows hosts per action, mean trust per role over time, live congestion per network and the controller's rule changes.

The Mininet topology has matching options for a real testbed (Linux, one network per Mininet instance):

```bash
sudo python src/sdn/mininet_topo.py --hosts 100 --switches 6
```

### Result: three networks of different sizes (seed 11)

N1: 500 hosts, 12 switches / N2: 200 hosts, 6 switches / N3: 50 hosts, 2 switches. 56,636 flows (7,698 attack). 90 malicious hosts, 0 never contained; mean time from first attack flow to first mitigation 0.0 s.

| | Attacks mitigated | Benign flows served | Benign flows blocked |
| --- | --- | --- | --- |
| Proposed framework | 100.0% | 98.76% | 603 |
| Static block at P ≥ 0.5 | 100.0% | 98.73% | 623 |

| Network | Hosts | Switches | Malicious | Flows | Attacks mitigated | Benign served |
| --- | --- | --- | --- | --- | --- | --- |
| N1 | 500 | 12 | 64 | 37,719 | 99.98% | 98.79% |
| N2 | 200 | 6 | 20 | 15,210 | 100.0% | 98.82% |
| N3 | 50 | 2 | 6 | 3,707 | 100.0% | 98.26% |

| Role | Mean final trust |
| --- | --- |
| normal | 0.952 |
| bursty | 0.609 |
| attacker | 0.005 |
| compromised | 0.05 |

As in Module 8, the synthetic flows are almost perfectly separable for the IDS, so the proposed framework and a static threshold are close here; most benign blocks come from the overloaded-server sessions of bursty hosts. The trust layer still separates roles clearly. For a test where the IDS makes real mistakes, see Module 9.

---

# 🤖 Module 11 — Agentic AI Security Analyst

### Purpose

Add an AI agent that supervises the SDN controller the way a SOC analyst would: it reviews the network on a schedule, investigates with tools, applies temporary overrides when they reduce harm, escalates permanent actions to a human, and writes an incident report.

```text
every N seconds:   observe  ->  investigate  ->  act (safely)  ->  record
                   overview     host details     overrides         incidents
                                decision          escalations      report
                                explanations
                                threat intel
```

### Backends ("brains")

| `--agent` | Model | API key (environment variable) |
| --- | --- | --- |
| `offline` | Built-in rule-based planner, deterministic, no network needed | none |
| `groq` | Groq (default `openai/gpt-oss-120b`; switches automatically if a model is unavailable to your key), OpenAI-compatible tool calling | `GROQ_API_KEY` |
| `claude` | Anthropic Claude (default `claude-sonnet-5-5`), Messages API tool use | `ANTHROPIC_API_KEY` |
| `openai` | Any OpenAI-compatible endpoint (`--agent_base_url`) | `OPENAI_API_KEY` |
| `ollama` | Local model through Ollama (default `llama3.1`, `http://localhost:11434`) | none |

Change the model with `--agent_model`. If an API call fails (no network, wrong key, rate limit), that review falls back to the offline planner and the error is listed in the report. Check the provider's console for current model names.

### Tools the agent can use (`src/agent/tools.py`)

| Tool | What it does |
| --- | --- |
| `get_overview` | Congestion per network, hosts per action, overrides, lowest-trust hosts |
| `list_hosts` | Hosts that are restricted, low-trust, flapping, matching a CVE, or overridden |
| `get_host` | Trust trend, recent IDS scores, decision history, rates, destination ports |
| `explain_decision` | TOPSIS, PPO and fused scores behind the controller's last decision |
| `get_threat_intel` | Registered CVE signatures |
| `apply_override` / `release_override` | Temporary MONITOR, RATE_LIMIT, REDIRECT or BLOCK |
| `request_human_approval` | Escalate permanent actions (quarantine, allow-listing, re-imaging) |
| `open_incident` | Record an incident for the report |

**Safety rules:** the agent only sees telemetry, never the simulator's ground-truth roles; it cannot fully ALLOW a host; every override needs a reason and lasts at most 60 s; protected and allow-listed hosts are off limits; at most 25 overrides per review; the controller's hard-block guardrail always wins over an override.

### Run

```bash
# offline planner (no key)
python scripts/run_sdn_simulation.py --hosts_per_network 500,200,50 --switches_per_network 12,6,2 --agent offline --out results/simulation_trace_agent.json

# Groq (Windows: set GROQ_API_KEY=your_key   Linux/macOS: export GROQ_API_KEY=your_key)
python scripts/run_sdn_simulation.py --hosts 300 --agent groq

# Claude
python scripts/run_sdn_simulation.py --hosts 300 --agent claude
```

Outputs: `results/agent_report.md` (incident report), the trace, and a 3D page whose decision feed shows the agent's actions in pink. Use `--agent_interval` to change how often the agent reviews (default every 10 s). LLM backends make several API calls per review, so long runs with many reviews use more tokens.

Never put API keys in the code or commit them; use environment variables.

### Result: offline agent on the three-network run of Module 10 (same seed and traffic)

| | Attacks mitigated | Benign flows served | Benign flows blocked |
| --- | --- | --- | --- |
| Framework without agent | 100.0% | 98.76% | 603 |
| **Framework + agent** | 100.0% | 99.11% | **434** |
| Static block at P ≥ 0.5 | 100.0% | 98.73% | 623 |

The agent cut wrongly blocked benign flows by 28 % without letting attacks through. It ran 12 reviews and applied 184 overrides.

Checked afterwards against the hidden ground truth:

| Incident | Severity | Title | Hosts | Actual roles |
| --- | --- | --- | --- | --- |
| INC-001 | low | Suspected false positives on bursty hosts | 71 | 71 bursty |
| INC-002 | high | Coordinated malicious activity in N1 | 47 | 43 attacker, 4 bursty |
| INC-003 | high | Coordinated malicious activity in N2 | 15 | 14 attacker, 1 bursty |
| INC-004 | high | Recently blocked hosts getting through with low IDS scores | 5 | 5 bursty |
| INC-005 | critical | Exploitation of CVE-2024-38856 | 30 | 30 compromised |
| INC-006 | high | Coordinated malicious activity in N3 | 3 | 3 attacker |

Overrides: 147 × bursty → RATE_LIMIT, 37 × compromised → REDIRECT. Escalations waiting for approval: 60 attacker, 30 compromised. The agent never relaxed control of an attacker. Its only mistakes involve bursty (benign) hosts: 5 listed in the coordinated-attack incidents, and 5 put on probation after the controller had blocked them during their flash crowd; probation only rate-limits them (30 s), it never blocks them.

LLM backends were tested with mocked API responses in `tests/test_agent.py` (Groq/OpenAI and Claude message formats, tool results, failure fallback); a live run needs your own key.

---

# ⚔️ Module 12 — Ten Attack Types and 200+ Attackers

### Attack types

`src/simulation/attack_library.py` models ten attacks as flows in the 28-feature schema:

| Group | Attack | What it looks like |
| --- | --- | --- |
| Classic | Port scan | Tiny SYN-only probes |
| Classic | SYN flood | Thousands of SYNs, no completed handshakes |
| Classic | CVE exploit | Injection / RCE payloads against the web service (port 8443) |
| Volumetric | UDP flood | High-rate datagrams to random ports |
| Volumetric | ICMP flood | Ping flood |
| Volumetric | DNS amplification | Small spoofed queries that trigger large responses |
| Credential / application | SSH brute force | Many short SSH sessions with failed logins |
| Credential / application | Slowloris | Low-rate DoS: long, almost idle HTTP connections |
| Post-compromise | Data exfiltration | Large, long uploads to an unusual port |
| Post-compromise | C2 beacon | Small periodic check-ins with a command server |

Attackers scan first, then run their main attack (spread evenly over the selected types). Compromised hosts exploit the CVE, then beacon to C2 and exfiltrate data.

The original IDS was trained on four attack families and misses many of these (e.g. about 31 % of SSH brute-force flows detected), so the attack mix uses an **extended IDS** trained on all ten types (`models/ids_rf_extended.joblib`, trained automatically on first use). `--unseen_attacks` leaves chosen types out of that training to test attacks the IDS has never seen.

### Run

```bash
# 1,600 hosts in three networks, 13 % attackers (208) + 4 % compromised (64), all ten attack types
python scripts/run_sdn_simulation.py --hosts_per_network 800,500,300 --switches_per_network 12,8,6 --attackers 0.13 --attack_types all --out results/simulation_trace_attacks.json

# a chosen subset
python scripts/run_sdn_simulation.py --hosts 500 --attack_types udp_flood,ssh_bruteforce,slowloris

# an attack the IDS has never seen, with and without the AI agent
python scripts/run_sdn_simulation.py --hosts 600 --attackers 0.15 --attack_types all --unseen_attacks slowloris --out results/simulation_trace_unseen.json
python scripts/run_sdn_simulation.py --hosts 600 --attackers 0.15 --attack_types all --unseen_attacks slowloris --agent offline --out results/simulation_trace_unseen_agent.json
```

3D pages: `visualization/sdn_3d_attacks.html`, `sdn_3d_unseen.html`, `sdn_3d_unseen_agent.html`. The side panel lists every attack type; hover a host to see its attack type.

### Result: 208 attackers + 64 compromised hosts, ten attack types

N1: 800 hosts, 12 switches / N2: 500 hosts, 8 switches / N3: 300 hosts, 6 switches. 123,766 flows (24,054 attack). Attacks mitigated 100.0%, benign traffic served 100.0%; 0 of 272 malicious hosts never contained.

| Attack | Hosts | Flows | Mitigated | Mean IDS score |
| --- | --- | --- | --- | --- |
| Port scan | 208 | 5,718 | 100.0% | 1.00 |
| SYN flood | 26 | 2,080 | 100.0% | 1.00 |
| CVE exploit | 64 | 2,560 | 100.0% | 1.00 |
| UDP flood | 26 | 2,078 | 100.0% | 1.00 |
| ICMP flood | 26 | 2,074 | 100.0% | 1.00 |
| DNS amplification | 26 | 2,078 | 100.0% | 1.00 |
| SSH brute force | 26 | 3,111 | 100.0% | 1.00 |
| Slowloris | 26 | 2,080 | 100.0% | 1.00 |
| Data exfiltration | 90 | 1,470 | 100.0% | 1.00 |
| C2 beacon | 90 | 805 | 100.0% | 1.00 |

With every type in its training data, the extended IDS separates these synthetic attacks perfectly, so this run shows scale rather than difficulty.

### Result: an attack the IDS has never seen (slowloris)

600 hosts, 15 % attackers, IDS trained without slowloris:

| | Attacks mitigated (all types) | Slowloris mitigated | Benign served |
| --- | --- | --- | --- |
| Framework alone | 91.38% | 0.0% | 100.0% |
| Framework + AI agent (offline) | 97.85% | 75.0% | 100.0% |

The IDS scores slowloris at about 0.14, so every flow looks harmless. The attackers were blocked moments earlier for their port scan (trust ≈ 0.01), yet the controller lets the slow traffic through and each harmless-looking flow rebuilds their trust (≈ 0.01 → 0.38 in 36 s). Two causes: the PPO policy relies mainly on traffic rate, and the trust engine rewards any flow the IDS calls benign. The agent's **probation** rule (recently blocked hosts are throttled if they are let through again within 90 s) catches all slowloris attackers without touching benign hosts; what remains gets through between reviews (every 10 s).

Improvements this points to: a trust floor or probation period inside the controller itself, and retraining PPO so it weighs trust and attack probability rather than rate alone.

---

# 🧠 Example End-to-End Scenario

Consider a compromised host generating a SYN flood.

### Step 1 — Traffic

```text
Attacker Host
     ↓
大量 SYN packets
     ↓
SDN network
```

### Step 2 — IDS

The flow is converted into the required feature vector.

```text
28 Features
     ↓
Random Forest
     ↓
Attack Probability = 0.98
```

### Step 3 — Trust

The device has previously shown malicious behaviour.

```text
Trust Score = 0.08
```

### Step 4 — Network Context

```text
Network Load = High
Packet Loss = Increasing
```

### Step 5 — PPO

The agent receives the current security and network state.

```text
Attack Probability → 0.98
Trust Score         → 0.08
Network Context     → High Risk

                ↓

              PPO

                ↓

             BLOCK
```

### Step 6 — SDN

Ryu installs the appropriate OpenFlow rule.

```text
Attacker Traffic
       ↓
    DROP/BLOCK
```

---

# 🧪 25% Project Milestone

The first major milestone focuses on the foundational security layer:

## Phase 1 — Calibrated Random Forest IDS

The milestone demonstrates:

* 28-feature schema validation
* Data preprocessing
* Random Forest training
* 5-fold cross-validation
* Platt/Sigmoid calibration
* Classification metrics
* Probability calibration metrics
* Sample traffic classification

## Phase 2 — Bayesian Trust Engine

The milestone demonstrates:

* Beta distribution updates
* Dynamic α and β values
* Trust-score calculation
* Exponential time decay
* Multiple device profiles
* SQLite persistence
* Trust audit trail

### Demonstration device profiles

```text
1. Trusted Enterprise Workstation
2. Bursting Web Application Server
3. Compromised Attacker Node
4. Inactive Edge Node
```

### Milestone pipeline

```text
              25% MILESTONE

       Network Flow / Dataset
                │
                ▼
       ┌──────────────────┐
       │ Calibrated RF IDS│
       └────────┬─────────┘
                │
                ▼
       Attack Probability
                │
                ▼
       ┌──────────────────┐
       │ Bayesian Trust   │
       │     Engine       │
       └────────┬─────────┘
                │
                ▼
          Device Trust
                │
                ▼
         SQLite Audit Log
```

---

# 📈 IDS Evaluation Metrics

The project evaluates the IDS using:

| Metric            | Purpose                                           |
| ----------------- | ------------------------------------------------- |
| Accuracy          | Overall prediction correctness                    |
| Precision         | Correctness of attack predictions                 |
| Recall / TPR      | Percentage of attacks detected                    |
| Specificity / TNR | Percentage of benign traffic correctly identified |
| FPR               | Percentage of benign traffic incorrectly flagged  |
| F1-score          | Balance between precision and recall              |
| ROC-AUC           | Overall classification capability                 |
| PR-AUC            | Precision-recall performance                      |
| Brier Score       | Probability calibration quality                   |
| ECE               | Calibration error                                 |

> **Note:** Target benchmark values should only be reported after they are obtained from the actual training/evaluation run.

---

# 📁 Repository Structure

```text
Computer-Network-Project/
│
├── data/
│   ├── raw/
│   ├── processed/
│   └── threat_db.sqlite
│
├── models/
│   ├── ids_rf_calibrated.joblib
│   └── rl_ppo_agent.zip
│
├── src/
│   ├── ids/
│   │   ├── datasets.py
│   │   ├── preprocess.py
│   │   ├── train_rf.py
│   │   └── evaluator.py
│   │
│   ├── trust/
│   │   ├── trust_engine.py
│   │   └── db_manager.py
│   │
│   ├── context/
│   │   └── collector.py
│   │
│   ├── rl/
│   │   ├── sdn_env.py
│   │   ├── reward.py
│   │   ├── train_ppo.py
│   │   └── policy_infer.py
│   │
│   ├── threat_intel/
│   │   ├── scraper.py
│   │   ├── nlp_parser.py
│   │   ├── traffic_gen.py
│   │   ├── retrainer.py
│   │   └── scheduler.py
│   │
│   ├── sdn/
│   │   ├── ryu_controller.py
│   │   ├── mininet_topo.py
│   │   └── traffic_injector.py
│   │
│   ├── agent/
│   │   ├── tools.py
│   │   └── agent.py
│   │
│   ├── mcdm/
│   │   ├── ahp.py
│   │   ├── topsis.py
│   │   └── decision_engine.py
│   │
│   └── simulation/
│       ├── network_sim.py
│       ├── large_network_sim.py
│       └── attack_library.py
│
├── tests/
│   ├── test_ids.py
│   ├── test_trust.py
│   ├── test_context.py
│   ├── test_rl_env.py
│   ├── test_threat_intel.py
│   ├── test_sdn_controller.py
│   ├── test_mcdm.py
│   ├── test_simulation.py
│   ├── test_datasets.py
│   ├── test_large_simulation.py
│   ├── test_agent.py
│   ├── test_attacks.py
│   └── test_integration.py
│
├── scripts/
│   ├── run_all_tests.py
│   ├── demo_simulation.py
│   ├── demo_25_percent_milestone.py
│   ├── evaluate_policies.py
│   ├── train_on_dataset.py
│   ├── evaluate_on_dataset.py
│   ├── run_sdn_simulation.py
│   └── build_3d_view.py
│
├── results/
│   ├── policy_comparison.json
│   ├── simulation_trace.json
│   ├── simulation_trace_large.json
│   ├── simulation_trace_agent.json
│   └── agent_report.md
│
├── visualization/
│   ├── sdn_3d_template.html
│   ├── sdn_3d_simulation.html
│   ├── sdn_3d_scale_template.html
│   ├── sdn_3d_large.html
│   └── sdn_3d_agent.html
│
├── docs/
│   ├── IEEE_Paper_Draft.md
│   └── Patent_Canvas.md
│
├── Dockerfile
├── requirements.txt
└── README.md
```

---

# ⚙️ Technologies Used

### Machine Learning

* Python
* NumPy
* Pandas
* SciPy
* Scikit-learn
* Imbalanced-learn
* Joblib

### Reinforcement Learning

* PyTorch
* Gymnasium
* Stable-Baselines3
* PPO

### SDN & Networking

* Ryu
* OpenFlow 1.3
* Mininet
* Scapy

### Threat Intelligence

* NVD
* CISA KEV
* Exploit-DB
* spaCy
* Regex

### Database

* SQLite
* SQLAlchemy

### Testing

* PyTest
* pytest-cov
* pytest-asyncio

The dependency set in `requirements.txt` includes the main ML, RL, networking, threat-intelligence, database, visualization, and testing libraries used by the project.

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone https://github.com/Narayangarg10/Computer-Network-Project.git
cd Computer-Network-Project
```

## 2. Create a virtual environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Install the spaCy English model

```bash
python -m spacy download en_core_web_sm
```

---

# ▶️ Running the Project

## Run the 25% milestone demonstration

```bash
python scripts/demo_25_percent_milestone.py
```

This demonstrates the two foundational components:

```text
Calibrated IDS
      +
Bayesian Trust Engine
```

---

## Run the complete standalone simulation

```bash
python scripts/demo_simulation.py
```

The complete demonstration is designed to integrate:

* IDS detection
* Probability calibration
* Bayesian trust
* Adaptive RL mitigation
* Threat intelligence
* Model validation

---

## Compare decision strategies

```bash
python scripts/evaluate_policies.py --steps 5000
```

## Run the end-to-end simulation and build the 3D view

```bash
python scripts/run_sdn_simulation.py
python scripts/build_3d_view.py
# then open visualization/sdn_3d_simulation.html
```

---

## Run all tests

```bash
python scripts/run_all_tests.py
```

or:

```bash
pytest tests/ -v --cov=src
```

---

# 🧠 Train the IDS

```bash
python src/ids/train_rf.py \
    --synthetic \
    --n_estimators 150 \
    --save_path models/ids_rf_calibrated.joblib
```

The trained model is saved as:

```text
models/ids_rf_calibrated.joblib
```

---

# 🤖 Train the PPO Agent

```bash
python src/rl/train_ppo.py \
    --total_timesteps 200000 \
    --save_path models/rl_ppo_agent.zip
```

The trained policy is saved as:

```text
models/rl_ppo_agent.zip
```

---

# 🛡️ Run Threat Intelligence

```bash
python src/threat_intel/scheduler.py --interval_hours 1
```

---

# 🌐 Run Ryu + Mininet

### Terminal 1 — Ryu Controller

```bash
ryu-manager src/sdn/ryu_controller.py --verbose
```

### Terminal 2 — Mininet

```bash
sudo python src/sdn/mininet_topo.py
```

> **Note:** Ryu and Mininet are primarily intended to run in a Linux environment or through Docker. The dependency configuration also restricts Ryu/eventlet installation on Windows.

---

# 🐳 Docker

Build the image:

```bash
docker build -t sdn-trust-rl .
```

Run:

```bash
docker run -it --privileged \
    -p 6653:6653 \
    -p 8080:8080 \
    --name sdn-trust-sim \
    sdn-trust-rl
```

---

# 🔬 Testing Strategy

The project contains unit and integration tests covering:

```text
IDS
 ↓
Trust Engine
 ↓
Network Context
 ↓
RL Environment
 ↓
Threat Intelligence
 ↓
SDN Controller
 ↓
End-to-End Integration
```

Tests are organized under:

```text
tests/
```

The repository currently includes dedicated tests for IDS, trust, context, RL, threat intelligence, SDN controller behaviour, and end-to-end integration.

---

# 📊 Expected Project Outputs

The project produces several important outputs.

### IDS

```text
Attack Probability
Classification
Performance Metrics
Calibration Metrics
```

### Trust Engine

```text
Alpha
Beta
Trust Score
Trust Variance
Trust History
```

### Network Context

```text
Bandwidth
Active Flows
Packet Loss
QoS Information
```

### RL

```text
Selected Mitigation Action
Reward
Policy
```

### SDN

```text
OpenFlow Flow Rules
Allow / Monitor / Rate Limit / Redirect / Block
```

---

# 🏆 Key Contribution

The main contribution of the project is the integration of multiple security intelligence layers rather than relying on a single binary IDS decision.

Instead of:

```text
Attack Detected
      ↓
     BLOCK
```

the proposed architecture uses:

```text
                 ┌───────────────┐
                 │ Attack        │
                 │ Probability   │
                 └───────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │ Device Trust  │
                 └───────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │ Network       │
                 │ Context       │
                 └───────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │ PPO Agent     │
                 └───────┬───────┘
                         │
                         ▼
       ┌─────────────────────────────────┐
       │ Adaptive Security Response      │
       │                                 │
       │ Allow | Monitor | Rate Limit    │
       │ Redirect | Block                │
       └─────────────────────────────────┘
```

This allows the system to distinguish between **malicious traffic, uncertain behaviour, trusted devices, and changing network conditions**.

---

# 🔮 Future Development

The planned development path is:

### Phase 1

**Calibrated Random Forest IDS**

### Phase 2

**Bayesian Dynamic Device Trust**

### Phase 3

**Real-Time Network Context**

### Phase 4

**PPO-Based Adaptive Mitigation**

### Phase 5

**Automated Threat Intelligence & Continuous Retraining**

### Phase 6

**Ryu + Mininet SDN Integration**

### Final Goal

```text
Continuous Network Monitoring
           ↓
       Threat Detection
           ↓
       Trust Analysis
           ↓
      Network Context
           ↓
      RL Decision
           ↓
     SDN Enforcement
           ↓
      New Behaviour
           ↓
   Continuous Learning
```

---

# 📚 Research Direction

The project is designed as a research-oriented SDN security framework combining:

* Machine Learning
* Probability Calibration
* Bayesian Inference
* Reinforcement Learning
* Software Defined Networking
* Network Security
* Threat Intelligence
* Continuous Learning

The repository also contains dedicated documentation for the research paper and patent-oriented design work under `docs/`.

---

# 👥 Project Status

**Current milestone:** full pipeline implemented and simulated end to end

* [x] Project architecture
* [x] 28-feature IDS pipeline
* [x] Random Forest IDS with Platt calibration
* [x] IDS evaluation framework
* [x] Bayesian trust engine with time decay and SQLite persistence
* [x] Real-time network context integration (port counters → congestion, utilisation, loss)
* [x] PPO training (`models/rl_ppo_agent.zip`, 300k steps) and evaluation against baselines
* [x] Multi-Criteria Decision Making: AHP weights + TOPSIS ranking fused with PPO
* [x] Ryu controller integration of the adaptive decision engine
* [x] Automated threat-intelligence pipeline (offline fixtures) feeding emerging-threat signatures
* [x] End-to-end simulation and interactive 3D visualisation
* [ ] Run on a live Mininet + Ryu testbed and capture traces
* [x] Train and evaluate the IDS on UNSW-NB15 and CICIDS2017 (Module 9)
* [x] Large and multi-network simulation with 3D view (Module 10)
* [x] Agentic AI security analyst: offline, Groq, Claude, OpenAI-compatible (Module 11)
* [x] Ten attack types, 200+ attackers, unseen-attack test (Module 12)
* [x] Monitoring of new devices and ambiguous IDS scores, shown in both 3D views (Module 7 guardrails)
* [ ] Retrain PPO so it relies on trust and attack probability, not traffic rate alone
* [ ] Choose the trust penalty on a validation split and re-run the real-data pipeline evaluation

### Fixes made while completing the project

| Area | Problem | Fix |
| --- | --- | --- |
| `context/collector.py`, `sdn/traffic_injector.py` | `Tuple` used without import (NameError on import) | Added the import |
| `ids/preprocess.py` | Synthetic generator never produced `tcprtt`, `packet_rate`, `byte_rate` | Derived columns added |
| `sdn/ryu_controller.py` | First packet of every flow measured over 1 ms, so benign clients looked like 1000 pps floods and were blocked | Rate window ≥ 1 s until a flow has 10 packets |
| `sdn/ryu_controller.py` + `ids/preprocess.py` | Unobserved reverse-direction features sent as 0, which matches attack profiles | Sent as NaN and imputed with training medians |
| `sdn/ryu_controller.py` | RF trained on full flows misses the first packets of a flood | Rate-anomaly score combined with the RF probability |
| `sdn/ryu_controller.py` | Audit log stored the new trust score as both previous and new | Previous score captured before the update |
| `rl/sdn_env.py` | Benign and attack confidences never overlapped, so a 0.5 threshold was already perfect | Added benign false-positive bursts and stealthy attacks |
| `requirements.txt` | `numpy<2`, `scikit-learn<1.5` cannot install on current Python | Lower bounds only |
| `trust/db_manager.py` | SQLite connections never closed, so Windows could not delete the database file | Connections close after each operation |
| `ids/preprocess.py` | Missing values filled with 0 before medians were computed | Medians computed from observed values first |

---

## 📄 License

This project is intended for academic and research purposes.

---

## ⭐ Project Summary

**Trust-Score-Driven Reinforcement Learning for Adaptive SDN Intrusion Mitigation & Automated Threat Intelligence** combines:

> **Detection + Trust + Context + Reinforcement Learning + Threat Intelligence + SDN Enforcement**

to create an adaptive security architecture capable of making more informed mitigation decisions than traditional static intrusion detection systems.
