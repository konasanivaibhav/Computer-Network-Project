"""
ryu_controller.py
=================
Ryu OpenFlow 1.3 SDN Controller Application with Closed-Loop ML/RL Mitigation.

Integrates:
1. Calibrated Random Forest IDS for sub-5ms flow classification.
2. Bayesian Dynamic Device Trust Scoring with SQLite state persistence.
3. Network Context Collector for OpenFlow 1.3 switch port statistics.
4. Reinforcement Learning Adaptive Response Engine selecting:
   - Allow (Forwarding)
   - Monitor (Port Mirroring)
   - Rate-Limit (OpenFlow 1.3 Meter Bands)
   - Redirect (Quarantine / Honeynet Destination Rewriting)
   - Block (Hard Drop FlowMod)
"""

import time
import os
import logging
from typing import Dict, Any, Optional, Tuple, List
import pandas as pd
import numpy as np

from src.ids.train_rf import CalibratedRFModel
from src.ids.preprocess import NetworkPreprocessor, ALL_CANONICAL_FEATURES
from src.trust.trust_engine import BayesianDynamicTrustEngine
from src.trust.db_manager import TrustDBManager
from src.context.collector import NetworkContextCollector
from src.rl.reward import MitigationAction
from src.rl.policy_infer import RLPolicyEngine
from src.mcdm.decision_engine import AdaptiveDecisionEngine, DecisionContext

logger = logging.getLogger(__name__)

# Ryu framework conditional imports
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    # Mock Ryu base class for non-Ryu runtime testing
    class app_manager:
        class RyuApp:
            def __init__(self, *args, **kwargs):
                pass
    def set_ev_cls(*args, **kwargs):
        def decorator(f):
            return f
        return decorator


class SDNRLControllerApp(app_manager.RyuApp):
    """
    Ryu Controller Application implementing Closed-Loop Trust-Score-Driven
    Reinforcement Learning Adaptive Intrusion Mitigation.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] if RYU_AVAILABLE else [4]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "sdn_trust_rl_controller"
        self.mac_to_port: Dict[int, Dict[str, int]] = {} # dpid -> {mac: port}

        # Initialize Subsystems
        self.trust_engine = BayesianDynamicTrustEngine()
        self.trust_db = TrustDBManager()
        self.context_collector = NetworkContextCollector()
        ppo_path = os.environ.get("PPO_MODEL_PATH", "models/rl_ppo_agent.zip")
        self.policy_engine = RLPolicyEngine(model_path=ppo_path if os.path.exists(ppo_path) else None)
        # Context-aware adaptive decision engine: PPO policy fused with AHP-TOPSIS
        # multi-criteria ranking, plus operator guardrails.
        self.decision_engine = AdaptiveDecisionEngine(
            policy_engine=self.policy_engine,
            protected_assets={"10.0.0.3"},
        )
        self.last_action: Dict[str, int] = {}
        self.last_decision = None

        # Load IDS Pipeline
        self.ids_model: Optional[CalibratedRFModel] = None
        self.model_path = "models/ids_rf_calibrated.joblib"
        self._load_ids_model()

        # Dedicated Honeynet / Quarantine Switch Port & IP
        self.HONEYPOT_DPID = 1
        self.HONEYPOT_PORT = 3
        self.HONEYPOT_IP = "10.0.0.100"
        self.HONEYPOT_MAC = "00:00:00:00:00:99"
        self.MIRROR_PORT = 4

        # Active Flow Trackers for Packet Rate Calculation
        self.flow_trackers: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
        logger.info("SDN Trust-Score RL Controller initialized successfully.")

    def _load_ids_model(self) -> None:
        """Load or reload calibrated Random Forest IDS."""
        if os.path.exists(self.model_path):
            try:
                self.ids_model = CalibratedRFModel.load(self.model_path)
                logger.info("Loaded active IDS pipeline from %s", self.model_path)
            except Exception as e:
                logger.warning("Failed to load IDS model from %s: %s", self.model_path, e)
        else:
            logger.info("No saved model found at %s. Operating in initial baseline mode.", self.model_path)

    # ==========================================================================
    # OPENFLOW 1.3 EVENT HANDLERS
    # ==========================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) if RYU_AVAILABLE else lambda f: f
    def switch_features_handler(self, ev):
        """Install default table-miss flow entry (send to controller)."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss rule: priority 0, match all, action: Output to Controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        logger.info("Switch connected: DPID %s. Installed default table-miss entry.", datapath.id)

        # Setup OpenFlow 1.3 Meter for Rate-Limiting (Meter ID = 1, Drop band at 500 kbps)
        self.setup_meter_band(datapath, meter_id=1, rate_kbps=500)

    def setup_meter_band(self, datapath, meter_id: int = 1, rate_kbps: int = 500) -> None:
        """Configure OpenFlow 1.3 Meter table entry for bandwidth rate-limiting."""
        if not RYU_AVAILABLE:
            return
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        bands = [parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=50)]
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands,
        )
        datapath.send_msg(req)
        logger.debug("Configured Meter %d (Rate: %d kbps) on DPID %s", meter_id, rate_kbps, datapath.id)

    def add_flow(
        self,
        datapath,
        priority: int,
        match,
        actions: List[Any],
        meter_id: Optional[int] = None,
        idle_timeout: int = 60,
        hard_timeout: int = 0,
    ) -> None:
        """Install a FlowMod rule on an OpenFlow switch."""
        if not RYU_AVAILABLE:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id=meter_id))

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    # ==========================================================================
    # CORE PACKET-IN & INTELLIGENCE PROCESSING
    # ==========================================================================

    def process_flow_intelligence(
        self,
        src_ip: str,
        dst_ip: str,
        proto_str: str,
        dst_port: int,
        packet_len: int,
        current_time: Optional[float] = None,
    ) -> Tuple[MitigationAction, float, float]:
        """
        Closed-Loop Decision Core:
        1. Extract flow features
        2. Compute calibrated IDS attack probability
        3. Retrieve/Update Bayesian device trust
        4. Query RL policy engine for optimal mitigation action
        """
        now = current_time if current_time is not None else time.time()
        flow_key = (src_ip, dst_ip, dst_port)

        # 1. Feature Extraction / Flow Tracking
        if flow_key not in self.flow_trackers:
            self.flow_trackers[flow_key] = {
                "start_time": now,
                "last_time": now,
                "packet_count": 1,
                "byte_count": packet_len,
            }
        else:
            ft = self.flow_trackers[flow_key]
            ft["packet_count"] += 1
            ft["byte_count"] += packet_len
            ft["last_time"] = now

        ft = self.flow_trackers[flow_key]
        dur = max(0.001, ft["last_time"] - ft["start_time"])
        # Rates are estimated over at least a 1-second observation window. With a
        # 1 ms floor, the very first packet of every flow looked like 1000 pps and
        # benign clients were classified as floods and blocked.
        # Once a flow has enough packets its real duration is a reliable window.
        rate_window = dur if ft["packet_count"] >= 10 else max(1.0, dur)
        flow_pps = ft["packet_count"] / rate_window
        byte_rate = (ft["byte_count"] * 8) / rate_window

        # 2. IDS Inference
        if self.ids_model is not None and self.ids_model.preprocessor is not None:
            # PacketIn only exposes the source -> destination direction. Fields the
            # controller cannot observe are passed as NaN and imputed with training
            # medians by the preprocessor, instead of zeros that mimic attack traffic.
            nan = float("nan")
            raw_row = pd.DataFrame([{
                "duration": dur,
                "spkts": ft["packet_count"],
                "dpkts": nan,
                "sbytes": ft["byte_count"],
                "dbytes": nan,
                "sttl": 64,
                "dttl": nan,
                "sloss": 0,
                "dloss": nan,
                "sload": byte_rate,
                "dload": nan,
                "smeansz": float(ft["byte_count"] / ft["packet_count"]),
                "dmeansz": nan,
                "trans_depth": 1 if dst_port in (80, 8080) else 0,
                "res_bdy_len": nan,
                "sjit": nan,
                "djit": nan,
                "synack": nan,
                "ackdat": nan,
                "swin": 65535,
                "dwin": nan,
                "stcpb": nan,
                "dtcpb": nan,
                "packet_rate": flow_pps,
                "byte_rate": byte_rate / 8.0,
                "proto": proto_str,
                "service": "http" if dst_port in (80, 8080) else ("ssl" if dst_port in (443, 8443) else "none"),
            }])
            X_trans = self.ids_model.preprocessor.transform(raw_row)
            attack_confidence = float(self.ids_model.predict_confidence(X_trans)[0])
        else:
            # Fallback heuristic if model not loaded
            attack_confidence = 0.85 if flow_pps > 300 or dst_port == 11211 else 0.05

        # The RF is trained on complete flows; a PacketIn view sees only the first
        # packets of a flood. A rate-anomaly score covers that gap and the higher of
        # the two is used as the attack confidence.
        attack_confidence = max(attack_confidence, self._volumetric_score(
            flow_pps, ft["packet_count"], proto_str, dst_port))

        # 3. Bayesian Trust Update
        previous_score = self.trust_engine.get_trust_score(src_ip, current_time=now)
        trust_state = self.trust_engine.update_flow_observation(
            device_id=src_ip,
            attack_confidence=attack_confidence,
            flow_weight=1.0,
            current_time=now,
        )
        self.trust_db.save_device_state(trust_state)

        # 4. Context Telemetry
        ctx = self.context_collector.get_current_context()

        # 5. Adaptive decision: PPO + AHP-TOPSIS (MCDM) + guardrails
        proto_enc = 0.33 if proto_str == "tcp" else (0.66 if proto_str == "udp" else 1.0)
        decision = self.decision_engine.decide(DecisionContext(
            attack_confidence=attack_confidence,
            trust_score=trust_state.score,
            trust_variance=trust_state.variance,
            congestion_index=ctx.congestion_index,
            packet_loss_rate=ctx.packet_loss_rate,
            flow_rate_norm=min(1.0, flow_pps / 1000.0),
            byte_rate_norm=min(1.0, byte_rate / 10_000_000.0),
            proto_encoded=proto_enc,
            dst_port_norm=dst_port / 65535.0,
            is_emerging_threat=bool(dst_port == 8443 and flow_pps > 200),
            prev_action=self.last_action.get(src_ip, 0),
            burst_factor=min(1.0, flow_pps / 500.0),
            src_ip=src_ip,
            dst_ip=dst_ip,
        ))
        action = decision.action
        self.last_action[src_ip] = int(action)
        self.last_decision = decision

        logger.info(
            "Flow %s -> %s:%d [%s] | P(Atk)=%.3f | Trust=%.3f (%s) | Action=%s",
            src_ip, dst_ip, dst_port, proto_str.upper(),
            attack_confidence, trust_state.score, trust_state.category, action.name
        )

        self.trust_db.log_audit_event(
            device_id=src_ip,
            attack_confidence=attack_confidence,
            action_taken=action.name,
            previous_score=previous_score,
            new_score=trust_state.score,
            timestamp=now,
        )

        return action, attack_confidence, trust_state.score

    AMPLIFICATION_PORTS = {19, 53, 123, 161, 389, 1900, 11211}

    @staticmethod
    def _volumetric_score(pps: float, packet_count: int, proto: str, dst_port: int) -> float:
        """Rate-anomaly confidence in [0, 1] for partially observed flows."""
        if packet_count < 10:
            return 0.0
        score = 1.0 / (1.0 + np.exp(-(pps - 150.0) / 30.0))   # ~0.5 at 150 pps, ~0.97 at 250 pps
        if proto == "udp" and dst_port in SDNRLControllerApp.AMPLIFICATION_PORTS and pps > 50:
            score = max(score, 0.9)
        return float(score)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) if RYU_AVAILABLE else lambda f: f
    def packet_in_handler(self, ev):
        """Process PacketIn event and enforce RL mitigation policy."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88CC: # Ignore LLDP
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Inspect IP / Transport Layer
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            # Forward non-IP / ARP normally
            out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        proto_str = "ip"
        dst_port = 0

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if tcp_pkt:
            proto_str = "tcp"
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            proto_str = "udp"
            dst_port = udp_pkt.dst_port
        elif icmp_pkt:
            proto_str = "icmp"

        # Execute Closed-Loop Intelligence
        action, atk_prob, trust = self.process_flow_intelligence(
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto_str=proto_str,
            dst_port=dst_port,
            packet_len=len(msg.data),
        )

        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)

        # Apply Mitigation FlowMod Actions
        if action == MitigationAction.ALLOW:
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=60)
        elif action == MitigationAction.MONITOR:
            # Output to destination + Mirror to capture port
            actions = [parser.OFPActionOutput(out_port), parser.OFPActionOutput(self.MIRROR_PORT)]
            self.add_flow(datapath, priority=15, match=match, actions=actions, idle_timeout=30)
        elif action == MitigationAction.RATE_LIMIT:
            # Output to destination via OpenFlow Meter 1
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, priority=20, match=match, actions=actions, meter_id=1, idle_timeout=30)
        elif action == MitigationAction.REDIRECT:
            # Rewrite destination IP/MAC to Honeynet sinkhole
            actions = [
                parser.OFPActionSetField(ipv4_dst=self.HONEYPOT_IP),
                parser.OFPActionSetField(eth_dst=self.HONEYPOT_MAC),
                parser.OFPActionOutput(self.HONEYPOT_PORT),
            ]
            self.add_flow(datapath, priority=25, match=match, actions=actions, idle_timeout=45)
        elif action == MitigationAction.BLOCK:
            # Drop flow entry: actions = []
            actions = []
            self.add_flow(datapath, priority=30, match=match, actions=actions, idle_timeout=120)

        # Send packet out if not dropped
        if action != MitigationAction.BLOCK:
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
