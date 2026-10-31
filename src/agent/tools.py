"""
tools.py
========
The tools the security agent can use on a running SDN simulation.

The agent sees only what a real SOC analyst could see at the controller:
trust scores, IDS probabilities, decisions and their explanations, traffic
statistics, threat-intel signatures. It never sees the simulator's ground-truth
host roles.

Every action goes through safety checks:
  * no overrides on protected assets or allow-listed hosts
  * the agent may not fully ALLOW a host the controller restricted; that needs
    a human (request_human_approval)
  * overrides are temporary (at most MAX_OVERRIDE_S seconds)
  * the controller's hard-block guardrail always wins over an agent override
  * at most MAX_ACTIONS_PER_STEP overrides per review
"""

from collections import Counter
from typing import Any, Dict, List, Optional

import numpy as np

ACTIONS = ["ALLOW", "MONITOR", "RATE_LIMIT", "REDIRECT", "BLOCK"]
MAX_OVERRIDE_S = 60
MAX_ACTIONS_PER_STEP = 25


class SDNToolbox:
    """Tool surface over a LargeSDNSimulation at tick `t`."""

    def __init__(self, sim, t: int, events: List[Dict[str, Any]]):
        self.sim, self.t, self.events = sim, t, events
        self.name_to_idx = {h.name: i for i, h in enumerate(sim.hosts)}
        self.actions_this_step = 0

    # ------------------------------------------------------------------ helpers
    def _idx(self, host: str) -> int:
        host = str(host).strip()
        if host in self.name_to_idx:
            return self.name_to_idx[host]
        for i, h in enumerate(self.sim.hosts):
            if h.ip == host:
                return i
        raise KeyError(f"Unknown host '{host}'. Use a name like h12 or an IP from list_hosts.")

    def _status(self, i: int) -> Dict[str, Any]:
        h, o = self.sim.hosts[i], self.sim.obs[i]
        ps = list(o["p"])
        acts = [a for _, a in o["acts"]]
        recent = [a for tt, a in o["acts"] if tt > self.t - 20]
        changes = sum(1 for x, y in zip(recent, recent[1:]) if x != y)
        ov = self.sim.overrides.get(i)
        return {
            "host": h.name, "ip": h.ip, "network": f"N{h.network + 1}", "switch": h.switch,
            "trust": round(float(self.sim.trust_now[i]), 3),
            "current_action": ACTIONS[int(self.sim.prev[i])] if acts else "NONE",
            "flows_seen": len(acts),
            "mean_p_attack_recent": round(float(np.mean(ps)), 3) if ps else None,
            "share_flows_flagged_recent": round(float(np.mean([p >= 0.5 for p in ps])), 3) if ps else None,
            "decision_changes_last_20s": changes,
            "signature_match": o["cve"],
            "override": None if not ov or ov["until"] < self.t else
            {"action": ACTIONS[ov["action"]], "until_t": ov["until"], "reason": ov["reason"]},
        }

    def _log(self, kind: str, text: str, **extra):
        ev = {"t": self.t, "type": "agent", "kind": kind, "text": text}
        ev.update(extra)
        self.events.append(ev)
        self.sim.agent_log.append(ev)
        return ev

    # ------------------------------------------------------------------ observe
    def get_overview(self) -> Dict[str, Any]:
        """Network-wide snapshot: congestion, hosts per action, most suspicious hosts."""
        H = len(self.sim.hosts)
        active = [i for i in range(H) if self.sim.obs[i]["acts"]]
        counts = Counter(ACTIONS[int(self.sim.prev[i])] for i in active)
        nets = []
        for n in range(self.sim.n_networks):
            members = [i for i in active if self.sim.hosts[i].network == n]
            nets.append({"network": f"N{n + 1}", "hosts": sum(h.network == n for h in self.sim.hosts),
                         "congestion": self.sim.last_ctx[n]["congestion"] if self.sim.last_ctx else 0.0,
                         "restricted_now": sum(int(self.sim.prev[i]) >= 2 for i in members)})
        suspicious = sorted(active, key=lambda i: float(self.sim.trust_now[i]))[:8]
        return {
            "t": self.t, "hosts_total": H, "hosts_seen": len(active),
            "hosts_by_current_action": dict(counts), "networks": nets,
            "active_overrides": sum(1 for o in self.sim.overrides.values() if o["until"] >= self.t),
            "threat_signatures": [s.cve_id for s in self.sim.signatures],
            "lowest_trust_hosts": [self._status(i) for i in suspicious],
        }

    def list_hosts(self, status: str = "restricted", network: Optional[str] = None, limit: int = 15) -> Dict[str, Any]:
        """status: restricted | low_trust | flapping | emerging | overridden"""
        out = []
        for i, h in enumerate(self.sim.hosts):
            if network and f"N{h.network + 1}" != network:
                continue
            if not self.sim.obs[i]["acts"]:
                continue
            s = self._status(i)
            keep = {
                "restricted": s["current_action"] in ("RATE_LIMIT", "REDIRECT", "BLOCK"),
                "low_trust": s["trust"] < 0.3,
                "flapping": s["decision_changes_last_20s"] >= 4,
                "emerging": s["signature_match"] is not None,
                "overridden": s["override"] is not None,
            }.get(status)
            if keep is None:
                raise ValueError("status must be restricted, low_trust, flapping, emerging or overridden")
            if keep:
                out.append(s)
        out.sort(key=lambda s: s["trust"])
        return {"status": status, "count": len(out), "hosts": out[:max(1, int(limit))]}

    def get_host(self, host: str) -> Dict[str, Any]:
        """Detailed view of one host: trust trend, recent IDS scores, traffic, ports, decision history."""
        i = self._idx(host)
        o = self.sim.obs[i]
        s = self._status(i)
        s.update({
            "trust_last_30s": [round(float(x), 3) for x in o["trust_hist"]],
            "p_attack_last_flows": [round(float(x), 3) for x in list(o["p"])[-15:]],
            "decision_history": [{"t": tt, "action": ACTIONS[a]} for tt, a in list(o["acts"])[-15:]],
            "mean_packets_per_s": round(float(np.mean(o["pps"])), 1) if o["pps"] else None,
            "mean_kbit_per_s": round(float(np.mean(o["bps"])) / 1e3, 1) if o["bps"] else None,
            "destination_ports": dict(Counter(o["ports"]).most_common(5)),
        })
        return s

    def explain_decision(self, host: str) -> Dict[str, Any]:
        """Why the controller chose its last action for this host (TOPSIS, PPO and fused scores)."""
        i = self._idx(host)
        d = self.sim.obs[i]["last_decision"]
        if d is None:
            return {"host": host, "explanation": "no decision yet"}
        return {"host": self.sim.hosts[i].name, **d,
                "how_to_read": "final = 0.6*topsis + 0.4*ppo per action [ALLOW, MONITOR, RATE_LIMIT, REDIRECT, BLOCK]; "
                               "guardrail, if set, overrode the fused choice"}

    def get_threat_intel(self) -> Dict[str, Any]:
        return {"signatures": [{"cve": s.cve_id, "type": s.attack_type, "protocol": s.protocol,
                                "port": s.target_port, "cvss": s.cvss_score, "severity": s.severity}
                               for s in self.sim.signatures]}

    # ------------------------------------------------------------------ act
    def apply_override(self, host: str, action: str, duration_s: int = 30, reason: str = "") -> Dict[str, Any]:
        """Temporarily force an action for a host (MONITOR, RATE_LIMIT, REDIRECT or BLOCK)."""
        i = self._idx(host)
        h = self.sim.hosts[i]
        action = str(action).upper().replace(" ", "_")
        if action not in ACTIONS:
            return {"ok": False, "error": f"action must be one of {ACTIONS}"}
        if action == "ALLOW":
            return {"ok": False, "error": "The agent may not fully allow a host; use request_human_approval."}
        if h.ip in self.sim.engine.allow_list or h.ip in self.sim.engine.protected_assets:
            return {"ok": False, "error": f"{h.name} is allow-listed or protected; overrides are not permitted."}
        if self.actions_this_step >= MAX_ACTIONS_PER_STEP:
            return {"ok": False, "error": f"Limit of {MAX_ACTIONS_PER_STEP} overrides per review reached."}
        if not reason.strip():
            return {"ok": False, "error": "A reason is required for every override."}
        dur = int(max(5, min(MAX_OVERRIDE_S, int(duration_s))))
        self.sim.overrides[i] = {"action": ACTIONS.index(action), "until": self.t + dur, "reason": reason}
        self.actions_this_step += 1
        self._log("override", f"{h.name} ({h.ip}) -> {action} for {dur}s: {reason}", host=h.name, action=action)
        return {"ok": True, "host": h.name, "action": action, "until_t": self.t + dur}

    def release_override(self, host: str, reason: str = "") -> Dict[str, Any]:
        i = self._idx(host)
        if i not in self.sim.overrides:
            return {"ok": False, "error": "no override on this host"}
        del self.sim.overrides[i]
        self._log("release", f"{self.sim.hosts[i].name}: override released. {reason}", host=self.sim.hosts[i].name)
        return {"ok": True}

    def request_human_approval(self, host: str, action: str, reason: str) -> Dict[str, Any]:
        """Escalate an action the agent is not allowed to take alone (e.g. permanent quarantine, allow-listing)."""
        i = self._idx(host)
        h = self.sim.hosts[i]
        item = {"t": self.t, "host": h.name, "ip": h.ip, "action": str(action), "reason": reason, "status": "pending"}
        self.sim.pending_approvals.append(item)
        self._log("approval", f"Needs human approval: {action} on {h.name} ({h.ip}). {reason}", host=h.name)
        return {"ok": True, "queued": item}

    def open_incident(self, title: str, severity: str, hosts: List[str], findings: str,
                      recommendation: str = "") -> Dict[str, Any]:
        severity = str(severity).lower()
        if severity not in ("low", "medium", "high", "critical"):
            severity = "medium"
        inc = {"id": f"INC-{len(self.sim.incidents) + 1:03d}", "t": self.t, "title": title, "severity": severity,
               "hosts": [str(x) for x in hosts][:50], "findings": findings, "recommendation": recommendation}
        self.sim.incidents.append(inc)
        self._log("incident", f"{inc['id']} [{severity.upper()}] {title}", incident=inc["id"])
        return {"ok": True, "incident": inc["id"]}


# JSON schemas for LLM tool use (Anthropic Messages API format)
TOOL_SCHEMAS = [
    {"name": "get_overview", "description": "Network-wide snapshot: congestion per network, hosts per current action, active overrides, threat signatures and the lowest-trust hosts.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "list_hosts", "description": "List hosts by status. restricted = currently rate-limited/redirected/blocked; low_trust = trust < 0.3; flapping = 4+ decision changes in 20 s; emerging = matches a new CVE signature; overridden = has an agent override.",
     "input_schema": {"type": "object", "properties": {
         "status": {"type": "string", "enum": ["restricted", "low_trust", "flapping", "emerging", "overridden"]},
         "network": {"type": "string", "description": "Optional network filter, e.g. N2"},
         "limit": {"type": "integer", "default": 15}}, "required": ["status"]}},
    {"name": "get_host", "description": "Detailed view of one host: trust trend, recent IDS attack probabilities, decision history, packet/bit rates and destination ports.",
     "input_schema": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]}},
    {"name": "explain_decision", "description": "Explain the controller's last decision for a host: TOPSIS closeness, PPO probabilities, fused scores and any guardrail.",
     "input_schema": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]}},
    {"name": "get_threat_intel", "description": "CVE signatures currently registered by the threat-intelligence pipeline.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "apply_override", "description": "Temporarily force MONITOR, RATE_LIMIT, REDIRECT or BLOCK for a host (max 60 s). A reason is required. Cannot ALLOW, cannot touch protected or allow-listed hosts; the controller's hard-block guardrail still wins.",
     "input_schema": {"type": "object", "properties": {
         "host": {"type": "string"}, "action": {"type": "string", "enum": ["MONITOR", "RATE_LIMIT", "REDIRECT", "BLOCK"]},
         "duration_s": {"type": "integer", "default": 30}, "reason": {"type": "string"}}, "required": ["host", "action", "reason"]}},
    {"name": "release_override", "description": "Remove an override you set earlier.",
     "input_schema": {"type": "object", "properties": {"host": {"type": "string"}, "reason": {"type": "string"}}, "required": ["host"]}},
    {"name": "request_human_approval", "description": "Escalate an action you may not take alone, e.g. permanent quarantine, allow-listing a host, or re-imaging a compromised device.",
     "input_schema": {"type": "object", "properties": {"host": {"type": "string"}, "action": {"type": "string"}, "reason": {"type": "string"}},
                      "required": ["host", "action", "reason"]}},
    {"name": "open_incident", "description": "Record an incident for the report: title, severity (low/medium/high/critical), affected hosts, findings and recommendation.",
     "input_schema": {"type": "object", "properties": {
         "title": {"type": "string"}, "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
         "hosts": {"type": "array", "items": {"type": "string"}}, "findings": {"type": "string"},
         "recommendation": {"type": "string"}}, "required": ["title", "severity", "hosts", "findings"]}},
]


def call_tool(toolbox: SDNToolbox, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    fn = getattr(toolbox, name, None)
    if fn is None or name.startswith("_"):
        return {"ok": False, "error": f"unknown tool {name}"}
    try:
        return fn(**(args or {}))
    except (KeyError, ValueError, TypeError) as e:
        return {"ok": False, "error": str(e)}
