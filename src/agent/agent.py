"""
agent.py
========
Agentic AI security analyst for the SDN framework.

Every `interval` simulated seconds the agent runs an observe -> investigate ->
act -> record loop over the tools in tools.py. Backends:

  offline   Rule-based planner. No API key, deterministic, always available.
  claude    Anthropic Messages API with tool use        (ANTHROPIC_API_KEY)
  groq      Groq, OpenAI-compatible chat completions     (GROQ_API_KEY)
  openai    Any OpenAI-compatible endpoint: OpenAI, a local Ollama server, ...
            (OPENAI_API_KEY, --base_url)

If an LLM call fails (no network, bad key, rate limit) that review falls back to
the offline planner and the failure is recorded in the agent log.
"""

import json
import os
from collections import Counter
from typing import Any, Callable, Dict, List, Optional

from src.agent.tools import SDNToolbox, TOOL_SCHEMAS, call_tool

SYSTEM_PROMPT = """You are a security operations agent supervising a software-defined network.
An automated controller already scores every flow with a calibrated Random Forest IDS,
keeps a Bayesian trust score per host, and picks an action per flow (ALLOW, MONITOR,
RATE_LIMIT, REDIRECT to honeypot, BLOCK) by fusing AHP-TOPSIS with a PPO policy.

Your job at each review:
1. Look at the overview, then investigate what needs attention: hosts that keep flipping
   between allow and block (possible false positives on a legitimate host), clusters of
   restricted hosts in one network (coordinated attack), hosts matching a new CVE signature,
   and persistently untrusted hosts.
2. Use tools to check evidence before acting. You cannot see ground truth, only telemetry.
3. Act with temporary overrides when they reduce harm: e.g. RATE_LIMIT instead of repeated
   BLOCK for a mostly-clean bursty host; MONITOR neighbours during a coordinated attack;
   REDIRECT exploit traffic to the honeypot for forensics.
4. Escalate anything permanent (quarantine, allow-listing, re-imaging) with request_human_approval.
5. Record each distinct situation once with open_incident (do not repeat incidents you already opened).
Prefer few, well-justified actions. Never act on protected or allow-listed hosts.
Finish with a two-sentence summary of what you found and did."""


# ======================================================================
# Offline planner
# ======================================================================
class OfflinePlanner:
    """Deterministic analyst playbook built on the same tools the LLM uses."""

    name = "offline"

    PROBATION_S = 90

    def __init__(self):
        self.incident_ids = {}      # situation key -> incident id (one incident per situation)
        self.escalated = set()
        self.probation = {}         # host -> tick until which it stays under watch

    def _incident(self, tb: SDNToolbox, key, title, severity, hosts, findings, recommendation="") -> bool:
        """Open an incident once per situation; later reviews add newly involved hosts to it."""
        if key in self.incident_ids:
            inc = next(i for i in tb.sim.incidents if i["id"] == self.incident_ids[key])
            new = [h for h in hosts if h not in inc["hosts"]]
            if new:
                inc["hosts"].extend(new)
                inc["findings"] = findings
                inc["updated_t"] = tb.t
            return False
        res = tb.open_incident(title, severity, hosts, findings, recommendation)
        self.incident_ids[key] = res["incident"]
        return True

    def step(self, tb: SDNToolbox) -> str:
        notes = []
        ov = tb.get_overview()

        # 1. Flapping hosts whose recent flows are mostly clean -> likely false positives
        flapping = tb.list_hosts("flapping", limit=50)["hosts"]
        fp_hosts = [h for h in flapping
                    if (h["share_flows_flagged_recent"] or 0) <= 0.6 and h["trust"] >= 0.3 and not h["signature_match"]]
        for h in fp_hosts:
            tb.apply_override(h["host"], "RATE_LIMIT", 20,
                              f"Decision flapping ({h['decision_changes_last_20s']} changes/20s) with "
                              f"{(1 - h['share_flows_flagged_recent']) * 100:.0f}% clean flows and trust {h['trust']}: "
                              "throttle instead of repeated hard blocks while the burst lasts")
        if fp_hosts:
            self._incident(tb, ("fp",), "Suspected false positives on bursty hosts", "low", [h["host"] for h in fp_hosts],
                           "Hosts alternate between ALLOW and BLOCK while most of their flows are clean; the pattern "
                           "matches a legitimate surge in which some sessions time out.",
                           "Temporary rate limiting applied instead of hard blocks. Review IDS behaviour for "
                           "overloaded-server sessions.")
            notes.append(f"throttled {len(fp_hosts)} flapping host(s)")

        # 2. Emerging-threat matches -> keep exploit traffic in the honeypot for forensics
        emerging = [h for h in tb.list_hosts("emerging", limit=50)["hosts"] if h["mean_p_attack_recent"] and h["mean_p_attack_recent"] >= 0.5]
        for h in emerging:
            if h["override"] is None:
                tb.apply_override(h["host"], "REDIRECT", 30,
                                  f"Traffic matches {h['signature_match']}; capture payloads in the honeypot")
            if h["host"] not in self.escalated:
                self.escalated.add(h["host"])
                tb.request_human_approval(h["host"], "Quarantine VLAN and re-image",
                                          f"Host exploited {h['signature_match']}; likely compromised device")
        new_cves = {h["signature_match"] for h in emerging}
        for cve in new_cves:
            hosts = [h["host"] for h in emerging if h["signature_match"] == cve]
            self._incident(tb, ("cve", cve), f"Exploitation of {cve}", "critical", hosts,
                           f"Hosts sending traffic that matches the {cve} signature with high IDS confidence.",
                           "Patch the target service; keep affected hosts quarantined pending approval.")
            notes.append(f"{len(hosts)} host(s) exploiting {cve}")

        # 3. Coordinated activity: 3+ low-trust restricted hosts in one network
        for net in ov["networks"]:
            bad = [h for h in tb.list_hosts("low_trust", network=net["network"], limit=200)["hosts"]
                   if h["current_action"] in ("REDIRECT", "BLOCK") and not h["signature_match"]]
            if len(bad) >= 3:
                ports = Counter()
                for h in bad[:20]:
                    ports.update(tb.get_host(h["host"])["destination_ports"])
                self._incident(tb, ("coord", net["network"]), f"Coordinated malicious activity in {net['network']}", "high",
                               [h["host"] for h in bad],
                               f"Untrusted hosts restricted in {net['network']}; most targeted ports {dict(ports.most_common(3))}.",
                               "Keep blocks in place; check these hosts for a shared infection vector.")
                notes.append(f"{len(bad)} untrusted hosts restricted in {net['network']}")
                # escalate persistent attackers once
                for h in bad:
                    if h["trust"] < 0.05 and h["host"] not in self.escalated:
                        self.escalated.add(h["host"])
                        tb.request_human_approval(h["host"], "Permanent block at the access port",
                                                  f"Trust {h['trust']} and repeated blocks")
        # 4. Probation: a host the controller blocked or redirected stays under watch for
        #    PROBATION_S seconds. If it is let through again during that time (e.g. a low-rate
        #    or previously unseen attack that the IDS scores as harmless), it is throttled.
        for h in tb.list_hosts("restricted", limit=1000)["hosts"]:
            if h["current_action"] in ("REDIRECT", "BLOCK") and h["trust"] < 0.3 and h["override"] is None:
                self.probation[h["host"]] = tb.t + self.PROBATION_S
        sneaking = []
        for name, until in list(self.probation.items()):
            if until < tb.t:
                del self.probation[name]
                continue
            st = tb.get_host(name)
            if st["current_action"] in ("ALLOW", "MONITOR") and st["override"] is None and st["trust"] < 0.6:
                sneaking.append(st)
        for h in sneaking:
            tb.apply_override(h["host"], "RATE_LIMIT", 30,
                              f"On probation after being blocked (trust {h['trust']}); now allowed with IDS score "
                              f"{h['mean_p_attack_recent']}: throttle possible low-rate or unseen attack")
        if sneaking:
            self._incident(tb, ("evasive",), "Recently blocked hosts getting through with low IDS scores", "high",
                           [h["host"] for h in sneaking],
                           "Hosts blocked moments ago are now sending traffic the IDS rates as harmless while their "
                           "trust rebuilds. This fits low-rate or previously unseen attacks (e.g. slowloris).",
                           "Keep them throttled; capture samples of this traffic and retrain the IDS on it.")
            notes.append(f"throttled {len(sneaking)} host(s) on probation")
        return "; ".join(notes) if notes else "no action needed"


# ======================================================================
# LLM backends
# ======================================================================
def _http_post(url: str, headers: Dict[str, str], payload: Dict[str, Any], timeout: float = 60.0) -> Dict[str, Any]:
    import requests
    r = requests.post(url, headers=headers, json=payload, timeout=timeout)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


class LLMAgent:
    """Tool-using LLM agent. `transport` can be replaced in tests."""

    def __init__(self, provider: str = "claude", model: Optional[str] = None, api_key: Optional[str] = None,
                 base_url: Optional[str] = None, max_tool_calls: int = 12, max_tokens: int = 1200,
                 transport: Callable = _http_post):
        self.provider = provider
        defaults = {
            "claude": ("claude-sonnet-5-5", "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1/messages"),
            "groq": ("openai/gpt-oss-120b", "GROQ_API_KEY", "https://api.groq.com/openai/v1/chat/completions"),
            "openai": ("gpt-4o-mini", "OPENAI_API_KEY", "https://api.openai.com/v1/chat/completions"),
        }
        if provider not in defaults:
            raise ValueError("provider must be claude, groq or openai")
        dm, env, url = defaults[provider]
        self.model = model or dm
        self.api_key = api_key or os.environ.get(env, "")
        if base_url:
            url = base_url.rstrip("/")
            if provider != "claude" and not url.endswith("/chat/completions"):
                url += "/chat/completions"
        self.url = url
        self.env_name = env
        self.max_tool_calls, self.max_tokens = max_tool_calls, max_tokens
        self.transport = transport
        self.memory: List[str] = []
        self.fallback = OfflinePlanner()
        self.name = f"{provider}:{self.model}"
        self.calls = 0
        self.errors: List[str] = []
        self.model_checked = False

    # Models tried, in order, when the requested one is unavailable to this account
    PREFERRED = ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "llama-3.3-70b-versatile", "meta-llama/llama-4",
                 "qwen", "moonshotai/kimi", "llama-3.1-8b-instant", "gpt-4o-mini", "gpt-4.1-mini"]

    def _switch_model(self, error_text: str) -> bool:
        """On 'model not found', ask the provider which models this key can use and pick one."""
        if self.model_checked or self.provider == "claude" or "model" not in error_text.lower():
            return False
        self.model_checked = True
        try:
            import requests
            url = self.url.rsplit("/chat/completions", 1)[0] + "/models"
            r = requests.get(url, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=30)
            ids = [m.get("id", "") for m in r.json().get("data", [])]
        except Exception as e:  # noqa: BLE001
            self.errors.append(f"could not list models: {e}")
            return False
        for pref in self.PREFERRED:
            match = next((i for i in ids if i == pref or i.startswith(pref)), None)
            if match and match != self.model:
                self.errors.append(f"model {self.model} not available to this key; switched to {match}")
                self.model, self.name = match, f"{self.provider}:{match}"
                return True
        self.errors.append(f"model {self.model} not available; models on this key: {', '.join(ids[:15])}")
        return False

    def _user_msg(self, tb: SDNToolbox) -> str:
        mem = "\n".join(f"- {m}" for m in self.memory[-4:]) or "- (first review)"
        incidents = ", ".join(f"{i['id']} {i['title']}" for i in tb.sim.incidents[-8:]) or "none"
        return (f"Review at t={tb.t}s.\nYour notes from earlier reviews:\n{mem}\n"
                f"Incidents already opened: {incidents}\n"
                f"Current overview:\n{json.dumps(tb.get_overview())}")

    # ---- Anthropic Messages API -----------------------------------------
    def _step_claude(self, tb: SDNToolbox) -> str:
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        messages = [{"role": "user", "content": self._user_msg(tb)}]
        for _ in range(self.max_tool_calls + 1):
            resp = self.transport(self.url, headers, {"model": self.model, "max_tokens": self.max_tokens,
                                                      "system": SYSTEM_PROMPT, "tools": TOOL_SCHEMAS, "messages": messages})
            self.calls += 1
            blocks = resp.get("content", [])
            uses = [b for b in blocks if b.get("type") == "tool_use"]
            if not uses:
                return " ".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
            messages.append({"role": "assistant", "content": blocks})
            results = [{"type": "tool_result", "tool_use_id": u["id"],
                        "content": json.dumps(call_tool(tb, u["name"], u.get("input") or {}))[:6000]} for u in uses]
            messages.append({"role": "user", "content": results})
        return "stopped after the tool-call limit"

    # ---- OpenAI-compatible (Groq, OpenAI, Ollama) ------------------------
    def _step_openai(self, tb: SDNToolbox) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                   "parameters": t["input_schema"]}} for t in TOOL_SCHEMAS]
        messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": self._user_msg(tb)}]
        for _ in range(self.max_tool_calls + 1):
            resp = self.transport(self.url, headers, {"model": self.model, "messages": messages, "tools": tools,
                                                      "tool_choice": "auto", "max_tokens": self.max_tokens, "temperature": 0.2})
            self.calls += 1
            msg = resp["choices"][0]["message"]
            calls = msg.get("tool_calls") or []
            if not calls:
                return (msg.get("content") or "").strip()
            messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
            for c in calls:
                try:
                    args = json.loads(c["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                out = call_tool(tb, c["function"]["name"], args)
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": json.dumps(out)[:6000]})
        return "stopped after the tool-call limit"

    def step(self, tb: SDNToolbox) -> str:
        if not self.api_key and "localhost" not in self.url and "127.0.0.1" not in self.url:
            msg = f"{self.env_name} is not set; used the offline planner for this review"
            if msg not in self.errors:
                self.errors.append(msg)
            return "[offline fallback] " + self.fallback.step(tb)
        run = self._step_claude if self.provider == "claude" else self._step_openai
        try:
            summary = run(tb)
        except Exception as e:  # network, auth, rate limit, malformed reply
            if "404" in str(e) and self._switch_model(str(e)):
                try:
                    summary = run(tb)
                except Exception as e2:  # noqa: BLE001
                    self.errors.append(f"t={tb.t}: {e2}")
                    return "[offline fallback] " + self.fallback.step(tb)
            else:
                self.errors.append(f"t={tb.t}: {e}")
                return "[offline fallback] " + self.fallback.step(tb)
        self.memory.append(f"t={tb.t}: {summary[:300]}")
        return summary


def make_agent(backend: str = "offline", model: Optional[str] = None, base_url: Optional[str] = None,
               api_key: Optional[str] = None):
    backend = (backend or "offline").lower()
    if backend in ("none", "off"):
        return None
    if backend == "offline":
        return OfflinePlanner()
    if backend in ("claude", "anthropic"):
        return LLMAgent("claude", model, api_key, base_url)
    if backend == "groq":
        return LLMAgent("groq", model, api_key, base_url)
    if backend in ("openai", "ollama"):
        url = base_url or ("http://localhost:11434/v1" if backend == "ollama" else None)
        return LLMAgent("openai", model or ("llama3.1" if backend == "ollama" else None), api_key, url)
    raise ValueError("agent backend must be offline, claude, groq, openai or ollama")


# ======================================================================
# Report
# ======================================================================
def write_report(trace: Dict[str, Any], path: str) -> str:
    ag = trace.get("agent", {})
    s = trace["summary"]
    lines = [f"# Incident report: {trace['meta']['title']}", "",
             f"Agent backend: **{ag.get('backend', 'none')}** · reviews: {ag.get('reviews', 0)} · "
             f"overrides: {ag.get('overrides', 0)} · incidents: {len(ag.get('incidents', []))} · "
             f"pending approvals: {len(ag.get('pending_approvals', []))}", "",
             "## Outcome", "",
             "| | Attacks mitigated | Benign flows served | Benign flows blocked |", "| --- | --- | --- | --- |",
             f"| Framework + agent | {s['proposed']['attack_mitigation_pct']}% | {s['proposed']['benign_served_pct']}% | {s['proposed']['benign_blocked']} |",
             f"| Static block at P ≥ 0.5 | {s['static_threshold_0_5']['attack_mitigation_pct']}% | {s['static_threshold_0_5']['benign_served_pct']}% | {s['static_threshold_0_5']['benign_blocked']} |",
             "", "## Incidents", ""]
    for inc in ag.get("incidents", []):
        hosts = ", ".join(inc["hosts"][:12]) + (" …" if len(inc["hosts"]) > 12 else "")
        upd = f" (updated t={inc['updated_t']}s)" if inc.get("updated_t") else ""
        lines += [f"### {inc['id']} · {inc['severity'].upper()} · opened t={inc['t']}s{upd} · {inc['title']}", "",
                  f"**Hosts ({len(inc['hosts'])}):** {hosts}", "", f"**Findings:** {inc['findings']}", ""]
        if inc.get("recommendation"):
            lines += [f"**Recommendation:** {inc['recommendation']}", ""]
    if not ag.get("incidents"):
        lines += ["No incidents recorded.", ""]
    lines += ["## Waiting for human approval", ""]
    for a in ag.get("pending_approvals", []):
        lines.append(f"- t={a['t']}s · {a['host']} ({a['ip']}): **{a['action']}** · {a['reason']}")
    if not ag.get("pending_approvals"):
        lines.append("None.")
    lines += ["", "## Review log", ""]
    for r in ag.get("review_summaries", []):
        lines.append(f"- t={r['t']}s: {r['summary']}")
    if ag.get("errors"):
        lines += ["", "## Backend issues", ""] + [f"- {e}" for e in ag["errors"]]
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path
