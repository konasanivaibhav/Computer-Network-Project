"""
test_agent.py
=============
Agentic AI analyst: tool safety rules, the offline planner, and the Claude and
Groq (OpenAI-compatible) tool-use loops driven by mocked API responses.
"""

import json

from src.simulation.large_network_sim import LargeSDNSimulation
from src.agent import OfflinePlanner, LLMAgent, SDNToolbox, make_agent, write_report


def _sim(tmp_path, agent=None, **kw):
    return LargeSDNSimulation(n_hosts=kw.pop("n_hosts", 40), n_switches=3, duration=kw.pop("duration", 40),
                              attacker_ratio=0.1, compromised_ratio=0.05, bursty_ratio=0.2, agent=agent,
                              agent_interval=10, ids_model_path=str(tmp_path / "ids.joblib"),
                              ppo_model_path=str(tmp_path / "none.zip"), seed=4, **kw)


def test_toolbox_safety_rules(tmp_path):
    sim = _sim(tmp_path, duration=12)
    sim.run()
    tb = SDNToolbox(sim, 12, [])
    host = sim.hosts[0].name
    assert tb.apply_override(host, "ALLOW", 30, "trust me")["ok"] is False          # agent cannot allow
    assert tb.apply_override(host, "BLOCK", 30, "")["ok"] is False                  # reason required
    sim.engine.allow_list.add(sim.hosts[1].ip)
    assert tb.apply_override(sim.hosts[1].name, "BLOCK", 30, "x")["ok"] is False    # allow-listed host
    r = tb.apply_override(host, "RATE_LIMIT", 999, "test")
    assert r["ok"] and r["until_t"] == 12 + 60                                      # capped at 60 s
    assert tb.get_host(host)["override"]["action"] == "RATE_LIMIT"
    assert "role" not in json.dumps(tb.get_host(host))                             # no ground truth exposed
    assert tb.list_hosts("restricted")["count"] >= 0


def test_offline_agent_runs_and_reports(tmp_path):
    tr = _sim(tmp_path, agent=OfflinePlanner(), n_hosts=60, duration=60).run()
    ag = tr["agent"]
    assert ag["backend"] == "offline" and ag["reviews"] == 6
    assert any(e["type"] == "agent" for e in tr["events"])
    assert len({i["title"] for i in ag["incidents"]}) == len(ag["incidents"])      # one incident per situation
    assert tr["summary"]["proposed"]["attack_mitigation_pct"] > 90
    path = write_report(tr, str(tmp_path / "report.md"))
    assert "# Incident report" in open(path, encoding="utf-8").read()


def _scripted(responses, seen):
    it = iter(responses)

    def transport(url, headers, payload):
        seen.append((url, headers, payload))
        return next(it)
    return transport


def test_groq_backend_tool_loop(tmp_path):
    sim = _sim(tmp_path, duration=12)
    sim.run()
    target = sim.hosts[2].name
    seen = []
    replies = [
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "get_host", "arguments": json.dumps({"host": target})}}]}}]},
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "c2", "type": "function", "function": {"name": "apply_override", "arguments": json.dumps(
                {"host": target, "action": "MONITOR", "duration_s": 20, "reason": "unusual ports"})}}]}}]},
        {"choices": [{"message": {"content": "Monitored one host with unusual ports."}}]},
    ]
    agent = LLMAgent("groq", api_key="test-key", transport=_scripted(replies, seen))
    summary = agent.step(SDNToolbox(sim, 12, []))
    assert summary == "Monitored one host with unusual ports."
    assert sim.overrides[2]["action"] == 1
    url, headers, payload = seen[0]
    assert url == "https://api.groq.com/openai/v1/chat/completions"
    assert headers["Authorization"] == "Bearer test-key"
    assert payload["model"] == "openai/gpt-oss-120b"
    assert payload["tools"][0]["type"] == "function"
    assert seen[1][2]["messages"][-1]["role"] == "tool"                            # tool result sent back


def test_claude_backend_tool_loop(tmp_path):
    sim = _sim(tmp_path, duration=12)
    sim.run()
    seen = []
    replies = [
        {"content": [{"type": "tool_use", "id": "t1", "name": "get_overview", "input": {}}], "stop_reason": "tool_use"},
        {"content": [{"type": "text", "text": "Network is quiet."}], "stop_reason": "end_turn"},
    ]
    agent = LLMAgent("claude", api_key="k", transport=_scripted(replies, seen))
    assert agent.step(SDNToolbox(sim, 12, [])) == "Network is quiet."
    url, headers, payload = seen[0]
    assert url == "https://api.anthropic.com/v1/messages" and headers["x-api-key"] == "k"
    assert payload["model"] == "claude-sonnet-5-5" and payload["tools"][0]["name"] == "get_overview"
    assert seen[1][2]["messages"][-1]["content"][0]["type"] == "tool_result"


def test_llm_failure_falls_back_to_offline(tmp_path):
    sim = _sim(tmp_path, duration=12)
    sim.run()

    def broken(url, headers, payload):
        raise RuntimeError("HTTP 401: invalid key")
    agent = LLMAgent("groq", api_key="bad", transport=broken)
    out = agent.step(SDNToolbox(sim, 12, []))
    assert out.startswith("[offline fallback]") and "401" in agent.errors[0]


def test_make_agent_backends():
    assert make_agent("none") is None
    assert isinstance(make_agent("offline"), OfflinePlanner)
    assert make_agent("groq", api_key="x").url.startswith("https://api.groq.com")
    assert make_agent("ollama").url == "http://localhost:11434/v1/chat/completions"


def test_unavailable_model_switches_automatically(tmp_path, monkeypatch=None):
    sim = _sim(tmp_path, duration=12)
    sim.run()
    calls = []

    def transport(url, headers, payload):
        calls.append(payload["model"])
        if payload["model"] == "retired-model":
            raise RuntimeError('HTTP 404: {"error":{"message":"The model `retired-model` does not exist","code":"model_not_found"}}')
        return {"choices": [{"message": {"content": "All quiet."}}]}

    class FakeResp:
        def json(self):
            return {"data": [{"id": "whisper-large-v3"}, {"id": "openai/gpt-oss-20b"}, {"id": "llama-3.1-8b-instant"}]}

    import requests
    original = requests.get
    requests.get = lambda *a, **k: FakeResp()
    try:
        agent = LLMAgent("groq", model="retired-model", api_key="k", transport=transport)
        assert agent.step(SDNToolbox(sim, 12, [])) == "All quiet."
    finally:
        requests.get = original
    assert agent.model == "openai/gpt-oss-20b" and calls == ["retired-model", "openai/gpt-oss-20b"]
    assert "switched to openai/gpt-oss-20b" in agent.errors[0]
