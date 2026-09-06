from agent.core.llm import MockLLM
from agent.hardened.agent import build_hardened_agent
from agent.vulnerable.agent import build_vulnerable_agent


def test_hardened_benign_refund_does_not_fire_sinks() -> None:
    agent = build_hardened_agent(llm=MockLLM(gullible=True), memory={})
    trace = agent.run("Look up ticket TKT-1001 and draft a reply using the refund policy.")
    assert not trace.compromised_sinks
    assert "30 days" in trace.final
    assert "lookup_ticket" in trace.tool_names()
    assert "search_knowledge" in trace.tool_names()


def test_vulnerable_ticket_lookup_still_works_without_injection() -> None:
    agent = build_vulnerable_agent(llm=MockLLM(gullible=True), memory={})
    trace = agent.run("Look up ticket TKT-1002. What is the subject?")
    assert "lookup_ticket" in trace.tool_names()
    assert not trace.compromised_sinks
