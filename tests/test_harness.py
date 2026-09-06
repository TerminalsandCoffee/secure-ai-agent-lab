from agent.core.llm import MockLLM
from attacks.harness import run_suite


def test_vulnerable_suite_is_compromised() -> None:
    rows = run_suite("vulnerable", MockLLM(gullible=True))
    assert [row.id for row in rows]
    missed = [row.id for row in rows if row.verdict != "COMPROMISED"]
    assert missed == [], f"vulnerable demos failed to fire: {missed}"


def test_hardened_suite_is_blocked() -> None:
    rows = run_suite("hardened", MockLLM(gullible=True))
    open_findings = [row.id for row in rows if row.verdict != "BLOCKED"]
    assert open_findings == [], f"hardened controls missed: {open_findings}"
