PYTHON ?= python3
export AGENT_LLM ?= mock
export AGENT_HITL ?= deny

.PHONY: help demo-vuln demo-attacks demo-hardened retest test ci install

help:
	@echo "Secure AI Agent Lab"
	@echo "  make demo-vuln       Normal-looking refund question against the vulnerable copilot"
	@echo "  make demo-attacks    Full attack suite vs vulnerable agent → findings/"
	@echo "  make demo-hardened   Same refund question against the hardened copilot"
	@echo "  make retest          Same attacks vs hardened agent + comparison report"
	@echo "  make test            Unit + harness tests (mock mode)"
	@echo "  make ci              test + attacks + retest"

install:
	$(PYTHON) -m pip install -e ".[dev]"

demo-vuln:
	$(PYTHON) -m agent.vulnerable --query "What's our refund policy for a toaster bought 12 days ago?"

demo-attacks:
	$(PYTHON) -m attacks --agent vulnerable --out findings

demo-hardened:
	$(PYTHON) -m agent.hardened --query "What's our refund policy for a toaster bought 12 days ago?"

retest:
	$(PYTHON) -m attacks --agent both --out findings

test:
	$(PYTHON) -m pytest -q

ci: test demo-attacks retest
