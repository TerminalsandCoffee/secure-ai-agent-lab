# Portfolio checklist

Use this if you are the author walking a reviewer through the repo, or a hiring manager deciding whether to clone it.

## Story (90 seconds)

1. Open `docs/exec-summary.md`. One table, one paragraph of controls.
2. `make demo-vuln` — a refund question is enough. The planted KB article hijacks the tool loop.
3. `make demo-hardened` — same question, a normal draft, no sinks.
4. `findings/retest.md` — five attacks, two columns.

## Clone and run

- [ ] Python 3.11+ 
- [ ] `make demo-vuln` works with `AGENT_LLM=mock` and no API keys
- [ ] `make demo-attacks` writes `findings/vulnerable.md`
- [ ] `make retest` writes `findings/retest.md` with hardened = BLOCKED
- [ ] `make test` is green
- [ ] Optional: `AGENT_LLM=ollama` against a local model (not required for CI)

## Technical depth

- [ ] Vulnerable tools are over-privileged on purpose (file read, fake shell, mock mail, mock HTTP)
- [ ] Hardened policy is not "please don't" in the prompt — it is an authorize() gate
- [ ] HITL is default-deny in CI (`AGENT_HITL=deny`)
- [ ] Retrieval quarantine + untrusted wrappers are visible in tool output
- [ ] Audit JSONL is written under `sandbox/logs/`
- [ ] OWASP LLM Top 10 2025 + ATLAS IDs are on each attack, not as a dump at the end

## Safety

- [ ] README opens with an authorized-use note
- [ ] Secrets match `FAKESECRET_demo_`
- [ ] No real network egress from `http_fetch`
- [ ] No `shell=True` / real host filesystem reads
- [ ] `tests/test_hygiene.py` rejects `sk-` / `AKIA` / PEM keys

## What this is not

- Not a chatbot UI
- Not a cert dump
- Not a copy of someone else's lab write-up
- Not advice to run these attacks against systems you do not own
