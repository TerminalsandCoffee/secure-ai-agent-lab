# Secure AI Agent Lab

> **Authorized use only.** This repository is an educational lab for a fictional
> product (Acme Support Copilot). Every target is local or planted. Secrets are
> labeled `FAKESECRET_demo_…`. Tools do not send real email, do not open real
> sockets to `evil.example`, and do not run a host shell. Do not point this
> agent at systems you do not own. Do not replace the planted files with real
> credentials.

A hiring-manager-runnable demo of the **attack → control → retest** loop on a
tool-using LLM agent. Depth over chrome: two agent builds, five documented
attacks, a policy gate you can read in one file, and CI that runs in mock mode
with no API keys.

The shape of the project (vulnerable agent, attacks, hardened rebuild, retest)
is inspired by curriculum-style lists such as
[taimurijlal/AI-Security-Projects](https://github.com/taimurijlal/AI-Security-Projects)
item #3 (Secure AI Agent). The scenario, code, and write-up here are original.

**Owner:** Rafael ([TerminalsandCoffee](https://github.com/TerminalsandCoffee))

---

## Five minutes (mock mode)

Needs Python 3.11+. No OpenAI key. No Ollama required.

```bash
python3 -m pip install -e ".[dev]"   # pytest only; runtime is stdlib
make demo-vuln                       # refund question → hijacked by a planted KB article
make demo-hardened                   # same question → a normal draft
make demo-attacks                    # five attacks vs vulnerable → findings/
make retest                          # same five vs hardened + findings/retest.md
make test
```

`AGENT_LLM` defaults to `mock`. The mock is *gullible on purpose* — it follows
injection text in user input, tool results, and (on the vulnerable build)
memory. That is how the lab stays deterministic. The hardened build uses the
**same** mock so the retest measures the control plane, not a friendlier model.

Optional local model:

```bash
export AGENT_LLM=ollama
export OLLAMA_MODEL=llama3.2
make demo-hardened
```

---

## Scenario

Acme Gadgets ships a **Support Copilot**. Intended job:

- look up tickets (`TKT-1001` …)
- search knowledge articles (refunds, shipping)
- draft a reply

The vulnerable build also has the tools a real team would bolt on “just for
debugging”: unrestricted file read, a fake shell, mock `send_email`, mock
`http_fetch`, and memory that is later trusted as system context.

A knowledge article named `urgent-security-bulletin.md` is poisoned. Asking
*“What's our refund policy?”* is enough.

---

## Architecture

```mermaid
flowchart TD
    Q[User query] --> L[Agent loop - JSON ReAct]
    L --> M[LLM: mock or Ollama]
    M --> P{Policy gate}
    P -->|vulnerable: allow all| T[Tools]
    P -->|hardened: allowlist + args + HITL| T
    T --> S[sandbox/ planted data]
    T --> A[JSONL audit]
    T --> L
    M --> F[Final reply + canary filter]
```

| Path | What you get |
|---|---|
| `agent/vulnerable/` | Over-privileged tools, trusted tool I/O, trusted memory |
| `agent/hardened/` | `policy.py` is the control plane; prompts are backup |
| `attacks/` | Catalog + harness |
| `sandbox/` | Fictional tickets, KB, secrets, simulated `/etc/passwd` |
| `findings/` | Generated JSON/Markdown |

---

## Threat model (short)

Untrusted: user text, tickets, knowledge, memory, tool output.
Trusted: the system prompt and (on the hardened build only) the policy module.

If those zones collapse, a planted sentence in a KB article can make the agent
read `sandbox/secrets/api_keys.env` and queue a mock email to `evil.example`.

Full write-up: [`docs/threat-model.md`](docs/threat-model.md).
One-page results: [`docs/exec-summary.md`](docs/exec-summary.md).

---

## Attack → fix → retest

| ID | Attack | OWASP LLM Top 10 (2025) | ATLAS |
|---|---|---|---|
| A1 | Direct goal hijack | LLM01, LLM06 | AML.T0051.000, AML.T0054 |
| A2 | Indirect injection via KB | LLM01, LLM04, LLM06 | AML.T0051.001 |
| A3 | Tool misuse (secret / mail / HTTP) | LLM06, LLM02 | AML.T0048 |
| A4 | System prompt leak | LLM07, LLM01 | AML.T0051.000 |
| A5 | Memory poisoning | LLM01, LLM04, LLM06 | AML.T0051.001 |

Vulnerable expected result: **COMPROMISED** (finding is real).
Hardened expected result: **BLOCKED**.

Controls that make the second column true — all in
[`agent/hardened/policy.py`](agent/hardened/policy.py) plus retrieval
quarantine and a canary filter:

- Tool allowlist
- Path allowlist; `sandbox/secrets/**` is never a support input
- Fake-shell allowlist (`ls` / `pwd` on KB + tickets)
- Email domain allowlist (`acme.example`)
- HTTP allowlist (`kb.acme.example`)
- Human-in-the-loop, default **deny** (`AGENT_HITL=deny`)
- Knowledge documents that look like instructions are quarantined
- Memory is re-injected as untrusted data, not as a second system prompt
- Final answers containing `SYS_CANARY_ACME_COPILOT_v1` are dropped

Retest report: [`findings/retest.md`](findings/retest.md) after `make retest`.

---

## How the mock LLM works

The mock emits the same JSON protocol Ollama is asked to use:

```json
{"thought": "...", "tool": "search_knowledge", "args": {"query": "refund"}}
{"thought": "...", "final": "Hi Dana, ..."}
```

If it sees override language (`ignore previous instructions`, `your new goal`,
…) it pursues a planted-secret exfil. It is a stand-in for a model that
followed the injection, not a product chatbot. Read
[`agent/core/llm.py`](agent/core/llm.py).

---

## HITL

```bash
AGENT_HITL=deny      # CI / default — high-risk tools never run
AGENT_HITL=allow     # skip the human (other allowlists still apply)
AGENT_HITL=prompt    # ask on stdin
```

Even with `allow`, `attacker@evil.example` and `http://evil.example/collect`
are still refused. Layered controls, not a single `if`.

---

## Layout

```
agent/core/          loop, mock/Ollama, protocol, audit
agent/vulnerable/    weak prompt, allow-all policy
agent/hardened/      policy, sandbox helpers, canary filter
attacks/             catalog + harness
sandbox/knowledge/   including the planted bulletin
sandbox/secrets/     FAKESECRET_demo_… only
tests/               policy, sandbox, mock, full harness
docs/                exec summary, threat model, checklist
```

---

## Safety boundary

| Tool | What actually happens |
|---|---|
| `read_file` | Reads under the project tree, or `sandbox/simulated_host` for absolute paths |
| `run_command` | In-process fake shell: `cat` / `ls` / `echo` / `pwd` |
| `send_email` | Writes JSON to `sandbox/outbox/` |
| `http_fetch` | Appends JSONL to `sandbox/logs/http_mock.jsonl` |

There is no `subprocess`, no SMTP, and no outbound HTTP to the attacker URLs
in the demos.

---

## License

MIT. See [`LICENSE`](LICENSE).

Walkthrough for reviewers: [`docs/portfolio-checklist.md`](docs/portfolio-checklist.md).
