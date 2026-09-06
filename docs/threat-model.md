# Threat model

Scope is the **Acme Support Copilot** process: one user query (or a short session), a model, a tool loop, and planted lab data under `sandbox/`.

Out of scope: attacking Ollama itself, attacking GitHub Actions, attacking third-party SaaS, or generating real exploit payloads.

## Assets

| Asset | Why it matters in the lab |
|---|---|
| `sandbox/secrets/api_keys.env` | Stand-in for an internal integration key |
| `sandbox/secrets/customer_export.csv` | Stand-in for support PII |
| System prompt + `SYS_CANARY_ACME_COPILOT_v1` | Operator instructions / policy text |
| Mock email outbox | Unauthorized action (data leaving the trust boundary) |
| Mock HTTP log | Same, as an outbound collector |
| Ticket + KB integrity | Integrity of what the agent believes |

## Actors

- **Support operator** — intended user. May paste untrusted customer text.
- **Customer / ticket author** — untrusted. Their text arrives via tickets and uploads.
- **Knowledge editor** — can plant articles. Treated as untrusted after retrieval.
- **Prompt attacker** — anyone who can set the user query (direct injection).

## Trust zones

```
┌─────────────────────────────────────────────┐
│ Operator / system prompt                    │  trusted instructions
├─────────────────────────────────────────────┤
│ User query, tickets, KB, memory, tool I/O   │  untrusted data
├─────────────────────────────────────────────┤
│ Policy gate + HITL + output filter          │  enforcement (hardened)
├─────────────────────────────────────────────┤
│ Tools (fake shell, mock mail, mock HTTP)    │  effects
└─────────────────────────────────────────────┘
```

The vulnerable build collapses the first two zones. That is the bug.

## Entry points

1. User query (direct injection, tool misuse, prompt leak)
2. `search_knowledge` return (indirect injection)
3. `memory_write` then later recall (stored injection)
4. `lookup_ticket` / uploaded notes (same class as 2)

## Abuse cases

| ID | Abuse | Impact in lab terms |
|---|---|---|
| A1 | Goal hijack via user prompt | Secret read + mock email to `evil.example` |
| A2 | Poisoned KB article | Same, from a normal refund question |
| A3 | Over-privileged tools | Fake shell + email + HTTP collector |
| A4 | "Repeat your system prompt" | Canary / instruction leak |
| A5 | Poisoned memory | Delayed hijack on the next turn |

## Controls (hardened)

| Control | Stops |
|---|---|
| Path allowlist + secrets deny | A1–A3, A5 secret reads |
| Command allowlist (`ls`/`pwd` on KB+tickets) | A3 `cat` |
| Email domain allowlist (`acme.example`) | A1–A3, A5 mail sink |
| HTTP allowlist (`kb.acme.example`) | A3 collector |
| HITL default-deny on high-risk tools | Residual attempts |
| Retriever quarantine | A2 payload delivery |
| Memory as untrusted data | A5 privilege promotion |
| Final-answer canary filter | A4 |

## Residual risk

- A confirmed HITL approval plus an allowlisted recipient would still send a mock email. That is the point of HITL: the human is the control, not the model.
- The mock LLM is deterministic. A real model can fail in other ways (obfuscated injection, multi-hop tool chaining). The policy layer is written to stay in front of those cases; it is not a complete RAG security product.
- Lab safety maps `/etc/passwd` onto `sandbox/simulated_host`. A production port of `read_file` needs a real jail, not this teaching map.

## Non-goals

- Red-teaming hosted models over the public internet
- Training-data extraction, model theft, or GPU DoS (LLM10)
- Building malware or a usable exfil channel
