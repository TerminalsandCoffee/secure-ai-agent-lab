"""Shared CLI for both copilots."""

from __future__ import annotations

import argparse
import json
import sys

from agent.core.display import render_trace
from agent.core.llm import load_backend
from agent.core.types import AgentTrace


def build_parser(agent_name: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Acme Support Copilot ({agent_name})",
    )
    parser.add_argument("--query", "-q", help="Single user query")
    parser.add_argument(
        "--llm",
        default=None,
        help="mock (default) or ollama. Overrides AGENT_LLM.",
    )
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--json", action="store_true", help="Print machine-readable trace")
    parser.add_argument("--repl", action="store_true", help="Interactive loop")
    return parser


def run_cli(agent_name: str, argv: list[str] | None = None) -> int:
    parser = build_parser(agent_name)
    args = parser.parse_args(argv)
    llm = load_backend(args.llm, gullible=True)

    if agent_name == "hardened":
        from agent.hardened.agent import build_hardened_agent

        agent = build_hardened_agent(llm=llm)
    else:
        from agent.vulnerable.agent import build_vulnerable_agent

        agent = build_vulnerable_agent(llm=llm)
    agent.max_steps = args.max_steps

    if args.repl:
        return _repl(agent)

    query = args.query or "What's our refund policy for a toaster bought 12 days ago?"
    trace = agent.run(query)
    _emit(trace, as_json=args.json)
    agent.audit.close()
    return 0


def _repl(agent) -> int:
    print(f"{agent.name} copilot. Ctrl-D to exit.")
    while True:
        try:
            query = input("you> ").strip()
        except EOFError:
            print()
            return 0
        if not query or query in {"quit", "exit"}:
            return 0
        trace = agent.run(query)
        print(render_trace(trace))
        print()


def _emit(trace: AgentTrace, *, as_json: bool) -> None:
    if as_json:
        json.dump(
            {
                "agent": trace.agent,
                "query": trace.query,
                "final": trace.final,
                "sinks": trace.compromised_sinks,
                "tools": [
                    {
                        "tool": s.tool,
                        "args": s.args,
                        "denied": bool(s.result.denied) if s.result else False,
                        "ok": bool(s.result.ok) if s.result else None,
                        "reason": s.decision.reason if s.decision else "",
                    }
                    for s in trace.steps
                    if s.tool
                ],
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return
    print(render_trace(trace))
