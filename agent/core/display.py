"""Terminal rendering for a single agent trace."""

from __future__ import annotations

from agent.core.types import AgentTrace, TraceStep


def render_trace(trace: AgentTrace, *, verbose: bool = True) -> str:
    lines = [
        f"+-- {trace.agent}",
        f"| query: {trace.query}",
    ]
    if len(trace.turns) > 1:
        for i, turn in enumerate(trace.turns[1:], start=2):
            lines.append(f"| turn {i}: {turn}")
    lines.append("|")

    for index, step in enumerate(trace.steps, start=1):
        lines.extend(_render_step(index, step, verbose=verbose))

    if trace.final:
        preview = _clip(trace.final, 400)
        lines.append(f"| final: {preview}")

    if trace.compromised_sinks:
        lines.append(f"| sinks: {', '.join(trace.compromised_sinks)}")
        lines.append("+-- COMPROMISED (expected on the vulnerable agent)")
    else:
        lines.append("+-- no unauthorized sinks fired")
    return "\n".join(lines)


def _render_step(index: int, step: TraceStep, *, verbose: bool) -> list[str]:
    lines: list[str] = []
    if step.final and step.tool is None:
        return lines
    if step.thought and verbose:
        lines.append(f"| [{index}] thought: {step.thought}")
    if step.tool:
        lines.append(f"| [{index}] tool   : {step.tool} {step.args}")
    if step.decision is not None:
        flag = "ALLOW" if step.decision.allowed else "DENY"
        lines.append(f"| [{index}] policy : {flag} — {step.decision.reason}")
    if step.result is not None:
        if step.result.denied:
            lines.append(f"| [{index}] result : denied ({step.result.reason})")
        else:
            body = _clip(step.result.output or step.result.reason, 220 if verbose else 80)
            status = "ok" if step.result.ok else "error"
            lines.append(f"| [{index}] result : {status} {body}")
    return lines


def _clip(text: str, limit: int) -> str:
    compact = " ".join((text or "").split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."
