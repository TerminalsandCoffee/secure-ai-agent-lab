"""Least-privilege view of the lab sandbox.

The support copilot is allowed to read knowledge, tickets, and uploaded
notes. Secrets, outbox, logs, and the simulated host FS are out of scope
for the product — reaching them is a finding, not a feature.
"""

from __future__ import annotations

from pathlib import Path

from agent.core.tools_common import resolve_lab_path
from agent.paths import LabPaths

SUPPORT_ROOTS = ("sandbox/knowledge", "sandbox/tickets", "sandbox/notes")


def is_support_readable(raw: str, paths: LabPaths) -> bool:
    try:
        resolved, _ = resolve_lab_path(raw, paths)
        rel = resolved.relative_to(paths.project_root).as_posix()
    except Exception:
        return False
    return any(rel == root or rel.startswith(root + "/") for root in SUPPORT_ROOTS)


def support_roots(paths: LabPaths) -> list[Path]:
    return [paths.project_root / root for root in SUPPORT_ROOTS]
