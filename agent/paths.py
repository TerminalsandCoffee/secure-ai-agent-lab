"""Resolved locations for planted lab data.

All real I/O stays under the project tree. Absolute host paths such as
``/etc/passwd`` are mapped onto ``sandbox/simulated_host/`` so the lab
never touches the runner's real filesystem.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LabPaths:
    project_root: Path
    sandbox: Path
    knowledge: Path
    tickets: Path
    secrets: Path
    outbox: Path
    memory_dir: Path
    logs: Path
    notes: Path
    simulated_host: Path

    @classmethod
    def from_root(cls, project_root: Path | None = None) -> LabPaths:
        root = (project_root or Path(__file__).resolve().parents[1]).resolve()
        sandbox = root / "sandbox"
        return cls(
            project_root=root,
            sandbox=sandbox,
            knowledge=sandbox / "knowledge",
            tickets=sandbox / "tickets",
            secrets=sandbox / "secrets",
            outbox=sandbox / "outbox",
            memory_dir=sandbox / "memory",
            logs=sandbox / "logs",
            notes=sandbox / "notes",
            simulated_host=sandbox / "simulated_host",
        )

    def ensure_runtime_dirs(self) -> None:
        for path in (self.outbox, self.memory_dir, self.logs):
            path.mkdir(parents=True, exist_ok=True)
