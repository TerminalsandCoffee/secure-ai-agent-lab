"""Structured JSONL audit of every tool authorization and execution."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.records: list[dict[str, Any]] = []
        self._fh: TextIO | None = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = path.open("a", encoding="utf-8")

    def write(self, **record: Any) -> None:
        row = {"ts": datetime.now(timezone.utc).isoformat(), **record}
        self.records.append(row)
        if self._fh is not None:
            self._fh.write(json.dumps(row, default=str) + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
