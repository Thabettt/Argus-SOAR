"""Phase results: every phase returns the same shape, so PackageEvidence can build a timeline.

    { "started_at": ..., "completed_at": ..., "actions": [ {action, target, result, at, detail?} ] }
"""

from __future__ import annotations

from typing import Any

from .aws_utils import now_iso


class PhaseRecorder:
    def __init__(self, phase: str):
        self.phase = phase
        self.started_at = now_iso()
        self.actions: list[dict[str, Any]] = []
        self.extra: dict[str, Any] = {}

    def record(self, action: str, target: str, result: str = "ok", detail: Any = None) -> None:
        entry: dict[str, Any] = {"action": action, "target": target, "result": result, "at": now_iso()}
        if detail is not None:
            entry["detail"] = detail
        self.actions.append(entry)

    def result(self) -> dict[str, Any]:
        out = {
            "phase": self.phase,
            "started_at": self.started_at,
            "completed_at": now_iso(),
            "actions": self.actions,
        }
        out.update(self.extra)
        return out
