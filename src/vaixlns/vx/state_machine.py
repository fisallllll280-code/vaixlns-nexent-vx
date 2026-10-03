"""VX state machine and runtime logic."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class NodeState(str, Enum):
    INITIAL = "INITIAL"
    READY = "READY"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"


@dataclass
class ExecutionEvent:
    name: str
    payload: Dict[str, Any] | None = None


class StateMachine:
    def __init__(self, name: str):
        self.name = name
        self.state = NodeState.INITIAL

    def apply(self, event: ExecutionEvent) -> NodeState:
        old = self.state
        name = event.name

        if self.state == NodeState.INITIAL and name == "BOOT":
            self.state = NodeState.READY
        elif self.state == NodeState.READY and name == "START":
            self.state = NodeState.ACTIVE
        elif name == "FAIL":
            self.state = NodeState.DEGRADED

        print(f"[{self.name}] {old.value} -> {self.state.value} | {name}")
        return self.state
