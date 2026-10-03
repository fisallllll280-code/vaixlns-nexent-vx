"""Epistemic state machine for knowledge transitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class EpistemicState(str, Enum):
    UNKNOWN = "UNKNOWN"
    OBSERVED = "OBSERVED"
    CORROBORATED = "CORROBORATED"
    DERIVED = "DERIVED"
    VERIFIED = "VERIFIED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTED = "EXECUTED"
    COMMITTED = "COMMITTED"
    ANCHORED = "ANCHORED"


@dataclass
class EpistemicTransition:
    from_state: EpistemicState
    to_state: EpistemicState
    evidence: Dict[str, Any]
    verifier: str
    authority: str
    timestamp: str
    cid: Optional[str] = None


class EpistemicStateMachine:
    """Tracks truth status across knowledge and execution lifecycle."""

    def __init__(self):
        self.state = EpistemicState.UNKNOWN
        self.transitions: List[EpistemicTransition] = []

    def transition(
        self,
        to_state: EpistemicState,
        *,
        evidence: Dict[str, Any],
        verifier: str,
        authority: str,
        timestamp: str,
        cid: Optional[str] = None,
    ) -> EpistemicTransition:
        current = self.state
        trans = EpistemicTransition(
            from_state=current,
            to_state=to_state,
            evidence=evidence,
            verifier=verifier,
            authority=authority,
            timestamp=timestamp,
            cid=cid,
        )
        self.transitions.append(trans)
        self.state = to_state
        return trans

    def snapshot(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "transition_count": len(self.transitions),
            "last_transition": self.transitions[-1].to_state.value if self.transitions else None,
        }
