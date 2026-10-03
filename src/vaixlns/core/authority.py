"""Authority hierarchy for decision rights in VX.

The key rule is: ability to generate a proposal is not the same as authority to commit it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List


class AuthorityLevel(str, Enum):
    MODEL = "MODEL"
    PROPOSAL = "PROPOSAL"
    EVIDENCE = "EVIDENCE"
    VERIFIER = "VERIFIER"
    GOVERNANCE = "GOVERNANCE"
    COMMIT = "COMMIT"


@dataclass
class AuthorityDecision:
    allowed: bool
    required_level: AuthorityLevel
    actual_level: AuthorityLevel
    reason: str = ""


class AuthorityHierarchy:
    """Creates a strict authority ladder for all state transitions."""

    _min_level_for_transition = {
        "proposal": AuthorityLevel.PROPOSAL,
        "analysis": AuthorityLevel.MODEL,
        "verification": AuthorityLevel.VERIFIER,
        "governance": AuthorityLevel.GOVERNANCE,
        "commit": AuthorityLevel.COMMIT,
    }

    def check(self, action: str, actor_level: AuthorityLevel) -> AuthorityDecision:
        required = self._min_level_for_transition.get(action, AuthorityLevel.PROPOSAL)
        if actor_level.value == required.value:
            return AuthorityDecision(True, required, actor_level, f"{action} is authorized by {actor_level}")

        if self._rank(actor_level) < self._rank(required):
            return AuthorityDecision(False, required, actor_level, f"{actor_level} is too weak for {action}")

        return AuthorityDecision(True, required, actor_level, f"{action} authorized via higher authority")

    def _rank(self, level: AuthorityLevel) -> int:
        order = [
            AuthorityLevel.MODEL,
            AuthorityLevel.PROPOSAL,
            AuthorityLevel.EVIDENCE,
            AuthorityLevel.VERIFIER,
            AuthorityLevel.GOVERNANCE,
            AuthorityLevel.COMMIT,
        ]
        return order.index(level)


__all__ = ["AuthorityLevel", "AuthorityDecision", "AuthorityHierarchy"]
