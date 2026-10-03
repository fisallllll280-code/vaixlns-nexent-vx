"""Sovereign gate for validating capabilities before execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from vaixlns.core.capability import Capability
from vaixlns.core.proof import ProofPackage


@dataclass
class ExecutionDecision:
    authorized: bool
    status: str
    capability_id: Optional[str] = None
    reason: Optional[str] = None


class SovereignExecutionGate:
    """The boundary between speculative capability generation and authorized reality."""

    def authorize(self, capability: Capability, proof: ProofPackage) -> ExecutionDecision:
        if capability is None:
            return ExecutionDecision(False, "rejected", reason="missing_capability")

        if not capability.is_closed():
            return ExecutionDecision(False, "rejected", capability.identity, "capability_not_closed")

        if capability.resource_contract is not None:
            if capability.resource_contract.determinism_required and not proof.determinism_test.get("status") == "pass":
                return ExecutionDecision(False, "rejected", capability.identity, "determinism_failed")

        if not proof.is_valid():
            return ExecutionDecision(False, "rejected", capability.identity, "proof_failed")

        if any(action in capability.forbidden_actions for action in capability.forbidden_actions):
            return ExecutionDecision(False, "rejected", capability.identity, "forbidden_action_present")

        return ExecutionDecision(True, "authorized", capability.identity, "proof_and_policy_valid")
