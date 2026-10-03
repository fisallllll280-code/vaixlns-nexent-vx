"""VX runtime interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from vaixlns.core.capability import Capability
from vaixlns.core.epistemic import EpistemicStateMachine, EpistemicState
from vaixlns.core.proof import ProofPackage
from vaixlns.vx.execution_gate import SovereignExecutionGate


@dataclass
class ExecutionRecord:
    capability_id: str
    status: str
    state: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class VXRuntime:
    def __init__(self):
        self.gate = SovereignExecutionGate()
        self.epistemic = EpistemicStateMachine()
        self.records: List[ExecutionRecord] = []

    def execute(self, capability: Capability, proof: ProofPackage) -> ExecutionRecord:
        decision = self.gate.authorize(capability, proof)
        if not decision.authorized:
            self.epistemic.transition(
                EpistemicState.VERIFIED,
                evidence={"reason": decision.reason},
                verifier="VX",
                authority=capability.authority_required,
                timestamp="now",
            )
            record = ExecutionRecord(capability.identity, decision.status, self.epistemic.state.value, {"reason": decision.reason})
            self.records.append(record)
            return record

        self.epistemic.transition(
            EpistemicState.AUTHORIZED,
            evidence={"capability": capability.identity},
            verifier="VX",
            authority=capability.authority_required,
            timestamp="now",
        )
        self.epistemic.transition(
            EpistemicState.EXECUTED,
            evidence={"proof_digest": proof.evidence_manifest.get("digest")},
            verifier="VX",
            authority=capability.authority_required,
            timestamp="now",
        )

        record = ExecutionRecord(capability.identity, "executed", self.epistemic.state.value, {"digest": proof.evidence_manifest.get("digest")})
        self.records.append(record)
        return record
