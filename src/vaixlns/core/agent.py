"""Canonical agent contracts and mathematical admission control."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Mapping, Sequence
from vaixlns.core.engineering import ReadinessResult, calculate_readiness

@dataclass(frozen=True)
class AgentContract:
    agent_id: str
    version: str
    mission: str
    domain: str
    capabilities: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    authority: str = "MODEL"
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    policies: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    proof_requirements: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    deterministic: bool = True
    resource_limits: Mapping[str, float] = field(default_factory=dict)

    def validate(self) -> tuple[str, ...]:
        failures: list[str] = []
        if not self.agent_id or not self.version or not self.mission: failures.append("identity")
        if not self.domain: failures.append("domain")
        if not self.capabilities: failures.append("capabilities")
        if not self.inputs or not self.outputs: failures.append("io_contract")
        if not self.policies: failures.append("policies")
        if not self.evidence_requirements: failures.append("evidence_requirements")
        if not self.proof_requirements: failures.append("proof_requirements")
        if not self.deterministic: failures.append("determinism")
        return tuple(failures)

@dataclass(frozen=True)
class AgentAdmission:
    contract: AgentContract
    readiness: ReadinessResult
    admitted: bool
    reasons: tuple[str, ...]

def admit_agent(contract: AgentContract, readiness_scores: Mapping[str, float], *,
                verification_passes: int = 0, verification_trials: int = 0) -> AgentAdmission:
    contract_failures = contract.validate()
    readiness = calculate_readiness(readiness_scores,
                                     verification_passes=verification_passes,
                                     verification_trials=verification_trials)
    reasons = tuple(contract_failures) + readiness.failed_gates
    return AgentAdmission(contract, readiness, not reasons and readiness.production_ready, reasons)

def rank_agents(candidates: Sequence[tuple[AgentContract, float, float, float, float, float, float, float]]) -> list[tuple[str, float]]:
    from vaixlns.core.engineering import CapabilityCandidate
    scored = []
    for contract, similarity, evidence, readiness, reliability, risk, cost, latency in candidates:
        c = CapabilityCandidate(contract.agent_id, similarity, evidence, readiness,
                                reliability, risk, cost, latency)
        scored.append((contract.agent_id, c.utility()))
    return sorted(scored, key=lambda item: item[1], reverse=True)
