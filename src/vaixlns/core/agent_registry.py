"""Deterministic canonical Agent Registry for VAIXLNS."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable

from vaixlns.core.agent import AgentContract, AgentAdmission, admit_agent


@dataclass
class RegisteredAgent:
    contract: AgentContract
    admission: AgentAdmission
    aliases: tuple[str, ...] = ()


@dataclass
class AgentRegistry:
    _agents: dict[str, RegisteredAgent] = field(default_factory=dict)

    def register(self, contract: AgentContract, readiness_scores: dict[str, float],
                 *, verification_passes: int = 0, verification_trials: int = 0,
                 aliases: Iterable[str] = ()) -> AgentAdmission:
        admission = admit_agent(
            contract, readiness_scores,
            verification_passes=verification_passes,
            verification_trials=verification_trials,
        )
        if not admission.admitted:
            return admission
        self._agents[contract.agent_id] = RegisteredAgent(
            contract=contract, admission=admission, aliases=tuple(aliases)
        )
        return admission

    def get(self, agent_id: str) -> RegisteredAgent | None:
        return self._agents.get(agent_id)

    def find_capability(self, capability: str) -> list[RegisteredAgent]:
        return sorted(
            (agent for agent in self._agents.values()
             if capability in agent.contract.capabilities),
            key=lambda item: (-item.admission.readiness.score, item.contract.agent_id),
        )

    def admitted_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._agents))
