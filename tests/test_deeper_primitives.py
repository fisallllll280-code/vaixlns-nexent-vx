"""Assumption registry and mutation engine.

A system is only as robust as the assumptions it silently depends on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Assumption:
    name: str
    claim: str
    confidence: float = 0.0
    status: str = "UNVERIFIED"


@dataclass
class AssumptionMutation:
    assumption_name: str
    mutation: str
    new_confidence: float
    consequence: str


class AssumptionRegistry:
    """Stores and tracks assumptions behind a state delta or decision."""

    def __init__(self):
        self.assumptions: Dict[str, Assumption] = {}

    def register(self, assumption: Assumption) -> None:
        self.assumptions[assumption.name] = assumption

    def get(self, name: str) -> Optional[Assumption]:
        return self.assumptions.get(name)

    def mutate(self, name: str, mutation: str, new_confidence: float, consequence: str) -> AssumptionMutation:
        current = self.assumptions.get(name)
        if current is None:
            raise KeyError(f"assumption '{name}' not found")

        mutation_record = AssumptionMutation(
            assumption_name=name,
            mutation=mutation,
            new_confidence=new_confidence,
            consequence=consequence,
        )

        current.confidence = new_confidence
        current.status = "MUTATED"
        return mutation_record


class AssumptionMutationEngine:
    """Generates robustness boundaries by changing assumptions and stress-testing them."""

    def generate_mutations(self, assumption: Assumption) -> List[str]:
        return [
            f"{assumption.name} == false",
            f"{assumption.name} == partially_true",
            f"{assumption.name} == boundary_case",
            f"{assumption.name} == hostile_environment",
        ]


__all__ = ["Assumption", "AssumptionMutation", "AssumptionRegistry", "AssumptionMutationEngine"]
