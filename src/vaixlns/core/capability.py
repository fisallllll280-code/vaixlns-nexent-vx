"""Core capability and epistemic models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ResourceContract:
    max_cpu_ms: int = 100
    max_memory_mb: int = 128
    network_allowed: bool = False
    determinism_required: bool = True
    latency_ms: Optional[int] = None
    external_state_allowed: bool = False


@dataclass
class Capability:
    identity: str
    name: str
    intent: str
    allowed_actions: List[str] = field(default_factory=list)
    forbidden_actions: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    authority_required: str = "system"
    resource_contract: Optional[ResourceContract] = None
    invariants: List[str] = field(default_factory=list)
    failure_modes: List[str] = field(default_factory=list)
    evidence_requirements: List[str] = field(default_factory=list)
    evolution_contract: Dict[str, Any] = field(default_factory=dict)

    def is_closed(self) -> bool:
        required = [
            self.identity,
            self.name,
            self.intent,
            self.allowed_actions,
            self.authority_required,
        ]
        return all(item not in (None, "", [], {}) for item in required)


@dataclass
class CapabilityGenome:
    identity: str
    semantic_type: str
    dependencies: List[str] = field(default_factory=list)
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    authority: str = "system"
    policies: List[str] = field(default_factory=list)
    invariants: List[str] = field(default_factory=list)
    execution_model: str = "deterministic"
    evidence_model: str = "ledgered"
    failure_model: str = "closed"
    repair_model: str = "localized"
    verification_model: str = "proof_gate"
    resource_model: Optional[ResourceContract] = None
    lineage: List[str] = field(default_factory=list)
