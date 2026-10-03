"""State Delta as the fundamental unit of change.

VX does not orchestrate agents. It manages state delta transitions across:
- Probabilistic Space (where AI generates candidates)
- Experimental Space (where simulations test results)
- Proof Space (where verifiers validate claims)
- Governance Space (where authority decides)
- Execution Space (where committed deltas become reality)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from hashlib import sha256


class DeltaStatus(str, Enum):
    PROPOSED = "PROPOSED"
    SIMULATED = "SIMULATED"
    EVIDENCE_GATHERED = "EVIDENCE_GATHERED"
    PARTIALLY_PROVEN = "PARTIALLY_PROVEN"
    FULLY_PROVEN = "FULLY_PROVEN"
    AUTHORIZED = "AUTHORIZED"
    COMMITTED = "COMMITTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"


class CognitiveLevelOfAnalysis(str, Enum):
    UNKNOWN = "UNKNOWN"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    MODELED = "MODELED"
    SIMULATED = "SIMULATED"
    PREDICTED = "PREDICTED"
    PROVEN = "PROVEN"


@dataclass
class Mutation:
    """A single state change within a delta."""
    path: str
    old_value: Any
    new_value: Any
    reason: str
    timestamp: str


@dataclass
class Assumption:
    """An assumption required for this delta to be valid."""
    name: str
    claim: str
    confidence: float  # 0.0 to 1.0
    verification_status: str  # UNVERIFIED, VERIFIED, DISPROVEN


@dataclass
class ProofObligation:
    """Something that must be proven for this delta to be committable."""
    claim: str
    required_evidence_class: str  # "FORMAL", "SIMULATION", "EMPIRICAL", "STATISTICAL"
    status: str  # OUTSTANDING, PARTIALLY_DISCHARGED, FULLY_DISCHARGED
    verifier: Optional[str] = None


@dataclass
class Reversibility:
    """Can this delta be undone, and at what cost?"""
    reversible: bool
    cost: Optional[float] = None
    constraints: List[str] = field(default_factory=list)


@dataclass
class StateDelta:
    """The fundamental unit of change in VX.
    
    Not an agent action. A proposed state transition with:
    - Origin (who/what proposed this)
    - Evidence (what justifies it)
    - Proof obligations (what must be validated)
    - Assumptions (what must remain true)
    - Reversibility (can we undo it)
    """
    
    id: str
    base_state_cid: str  # Content ID of the state we're starting from
    proposed_state_cid: str  # Content ID of the state we're proposing
    intent: str  # What is the purpose of this delta?
    
    # The actual changes
    mutations: List[Mutation] = field(default_factory=list)
    
    # What must be true for this to work
    assumptions: List[Assumption] = field(default_factory=list)
    
    # What gets affected
    invariants_affected: List[str] = field(default_factory=list)
    
    # What justifies this
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    
    # What still needs to be proven
    proof_obligations: List[ProofObligation] = field(default_factory=list)
    
    # Can we undo this
    reversibility: Optional[Reversibility] = None
    
    # Status in the pipeline
    status: DeltaStatus = DeltaStatus.PROPOSED
    
    # Who/what proposed this
    proposer: str = "unknown"
    proposer_type: str = "unknown"  # "AGENT", "SIMULATION", "VERIFIER", "GOVERNANCE"
    
    # Cognitive level at which this was generated
    cognitive_level: CognitiveLevelOfAnalysis = CognitiveLevelOfAnalysis.UNKNOWN
    
    # Simulation results (if tested)
    simulation_results: List[Dict[str, Any]] = field(default_factory=list)
    
    # Counterfactuals (what if we don't do this)
    counterfactuals: List[Dict[str, Any]] = field(default_factory=list)
    
    # Alternative deltas (other proposals for same intent)
    alternatives: List[str] = field(default_factory=list)
    
    # Failure scenarios discovered during analysis
    failure_scenarios: List[Dict[str, Any]] = field(default_factory=list)

    def compute_digest(self) -> str:
        """Compute deterministic hash of this delta."""
        content = f"{self.base_state_cid}:{self.proposed_state_cid}:{self.intent}"
        return sha256(content.encode()).hexdigest()[:16]


@dataclass
class CognitiveState:
    """What the system thinks about the actual state.
    
    Separates:
    - S_actual: What actually is
    - S_observed: What we measured
    - S_inferred: What we reasoned
    - S_simulated: What simulation predicted
    - S_proposed: What we want it to be
    """
    
    timestamp: str
    
    # Reality
    actual_state_cid: str
    
    # Observation level
    observed_state_cid: Optional[str] = None
    observation_confidence: float = 0.0
    observation_gaps: List[str] = field(default_factory=list)
    
    # Inference level
    inferred_state_cid: Optional[str] = None
    inference_confidence: float = 0.0
    inferred_from_agents: List[str] = field(default_factory=list)
    
    # Simulation level
    simulated_state_cid: Optional[str] = None
    simulation_conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Prediction level
    predicted_state_cid: Optional[str] = None
    prediction_horizon: Optional[float] = None  # time units ahead
    
    # Proposal level
    proposed_state_cid: Optional[str] = None
    pending_deltas: List[str] = field(default_factory=list)  # IDs of StateDelta
    
    # Disagreement
    disagreement_detected: bool = False
    disagreement_graph: Dict[str, Any] = field(default_factory=dict)
    
    # Overall uncertainty
    uncertainty_level: float = 1.0  # 0.0 = certain, 1.0 = no information
    uncertainty_budget_remaining: float = 1.0


@dataclass
class RealityBoundary:
    """The strict separation between spaces.
    
    VX maintains hard boundaries between:
    - AI Space (probabilistic)
    - Simulation Space (experimental)
    - Proof Space (verified)
    - Execution Space (committed)
    - External Reality (observable)
    """
    
    ai_space: Dict[str, Any] = field(default_factory=dict)
    """Candidates generated by AI/NEXENT"""
    
    simulation_space: Dict[str, Any] = field(default_factory=dict)
    """Results from simulations and counterfactuals"""
    
    proof_space: Dict[str, Any] = field(default_factory=dict)
    """Claims that have passed verification"""
    
    verified_space: Dict[str, Any] = field(default_factory=dict)
    """State with full proof coverage"""
    
    execution_space: Dict[str, Any] = field(default_factory=dict)
    """Committed deltas being executed"""
    
    external_reality: Dict[str, Any] = field(default_factory=dict)
    """Observed actual reality"""
    
    # Transition rules (not all adjacent spaces can communicate directly)
    allowed_transitions: Dict[str, List[str]] = field(default_factory=lambda: {
        "ai_space": ["simulation_space"],
        "simulation_space": ["proof_space"],
        "proof_space": ["verified_space"],
        "verified_space": ["execution_space"],
        "execution_space": ["external_reality"],
        "external_reality": ["ai_space"],  # Close the loop for learning
    })
    
    def validate_transition(self, from_space: str, to_space: str) -> bool:
        """Check if transition between spaces is allowed."""
        return to_space in self.allowed_transitions.get(from_space, [])
