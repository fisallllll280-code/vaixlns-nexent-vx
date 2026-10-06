"""Proof Classifier and Verification Portfolio."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import List

class ClaimType(str, Enum):
    MATHEMATICAL="MATHEMATICAL"; PROGRAM_INVARIANT="PROGRAM_INVARIANT"; PERFORMANCE="PERFORMANCE"
    REAL_WORLD_BEHAVIOR="REAL_WORLD_BEHAVIOR"; FUTURE_PREDICTION="FUTURE_PREDICTION"; SECURITY="SECURITY"; UNKNOWN="UNKNOWN"

class VerificationMethod(str, Enum):
    FORMAL="FORMAL"; SIMULATION="SIMULATION"; TESTING="TESTING"; STATIC_ANALYSIS="STATIC_ANALYSIS"
    ADVERSARIAL="ADVERSARIAL"; STATISTICAL="STATISTICAL"; EMPIRICAL="EMPIRICAL"; REPLAY="REPLAY"

@dataclass
class ProofPlan:
    claim_type: ClaimType
    required_methods: List[VerificationMethod]
    reason: str

class ProofClassifier:
    def classify(self, claim: str) -> ClaimType:
        lowered=claim.lower()
        if any(t in lowered for t in ["proof","theorem","invariant","always","for all"]):
            return ClaimType.MATHEMATICAL if "theorem" in lowered or "for all" in lowered else ClaimType.PROGRAM_INVARIANT
        if any(t in lowered for t in ["latency","throughput","performance","time","cpu","memory"]): return ClaimType.PERFORMANCE
        if any(t in lowered for t in ["security","exploit","attack","vulnerability","auth","permissions"]): return ClaimType.SECURITY
        if any(t in lowered for t in ["future","predict","forecast","trend","likely"]): return ClaimType.FUTURE_PREDICTION
        if any(t in lowered for t in ["observed","real world","production","behavior","deployed"]): return ClaimType.REAL_WORLD_BEHAVIOR
        return ClaimType.UNKNOWN

    def build_plan(self, claim: str) -> ProofPlan:
        ct=self.classify(claim)
        mapping={
            ClaimType.MATHEMATICAL:[VerificationMethod.FORMAL],
            ClaimType.PROGRAM_INVARIANT:[VerificationMethod.FORMAL,VerificationMethod.TESTING],
            ClaimType.PERFORMANCE:[VerificationMethod.STATISTICAL,VerificationMethod.TESTING],
            ClaimType.REAL_WORLD_BEHAVIOR:[VerificationMethod.EMPIRICAL,VerificationMethod.REPLAY],
            ClaimType.FUTURE_PREDICTION:[VerificationMethod.SIMULATION,VerificationMethod.STATISTICAL],
            ClaimType.SECURITY:[VerificationMethod.FORMAL,VerificationMethod.ADVERSARIAL,VerificationMethod.TESTING],
            ClaimType.UNKNOWN:[VerificationMethod.SIMULATION,VerificationMethod.TESTING],
        }
        return ProofPlan(ct,mapping[ct],f"claim classified as {ct.value}")

__all__=["ClaimType","VerificationMethod","ProofPlan","ProofClassifier"]
