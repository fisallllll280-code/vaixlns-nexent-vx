"""Mathematical engineering primitives for VAIXLNS agent readiness.

All scores are normalized to [0, 1]. The module is dependency-free and
deliberately deterministic so readiness decisions can be replayed.
"""
from __future__ import annotations
from dataclasses import dataclass
from math import exp, log, sqrt
from typing import Mapping, Sequence

READINESS_WEIGHTS: Mapping[str, float] = {
    "identity": 0.05, "contract": 0.10, "capability": 0.10, "security": 0.10,
    "authority": 0.10, "evidence": 0.10, "verification": 0.12,
    "recovery": 0.08, "replay": 0.07, "observability": 0.05,
    "regression": 0.08, "determinism": 0.05,
}

def _clip(value: float) -> float:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"score must be in [0,1], got {value!r}")
    return value

def weighted_geometric_mean(scores: Mapping[str, float], weights: Mapping[str, float]) -> float:
    if not scores:
        raise ValueError("scores cannot be empty")
    total = sum(weights.get(k, 0.0) for k in scores)
    if total <= 0:
        raise ValueError("weights must have positive mass")
    return exp(sum((weights.get(k, 0.0) / total) * log(max(_clip(v), 1e-12))
                   for k, v in scores.items()))

def wilson_lower_bound(successes: int, trials: int, z: float = 1.96) -> float:
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("invalid successes/trials")
    if trials == 0:
        return 0.0
    p = successes / trials
    denom = 1.0 + z * z / trials
    centre = p + z * z / (2.0 * trials)
    margin = z * sqrt((p * (1.0 - p) + z * z / (4.0 * trials)) / trials)
    return max(0.0, min(1.0, (centre - margin) / denom))

def expected_risk(probabilities: Sequence[float], impacts: Sequence[float]) -> float:
    if len(probabilities) != len(impacts):
        raise ValueError("probabilities and impacts must have equal length")
    return min(1.0, sum(_clip(p) * _clip(i) for p, i in zip(probabilities, impacts)))

def blast_radius(edge_weights: Sequence[float]) -> float:
    result = 1.0
    for weight in edge_weights:
        result *= 1.0 - _clip(weight)
    return 1.0 - result

def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b) or not a:
        raise ValueError("vectors must have equal non-zero length")
    dot = sum(x * y for x, y in zip(a, b))
    na = sqrt(sum(x * x for x in a))
    nb = sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return max(0.0, min(1.0, dot / (na * nb)))

@dataclass(frozen=True)
class ReadinessResult:
    score: float
    production_ready: bool
    failed_gates: tuple[str, ...]
    confidence: float

def calculate_readiness(scores: Mapping[str, float], *, verification_passes: int = 0,
                        verification_trials: int = 0, minimum_gate: float = 0.80) -> ReadinessResult:
    missing = tuple(k for k in READINESS_WEIGHTS if k not in scores)
    if missing:
        raise ValueError(f"missing readiness dimensions: {missing}")
    normalized = {k: _clip(scores[k]) for k in READINESS_WEIGHTS}
    score = weighted_geometric_mean(normalized, READINESS_WEIGHTS)
    confidence = (wilson_lower_bound(verification_passes, verification_trials)
                  if verification_trials else normalized["verification"])
    hard = {"authority": normalized["authority"], "evidence": normalized["evidence"],
            "verification": confidence, "security": normalized["security"]}
    failed = tuple(k for k, value in hard.items() if value < minimum_gate)
    return ReadinessResult(score, score >= minimum_gate and not failed, failed, confidence)

@dataclass(frozen=True)
class CapabilityCandidate:
    identity: str
    similarity: float
    evidence: float
    readiness: float
    reliability: float
    risk: float
    cost: float
    latency: float
    def utility(self, *, alpha: float = 0.30, beta: float = 0.15, gamma: float = 0.20,
                delta: float = 0.15, risk_penalty: float = 0.10,
                cost_penalty: float = 0.05, latency_penalty: float = 0.05) -> float:
        return (alpha * self.similarity + beta * self.evidence + gamma * self.readiness
                + delta * self.reliability - risk_penalty * self.risk
                - cost_penalty * self.cost - latency_penalty * self.latency)
