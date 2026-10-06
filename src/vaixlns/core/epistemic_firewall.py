"""Epistemic firewall for truth-state transitions."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

class EpistemicKind(str, Enum):
    UNKNOWN="UNKNOWN"
    OBSERVED="OBSERVED"
    PREDICTED="PREDICTED"
    DERIVED="DERIVED"
    VERIFIED="VERIFIED"
    PROVEN="PROVEN"

@dataclass(frozen=True)
class FirewallDecision:
    allowed: bool
    reason: str

class EpistemicFirewall:
    """Prevents epistemic promotion without required evidence."""
    def allow_transition(self, source:EpistemicKind, target:EpistemicKind, *,
                          evidence_present:bool, authority:str)->FirewallDecision:
        if source == EpistemicKind.PREDICTED and target == EpistemicKind.PROVEN:
            if not evidence_present:
                return FirewallDecision(False,"missing evidence")
            if authority not in {"VERIFIER","GOVERNANCE"}:
                return FirewallDecision(False,"insufficient authority")
        if target == EpistemicKind.PROVEN and not evidence_present:
            return FirewallDecision(False,"missing evidence")
        return FirewallDecision(True,"transition allowed")

__all__=["EpistemicKind","FirewallDecision","EpistemicFirewall"]
