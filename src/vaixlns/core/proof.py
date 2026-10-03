"""Proof artifacts for capability validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ProofPackage:
    capability_id: str
    dependency_proof: Dict[str, Any]
    invariant_proof: Dict[str, Any]
    determinism_test: Dict[str, Any]
    negative_tests: List[Dict[str, Any]] = field(default_factory=list)
    evidence_manifest: Dict[str, Any] = field(default_factory=dict)
    security_analysis: Dict[str, Any] = field(default_factory=dict)
    replay_test: Dict[str, Any] = field(default_factory=dict)
    resource_test: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        checks = [
            self.dependency_proof.get("status") == "pass",
            self.invariant_proof.get("status") == "pass",
            self.determinism_test.get("status") == "pass",
            all(item.get("status") == "pass" for item in self.negative_tests),
            bool(self.evidence_manifest),
        ]
        return all(checks)
