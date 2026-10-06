"""Basic tests for capability closure and proof validation."""

from vaixlns.core.capability import Capability, ResourceContract
from vaixlns.core.proof import ProofPackage
from vaixlns.vx.execution_gate import SovereignExecutionGate


def test_capability_gate_authorizes_valid_capability():
    capability = Capability(
        identity="CAP-101",
        name="safe_patch",
        intent="repair known failure",
        allowed_actions=["analyze", "repair"],
        forbidden_actions=[],
        authority_required="governance",
        resource_contract=ResourceContract(
            max_cpu_ms=100,
            max_memory_mb=128,
            network_allowed=False,
            determinism_required=True,
        ),
    )

    proof = ProofPackage(
        capability_id=capability.identity,
        dependency_proof={"status": "pass"},
        invariant_proof={"status": "pass"},
        determinism_test={"status": "pass"},
        negative_tests=[{"status": "pass"}],
        evidence_manifest={"digest": "demo"},
    )

    decision = SovereignExecutionGate().authorize(capability, proof)
    assert decision.authorized is True
    assert decision.status == "authorized"


def test_capability_gate_rejects_invalid_proof():
    capability = Capability(
        identity="CAP-102",
        name="unsafe_patch",
        intent="perform uncertain mutation",
        allowed_actions=["mutate"],
        forbidden_actions=["mutate_canon_without_governance"],
        authority_required="governance",
    )

    proof = ProofPackage(
        capability_id=capability.identity,
        dependency_proof={"status": "fail"},
        invariant_proof={"status": "pass"},
        determinism_test={"status": "pass"},
        negative_tests=[{"status": "pass"}],
        evidence_manifest={"digest": "demo"},
    )

    decision = SovereignExecutionGate().authorize(capability, proof)
    assert decision.authorized is False
    assert decision.status == "rejected"
