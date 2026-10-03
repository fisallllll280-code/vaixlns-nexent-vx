"""Example usage of the VAIXLNS architecture."""

from vaixlns.core.capability import Capability, ResourceContract
from vaixlns.core.proof import ProofPackage
from vaixlns.vx.runtime import VXRuntime


def main() -> None:
    cap = Capability(
        identity="CAP-001",
        name="semantic_repair",
        intent="repair broken dependency graph",
        allowed_actions=["analyze", "suggest_patch", "replay"],
        forbidden_actions=["mutate_canon_without_governance"],
        preconditions=["system_state_known"],
        inputs=["failure_graph"],
        outputs=["repair_plan"],
        authority_required="governance",
        resource_contract=ResourceContract(
            max_cpu_ms=250,
            max_memory_mb=256,
            network_allowed=False,
            determinism_required=True,
        ),
        invariants=["no_unsafe_execution", "replayable"],
        evidence_requirements=["dependency_proof", "negative_tests"],
    )

    proof = ProofPackage(
        capability_id=cap.identity,
        dependency_proof={"status": "pass"},
        invariant_proof={"status": "pass"},
        determinism_test={"status": "pass"},
        negative_tests=[{"status": "pass"}],
        evidence_manifest={"digest": "abc123"},
        security_analysis={"status": "pass"},
        replay_test={"status": "pass"},
        resource_test={"status": "pass"},
    )

    runtime = VXRuntime()
    result = runtime.execute(cap, proof)
    print(result)


if __name__ == "__main__":
    main()
