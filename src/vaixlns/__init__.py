from vaixlns.core.authority import AuthorityHierarchy, AuthorityLevel
from vaixlns.core.epistemic_firewall import EpistemicFirewall, EpistemicKind
from vaixlns.core.proof_classifier import ProofClassifier, ClaimType
from vaixlns.core.assumptions import Assumption, AssumptionRegistry


def test_authority_hierarchy_blocks_low_level_commit():
    gate = AuthorityHierarchy()
    decision = gate.check("commit", AuthorityLevel.VERIFIER)
    assert decision.allowed is False
    assert decision.required_level == AuthorityLevel.COMMIT


def test_epistemic_firewall_blocks_prediction_to_truth_without_evidence():
    firewall = EpistemicFirewall()
    decision = firewall.allow_transition(EpistemicKind.PREDICTED, EpistemicKind.PROVEN, evidence_present=False, authority="VERIFIER")
    assert decision.allowed is False
    assert "missing evidence" in decision.reason


def test_proof_classifier_identifies_math_claim():
    classifier = ProofClassifier()
    plan = classifier.build_plan("for all values, invariant holds")
    assert plan.claim_type == ClaimType.MATHEMATICAL
    assert plan.required_methods[0].value == "FORMAL"


def test_assumption_registry_supports_mutation():
    registry = AssumptionRegistry()
    registry.register(Assumption(name="network_delay_bounded", claim="network delay bounded", confidence=0.9, status="VERIFIED"))
    mutation = registry.mutate("network_delay_bounded", "network_delay_bounded == false", 0.3, "failure in degraded network")
    assert mutation.new_confidence == 0.3
    assert registry.get("network_delay_bounded").confidence == 0.3
