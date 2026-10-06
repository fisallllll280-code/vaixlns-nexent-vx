from vaixlns.core.engineering import blast_radius, calculate_readiness, cosine_similarity, expected_risk, weighted_geometric_mean, wilson_lower_bound
from vaixlns.core.agent import AgentContract, admit_agent, rank_agents

def _scores(value=1.0):
    return {k: value for k in ("identity","contract","capability","security","authority","evidence","verification","recovery","replay","observability","regression","determinism")}

def test_geometric_mean_penalizes_weak_dimension():
    assert weighted_geometric_mean({"a":1.0,"b":0.25},{"a":0.5,"b":0.5}) == 0.5

def test_readiness_requires_hard_safety_gates():
    scores = _scores(); scores["security"] = 0.79
    result = calculate_readiness(scores)
    assert not result.production_ready
    assert "security" in result.failed_gates

def test_wilson_bound_is_conservative():
    assert wilson_lower_bound(10,10) < 1.0
    assert wilson_lower_bound(0,10) == 0.0

def test_risk_and_blast_radius_are_bounded():
    assert expected_risk([0.5,0.2],[0.4,0.5]) == 0.3
    assert 0.0 <= blast_radius([0.2,0.3]) <= 1.0

def test_capability_similarity():
    assert abs(cosine_similarity([1,0],[1,0]) - 1.0) < 1e-12
    assert cosine_similarity([1,0],[0,1]) == 0.0

def test_agent_admission():
    contract = AgentContract("AGENT-RESEARCH-001","1.0.0","research and synthesize evidence","research",
        ("search","synthesis"), inputs=("objective",), outputs=("evidence_bundle",),
        policies=("deny-by-default",), evidence_requirements=("source_trace",),
        proof_requirements=("verification",))
    admission = admit_agent(contract, _scores(), verification_passes=20, verification_trials=20)
    assert admission.admitted

def test_agent_contract_blocks_incomplete_agent():
    contract = AgentContract("AGENT-INCOMPLETE","1.0.0","","research")
    admission = admit_agent(contract, _scores())
    assert not admission.admitted
    assert "identity" in admission.reasons

def test_agent_routing_is_deterministic():
    c1 = AgentContract("A","1","x","research",("search",),("web",),inputs=("q",),outputs=("e",),policies=("p",),evidence_requirements=("e",),proof_requirements=("p",))
    c2 = AgentContract("B","1","x","research",("search",),("web",),inputs=("q",),outputs=("e",),policies=("p",),evidence_requirements=("e",),proof_requirements=("p",))
    ranked = rank_agents([(c1,.9,.9,.9,.9,.1,.1,.1),(c2,.8,.9,.9,.9,.1,.1,.1)])
    assert ranked[0][0] == "A"
