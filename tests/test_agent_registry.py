from vaixlns.core.agent_registry import AgentRegistry
from vaixlns.core.agent import AgentContract

def _scores():
    return {k:1.0 for k in ("identity","contract","capability","security","authority","evidence","verification","recovery","replay","observability","regression","determinism")}

def _contract(agent_id, capability):
    return AgentContract(agent_id, "1.0.0", "execute bounded research", "research",
        capabilities=(capability,), inputs=("objective",), outputs=("evidence",),
        policies=("deny-by-default",), evidence_requirements=("trace",),
        proof_requirements=("verification",))

def test_registry_only_admits_verified_agents():
    registry = AgentRegistry()
    result = registry.register(_contract("AGENT-A","research"), _scores(), verification_passes=20, verification_trials=20)
    assert result.admitted
    assert registry.admitted_ids() == ("AGENT-A",)
    assert registry.find_capability("research")[0].contract.agent_id == "AGENT-A"

def test_registry_rejects_incomplete_contract():
    registry = AgentRegistry()
    bad = AgentContract("BAD","1.0.0","","research")
    result = registry.register(bad, _scores())
    assert not result.admitted
    assert registry.admitted_ids() == ()
