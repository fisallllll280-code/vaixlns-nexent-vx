from vaixlns.vx.external_integration_gate import ExternalIntegrationRuntimeGate, IntegrationKind, RuntimeIntegration


def base(**changes):
    values = dict(
        integration_id="model:1",
        kind=IntegrationKind.MODEL,
        endpoint="provider://model",
        capability="inference",
        allowed_capabilities=("inference",),
        contract_version="v1",
        dependency_fingerprint="dep:v1",
        environment_fingerprint="env:v1",
        proof_integration_identity="model:1",
        proof_dependency_fingerprint="dep:v1",
        proof_environment_fingerprint="env:v1",
        proof_expires_epoch=200,
        now_epoch=120,
        explicit_authority=True,
    )
    values.update(changes)
    return RuntimeIntegration(**values)


def test_fresh_proven_integration_can_execute():
    assert ExternalIntegrationRuntimeGate().authorize(base()) is True


def test_stale_proof_blocks():
    assert ExternalIntegrationRuntimeGate().authorize(base(now_epoch=200)) is False


def test_dependency_drift_blocks():
    assert ExternalIntegrationRuntimeGate().authorize(base(dependency_fingerprint="dep:v2")) is False


def test_identity_drift_blocks():
    assert ExternalIntegrationRuntimeGate().authorize(base(proof_integration_identity="model:changed")) is False


def test_capability_escalation_blocks():
    assert ExternalIntegrationRuntimeGate().authorize(base(capability="filesystem_write")) is False
