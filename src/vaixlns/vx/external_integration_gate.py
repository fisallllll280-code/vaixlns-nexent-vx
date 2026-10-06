"""VX runtime-side external integration boundary."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class IntegrationKind(str, Enum):
    MODEL = "MODEL"
    API = "API"
    SERVER = "SERVER"
    TOOL = "TOOL"
    CONNECTOR = "CONNECTOR"
    REPOSITORY = "REPOSITORY"
    DATA_SOURCE = "DATA_SOURCE"


@dataclass(frozen=True)
class RuntimeIntegration:
    integration_id: str
    kind: IntegrationKind
    endpoint: str
    capability: str
    contract_version: str
    dependency_fingerprint: str
    environment_fingerprint: str
    proof_integration_identity: str
    proof_dependency_fingerprint: str
    proof_environment_fingerprint: str
    proof_expires_epoch: int
    now_epoch: int
    explicit_authority: bool


class ExternalIntegrationRuntimeGate:
    def authorize(self, integration: RuntimeIntegration) -> bool:
        if not integration.explicit_authority:
            return False
        if integration.integration_id == "":
            return False
        if integration.proof_integration_identity != integration.integration_id:
            return False
        if integration.dependency_fingerprint != integration.proof_dependency_fingerprint:
            return False
        if integration.environment_fingerprint != integration.proof_environment_fingerprint:
            return False
        if integration.now_epoch >= integration.proof_expires_epoch:
            return False
        if not integration.contract_version:
            return False
        return True
