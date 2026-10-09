# Agent Action-Control Assurance v1

**Status:** IMPLEMENTED ON FEATURE BRANCH; VERIFICATION PENDING CI  
**Layer:** VX execution / verification boundary  
**Canonical authority:** VAIXLNS, Golden Source project.genome::v1.0.0  
**Implementation:** src/vaixlns/vx/agent_assurance.py  
**Contract schema:** schemas/agent-action-control-assurance-v1.schema.json

## Commercially bounded service

This module is the first reference implementation for the proposed **Agent Action-Control Snapshot**: a scoped assessment of whether an agent action is bound to an authorized task, a current resource version, a verified plan, independent target-side evidence and a valid closure decision.

The service must not be marketed as a certification or a guarantee that a system has no vulnerabilities. Each engagement names the target, permitted test actions, allowlisted diff paths, evidence channels, test limits and reproduction commands.

## State lifecycle

    SPECIFIED → AUTHORIZED → VERIFIED_PLAN → EXECUTING → EFFECT_VERIFIED → CLOSED_VERIFIED

Exceptional paths are explicit:

- PARTIAL_EFFECT → COMPENSATING → CLOSED_FAILED
- REJECTED, EXPIRED, CONFLICT, ABORTED or RECOVERY_REQUIRED must not be re-labelled as success.
- RECOVERY_REQUIRED is used when the effect cannot be independently established or assurance evidence conflicts.
- CLOSED_VERIFIED is reachable only after EFFECT_VERIFIED and retained evidence references.
- A task that produced a partial effect cannot be marked successful. Closure as failed requires independently attested evidence that there are no residual effects.

## Authorization and resource-version invariants

1. The permit is signed and bound to contract_id, operation_id, principal_id, resource_id, exact resource version, allowed actions and expiry.
2. Expired, revoked, forged, untrusted, out-of-scope or version-stale permits are rejected.
3. The permit and resource version are checked again immediately before an execution ticket is issued, to narrow the time-of-check/time-of-use window.
4. The task contract's idempotency key is stable across retries; a digest of the full contract catches reuse of the same contract/operation IDs with altered scope.
5. The returned ExecutionTicket.idempotency_key must be enforced atomically by the downstream actuator. The in-memory registry is not durable and cannot alone prevent duplicate external effects across process restarts.

## Evidence oracle

Verified closure requires three signed receipts from distinct trusted sources and key IDs:

- **Target audit:** complete log marker, sequence number, before/after resource versions, diff paths, effect state and state hash.
- **Independent readback:** independently observed state hash and resource version that match the target audit.
- **Tripwire monitor:** complete coverage, clean result and no unexpected events.

Evidence signed with the agent connector's identity is rejected. Fake readback payloads, a tampered signature, duplicate channels, incomplete target logs, out-of-allowlist diffs or a triggered tripwire cannot produce CLOSED_VERIFIED.

These receipts are still attestations from configured trust roots, not mathematical proof of the absence of every possible side effect. Production deployment requires separately isolated target-side audit, read-only readback and tripwire services with protected keys, sequence/retention guarantees and explicit trust configuration.

## Running the reference checks

From the repository root, using Python 3.10 or later and the standard library:

    python -m py_compile src/vaixlns/vx/agent_assurance.py tests/test_agent_assurance.py scripts/run_agent_assurance_mutations.py
    PYTHONPATH=src python -m unittest discover -s tests -p "test_agent_assurance.py" -v
    PYTHONPATH=src python scripts/run_agent_assurance_mutations.py
    python -m json.tool schemas/agent-action-control-assurance-v1.schema.json > /dev/null

The randomized test explores 5,000 deterministic random transition sequences. The curated mutation runner deliberately disables the permit-expiry, action-scope and resource-version guards and expects each targeted safety test to fail. It is a targeted mutation canary, not a general mutation-testing engine or a formal model checker.

## Production blockers

This code is a **reference state machine**, not yet a production security boundary:

- IdempotencyRegistry is in-memory; replace it with an atomic durable store.
- Python object state is not a process isolation boundary.
- HMAC verifier and signer objects are fixtures/adapters; production keys must be held by separate authorization/evidence services or a managed key system and never exposed to the agent.
- No real repository, GitHub, cloud, filesystem or other target actuator is connected here.
- No target-side audit/tripwire adapter, TLA+ model, concurrency test, or external readback integration is included.
- A green test suite validates the tested contract, not all possible production behavior.

Keep this feature behind pull-request review until the CI evidence is inspected. Do not promote this artifact to VERIFIED or production-ready before these blockers are closed.
