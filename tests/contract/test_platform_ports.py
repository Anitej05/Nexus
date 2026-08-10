import inspect
from typing import get_type_hints

from nexus_contracts.platform import (
    ArtifactPort,
    AuditPort,
    BranchPort,
    EmbeddingPort,
    EntityDecisionPort,
    GraphProjectionPort,
    MalwareScanPort,
    MalwareScanResult,
    ObjectStorePort,
    OntologyReadPort,
    OntologyWritePort,
    PolicyPort,
    RequestContext,
    ResourceRef,
    SecretPort,
    SignalPort,
    StructuredOutputPort,
)


def test_plan_b_port_parameter_contracts_are_stable() -> None:
    expected = {
        OntologyWritePort.apply_observations: [
            "self",
            "context",
            "observations",
            "idempotency_key",
        ],
        OntologyReadPort.snapshot: ["self", "context", "object_refs", "valid_time", "branch_id"],
        OntologyReadPort.read_objects: ["self", "context", "snapshot", "query"],
        GraphProjectionPort.read_subgraph: ["self", "context", "snapshot", "query"],
        BranchPort.put: [
            "self",
            "context",
            "branch_id",
            "resource_kind",
            "resource_key",
            "content",
            "expected_version",
            "idempotency_key",
        ],
        PolicyPort.authorize: ["self", "context", "operation", "resources", "attributes"],
        ObjectStorePort.put_bytes: [
            "self",
            "context",
            "key",
            "body",
            "content_type",
            "sha256",
            "idempotency_key",
        ],
        AuditPort.append: [
            "self",
            "context",
            "event_type",
            "subject",
            "payload",
            "idempotency_key",
        ],
        ArtifactPort.publish: [
            "self",
            "context",
            "artifact_type",
            "schema_uri",
            "payload",
            "evidence",
            "idempotency_key",
            "objective_id",
            "situation_id",
            "task_id",
            "sensitivity",
        ],
        SignalPort.publish_signal: [
            "self",
            "context",
            "signal_type",
            "severity",
            "body",
            "evidence",
            "idempotency_key",
        ],
        EntityDecisionPort.apply: [
            "self",
            "context",
            "decision",
            "expected_version",
            "idempotency_key",
        ],
    }

    for method, parameter_names in expected.items():
        assert list(inspect.signature(method).parameters) == parameter_names


def test_artifact_optional_scope_identifiers_are_keyword_only() -> None:
    signature = inspect.signature(ArtifactPort.publish)
    assert signature.parameters["objective_id"].kind is inspect.Parameter.KEYWORD_ONLY


def test_remaining_port_annotations_use_canonical_boundary_types() -> None:
    secret = get_type_hints(SecretPort.resolve)
    embedding = get_type_hints(EmbeddingPort.embed)
    malware = get_type_hints(MalwareScanPort.scan)
    structured = get_type_hints(StructuredOutputPort.generate_object)

    assert secret["context"] is RequestContext
    assert secret["secret_ref"] is ResourceRef
    assert embedding["context"] is RequestContext
    assert embedding["model_id"] is str
    assert malware["context"] is RequestContext
    assert malware["content"] is bytes
    assert malware["return"] is MalwareScanResult
    assert structured["context"] is RequestContext
    assert structured["prompt"] is str
    assert structured["idempotency_key"] is str
