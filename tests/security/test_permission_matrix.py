from __future__ import annotations

import json
from pathlib import Path

import pytest

DATA = Path("infrastructure/opa/bundles/nexus/data.json")

OPERATIONS = {
    "tenant.admin",
    "membership.manage",
    "ontology.read",
    "ontology.write",
    "ontology.schema.publish",
    "entity.resolve",
    "branch.read",
    "branch.create",
    "branch.write",
    "branch.submit",
    "branch.approve",
    "branch.merge",
    "model.read",
    "model.train",
    "model.promote",
    "workflow.read",
    "workflow.design",
    "workflow.publish",
    "workflow.execute",
    "agent.read",
    "agent.publish",
    "agent.publish_self",
    "agent.grant_scope",
    "agent.retire",
    "action.read",
    "action.propose",
    "action.approve",
    "action.execute",
    "policy.read",
    "policy.write",
    "audit.read",
}

EXPECTED_ROLES = {
    "platform_admin": OPERATIONS - {"agent.publish_self"},
    "data_steward": {
        "ontology.write",
        "ontology.schema.publish",
        "entity.resolve",
        "branch.read",
        "branch.create",
        "branch.write",
        "branch.submit",
        "audit.read",
    },
    "ml_engineer": {
        "ontology.read",
        "model.read",
        "model.train",
        "model.promote",
        "branch.read",
        "branch.create",
        "branch.write",
        "branch.submit",
        "workflow.read",
    },
    "workflow_designer": {
        "ontology.read",
        "workflow.read",
        "workflow.design",
        "workflow.publish",
        "agent.read",
        "agent.publish",
        "branch.read",
        "branch.create",
        "branch.write",
        "branch.submit",
    },
    "operator": {
        "ontology.read",
        "workflow.read",
        "workflow.execute",
        "action.read",
        "action.propose",
        "action.execute",
        "agent.read",
    },
    "approver": {
        "ontology.read",
        "branch.read",
        "branch.approve",
        "branch.merge",
        "model.read",
        "workflow.read",
        "action.read",
        "action.approve",
        "audit.read",
    },
    "auditor": {
        "ontology.read",
        "branch.read",
        "model.read",
        "workflow.read",
        "agent.read",
        "action.read",
        "policy.read",
        "audit.read",
    },
    "viewer": {
        "ontology.read",
        "branch.read",
        "model.read",
        "workflow.read",
        "agent.read",
        "action.read",
    },
}


@pytest.mark.parametrize(
    ("role", "operation", "allowed"),
    [
        ("viewer", "ontology.read", True),
        ("viewer", "ontology.write", False),
        ("workflow_designer", "agent.publish", True),
        ("workflow_designer", "agent.grant_scope", False),
        ("approver", "action.approve", True),
        ("auditor", "audit.read", True),
    ],
)
def test_explicit_role_matrix(role: str, operation: str, allowed: bool) -> None:
    roles = json.loads(DATA.read_text(encoding="utf-8"))["nexus"]["roles"]
    assert (operation in roles[role]) is allowed


def test_admin_is_explicit_and_no_grant_uses_wildcards() -> None:
    document = json.loads(DATA.read_text(encoding="utf-8"))["nexus"]
    assert set(document["operations"]) == OPERATIONS
    assert set(document["roles"]) == {
        "platform_admin",
        "data_steward",
        "ml_engineer",
        "workflow_designer",
        "operator",
        "approver",
        "auditor",
        "viewer",
    }
    assert {role: set(grants) for role, grants in document["roles"].items()} == EXPECTED_ROLES
    assert set(document["roles"]["platform_admin"]) == OPERATIONS - {"agent.publish_self"}
    assert set(document["agent_hard_denials"]) == {"policy.write", "agent.publish_self"}
    assert all("*" not in grants for grants in document["roles"].values())


@pytest.mark.parametrize("role", sorted(EXPECTED_ROLES))
@pytest.mark.parametrize("operation", sorted(OPERATIONS))
def test_complete_eight_by_thirty_one_matrix(role: str, operation: str) -> None:
    roles = json.loads(DATA.read_text(encoding="utf-8"))["nexus"]["roles"]
    assert (operation in roles[role]) is (operation in EXPECTED_ROLES[role])


@pytest.mark.parametrize("operation", sorted(OPERATIONS))
def test_only_explicit_read_consumer_is_redaction_safe(operation: str) -> None:
    policy = json.loads(DATA.read_text(encoding="utf-8"))["nexus"]
    assert (operation in policy["redaction_safe_operations"]) is (operation == "ontology.read")
