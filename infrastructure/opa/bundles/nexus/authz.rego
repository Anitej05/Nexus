package nexus.authz

import rego.v1

policy_revision := data.nexus.policy_revision
default allow := false
default obligations := []
default reason_codes := ["denied"]

effective_class := data.nexus.action.effective_risk if risk_facts_valid
effective_class := null if not risk_facts_valid

risk_facts_valid if {
    input.trusted_facts.configured_base_risk in {"R0", "R1", "R2", "R3", "R4"}
    input.trusted_facts.contextual_risk in {"R0", "R1", "R2", "R3", "R4"}
}

decision := {
    "decision_id": object.get(input, "decision_id", ""),
    "allow": allow,
    "effective_class": effective_class,
    "obligations": obligations,
    "reason_codes": reason_codes,
    "policy_revision": policy_revision,
}

allow if {
    valid_identity
    known_operation
    explicit_role_grant
    exact_scope
    tenant_exact
    sensitivity_allowed
    trusted_provenance
    action_provenance_valid
    agent_allowed
    delegation_valid
    obligations_enforced
    data.nexus.action.risk_permits
}

known_operation if input.operation in data.nexus.operations

valid_identity if {
    is_string(input.decision_id)
    is_string(input.tenant_id)
    is_string(input.actor.actor_id)
    is_array(input.actor.roles)
    is_array(input.actor.scopes)
    count(input.actor.roles) > 0
}

explicit_role_grant if {
    some role in input.actor.roles
    grants := data.nexus.roles[role]
    input.operation in grants
}

exact_scope if input.operation in input.actor.scopes

tenant_exact if {
    every resource in input.resources {
        resource.tenant_id == input.tenant_id
    }
}

sensitivity_allowed if {
    labels := {label | some label in input.trusted_facts.resource_sensitivity}
    clearances := {label | some label in input.actor.sensitivity_clearances}
    known := {label | some label in data.nexus.sensitivity_labels}
    count(labels - known) == 0
    count(labels) > 0
    count(clearances - known) == 0
    count(labels - clearances) == 0
}

trusted_provenance if {
    risk_facts_valid
    is_array(input.trusted_facts.resource_sensitivity)
}

action_provenance_valid if input.operation != "action.execute"

action_provenance_valid if {
    input.operation == "action.execute"
    is_string(input.trusted_facts.action_id)
    is_number(input.trusted_facts.action_version)
    input.trusted_facts.action_version > 0
    regex.match(`^[0-9a-f]{64}$`, input.trusted_facts.plan_hash)
}

agent_allowed if input.actor.agent_id == null

agent_allowed if {
    input.actor.agent_id != null
    not input.operation in data.nexus.agent_hard_denials
    not delegation_expands
    requested_covers_actual
}

delegation_valid if {
    count(input.delegation_chain) == 0
    input.actor.agent_id == null
    input.trusted_facts.requested_capabilities == null
}

delegation_valid if {
    count(input.delegation_chain) > 0
    count(input.delegation_chain) <= 8
    input.trusted_facts.delegator_capabilities != null
    input.delegation_chain[0].delegator_id == input.actor.actor_id
    input.delegation_chain[count(input.delegation_chain) - 1].delegate_id == input.actor.agent_id
    not delegation_violation
    not delegation_expands
}

delegation_violation if {
    some i
    link := input.delegation_chain[i]
    link.tenant_id != input.tenant_id
}

delegation_violation if {
    some i
    input.delegation_chain[i].delegate_id == input.delegation_chain[0].delegator_id
}

delegation_violation if {
    some i
    link := input.delegation_chain[i]
    link.delegator_id == link.delegate_id
}

delegation_violation if {
    some i
    i > 0
    previous := input.delegation_chain[i - 1]
    link := input.delegation_chain[i]
    previous.delegate_id != link.delegator_id
}

delegation_violation if {
    some i, j
    i < j
    input.delegation_chain[i].delegate_id == input.delegation_chain[j].delegate_id
}

delegation_expands if {
    count(input.delegation_chain) > 0
    first := input.delegation_chain[0].capabilities
    not capability_subset(first, input.trusted_facts.delegator_capabilities)
}

delegation_expands if {
    some i
    i > 0
    child := input.delegation_chain[i].capabilities
    parent := input.delegation_chain[i - 1].capabilities
    not capability_subset(child, parent)
}

delegation_expands if {
    count(input.delegation_chain) > 0
    requested := input.trusted_facts.requested_capabilities
    requested != null
    last := input.delegation_chain[count(input.delegation_chain) - 1].capabilities
    not capability_subset(requested, last)
}

capability_subset(child, parent) if {
    capability_shape(child)
    capability_shape(parent)
    dimensions := ["tools", "object_types", "properties", "actions", "external_destinations"]
    every dimension in dimensions {
        child_set := {value | some value in child[dimension]}
        parent_set := {value | some value in parent[dimension]}
        count(child_set - parent_set) == 0
    }
}

capability_shape(value) if {
    object.keys(value) == {"tools", "object_types", "properties", "actions", "external_destinations"}
    every dimension in object.keys(value) {
        is_array(value[dimension])
        value[dimension] == sort(value[dimension])
        count(value[dimension]) == count({item | some item in value[dimension]})
        every item in value[dimension] {
            is_string(item)
            item != ""
        }
    }
}

requested_covers_actual if {
    requested := input.trusted_facts.requested_capabilities
    requested != null
    capability_shape(requested)
    input.operation in requested.actions
    every resource in input.resources {
        resource.kind in requested.object_types
    }
    every tool in input.trusted_facts.used_tools {
        tool in requested.tools
    }
    every property in input.trusted_facts.used_properties {
        property in requested.properties
    }
    every action in input.trusted_facts.used_actions {
        action in requested.actions
    }
    every destination in input.trusted_facts.used_external_destinations {
        destination in requested.external_destinations
    }
}

obligations := sort({value | some value in array.concat(input.trusted_facts.obligations, ["require_approval"])}) if {
    data.nexus.action.requires_approval
}

obligations := sort({value | some value in input.trusted_facts.obligations}) if not data.nexus.action.requires_approval

obligations_enforced if {
    every obligation in input.trusted_facts.obligations {
        obligation in input.trusted_facts.consumer_enforced_obligations
        valid_obligation(obligation)
        redaction_permitted(obligation)
    }
}

valid_obligation(value) if value == "require_approval"
valid_obligation(value) if regex.match(`^max_rows:[1-9][0-9]*$`, value)
valid_obligation(value) if {
    regex.match(`^redact_properties:[A-Za-z0-9_.-]+(,[A-Za-z0-9_.-]+)*$`, value)
    parts := split(trim_prefix(value, "redact_properties:"), ",")
    parts == sort(parts)
    count(parts) == count({part | some part in parts})
}

redaction_permitted(value) if not startswith(value, "redact_properties:")
redaction_permitted(value) if {
    startswith(value, "redact_properties:")
    input.operation in data.nexus.redaction_safe_operations
}

reason_codes := ["explicit_grant"] if allow
reason_codes := ["approval_required"] if {
    not allow
    data.nexus.action.requires_approval
}
