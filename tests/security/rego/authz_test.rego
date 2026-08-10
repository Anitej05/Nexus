package nexus.authz_test

import rego.v1

base_input := {
    "decision_id": "018f0000-0000-7000-8000-000000000021",
    "tenant_id": "018f0000-0000-7000-8000-000000000001",
    "actor": {
        "actor_id": "018f0000-0000-7000-8000-000000000002",
        "agent_id": null,
        "roles": ["viewer"],
        "scopes": ["ontology.read"],
        "sensitivity_clearances": ["internal"],
    },
    "resources": [{
        "tenant_id": "018f0000-0000-7000-8000-000000000001",
        "kind": "ontology_object",
        "id": "018f0000-0000-7000-8000-000000000011",
        "version": 1,
    }],
    "operation": "ontology.read",
    "attributes": {},
    "delegation_chain": [],
    "trusted_facts": {
        "resource_sensitivity": ["internal"],
        "configured_base_risk": "R0",
        "contextual_risk": "R0",
        "delegator_capabilities": null,
        "requested_capabilities": null,
        "approval": null,
        "action_id": null,
        "action_version": null,
        "plan_hash": null,
        "used_tools": [],
        "used_properties": [],
        "used_actions": [],
        "used_external_destinations": [],
        "consumer_enforced_obligations": [],
        "obligations": [],
    },
}

test_viewer_read_allowed if {
    data.nexus.authz.decision with input as base_input
    data.nexus.authz.decision.allow == true with input as base_input
}

prototype_replay_read_input := value if {
    actor := object.union(base_input.actor, {
        "roles": ["operator"],
        "scopes": ["action.read"],
    })
    resource := object.union(base_input.resources[0], {
        "kind": "prototype.run",
        "id": "018f0000-0000-7000-8000-000000000901",
    })
    value := object.union(base_input, {
        "actor": actor,
        "resources": [resource],
        "operation": "action.read",
    })
}

test_prototype_execution_replay_read_allowed_for_same_operator_and_resource if {
    decision := data.nexus.authz.decision with input as prototype_replay_read_input
    decision.allow == true
    decision.effective_class == "R0"
    decision.reason_codes == ["explicit_grant"]
}

test_prototype_execution_replay_read_denial_is_bounded_and_safe if {
    actor := object.union(prototype_replay_read_input.actor, {"scopes": []})
    value := object.union(prototype_replay_read_input, {"actor": actor})
    decision := data.nexus.authz.decision with input as value
    decision.allow == false
    decision.decision_id == base_input.decision_id
    decision.reason_codes == ["denied"]
}

test_viewer_write_default_denied if {
    value := object.union(base_input, {"operation": "ontology.write"})
    data.nexus.authz.decision.allow == false with input as value
}

test_unknown_operation_denied if {
    value := object.union(base_input, {"operation": "unknown"})
    data.nexus.authz.decision.allow == false with input as value
}

test_cross_tenant_denied if {
    resources := [object.union(base_input.resources[0], {"tenant_id": "018f0000-0000-7000-8000-000000000099"})]
    value := object.union(base_input, {"resources": resources})
    data.nexus.authz.decision.allow == false with input as value
}

test_missing_exact_scope_denied if {
    actor := object.union(base_input.actor, {"scopes": []})
    value := object.union(base_input, {"actor": actor})
    data.nexus.authz.decision.allow == false with input as value
}

test_unknown_sensitivity_denied if {
    facts := object.union(base_input.trusted_facts, {"resource_sensitivity": ["secret"]})
    value := object.union(base_input, {"trusted_facts": facts})
    data.nexus.authz.decision.allow == false with input as value
}

test_agent_policy_write_hard_denied if {
    actor := object.union(base_input.actor, {
        "agent_id": "018f0000-0000-7000-8000-000000000030",
        "roles": ["platform_admin"],
        "scopes": ["policy.write"],
    })
    value := object.union(base_input, {"actor": actor, "operation": "policy.write"})
    data.nexus.authz.decision.allow == false with input as value
}

test_agent_publish_self_hard_denied if {
    actor := object.union(base_input.actor, {
        "agent_id": "018f0000-0000-7000-8000-000000000030",
        "roles": ["platform_admin"],
        "scopes": ["agent.publish_self"],
    })
    value := object.union(base_input, {"actor": actor, "operation": "agent.publish_self"})
    data.nexus.authz.decision.allow == false with input as value
}

test_malformed_actor_shape_denied if {
    actor := object.union(base_input.actor, {"roles": "viewer"})
    value := object.union(base_input, {"actor": actor})
    data.nexus.authz.decision.allow == false with input as value
}

test_unenforced_obligation_denied if {
    facts := object.union(base_input.trusted_facts, {"obligations": ["max_rows:10"]})
    value := object.union(base_input, {"trusted_facts": facts})
    data.nexus.authz.decision.allow == false with input as value
}

test_enforced_obligation_allowed if {
    facts := object.union(base_input.trusted_facts, {
        "obligations": ["max_rows:10"],
        "consumer_enforced_obligations": ["max_rows:10"],
    })
    value := object.union(base_input, {"trusted_facts": facts})
    data.nexus.authz.decision.allow == true with input as value
}

test_redaction_obligation_denied_for_unsafe_write if {
    actor := object.union(base_input.actor, {
        "roles": ["data_steward"],
        "scopes": ["ontology.write"],
    })
    facts := object.union(base_input.trusted_facts, {
        "obligations": ["redact_properties:ssn"],
        "consumer_enforced_obligations": ["redact_properties:ssn"],
    })
    value := object.union(base_input, {
        "actor": actor,
        "operation": "ontology.write",
        "trusted_facts": facts,
    })
    data.nexus.authz.decision.allow == false with input as value
}

test_obligation_grammar_edges if {
    data.nexus.authz.valid_obligation("max_rows:1")
    data.nexus.authz.valid_obligation("redact_properties:a,b")
    not data.nexus.authz.valid_obligation("max_rows:0")
    not data.nexus.authz.valid_obligation("max_rows:01")
    not data.nexus.authz.valid_obligation("redact_properties:b,a")
    not data.nexus.authz.valid_obligation("redact_properties:a,a")
    not data.nexus.authz.valid_obligation("unknown:value")
}

full_capabilities := {
    "tools": ["search"],
    "object_types": ["ontology_object", "shipment"],
    "properties": ["status"],
    "actions": ["ontology.read", "reroute"],
    "external_destinations": ["carrier"],
}

actual_capabilities := {
    "tools": [],
    "object_types": ["ontology_object"],
    "properties": [],
    "actions": ["ontology.read"],
    "external_destinations": [],
}

empty_capabilities := {
    "tools": [],
    "object_types": [],
    "properties": [],
    "actions": [],
    "external_destinations": [],
}

test_delegation_expansion_denied_in_every_dimension if {
    dimensions := ["tools", "object_types", "properties", "actions", "external_destinations"]
    every dimension in dimensions {
        expanded := object.union(full_capabilities, {dimension: array.concat(full_capabilities[dimension], ["extra"])})
        not data.nexus.authz.capability_subset(expanded, full_capabilities) with input as base_input
    }
}

test_delegation_subset_allowed_in_every_dimension if {
    data.nexus.authz.capability_subset(empty_capabilities, full_capabilities) with input as base_input
}

all_used_input(requested) := value if {
    facts := object.union(base_input.trusted_facts, {
        "requested_capabilities": requested,
        "used_tools": ["search"],
        "used_properties": ["status"],
        "used_actions": ["reroute"],
        "used_external_destinations": ["carrier"],
    })
    value := object.union(base_input, {"trusted_facts": facts})
}

test_requested_capabilities_cover_every_used_dimension if {
    data.nexus.authz.requested_covers_actual with input as all_used_input(full_capabilities)
}

test_absence_in_each_used_capability_dimension_denies if {
    dimensions := ["tools", "object_types", "properties", "actions", "external_destinations"]
    every dimension in dimensions {
        reduced := object.union(full_capabilities, {dimension: []})
        not data.nexus.authz.requested_covers_actual with input as all_used_input(reduced)
    }
}

agent_input(link) := value if {
    actor := object.union(base_input.actor, {
        "agent_id": link.delegate_id,
    })
    facts := object.union(base_input.trusted_facts, {
        "delegator_capabilities": full_capabilities,
        "requested_capabilities": actual_capabilities,
    })
    value := object.union(base_input, {
        "actor": actor,
        "delegation_chain": [link],
        "trusted_facts": facts,
    })
}

valid_link := {
    "tenant_id": base_input.tenant_id,
    "delegator_id": base_input.actor.actor_id,
    "delegate_id": "018f0000-0000-7000-8000-000000000030",
    "capabilities": full_capabilities,
}

test_valid_agent_delegation_allowed if {
    data.nexus.authz.decision.allow == true with input as agent_input(valid_link)
}

test_empty_agent_capabilities_deny_real_operation if {
    facts := object.union(agent_input(valid_link).trusted_facts, {
        "requested_capabilities": empty_capabilities,
    })
    value := object.union(agent_input(valid_link), {"trusted_facts": facts})
    data.nexus.authz.decision.allow == false with input as value
}

test_null_agent_capabilities_deny_real_operation if {
    facts := object.union(agent_input(valid_link).trusted_facts, {
        "requested_capabilities": null,
    })
    value := object.union(agent_input(valid_link), {"trusted_facts": facts})
    data.nexus.authz.decision.allow == false with input as value
}

missing_sensitivity_input := value if {
    facts := {key: item | some key, item in base_input.trusted_facts; key != "resource_sensitivity"}
    without_facts := {key: item | some key, item in base_input; key != "trusted_facts"}
    value := object.union(without_facts, {"trusted_facts": facts})
}

test_missing_sensitivity_provenance_denied if {
    data.nexus.authz.decision.allow == false with input as missing_sensitivity_input
}

test_empty_sensitivity_provenance_denied if {
    facts := object.union(base_input.trusted_facts, {"resource_sensitivity": []})
    value := object.union(base_input, {"trusted_facts": facts})
    data.nexus.authz.decision.allow == false with input as value
}

missing_risk_input := value if {
    facts := {key: item | some key, item in base_input.trusted_facts; key != "configured_base_risk"}
    without_facts := {key: item | some key, item in base_input; key != "trusted_facts"}
    value := object.union(without_facts, {"trusted_facts": facts})
}

test_missing_risk_provenance_denied if {
    data.nexus.authz.decision.allow == false with input as missing_risk_input
}

test_action_execute_without_provenance_denied if {
    actor := object.union(base_input.actor, {
        "roles": ["operator"],
        "scopes": ["action.execute"],
    })
    value := object.union(base_input, {"actor": actor, "operation": "action.execute"})
    data.nexus.authz.decision.allow == false with input as value
}

test_delegation_tenant_mismatch_denied if {
    link := object.union(valid_link, {"tenant_id": "018f0000-0000-7000-8000-000000000099"})
    data.nexus.authz.decision.allow == false with input as agent_input(link)
}


test_unknown_capability_dimension_denied if {
    malformed := object.union(full_capabilities, {"unknown": []})
    not data.nexus.authz.capability_shape(malformed) with input as base_input
}

test_noncanonical_capability_arrays_denied if {
    duplicate := object.union(full_capabilities, {"actions": ["ontology.read", "ontology.read"]})
    unsorted := object.union(full_capabilities, {"object_types": ["shipment", "ontology_object"]})
    empty_name := object.union(full_capabilities, {"tools": [""]})
    not data.nexus.authz.capability_shape(duplicate) with input as base_input
    not data.nexus.authz.capability_shape(unsorted) with input as base_input
    not data.nexus.authz.capability_shape(empty_name) with input as base_input
}

test_delegation_gap_denied if {
    second := {
        "tenant_id": base_input.tenant_id,
        "delegator_id": "018f0000-0000-7000-8000-000000000099",
        "delegate_id": "018f0000-0000-7000-8000-000000000031",
        "capabilities": full_capabilities,
    }
    value := object.union(agent_input(valid_link), {"delegation_chain": [valid_link, second]})
    not data.nexus.authz.delegation_valid with input as value
}

test_delegation_cycle_denied if {
    second := {
        "tenant_id": base_input.tenant_id,
        "delegator_id": valid_link.delegate_id,
        "delegate_id": valid_link.delegator_id,
        "capabilities": full_capabilities,
    }
    actor := object.union(agent_input(valid_link).actor, {"agent_id": second.delegate_id})
    value := object.union(agent_input(valid_link), {
        "actor": actor,
        "delegation_chain": [valid_link, second],
    })
    not data.nexus.authz.delegation_valid with input as value
}

test_delegation_depth_over_eight_denied if {
    chain := [valid_link, valid_link, valid_link, valid_link, valid_link, valid_link, valid_link, valid_link, valid_link]
    value := object.union(agent_input(valid_link), {"delegation_chain": chain})
    not data.nexus.authz.delegation_valid with input as value
}
