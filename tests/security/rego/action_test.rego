package nexus.action_test

import rego.v1

risk_input(base, context) := {
    "tenant_id": "018f0000-0000-7000-8000-000000000001",
    "trusted_facts": {
        "configured_base_risk": base,
        "contextual_risk": context,
        "approval": null,
    },
}

test_risk_never_decreases if {
    data.nexus.action.effective_risk == "R3" with input as risk_input("R3", "R1")
    data.nexus.action.effective_risk == "R4" with input as risk_input("R2", "R4")
}

test_r4_never_permits if {
    not data.nexus.action.risk_permits with input as risk_input("R4", "R0")
}

test_r3_requires_approval if {
    data.nexus.action.requires_approval with input as risk_input("R3", "R0")
    not data.nexus.action.risk_permits with input as risk_input("R3", "R0")
}

test_all_twenty_five_risk_pairs_are_monotonic if {
    risks := ["R0", "R1", "R2", "R3", "R4"]
    every base in risks {
        every context in risks {
            effective := data.nexus.action.effective_risk with input as risk_input(base, context)
            data.nexus.risk_rank[effective] >= data.nexus.risk_rank[base]
            data.nexus.risk_rank[effective] >= data.nexus.risk_rank[context]
        }
    }
}

valid_approval_input := {
    "tenant_id": "018f0000-0000-7000-8000-000000000001",
    "trusted_facts": {
        "configured_base_risk": "R3",
        "contextual_risk": "R0",
        "action_id": "018f0000-0000-7000-8000-000000000010",
        "action_version": 2,
        "plan_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "approval": {
            "tenant_id": "018f0000-0000-7000-8000-000000000001",
            "action_id": "018f0000-0000-7000-8000-000000000010",
            "action_version": 2,
            "plan_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "approver_id": "018f0000-0000-7000-8000-000000000020",
            "requester_id": "018f0000-0000-7000-8000-000000000021",
            "proposer_id": "018f0000-0000-7000-8000-000000000022",
            "executor_id": "018f0000-0000-7000-8000-000000000023",
            "approved": true,
            "consumed": false,
        },
    },
}

test_exact_approval_permits_r3 if {
    data.nexus.action.risk_permits with input as valid_approval_input
}

test_self_approval_denied if {
    approval := object.union(valid_approval_input.trusted_facts.approval, {
        "requester_id": valid_approval_input.trusted_facts.approval.approver_id,
    })
    facts := object.union(valid_approval_input.trusted_facts, {"approval": approval})
    value := object.union(valid_approval_input, {"trusted_facts": facts})
    not data.nexus.action.risk_permits with input as value
}

test_consumed_approval_denied if {
    approval := object.union(valid_approval_input.trusted_facts.approval, {"consumed": true})
    facts := object.union(valid_approval_input.trusted_facts, {"approval": approval})
    value := object.union(valid_approval_input, {"trusted_facts": facts})
    not data.nexus.action.risk_permits with input as value
}

test_every_separation_of_duties_actor_is_distinct if {
    actor_fields := ["requester_id", "proposer_id", "executor_id"]
    every field in actor_fields {
        approval := object.union(valid_approval_input.trusted_facts.approval, {
            field: valid_approval_input.trusted_facts.approval.approver_id,
        })
        facts := object.union(valid_approval_input.trusted_facts, {"approval": approval})
        value := object.union(valid_approval_input, {"trusted_facts": facts})
        not data.nexus.action.risk_permits with input as value
    }
}

test_every_exact_approval_binding_mismatch_denied if {
    mismatches := {
        "tenant_id": "018f0000-0000-7000-8000-000000000099",
        "action_id": "018f0000-0000-7000-8000-000000000099",
        "action_version": 3,
        "plan_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }
    every field, mismatch in mismatches {
        approval := object.union(valid_approval_input.trusted_facts.approval, {field: mismatch})
        facts := object.union(valid_approval_input.trusted_facts, {"approval": approval})
        value := object.union(valid_approval_input, {"trusted_facts": facts})
        not data.nexus.action.risk_permits with input as value
    }
}
