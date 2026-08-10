package nexus.action

import rego.v1

risk_rank := data.nexus.risk_rank

effective_risk := risk if {
    base := input.trusted_facts.configured_base_risk
    context := input.trusted_facts.contextual_risk
    risk_rank[base] >= risk_rank[context]
    risk := base
}

effective_risk := risk if {
    base := input.trusted_facts.configured_base_risk
    context := input.trusted_facts.contextual_risk
    risk_rank[context] > risk_rank[base]
    risk := context
}

approval_valid if {
    approval := input.trusted_facts.approval
    approval.approved == true
    approval.consumed == false
    approval.tenant_id == input.tenant_id
    approval.action_id == input.trusted_facts.action_id
    approval.action_version == input.trusted_facts.action_version
    approval.plan_hash == input.trusted_facts.plan_hash
    approval.approver_id != approval.requester_id
    approval.approver_id != approval.proposer_id
    approval.approver_id != approval.executor_id
}

risk_permits if {
    effective_risk in {"R0", "R1", "R2"}
}

risk_permits if {
    effective_risk == "R3"
    approval_valid
}

requires_approval if {
    effective_risk == "R3"
    not approval_valid
}
