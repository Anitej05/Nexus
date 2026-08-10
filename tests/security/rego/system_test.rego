package system.authz_test

import rego.v1

test_health_is_allowed if {
    data.system.authz.allow with input as {"method": "GET", "path": ["health"]}
}

test_exact_decision_post_is_allowed if {
    data.system.authz.allow with input as {
        "method": "POST",
        "path": ["v1", "data", "nexus", "authz", "decision"],
    }
}

test_data_management_is_denied if {
    not data.system.authz.allow with input as {
        "method": "PUT",
        "path": ["v1", "data", "nexus", "roles", "viewer"],
    }
}

test_policy_management_is_denied if {
    not data.system.authz.allow with input as {
        "method": "DELETE",
        "path": ["v1", "policies", "nexus-authz"],
    }
}

test_other_decision_path_is_denied if {
    not data.system.authz.allow with input as {
        "method": "POST",
        "path": ["v1", "data", "system", "authz", "allow"],
    }
}
