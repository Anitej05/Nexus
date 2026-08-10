import argparse
import json
import os
import sys
import time
from urllib.request import Request, urlopen

KNOWN_DENY = {
    "input": {
        "decision_id": "018f0000-0000-7000-8000-000000000021",
        "tenant_id": "018f0000-0000-7000-8000-000000000001",
        "actor": {
            "actor_id": "018f0000-0000-7000-8000-000000000002",
            "agent_id": None,
            "roles": ["viewer"],
            "scopes": ["ontology.write"],
            "sensitivity_clearances": ["internal"],
        },
        "resources": [],
        "operation": "ontology.write",
        "attributes": {},
        "delegation_chain": [],
        "trusted_facts": {
            "resource_sensitivity": ["internal"],
            "configured_base_risk": "R0",
            "contextual_risk": "R0",
            "delegator_capabilities": None,
            "requested_capabilities": None,
            "approval": None,
            "action_id": None,
            "action_version": None,
            "plan_hash": None,
            "used_tools": [],
            "used_properties": [],
            "used_actions": [],
            "used_external_destinations": [],
            "consumer_enforced_obligations": [],
            "obligations": [],
        },
    }
}


def healthy() -> bool:
    try:
        opa_url = os.environ.get("OPA_DECISION_URL")
        if opa_url:
            request = Request(  # noqa: S310 -- fixed operator-controlled internal URL.
                opa_url,
                data=json.dumps(KNOWN_DENY).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=2) as response:  # noqa: S310
                result = json.load(response)["result"]
            return (
                type(result) is dict
                and result.get("decision_id") == KNOWN_DENY["input"]["decision_id"]
                and type(result.get("decision_id")) is str
                and result.get("allow") is False
                and result.get("effective_class") == "R0"
                and type(result.get("effective_class")) is str
                and result.get("obligations") == []
                and result.get("reason_codes") == ["denied"]
                and result.get("policy_revision") == "1.0.0"
                and type(result.get("policy_revision")) is str
                and set(result)
                == {
                    "decision_id",
                    "allow",
                    "effective_class",
                    "obligations",
                    "reason_codes",
                    "policy_revision",
                }
            )
        url = os.environ.get("OTEL_HEALTH_URL", "http://otel-collector:13133/")
        with urlopen(url, timeout=2) as response:  # noqa: S310
            return 200 <= response.status < 400
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


arguments = argparse.ArgumentParser()
arguments.add_argument("--self-check", action="store_true")
options = arguments.parse_args()
if options.self_check:
    sys.exit(0 if healthy() else 1)
while not healthy():
    time.sleep(1)
while healthy():
    time.sleep(2)
sys.exit(1)
