from pathlib import Path


def test_policy_bundle_uses_rego_v1_and_is_versioned() -> None:
    bundle = Path("infrastructure/opa/bundles/nexus")
    authz = (bundle / "authz.rego").read_text(encoding="utf-8")
    action = (bundle / "action.rego").read_text(encoding="utf-8")
    assert "import rego.v1" in authz
    assert "import rego.v1" in action
    assert "policy_revision" in authz


def test_genuine_rego_tests_exist() -> None:
    tests = list(Path("tests/security/rego").glob("*_test.rego"))
    assert len(tests) >= 2
    assert all("test_" in path.read_text(encoding="utf-8") for path in tests)


def test_compose_mounts_policy_read_only_and_configures_consumers() -> None:
    compose = Path("infrastructure/compose/compose.yml").read_text(encoding="utf-8")
    assert "../opa/bundles/nexus:/policy:ro" in compose
    assert "OPA_DECISION_URL: http://opa:8181/v1/data/nexus/authz/decision" in compose
    assert compose.count("NEXUS_OPA_DECISION_URL:") == 2
    opa_section = compose.split("  opa:", 1)[1].split("  opa-health-probe:", 1)[0]
    assert "ports:" not in opa_section
    assert "--authorization=basic" in opa_section
    system_policy = Path("infrastructure/opa/bundles/nexus/system.rego").read_text()
    assert "package system.authz" in system_policy
    assert 'input.method == "POST"' in system_policy
