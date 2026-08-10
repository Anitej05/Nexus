"""HTTP contract for the reusable authentication dependency."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from uuid import UUID

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from nexus_contracts.platform import RequestContext
from nexus_security.auth import (
    AgentIdentityDenied,
    AuthenticationError,
    IdentityProviderUnavailable,
    OIDCAuthenticator,
    Principal,
    PrincipalNotRegistered,
    TenantAccess,
    TenantAccessDenied,
    TenantSelectionRequired,
)
from nexus_security.dependencies import (
    get_authenticator,
    install_auth_exception_handlers,
    require_context,
)


@pytest.fixture
def app() -> FastAPI:
    app = FastAPI()
    install_auth_exception_handlers(app)
    context_dependency = Depends(require_context)

    @app.get("/protected")
    async def protected(context: RequestContext = context_dependency) -> dict[str, str]:
        return {"tenant_id": str(context.tenant_id)}

    return app


@pytest.mark.parametrize(
    ("authorization", "code"),
    [(None, "missing_token"), ("Token arbitrary-secret-token", "invalid_token")],
)
async def test_bearer_failures_return_canonical_problem_without_echoing_credentials(
    app: FastAPI, authorization: str | None, code: str
) -> None:
    headers = {} if authorization is None else {"Authorization": authorization}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/protected", headers=headers)

    body = response.json()
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert set(body) == {
        "type",
        "title",
        "status",
        "detail",
        "instance",
        "code",
        "correlation_id",
    }
    assert body["status"] == 401
    assert body["code"] == code
    assert UUID(body["correlation_id"]).version == 7
    assert "arbitrary-secret-token" not in response.text


async def test_invalid_correlation_id_is_typed_and_replaced_with_safe_uuid7(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/protected",
            headers={
                "Authorization": "Bearer syntactically-valid",
                "X-Correlation-ID": "not-a-uuid",
            },
        )

    body = response.json()
    assert response.status_code == 400
    assert body["code"] == "invalid_correlation_id"
    assert UUID(body["correlation_id"]).version == 7


async def test_missing_bearer_wins_over_invalid_correlation_id(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/protected", headers={"X-Correlation-ID": "not-a-uuid"})

    assert response.status_code == 401
    assert response.json()["code"] == "missing_token"
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("authorization", [None, "Basic credential"])
async def test_early_bearer_failures_echo_accepted_correlation_id(
    app: FastAPI, authorization: str | None
) -> None:
    correlation_id = "018f0000-0000-7000-8000-000000000003"
    headers = {"X-Correlation-ID": correlation_id}
    if authorization is not None:
        headers["Authorization"] = authorization
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/protected", headers=headers)

    assert response.status_code == 401
    assert response.json()["correlation_id"] == correlation_id


async def test_oversized_bearer_is_rejected_before_authenticator_dependency(app: FastAPI) -> None:
    called = False

    async def unexpected_authenticator() -> OIDCAuthenticator:
        nonlocal called
        called = True
        raise AssertionError("adapter must not be constructed")

    app.dependency_overrides[get_authenticator] = unexpected_authenticator
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/protected", headers={"Authorization": "bearer " + "x" * 20000}
        )

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"
    assert called is False


@pytest.mark.parametrize(
    ("failure", "status", "code"),
    [
        (PrincipalNotRegistered(), 403, "principal_not_registered"),
        (IdentityProviderUnavailable(), 503, "identity_provider_unavailable"),
        (AuthenticationError("invalid_token_signature"), 401, "invalid_token_signature"),
    ],
)
async def test_authenticator_failures_map_to_canonical_problem_bodies(
    app: FastAPI, failure: AuthenticationError, status: int, code: str
) -> None:
    class FailingAuthenticator:
        async def authenticate(self, _token: str) -> Principal:
            raise failure

    app.dependency_overrides[get_authenticator] = lambda: FailingAuthenticator()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/protected", headers={"Authorization": "Bearer valid"})

    assert response.status_code == status
    assert response.json()["code"] == code
    assert set(response.json()) == {
        "type",
        "title",
        "status",
        "detail",
        "instance",
        "code",
        "correlation_id",
    }
    assert ("www-authenticate" in response.headers) is (status == 401)


@pytest.mark.parametrize(
    ("failure", "status", "title", "code"),
    [
        (TenantSelectionRequired(), 400, "Tenant selection required", "tenant_selection_required"),
        (TenantAccessDenied(), 403, "Tenant access denied", "tenant_access_denied"),
        (AgentIdentityDenied(), 403, "Agent identity denied", "agent_identity_denied"),
        (
            IdentityProviderUnavailable(),
            503,
            "Identity provider unavailable",
            "identity_provider_unavailable",
        ),
    ],
)
async def test_frozen_problem_values_are_exact_for_typed_failures(
    app: FastAPI, failure: AuthenticationError, status: int, title: str, code: str
) -> None:
    class FailingAuthenticator:
        async def authenticate(self, _token: str) -> Principal:
            raise failure

    app.dependency_overrides[get_authenticator] = lambda: FailingAuthenticator()
    correlation = "018f0000-0000-7000-8000-000000000003"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/protected", headers={"Authorization": "Bearer valid", "X-Correlation-ID": correlation}
        )
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": f"https://nexus.local/problems/{code.replace('_', '-')}",
        "title": title,
        "status": status,
        "detail": None,
        "instance": None,
        "code": code,
        "correlation_id": correlation,
    }
    assert "www-authenticate" not in response.headers


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, str]:
    numbers = key.public_key().public_numbers()

    def encoded(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": encoded(numbers.n),
        "e": encoded(numbers.e),
    }


class _Memberships:
    async def resolve(self, _issuer: str, _subject: str) -> tuple:
        return ()


class _Agents:
    async def has_active_version(self, _agent_id: UUID) -> bool:
        return False


async def test_real_oidc_decoding_and_signature_failures_redact_sentinels(
    app: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    issuer = "https://identity.example.test/realms/nexus"
    jwks_url = "https://identity.example.test/jwks"
    header_marker = "JOSE_HEADER_SENTINEL"
    claim_marker = "CLIENT_SECRET_SENTINEL"
    signature_marker = "SIGNATURE_SENTINEL"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime(2026, 8, 9, tzinfo=UTC)
    token = jwt.encode(
        {
            "iss": issuer,
            "aud": "nexus-api",
            "sub": claim_marker,
            "exp": now + timedelta(minutes=5),
            "nbf": now,
        },
        key,
        algorithm="RS256",
        headers={"kid": header_marker},
    )
    authenticator = OIDCAuthenticator(
        issuer=issuer,
        jwks_url=jwks_url,
        audience="nexus-api",
        worker_azp="nexus-worker",
        membership_repository=_Memberships(),
        agent_repository=_Agents(),
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, json={"keys": [_jwk(key, header_marker)]})
            )
        ),
        clock=lambda: now,
    )
    app.dependency_overrides[get_authenticator] = lambda: authenticator
    caplog.set_level("DEBUG")
    corrupted = token.rsplit(".", 1)[0] + "." + signature_marker
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        decoded_response = await client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        response = await client.get("/protected", headers={"Authorization": f"Bearer {corrupted}"})
    observed = decoded_response.text + response.text + caplog.text
    for sentinel in (header_marker, claim_marker, signature_marker, corrupted):
        assert sentinel not in observed
    assert response.status_code == 401
    assert decoded_response.status_code == 403
    await authenticator.aclose()


async def test_real_jwks_upstream_body_is_redacted_from_asgi_response_and_logs(
    app: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    issuer = "https://identity.example.test/realms/nexus"
    upstream_marker = "UPSTREAM_BODY_SENTINEL"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime(2026, 8, 9, tzinfo=UTC)
    token = jwt.encode(
        {
            "iss": issuer,
            "aud": "nexus-api",
            "sub": "subject",
            "exp": now + timedelta(minutes=5),
            "nbf": now,
        },
        key,
        algorithm="RS256",
        headers={"kid": "key"},
    )
    authenticator = OIDCAuthenticator(
        issuer=issuer,
        jwks_url="https://identity.example.test/jwks",
        audience="nexus-api",
        worker_azp="nexus-worker",
        membership_repository=_Memberships(),
        agent_repository=_Agents(),
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, content=upstream_marker.encode())
            )
        ),
        clock=lambda: now,
    )
    app.dependency_overrides[get_authenticator] = lambda: authenticator
    caplog.set_level("DEBUG")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert upstream_marker not in response.text + caplog.text
    assert response.status_code == 503
    await authenticator.aclose()


async def test_dependency_override_builds_selected_tenant_request_context(app: FastAPI) -> None:
    tenant = UUID("018f0000-0000-7000-8000-000000000002")
    actor = UUID("018f0000-0000-7000-8000-000000000001")
    access = TenantAccess(
        tenant, frozenset({"viewer"}), frozenset({"read"}), frozenset({"internal"})
    )
    principal = Principal(
        actor,
        "issuer",
        frozenset({"nexus-api"}),
        access.roles,
        access.scopes,
        frozenset({tenant}),
        access.sensitivity_clearances,
        "human",
        _accesses={tenant: access},
    )

    class StaticAuthenticator:
        async def authenticate(self, _token: str) -> Principal:
            return principal

    app.dependency_overrides[get_authenticator] = lambda: StaticAuthenticator()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/protected", headers={"Authorization": "Bearer valid", "X-Nexus-Tenant": str(tenant)}
        )

    assert response.status_code == 200
    assert response.json()["tenant_id"] == str(tenant)
