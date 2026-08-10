"""OIDC authentication behavior, including hostile JWKS and JWT inputs."""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime, timedelta
from uuid import UUID

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from nexus_security.auth import (
    AgentIdentityDenied,
    AuthenticationError,
    IdentityProviderUnavailable,
    Membership,
    OIDCAuthenticator,
    PrincipalNotRegistered,
    TenantAccessDenied,
    TenantSelectionRequired,
)

ISSUER = "https://identity.example.test/realms/nexus"
JWKS_URL = "https://identity.example.test/realms/nexus/protocol/openid-connect/certs"
AUDIENCE = "nexus-api"
ACTOR_ID = UUID("018f0000-0000-7000-8000-000000000001")
TENANT_ONE = UUID("018f0000-0000-7000-8000-000000000002")
TENANT_TWO = UUID("018f0000-0000-7000-8000-000000000003")
AGENT_ID = UUID("018f0000-0000-7000-8000-000000000004")


def _b64(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64(numbers.n),
        "e": _b64(numbers.e),
    }


class FakeMemberships:
    def __init__(self, memberships: tuple[Membership, ...]) -> None:
        self.memberships = memberships
        self.calls = 0

    async def resolve(self, issuer: str, subject: str) -> tuple[Membership, ...]:
        self.calls += 1
        assert issuer == ISSUER
        assert subject == "external-subject"
        return self.memberships


class FakeAgents:
    def __init__(self, active: bool = True) -> None:
        self.active = active

    async def has_active_version(self, agent_id: UUID) -> bool:
        return self.active and agent_id == AGENT_ID


@pytest.fixture
def key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def membership() -> Membership:
    return Membership(
        actor_id=ACTOR_ID,
        tenant_id=TENANT_ONE,
        roles=frozenset({"viewer", "operator"}),
        scopes=frozenset({"ontology.read", "signals.read"}),
        sensitivity_clearances=frozenset({"internal"}),
    )


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 8, 9, tzinfo=UTC)


def _token(
    key: rsa.RSAPrivateKey,
    now: datetime,
    *,
    kid: str = "key-one",
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    subject: str = "external-subject",
    expires: timedelta = timedelta(minutes=5),
    nbf: datetime | None = None,
    roles: list[str] | None = None,
    scope: str = "ontology.read forbidden.scope",
    **claims: object,
) -> str:
    payload: dict[str, object] = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "exp": now + expires,
        "nbf": now - timedelta(seconds=1) if nbf is None else nbf,
        "realm_access": {"roles": roles or ["viewer", "platform_admin"]},
        "scope": scope,
        **claims,
    }
    return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


def _authenticator(
    transport: httpx.MockTransport,
    memberships: FakeMemberships,
    agents: FakeAgents,
    now: datetime,
) -> OIDCAuthenticator:
    return OIDCAuthenticator(
        issuer=ISSUER,
        jwks_url=JWKS_URL,
        audience=AUDIENCE,
        worker_azp="nexus-worker",
        membership_repository=memberships,
        agent_repository=agents,
        http_client=httpx.AsyncClient(transport=transport),
        clock=lambda: now,
    )


def _jwks_transport(
    jwks: dict[str, object], headers: dict[str, str] | None = None
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == JWKS_URL
        return httpx.Response(200, json=jwks, headers=headers)

    return httpx.MockTransport(handler)


async def test_authenticator_intersects_verified_token_roles_and_scopes_per_membership(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    principal = await authenticator.authenticate(_token(key, now))
    selected = principal.for_tenant(TENANT_ONE)

    assert principal.actor_id == ACTOR_ID
    assert selected.roles == frozenset({"viewer"})
    assert selected.scopes == frozenset({"ontology.read"})
    assert selected.sensitivity_clearances == frozenset({"internal"})


@pytest.mark.parametrize(
    ("claims", "code"),
    [
        ({"audience": "another-api"}, "invalid_token_audience"),
        ({"issuer": "https://untrusted.example.test"}, "invalid_token_issuer"),
        ({"expires": timedelta(minutes=-2)}, "token_expired"),
        ({"nbf": datetime(2026, 8, 9, 0, 5, tzinfo=UTC)}, "token_not_yet_valid"),
        ({"subject": ""}, "invalid_token_subject"),
    ],
)
async def test_authenticator_rejects_invalid_registered_claims(
    key: rsa.RSAPrivateKey,
    membership: Membership,
    now: datetime,
    claims: dict[str, object],
    code: str,
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    with pytest.raises(AuthenticationError) as error:
        await authenticator.authenticate(_token(key, now, **claims))

    assert error.value.code == code


async def test_nbf_is_optional_but_exp_remains_required(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )
    claims = jwt.decode(_token(key, now), options={"verify_signature": False})
    claims.pop("nbf")
    without_nbf = jwt.encode(
        claims, key, algorithm="RS256", headers={"kid": "key-one", "typ": "JWT"}
    )

    principal = await authenticator.authenticate(without_nbf)

    assert principal.actor_id == membership.actor_id
    claims.pop("exp")
    without_exp = jwt.encode(
        claims, key, algorithm="RS256", headers={"kid": "key-one", "typ": "JWT"}
    )
    with pytest.raises(AuthenticationError) as missing_exp:
        await authenticator.authenticate(without_exp)
    assert missing_exp.value.code == "invalid_token"


@pytest.mark.parametrize("nbf", [None, True, "0", float("nan"), float("inf")])
async def test_present_nbf_must_be_a_finite_numeric_date(
    key: rsa.RSAPrivateKey,
    membership: Membership,
    now: datetime,
    nbf: object,
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )
    claims = jwt.decode(_token(key, now), options={"verify_signature": False})
    claims["nbf"] = nbf
    token = jwt.encode(
        claims, key, algorithm="RS256", headers={"kid": "key-one", "typ": "JWT"}
    )

    with pytest.raises(AuthenticationError) as failure:
        await authenticator.authenticate(token)

    assert failure.value.code == "invalid_token"


async def test_authenticator_rejects_algorithm_confusion_before_membership_lookup(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "external-subject",
            "exp": now + timedelta(minutes=5),
        },
        "not-an-rsa-key-that-is-at-least-thirty-two-bytes",
        algorithm="HS256",
        headers={"kid": "key-one"},
    )
    memberships = FakeMemberships((membership,))
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}), memberships, FakeAgents(), now
    )

    with pytest.raises(AuthenticationError) as error:
        await authenticator.authenticate(token)

    assert error.value.code == "invalid_token_algorithm"
    assert memberships.calls == 0


async def test_unknown_kid_forces_exactly_one_refresh_then_rejects(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200, json={"keys": [_jwk(key, "old")]}, headers={"cache-control": "max-age=60"}
        )

    authenticator = _authenticator(
        httpx.MockTransport(handler), FakeMemberships((membership,)), FakeAgents(), now
    )
    with pytest.raises(AuthenticationError) as error:
        await authenticator.authenticate(_token(key, now, kid="unknown"))

    assert error.value.code == "invalid_token_key"
    assert calls == 1


async def test_expired_jwks_cache_fails_closed_when_refresh_is_unavailable(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    calls = 0
    current = now

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                200, json={"keys": [_jwk(key, "key-one")]}, headers={"cache-control": "max-age=1"}
            )
        raise httpx.ConnectError("unavailable", request=request)

    authenticator = OIDCAuthenticator(
        issuer=ISSUER,
        jwks_url=JWKS_URL,
        audience=AUDIENCE,
        worker_azp="nexus-worker",
        membership_repository=FakeMemberships((membership,)),
        agent_repository=FakeAgents(),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        clock=lambda: current,
    )
    await authenticator.authenticate(_token(key, now))
    current = now + timedelta(seconds=2)

    with pytest.raises(IdentityProviderUnavailable):
        await authenticator.authenticate(_token(key, current))


async def test_jwks_rejects_duplicate_and_non_signing_keys(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    duplicate = _jwk(key, "key-one")
    malformed = {**_jwk(key, "key-two"), "use": "enc"}
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one"), duplicate, malformed]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    with pytest.raises(IdentityProviderUnavailable):
        await authenticator.authenticate(_token(key, now))


async def test_jwks_accepts_valid_signing_key_alongside_keycloak_encryption_key(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    encryption_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encryption_jwk = _jwk(encryption_key, "keycloak-encryption-key")
    encryption_jwk.update({"use": "enc", "alg": "RSA-OAEP"})
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one"), encryption_jwk]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    principal = await authenticator.authenticate(_token(key, now))

    assert principal.actor_id == membership.actor_id


async def test_jwks_cache_single_flights_concurrent_authentication(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return httpx.Response(
            200, json={"keys": [_jwk(key, "key-one")]}, headers={"cache-control": "max-age=60"}
        )

    authenticator = _authenticator(
        httpx.MockTransport(handler), FakeMemberships((membership,)), FakeAgents(), now
    )
    await asyncio.gather(*[authenticator.authenticate(_token(key, now)) for _ in range(8)])

    assert calls == 1


async def test_unregistered_verified_principal_is_denied_without_token_claim_tenants(
    key: rsa.RSAPrivateKey, now: datetime
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}), FakeMemberships(()), FakeAgents(), now
    )

    with pytest.raises(PrincipalNotRegistered):
        await authenticator.authenticate(_token(key, now, tenants=[str(TENANT_ONE)]))


async def test_multiple_memberships_require_selected_uuid7_tenant(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    second = Membership(
        ACTOR_ID,
        TENANT_TWO,
        frozenset({"operator"}),
        frozenset({"signals.read"}),
        frozenset({"restricted"}),
    )
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership, second)),
        FakeAgents(),
        now,
    )
    principal = await authenticator.authenticate(_token(key, now, roles=["operator"]))

    with pytest.raises(TenantSelectionRequired):
        principal.select_tenant(None)
    with pytest.raises(TenantAccessDenied):
        principal.select_tenant(UUID("018f0000-0000-7000-8000-000000000009"))
    assert principal.select_tenant(TENANT_TWO).roles == frozenset({"operator"})


async def test_agent_requires_worker_azp_valid_uuid7_and_active_version(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership,)),
        FakeAgents(False),
        now,
    )
    token = _token(key, now, azp="nexus-worker", agent_id=str(AGENT_ID))

    with pytest.raises(AgentIdentityDenied):
        await authenticator.authenticate(token)


async def test_human_token_cannot_spoof_agent_semantics(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    principal = await authenticator.authenticate(_token(key, now, agent_id=str(AGENT_ID)))

    assert principal.kind == "human"
    assert principal.agent_id is None


async def test_human_nexus_web_azp_is_not_mistaken_for_a_workload(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    principal = await authenticator.authenticate(
        _token(key, now, azp="nexus-web", agent_id=str(AGENT_ID))
    )

    assert principal.kind == "human"
    assert principal.agent_id is None


async def test_active_worker_identity_accepts_worker_shaped_token(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    principal = await authenticator.authenticate(
        _token(key, now, azp="nexus-worker", agent_id=str(AGENT_ID))
    )

    assert principal.kind == "agent"
    assert principal.agent_id == AGENT_ID


async def test_multi_tenant_principal_exposes_no_union_authority(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    first = Membership(
        ACTOR_ID,
        TENANT_ONE,
        frozenset({"viewer"}),
        frozenset({"ontology.read"}),
        frozenset({"internal"}),
    )
    second = Membership(
        ACTOR_ID,
        TENANT_TWO,
        frozenset({"operator"}),
        frozenset({"signals.read"}),
        frozenset({"restricted"}),
    )
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((first, second)),
        FakeAgents(),
        now,
    )

    principal = await authenticator.authenticate(
        _token(key, now, roles=["viewer", "operator"], scope="ontology.read signals.read")
    )

    assert principal.roles == frozenset()
    assert principal.scopes == frozenset()
    assert principal.sensitivity_clearances == frozenset()
    assert principal.for_tenant(TENANT_ONE).roles == frozenset({"viewer"})
    assert principal.for_tenant(TENANT_TWO).roles == frozenset({"operator"})


async def test_no_store_does_not_share_jwks_between_concurrent_lookups(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return httpx.Response(
            200, json={"keys": [_jwk(key, "key-one")]}, headers={"cache-control": "no-store"}
        )

    authenticator = _authenticator(
        httpx.MockTransport(handler), FakeMemberships((membership,)), FakeAgents(), now
    )
    await asyncio.gather(
        authenticator.authenticate(_token(key, now)),
        authenticator.authenticate(_token(key, now)),
    )

    assert calls == 2


@pytest.mark.parametrize("cache_control", ['max-age="60"', "max-age=999999999999999999999"])
async def test_cache_control_is_bounded_and_never_raises_overflow(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime, cache_control: str
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}, {"cache-control": cache_control}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    principal = await authenticator.authenticate(_token(key, now))

    assert principal.actor_id == ACTOR_ID


@pytest.mark.parametrize(
    "mutate",
    [
        lambda jwk: jwk.update({"key_ops": ["verify", "sign"]}),
        lambda jwk: jwk.update({"n": "!!!!"}),
        lambda jwk: jwk.update({"e": "AA"}),
    ],
)
async def test_jwks_rejects_noncanonical_or_nonverification_rsa_material(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime, mutate: object
) -> None:
    jwk = _jwk(key, "key-one")
    mutate(jwk)  # type: ignore[operator]  # Literal hostile transport mutation.
    authenticator = _authenticator(
        _jwks_transport({"keys": [jwk]}), FakeMemberships((membership,)), FakeAgents(), now
    )

    with pytest.raises(IdentityProviderUnavailable):
        await authenticator.authenticate(_token(key, now))


async def test_max_age_zero_never_reuses_a_jwks_snapshot(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200, json={"keys": [_jwk(key, "key-one")]}, headers={"cache-control": "max-age=0"}
        )

    authenticator = _authenticator(
        httpx.MockTransport(handler), FakeMemberships((membership,)), FakeAgents(), now
    )
    await authenticator.authenticate(_token(key, now))
    await authenticator.authenticate(_token(key, now))

    assert calls == 2


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"location": "https://evil.example.test/jwks"}),
        httpx.Response(200, content=b"not-json"),
        httpx.Response(200, content=b"{}"),
        httpx.Response(200, headers={"content-length": "999999"}, content=b"{}"),
    ],
)
async def test_hostile_jwks_responses_fail_closed(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime, response: httpx.Response
) -> None:
    authenticator = _authenticator(
        httpx.MockTransport(lambda _request: response),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    with pytest.raises(IdentityProviderUnavailable):
        await authenticator.authenticate(_token(key, now))


async def test_jwks_timeout_maps_to_unavailable_and_cancellation_propagates(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    timeout = _authenticator(
        httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=request))
        ),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )
    with pytest.raises(IdentityProviderUnavailable):
        await timeout.authenticate(_token(key, now))

    async def cancelled(_request: httpx.Request) -> httpx.Response:
        raise asyncio.CancelledError()

    cancellation = _authenticator(
        httpx.MockTransport(cancelled), FakeMemberships((membership,)), FakeAgents(), now
    )
    with pytest.raises(asyncio.CancelledError):
        await cancellation.authenticate(_token(key, now))


async def test_bad_signature_and_missing_or_invalid_worker_agent_id_are_denied(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [_jwk(key, "key-one")]}),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )
    signed = _token(key, now)
    forged = signed.rsplit(".", 1)[0] + ".forged"
    with pytest.raises(AuthenticationError) as signature:
        await authenticator.authenticate(forged)
    assert signature.value.code == "invalid_token_signature"
    for claim in (None, "not-a-uuid"):
        with pytest.raises(AgentIdentityDenied):
            await authenticator.authenticate(_token(key, now, azp="nexus-worker", agent_id=claim))


async def test_overlapping_key_rotation_and_live_snapshot_unknown_kid_refresh_once(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    newer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        keys = [_jwk(key, "old")] if calls == 1 else [_jwk(key, "old"), _jwk(newer, "new")]
        return httpx.Response(200, json={"keys": keys}, headers={"cache-control": "max-age=60"})

    authenticator = _authenticator(
        httpx.MockTransport(handler), FakeMemberships((membership,)), FakeAgents(), now
    )
    await authenticator.authenticate(_token(key, now, kid="old"))
    await authenticator.authenticate(_token(newer, now, kid="new"))
    await authenticator.authenticate(_token(key, now, kid="old"))

    assert calls == 2


async def test_streamed_oversize_jwks_is_rejected_before_json_decode(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    response = httpx.Response(200, content=b"x" * (256 * 1024 + 1))
    authenticator = _authenticator(
        httpx.MockTransport(lambda _request: response),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )

    with pytest.raises(IdentityProviderUnavailable):
        await authenticator.authenticate(_token(key, now))


@pytest.mark.parametrize(
    ("cache_control", "advance", "expected_calls"),
    [
        (None, timedelta(minutes=4), 1),
        (None, timedelta(minutes=6), 2),
        ("max-age=999999", timedelta(minutes=59), 1),
        ("max-age=999999", timedelta(hours=2), 2),
    ],
)
async def test_default_and_capped_jwks_ttl_control_refresh(
    key: rsa.RSAPrivateKey,
    membership: Membership,
    now: datetime,
    cache_control: str | None,
    advance: timedelta,
    expected_calls: int,
) -> None:
    current = now
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        headers = {} if cache_control is None else {"cache-control": cache_control}
        return httpx.Response(200, json={"keys": [_jwk(key, "key-one")]}, headers=headers)

    authenticator = OIDCAuthenticator(
        issuer=ISSUER,
        jwks_url=JWKS_URL,
        audience=AUDIENCE,
        worker_azp="nexus-worker",
        membership_repository=FakeMemberships((membership,)),
        agent_repository=FakeAgents(),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        clock=lambda: current,
    )
    await authenticator.authenticate(_token(key, now))
    current = now + advance
    await authenticator.authenticate(_token(key, current))
    assert calls == expected_calls


async def test_concurrent_unknown_kid_on_live_snapshot_refreshes_once(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime
) -> None:
    newer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        keys = [_jwk(key, "old")] if calls == 1 else [_jwk(key, "old"), _jwk(newer, "new")]
        return httpx.Response(200, json={"keys": keys}, headers={"cache-control": "max-age=60"})

    authenticator = _authenticator(
        httpx.MockTransport(handler), FakeMemberships((membership,)), FakeAgents(), now
    )
    await authenticator.authenticate(_token(key, now, kid="old"))
    await asyncio.gather(
        *[authenticator.authenticate(_token(newer, now, kid="new")) for _ in range(4)]
    )
    assert calls == 2


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, headers={"content-length": "not-a-number"}, content=b"{}"),
        httpx.Response(
            200, request=httpx.Request("GET", "https://other.example.test/jwks"), json={"keys": []}
        ),
    ],
)
async def test_invalid_content_length_and_final_origin_are_rejected(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime, response: httpx.Response
) -> None:
    authenticator = _authenticator(
        httpx.MockTransport(lambda _request: response),
        FakeMemberships((membership,)),
        FakeAgents(),
        now,
    )
    with pytest.raises(IdentityProviderUnavailable):
        await authenticator.authenticate(_token(key, now))


@pytest.mark.parametrize("header_alg", ["none", "HS256"])
async def test_none_and_hmac_headers_fail_before_jwks(
    header_alg: str, membership: Membership, now: datetime
) -> None:
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "external-subject",
            "exp": now + timedelta(minutes=5),
            "nbf": now,
        },
        None if header_alg == "none" else "x" * 32,
        algorithm=None if header_alg == "none" else header_alg,
        headers={"kid": "key-one", "alg": header_alg},
    )
    authenticator = _authenticator(
        _jwks_transport({"keys": []}), FakeMemberships((membership,)), FakeAgents(), now
    )
    with pytest.raises(AuthenticationError) as failure:
        await authenticator.authenticate(token)
    assert failure.value.code == "invalid_token_algorithm"


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "EC", "kid": "x", "use": "sig", "alg": "RS256"},
        {"kty": "RSA", "kid": "x", "use": "sig", "alg": "RS512", "n": "AQ", "e": "Aw"},
    ],
)
async def test_non_rsa_and_wrong_algorithm_jwks_are_rejected(
    key: rsa.RSAPrivateKey, membership: Membership, now: datetime, jwk: dict[str, str]
) -> None:
    authenticator = _authenticator(
        _jwks_transport({"keys": [jwk]}), FakeMemberships((membership,)), FakeAgents(), now
    )
    with pytest.raises(IdentityProviderUnavailable):
        await authenticator.authenticate(_token(key, now))
