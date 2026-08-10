"""Fail-closed OIDC bearer authentication and tenant membership resolution."""

from __future__ import annotations

import asyncio
import base64
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import jwt
from jwt import InvalidAudienceError, InvalidIssuerError, InvalidSignatureError, PyJWK
from jwt.exceptions import DecodeError, InvalidTokenError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

MAX_TOKEN_BYTES = 16 * 1024
MAX_HEADER_BYTES = 1024
MAX_JWKS_BYTES = 256 * 1024
DEFAULT_JWKS_TTL = timedelta(minutes=5)
MAX_JWKS_TTL = timedelta(hours=1)
CLOCK_SKEW = timedelta(seconds=30)
_MAX_KID_LENGTH = 256
_MAX_SUBJECT_LENGTH = 1024
_MAX_CACHE_AGE = re.compile(
    r'(?:^|,)\s*max-age\s*=\s*(?:"(?P<quoted>\d{1,10})"|(?P<plain>\d{1,10}))(?:\s*,|$)',
    re.IGNORECASE,
)
_NO_STORE = re.compile(r"(?:^|,)\s*no-store\s*(?:,|$)", re.IGNORECASE)
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")


class AuthenticationError(Exception):
    """A safe, typed client authentication failure."""

    status = 401
    title = "Authentication failed"

    def __init__(self, code: str = "invalid_token") -> None:
        self.code = code
        self.correlation_id: UUID | None = None
        super().__init__(code)


class IdentityProviderUnavailable(AuthenticationError):
    status = 503
    title = "Identity provider unavailable"

    def __init__(self) -> None:
        super().__init__("identity_provider_unavailable")


class InvalidCorrelationID(AuthenticationError):
    status = 400
    title = "Invalid correlation identifier"

    def __init__(self) -> None:
        super().__init__("invalid_correlation_id")


class PrincipalNotRegistered(AuthenticationError):
    status = 403
    title = "Principal not registered"

    def __init__(self) -> None:
        super().__init__("principal_not_registered")


class TenantSelectionRequired(AuthenticationError):
    status = 400
    title = "Tenant selection required"

    def __init__(self) -> None:
        super().__init__("tenant_selection_required")


class TenantAccessDenied(AuthenticationError):
    status = 403
    title = "Tenant access denied"

    def __init__(self) -> None:
        super().__init__("tenant_access_denied")


class AgentIdentityDenied(AuthenticationError):
    status = 403
    title = "Agent identity denied"

    def __init__(self) -> None:
        super().__init__("agent_identity_denied")


@dataclass(frozen=True, slots=True)
class Membership:
    """The only tenant authority acquired after a verified external identity lookup."""

    actor_id: UUID
    tenant_id: UUID
    roles: frozenset[str]
    scopes: frozenset[str]
    sensitivity_clearances: frozenset[str]


class MembershipRepository(Protocol):
    async def resolve(self, issuer: str, subject: str) -> tuple[Membership, ...]: ...


class AgentIdentityRepository(Protocol):
    async def has_active_version(self, agent_id: UUID) -> bool: ...


class DenyAllAgentIdentityRepository:
    """Task 10 owns the registry adapter; requests deny until it is installed."""

    async def has_active_version(self, agent_id: UUID) -> bool:
        return False


class PostgresMembershipRepository:
    """Runtime adapter for Task 3's narrowly granted security-definer resolver."""

    def __init__(self, database_url: str) -> None:
        self._engine: AsyncEngine = create_async_engine(database_url, pool_pre_ping=True)

    async def resolve(self, issuer: str, subject: str) -> tuple[Membership, ...]:
        async with self._engine.connect() as connection:
            rows = (
                await connection.execute(
                    text("select * from public.resolve_principal_memberships(:issuer, :subject)"),
                    {"issuer": issuer, "subject": subject},
                )
            ).mappings()
            return tuple(
                Membership(
                    actor_id=cast(UUID, row["actor_id"]),
                    tenant_id=cast(UUID, row["tenant_id"]),
                    roles=frozenset(cast(Sequence[str], row["roles"])),
                    scopes=frozenset(cast(Sequence[str], row["scopes"])),
                    sensitivity_clearances=frozenset(
                        cast(Sequence[str], row["sensitivity_clearances"])
                    ),
                )
                for row in rows
            )

    async def aclose(self) -> None:
        await self._engine.dispose()


@dataclass(frozen=True, slots=True)
class TenantAccess:
    tenant_id: UUID
    roles: frozenset[str]
    scopes: frozenset[str]
    sensitivity_clearances: frozenset[str]


@dataclass(frozen=True, slots=True)
class Principal:
    actor_id: UUID
    issuer: str
    audience: frozenset[str]
    roles: frozenset[str]
    scopes: frozenset[str]
    tenant_ids: frozenset[UUID]
    sensitivity_clearances: frozenset[str]
    kind: Literal["human", "agent"]
    agent_id: UUID | None = None
    _accesses: Mapping[UUID, TenantAccess] | None = None

    def select_tenant(self, tenant_id: UUID | None) -> TenantAccess:
        if tenant_id is None:
            if len(self.tenant_ids) != 1:
                raise TenantSelectionRequired()
            tenant_id = next(iter(self.tenant_ids))
        if tenant_id not in self.tenant_ids:
            raise TenantAccessDenied()
        access = (self._accesses or {}).get(tenant_id)
        if access is None:
            raise TenantAccessDenied()
        return access

    def for_tenant(self, tenant_id: UUID | str) -> TenantAccess:
        """Select exactly an assigned tenant; token tenant claims are never considered."""
        try:
            parsed = _uuid7(tenant_id)
        except (TypeError, ValueError) as error:
            raise TenantAccessDenied() from error
        return self.select_tenant(parsed)


@dataclass(frozen=True, slots=True)
class _JWKSSnapshot:
    keys: Mapping[str, PyJWK]
    expires_at: datetime
    generation: int


def _uuid7(value: UUID | str) -> UUID:
    parsed = value if isinstance(value, UUID) else UUID(value)
    if parsed.version != 7 or str(parsed) != str(value).lower():
        raise ValueError("must be a canonical UUIDv7")
    return parsed


def _audience_values(value: object) -> frozenset[str]:
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return frozenset(value)
    return frozenset()


def _token_roles(claims: Mapping[str, Any]) -> frozenset[str]:
    realm_access = claims.get("realm_access")
    roles = realm_access.get("roles") if isinstance(realm_access, Mapping) else None
    if not isinstance(roles, list):
        return frozenset()
    return frozenset(role for role in roles if isinstance(role, str))


def _token_scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    scope = claims.get("scope", "")
    return frozenset(scope.split()) if isinstance(scope, str) else frozenset()


def _cache_ttl(cache_control: str | None) -> timedelta:
    if cache_control and _NO_STORE.search(cache_control):
        return timedelta(0)
    match = _MAX_CACHE_AGE.search(cache_control or "")
    if match is None:
        return DEFAULT_JWKS_TTL
    seconds = int(match.group("quoted") or match.group("plain"))
    return min(timedelta(seconds=seconds), MAX_JWKS_TTL)


class OIDCAuthenticator:
    """Authenticate RS256 access tokens without granting raw token authority."""

    def __init__(
        self,
        *,
        issuer: str,
        jwks_url: str,
        audience: str,
        worker_azp: str,
        membership_repository: MembershipRepository,
        agent_repository: AgentIdentityRepository,
        http_client: httpx.AsyncClient,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        issuer_parts = urlsplit(issuer)
        jwks_parts = urlsplit(jwks_url)
        valid_issuer = issuer_parts.scheme and issuer_parts.netloc
        valid_jwks = jwks_parts.scheme and jwks_parts.netloc
        if not (valid_issuer and valid_jwks):
            raise ValueError("issuer and JWKS URL must be absolute")
        self.issuer = issuer
        self.jwks_url = jwks_url
        self.audience = audience
        self.worker_azp = worker_azp
        self._memberships = membership_repository
        self._agents = agent_repository
        self._http = http_client
        self._clock = clock
        self._snapshot: _JWKSSnapshot | None = None
        self._generation = 0
        self._refresh_lock = asyncio.Lock()

    async def authenticate(self, token: str) -> Principal:
        header = self._header(token)
        key = await self._key_for(cast(str, header["kid"]))
        claims = self._decode(token, key)
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > _MAX_SUBJECT_LENGTH:
            raise AuthenticationError("invalid_token_subject")
        memberships = await self._memberships.resolve(self.issuer, subject)
        if not memberships:
            raise PrincipalNotRegistered()
        actor_id = memberships[0].actor_id
        if actor_id.version != 7 or any(member.actor_id != actor_id for member in memberships):
            raise PrincipalNotRegistered()
        roles, scopes = _token_roles(claims), _token_scopes(claims)
        accesses = {
            member.tenant_id: TenantAccess(
                tenant_id=member.tenant_id,
                roles=roles & member.roles,
                scopes=scopes & member.scopes,
                sensitivity_clearances=member.sensitivity_clearances,
            )
            for member in memberships
            if member.tenant_id.version == 7
        }
        if not accesses:
            raise PrincipalNotRegistered()
        agent_id: UUID | None = None
        kind: Literal["human", "agent"] = "human"
        if claims.get("azp") == self.worker_azp:
            try:
                agent_id = _uuid7(cast(str, claims.get("agent_id")))
            except (TypeError, ValueError) as error:
                raise AgentIdentityDenied() from error
            if not await self._agents.has_active_version(agent_id):
                raise AgentIdentityDenied()
            kind = "agent"
        effective_accesses = tuple(accesses.values())
        top_level = effective_accesses[0] if len(effective_accesses) == 1 else None
        return Principal(
            actor_id=actor_id,
            issuer=self.issuer,
            audience=_audience_values(claims.get("aud")),
            roles=frozenset() if top_level is None else top_level.roles,
            scopes=frozenset() if top_level is None else top_level.scopes,
            tenant_ids=frozenset(accesses),
            sensitivity_clearances=(
                frozenset() if top_level is None else top_level.sensitivity_clearances
            ),
            kind=kind,
            agent_id=agent_id,
            _accesses=accesses,
        )

    def _header(self, token: str) -> Mapping[str, object]:
        if not isinstance(token, str) or not token or len(token.encode()) > MAX_TOKEN_BYTES:
            raise AuthenticationError("invalid_token")
        encoded_header = token.split(".", 1)[0]
        if len(encoded_header.encode()) > MAX_HEADER_BYTES:
            raise AuthenticationError("invalid_token")
        try:
            header = jwt.get_unverified_header(token)
        except DecodeError as error:
            raise AuthenticationError("invalid_token") from error
        if header.get("alg") != "RS256":
            raise AuthenticationError("invalid_token_algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > _MAX_KID_LENGTH:
            raise AuthenticationError("invalid_token_key")
        if header.get("typ", "JWT") != "JWT":
            raise AuthenticationError("invalid_token")
        return header

    def _decode(self, token: str, key: PyJWK) -> Mapping[str, Any]:
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "require": ["exp", "iss", "aud", "sub"],
                    "verify_exp": False,
                    "verify_nbf": False,
                },
            )
        except InvalidAudienceError as error:
            raise AuthenticationError("invalid_token_audience") from error
        except InvalidIssuerError as error:
            raise AuthenticationError("invalid_token_issuer") from error
        except InvalidSignatureError as error:
            raise AuthenticationError("invalid_token_signature") from error
        except InvalidTokenError as error:
            raise AuthenticationError("invalid_token") from error
        self._validate_times(claims)
        return claims

    def _validate_times(self, claims: Mapping[str, Any]) -> None:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("clock must return aware UTC time")
        try:
            expiry = datetime.fromtimestamp(float(claims["exp"]), UTC)
            not_before = None
            if "nbf" in claims:
                not_before_raw = claims["nbf"]
                if (
                    isinstance(not_before_raw, bool)
                    or not isinstance(not_before_raw, int | float)
                    or not math.isfinite(not_before_raw)
                ):
                    raise ValueError("nbf must be a finite NumericDate")
                not_before = datetime.fromtimestamp(not_before_raw, UTC)
        except (KeyError, TypeError, ValueError, OverflowError, OSError) as error:
            raise AuthenticationError("invalid_token") from error
        if expiry < now - CLOCK_SKEW:
            raise AuthenticationError("token_expired")
        if not_before is not None and not_before > now + CLOCK_SKEW:
            raise AuthenticationError("token_not_yet_valid")

    async def _key_for(self, kid: str) -> PyJWK:
        snapshot = self._snapshot
        now = self._clock()
        if snapshot is not None and snapshot.expires_at > now and kid in snapshot.keys:
            return snapshot.keys[kid]
        observed_generation = snapshot.generation if snapshot is not None else -1
        snapshot = await self._refresh(observed_generation)
        key = snapshot.keys.get(kid)
        if key is None:
            raise AuthenticationError("invalid_token_key")
        return key

    async def _refresh(self, observed_generation: int) -> _JWKSSnapshot:
        async with self._refresh_lock:
            current = self._snapshot
            if (
                current is not None
                and current.expires_at > self._clock()
                and current.generation > observed_generation
            ):
                return current
            try:
                async with self._http.stream(
                    "GET", self.jwks_url, follow_redirects=False
                ) as response:
                    content_length = response.headers.get("content-length")
                    if content_length is not None and (
                        not content_length.isdecimal() or int(content_length) > MAX_JWKS_BYTES
                    ):
                        raise IdentityProviderUnavailable()
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_JWKS_BYTES:
                            raise IdentityProviderUnavailable()
            except httpx.HTTPError as error:
                raise IdentityProviderUnavailable() from error
            if response.is_redirect or response.status_code != 200:
                raise IdentityProviderUnavailable()
            final = urlsplit(str(response.url))
            expected = urlsplit(self.jwks_url)
            if (final.scheme, final.netloc) != (expected.scheme, expected.netloc):
                raise IdentityProviderUnavailable()
            try:
                document = json.loads(body)
                keys = self._validated_keys(document)
                ttl = _cache_ttl(response.headers.get("cache-control"))
            except (TypeError, ValueError, json.JSONDecodeError, jwt.PyJWTError) as error:
                raise IdentityProviderUnavailable() from error
            self._generation += 1
            snapshot = _JWKSSnapshot(
                keys=keys,
                expires_at=self._clock() + ttl,
                generation=self._generation,
            )
            if ttl > timedelta(0):
                self._snapshot = snapshot
            else:
                self._snapshot = None
            return snapshot

    async def aclose(self) -> None:
        await self._http.aclose()
        close = getattr(self._memberships, "aclose", None)
        if close is not None:
            await close()

    @staticmethod
    def _validated_keys(document: object) -> Mapping[str, PyJWK]:
        if not isinstance(document, Mapping) or not isinstance(document.get("keys"), list):
            raise ValueError("JWKS must have a keys array")
        result: dict[str, PyJWK] = {}
        seen_kids: set[str] = set()
        for raw in cast(list[object], document["keys"]):
            if not isinstance(raw, Mapping):
                raise ValueError("malformed JWK")
            kid, key_type, use, algorithm = (
                raw.get("kid"),
                raw.get("kty"),
                raw.get("use"),
                raw.get("alg"),
            )
            operations = raw.get("key_ops")
            if (
                not isinstance(kid, str)
                or not kid
                or len(kid) > _MAX_KID_LENGTH
                or kid in seen_kids
            ):
                raise ValueError("untrusted JWK")
            seen_kids.add(kid)
            modulus, exponent = raw.get("n"), raw.get("e")
            if not isinstance(modulus, str) or not isinstance(exponent, str):
                raise ValueError("missing RSA parameters")
            modulus_value = _strict_b64url_int(modulus)
            exponent_value = _strict_b64url_int(exponent)
            unsafe_exponent = exponent_value < 3 or exponent_value % 2 == 0
            if modulus_value.bit_length() < 2048 or unsafe_exponent:
                raise ValueError("unsafe RSA parameters")
            if (
                key_type == "RSA"
                and use == "enc"
                and algorithm in {"RSA-OAEP", "RSA-OAEP-256"}
                and (operations is None or operations == ["encrypt"])
            ):
                continue
            if (
                key_type != "RSA"
                or use != "sig"
                or algorithm != "RS256"
                or (operations is not None and operations != ["verify"])
            ):
                raise ValueError("untrusted JWK")
            try:
                result[kid] = PyJWK.from_dict(dict(raw), algorithm="RS256")
            except (TypeError, ValueError, jwt.PyJWTError) as error:
                raise ValueError("invalid RSA parameters") from error
        if not result:
            raise ValueError("empty JWKS")
        return result


def _strict_b64url_int(value: str) -> int:
    if not _BASE64URL.fullmatch(value):
        raise ValueError("not canonical base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if not decoded or decoded[0] == 0:
        raise ValueError("zero or noncanonical integer")
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return int.from_bytes(decoded, "big")
