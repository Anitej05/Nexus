"""FastAPI dependency and exception boundary for authenticated request context."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from nexus_contracts.platform import Problem, RequestContext

from nexus_security.auth import (
    MAX_TOKEN_BYTES,
    AgentIdentityRepository,
    AuthenticationError,
    DenyAllAgentIdentityRepository,
    InvalidCorrelationID,
    OIDCAuthenticator,
    PostgresMembershipRepository,
    TenantAccessDenied,
)
from nexus_security.ids import new_id
from nexus_security.settings import OIDCSettings


def _correlation_id(value: str | None) -> UUID:
    if value is None:
        return new_id()
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise InvalidCorrelationID() from error
    if parsed.version != 7 or str(parsed) != value.lower():
        raise InvalidCorrelationID()
    return parsed


def build_authenticator(
    *,
    settings: OIDCSettings | None = None,
    agent_repository: AgentIdentityRepository | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> OIDCAuthenticator:
    """Build the production adapter; agent access stays closed until Task 10."""
    configured = settings or OIDCSettings.from_environment()
    database_url = os.environ.get("NEXUS_DATABASE_URL")
    if not database_url:
        raise RuntimeError("NEXUS_DATABASE_URL is required for membership resolution")
    return OIDCAuthenticator(
        issuer=configured.issuer,
        jwks_url=configured.jwks_url,
        audience=configured.audience,
        worker_azp=configured.worker_azp,
        membership_repository=PostgresMembershipRepository(database_url),
        agent_repository=agent_repository or DenyAllAgentIdentityRepository(),
        http_client=http_client or httpx.AsyncClient(timeout=httpx.Timeout(3.0)),
    )


async def get_authenticator(request: Request) -> OIDCAuthenticator:
    authenticator = getattr(request.app.state, "oidc_authenticator", None)
    if not isinstance(authenticator, OIDCAuthenticator):
        raise RuntimeError("OIDC authenticator was not initialized")
    return authenticator


@asynccontextmanager
async def auth_lifespan(app: FastAPI) -> AsyncIterator[None]:
    authenticator = build_authenticator()
    app.state.oidc_authenticator = authenticator
    try:
        yield
    finally:
        await authenticator.aclose()


async def _bearer_token(
    authorization: Annotated[str | None, Header()] = None,
    correlation_header: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
) -> str:
    def early_failure(code: str) -> AuthenticationError:
        error = AuthenticationError(code)
        try:
            error.correlation_id = _correlation_id(correlation_header)
        except InvalidCorrelationID:
            error.correlation_id = new_id()
        return error

    if authorization is None:
        raise early_failure("missing_token")
    prefix, separator, token = authorization.partition(" ")
    malformed = (
        prefix.casefold() != "bearer"
        or not separator
        or not token
        or token.strip() != token
        or " " in token
        or len(token.encode()) > MAX_TOKEN_BYTES
    )
    if malformed:
        raise early_failure("invalid_token")
    return token


async def _authenticated_correlation(
    _token: Annotated[str, Depends(_bearer_token)],
    correlation_header: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
) -> UUID:
    return _correlation_id(correlation_header)


async def require_context(
    request: Request,
    token: Annotated[str, Depends(_bearer_token)],
    correlation_id: Annotated[UUID, Depends(_authenticated_correlation)],
    authenticator: Annotated[OIDCAuthenticator, Depends(get_authenticator)],
    tenant_header: Annotated[str | None, Header(alias="X-Nexus-Tenant")] = None,
) -> RequestContext:
    """Authenticate bearer input and build context only from verified database grants."""
    try:
        principal = await authenticator.authenticate(token)
        tenant_id: UUID | None = None
        if tenant_header is not None:
            tenant_id = UUID(tenant_header)
            if tenant_id.version != 7 or str(tenant_id) != tenant_header.lower():
                raise ValueError("not UUIDv7")
        access = principal.select_tenant(tenant_id)
    except AuthenticationError as authentication_failure:
        authentication_failure.correlation_id = correlation_id
        raise
    except (TypeError, ValueError) as error:
        tenant_failure = TenantAccessDenied()
        tenant_failure.correlation_id = correlation_id
        raise tenant_failure from error
    return RequestContext(
        tenant_id=access.tenant_id,
        actor_id=principal.actor_id,
        correlation_id=correlation_id,
        roles=access.roles,
        scopes=access.scopes,
        sensitivity_clearances=access.sensitivity_clearances,
        agent_id=principal.agent_id,
    )


def install_auth_exception_handlers(app: FastAPI) -> None:
    """Install the canonical RFC 9457 projection without leaking security inputs."""

    @app.exception_handler(AuthenticationError)
    async def authentication_problem(_request: Request, error: AuthenticationError) -> JSONResponse:
        correlation_id = error.correlation_id or new_id()
        problem = Problem(
            type=f"https://nexus.local/problems/{error.code.replace('_', '-')}",
            title=error.title,
            status=error.status,
            detail=None,
            instance=None,
            code=error.code,
            correlation_id=correlation_id,
        )
        headers = {"WWW-Authenticate": "Bearer"} if error.status == 401 else {}
        return JSONResponse(
            status_code=error.status,
            content=problem.model_dump(mode="json", exclude={"schema_version"}),
            headers=headers,
            media_type="application/problem+json",
        )
