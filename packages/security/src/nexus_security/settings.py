"""Strict, small OIDC configuration surface."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OIDCSettings:
    """OIDC values with an issuer identity distinct from JWKS transport."""

    issuer: str
    jwks_url: str
    audience: str
    worker_azp: str

    @classmethod
    def from_environment(cls) -> OIDCSettings:
        return cls(
            issuer=os.environ.get("NEXUS_OIDC_ISSUER", "http://localhost:18080/realms/nexus"),
            jwks_url=os.environ.get(
                "NEXUS_OIDC_JWKS_URL",
                "http://keycloak:8080/realms/nexus/protocol/openid-connect/certs",
            ),
            audience=os.environ.get("NEXUS_OIDC_AUDIENCE", "nexus-api"),
            worker_azp=os.environ.get("NEXUS_OIDC_WORKER_AZP", "nexus-worker"),
        )
