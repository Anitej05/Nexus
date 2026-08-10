"""Route contribution registry owned by platform extensions."""

from fastapi import APIRouter

from nexus_api.contributions.health import router as health_router
from nexus_api.routes.audit import router as audit_router
from nexus_api.routes.prototype import router as prototype_router

ROUTERS: tuple[APIRouter, ...] = (health_router, audit_router, prototype_router)
