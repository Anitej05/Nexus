"""Application entry point that preserves the platform contribution boundary."""

from fastapi import FastAPI
from nexus_security.dependencies import auth_lifespan, install_auth_exception_handlers

from nexus_api.contributions import ROUTERS

app = FastAPI(
    title="NEXUS API",
    version="0.1.0",
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
    lifespan=auth_lifespan,
)

install_auth_exception_handlers(app)


@app.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


for router in ROUTERS:
    app.include_router(router)
