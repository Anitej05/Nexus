"""Async database-engine helpers with tenant-context pool hygiene."""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


def create_runtime_engine(database_url: str) -> AsyncEngine:
    """Create an application engine that clears tenant settings at checkout."""
    engine = create_async_engine(database_url, pool_pre_ping=True)

    @event.listens_for(engine.sync_engine, "checkout")
    def reset_tenant_settings(dbapi_connection: Any, _record: object, _proxy: object) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("RESET nexus.tenant_id")
            cursor.execute("RESET nexus.actor_id")
        finally:
            cursor.close()

    return engine
