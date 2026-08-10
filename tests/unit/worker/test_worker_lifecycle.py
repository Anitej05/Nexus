"""Task 2 worker lifecycle behavior."""

import asyncio

import pytest
from nexus_worker.main import run_worker


@pytest.mark.asyncio
async def test_worker_stays_alive_until_its_shutdown_signal() -> None:
    """Returning after contribution loading would cause Compose to restart-loop the worker."""
    shutdown = asyncio.Event()
    task = asyncio.create_task(run_worker(shutdown))
    await asyncio.sleep(0)

    assert not task.done()
    shutdown.set()
    await task
