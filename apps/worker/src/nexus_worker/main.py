"""Worker entry point that preserves the platform contribution boundary."""

import asyncio

from nexus_worker.contributions import CONTRIBUTIONS, WorkerContribution


def load_contributions() -> tuple[WorkerContribution, ...]:
    """Return registered contributions without performing worker I/O."""
    return CONTRIBUTIONS


async def run_worker(shutdown: asyncio.Event | None = None) -> None:
    """Keep the Task 2 worker service alive until Temporal registration arrives."""
    load_contributions()
    await (shutdown or asyncio.Event()).wait()


if __name__ == "__main__":
    asyncio.run(run_worker())
