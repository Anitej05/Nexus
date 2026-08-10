"""Typed worker contribution registry owned by platform extensions."""

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class WorkerContribution:
    task_queue: str
    workflows: tuple[type[object], ...]
    activities: tuple[Callable[..., object], ...]


CONTRIBUTIONS: tuple[WorkerContribution, ...] = ()
