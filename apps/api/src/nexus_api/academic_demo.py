"""Loopback-only academic application using the shared Nexus analysis engine.

Demonstration identities are intentionally public role selectors. This app is
separate from the OIDC/OPA deployment and must never bind to an external host.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from nexus_contracts.platform import RequestContext
from nexus_security.ids import new_id
from pydantic import UUID7

from nexus_api.prototype.models import (
    CreatePrototypeRunRequest,
    PrototypeAdvisory,
    PrototypeAgentFinding,
    PrototypeApproval,
    PrototypeApprovalCommand,
    PrototypeAuditRef,
    PrototypeExecution,
    PrototypeExecutionCommand,
    PrototypeGraph,
    PrototypePlan,
    PrototypeRunView,
    PrototypeSignal,
    PrototypeTrace,
    PrototypeTraceEvent,
)
from nexus_api.prototype.orchestrator import (
    AdvisoryFacade,
    DeterministicAdvisoryFacade,
    PrototypeOrchestrator,
    build_prototype_plan,
    calculate_verification,
)
from nexus_api.prototype.risk import incident_risk_signal, supply_risk_signal
from nexus_api.prototype.seed import build_projection, scenario_catalog

_TENANT = "018f0000-0000-7000-8000-000000000a01"
_IDENTITIES = (
    {
        "label": "Analyst / proposer",
        "role": "proposer",
        "token": "academic-proposer",
        "actor_id": "018f0000-0000-7000-8000-000000000a02",
    },
    {
        "label": "Independent approver",
        "role": "approver",
        "token": "academic-approver",
        "actor_id": "018f0000-0000-7000-8000-000000000a03",
    },
    {
        "label": "Read-only viewer",
        "role": "viewer",
        "token": "academic-viewer",
        "actor_id": "018f0000-0000-7000-8000-000000000a04",
    },
)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _identity(authorization: Annotated[str | None, Header()] = None) -> dict[str, str]:
    for identity in _IDENTITIES:
        if authorization == "Bearer " + identity["token"]:
            return identity
    raise HTTPException(401, "Select a local demonstration identity")


Identity = Annotated[dict[str, str], Depends(_identity)]


def _require_role(identity: dict[str, str], role: str) -> None:
    if identity["role"] != role:
        raise HTTPException(403, "This demonstration role cannot perform the operation")


def _key(value: Annotated[str | None, Header(alias="Idempotency-Key")] = None) -> str:
    if not value or len(value.encode()) > 128 or not value.isprintable():
        raise HTTPException(400, "A bounded Idempotency-Key is required")
    return value


CommandKey = Annotated[str, Depends(_key)]


class DemoRepository:
    """Transactionally persist snapshots, hash-linked events and command receipts."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.transaction() as connection:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS runs "
                "(run_id TEXT PRIMARY KEY, state TEXT NOT NULL, state_hash TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS events "
                "(run_id TEXT NOT NULL, sequence INTEGER NOT NULL, body TEXT NOT NULL, "
                "hash TEXT NOT NULL, PRIMARY KEY(run_id, sequence));"
                "CREATE TABLE IF NOT EXISTS commands "
                "(actor TEXT NOT NULL, stage TEXT NOT NULL, key TEXT NOT NULL, "
                "fingerprint TEXT NOT NULL, run_id TEXT NOT NULL, PRIMARY KEY(actor,stage,key));"
            )

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def events(self, connection: sqlite3.Connection, run_id: str) -> list[PrototypeTraceEvent]:
        result = []
        previous = "0" * 64
        for index, row in enumerate(
            connection.execute(
                "SELECT sequence, body, hash FROM events WHERE run_id=? ORDER BY sequence",
                (run_id,),
            ),
            start=1,
        ):
            body = json.loads(row["body"])
            expected = _digest({"run_id": run_id, "previous": previous, "event": body})
            if row["sequence"] != index or body["sequence"] != index or row["hash"] != expected:
                raise HTTPException(503, "Stored audit integrity check failed")
            result.append(PrototypeTraceEvent.model_validate({**body, "hash": expected}))
            previous = expected
        return result

    def load(self, connection: sqlite3.Connection, run_id: str) -> PrototypeRunView:
        try:
            return self._load(connection, run_id)
        except (ValueError, KeyError, TypeError) as error:
            raise HTTPException(503, "Stored run integrity check failed") from error

    def _load(self, connection: sqlite3.Connection, run_id: str) -> PrototypeRunView:
        row = connection.execute(
            "SELECT state,state_hash FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Run not found")
        state = json.loads(row["state"])
        if _digest(state) != row["state_hash"]:
            raise HTTPException(503, "Stored run integrity check failed")
        events = self.events(connection, run_id)
        run = PrototypeRunView.model_validate(state)
        refs = tuple(
            PrototypeAuditRef(
                event_id=e.event_id, sequence=e.sequence, event_type=e.event_type, hash=e.hash
            )
            for e in events
        )
        if not events or run.audit_events != refs:
            raise HTTPException(503, "Run and audit history do not match")
        if run != self.reduce(run_id, events):
            raise HTTPException(503, "Stored run does not follow from its audit history")
        return run

    def reduce(self, run_id: str, events: list[PrototypeTraceEvent]) -> PrototypeRunView:
        """Derive state from events, never from an editable snapshot's claimed status."""
        prefix = [
            "prototype.run.created",
            "prototype.signal.published",
            "prototype.signal.published",
            "prototype.agent.completed",
            "prototype.agent.completed",
            "prototype.agent.completed",
            "prototype.briefing.generated",
            "prototype.plan.prepared",
        ]
        if [event.event_type for event in events[:8]] != prefix:
            raise HTTPException(503, "Invalid analysis event sequence")
        created = events[0]
        scenario_id = str(created.public_payload["scenario_id"])
        graph = build_projection(scenario_id)
        if (
            created.public_payload["seed_digest"] != graph.seed_digest
            or str(created.actor_id) != _IDENTITIES[0]["actor_id"]
        ):
            raise HTTPException(503, "Invalid scenario provenance")
        signals = tuple(PrototypeSignal.model_validate(e.public_payload) for e in events[1:3])
        if signals != (supply_risk_signal(graph), incident_risk_signal(graph)):
            raise HTTPException(503, "Stored risk signals differ from scenario evidence")
        plan = PrototypePlan.model_validate(events[7].public_payload)
        if plan != build_prototype_plan(graph):
            raise HTTPException(503, "Stored plan differs from immutable scenario inputs")
        run = PrototypeRunView.model_validate(
            {
                "run_id": run_id,
                "tenant_id": _TENANT,
                "scenario_id": scenario_id,
                "seed_digest": graph.seed_digest,
                "proposer_id": created.actor_id,
                "status": "awaiting_approval",
                "signals": signals,
                "findings": tuple(
                    PrototypeAgentFinding.model_validate(e.public_payload) for e in events[3:6]
                ),
                "llm": PrototypeAdvisory.model_validate(events[6].public_payload),
                "plan": plan,
                "audit_events": (),
            }
        )
        if any(event.actor_id != created.actor_id for event in events[:8]):
            raise HTTPException(503, "Invalid analysis actor")
        if len(events) > 8:
            event = events[8]
            approval = PrototypeApproval.model_validate(event.public_payload)
            if (
                event.event_type != "prototype.approval.recorded"
                or str(event.actor_id) != _IDENTITIES[1]["actor_id"]
                or approval.approver_id != event.actor_id
                or approval.plan_hash != plan.plan_hash
            ):
                raise HTTPException(503, "Invalid approval event")
            run = run.model_copy(update={"approval": approval, "status": approval.status})
        if len(events) > 9:
            if len(events) != 11 or run.status != "approved":
                raise HTTPException(503, "Invalid execution sequence")
            executed, verified = events[9:11]
            receipt = (
                "sim-"
                + _digest(
                    {"run_id": run_id, "schema_version": "1.0.0", "plan_hash": plan.plan_hash}
                )[:32]
            )
            execution = PrototypeExecution(plan_hash=plan.plan_hash, receipt_id=receipt)
            verification = calculate_verification(plan, receipt)
            if (
                executed.event_type != "prototype.action.executed"
                or verified.event_type != "prototype.verification.completed"
                or executed.actor_id != created.actor_id
                or verified.actor_id != created.actor_id
                or executed.public_payload != execution.model_dump(mode="json")
                or verified.public_payload != verification.model_dump(mode="json")
            ):
                raise HTTPException(503, "Invalid simulation evidence")
            run = run.model_copy(
                update={"execution": execution, "verification": verification, "status": "verified"}
            )
        return run.model_copy(
            update={
                "audit_events": tuple(
                    PrototypeAuditRef(
                        event_id=e.event_id,
                        sequence=e.sequence,
                        event_type=e.event_type,
                        hash=e.hash,
                    )
                    for e in events
                )
            }
        )

    def save(self, connection: sqlite3.Connection, run: PrototypeRunView) -> None:
        value = run.model_dump(mode="json")
        connection.execute(
            "INSERT INTO runs VALUES(?,?,?) ON CONFLICT(run_id) DO UPDATE SET "
            "state=excluded.state,state_hash=excluded.state_hash",
            (str(run.run_id), _json(value), _digest(value)),
        )

    def append(
        self,
        connection: sqlite3.Connection,
        run: PrototypeRunView,
        identity: dict[str, str],
        event_type: str,
        payload: dict[str, Any],
    ) -> PrototypeRunView:
        previous = run.audit_events[-1].hash if run.audit_events else "0" * 64
        body = {
            "event_id": str(new_id()),
            "sequence": len(run.audit_events) + 1,
            "occurred_at": datetime.now(UTC).isoformat(),
            "actor_id": identity["actor_id"],
            "event_type": event_type,
            "public_payload": payload,
        }
        digest = _digest({"run_id": str(run.run_id), "previous": previous, "event": body})
        event = PrototypeTraceEvent.model_validate({**body, "hash": digest})
        connection.execute(
            "INSERT INTO events VALUES(?,?,?,?)",
            (str(run.run_id), event.sequence, _json(body), digest),
        )
        ref = PrototypeAuditRef(
            event_id=event.event_id, sequence=event.sequence, event_type=event_type, hash=digest
        )
        return run.model_copy(update={"audit_events": (*run.audit_events, ref)})

    def replay(
        self,
        connection: sqlite3.Connection,
        identity: dict[str, str],
        stage: str,
        key: str,
        payload: dict[str, Any],
    ) -> PrototypeRunView | None:
        row = connection.execute(
            "SELECT fingerprint,run_id FROM commands WHERE actor=? AND stage=? AND key=?",
            (identity["actor_id"], stage, key),
        ).fetchone()
        if row is None:
            return None
        if row["fingerprint"] != _digest(payload):
            raise HTTPException(409, "Idempotency key already belongs to a different command")
        return self.load(connection, row["run_id"])

    def record(
        self,
        connection: sqlite3.Connection,
        identity: dict[str, str],
        stage: str,
        key: str,
        payload: dict[str, Any],
        run: PrototypeRunView,
    ) -> None:
        self.save(connection, run)
        connection.execute(
            "INSERT INTO commands VALUES(?,?,?,?,?)",
            (identity["actor_id"], stage, key, _digest(payload), str(run.run_id)),
        )


def create_demo_app(database_path: Path, advisory: AdvisoryFacade | None = None) -> FastAPI:
    repository = DemoRepository(database_path)
    orchestrator = PrototypeOrchestrator(advisory or DeterministicAdvisoryFacade())
    app = FastAPI(
        title="Nexus academic local demonstration", docs_url=None, redoc_url=None, openapi_url=None
    )

    @app.middleware("http")
    async def loopback_boundary(request: Request, call_next: Any) -> Any:
        hostname = request.url.hostname
        origin = request.headers.get("origin")
        local_hosts = {"127.0.0.1", "localhost", "::1"}
        origin_parts = urlsplit(origin) if origin else None
        if (
            hostname not in local_hosts
            or request.client is None
            or request.client.host not in local_hosts
            or (
                origin_parts is not None
                and (
                    origin_parts.scheme != request.url.scheme
                    or origin_parts.netloc != request.url.netloc
                )
            )
        ):
            return JSONResponse({"detail": "The academic demo is available only on loopback"}, 403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/")
    @app.get("/prototype")
    async def dashboard() -> FileResponse:
        return FileResponse(Path(__file__).parent / "static" / "prototype" / "index.html")

    @app.get("/health/live")
    async def health() -> dict[str, str]:
        return {"status": "ok", "mode": "academic_local"}

    @app.get("/api/v1/prototype/demo-session")
    async def demo_session() -> dict[str, Any]:
        return {
            "mode": "academic_local",
            "identities": [
                {key: item[key] for key in ("label", "role", "token")} for item in _IDENTITIES
            ],
        }

    @app.get("/api/v1/prototype/scenarios")
    async def scenarios(identity: Identity) -> dict[str, Any]:
        return {"scenarios": scenario_catalog()}

    @app.post("/api/v1/prototype/runs", status_code=201)
    async def create_run(
        command: CreatePrototypeRunRequest, identity: Identity, key: CommandKey
    ) -> PrototypeRunView:
        _require_role(identity, "proposer")
        payload = command.model_dump(mode="json")
        with repository.transaction() as connection:
            replay = repository.replay(connection, identity, "create", key, payload)
            if replay is not None:
                return replay
        graph = build_projection(command.scenario_id)
        context = RequestContext.model_validate(
            {
                "tenant_id": _TENANT,
                "actor_id": identity["actor_id"],
                "correlation_id": new_id(),
                "roles": [identity["role"]],
                "scopes": ["action.read", "action.propose", "action.execute"],
                "sensitivity_clearances": ["internal"],
            }
        )
        result = await orchestrator.run(graph, idempotency_key=key, context=context)
        run = PrototypeRunView(
            run_id=new_id(),
            tenant_id=context.tenant_id,
            scenario_id=command.scenario_id,
            seed_digest=graph.seed_digest,
            status="awaiting_approval",
            proposer_id=context.actor_id,
            signals=result.signals,
            findings=result.findings,
            llm=result.advisory,
            plan=result.plan,
            audit_events=(),
        )
        with repository.transaction() as connection:
            replay = repository.replay(connection, identity, "create", key, payload)
            if replay is not None:
                return replay
            entries = [
                (
                    "prototype.run.created",
                    {"scenario_id": command.scenario_id, "seed_digest": graph.seed_digest},
                ),
                *(
                    ("prototype.signal.published", item.model_dump(mode="json"))
                    for item in result.signals
                ),
                *(
                    ("prototype.agent.completed", item.model_dump(mode="json"))
                    for item in result.findings
                ),
                ("prototype.briefing.generated", result.advisory.model_dump(mode="json")),
                ("prototype.plan.prepared", result.plan.model_dump(mode="json")),
            ]
            for event_type, value in entries:
                run = repository.append(connection, run, identity, event_type, value)
            repository.record(connection, identity, "create", key, payload, run)
        return run

    @app.get("/api/v1/prototype/runs/{run_id}")
    async def get_run(run_id: UUID7, identity: Identity) -> PrototypeRunView:
        with repository.transaction() as connection:
            return repository.load(connection, str(run_id))

    @app.get("/api/v1/prototype/runs/{run_id}/graph")
    async def graph(run_id: UUID7, identity: Identity) -> PrototypeGraph:
        with repository.transaction() as connection:
            run = repository.load(connection, str(run_id))
        return build_projection(run.scenario_id)

    @app.get("/api/v1/prototype/runs/{run_id}/trace")
    async def trace(run_id: UUID7, identity: Identity) -> PrototypeTrace:
        with repository.transaction() as connection:
            repository.load(connection, str(run_id))
            return PrototypeTrace(
                run_id=run_id, events=tuple(repository.events(connection, str(run_id)))
            )

    def precondition(run: PrototypeRunView, digest: str, if_match: str | None) -> None:
        if if_match != f'"{run.plan.plan_hash}"' or digest != run.plan.plan_hash:
            raise HTTPException(412, "Approval and execution require the exact current plan hash")

    @app.post("/api/v1/prototype/runs/{run_id}/approval")
    async def approve(
        run_id: UUID7,
        command: PrototypeApprovalCommand,
        identity: Identity,
        key: CommandKey,
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ) -> PrototypeRunView:
        _require_role(identity, "approver")
        payload = {"run_id": str(run_id), **command.model_dump(mode="json")}
        with repository.transaction() as connection:
            run = repository.load(connection, str(run_id))
            precondition(run, command.plan_hash, if_match)
            replay = repository.replay(connection, identity, "approval", key, payload)
            if replay is not None:
                return replay
            if str(run.proposer_id) == identity["actor_id"]:
                raise HTTPException(403, "A different identity must approve")
            if run.status != "awaiting_approval":
                raise HTTPException(409, "This run already has a terminal approval decision")
            approval = PrototypeApproval.model_validate(
                {
                    "plan_hash": command.plan_hash,
                    "approver_id": identity["actor_id"],
                    "status": "approved" if command.decision == "approve" else "rejected",
                    "reason_sha256": hashlib.sha256(command.reason.encode()).hexdigest()
                    if command.reason
                    else None,
                }
            )
            run = run.model_copy(update={"approval": approval, "status": approval.status})
            run = repository.append(
                connection,
                run,
                identity,
                "prototype.approval.recorded",
                approval.model_dump(mode="json"),
            )
            repository.record(connection, identity, "approval", key, payload, run)
            return run

    @app.post("/api/v1/prototype/runs/{run_id}/execute")
    async def execute(
        run_id: UUID7,
        command: PrototypeExecutionCommand,
        identity: Identity,
        key: CommandKey,
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ) -> PrototypeRunView:
        _require_role(identity, "proposer")
        payload = {"run_id": str(run_id), **command.model_dump(mode="json")}
        with repository.transaction() as connection:
            run = repository.load(connection, str(run_id))
            precondition(run, command.plan_hash, if_match)
            replay = repository.replay(connection, identity, "execute", key, payload)
            if replay is not None:
                return replay
            if (
                run.status != "approved"
                or run.approval is None
                or run.approval.status != "approved"
                or str(run.proposer_id) != identity["actor_id"]
            ):
                raise HTTPException(409, "An approved unconsumed plan is required")
            receipt = "sim-" + _digest(payload)[:32]
            execution = PrototypeExecution(plan_hash=command.plan_hash, receipt_id=receipt)
            verification = calculate_verification(run.plan, receipt)
            run = run.model_copy(
                update={"execution": execution, "verification": verification, "status": "verified"}
            )
            run = repository.append(
                connection,
                run,
                identity,
                "prototype.action.executed",
                execution.model_dump(mode="json"),
            )
            run = repository.append(
                connection,
                run,
                identity,
                "prototype.verification.completed",
                verification.model_dump(mode="json"),
            )
            repository.record(connection, identity, "execute", key, payload, run)
            return run

    return app
