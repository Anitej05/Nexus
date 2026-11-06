"""Authenticated, versioned operational planning and explicit human writeback."""

import asyncio
import copy
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.responses import Response

from .auth import create_session, hash_password, lookup_session, revoke_session, verify_password
from .registry import (
    analyze_domain,
    apply_domain_changes,
    domain_catalog,
    sample_payload,
    validate_domain,
)
from .storage import OperationsStore, StorageIntegrityError

PREFIX = "/api/v1/operations"
COOKIE = "nexus_operations"


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def event(ws: dict[str, Any], actor: str, kind: str, details: dict[str, Any]) -> None:
    item = {
        "actor": actor,
        "kind": kind,
        "details": details,
        "at": datetime.now(UTC).isoformat(),
        "previous_hash": ws["events"][-1]["hash"] if ws["events"] else None,
    }
    item["hash"] = digest(item)
    ws["events"].append(item)


def verify_events(ws: dict[str, Any]) -> None:
    previous = None
    for item in ws["events"]:
        content = {key: value for key, value in item.items() if key != "hash"}
        if item.get("previous_hash") != previous or item.get("hash") != digest(content):
            raise StorageIntegrityError("Workspace audit chain mismatch")
        previous = item["hash"]


def decision_digest(decision: dict[str, Any]) -> str:
    content = {
        key: decision[key]
        for key in (
            "id",
            "workspace_id",
            "scenario_id",
            "author_id",
            "baseline_revision",
            "payload",
            "analysis",
        )
    }
    content["status"] = "proposed"
    return digest(content)


def attach_learning(analysis: dict[str, Any], metadata: dict[str, Any]) -> None:
    analysis["learning"] = copy.deepcopy(metadata)
    node_id = "@model/" + metadata["id"]
    analysis["graph"]["nodes"].append(
        {
            "id": node_id,
            "type": "trained_model",
            "label": "Trained duration model",
            "history_kind": metadata["history_kind"],
            "training_digest": metadata["training_digest"],
            "validation_mae": metadata["metrics"]["validation"]["duration"]["mae"],
            "held_out_test_mae": metadata["metrics"]["test"]["duration"]["mae"],
        }
    )


def create_operations_app(database_url: str) -> FastAPI:
    store = OperationsStore(database_url)
    dummy_password_hash = hash_password(secrets.token_urlsafe(32))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await store.initialize()
        yield
        await store.close()

    app = FastAPI(title="Nexus Operations", lifespan=lifespan)
    app.state.store = store

    @app.middleware("http")
    async def bounds(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in ("POST", "PUT"):
            total = 0
            chunks = []
            async for chunk in request.stream():
                total += len(chunk)
                if total > 1024 * 1024:
                    return JSONResponse({"detail": "Request exceeds 1 MiB"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.get("/health/live")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/operations")
    async def page() -> FileResponse:
        return FileResponse(Path(__file__).parents[1] / "static/operations/index.html")

    @app.api_route(PREFIX + "/{path:path}", methods=["GET", "POST", "PUT"])
    async def api(path: str, request: Request) -> Any:
        method = request.method
        body: dict[str, Any] = {}
        if method != "GET":
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                raise HTTPException(403, "Cross-origin mutation rejected")
            try:
                body = await request.json()
                if not isinstance(body, dict):
                    raise ValueError("Expected JSON object")
                digest(body)
            except (ValueError, TypeError, RecursionError) as exc:
                raise HTTPException(422, "Expected finite JSON object") from exc
        try:
            if method == "GET" and path == "integrations/models":
                from .integrations import IntegrationError, list_models

                async with store.transaction() as state:
                    if not lookup_session(state, request.cookies.get(COOKIE, "")):
                        raise HTTPException(401, "Sign in required")
                try:
                    return await list_models()
                except IntegrationError as exc:
                    raise HTTPException(503, str(exc)) from exc
            prepared = None
            parts = path.split("/")
            action = "/".join(parts[2:])
            if (
                method == "POST"
                and len(parts) >= 3
                and parts[0] == "workspaces"
                and action
                in (
                    "analyze",
                    "scenarios",
                    "integrations/weather",
                    "integrations/advice",
                    "learning/history",
                    "learning/train",
                    "learning/scenarios",
                    "learning/evaluate",
                )
            ):
                async with store.transaction() as snapshot_state:
                    snapshot_session = lookup_session(
                        snapshot_state, request.cookies.get(COOKIE, "")
                    )
                    if not snapshot_session:
                        raise HTTPException(401, "Sign in required")
                    require(snapshot_session["user"], "owner", "planner")
                    if not hmac.compare_digest(
                        request.headers.get("X-Nexus-CSRF", ""), snapshot_session["csrf_token"]
                    ):
                        raise HTTPException(403, "Invalid CSRF token")
                    snapshot = copy.deepcopy(snapshot_state["workspaces"].get(parts[1]))
                    if not snapshot:
                        raise HTTPException(404, "Workspace not found")
                    key = request.headers.get("Idempotency-Key")
                    receipt_key = (
                        digest([snapshot_session["user"]["id"], method, path, key]) if key else None
                    )
                    if receipt_key and receipt_key in snapshot_state["receipts"]:
                        receipt = snapshot_state["receipts"][receipt_key]
                        if receipt["fingerprint"] != digest(body):
                            raise HTTPException(409, "Idempotency key reused with different input")
                        return receipt["result"]
                verify_events(snapshot)
                prepared = await prepare(snapshot, action, body)
            async with store.transaction() as state:
                session = lookup_session(state, request.cookies.get(COOKIE, ""))
                if path == "session" and method == "GET":
                    return {"needs_setup": not state["users"], **(session or {"user": None})}
                if path in ("setup", "login") and method == "POST":
                    user: dict[str, Any] | None
                    username, password = body.get("username", ""), body.get("password", "")
                    if not isinstance(username, str) or not re.fullmatch(
                        r"[A-Za-z0-9_.-]{3,64}", username
                    ):
                        raise HTTPException(
                            422, "Username must contain 3–64 letters, digits, . _ or -"
                        )
                    if path == "setup":
                        if (
                            not request.client
                            or request.client.host not in ("127.0.0.1", "::1")
                            or request.url.hostname not in ("localhost", "127.0.0.1", "::1")
                        ):
                            raise HTTPException(403, "Initial owner setup requires localhost")
                        if state["users"]:
                            raise HTTPException(409, "Owner already configured")
                        user = {
                            "id": uuid.uuid4().hex,
                            "username": username,
                            "role": "owner",
                            "password_hash": await asyncio.to_thread(hash_password, password),
                        }
                        state["users"][user["id"]] = user
                    else:
                        # Persistent, bounded host throttle; failed logins return a response
                        # so their attempt counters commit rather than rolling back.
                        rate_key = "auth:" + digest(
                            request.client.host if request.client else "unknown"
                        )
                        now = time.time()
                        expired_rates = [
                            entry_key
                            for entry_key, entry in state["receipts"].items()
                            if entry_key.startswith("auth:") and entry["until"] <= now
                        ][:256]
                        for entry_key in expired_rates:
                            del state["receipts"][entry_key]
                        attempts = state["receipts"].get(rate_key, {"until": now + 900, "count": 0})
                        if attempts["until"] <= now:
                            attempts = {"until": now + 900, "count": 0}
                        if attempts["count"] >= 10:
                            return JSONResponse(
                                {"detail": "Too many login attempts; retry later"},
                                status_code=429,
                                headers={"Retry-After": "900"},
                            )
                        if rate_key not in state["receipts"] and len(state["receipts"]) >= 2000:
                            return JSONResponse(
                                {"detail": "Login capacity reached; retry later"}, status_code=429
                            )
                        attempts["count"] += 1
                        state["receipts"][rate_key] = attempts
                        user = next(
                            (u for u in state["users"].values() if u["username"] == username), None
                        )
                        # Same expensive verification for unknown usernames.
                        encoded = user["password_hash"] if user else dummy_password_hash
                        valid = await asyncio.to_thread(verify_password, password, encoded)
                        if not valid or not user or user.get("disabled"):
                            return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
                    revoke_session(state, request.cookies.get(COOKIE, ""))
                    result = create_session(state, user)
                    token = result.pop("token")
                    response = JSONResponse(result)
                    response.set_cookie(
                        COOKIE,
                        token,
                        httponly=True,
                        samesite="strict",
                        secure=request.url.scheme == "https",
                        max_age=28800,
                    )
                    return response
                if not session:
                    raise HTTPException(401, "Sign in required")
                user = session["user"]
                if method != "GET" and not hmac.compare_digest(
                    request.headers.get("X-Nexus-CSRF", ""), session["csrf_token"]
                ):
                    raise HTTPException(403, "Invalid CSRF token")
                if path == "logout" and method == "POST":
                    revoke_session(state, request.cookies.get(COOKIE, ""))
                    response = JSONResponse({"signed_out": True})
                    response.delete_cookie(COOKIE)
                    return response
                key = request.headers.get("Idempotency-Key") if method != "GET" else None
                receipt_key = digest([user["id"], method, path, key]) if key else None
                fingerprint = digest(body)
                if receipt_key and receipt_key in state["receipts"]:
                    receipt = state["receipts"][receipt_key]
                    if receipt["fingerprint"] != fingerprint:
                        raise HTTPException(409, "Idempotency key reused with different input")
                    return receipt["result"]
                result = await dispatch(state, user, path, method, body, prepared)
                if receipt_key:
                    if key is not None and len(key) > 128 or len(state["receipts"]) >= 2000:
                        raise HTTPException(422, "Idempotency receipt limit reached")
                    state["receipts"][receipt_key] = {
                        "fingerprint": fingerprint,
                        "result": copy.deepcopy(result),
                    }
                return result
        except StorageIntegrityError as exc:
            raise HTTPException(503, "Stored data integrity check failed") from exc
        except (ValueError, KeyError, TypeError, OverflowError, AttributeError) as exc:
            raise HTTPException(422, str(exc)[:300]) from exc

    return app


def require(user: dict[str, Any], *roles: str) -> None:
    if user["role"] not in roles:
        raise HTTPException(403, "Role does not permit this operation")


def revision(ws: dict[str, Any], body: dict[str, Any]) -> None:
    if (
        type(body.get("expected_revision")) is not int
        or body["expected_revision"] != ws["revision"]
    ):
        raise HTTPException(409, "Plan revision changed; refresh and compare again")


def name(body: dict[str, Any]) -> str:
    value = body.get("name")
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 120:
        raise ValueError("Name must contain 1–120 characters")
    return value.strip()


async def prepare(ws: dict[str, Any], action: str, body: dict[str, Any]) -> dict[str, Any]:
    from .integrations import IntegrationError, advise, fetch_weather

    try:
        if action in ("learning/history", "learning/train"):
            from .learning_control import prepare_learning

            return await asyncio.to_thread(prepare_learning, ws, action, body)
        if action == "learning/scenarios":
            from .learning_control import prepare_model_scenario

            revision(ws, body)
            result = await asyncio.to_thread(prepare_model_scenario, ws, body)
            attach_learning(result["analysis"], result["model_metadata"])
            return result
        if action == "learning/evaluate":
            from .learning import evaluate_models, validate_history
            from .learning_control import initial

            state = ws.get("learning", initial())
            artifact = state["models"].get(body.get("model_id"))
            if not artifact:
                raise ValueError("Trained model not found")
            history = body.get("history")
            if not isinstance(history, dict):
                raise ValueError("Evaluation history required")
            history = validate_history(history)
            existing = {p for groups in artifact["split"]["project_ids"].values() for p in groups}
            if any(
                r["domain"] != ws["domain"] or r["project_id"] in existing for r in history["rows"]
            ):
                raise ValueError("External evaluation needs new projects from the same domain")
            metrics = await asyncio.to_thread(evaluate_models, artifact, history, "test")
            return {
                "revision": ws["revision"],
                "learning_revision": state["history_revision"],
                "model_id": artifact["id"],
                "metrics": metrics,
                "kind": history["kind"],
                "evaluation_digest": digest(history),
                "partition": "test",
                "note": "External evaluation only; model and training history unchanged",
            }
        data: dict[str, Any] = {"revision": ws["revision"]}
        if action == "integrations/weather":
            lat, long = body.get("latitude"), body.get("longitude")
            if (
                isinstance(lat, bool)
                or isinstance(long, bool)
                or not isinstance(lat, (int, float))
                or not isinstance(long, (int, float))
            ):
                raise ValueError("Invalid latitude or longitude")
            data["observation"] = await fetch_weather(lat, long)
        elif action == "integrations/advice":
            if not ws["analysis"]:
                raise ValueError("Analyze the current dataset first")
            data["analysis_hash"] = digest(ws["analysis"])
            data["advice"] = await advise(
                ws["analysis"],
                body.get("question", "Explain the primary risks and feasible next steps."),
            )
        else:
            if not ws["dataset"]:
                raise ValueError("Import a dataset first")
            if action == "analyze":
                seed, samples = body.get("seed", 42), body.get("samples", 100)
                if type(seed) is not int or type(samples) is not int or not 1 <= samples <= 200:
                    raise ValueError("Invalid forecast seed or samples (1–200)")
                data["analysis"] = await asyncio.to_thread(
                    analyze_domain, ws["domain"], ws["dataset"], seed=seed, samples=samples
                )
                if (ws.get("analysis") or {}).get("learning"):
                    attach_learning(data["analysis"], ws["analysis"]["learning"])
            else:
                revision(ws, body)
                changes = body.get("changes")
                if not isinstance(changes, list) or any(
                    not isinstance(change, dict) for change in changes
                ):
                    raise ValueError("Changes must be a list of objects")
                data["payload"] = apply_domain_changes(ws["domain"], ws["dataset"], changes)
                data["baseline"] = await asyncio.to_thread(
                    analyze_domain, ws["domain"], ws["dataset"], seed=42, samples=100
                )
                data["analysis"] = await asyncio.to_thread(
                    analyze_domain, ws["domain"], data["payload"], seed=42, samples=100
                )
                if (ws.get("analysis") or {}).get("learning"):
                    attach_learning(data["analysis"], ws["analysis"]["learning"])
        return data
    except IntegrationError as exc:
        raise HTTPException(503, str(exc)) from exc


async def dispatch(
    state: dict[str, Any],
    user: dict[str, Any],
    path: str,
    method: str,
    body: dict[str, Any],
    prepared: dict[str, Any] | None = None,
) -> Any:
    parts = path.split("/")
    if path == "users" and method == "POST":
        require(user, "owner")
        username = body.get("username", "")
        if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
            raise ValueError("Invalid username")
        if any(u["username"] == username for u in state["users"].values()):
            raise HTTPException(409, "Username already exists")
        if body.get("role") not in ("planner", "approver", "viewer"):
            raise ValueError("Invalid role")
        item = {
            "id": uuid.uuid4().hex,
            "username": username,
            "role": body["role"],
            "password_hash": await asyncio.to_thread(hash_password, body.get("password", "")),
        }
        state["users"][item["id"]] = item
        return {k: item[k] for k in ("id", "username", "role")}
    if path == "domains" and method == "GET":
        return domain_catalog()
    if len(parts) == 3 and parts[0] == "domains" and parts[2] == "sample" and method == "GET":
        return sample_payload(parts[1])
    if (
        len(parts) == 3
        and parts[0] == "domains"
        and parts[2] == "history-sample"
        and method == "GET"
    ):
        from .synthetic import generate_history

        return generate_history(parts[1])
    if path == "workspaces":
        if method == "GET":
            return [
                {k: w[k] for k in ("id", "name", "domain", "revision")}
                for w in state["workspaces"].values()
            ]
        if method == "POST":
            require(user, "owner", "planner")
            domain = body.get("domain")
            if domain not in {d["id"] for d in domain_catalog()}:
                raise ValueError("Unknown domain")
            ws = {
                "id": uuid.uuid4().hex,
                "name": name(body),
                "domain": domain,
                "revision": 0,
                "dataset": None,
                "analysis": None,
                "scenarios": [],
                "decisions": [],
                "events": [],
                "observations": [],
                "versions": [],
            }
            state["workspaces"][ws["id"]] = ws
            event(ws, user["id"], "workspace_created", {"domain": domain})
            return ws
    if len(parts) >= 2 and parts[0] == "workspaces":
        ws = state["workspaces"].get(parts[1])
        if not ws:
            raise HTTPException(404, "Workspace not found")
        verify_events(ws)
        if len(parts) == 2 and method == "GET":
            return {
                **{key: value for key, value in ws.items() if key != "learning"},
                "decisions": [state["decisions"][d] for d in ws["decisions"]],
            }
        if parts[2:] == ["learning"] and method == "GET":
            from .learning_control import summary

            return summary(ws)
        if len(parts) == 5 and parts[2:4] == ["learning", "models"] and method == "GET":
            from .learning_control import initial

            artifact = ws.get("learning", initial())["models"].get(parts[4])
            if not artifact:
                raise HTTPException(404, "Model artifact not found")
            return artifact
        if len(parts) == 3 and parts[2] == "events" and method == "GET":
            return ws["events"]
        require(user, "owner", "planner")
        action = "/".join(parts[2:])
        if action in ("learning/history", "learning/train") and method == "POST":
            from .learning_control import initial, summary

            if prepared is None:
                raise ValueError("Training preparation missing")
            if prepared["learning_revision"] != ws.get("learning", initial())["history_revision"]:
                raise HTTPException(409, "Historical outcomes changed during training; retry")
            ws["learning"] = prepared["state"]
            event(
                ws,
                user["id"],
                "learning_" + prepared["training"],
                {
                    "history_revision": ws["learning"]["history_revision"],
                    "training": prepared["training"],
                    "row_count": summary(ws)["row_count"],
                    "history_digest": digest(ws["learning"]["history"]),
                    "active_model_id": ws["learning"]["active_id"],
                },
            )
            return summary(ws)
        if action == "learning/evaluate" and method == "POST":
            from .learning_control import initial

            if prepared is None:
                raise ValueError("Evaluation preparation missing")
            if prepared["learning_revision"] != ws.get("learning", initial())["history_revision"]:
                raise HTTPException(409, "Historical outcomes changed during evaluation")
            event(
                ws,
                user["id"],
                "learning_external_evaluated",
                {
                    "model_id": prepared["model_id"],
                    "metrics": prepared["metrics"],
                    "evaluation_digest": prepared["evaluation_digest"],
                },
            )
            return prepared
        if prepared is not None:
            if prepared["revision"] != ws["revision"]:
                raise HTTPException(409, "Plan changed during computation; retry")
            if "analysis_hash" in prepared and prepared["analysis_hash"] != digest(ws["analysis"]):
                raise HTTPException(409, "Analysis changed during advice; retry")
        if action == "learning/scenarios" and method == "POST":
            from .learning_control import initial

            if prepared is None:
                raise ValueError("Model scenario preparation missing")
            revision(ws, body)
            learning = ws.get("learning", initial())
            if (
                prepared["learning_revision"] != learning["history_revision"]
                or prepared["model_id"] != learning["active_id"]
            ):
                raise HTTPException(409, "Trained model changed during planning; retry")
            scenario = {
                "id": uuid.uuid4().hex,
                "name": name(body),
                "baseline_revision": ws["revision"],
                "payload": prepared["payload"],
                "analysis": prepared["analysis"],
                "changes": prepared["changes"],
                "model_metadata": prepared["model_metadata"],
                "diff": {
                    "baseline": prepared["baseline"]["forecast"],
                    "branch": prepared["analysis"]["forecast"],
                    "baseline_cost": prepared["baseline"]["cost"],
                    "branch_cost": prepared["analysis"]["cost"],
                },
            }
            ws["scenarios"].append(scenario)
            event(
                ws,
                user["id"],
                "learning_scenario_compared",
                {"scenario_id": scenario["id"], "model_id": prepared["model_id"]},
            )
            return scenario
        if action == "dataset" and method == "PUT":
            revision(ws, body)
            payload = body.get("payload")
            source_digest = digest(payload)
            if isinstance(payload, dict) and "csv_files" in payload:
                from .imports import parse_csv_bundle

                payload = parse_csv_bundle(payload["csv_files"])
            if not isinstance(payload, dict):
                raise ValueError("Dataset must be an object")
            normalized = validate_domain(ws["domain"], payload)
            provenance = body.get("provenance", {})
            if provenance.get("kind") not in ("user_upload", "synthetic"):
                raise ValueError("Source kind must be user_upload or synthetic")
            source_name = name({"name": provenance.get("name")})
            update_plan(
                ws,
                normalized,
                {"kind": provenance["kind"], "name": source_name, "sha256": source_digest},
                user["id"],
                "dataset_imported",
            )
            return {"revision": ws["revision"], "provenance": ws["provenance"]}
        if action == "analyze" and method == "POST":
            if not ws["dataset"]:
                raise ValueError("Import a dataset first")
            seed, samples = body.get("seed", 42), body.get("samples", 100)
            if type(seed) is not int or type(samples) is not int or not 1 <= samples <= 200:
                raise ValueError("Invalid forecast seed or samples (1–200)")
            ws["analysis"] = (prepared or {})["analysis"]
            event(
                ws,
                user["id"],
                "analysis_completed",
                {"revision": ws["revision"], "seed": seed, "samples": samples},
            )
            return ws["analysis"]
        if action == "scenarios" and method == "POST":
            revision(ws, body)
            if not ws["dataset"]:
                raise ValueError("Import a dataset first")
            payload = (prepared or {})["payload"]
            baseline = (prepared or {})["baseline"]
            analysis = (prepared or {})["analysis"]
            s = {
                "id": uuid.uuid4().hex,
                "name": name(body),
                "baseline_revision": ws["revision"],
                "payload": payload,
                "analysis": analysis,
                "changes": body["changes"],
                "diff": {
                    "baseline": baseline["forecast"],
                    "branch": analysis["forecast"],
                    "baseline_cost": baseline["cost"],
                    "branch_cost": analysis["cost"],
                },
            }
            ws["scenarios"].append(s)
            event(
                ws,
                user["id"],
                "scenario_compared",
                {"scenario_id": s["id"], "revision": ws["revision"]},
            )
            return s
        if action == "decisions" and method == "POST":
            revision(ws, body)
            selected: dict[str, Any] | None = next(
                (s for s in ws["scenarios"] if s["id"] == body.get("scenario_id")), None
            )
            if not selected or selected["baseline_revision"] != ws["revision"]:
                raise HTTPException(409, "Scenario is missing or stale")
            s = selected
            if s["analysis"]["infeasible"]:
                raise HTTPException(409, "Cannot propose an infeasible branch")
            d = {
                "id": uuid.uuid4().hex,
                "workspace_id": ws["id"],
                "scenario_id": s["id"],
                "author_id": user["id"],
                "baseline_revision": ws["revision"],
                "payload": copy.deepcopy(s["payload"]),
                "analysis": copy.deepcopy(s["analysis"]),
                "status": "proposed",
            }
            d["plan_hash"] = decision_digest(d)
            state["decisions"][d["id"]] = d
            ws["decisions"].append(d["id"])
            event(
                ws,
                user["id"],
                "decision_proposed",
                {"decision_id": d["id"], "plan_hash": d["plan_hash"]},
            )
            return d
        if action == "integrations/weather" and method == "POST":
            observation = (prepared or {})["observation"]
            ws["observations"].append(observation)
            event(ws, user["id"], "weather_fetched", {"sha256": digest(observation)})
            return observation
        if action == "integrations/advice" and method == "POST":
            if not ws["analysis"]:
                raise ValueError("Analyze the current dataset first")
            advice = (prepared or {})["advice"]
            event(
                ws, user["id"], "advice_generated", {"revision": ws["revision"], "advice": advice}
            )
            return advice
    if len(parts) == 3 and parts[0] == "decisions" and method == "POST":
        d = state["decisions"].get(parts[1])
        if not d:
            raise HTTPException(404, "Decision not found")
        if d["plan_hash"] != decision_digest(d):
            raise StorageIntegrityError("Decision content no longer matches approved plan")
        if not hmac.compare_digest(str(body.get("plan_hash", "")), d["plan_hash"]):
            raise HTTPException(409, "Exact plan hash required")
        ws = state["workspaces"][d["workspace_id"]]
        verify_events(ws)
        if ws["revision"] != d["baseline_revision"]:
            raise HTTPException(409, "Decision is stale")
        if parts[2] == "approve":
            require(user, "approver", "owner")
            if d["author_id"] == user["id"]:
                raise HTTPException(403, "Independent approver required")
            if d["status"] != "proposed":
                raise HTTPException(409, "Decision already reviewed")
            if body.get("decision") not in ("approve", "reject"):
                raise ValueError("Decision must be approve or reject")
            d["status"] = "approved" if body["decision"] == "approve" else "rejected"
            d["approver_id"] = user["id"]
        elif parts[2] == "apply":
            require(user, "owner", "planner")
            if d["author_id"] != user["id"]:
                raise HTTPException(403, "Only proposing author may apply")
            if d["status"] != "approved":
                raise HTTPException(409, "Independent approval required")
            update_plan(
                ws,
                d["payload"],
                {
                    "kind": "approved_branch",
                    "name": d["scenario_id"],
                    "sha256": digest(d["payload"]),
                    "origin": copy.deepcopy(ws["provenance"].get("origin", ws["provenance"])),
                },
                user["id"],
                "plan_applied",
            )
            ws["analysis"] = copy.deepcopy(d["analysis"])
            d["status"] = "applied"
        else:
            raise HTTPException(404)
        event(
            ws,
            user["id"],
            "decision_" + d["status"],
            {"decision_id": d["id"], "plan_hash": d["plan_hash"]},
        )
        return d
    raise HTTPException(404, "Unknown operation")


def update_plan(
    ws: dict[str, Any], payload: dict[str, Any], provenance: dict[str, Any], actor: str, kind: str
) -> None:
    if ws["dataset"]:
        ws["versions"].append(
            {
                "revision": ws["revision"],
                "dataset": ws["dataset"],
                "analysis": ws["analysis"],
                "provenance": ws["provenance"],
            }
        )
    ws["revision"] += 1
    ws["dataset"] = copy.deepcopy(payload)
    ws["analysis"] = None
    ws["provenance"] = {
        **provenance,
        "revision": ws["revision"],
        "imported_at": datetime.now(UTC).isoformat(),
    }
    event(ws, actor, kind, {"revision": ws["revision"], "provenance": ws["provenance"]})
