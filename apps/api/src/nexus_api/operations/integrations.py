"""Read-only external weather and NVIDIA inference integrations."""

from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import UTC, date, datetime
from typing import Any

import httpx

_transport: httpx.AsyncBaseTransport | None = None
NVIDIA = "https://integrate.api.nvidia.com/v1"


class IntegrationError(RuntimeError):
    """An external service is unavailable or returned an invalid response."""


def _key() -> str:
    key = os.getenv("NVIDIA_API_KEY", "").strip()
    if not key:
        raise IntegrationError("NVIDIA API key is not configured")
    return key


async def _request(method: str, url: str, **kwargs: Any) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(
            timeout=45, transport=_transport, follow_redirects=False
        ) as client:
            async with client.stream(method, url, **kwargs) as response:
                response.raise_for_status()
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > 1024 * 1024:
                        raise IntegrationError("External service response exceeds size limit")
                data = json.loads(content)
        if not isinstance(data, dict):
            raise IntegrationError("External service returned an invalid response")
        return data
    except (httpx.HTTPError, ValueError) as exc:
        raise IntegrationError("External service request failed or returned invalid JSON") from exc


async def fetch_weather(lat: float, long: float) -> dict[str, Any]:
    if (
        isinstance(lat, bool)
        or isinstance(long, bool)
        or not isinstance(lat, (int, float))
        or not isinstance(long, (int, float))
        or not math.isfinite(lat)
        or not math.isfinite(long)
        or not -90 <= lat <= 90
        or not -180 <= long <= 180
    ):
        raise ValueError("Invalid latitude or longitude")
    data = await _request(
        "GET",
        "https://api.open-meteo.com/v1/forecast",
        params={
            "latitude": lat,
            "longitude": long,
            "daily": "precipitation_sum,weather_code",
            "timezone": "auto",
            "forecast_days": 7,
        },
    )
    daily = data.get("daily")
    try:
        if not isinstance(daily, dict):
            raise ValueError("missing daily data")
        times, rainfall, codes = daily["time"], daily["precipitation_sum"], daily["weather_code"]
        if not all(isinstance(a, list) for a in (times, rainfall, codes)):
            raise ValueError("invalid arrays")
        if not 1 <= len(times) <= 7 or len(times) != len(rainfall) or len(times) != len(codes):
            raise ValueError("invalid array lengths")
        for day in times:
            if not isinstance(day, str) or date.fromisoformat(day).isoformat() != day:
                raise ValueError("invalid date")
        for value in rainfall + codes:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError("invalid daily value")
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise IntegrationError("Weather service returned invalid daily forecast") from exc
    digest = hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {
        "source": "Open-Meteo",
        "source_url": "https://api.open-meteo.com/v1/forecast",
        "fetched_at": datetime.now(UTC).isoformat(),
        "source_digest": digest,
        "latitude": lat,
        "longitude": long,
        "daily": daily,
    }


async def list_models() -> list[str]:
    data = await _request("GET", f"{NVIDIA}/models", headers={"Authorization": f"Bearer {_key()}"})
    entries = data.get("data")
    if not isinstance(entries, list):
        raise IntegrationError("NVIDIA returned an invalid model catalogue")
    return [
        entry["id"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    ]


async def advise(analysis: dict[str, Any], question: str) -> dict[str, Any]:
    if not isinstance(question, str) or not question.strip() or len(question) > 2000:
        raise ValueError("Question must contain 1 to 2000 characters")
    try:
        graph = analysis["graph"]
        nodes = graph["nodes"]
        ids = {
            node["id"]
            for node in nodes
            if isinstance(node, dict) and isinstance(node.get("id"), str)
        }
        context = json.dumps(
            {
                k: analysis.get(k)
                for k in (
                    "graph",
                    "metrics",
                    "activities",
                    "risks",
                    "forecast",
                    "cost",
                    "assumptions",
                    "infeasible",
                    "alternatives",
                )
            },
            allow_nan=False,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid analysis") from exc
    if len(context) > 100000:
        raise ValueError("Analysis is too large for advisor")
    model = os.getenv("NEXUS_LLM_MODEL", "stepfun-ai/step-5-preview")
    result = await _request(
        "POST",
        f"{NVIDIA}/chat/completions",
        headers={"Authorization": f"Bearer {_key()}"},
        json={
            "model": model,
            "temperature": 0.1,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": "You are a read-only operations advisor. "
                    "Use only supplied analysis as evidence. "
                    "Never claim to perform actions. Return JSON with answer (string) and "
                    "evidence_ids (array of exact graph node IDs). State uncertainty; "
                    "no fabricated facts. Only report shortages or infeasibility when the "
                    "infeasible list reports them; missing data is unknown. "
                    "Keep the answer under 150 words.",
                },
                {
                    "role": "user",
                    "content": json.dumps({"question": question, "analysis": json.loads(context)}),
                },
            ],
        },
    )
    try:
        content = result["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        refs = parsed["evidence_ids"]
        if (
            not isinstance(parsed["answer"], str)
            or not parsed["answer"].strip()
            or not isinstance(refs, list)
            or not refs
            or any(not isinstance(x, str) or x not in ids for x in refs)
        ):
            raise ValueError("invalid evidence")
    except (KeyError, TypeError, IndexError, ValueError) as exc:
        raise IntegrationError("Advisor response did not contain valid grounded evidence") from exc
    return {"answer": parsed["answer"], "evidence_ids": refs, "model": model}
