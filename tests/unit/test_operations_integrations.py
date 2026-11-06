import httpx
import pytest
from nexus_api.operations.integrations import IntegrationError, advise, fetch_weather, list_models


@pytest.mark.asyncio
async def test_weather_returns_source_data(monkeypatch):
    async def handler(request):
        assert request.url.host == "api.open-meteo.com"
        return httpx.Response(
            200,
            json={"daily": {"time": ["2026-01-01"], "precipitation_sum": [4], "weather_code": [1]}},
        )

    monkeypatch.setattr(
        "nexus_api.operations.integrations._transport", httpx.MockTransport(handler)
    )
    result = await fetch_weather(51.5, -0.1)
    assert result["daily"]["precipitation_sum"] == [4]


@pytest.mark.asyncio
async def test_model_listing_and_grounded_advice(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-secret")

    async def handler(request):
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "model-a"}]})
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"answer":"Review A", "evidence_ids":["a"]}'}}]
            },
        )

    monkeypatch.setattr(
        "nexus_api.operations.integrations._transport", httpx.MockTransport(handler)
    )
    assert await list_models() == ["model-a"]
    answer = await advise(
        {"graph": {"nodes": [{"id": "a"}], "edges": []}, "risks": []}, "What matters?"
    )
    assert answer["evidence_ids"] == ["a"]


@pytest.mark.asyncio
async def test_ungrounded_advice_rejected(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-secret")

    async def handler(request):
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"answer":"x", "evidence_ids":["invented"]}'}}]
            },
        )

    monkeypatch.setattr(
        "nexus_api.operations.integrations._transport", httpx.MockTransport(handler)
    )
    with pytest.raises(IntegrationError):
        await advise({"graph": {"nodes": [{"id": "a"}], "edges": []}}, "What matters?")


@pytest.mark.asyncio
async def test_weather_rejects_malformed_daily_data(monkeypatch):
    async def handler(request):
        return httpx.Response(
            200,
            json={
                "daily": {"time": ["2026-01-01"], "precipitation_sum": [-1], "weather_code": [1]}
            },
        )

    monkeypatch.setattr(
        "nexus_api.operations.integrations._transport", httpx.MockTransport(handler)
    )
    with pytest.raises(IntegrationError):
        await fetch_weather(0, 0)


@pytest.mark.asyncio
async def test_provider_response_size_is_bounded(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-secret")

    async def handler(request):
        return httpx.Response(200, json={"data": [], "padding": "x" * (1024 * 1024 + 1)})

    monkeypatch.setattr(
        "nexus_api.operations.integrations._transport", httpx.MockTransport(handler)
    )
    with pytest.raises(IntegrationError):
        await list_models()
