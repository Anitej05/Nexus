"""Prototype facade over the reviewed bounded structured-output adapter."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from nexus_contracts.platform import RequestContext, ResourceRef, StructuredOutputPort
from nexus_contracts.prototype import EvidenceFact, SpecialistFinding
from nexus_llm import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL_ID,
    EvidenceInputError,
    InvalidStructuredOutput,
    LLMSettings,
    ProviderTimeout,
    ProviderUnavailable,
    ValidationCode,
    canonical_evidence_prompt,
)
from pydantic import UUID7, ValidationError

from nexus_api.prototype.models import (
    PromptVersion,
    PrototypeAdvisory,
    PrototypeAgentFinding,
    PrototypeGraph,
    PrototypeSignal,
    ProviderStatus,
)
from nexus_api.prototype.orchestrator import DeterministicAdvisoryFacade

PROMPT_VERSION: PromptVersion = "prototype-briefing.v1"
_EVIDENCE_OCCURRED_AT = datetime(2026, 8, 9, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class PrototypeLLMSettings:
    """Safe API-facing configuration view with no implicit fallback model."""

    base_url: str
    model_id: str
    api_key: str | None = field(default=None, repr=False)
    total_timeout_seconds: float = 30.0
    fallback_model_id: None = None

    @classmethod
    def from_environment(cls) -> PrototypeLLMSettings:
        settings = prototype_llm_settings()
        return cls(
            base_url=settings.base_url,
            model_id=settings.model_id,
            api_key=settings.api_key,
            total_timeout_seconds=settings.total_timeout_seconds,
        )


def prototype_llm_settings() -> LLMSettings:
    """Resolve documented prototype overrides before the shared provider settings."""
    raw_timeout = (
        os.getenv("NEXUS_PROTOTYPE_LLM_TIMEOUT_SECONDS")
        or os.getenv("NEXUS_LLM_TOTAL_TIMEOUT_SECONDS")
        or "30"
    )
    try:
        timeout = min(30.0, max(1.0, float(raw_timeout)))
    except ValueError:
        timeout = 30.0
    return LLMSettings(
        base_url=os.getenv("NEXUS_PROTOTYPE_LLM_BASE_URL")
        or os.getenv("NEXUS_LLM_BASE_URL")
        or DEFAULT_BASE_URL,
        model_id=os.getenv("NEXUS_PROTOTYPE_LLM_MODEL")
        or os.getenv("NEXUS_LLM_MODEL")
        or DEFAULT_MODEL_ID,
        api_key=(
            os.getenv("NEXUS_PROTOTYPE_LLM_API_KEY")
            if "NEXUS_PROTOTYPE_LLM_API_KEY" in os.environ
            else os.getenv("NEXUS_LLM_API_KEY")
        ),
        total_timeout_seconds=timeout,
    )


def _evidence_id(node_id: str) -> UUID7:
    raw = bytearray(hashlib.sha256(f"prototype-evidence:{node_id}".encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return UUID(bytes=bytes(raw))


def _evidence_facts(
    context: RequestContext,
    graph: PrototypeGraph,
    signals: tuple[PrototypeSignal, PrototypeSignal],
    findings: tuple[PrototypeAgentFinding, PrototypeAgentFinding, PrototypeAgentFinding],
) -> tuple[tuple[EvidenceFact, ...], dict[str, tuple[str, ...]]]:
    node_facts = tuple(
        EvidenceFact(
            ref=ResourceRef(
                tenant_id=context.tenant_id,
                kind="prototype.graph.node",
                id=_evidence_id(node.id),
                version=1,
            ),
            occurred_at=_EVIDENCE_OCCURRED_AT,
            predicate="prototype.graph_node",
            value={**node.model_dump(mode="json"), "node_id": node.id},
        )
        for node in graph.nodes
    )
    signal_facts = tuple(
        EvidenceFact(
            ref=ResourceRef(
                tenant_id=context.tenant_id,
                kind="prototype.risk.signal",
                id=_evidence_id(f"signal:{signal.domain}"),
                version=1,
            ),
            occurred_at=_EVIDENCE_OCCURRED_AT,
            predicate="prototype.risk_signal",
            value=signal.model_dump(mode="json"),
        )
        for signal in signals
    )
    finding_facts = tuple(
        EvidenceFact(
            ref=ResourceRef(
                tenant_id=context.tenant_id,
                kind="prototype.agent.finding",
                id=_evidence_id(f"finding:{finding.agent_role}"),
                version=1,
            ),
            occurred_at=_EVIDENCE_OCCURRED_AT,
            predicate="prototype.agent_finding",
            value=finding.model_dump(mode="json"),
        )
        for finding in findings
    )
    facts = node_facts + signal_facts + finding_facts
    citation_map: dict[str, tuple[str, ...]] = {
        str(fact.ref.id): (graph.nodes[index].id,) for index, fact in enumerate(node_facts)
    }
    citation_map.update(
        {
            str(fact.ref.id): signal.evidence_node_ids
            for fact, signal in zip(signal_facts, signals, strict=True)
        }
    )
    citation_map.update(
        {
            str(fact.ref.id): finding.evidence_node_ids
            for fact, finding in zip(finding_facts, findings, strict=True)
        }
    )
    return facts, citation_map


class StructuredAdvisoryFacade:
    """Translate the reviewed SpecialistFinding contract into prototype state."""

    def __init__(
        self,
        port: StructuredOutputPort,
        *,
        model_id: str = DEFAULT_MODEL_ID,
        prompt_version: PromptVersion = PROMPT_VERSION,
    ) -> None:
        self._port = port
        self._model_id = model_id
        self._prompt_version = prompt_version
        self._fallback = DeterministicAdvisoryFacade()

    async def _degraded(
        self,
        graph: PrototypeGraph,
        signals: tuple[PrototypeSignal, PrototypeSignal],
        findings: tuple[PrototypeAgentFinding, PrototypeAgentFinding, PrototypeAgentFinding],
        *,
        context: RequestContext | None,
        idempotency_key: str,
        status: ProviderStatus,
    ) -> PrototypeAdvisory:
        fallback = await self._fallback.generate(
            graph, signals, findings, context=context, idempotency_key=idempotency_key
        )
        return fallback.model_copy(
            update={
                "provider_status": status,
                "model_id": self._model_id,
                "prompt_version": self._prompt_version,
            }
        )

    async def generate(
        self,
        graph: PrototypeGraph,
        signals: tuple[PrototypeSignal, PrototypeSignal],
        findings: tuple[PrototypeAgentFinding, PrototypeAgentFinding, PrototypeAgentFinding],
        *,
        context: RequestContext | None,
        idempotency_key: str,
    ) -> PrototypeAdvisory:
        if context is None:
            return await self._degraded(
                graph,
                signals,
                findings,
                context=None,
                idempotency_key=idempotency_key,
                status="unavailable",
            )
        facts, citation_map = _evidence_facts(context, graph, signals, findings)
        try:
            prompt = canonical_evidence_prompt("decision_critic", facts)
            bound_key = hashlib.sha256(idempotency_key.encode()).hexdigest()
            result = await self._port.generate_object(context, prompt, SpecialistFinding, bound_key)
            if not isinstance(result, SpecialistFinding):
                result = SpecialistFinding.model_validate(result)
        except ProviderTimeout:
            return await self._degraded(
                graph,
                signals,
                findings,
                context=context,
                idempotency_key=idempotency_key,
                status="timeout",
            )
        except ProviderUnavailable:
            return await self._degraded(
                graph,
                signals,
                findings,
                context=context,
                idempotency_key=idempotency_key,
                status="unavailable",
            )
        except InvalidStructuredOutput as error:
            citation_codes = {ValidationCode.CITATIONS_REQUIRED, ValidationCode.CITATION_ALLOWLIST}
            status: ProviderStatus = (
                "uncited"
                if citation_codes.intersection(error.validation_codes)
                else "invalid_output"
            )
            return await self._degraded(
                graph,
                signals,
                findings,
                context=context,
                idempotency_key=idempotency_key,
                status=status,
            )
        except (EvidenceInputError, ValidationError, ValueError, TypeError):
            return await self._degraded(
                graph,
                signals,
                findings,
                context=context,
                idempotency_key=idempotency_key,
                status="malformed",
            )
        citation_nodes: list[str] = []
        for citation in result.cited_evidence:
            if citation.tenant_id != context.tenant_id or str(citation.id) not in citation_map:
                return await self._degraded(
                    graph,
                    signals,
                    findings,
                    context=context,
                    idempotency_key=idempotency_key,
                    status="uncited",
                )
            citation_nodes.extend(citation_map[str(citation.id)])
        if not result.abstain and not citation_nodes:
            return await self._degraded(
                graph,
                signals,
                findings,
                context=context,
                idempotency_key=idempotency_key,
                status="uncited",
            )
        return PrototypeAdvisory(
            provider_status="available",
            model_id=self._model_id,
            prompt_version=self._prompt_version,
            summary_sha256=hashlib.sha256(result.conclusion.encode()).hexdigest(),
            citation_node_ids=tuple(
                node.id for node in graph.nodes if node.id in set(citation_nodes)
            ),
        )
