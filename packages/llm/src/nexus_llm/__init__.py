"""Safe OpenAI-compatible structured-output boundary."""

from nexus_llm.openai_compatible import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL_ID,
    EvidenceInputError,
    InvalidStructuredOutput,
    LLMSettings,
    OpenAICompatibleStructuredOutput,
    ProviderTimeout,
    ProviderUnavailable,
    ValidationCode,
    canonical_evidence_prompt,
)

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL_ID",
    "EvidenceInputError",
    "InvalidStructuredOutput",
    "LLMSettings",
    "OpenAICompatibleStructuredOutput",
    "ProviderTimeout",
    "ProviderUnavailable",
    "ValidationCode",
    "canonical_evidence_prompt",
]
