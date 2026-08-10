"""Contract checks for the Slice C StructuredOutputPort implementation."""

import inspect

from nexus_contracts.platform import StructuredOutputPort
from nexus_llm import OpenAICompatibleStructuredOutput


def test_openai_compatible_adapter_preserves_structured_output_port_signature() -> None:
    """Changing the adapter call boundary would prevent later supervisor substitution."""
    protocol = inspect.signature(StructuredOutputPort.generate_object)
    adapter = inspect.signature(OpenAICompatibleStructuredOutput.generate_object)

    assert list(adapter.parameters) == list(protocol.parameters)
    assert inspect.iscoroutinefunction(OpenAICompatibleStructuredOutput.generate_object)
