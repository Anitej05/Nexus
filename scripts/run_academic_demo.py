"""Run the complete academic workflow on loopback without Docker."""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn
from nexus_api.academic_demo import create_demo_app
from nexus_api.prototype.llm import StructuredAdvisoryFacade, prototype_llm_settings
from nexus_api.prototype.orchestrator import AdvisoryFacade
from nexus_llm import OpenAICompatibleStructuredOutput


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--database",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "artifacts" / "academic-demo.sqlite3",
    )
    parser.add_argument(
        "--live-llm",
        action="store_true",
        help="Try the configured model; safe fallback remains available",
    )
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    advisory: AdvisoryFacade | None = None
    if args.live_llm:
        settings = prototype_llm_settings()
        advisory = StructuredAdvisoryFacade(
            OpenAICompatibleStructuredOutput(settings), model_id=settings.model_id
        )
    print(f"NEXUS academic demo: http://127.0.0.1:{args.port}/prototype")
    print(
        "Local demonstration identities only. All actions are simulations. Ctrl+C stops the server."
    )
    uvicorn.run(create_demo_app(args.database, advisory), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
