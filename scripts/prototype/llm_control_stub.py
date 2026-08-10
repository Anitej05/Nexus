# ruff: noqa: E501
"""Loopback-only OpenAI chat proxy with an exact test control surface."""

from __future__ import annotations

import argparse
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import urlsplit

import httpx

MAX_BODY_BYTES = 1_048_576
MODEL_ID = "deepseek-ai/DeepSeek-V4-Flash-0731"
CHAT_PATH = "/v1/chat/completions"
MODELS_PATH = "/v1/models"
CONTROL_PATH = "/control"
MODES = frozenset({"valid-alias", "unavailable"})


class StubState:
    mode = "valid-alias"
    upstream = ""


class Handler(BaseHTTPRequestHandler):
    state: ClassVar[StubState]

    def log_message(self, _format: str, *_args: object) -> None:
        """Prompts, model output, and bearer headers never reach process logs."""

    def _json(self, status: int, value: object) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self, *, limit: int) -> object | None:
        length = self.headers.get("content-length", "")
        if not length.isdecimal() or int(length) > limit:
            return None
        try:
            return json.loads(self.rfile.read(int(length)))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    def _control(self) -> None:
        if self.command == "GET":
            self._json(HTTPStatus.OK, {"mode": self.state.mode})
            return
        value = self._read_json(limit=1024)
        mode = value.get("mode") if isinstance(value, dict) else None
        if mode not in MODES:
            self._json(HTTPStatus.BAD_REQUEST, {"error": {"code": "invalid_control"}})
            return
        self.state.mode = mode
        self._json(HTTPStatus.OK, {"mode": self.state.mode})

    def _proxy_chat(self) -> None:
        if self.state.mode == "unavailable":
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": {"code": "provider_unavailable", "message": "unavailable"}},
            )
            return
        value = self._read_json(limit=MAX_BODY_BYTES)
        if not isinstance(value, dict) or value.get("model") != MODEL_ID:
            self._json(HTTPStatus.BAD_REQUEST, {"error": {"code": "invalid_request"}})
            return
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        headers = {"content-type": "application/json", "accept-encoding": "identity"}
        authorization = self.headers.get("authorization")
        if authorization:
            headers["authorization"] = authorization
        try:
            with httpx.stream(
                "POST",
                self.state.upstream.rstrip("/") + "/chat/completions",
                headers=headers,
                content=body,
                timeout=30.0,
                follow_redirects=False,
            ) as response:
                content_type = response.headers.get("content-type", "").partition(";")[0].strip()
                encoding = response.headers.get("content-encoding")
                length = response.headers.get("content-length")
                if (
                    response.status_code != HTTPStatus.OK
                    or content_type != "application/json"
                    or (encoding is not None and encoding.lower() != "identity")
                    or (length is not None and (not length.isdecimal() or int(length) > MAX_BODY_BYTES))
                ):
                    raise ValueError("untrusted provider response")
                bounded = bytearray()
                for chunk in response.iter_raw():
                    bounded.extend(chunk)
                    if len(bounded) > MAX_BODY_BYTES:
                        raise ValueError("untrusted provider response")
            content = bytes(bounded)
            if not isinstance(json.loads(content), dict):
                raise ValueError("untrusted provider response")
        except (httpx.HTTPError, json.JSONDecodeError, ValueError):
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": {"code": "provider_unavailable", "message": "unavailable"}},
            )
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _reject_method(self) -> None:
        status = (
            HTTPStatus.METHOD_NOT_ALLOWED
            if self.path in {CHAT_PATH, MODELS_PATH, CONTROL_PATH}
            else HTTPStatus.NOT_FOUND
        )
        self._json(
            status,
            {
                "error": {
                    "code": "method_not_allowed"
                    if status == HTTPStatus.METHOD_NOT_ALLOWED
                    else "not_found"
                }
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        if self.path == CONTROL_PATH:
            self._control()
        elif self.path == MODELS_PATH:
            self._json(
                HTTPStatus.OK,
                {
                    "object": "list",
                    "data": [{"id": MODEL_ID, "object": "model", "owned_by": "managed-e2e"}],
                },
            )
        elif self.path == CHAT_PATH:
            self._reject_method()
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": {"code": "not_found"}})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == CONTROL_PATH:
            self._control()
        elif self.path == CHAT_PATH:
            self._proxy_chat()
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": {"code": "not_found"}})

    do_PUT = _reject_method  # noqa: N815
    do_PATCH = _reject_method  # noqa: N815
    do_DELETE = _reject_method  # noqa: N815
    do_HEAD = _reject_method  # noqa: N815
    do_OPTIONS = _reject_method  # noqa: N815


def main(argv: list[str] | None = None) -> int:
    if (
        os.getenv("NEXUS_RUN_COMPOSE_TESTS") != "1"
        or os.getenv("NEXUS_PROTOTYPE_E2E_MANAGED") != "1"
    ):
        raise RuntimeError("managed LLM stub requires explicit test opt-ins")
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--upstream", required=True)
    arguments = parser.parse_args(argv)
    parsed = urlsplit(arguments.upstream)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/v1"
    ):
        raise RuntimeError("upstream must be an exact credential-free loopback /v1 URL")
    if not 1 <= arguments.port <= 65535:
        raise RuntimeError("port must be valid")
    state = StubState()
    state.upstream = arguments.upstream.rstrip("/")
    Handler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", arguments.port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
