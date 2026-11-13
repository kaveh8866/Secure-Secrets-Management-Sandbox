"""HTTP API for the secrets sandbox.

Design constraints that shaped this file:

* **No framework.** ``http.server`` is in the standard library; a secrets
  service that pulls in a web framework inherits the framework's CVEs. The
  surface here is small enough to audit in one sitting.
* **Fail closed.** A missing or malformed ``Authorization`` header is 401, an
  unknown token is 401, an insufficient capability is 403 — there is no
  unauthenticated path except ``/healthz`` and ``/readyz``.
* **No secret ever reaches a log line.** Request logging records method, path,
  status and duration. Bodies and headers are never logged.
* **Bounded input.** Bodies over 64 KiB are refused before they are read, so a
  request cannot exhaust the container's 128 MiB.
"""

from __future__ import annotations

import hmac
import json
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlparse

from . import crypto
from .policy import Policy, authenticate
from .store import SecretStore, StoreError

SERVICE_VERSION = "0.1.0"
MAX_BODY_BYTES = 64 * 1024
SECRETS_PREFIX = "/v1/secrets/"


@dataclass
class AppContext:
    store: SecretStore
    policies: list[Policy]
    allow_api_rotation: bool = False
    started_at: float = field(default_factory=time.time)
    request_counter: int = 0
    counter_lock: threading.Lock = field(default_factory=threading.Lock)

    def next_request_id(self) -> str:
        with self.counter_lock:
            self.request_counter += 1
            return f"req-{self.request_counter:06d}"


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


class SecretsHandler(BaseHTTPRequestHandler):
    server_version = f"secretsd/{SERVICE_VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------- plumbing

    @property
    def context(self) -> AppContext:
        return self.server.context  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - stdlib name
        """Silence the default stderr log; structured logging happens in _send."""
        return

    def _bearer_token(self) -> str | None:
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            return None
        token = header[7:].strip()
        return token or None

    def _require(self, action: str, secret_name: str | None = None) -> Policy:
        policy = authenticate(self.context.policies, self._bearer_token())
        if policy is None:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "unauthorized", "A valid bearer token is required.")
        if not policy.allows(action, secret_name):
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "forbidden",
                f"Token '{policy.name}' may not {action} this path.",
            )
        return policy

    def _read_json_body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ApiError(HTTPStatus.LENGTH_REQUIRED, "length_required", "Content-Length is required.")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "bad_length", "Content-Length is not a number.") from exc
        if length > MAX_BODY_BYTES:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large", f"Body exceeds {MAX_BODY_BYTES} bytes.")
        if length <= 0:
            raise ApiError(HTTPStatus.BAD_REQUEST, "empty_body", "A JSON body is required.")
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "bad_json", "Body is not valid UTF-8 JSON.") from exc
        if not isinstance(parsed, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "bad_json", "Body must be a JSON object.")
        return parsed

    def _send(self, status: HTTPStatus, payload: dict[str, Any], *, request_id: str, started: float) -> None:
        body = _json_bytes(payload)
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Request-Id", request_id)
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

        # Structured, value-free access log.
        entry = {
            "ts": round(time.time(), 3),
            "request_id": request_id,
            "method": self.command,
            "path": urlparse(self.path).path,
            "status": int(status),
            "duration_ms": round((time.time() - started) * 1000, 2),
            "client": self.client_address[0],
        }
        print(json.dumps(entry, sort_keys=True), flush=True)

    # -------------------------------------------------------------- routing

    def _dispatch(self) -> None:
        started = time.time()
        request_id = self.context.next_request_id()
        try:
            status, payload = self._route()
        except ApiError as error:
            status, payload = error.status, {"error": error.code, "message": error.message}
        except KeyError:
            status, payload = HTTPStatus.NOT_FOUND, {"error": "not_found", "message": "No such secret."}
        except StoreError as error:
            status, payload = HTTPStatus.BAD_REQUEST, {"error": "invalid_request", "message": str(error)}
        except crypto.CryptoError:
            # Never surface the underlying reason: it can distinguish "wrong key"
            # from "tampered ciphertext", which is useful to an attacker.
            status, payload = HTTPStatus.INTERNAL_SERVER_ERROR, {
                "error": "crypto_failure",
                "message": "The secret could not be decrypted.",
            }
        except Exception:  # noqa: BLE001 - last resort, never leak a traceback
            status, payload = HTTPStatus.INTERNAL_SERVER_ERROR, {
                "error": "internal_error",
                "message": "The request failed.",
            }
        self._send(status, payload, request_id=request_id, started=started)

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_DELETE = _dispatch
    do_HEAD = _dispatch

    def _route(self) -> tuple[HTTPStatus, dict[str, Any]]:
        path = urlparse(self.path).path.rstrip("/") or "/"
        method = self.command
        ctx = self.context

        if path == "/healthz" and method in {"GET", "HEAD"}:
            return HTTPStatus.OK, {"status": "ok", "service": "secretsd", "version": SERVICE_VERSION}

        if path == "/readyz" and method in {"GET", "HEAD"}:
            stats = ctx.store.stats()
            return HTTPStatus.OK, {"status": "ready", "secrets": stats["secrets"]}

        if path == "/v1/status" and method in {"GET", "HEAD"}:
            self._require("list")
            stats = ctx.store.stats()
            return HTTPStatus.OK, {
                "service": "secretsd",
                "version": SERVICE_VERSION,
                "uptime_seconds": round(time.time() - ctx.started_at, 1),
                "secrets": stats["secrets"],
                "master_key_fingerprint": stats["master_key_fingerprint"],
                "api_rotation_enabled": ctx.allow_api_rotation,
                "actors": [policy.describe() for policy in ctx.policies],
            }

        if path == "/v1/secrets":
            if method in {"GET", "HEAD"}:
                self._require("list")
                return HTTPStatus.OK, {"secrets": ctx.store.list_names()}
            raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed", f"{method} is not allowed here.")

        if path == "/v1/rotate":
            if method != "POST":
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed", "Rotation is POST only.")
            policy = self._require("rotate")
            if not ctx.allow_api_rotation:
                raise ApiError(
                    HTTPStatus.FORBIDDEN,
                    "rotation_disabled",
                    "API rotation is disabled; run the rotate command inside the container.",
                )
            body = self._read_json_body()
            new_key = body.get("new_master_key")
            if not isinstance(new_key, str):
                raise ApiError(HTTPStatus.BAD_REQUEST, "bad_request", "new_master_key must be a string.")
            master = crypto.load_master_key(new_key)
            count = ctx.store.rotate(master, actor=policy.name)
            return HTTPStatus.OK, {"rotated": count, "master_key_fingerprint": crypto.fingerprint(master)}

        if path.startswith(SECRETS_PREFIX):
            raw_name = path[len(SECRETS_PREFIX):]
            name = unquote(raw_name).strip("/")
            if not name:
                raise ApiError(HTTPStatus.BAD_REQUEST, "bad_request", "A secret name is required.")

            if method in {"GET", "HEAD"}:
                policy = self._require("read", name)
                value, meta = ctx.store.get(name, actor=policy.name)
                return HTTPStatus.OK, {
                    "name": name,
                    "value": value.decode("utf-8"),
                    "version": meta["version"],
                    "updated_at": meta["updated_at"],
                }

            if method == "PUT":
                policy = self._require("write", name)
                body = self._read_json_body()
                value = body.get("value")
                if not isinstance(value, str):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "bad_request", "value must be a string.")
                meta = ctx.store.put(name, value.encode("utf-8"), actor=policy.name)
                return HTTPStatus.CREATED, {"name": meta["name"], "version": meta["version"]}

            if method == "DELETE":
                policy = self._require("delete", name)
                result = ctx.store.delete(name, actor=policy.name)
                return HTTPStatus.OK, {"deleted": True, **result}

            raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed", f"{method} is not allowed here.")

        raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "Unknown endpoint.")


class SecretsServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], context: AppContext) -> None:
        self.context = context
        super().__init__(address, SecretsHandler)
