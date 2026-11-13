"""Service entrypoint.

    python -m secretsd                 # serve
    python -m secretsd --check         # validate configuration, then exit
    python -m secretsd --generate-key  # print a fresh master key
    python -m secretsd --hash-token    # read a token from stdin, print its sha256

Configuration is environment-only. Nothing is read from disk except the key
file, the policy file and the encrypted vault, so a container can be rotated by
replacing one environment variable.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from . import crypto
from .api import AppContext, SecretsServer
from .policy import PolicyError, load_policies
from .store import SecretStore, StoreError

DEFAULT_PORT = 8200
DEFAULT_BIND = "0.0.0.0"
DEFAULT_DATA_DIR = "/data"
DEFAULT_POLICY_FILE = "/etc/secretsd/policies.toml"


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip() or default


def _read_master_key() -> bytes:
    inline = _env("SECRETSD_MASTER_KEY")
    path = _env("SECRETSD_MASTER_KEY_FILE")

    if inline and path:
        raise SystemExit("Set either SECRETSD_MASTER_KEY or SECRETSD_MASTER_KEY_FILE, not both.")

    if path:
        try:
            text = Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemExit(f"Master key file is unreadable: {path}") from exc
        return crypto.load_master_key(text)

    if inline:
        return crypto.load_master_key(inline)

    raise SystemExit(
        "No master key configured. Set SECRETSD_MASTER_KEY (base64url, 32 bytes) or "
        "SECRETSD_MASTER_KEY_FILE. Generate one with: python -m secretsd --generate-key"
    )


def build_context() -> AppContext:
    port_text = _env("SECRETSD_PORT", str(DEFAULT_PORT)) or str(DEFAULT_PORT)
    try:
        port = int(port_text)
    except ValueError as exc:
        raise SystemExit("SECRETSD_PORT must be an integer.") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("SECRETSD_PORT must be between 1 and 65535.")

    data_dir = _env("SECRETSD_DATA_DIR", DEFAULT_DATA_DIR) or DEFAULT_DATA_DIR
    policy_file = _env("SECRETSD_POLICY_FILE", DEFAULT_POLICY_FILE) or DEFAULT_POLICY_FILE
    root_token = _env("SECRETSD_ROOT_TOKEN")
    allow_rotation = (_env("SECRETSD_ALLOW_API_ROTATION", "false") or "false").lower() in {"1", "true", "yes"}

    master = _read_master_key()

    try:
        policies = load_policies(policy_file, root_token=root_token)
    except PolicyError as exc:
        raise SystemExit(f"Policy configuration rejected: {exc}") from exc

    try:
        store = SecretStore(data_dir, master)
    except (StoreError, OSError) as exc:
        raise SystemExit(f"Vault could not be opened: {exc}") from exc

    context = AppContext(store=store, policies=policies, allow_api_rotation=allow_rotation)
    context.bind_address = (_env("SECRETSD_BIND", DEFAULT_BIND) or DEFAULT_BIND, port)  # type: ignore[attr-defined]
    return context


def serve() -> int:
    context = build_context()
    address = context.bind_address  # type: ignore[attr-defined]

    server = SecretsServer(address, context)
    stats = context.store.stats()

    print(
        f'{{"event":"startup","service":"secretsd","bind":"{address[0]}:{address[1]}",'
        f'"secrets":{stats["secrets"]},"key_fingerprint":"{stats["master_key_fingerprint"]}",'
        f'"actors":{len(context.policies)},"api_rotation":{str(context.allow_api_rotation).lower()}}}',
        flush=True,
    )

    def _stop(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print('{"event":"shutdown","reason":"signal"}', flush=True)
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secretsd", description="Secure secrets management sandbox")
    parser.add_argument("--check", action="store_true", help="validate configuration and exit")
    parser.add_argument("--generate-key", action="store_true", help="print a fresh master key and exit")
    parser.add_argument("--hash-token", action="store_true", help="read a token from stdin and print its sha256")
    args = parser.parse_args(argv)

    if args.generate_key:
        print(crypto.generate_master_key())
        return 0

    if args.hash_token:
        token = sys.stdin.readline().strip()
        if not token:
            print("No token on stdin.", file=sys.stderr)
            return 2
        from .policy import hash_token

        print(hash_token(token))
        return 0

    if args.check:
        context = build_context()
        stats = context.store.stats()
        print(
            f"configuration ok: secrets={stats['secrets']} "
            f"key_fingerprint={stats['master_key_fingerprint']} actors={len(context.policies)}"
        )
        return 0

    return serve()


if __name__ == "__main__":
    sys.exit(main())
