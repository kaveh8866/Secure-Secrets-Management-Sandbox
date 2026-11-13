"""Operator CLI — `vaultctl`.

Talks to a running service over HTTP. The token comes from ``SECRETSD_TOKEN``
and is kept in memory only: it is never placed on the command line (where it
would land in shell history and in ``ps``) and never written to disk.

    vaultctl put prod/stripe_key --value-file ./stripe.key
    vaultctl get prod/stripe_key
    vaultctl list
    vaultctl export --format env --out ./app.env
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_URL = "http://127.0.0.1:8200"
TIMEOUT_SECONDS = 10


class CliError(Exception):
    pass


def _base_url() -> str:
    return (os.environ.get("SECRETSD_URL") or DEFAULT_URL).rstrip("/")


def _token() -> str:
    token = os.environ.get("SECRETSD_TOKEN", "").strip()
    if not token:
        raise CliError("SECRETSD_TOKEN is not set. Export a token before running vaultctl.")
    return token


def _request(method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    url = f"{_base_url()}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {_token()}")
    if data is not None:
        request.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
            message = parsed.get("message") or parsed.get("error") or body
        except json.JSONDecodeError:
            message = body
        raise CliError(f"{error.code}: {message}") from error
    except urllib.error.URLError as error:
        raise CliError(f"Cannot reach {_base_url()}: {error.reason}") from error


def _quote(name: str) -> str:
    return urllib.parse.quote(name, safe="").replace("%2F", "/")


def _read_value(args: argparse.Namespace) -> str:
    if args.value is not None:
        raise CliError("Refusing --value: it leaks into shell history. Use --value-file or stdin.")
    if args.value_file:
        try:
            return Path(args.value_file).read_text(encoding="utf-8").rstrip("\n")
        except OSError as exc:
            raise CliError(f"Cannot read {args.value_file}") from exc
    if sys.stdin.isatty():
        raise CliError("No value supplied. Pipe it on stdin or use --value-file.")
    return sys.stdin.read().rstrip("\n")


def env_name(secret_name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", secret_name).strip("_").upper()
    return cleaned or "SECRET"


def cmd_put(args: argparse.Namespace) -> int:
    value = _read_value(args)
    status, body = _request("PUT", f"/v1/secrets/{_quote(args.name)}", {"value": value})
    print(f"{body.get('name')}: version {body.get('version')} ({status})")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    _status, body = _request("GET", f"/v1/secrets/{_quote(args.name)}")
    if args.raw:
        print(body.get("value", ""))
    else:
        print(json.dumps({k: v for k, v in body.items() if k != "value"}, indent=2))
        print(f"value: {len(body.get('value', ''))} bytes (use --raw to print it)")
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    _status, body = _request("GET", "/v1/secrets")
    for entry in body.get("secrets", []):
        print(f"{entry['name']}\tv{entry['version']}\t{entry['updated_at']}")
    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    _status, body = _request("DELETE", f"/v1/secrets/{_quote(args.name)}")
    print(f"{body.get('name')}: deleted v{body.get('deleted_version')}")
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    _status, body = _request("GET", "/v1/status")
    print(json.dumps(body, indent=2))
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    key_file = Path(args.new_key_file)
    if not key_file.exists():
        raise CliError(f"New master key file not found: {key_file}")
    new_key = key_file.read_text(encoding="utf-8").strip()
    _status, body = _request("POST", "/v1/rotate", {"new_master_key": new_key})
    print(f"rotated {body.get('rotated')} secret(s); new fingerprint {body.get('master_key_fingerprint')}")
    return 0


def _under_prefix(name: str, prefix: str) -> bool:
    """Segment-aware prefix match: `app/ci` covers `app/ci/x`, never `app/ci-tokens`."""
    prefix = prefix.strip("/")
    return not prefix or name == prefix or name.startswith(prefix + "/")


def cmd_export(args: argparse.Namespace) -> int:
    _status, listing = _request("GET", "/v1/secrets")
    rendered: dict[str, str] = {}
    for entry in listing.get("secrets", []):
        if not _under_prefix(entry["name"], args.prefix or ""):
            continue
        _status, body = _request("GET", f"/v1/secrets/{_quote(entry['name'])}")
        variable = env_name(entry["name"])
        if variable in rendered:
            raise CliError(
                f"Two secrets map to the same variable {variable}; export them separately with --prefix."
            )
        rendered[variable] = body.get("value", "")

    if args.format == "json":
        output = json.dumps(rendered, indent=2) + "\n"
    else:
        multiline = sorted(k for k, v in rendered.items() if "\n" in v or "\r" in v)
        if multiline:
            # Writing these as-is would split one secret across several lines and
            # silently produce bogus variables (a PEM block becomes four keys).
            raise CliError(
                "Refusing --format env: multiline value(s) "
                + ", ".join(multiline)
                + " cannot be represented in a .env file. Use --format json, or --prefix to exclude them."
            )
        output = "".join(f"{variable}={value}\n" for variable, value in rendered.items())

    if args.out:
        target = Path(args.out)
        if target.exists() and not args.force:
            raise CliError(f"{target} exists; pass --force to overwrite.")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(output)
        os.chmod(target, 0o600)
        print(f"wrote {len(rendered)} variable(s) to {target} (mode 0600)", file=sys.stderr)
    else:
        sys.stdout.write(output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultctl", description="CLI for the secrets sandbox")
    sub = parser.add_subparsers(dest="command", required=True)

    put = sub.add_parser("put", help="create or replace a secret")
    put.add_argument("name")
    put.add_argument("--value-file", help="read the value from this file")
    put.add_argument("--value", help="unsupported: leaks into shell history")
    put.set_defaults(func=cmd_put)

    get = sub.add_parser("get", help="read a secret")
    get.add_argument("name")
    get.add_argument("--raw", action="store_true", help="print only the value")
    get.set_defaults(func=cmd_get)

    listing = sub.add_parser("list", help="list secret names and versions")
    listing.set_defaults(func=cmd_list)

    rm = sub.add_parser("rm", help="delete a secret")
    rm.add_argument("name")
    rm.set_defaults(func=cmd_rm)

    status = sub.add_parser("status", help="service status")
    status.set_defaults(func=cmd_status)

    rotate = sub.add_parser("rotate", help="re-wrap secrets under a new master key")
    rotate.add_argument("--new-key-file", required=True)
    rotate.set_defaults(func=cmd_rotate)

    export = sub.add_parser("export", help="render secrets as env or json")
    export.add_argument("--format", choices=("env", "json"), default="env")
    export.add_argument("--prefix", help="only secrets under this prefix")
    export.add_argument("--out", help="write to this file with mode 0600")
    export.add_argument("--force", action="store_true")
    export.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
