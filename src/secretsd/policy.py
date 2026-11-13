"""Token policies: SHA-256 hashes only, least privilege by path prefix.

The policy file never contains a token. It contains the SHA-256 of a token, so
the file can be committed, mounted read-only, and reviewed in a pull request
without leaking anything usable. Tokens themselves live in the environment,
which stays out of Git.

Matching rules:

* ``*`` as a path grants the capability for every secret;
* ``team/api`` grants it for ``team/api`` and ``team/api/<anything>``;
* prefix matching is segment-aware, so ``team/api`` does **not** grant
  ``team/api-keys`` — the classic string-prefix privilege escalation.

Unknown tokens are rejected in constant time against every known hash, so the
response time does not reveal which prefix was close.
"""

from __future__ import annotations

import hashlib
import hmac
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

VALID_ACTIONS = frozenset({"read", "write", "delete", "list", "rotate"})


class PolicyError(Exception):
    """The policy file is missing, malformed, or contains plaintext tokens."""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Policy:
    name: str
    sha256: str
    capabilities: frozenset[str]
    path_prefixes: tuple[str, ...] = field(default_factory=tuple)

    def allows(self, action: str, secret_name: str | None = None) -> bool:
        if action not in self.capabilities:
            return False
        if secret_name is None or "*" in self.path_prefixes:
            return True
        return any(
            secret_name == prefix or secret_name.startswith(f"{prefix}/")
            for prefix in self.path_prefixes
        )

    def describe(self) -> dict[str, object]:
        """Safe projection for the status endpoint — no hash is returned."""
        return {
            "name": self.name,
            "capabilities": sorted(self.capabilities),
            "paths": list(self.path_prefixes) or ["*"],
        }


def _parse_policy(document: dict, index: int) -> Policy:
    entry = document
    if not isinstance(entry, dict):
        raise PolicyError(f"tokens[{index}] must be a table.")

    name = str(entry.get("name", "")).strip()
    if not name:
        raise PolicyError(f"tokens[{index}] has no name.")

    if "token" in entry:
        raise PolicyError(
            f"Policy '{name}' contains a plaintext 'token'. Store 'sha256' instead "
            "(python -m secretsd --hash-token)."
        )

    digest = str(entry.get("sha256", "")).strip().lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise PolicyError(f"Policy '{name}' has no valid sha256 field.")

    raw_capabilities = entry.get("capabilities", [])
    if not isinstance(raw_capabilities, list) or not raw_capabilities:
        raise PolicyError(f"Policy '{name}' declares no capabilities.")
    capabilities = frozenset(str(item).strip().lower() for item in raw_capabilities)
    unknown = capabilities - VALID_ACTIONS
    if unknown:
        raise PolicyError(f"Policy '{name}' has unknown capabilities: {sorted(unknown)}.")

    raw_paths = entry.get("paths", ["*"])
    if not isinstance(raw_paths, list) or not raw_paths:
        raise PolicyError(f"Policy '{name}' has an invalid paths list.")
    prefixes = tuple(str(item).strip().strip("/") for item in raw_paths if str(item).strip())
    if not prefixes:
        raise PolicyError(f"Policy '{name}' has an empty path prefix.")

    return Policy(name=name, sha256=digest, capabilities=capabilities, path_prefixes=prefixes)


def load_policies(path: str | Path, *, root_token: str | None = None) -> list[Policy]:
    policies: list[Policy] = []
    target = Path(path)

    if target.exists():
        try:
            document = tomllib.loads(target.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError("Policy file is unreadable or not valid TOML.") from exc
        tokens = document.get("tokens", [])
        if not isinstance(tokens, list):
            raise PolicyError("Policy file must declare [[tokens]] entries.")
        policies = [_parse_policy(entry, index) for index, entry in enumerate(tokens)]
    elif root_token is None:
        raise PolicyError(f"Policy file not found: {target}")

    if root_token:
        if len(root_token) < 16:
            raise PolicyError("SECRETSD_ROOT_TOKEN must be at least 16 characters.")
        policies.append(
            Policy(
                name="root",
                sha256=hash_token(root_token),
                capabilities=frozenset(VALID_ACTIONS),
                path_prefixes=("*",),
            )
        )

    if not policies:
        raise PolicyError("No tokens are configured; the service would reject every request.")

    digests = [policy.sha256 for policy in policies]
    if len(set(digests)) != len(digests):
        raise PolicyError("Two policies share the same token hash.")

    return policies


def authenticate(policies: list[Policy], token: str | None) -> Policy | None:
    """Constant-time token lookup. Returns None for unknown or missing tokens."""
    if not token:
        return None
    presented = hash_token(token).encode("ascii")
    matched: Policy | None = None
    for policy in policies:
        # compare_digest on equal-length hex digests keeps this constant-time;
        # every policy is always compared, so timing does not reveal position.
        if hmac.compare_digest(presented, policy.sha256.encode("ascii")):
            matched = policy
    return matched
