"""Policy engine: hash-only parsing, segment-aware prefixes, least privilege."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secretsd.policy import (
    Policy,
    PolicyError,
    authenticate,
    hash_token,
    load_policies,
)


def write_policy(body: str) -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8")
    handle.write(body)
    handle.close()
    return Path(handle.name)


class ParsingTests(unittest.TestCase):
    def test_loads_valid_policies(self) -> None:
        path = write_policy(
            """
[[tokens]]
name = "ci"
sha256 = "%s"
capabilities = ["read"]
paths = ["app/ci"]
""" % hash_token("token-one")
        )
        policies = load_policies(path)
        self.assertEqual(len(policies), 1)
        self.assertEqual(policies[0].name, "ci")
        path.unlink()

    def test_rejects_plaintext_token(self) -> None:
        path = write_policy(
            """
[[tokens]]
name = "bad"
token = "plaintext-is-not-allowed"
capabilities = ["read"]
"""
        )
        with self.assertRaises(PolicyError):
            load_policies(path)
        path.unlink()

    def test_rejects_unknown_capability(self) -> None:
        path = write_policy(
            """
[[tokens]]
name = "typo"
sha256 = "%s"
capabilities = ["raed"]
""" % hash_token("token-two")
        )
        with self.assertRaises(PolicyError):
            load_policies(path)
        path.unlink()

    def test_rejects_duplicate_hashes(self) -> None:
        digest = hash_token("same-token")
        path = write_policy(
            f"""
[[tokens]]
name = "a"
sha256 = "{digest}"
capabilities = ["read"]

[[tokens]]
name = "b"
sha256 = "{digest}"
capabilities = ["write"]
"""
        )
        with self.assertRaises(PolicyError):
            load_policies(path)
        path.unlink()

    def test_root_token_is_appended(self) -> None:
        policies = load_policies("/nonexistent/policies.toml", root_token="a-long-enough-root-token")
        self.assertEqual([p.name for p in policies], ["root"])
        self.assertTrue(policies[0].allows("rotate", "anything"))

    def test_short_root_token_rejected(self) -> None:
        with self.assertRaises(PolicyError):
            load_policies("/nonexistent/policies.toml", root_token="short")

    def test_missing_file_without_root_is_error(self) -> None:
        with self.assertRaises(PolicyError):
            load_policies("/nonexistent/policies.toml")


class AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = Policy(
            name="ci",
            sha256=hash_token("ci-token"),
            capabilities=frozenset({"read", "list"}),
            path_prefixes=("app/ci",),
        )

    def test_allows_exact_and_descendant_paths(self) -> None:
        self.assertTrue(self.policy.allows("read", "app/ci"))
        self.assertTrue(self.policy.allows("read", "app/ci/github"))

    def test_prefix_is_segment_aware(self) -> None:
        # The classic escalation: "app/ci" must not grant "app/ci-tokens".
        self.assertFalse(self.policy.allows("read", "app/ci-tokens"))
        self.assertFalse(self.policy.allows("read", "app/cinema"))

    def test_denies_unlisted_capability(self) -> None:
        self.assertFalse(self.policy.allows("write", "app/ci/github"))
        self.assertFalse(self.policy.allows("delete", "app/ci/github"))

    def test_wildcard_path_grants_everything_for_capability(self) -> None:
        root = Policy("root", hash_token("x"), frozenset({"read"}), ("*",))
        self.assertTrue(root.allows("read", "anywhere/at/all"))


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policies = [
            Policy("ci", hash_token("ci-token"), frozenset({"read"}), ("app/ci",)),
            Policy("ops", hash_token("ops-token"), frozenset({"read", "write"}), ("*",)),
        ]

    def test_valid_token_matches_its_policy(self) -> None:
        self.assertEqual(authenticate(self.policies, "ops-token").name, "ops")

    def test_unknown_token_is_none(self) -> None:
        self.assertIsNone(authenticate(self.policies, "not-a-token"))

    def test_missing_token_is_none(self) -> None:
        self.assertIsNone(authenticate(self.policies, None))
        self.assertIsNone(authenticate(self.policies, ""))


if __name__ == "__main__":
    unittest.main()
