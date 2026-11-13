"""CLI export: prefix boundaries, .env safety, and lossless JSON."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secretsd import cli


class FakeVault:
    """Minimal stand-in for the HTTP API: listing plus per-name reads."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self.secrets = secrets

    def __call__(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        if method == "GET" and path == "/v1/secrets":
            return 200, {
                "secrets": [
                    {"name": name, "version": 1, "updated_at": "2026-01-01T00:00:00Z"}
                    for name in self.secrets
                ]
            }
        if method == "GET" and path.startswith("/v1/secrets/"):
            name = path[len("/v1/secrets/") :]
            return 200, {"name": name, "version": 1, "value": self.secrets[name]}
        raise AssertionError(f"unexpected request: {method} {path}")


class ExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "app.env"
        patcher = mock.patch.dict(os.environ, {"SECRETSD_TOKEN": "test-token"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_export(self, secrets: dict[str, str], *argv: str) -> int:
        with mock.patch.object(cli, "_request", FakeVault(secrets)):
            return cli.main(["export", *argv])

    def test_multiline_env_export_is_refused(self) -> None:
        secrets = {
            "shared/tls/key": "-----BEGIN KEY-----\nAAA\nBBB\n-----END KEY-----",
            "app/ci/token": "single-line",
        }
        code = self.run_export(secrets, "--format", "env", "--out", str(self.out))
        self.assertEqual(code, 1)
        self.assertFalse(self.out.exists(), "a refused export must not leave a partial file")

    def test_multiline_json_export_is_lossless(self) -> None:
        pem = "-----BEGIN KEY-----\nAAA\nBBB\n-----END KEY-----"
        code = self.run_export({"shared/tls/key": pem}, "--format", "json", "--out", str(self.out))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(self.out.read_text(encoding="utf-8")), {"SHARED_TLS_KEY": pem})

    def test_prefix_is_segment_aware(self) -> None:
        secrets = {"app/ci/deploy": "one", "app/ci-tokens/other": "two"}
        code = self.run_export(secrets, "--prefix", "app/ci", "--out", str(self.out))
        self.assertEqual(code, 0)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "APP_CI_DEPLOY=one\n")

    def test_variable_collision_is_refused(self) -> None:
        secrets = {"app/ci/token": "one", "app/ci-token": "two"}
        code = self.run_export(secrets, "--out", str(self.out))
        self.assertEqual(code, 1)
        self.assertFalse(self.out.exists())

    def test_values_containing_equals_survive_env_export(self) -> None:
        value = "base64padding=="
        code = self.run_export({"app/ci/token": value}, "--out", str(self.out))
        self.assertEqual(code, 0)
        self.assertEqual(self.out.read_text(encoding="utf-8"), f"APP_CI_TOKEN={value}\n")
        if os.name != "nt":  # NTFS cannot express 0600; the container check covers it
            self.assertEqual(self.out.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
