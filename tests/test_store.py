"""Store behaviour: versions, atomic persistence, rotation, audit hygiene."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from secretsd import crypto
from secretsd.store import SecretStore, StoreError


class StoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.master = crypto.load_master_key(crypto.generate_master_key())
        self.store = SecretStore(self.dir, self.master)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_put_get_round_trip(self) -> None:
        meta = self.store.put("app/db_password", b"hunter2", actor="root")
        self.assertEqual(meta["version"], 1)
        value, read_meta = self.store.get("app/db_password", actor="root")
        self.assertEqual(value, b"hunter2")
        self.assertEqual(read_meta["version"], 1)

    def test_version_increments_on_overwrite(self) -> None:
        self.store.put("app/token", b"one", actor="root")
        meta = self.store.put("app/token", b"two", actor="root")
        self.assertEqual(meta["version"], 2)
        value, _ = self.store.get("app/token", actor="root")
        self.assertEqual(value, b"two")

    def test_unknown_secret_raises_key_error(self) -> None:
        with self.assertRaises(KeyError):
            self.store.get("app/missing", actor="root")

    def test_invalid_names_rejected(self) -> None:
        for bad in ("", "..", "app/../etc/passwd", "app/ token", "-leading-dash"):
            with self.assertRaises(StoreError, msg=bad):
                self.store.put(bad, b"x", actor="root")

    def test_empty_value_rejected(self) -> None:
        with self.assertRaises(StoreError):
            self.store.put("app/empty", b"", actor="root")

    def test_vault_on_disk_is_ciphertext_only(self) -> None:
        self.store.put("app/plain", b"THIS-MUST-NOT-APPEAR", actor="root")
        raw = (self.dir / "secrets.json").read_text(encoding="utf-8")
        self.assertNotIn("THIS-MUST-NOT-APPEAR", raw)
        document = json.loads(raw)
        self.assertEqual(document["schema"], 1)
        self.assertIn("ciphertext", document["records"]["app/plain"]["envelope"])

    def test_audit_log_never_contains_values(self) -> None:
        self.store.put("app/audited", b"AUDIT-CANARY-1234", actor="root")
        self.store.get("app/audited", actor="root")
        log = (self.dir / "audit.log").read_text(encoding="utf-8")
        self.assertNotIn("AUDIT-CANARY-1234", log)
        self.assertIn('"action": "write"', log)
        self.assertIn('"action": "read"', log)

    def test_persists_across_reopen(self) -> None:
        self.store.put("app/persisted", b"still-here", actor="root")
        reopened = SecretStore(self.dir, self.master)
        value, _ = reopened.get("app/persisted", actor="root")
        self.assertEqual(value, b"still-here")

    def test_rotate_rewraps_and_survives_restart(self) -> None:
        self.store.put("app/one", b"first", actor="root")
        self.store.put("app/two", b"second", actor="root")

        new_master = crypto.load_master_key(crypto.generate_master_key())
        self.assertEqual(self.store.rotate(new_master, actor="root"), 2)

        value, _ = self.store.get("app/one", actor="root")
        self.assertEqual(value, b"first")

        reopened = SecretStore(self.dir, new_master)
        self.assertEqual(reopened.get("app/two", actor="root")[0], b"second")

        # The old key must no longer open the vault.
        stale = SecretStore(self.dir, self.master)
        with self.assertRaises(crypto.CryptoError):
            stale.get("app/one", actor="root")

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not meaningful on Windows")
    def test_files_are_owner_only(self) -> None:
        self.store.put("app/perm", b"x", actor="root")
        self.assertEqual(self.dir.joinpath("secrets.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.dir.joinpath("audit.log").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
