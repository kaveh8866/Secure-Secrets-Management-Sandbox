"""Encrypted, single-file secret store.

The store is a JSON document of *envelopes* — never plaintext. It is written
atomically (temp file, fsync, rename) so a crash cannot leave a half-written
vault, and it only ever holds ciphertext, names, versions and timestamps.

The audit trail is append-only JSONL and is deliberately value-free: it records
who touched which secret, never what the secret was. A secrets manager whose
own logs contain the credentials is not a secrets manager.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import crypto

NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$")
MAX_VALUE_BYTES = 16 * 1024
SCHEMA_VERSION = 1


class StoreError(Exception):
    """Operational failure (bad name, missing secret, corrupt vault)."""


class SecretStore:
    def __init__(self, data_dir: str | Path, master_key: bytes, *, clock: Callable[[], float] = time.time) -> None:
        self.root = Path(data_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.vault_path = self.root / "secrets.json"
        self.audit_path = self.root / "audit.log"
        self._master = master_key
        self._clock = clock
        self._lock = threading.RLock()
        self._records: dict[str, dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------ io

    def _load(self) -> None:
        if not self.vault_path.exists():
            self._records = {}
            return
        try:
            document = json.loads(self.vault_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StoreError("Vault file is unreadable or not valid JSON.") from exc
        if document.get("schema") != SCHEMA_VERSION:
            raise StoreError(f"Unsupported vault schema: {document.get('schema')!r}.")
        records = document.get("records")
        if not isinstance(records, dict):
            raise StoreError("Vault file has no records object.")
        self._records = records

    def _save(self) -> None:
        payload = json.dumps(
            {"schema": SCHEMA_VERSION, "records": self._records},
            indent=2,
            sort_keys=True,
        )
        directory = str(self.root)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".secrets-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.vault_path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _audit(self, event: dict[str, Any]) -> None:
        line = json.dumps({"ts": int(self._clock()), **event}, sort_keys=True)
        # ctime is created lazily; 0600 before any secret name is written.
        new_file = not self.audit_path.exists()
        with self.audit_path.open("a", encoding="utf-8") as handle:
            if new_file:
                os.chmod(self.audit_path, 0o600)
            handle.write(line + "\n")

    # --------------------------------------------------------------- public

    @staticmethod
    def validate_name(name: str) -> str:
        candidate = (name or "").strip().strip("/")
        if not NAME_PATTERN.match(candidate) or ".." in candidate:
            raise StoreError(
                "Secret name must match [a-zA-Z0-9][a-zA-Z0-9._/-]{0,127} and must not contain '..'."
            )
        return candidate

    def put(self, name: str, value: bytes, *, actor: str) -> dict[str, Any]:
        if not value:
            raise StoreError("Secret value is empty.")
        if len(value) > MAX_VALUE_BYTES:
            raise StoreError(f"Secret value exceeds {MAX_VALUE_BYTES} bytes.")
        key = self.validate_name(name)
        with self._lock:
            now = int(self._clock())
            existing = self._records.get(key)
            version = int(existing["version"]) + 1 if existing else 1
            envelope = crypto.seal(self._master, value, key)
            self._records[key] = {
                "version": version,
                "created_at": existing["created_at"] if existing else now,
                "updated_at": now,
                "envelope": envelope,
            }
            self._save()
            self._audit({"action": "write", "name": key, "actor": actor, "version": version})
            return {"name": key, "version": version, "updated_at": now}

    def get(self, name: str, *, actor: str) -> tuple[bytes, dict[str, Any]]:
        key = self.validate_name(name)
        with self._lock:
            record = self._records.get(key)
            if record is None:
                raise KeyError(key)
            plaintext = crypto.open_envelope(self._master, record["envelope"], key)
            self._audit({"action": "read", "name": key, "actor": actor, "version": record["version"]})
            return plaintext, {"version": record["version"], "updated_at": record["updated_at"]}

    def delete(self, name: str, *, actor: str) -> dict[str, Any]:
        key = self.validate_name(name)
        with self._lock:
            record = self._records.pop(key, None)
            if record is None:
                raise KeyError(key)
            self._save()
            self._audit({"action": "delete", "name": key, "actor": actor, "version": record["version"]})
            return {"name": key, "deleted_version": record["version"]}

    def list_names(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {"name": name, "version": record["version"], "updated_at": record["updated_at"]}
                for name, record in sorted(self._records.items())
            ]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "secrets": len(self._records),
                "schema": SCHEMA_VERSION,
                "master_key_fingerprint": crypto.fingerprint(self._master),
            }

    def rotate(self, new_master: bytes, *, actor: str) -> int:
        """Re-wrap every DEK under a new master key. Values stay sealed."""
        with self._lock:
            rotated: dict[str, dict[str, Any]] = {}
            for name, record in self._records.items():
                envelope = crypto.rewrap(self._master, new_master, record["envelope"], name)
                rotated[name] = {**record, "envelope": envelope}
            previous = self._records
            self._records = rotated
            self._master = new_master
            try:
                self._save()
            except BaseException:
                self._records = previous
                raise
            self._audit({"action": "rotate", "count": len(rotated), "actor": actor})
            return len(rotated)
