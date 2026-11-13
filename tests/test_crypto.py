"""Cryptographic invariants: round-trip, tamper detection, name binding, rotation."""

from __future__ import annotations

import unittest

from secretsd import crypto


class MasterKeyTests(unittest.TestCase):
    def test_generated_key_is_32_bytes(self) -> None:
        key = crypto.load_master_key(crypto.generate_master_key())
        self.assertEqual(len(key), crypto.KEY_BYTES)

    def test_rejects_wrong_length(self) -> None:
        with self.assertRaises(crypto.CryptoError):
            crypto.load_master_key("c2hvcnQ")  # "short"

    def test_rejects_single_repeated_byte(self) -> None:
        # 32 zero bytes: long enough, but obviously a placeholder.
        with self.assertRaises(crypto.CryptoError):
            crypto.load_master_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    def test_rejects_empty(self) -> None:
        with self.assertRaises(crypto.CryptoError):
            crypto.load_master_key("   ")


class EnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.master = crypto.load_master_key(crypto.generate_master_key())

    def test_round_trip(self) -> None:
        envelope = crypto.seal(self.master, b"s3cr3t-value", "app/db/password")
        self.assertEqual(crypto.open_envelope(self.master, envelope, "app/db/password"), b"s3cr3t-value")

    def test_ciphertext_is_not_plaintext(self) -> None:
        envelope = crypto.seal(self.master, b"visible-marker", "app/x")
        self.assertNotIn("visible-marker", str(envelope))

    def test_tampered_ciphertext_fails(self) -> None:
        envelope = crypto.seal(self.master, b"value", "app/x")
        raw = envelope["ciphertext"]
        envelope["ciphertext"] = ("A" if raw[0] != "A" else "B") + raw[1:]
        with self.assertRaises(crypto.CryptoError):
            crypto.open_envelope(self.master, envelope, "app/x")

    def test_wrong_master_key_fails(self) -> None:
        envelope = crypto.seal(self.master, b"value", "app/x")
        other = crypto.load_master_key(crypto.generate_master_key())
        with self.assertRaises(crypto.CryptoError):
            crypto.open_envelope(other, envelope, "app/x")

    def test_envelope_is_bound_to_its_name(self) -> None:
        envelope = crypto.seal(self.master, b"prod-only", "prod/api/key")
        with self.assertRaises(crypto.CryptoError):
            crypto.open_envelope(self.master, envelope, "dev/api/key")

    def test_each_seal_uses_fresh_nonces(self) -> None:
        first = crypto.seal(self.master, b"same", "app/x")
        second = crypto.seal(self.master, b"same", "app/x")
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])


class RotationTests(unittest.TestCase):
    def test_rewrap_keeps_value_readable(self) -> None:
        old = crypto.load_master_key(crypto.generate_master_key())
        new = crypto.load_master_key(crypto.generate_master_key())
        envelope = crypto.seal(old, b"rotate-me", "app/token")

        rotated = crypto.rewrap(old, new, envelope, "app/token")

        # Value survives; ciphertext is untouched (rotation is a re-wrap).
        self.assertEqual(crypto.open_envelope(new, rotated, "app/token"), b"rotate-me")
        self.assertEqual(rotated["ciphertext"], envelope["ciphertext"])
        # The old key no longer opens it.
        with self.assertRaises(crypto.CryptoError):
            crypto.open_envelope(old, rotated, "app/token")


if __name__ == "__main__":
    unittest.main()
