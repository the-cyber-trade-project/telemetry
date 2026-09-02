"""Tests for cryptographic signing, canonical JSON, and Ed25519 verification."""

import pytest
from cyber_trade_telemetry.crypto import (
    canonical_json,
    sha256_hash,
    generate_keypair,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
    sign_payload,
    verify_signature,
    verify_hash_constant_time
)


def test_canonical_json_determinism():
    data1 = {"b": 2, "a": 1, "nested": {"z": "end", "m": "mid"}}
    data2 = {"nested": {"m": "mid", "z": "end"}, "a": 1, "b": 2}
    assert canonical_json(data1) == canonical_json(data2)
    assert canonical_json(data1) == '{"a":1,"b":2,"nested":{"m":"mid","z":"end"}}'


def test_keypair_generation_and_pem_roundtrip():
    priv, pub = generate_keypair()
    priv_pem = export_private_key_pem(priv)
    pub_pem = export_public_key_pem(pub)

    assert "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem

    loaded_priv = load_private_key_pem(priv_pem)
    loaded_pub = load_public_key_pem(pub_pem)

    payload = {"employer_id": "PEC-EMP-2026-0014", "compliant": True}
    sig = sign_payload(payload, loaded_priv)
    assert verify_signature(payload, sig, loaded_pub) is True


def test_signature_tamper_detection():
    priv, pub = generate_keypair()
    payload = {"employer_id": "PEC-EMP-2026-0014", "ratio": 1.5}
    sig = sign_payload(payload, priv)

    # Valid check
    assert verify_signature(payload, sig, pub) is True

    # Tampered payload check
    tampered = {"employer_id": "PEC-EMP-2026-0014", "ratio": 3.0}
    assert verify_signature(tampered, sig, pub) is False


def test_constant_time_comparison():
    h1 = sha256_hash("test_string_1")
    h2 = sha256_hash("test_string_1")
    h3 = sha256_hash("test_string_2")

    assert verify_hash_constant_time(h1, h2) is True
    assert verify_hash_constant_time(h1, h3) is False
