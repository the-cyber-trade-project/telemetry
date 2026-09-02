"""Cryptographic engine for telemetry attestation, Ed25519 signatures, and SHA-256 proofs."""

import json
import hashlib
import hmac
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def canonical_json(data: Dict[str, Any]) -> str:
    """Serializes a dictionary into deterministic canonical JSON (RFC 8785)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hash(data: str) -> str:
    """Computes standard SHA-256 hex digest."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates a new Ed25519 private/public keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def export_private_key_pem(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Exports private key to PKCS8 PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def export_public_key_pem(public_key: ed25519.Ed25519PublicKey) -> str:
    """Exports public key to SubjectPublicKeyInfo PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def load_private_key_pem(pem_str: str) -> ed25519.Ed25519PrivateKey:
    """Loads private key from PEM string."""
    return serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)


def load_public_key_pem(pem_str: str) -> ed25519.Ed25519PublicKey:
    """Loads public key from PEM string."""
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def sign_payload(data: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> str:
    """Signs canonical representation of payload using Ed25519."""
    raw = canonical_json(data).encode("utf-8")
    signature = private_key.sign(raw)
    return signature.hex()


def verify_signature(data: Dict[str, Any], signature_hex: str, public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verifies Ed25519 signature in constant time against canonical payload."""
    try:
        raw = canonical_json(data).encode("utf-8")
        sig_bytes = bytes.fromhex(signature_hex)
        public_key.verify(sig_bytes, raw)
        return True
    except Exception:
        return False


def verify_hash_constant_time(expected: str, actual: str) -> bool:
    """Performs constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(expected, actual)
