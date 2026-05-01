"""
AES-256-GCM authenticated encryption with HKDF-SHA256 key derivation.

Security properties:
  - AES-256-GCM:  authenticated encryption (confidentiality + integrity + authenticity)
  - HKDF-SHA256:  secure key derivation from the one-time code + public salt
  - X25519 ECDH:  optional SDK-to-SDK direct secure channel
  - All secrets:  stored as SHA-256 hashes only; raw values returned once to caller
"""

import os
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag  # noqa: F401 – re-exported for callers


# Canonical HKDF info string versioned so future changes are detectable
KDF_INFO = b"otc-secure-comm-v1"


class CryptoEngine:
    OTC_BYTES = 32      # 256-bit one-time code
    SALT_BYTES = 32     # 256-bit HKDF salt (public, stored in DB)
    KEY_BYTES = 32      # AES-256
    NONCE_BYTES = 12    # GCM standard nonce (96-bit)

    # ------------------------------------------------------------------ OTC

    @classmethod
    def generate_otc(cls) -> bytes:
        return os.urandom(cls.OTC_BYTES)

    @classmethod
    def generate_salt(cls) -> bytes:
        return os.urandom(cls.SALT_BYTES)

    @classmethod
    def encode_b64url(cls, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @classmethod
    def decode_b64url(cls, s: str) -> bytes:
        pad = 4 - len(s) % 4
        if pad != 4:
            s += "=" * pad
        return base64.urlsafe_b64decode(s)

    @classmethod
    def hash_secret(cls, secret: bytes) -> str:
        """One-way SHA-256 hash for DB storage."""
        return hashlib.sha256(secret).hexdigest()

    @classmethod
    def verify_secret(cls, secret: bytes, stored_hash: str) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        computed = hashlib.sha256(secret).hexdigest()
        return hmac.compare_digest(computed.encode(), stored_hash.encode())

    # ------------------------------------------------------------------ KDF

    @classmethod
    def derive_session_key(cls, otc: bytes, salt: bytes) -> bytes:
        """
        HKDF-SHA256(IKM=otc, salt=salt, info=KDF_INFO) → 32-byte AES key.
        Both parties call this locally; the server never calls it.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=cls.KEY_BYTES,
            salt=salt,
            info=KDF_INFO,
            backend=default_backend(),
        )
        return hkdf.derive(otc)

    # ------------------------------------------------------------------ AES-256-GCM

    @classmethod
    def encrypt(cls, key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        AES-256-GCM encrypt.
        Returns: random_nonce (12 B) || ciphertext || auth_tag (16 B)
        """
        nonce = os.urandom(cls.NONCE_BYTES)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad or None)
        return nonce + ciphertext

    @classmethod
    def decrypt(cls, key: bytes, data: bytes, aad: bytes = b"") -> bytes:
        """
        AES-256-GCM decrypt.
        Raises cryptography.exceptions.InvalidTag on auth failure.
        """
        if len(data) < cls.NONCE_BYTES + 16:
            raise ValueError("Ciphertext too short to be valid")
        nonce = data[: cls.NONCE_BYTES]
        ciphertext = data[cls.NONCE_BYTES :]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad or None)

    # ------------------------------------------------------------------ API keys

    @classmethod
    def generate_api_key(cls) -> tuple[str, str]:
        """Returns (raw_key, stored_hash). Only ever persist the hash."""
        raw = "otc_sk_" + cls.encode_b64url(os.urandom(32))
        return raw, cls.hash_secret(raw.encode())

    @classmethod
    def verify_api_key(cls, raw_key: str, stored_hash: str) -> bool:
        return cls.verify_secret(raw_key.encode(), stored_hash)

    # ------------------------------------------------------------------ X25519 ECDH (SDK direct channel)

    @classmethod
    def generate_x25519_keypair(cls) -> tuple[str, str]:
        """Returns (private_b64, public_b64) for SDK-to-SDK ECDH."""
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode()

    @classmethod
    def x25519_shared_secret(cls, private_b64: str, peer_public_b64: str) -> bytes:
        """Compute X25519 shared secret. Feed into HKDF before use as a key."""
        priv = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
        pub = X25519PublicKey.from_public_bytes(base64.b64decode(peer_public_b64))
        return priv.exchange(pub)
