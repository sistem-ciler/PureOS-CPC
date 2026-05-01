"""
Client-side cryptography for the OTC Secure Communication SDK.

Key principle: The server NEVER sees plaintext. All encryption and decryption
happens here, on the client. The server only stores and relays ciphertext blobs.

Usage:
    # Party A (session creator)
    crypto_a = SessionCrypto.from_otc(otc, kdf_salt, kdf_info)
    ciphertext_b64 = crypto_a.encrypt_message("Hello from A!")

    # Party B (redeemer) — derives the identical key from the same inputs
    crypto_b = SessionCrypto.from_otc(otc, kdf_salt, kdf_info)
    plaintext = crypto_b.decrypt_message(ciphertext_b64)
"""

import os
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


class SessionCrypto:
    """
    Holds the derived AES-256-GCM session key.
    Instantiate via SessionCrypto.from_otc(...) — never pass a raw key directly.
    """

    _NONCE_BYTES = 12   # GCM standard 96-bit nonce
    _KEY_BYTES = 32     # AES-256

    def __init__(self, session_key: bytes):
        if len(session_key) != self._KEY_BYTES:
            raise ValueError("Session key must be 32 bytes")
        self._key = session_key

    # ------------------------------------------------------------------ factory

    @classmethod
    def from_otc(cls, otc: str, kdf_salt: str, kdf_info: str = "otc-secure-comm-v1") -> "SessionCrypto":
        """
        Derive the session key from the one-time code.

        Args:
            otc:      URL-safe base64 OTC returned by the server on session creation
                      or passed out-of-band to the redeemer.
            kdf_salt: URL-safe base64 salt returned in SessionCreatedResponse /
                      RedeemOTCResponse.
            kdf_info: Canonical info string from the same responses.
        """
        otc_bytes = cls._decode_b64url(otc)
        salt_bytes = cls._decode_b64url(kdf_salt)
        info_bytes = kdf_info.encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=cls._KEY_BYTES,
            salt=salt_bytes,
            info=info_bytes,
            backend=default_backend(),
        )
        key = hkdf.derive(otc_bytes)
        return cls(key)

    # ------------------------------------------------------------------ encrypt / decrypt

    def encrypt_message(self, plaintext: str, aad: str = "") -> str:
        """
        Encrypt a UTF-8 string. Returns standard base64 ciphertext suitable for
        posting to POST /sessions/{id}/messages.

        Format: base64( random_nonce(12B) || AES-GCM-ciphertext+tag )
        """
        nonce = os.urandom(self._NONCE_BYTES)
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            aad.encode("utf-8") if aad else None,
        )
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt_message(self, ciphertext_b64: str, aad: str = "") -> str:
        """
        Decrypt a ciphertext blob received from GET /sessions/{id}/messages.
        Raises InvalidTag if the message has been tampered with.
        """
        data = base64.b64decode(ciphertext_b64)
        if len(data) < self._NONCE_BYTES + 16:
            raise ValueError("Ciphertext too short")
        nonce = data[: self._NONCE_BYTES]
        ct = data[self._NONCE_BYTES :]
        aesgcm = AESGCM(self._key)
        plaintext = aesgcm.decrypt(
            nonce,
            ct,
            aad.encode("utf-8") if aad else None,
        )
        return plaintext.decode("utf-8")

    def encrypt_bytes(self, data: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(self._NONCE_BYTES)
        aesgcm = AESGCM(self._key)
        return nonce + aesgcm.encrypt(nonce, data, aad or None)

    def decrypt_bytes(self, data: bytes, aad: bytes = b"") -> bytes:
        nonce = data[: self._NONCE_BYTES]
        aesgcm = AESGCM(self._key)
        return aesgcm.decrypt(nonce, data[self._NONCE_BYTES :], aad or None)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _decode_b64url(s: str) -> bytes:
        pad = 4 - len(s) % 4
        if pad != 4:
            s += "=" * pad
        return base64.urlsafe_b64decode(s)

    @staticmethod
    def generate_keypair_x25519() -> tuple[str, str]:
        """
        Generate an X25519 keypair for direct (server-bypass) ECDH channels.
        Returns (private_b64, public_b64). Keep private_b64 secret.
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization

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

    @staticmethod
    def derive_from_ecdh(private_b64: str, peer_public_b64: str, salt: str = "", info: str = "ecdh-channel-v1") -> "SessionCrypto":
        """
        Derive a session key via X25519 ECDH + HKDF.
        Both sides call this with their own private key and the peer's public key.
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

        priv = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
        pub = X25519PublicKey.from_public_bytes(base64.b64decode(peer_public_b64))
        shared_secret = priv.exchange(pub)

        salt_bytes = base64.b64decode(salt) if salt else None
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            info=info.encode(),
            backend=default_backend(),
        )
        key = hkdf.derive(shared_secret)
        return SessionCrypto(key)
