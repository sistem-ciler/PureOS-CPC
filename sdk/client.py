"""
OTC Secure Communication — Python SDK client.

Handles all API calls and integrates with SessionCrypto for end-to-end encryption.

Quick start:
    client = OTCClient("https://your-server", api_key="otc_sk_...")

    # Party A: create a session and get the OTC
    session = client.create_session(label="contract-review")
    otc = session["otc"]                   # share this out-of-band with Party B
    crypto_a = client.session_crypto(session)

    # Party A: send a message
    client.send_message(session["session_id"], crypto_a.encrypt_message("Hi B!"))

    # Party B: redeem the OTC
    client_b = OTCClient("https://your-server", access_token="...")
    redeemed = client_b.redeem_session(session["session_id"], otc)
    crypto_b = OTCClient.session_crypto_from_redeem(redeemed, otc)

    # Party B: read messages
    msgs = client_b.get_messages(session["session_id"])
    for m in msgs:
        print(crypto_b.decrypt_message(m["ciphertext_b64"]))
"""

from __future__ import annotations

import httpx
from typing import Any

from sdk.crypto import SessionCrypto


class OTCError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class OTCClient:
    def __init__(
        self,
        base_url: str,
        *,
        access_token: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
    ):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._access_token = access_token
        self._api_key = api_key

    # ------------------------------------------------------------------ auth helpers

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json"}
        if self._access_token:
            h["Authorization"] = f"Bearer {self._access_token}"
        elif self._api_key:
            h["X-API-Key"] = self._api_key
        return h

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = f"{self._base_url}{path}"
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.request(method, url, headers=self._headers(), **kwargs)
        if not resp.is_success:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise OTCError(resp.status_code, detail)
        if resp.status_code == 204:
            return None
        return resp.json()

    # ------------------------------------------------------------------ auth

    @classmethod
    def register(cls, base_url: str, email: str, password: str, tenant_name: str) -> dict:
        """Register a new tenant + admin user. Returns tokens and the one-time API key."""
        url = f"{base_url.rstrip('/')}/auth/register"
        resp = httpx.post(url, json={"email": email, "password": password, "tenant_name": tenant_name})
        if not resp.is_success:
            raise OTCError(resp.status_code, resp.text)
        return resp.json()

    def login(self, email: str, password: str) -> dict:
        data = self._request("POST", "/auth/login", json={"email": email, "password": password})
        self._access_token = data["access_token"]
        return data

    def refresh(self, refresh_token: str) -> dict:
        data = self._request("POST", "/auth/refresh", json={"refresh_token": refresh_token})
        self._access_token = data["access_token"]
        return data

    def me(self) -> dict:
        return self._request("GET", "/auth/me")

    # ------------------------------------------------------------------ sessions

    def create_session(
        self,
        label: str | None = None,
        ttl_seconds: int | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """
        Create an OTC session. Returns a dict with:
          session_id, otc (one-time code), kdf_salt, expires_at, key_derivation_info
        Store 'otc' securely — it is returned exactly once.
        """
        return self._request(
            "POST",
            "/sessions",
            json={"label": label, "ttl_seconds": ttl_seconds, "metadata": metadata or {}},
        )

    def get_session(self, session_id: str) -> dict:
        return self._request("GET", f"/sessions/{session_id}")

    def list_sessions(
        self,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        return self._request("GET", "/sessions", params=params)

    def redeem_session(self, session_id: str, otc: str) -> dict:
        """
        Party B redeems the OTC. Returns kdf_salt + key_derivation_info for local key derivation.
        """
        return self._request(
            "POST",
            f"/sessions/{session_id}/redeem",
            json={"otc": otc},
        )

    def revoke_session(self, session_id: str) -> None:
        self._request("DELETE", f"/sessions/{session_id}")

    # ------------------------------------------------------------------ messages

    def send_message(self, session_id: str, ciphertext_b64: str) -> dict:
        """Post an already-encrypted message. Use SessionCrypto.encrypt_message() first."""
        return self._request(
            "POST",
            f"/sessions/{session_id}/messages",
            json={"ciphertext_b64": ciphertext_b64},
        )

    def get_messages(self, session_id: str, after: int = 0) -> list[dict]:
        return self._request("GET", f"/sessions/{session_id}/messages", params={"after": after})

    # ------------------------------------------------------------------ crypto helpers

    @staticmethod
    def session_crypto(session_created: dict) -> SessionCrypto:
        """
        Build SessionCrypto for Party A from a create_session() response.
        Requires the 'otc' field — only available at creation time.
        """
        return SessionCrypto.from_otc(
            session_created["otc"],
            session_created["kdf_salt"],
            session_created["key_derivation_info"],
        )

    @staticmethod
    def session_crypto_from_redeem(redeem_response: dict, otc: str) -> SessionCrypto:
        """
        Build SessionCrypto for Party B from a redeem_session() response + the raw OTC.
        """
        return SessionCrypto.from_otc(
            otc,
            redeem_response["kdf_salt"],
            redeem_response["key_derivation_info"],
        )

    # ------------------------------------------------------------------ tenant

    def get_tenant(self) -> dict:
        return self._request("GET", "/tenants/me")

    def update_tenant(self, session_ttl_seconds: int | None = None, settings: dict | None = None) -> dict:
        body: dict[str, Any] = {}
        if session_ttl_seconds is not None:
            body["session_ttl_seconds"] = session_ttl_seconds
        if settings is not None:
            body["settings"] = settings
        return self._request("PUT", "/tenants/me", json=body)

    def rotate_api_key(self) -> dict:
        """Rotate the tenant API key. Returns the new raw key — store it immediately."""
        return self._request("POST", "/tenants/me/rotate-api-key")

    # ------------------------------------------------------------------ admin

    def admin_stats(self) -> dict:
        return self._request("GET", "/admin/stats")

    def admin_list_tenants(self, limit: int = 50, offset: int = 0) -> dict:
        return self._request("GET", "/admin/tenants", params={"limit": limit, "offset": offset})

    def admin_update_tenant(self, tenant_id: str, **kwargs) -> dict:
        return self._request("PATCH", f"/admin/tenants/{tenant_id}", json=kwargs)

    def admin_list_users(self, tenant_id: str | None = None) -> dict:
        params = {}
        if tenant_id:
            params["tenant_id"] = tenant_id
        return self._request("GET", "/admin/users", params=params)

    def admin_audit_logs(
        self,
        tenant_id: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> dict:
        params: dict[str, Any] = {"limit": limit}
        if tenant_id:
            params["tenant_id"] = tenant_id
        if action:
            params["action"] = action
        return self._request("GET", "/admin/audit-logs", params=params)
