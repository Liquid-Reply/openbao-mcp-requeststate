"""OpenBao building blocks for protecting MCP `requestState` (spec 2026-07-28).

The MCP Python SDK already seals `requestState` in an AEAD claims envelope
(expiry, request binding, principal, audience) via its `RequestStateBoundary`.
What the SDK cannot answer by itself:

  1. Where do stateless replicas get a *shared* sealing key, and how is it
     rotated?                          -> `load_key_ring()` (KV v2)
  2. What if policy forbids AEAD keys in application memory at all?
                                       -> `TransitCodec` (Transit engine)
  3. How is a destructive confirmation limited to *at most one* use? Claims
     bound the replay window but never guarantee single-use.
                                       -> `SingleUse` (response wrapping)
"""

from __future__ import annotations

import base64
import os
from typing import Any

import httpx
from mcp.server.request_state import InvalidRequestState


class OpenBaoError(RuntimeError):
    """An OpenBao request failed for a reason other than 'token already used'."""


class AlreadyRedeemed(Exception):
    """A single-use confirmation token was already consumed (or expired)."""


class OpenBao:
    """Minimal OpenBao API client (token or AppRole auth).

    Synchronous on purpose: the SDK's `RequestStateCodec` protocol is
    synchronous, and everything else here is either startup-time or explicitly
    pushed off the event loop with `anyio.to_thread` by the caller.
    """

    def __init__(
        self,
        addr: str | None = None,
        token: str | None = None,
        role_id: str | None = None,
        secret_id: str | None = None,
    ) -> None:
        self._http = httpx.Client(
            base_url=(addr or os.environ.get("BAO_ADDR", "http://127.0.0.1:8200")) + "/v1",
            timeout=5.0,
        )
        role_id = role_id or os.environ.get("BAO_ROLE_ID")
        secret_id = secret_id or os.environ.get("BAO_SECRET_ID")
        if role_id and secret_id:
            token = self._login_approle(role_id, secret_id)
        else:
            token = token or os.environ.get("BAO_TOKEN")
        if not token:
            raise OpenBaoError("set BAO_ROLE_ID/BAO_SECRET_ID or BAO_TOKEN")
        self._http.headers["X-Vault-Token"] = token

    def _login_approle(self, role_id: str, secret_id: str) -> str:
        resp = self._http.post("/auth/approle/login", json={"role_id": role_id, "secret_id": secret_id})
        if resp.status_code != 200:
            raise OpenBaoError(f"AppRole login failed: {resp.text}")
        return resp.json()["auth"]["client_token"]

    def _post(self, path: str, payload: dict[str, Any], **headers: str) -> httpx.Response:
        return self._http.post(path, json=payload, headers=headers)

    # --- KV v2 -------------------------------------------------------------

    def kv_get(self, path: str, mount: str = "secret") -> dict[str, Any]:
        resp = self._http.get(f"/{mount}/data/{path}")
        if resp.status_code != 200:
            raise OpenBaoError(f"KV read {path!r} failed: {resp.status_code} {resp.text}")
        return resp.json()["data"]["data"]

    # --- Transit -----------------------------------------------------------

    def transit_encrypt(self, key: str, plaintext: bytes) -> str:
        resp = self._post(f"/transit/encrypt/{key}", {"plaintext": base64.b64encode(plaintext).decode()})
        if resp.status_code != 200:
            raise OpenBaoError(f"transit encrypt failed: {resp.status_code} {resp.text}")
        return resp.json()["data"]["ciphertext"]

    def transit_decrypt(self, key: str, ciphertext: str) -> bytes:
        resp = self._post(f"/transit/decrypt/{key}", {"ciphertext": ciphertext})
        if resp.status_code != 200:
            # Tampered, expired-version, or foreign ciphertext: the caller
            # (the codec) turns this into a frozen wire rejection.
            raise InvalidRequestState(f"transit decrypt refused ({resp.status_code})")
        return base64.b64decode(resp.json()["data"]["plaintext"])

    # --- Response wrapping -------------------------------------------------

    def wrap(self, payload: dict[str, Any], ttl_seconds: int) -> str:
        """Store `payload` in OpenBao, get back a single-use claim token."""
        resp = self._post("/sys/wrapping/wrap", payload, **{"X-Vault-Wrap-TTL": str(ttl_seconds)})
        if resp.status_code != 200:
            raise OpenBaoError(f"wrap failed: {resp.status_code} {resp.text}")
        return resp.json()["wrap_info"]["token"]

    def unwrap(self, token: str) -> dict[str, Any]:
        """Redeem a wrapping token. Exactly one call can ever succeed."""
        resp = self._post("/sys/wrapping/unwrap", {"token": token})
        if resp.status_code in (400, 403, 404):
            raise AlreadyRedeemed("confirmation token already used, expired, or unknown")
        if resp.status_code != 200:
            raise OpenBaoError(f"unwrap failed: {resp.status_code} {resp.text}")
        return resp.json()["data"]


# --- 1. Shared key ring for the SDK's built-in AES-GCM codec ---------------


def load_key_ring(bao: OpenBao, path: str = "mcp/request-state-keys") -> list[bytes]:
    """Fetch the fleet-wide request-state key ring from KV v2.

    Every stateless replica loads the same ring, so any replica can unseal
    state minted by any other — which is the entire premise of MRTR.
    Ring order matters to the SDK: keys[0] seals, all keys unseal.
    """
    keys = [bytes.fromhex(k) for k in bao.kv_get(path)["keys"].split(",")]
    if not keys:
        raise OpenBaoError(f"no request-state keys at {path!r}")
    return keys


# --- 2. Codec variant: the AEAD key never leaves OpenBao -------------------


class TransitCodec:
    """`RequestStateCodec` backed by OpenBao's Transit engine.

    The SDK still mints and verifies every claim (expiry, request binding,
    principal, audience); Transit only performs the AEAD, so the key material
    never exists in application memory. The trade-off is one OpenBao round
    trip per seal/unseal — and the SDK's codec protocol is synchronous, so
    that round trip blocks the worker. Prefer `load_key_ring()` unless key
    custody rules force the crypto into OpenBao.
    """

    def __init__(self, bao: OpenBao, key: str = "mcp-request-state") -> None:
        self._bao, self._key = bao, key

    def seal(self, payload: bytes) -> str:
        return self._bao.transit_encrypt(self._key, payload)

    def unseal(self, token: str) -> bytes:
        if not token.startswith("vault:"):
            raise InvalidRequestState("malformed")
        return self._bao.transit_decrypt(self._key, token)


# --- 3. At-most-once redemption for destructive confirmations --------------


class SingleUse:
    """Single-use server-side claim checks, built on response wrapping.

    The claims envelope bounds *where* and *until when* a `requestState` is
    valid, but a valid one can still be presented twice. For a destructive
    confirmation the spec requires at-most-once semantics enforced
    server-side; a wrapping token is exactly that: TTL-bound, audit-logged,
    and dead the moment it is unwrapped.
    """

    def __init__(self, bao: OpenBao, ttl_seconds: int = 120) -> None:
        self._bao, self._ttl = bao, ttl_seconds

    def issue(self, plan: dict[str, Any]) -> str:
        return self._bao.wrap(plan, self._ttl)

    def redeem(self, token: str) -> dict[str, Any]:
        return self._bao.unwrap(token)  # raises AlreadyRedeemed on second use

    def burn(self, token: str) -> None:
        """Consume a token that will never be redeemed (user declined)."""
        try:
            self._bao.unwrap(token)
        except AlreadyRedeemed:
            pass
