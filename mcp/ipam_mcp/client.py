"""Thin IPAM API client. The MCP server never touches the database; everything goes through the
audited API with the server's own API key (spec §9.1)."""

from __future__ import annotations

import os
from typing import Any

import httpx

KEYRING_SERVICE = "ipam-mcp"
KEYRING_USER = "api-key"
DEFAULT_URL = "http://127.0.0.1:8820/api/v1"


class IpamError(Exception):
    def __init__(self, status: int, body: dict[str, Any]):
        self.status = status
        self.body = body
        self.code = body.get("code") or f"HTTP-{status}"
        super().__init__(self.describe())

    def describe(self) -> str:
        """A one-paragraph explanation Claude can relay: code, message and the useful extras."""
        skip = {"type", "title", "status", "code", "detail", "requestId"}
        extras = {k: v for k, v in self.body.items() if k not in skip}
        msg = f"{self.code}: {self.body.get('detail') or self.body.get('message') or 'request failed'}"
        if extras:
            msg += " | " + "; ".join(f"{k}={v}" for k, v in extras.items())
        return msg


def load_key() -> str:
    """IPAM_API_KEY from the environment, else Windows Credential Manager (set with ipam-mcp-setkey)."""
    key = os.environ.get("IPAM_API_KEY")
    if key:
        return key.strip()
    try:
        import keyring

        key = keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception:  # noqa: BLE001 - no keyring backend (e.g. in a container)
        key = None
    if not key:
        raise RuntimeError(
            "No IPAM API key. Issue one on the IPAM API keys page (scope: read), then run "
            "'ipam-mcp-setkey' to store it in Windows Credential Manager, or set IPAM_API_KEY."
        )
    return key.strip()


class Ipam:
    def __init__(self, base_url: str | None = None, key: str | None = None, client_name: str | None = None):
        self.base_url = (base_url or os.environ.get("IPAM_URL") or DEFAULT_URL).rstrip("/")
        self._key = key
        self.client_name = client_name or os.environ.get("IPAM_CLIENT_NAME") or "ClaudeCowork-MCP/0.1"
        self._http: httpx.Client | None = None

    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(
                base_url=self.base_url,
                headers={"X-API-Key": self._key or load_key(), "X-Client-Name": self.client_name, "Accept": "application/json"},
                timeout=20,
            )
        return self._http

    def get(self, path: str, **params: Any) -> Any:
        clean = {k: v for k, v in params.items() if v is not None and v != ""}
        try:
            r = self.http.get(path, params=clean)
        except httpx.ConnectError as exc:
            raise IpamError(503, {"code": "IPAM-UNREACHABLE", "detail": f"Can't reach IPAM at {self.base_url}. Is the Docker stack running?"}) from exc
        if r.status_code >= 400:
            try:
                body = r.json()
            except ValueError:
                body = {"detail": r.text[:300]}
            raise IpamError(r.status_code, body if isinstance(body, dict) else {"detail": str(body)})
        return r.json()
