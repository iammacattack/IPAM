"""API-key authentication (spec §10.4).

Keys look like ``ipam_<8-char prefix>_<secret>``. Only the prefix and a SHA-256
of the secret are stored; a fast hash is fine because the secret is 32 random
bytes. Entra ID and MFA come in Phase 4.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from fastapi import Request

from .config import ALL_SCOPES
from .db import autocommit
from .errors import IpamError

KEY_RE = re.compile(r"^ipam_([A-Za-z0-9]{8})_([A-Za-z0-9_-]{32,})$")


@dataclass
class Principal:
    actor_type: str
    actor_id: str
    display: str
    auth_method: str
    scopes: list[str] = field(default_factory=list)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_key() -> str:
    return f"ipam_{secrets.token_hex(4)}_{secrets.token_urlsafe(32)}"


def ensure_bootstrap_key(conn, key: str) -> None:
    """Register the development key from .env if it isn't there yet."""
    m = KEY_RE.match(key)
    if not m:
        raise RuntimeError("IPAM_BOOTSTRAP_API_KEY isn't in the ipam_<prefix>_<secret> format")
    prefix, secret = m.groups()
    conn.execute(
        """
        INSERT INTO api_key (prefix, secret_hash, owner, purpose, client_name, scopes, expires_at)
        VALUES (%s, %s, 'bootstrap (POC)', 'Local development key from .env', NULL, %s, now() + interval '365 days')
        ON CONFLICT (prefix) DO NOTHING
        """,
        (prefix, hash_secret(secret), ALL_SCOPES),
    )


def _fail(request: Request, code: str, message: str) -> IpamError:
    request.state.audit["action"] = "auth.failed"
    return IpamError(code, message)


def authenticate(request: Request) -> Principal:
    raw = request.headers.get("x-api-key")
    if not raw:
        raise _fail(request, "IPAM-AUTH-REQUIRED", "Send an API key in the X-API-Key header")
    m = KEY_RE.match(raw.strip())
    if not m:
        raise _fail(request, "IPAM-KEY-INVALID", "API key isn't valid")
    prefix, secret = m.groups()
    with autocommit() as conn:
        row = conn.execute("SELECT * FROM api_key WHERE prefix = %s", (prefix,)).fetchone()
        if row is None or not hmac.compare_digest(row["secret_hash"], hash_secret(secret)):
            request.state.audit["actorId"] = f"key:{prefix}"
            raise _fail(request, "IPAM-KEY-INVALID", "API key isn't valid")
        if row["revoked_at"] is not None:
            raise _fail(request, "IPAM-KEY-REVOKED", "API key has been revoked")
        if row["expires_at"] <= datetime.now(timezone.utc):
            raise _fail(request, "IPAM-KEY-EXPIRED", "API key has expired")
        conn.execute(
            "UPDATE api_key SET last_used_at = now(), last_used_ip = %s WHERE key_id = %s",
            (request.client.host if request.client else None, row["key_id"]),
        )
    principal = Principal(
        actor_type="api-key",
        actor_id=f"key:{prefix}",
        display=f"{prefix} ({row['owner']})",
        auth_method="api-key",
        scopes=list(row["scopes"]),
    )
    request.state.principal = principal
    return principal


def require(scope: str) -> Callable[[Request], Principal]:
    def dependency(request: Request) -> Principal:
        principal = authenticate(request)
        if scope not in principal.scopes:
            raise IpamError("IPAM-SCOPE-MISSING", f"This call needs the '{scope}' scope")
        return principal

    dependency.__name__ = f"require_{scope.replace(':', '_')}"
    return dependency
