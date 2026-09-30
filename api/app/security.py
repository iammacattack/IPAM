"""Passwords, TOTP, secret sealing and permissions (the PAMdora model, in Python).

- Passwords and backup codes: bcrypt, cost 12 (as PAMdora).
- TOTP: RFC 6238, SHA-1, 6 digits, 30 s, +/-1 step (what every authenticator app does).
  The last accepted step is stored so the same code can't be replayed.
- TOTP secrets are sealed with AES-256-GCM using IPAM_SECRET_KEY; the database never holds them in clear.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import secrets
import time

import bcrypt
import pyotp
import segno
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings

ISSUER = "NEXTDC IPAM"

# --------------------------------------------------------------------------- #
# Permissions and system roles (spec §10.3)
# --------------------------------------------------------------------------- #

PERMISSIONS: dict[str, str] = {
    "read": "View templates, sites, designs, lookups and the library",
    "templates.write": "Create and edit draft templates",
    "templates.release": "Release a template version",
    "vlans.write": "Add VLANs to the library",
    "sites.deploy": "Reserve a site",
    "sites.confirm": "Confirm a site allocation",
    "sites.release": "Cancel a site reservation",
    "hosts.assign": "Assign a host address to a machine",
    "audit.read": "View and export the audit log",
    "users.manage": "Add, change and disable users; reset passwords and 2FA",
    "apikeys.manage": "Issue and revoke API keys",
}

SYSTEM_ROLES: list[dict] = [
    {"key": "viewer", "name": "Viewer", "description": "Read-only: designs, lookups, library.", "permissions": ["read"]},
    {"key": "designer", "name": "Designer", "description": "Curates templates and the VLAN library.",
     "permissions": ["read", "templates.write", "templates.release", "vlans.write"]},
    {"key": "operator", "name": "Operator", "description": "Deploys sites and assigns host addresses.",
     "permissions": ["read", "sites.deploy", "sites.confirm", "sites.release", "hosts.assign"]},
    {"key": "auditor", "name": "Auditor", "description": "Reads and exports the audit log.", "permissions": ["read", "audit.read"]},
    {"key": "admin", "name": "Administrator", "description": "Everything, including users and API keys.", "permissions": ["*"]},
]

# API-key scopes (spec §10.4) expressed as permissions. Keys are exempt from 2FA (R17),
# so they never get users.manage or apikeys.manage.
SCOPE_PERMISSIONS: dict[str, list[str]] = {
    "read": ["read"],
    "hosts:reserve": ["hosts.assign"],
    "hosts:write": ["hosts.assign"],
    "sites:deploy": ["sites.deploy", "sites.confirm", "sites.release"],
    "templates:write": ["templates.write", "templates.release", "vlans.write"],
    "audit:read": ["audit.read"],  # e.g. a SIEM or reporting client
}


def has_permission(granted: set[str], needed: str) -> bool:
    return "*" in granted or needed in granted


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except ValueError:
        return False


# Used to spend the same time on unknown usernames, so response time doesn't reveal which exist.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problem(plain: str, username: str) -> str | None:
    """POC policy: 12+ characters, three of four character classes, not the username."""
    if len(plain) < 12:
        return "Use at least 12 characters"
    if username and username.lower() in plain.lower():
        return "The password mustn't contain the username"
    classes = sum(bool(any(f(c) for c in plain)) for f in (str.islower, str.isupper, str.isdigit, lambda c: not c.isalnum()))
    if classes < 3:
        return "Use at least three of: lower case, upper case, digits, symbols"
    return None


def generate_password() -> str:
    """A temporary password that meets the policy."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    core = "".join(secrets.choice(alphabet) for _ in range(14))
    return f"{core[:5]}-{core[5:10]}-{core[10:]}{secrets.choice('23456789')}"


# --------------------------------------------------------------------------- #
# Session tokens
# --------------------------------------------------------------------------- #


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Sealing (AES-256-GCM)
# --------------------------------------------------------------------------- #


def _key() -> bytes:
    raw = settings.secret_key
    if not raw:
        raise RuntimeError("IPAM_SECRET_KEY isn't set; run scripts/Initialize-IpamEnv.ps1 to add it to .env")
    key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if len(key) != 32:
        raise RuntimeError("IPAM_SECRET_KEY must be 32 bytes (base64url)")
    return key


def seal(plain: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_key()).encrypt(nonce, plain.encode("utf-8"), b"ipam-totp")
    return "v1." + base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def unseal(sealed: str) -> str:
    if not sealed.startswith("v1."):
        raise ValueError("unknown sealed-secret format")
    blob = base64.urlsafe_b64decode(sealed[3:])
    return AESGCM(_key()).decrypt(blob[:12], blob[12:], b"ipam-totp").decode("utf-8")


# --------------------------------------------------------------------------- #
# TOTP
# --------------------------------------------------------------------------- #


def new_totp_secret() -> str:
    return pyotp.random_base32(32)


def provisioning(secret: str, username: str) -> dict[str, str]:
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)
    buf = io.BytesIO()
    segno.make(uri, error="m").save(buf, kind="svg", scale=5, border=2, dark="#0f1b33", light="#ffffff")
    return {
        "otpauthUri": uri,
        "secret": secret,
        "qrSvg": "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode("ascii"),
    }


def totp_step(secret: str, code: str, last_step: int | None) -> int | None:
    """Return the accepted time-step, or None. Accepts +/-1 step; refuses a step already used."""
    code = code.strip().replace(" ", "")
    if not (len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret)
    now = int(time.time()) // 30
    for step in (now, now - 1, now + 1):
        if last_step is not None and step <= last_step:
            continue
        if secrets.compare_digest(totp.at(step * 30), code):
            return step
    return None


def new_backup_codes(n: int = 10) -> list[str]:
    return ["-".join(secrets.token_hex(2).upper() for _ in range(3)) for _ in range(n)]
