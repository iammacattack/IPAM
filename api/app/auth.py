"""Authentication and authorisation.

Two ways in:

- **People**: local username + password, TOTP 2FA (the PAMdora model), a server-side session
  referenced by an HttpOnly, SameSite=Strict cookie. Tokens never reach browser JavaScript.
- **Machines**: API keys ``ipam_<prefix>_<secret>`` in ``X-API-Key`` (spec §10.4), exempt from 2FA.

Permissions come from roles (users) or scopes (keys). High-risk actions also need a *fresh*
2FA code (step-up): the client resends the request with ``X-IPAM-2FA: <code>``, and one code
covers the configured window.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from fastapi import Request, Security
from fastapi.security import APIKeyCookie, APIKeyHeader

from . import repo
from .config import ALL_SCOPES
from .db import autocommit
from .errors import IpamError
from .security import SCOPE_PERMISSIONS, has_permission, token_hash, totp_step, unseal, verify_password

KEY_RE = re.compile(r"^ipam_([A-Za-z0-9]{8})_([A-Za-z0-9_-]{32,})$")
SESSION_COOKIE = "ipam_session"
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "IPAM-UI"
STEP_UP_HEADER = "x-ipam-2fa"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Declared so Swagger UI shows an Authorize button; authenticate() reads the header itself.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="API key for scripts and integrations")
session_cookie = APIKeyCookie(name=SESSION_COOKIE, auto_error=False, description="Browser session (set by /auth/login)")


@dataclass
class Principal:
    actor_type: str  # user | api-key
    actor_id: str
    display: str
    auth_method: str
    mfa: bool
    permissions: set[str] = field(default_factory=set)
    scopes: list[str] = field(default_factory=list)
    user_id: Any = None
    username: str | None = None
    session_id: Any = None
    step_up_at: datetime | None = None
    must_change_password: bool = False
    mfa_enrolled: bool = False
    mfa_enrol_required: bool = False

    def can(self, permission: str) -> bool:
        return has_permission(self.permissions, permission)


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #


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
        INSERT INTO api_key (prefix, secret_hash, owner, purpose, client_name, scopes, expires_at, created_by)
        VALUES (%s, %s, 'bootstrap (POC)', 'Local development key from .env (tests and scripts)', NULL, %s,
                now() + interval '365 days', 'bootstrap')
        ON CONFLICT (prefix) DO UPDATE SET scopes = EXCLUDED.scopes, created_by = 'bootstrap'
            WHERE api_key.owner = 'bootstrap (POC)'
        """,
        (prefix, hash_secret(secret), ALL_SCOPES),
    )


def _key_principal(request: Request, raw: str) -> Principal:
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
    perms = {p for s in row["scopes"] for p in SCOPE_PERMISSIONS.get(s, [])}
    return Principal(
        actor_type="api-key", actor_id=f"key:{prefix}", display=f"{prefix} ({row['owner']})",
        auth_method="api-key", mfa=False, permissions=perms, scopes=list(row["scopes"]),
    )


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #


def load_user_access(conn, user_id) -> tuple[set[str], list[dict[str, str]]]:
    rows = conn.execute(
        """SELECT r.role_key, r.name, rp.permission FROM user_role ur JOIN role r USING (role_key)
           LEFT JOIN role_permission rp USING (role_key) WHERE ur.user_id = %s""",
        (user_id,),
    ).fetchall()
    perms = {r["permission"] for r in rows if r["permission"]}
    roles = {r["role_key"]: r["name"] for r in rows}
    return perms, [{"key": k, "name": v} for k, v in sorted(roles.items())]


def mfa_enrolled(conn, user_id) -> bool:
    return conn.execute("SELECT 1 FROM mfa_device WHERE user_id = %s AND status = 'active'", (user_id,)).fetchone() is not None


def mfa_enrol_required(cfg: dict[str, Any], roles: list[dict[str, str]], enrolled: bool) -> bool:
    if enrolled:
        return False
    required = set(cfg.get("mfaRequiredForRoles") or [])
    return any(r["key"] in required for r in roles)


def _session_principal(request: Request, token: str) -> Principal:
    with autocommit() as conn:
        s = conn.execute(
            """SELECT s.*, u.username, u.full_name, u.status, u.locked_until, u.must_change_password
               FROM user_session s JOIN app_user u USING (user_id) WHERE s.token_hash = %s""",
            (token_hash(token),),
        ).fetchone()
        now = datetime.now(timezone.utc)
        if s is None or s["state"] == "revoked":
            raise _fail(request, "IPAM-SESSION-INVALID", "You're signed out. Sign in again.")
        request.state.audit["actorId"] = f"user:{s['username']}"
        if s["state"] == "mfa-pending":
            raise _fail(request, "IPAM-MFA-REQUIRED", "Enter your 2FA code to finish signing in")
        cfg = repo.settings(conn)
        idle = timedelta(minutes=int(cfg["sessionIdleMinutes"]))
        if s["expires_at"] <= now or s["last_seen_at"] + idle <= now:
            conn.execute("UPDATE user_session SET state = 'revoked' WHERE session_id = %s", (s["session_id"],))
            raise _fail(request, "IPAM-SESSION-EXPIRED", "Your session timed out. Sign in again.")
        if s["status"] != "active" or (s["locked_until"] and s["locked_until"] > now):
            conn.execute("UPDATE user_session SET state = 'revoked' WHERE session_id = %s", (s["session_id"],))
            raise _fail(request, "IPAM-SESSION-INVALID", "This account can't sign in right now")
        # Cookie-authenticated writes must come from the UI (a cross-site form can't set this header).
        if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            raise IpamError("IPAM-CSRF", "Write requests from the browser must come from the IPAM UI", status=403)
        if (now - s["last_seen_at"]).total_seconds() > 30:
            conn.execute("UPDATE user_session SET last_seen_at = now() WHERE session_id = %s", (s["session_id"],))
        perms, roles = load_user_access(conn, s["user_id"])
        enrolled = mfa_enrolled(conn, s["user_id"])
    return Principal(
        actor_type="user", actor_id=f"user:{s['username']}", display=s["full_name"] or s["username"],
        auth_method=s["auth_method"], mfa=s["auth_method"] != "password", permissions=perms,
        user_id=s["user_id"], username=s["username"], session_id=s["session_id"], step_up_at=s["step_up_at"],
        must_change_password=s["must_change_password"], mfa_enrolled=enrolled,
        mfa_enrol_required=mfa_enrol_required(cfg, roles, enrolled),
    )


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


def _fail(request: Request, code: str, message: str) -> IpamError:
    request.state.audit["action"] = request.state.audit.get("action") or "auth.failed"
    return IpamError(code, message, status=401)


def authenticate(request: Request, *, allow_restricted: bool = False) -> Principal:
    raw_key = request.headers.get("x-api-key")
    cookie = request.cookies.get(SESSION_COOKIE)
    if raw_key:
        principal = _key_principal(request, raw_key)
    elif cookie:
        principal = _session_principal(request, cookie)
    else:
        raise _fail(request, "IPAM-AUTH-REQUIRED", "Sign in, or send an API key in the X-API-Key header")
    request.state.principal = principal
    if not allow_restricted:
        if principal.must_change_password:
            raise IpamError("IPAM-PASSWORD-CHANGE-REQUIRED", "Change your password before continuing", status=403)
        if principal.mfa_enrol_required:
            raise IpamError("IPAM-MFA-ENROLMENT-REQUIRED", "Your role needs 2FA. Set up an authenticator app first.", status=403)
    return principal


def verify_second_factor(conn, user_id, code: str) -> str | None:
    """Check a TOTP or backup code. Returns 'totp' / 'backup-code', or None. Consumes what it accepts."""
    code = (code or "").strip()
    for d in conn.execute(
        "SELECT device_id, totp_secret, last_step FROM mfa_device WHERE user_id = %s AND status = 'active'", (user_id,)
    ).fetchall():
        step = totp_step(unseal(d["totp_secret"]), code, d["last_step"])
        if step is not None:
            conn.execute("UPDATE mfa_device SET last_step = %s, last_used_at = now() WHERE device_id = %s", (step, d["device_id"]))
            return "totp"
    normalised = code.upper().replace(" ", "")
    if re.fullmatch(r"[0-9A-F]{4}-?[0-9A-F]{4}-?[0-9A-F]{4}", normalised):
        normalised = "-".join(re.findall(r"[0-9A-F]{4}", normalised))
        for b in conn.execute("SELECT code_id, code_hash FROM mfa_backup_code WHERE user_id = %s AND used_at IS NULL", (user_id,)).fetchall():
            if verify_password(normalised, b["code_hash"]):
                conn.execute("UPDATE mfa_backup_code SET used_at = now() WHERE code_id = %s", (b["code_id"],))
                return "backup-code"
    return None


def record_mfa_failure(conn, user_id, cfg: dict[str, Any]) -> bool:
    """Count a bad 2FA code; lock 2FA after too many. Returns True if now locked."""
    row = conn.execute(
        "UPDATE app_user SET failed_mfa_attempts = failed_mfa_attempts + 1 WHERE user_id = %s RETURNING failed_mfa_attempts",
        (user_id,),
    ).fetchone()
    if row["failed_mfa_attempts"] >= int(cfg["maxFailedLogins"]):
        conn.execute(
            "UPDATE app_user SET mfa_locked_until = now() + make_interval(mins => %s), failed_mfa_attempts = 0 WHERE user_id = %s",
            (int(cfg["lockoutMinutes"]), user_id),
        )
        return True
    return False


def require_step_up(request: Request, principal: Principal, action: str) -> None:
    """High-risk action for a person: needs a fresh 2FA code (API keys are exempt, spec R17)."""
    if principal.actor_type != "user":
        return
    with autocommit() as conn:
        cfg = repo.settings(conn)
        if action not in set(cfg.get("stepUpActions") or []):
            return
        window = timedelta(minutes=max(0, int(cfg["stepUpWindowMinutes"])))
        now = datetime.now(timezone.utc)
        if window and principal.step_up_at and principal.step_up_at + window > now:
            return
        if not principal.mfa_enrolled:
            raise IpamError("IPAM-MFA-ENROLMENT-REQUIRED", "This action needs 2FA. Set up an authenticator app in My account first.", status=403, action=action)
        code = request.headers.get(STEP_UP_HEADER)
        if not code:
            raise IpamError("IPAM-STEP-UP-REQUIRED", "Enter a code from your authenticator app to continue", status=403, action=action)
        locked = conn.execute("SELECT mfa_locked_until FROM app_user WHERE user_id = %s", (principal.user_id,)).fetchone()["mfa_locked_until"]
        if locked and locked > now:
            raise IpamError("IPAM-MFA-LOCKED", "Too many wrong codes. Try again later.", status=429)
        method = verify_second_factor(conn, principal.user_id, code)
        if method is None:
            record_mfa_failure(conn, principal.user_id, cfg)
            raise IpamError("IPAM-STEP-UP-FAILED", "That code isn't right, or it's already been used", status=403, action=action)
        conn.execute("UPDATE app_user SET failed_mfa_attempts = 0 WHERE user_id = %s", (principal.user_id,))
        conn.execute("UPDATE user_session SET step_up_at = now() WHERE session_id = %s", (principal.session_id,))
    request.state.audit["stepUp"] = method


def require(permission: str, step_up: str | None = None) -> Callable[..., Principal]:
    """Dependency: authenticated, holds ``permission``, and (for people) passed step-up if ``step_up`` is configured."""

    def dependency(
        request: Request,
        _key: str | None = Security(api_key_header),
        _cookie: str | None = Security(session_cookie),
    ) -> Principal:
        principal = authenticate(request)
        if not principal.can(permission):
            raise IpamError("IPAM-PERMISSION-DENIED", f"You don't have permission to do that ({permission})", status=403, permission=permission)
        if step_up:
            require_step_up(request, principal, step_up)
        return principal

    dependency.__name__ = f"require_{permission.replace('.', '_')}"
    return dependency


def signed_in(request: Request, _cookie: str | None = Security(session_cookie)) -> Principal:
    """Any signed-in person, even one who still has to change password or enrol 2FA."""
    return authenticate(request, allow_restricted=True)
