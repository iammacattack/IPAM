"""Sign-in, 2FA and "my account" (the PAMdora flow).

login -> (if 2FA enrolled) mfa/verify -> active session. The session cookie is HttpOnly and
SameSite=Strict; its token is rotated when 2FA completes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict

from .. import repo
from ..audit import note
from ..auth import (
    SESSION_COOKIE, Principal, load_user_access, mfa_enrol_required, mfa_enrolled, record_mfa_failure,
    require, require_step_up, signed_in, verify_second_factor,
)
from ..config import settings
from ..db import autocommit, tx
from ..errors import IpamError
from ..security import (
    DUMMY_HASH, PERMISSIONS, hash_password, new_backup_codes, new_token, new_totp_secret, password_problem,
    provisioning, seal, token_hash, totp_step, unseal, verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

BACKUP_HASH_ROUNDS = 10  # backup codes carry 48 random bits; cost 10 keeps enrolment quick


class LoginIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"username": "admin", "password": "your password"}]})
    username: str
    password: str


class CodeIn(BaseModel):
    code: str


class PasswordIn(BaseModel):
    currentPassword: str
    newPassword: str


def _set_cookie(response: Response, token: str, max_age: int) -> None:
    response.set_cookie(
        SESSION_COOKIE, token, max_age=max_age, httponly=True, secure=settings.cookie_secure, samesite="strict", path="/",
    )


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=settings.cookie_secure, samesite="strict")


def me_view(conn, user_id) -> dict[str, Any]:
    u = conn.execute("SELECT * FROM app_user WHERE user_id = %s", (user_id,)).fetchone()
    perms, roles = load_user_access(conn, user_id)
    cfg = repo.settings(conn)
    enrolled = mfa_enrolled(conn, user_id)
    backup_left = conn.execute(
        "SELECT count(*) AS n FROM mfa_backup_code WHERE user_id = %s AND used_at IS NULL", (user_id,)
    ).fetchone()["n"]
    return {
        "username": u["username"],
        "fullName": u["full_name"],
        "email": u["email"],
        "roles": roles,
        "permissions": sorted(PERMISSIONS) if "*" in perms else sorted(perms),
        "mustChangePassword": u["must_change_password"],
        "mfaEnrolled": enrolled,
        "mfaEnrolRequired": mfa_enrol_required(cfg, roles, enrolled),
        "backupCodesLeft": backup_left,
        "lastLoginAt": u["last_login_at"],
        "stepUpActions": list(cfg.get("stepUpActions") or []),
        "stepUpWindowMinutes": int(cfg["stepUpWindowMinutes"]),
        "sessionIdleMinutes": int(cfg["sessionIdleMinutes"]),
    }


def _client(request: Request) -> tuple[str | None, str | None]:
    return (request.client.host if request.client else None, request.headers.get("user-agent"))


@router.post("/login")
def login(request: Request, response: Response, body: LoginIn):
    username = body.username.strip().lower()
    note(request, "auth.login", objectType="user", objectKey=username)
    request.state.audit["actorId"] = f"user:{username}"
    generic = IpamError("IPAM-LOGIN-FAILED", "Invalid username or password", status=401)
    with autocommit() as conn:
        cfg = repo.settings(conn)
        u = conn.execute("SELECT * FROM app_user WHERE lower(username) = %s", (username,)).fetchone()
        now = datetime.now(timezone.utc)
        if u is None:
            verify_password(body.password, DUMMY_HASH)  # same time as a real check
            raise generic
        if u["locked_until"] and u["locked_until"] > now:
            raise IpamError("IPAM-ACCOUNT-LOCKED", "Too many failed sign-ins. Try again later.", status=429)
        if not verify_password(body.password, u["password_hash"]):
            row = conn.execute(
                "UPDATE app_user SET failed_login_attempts = failed_login_attempts + 1 WHERE user_id = %s RETURNING failed_login_attempts",
                (u["user_id"],),
            ).fetchone()
            if row["failed_login_attempts"] >= int(cfg["maxFailedLogins"]):
                conn.execute(
                    "UPDATE app_user SET locked_until = now() + make_interval(mins => %s), failed_login_attempts = 0 WHERE user_id = %s",
                    (int(cfg["lockoutMinutes"]), u["user_id"]),
                )
                request.state.audit["changes"] = {"locked": True}
            raise generic
        if u["status"] != "active":
            raise generic
        conn.execute(
            "UPDATE app_user SET failed_login_attempts = 0, locked_until = NULL, last_login_at = now() WHERE user_id = %s",
            (u["user_id"],),
        )
        needs_mfa = mfa_enrolled(conn, u["user_id"])
        token = new_token()
        ip, ua = _client(request)
        hours = int(cfg["sessionAbsoluteHours"])
        conn.execute(
            """INSERT INTO user_session (user_id, token_hash, state, auth_method, expires_at, source_ip, user_agent)
               VALUES (%s, %s, %s, 'password', now() + make_interval(mins => %s), %s, %s)""",
            (u["user_id"], token_hash(token), "mfa-pending" if needs_mfa else "active", 10 if needs_mfa else hours * 60, ip, ua),
        )
        _set_cookie(response, token, 600 if needs_mfa else hours * 3600)
        if needs_mfa:
            response.status_code = 202
            request.state.audit["action"] = "auth.login_mfa_required"
            return {"mfaRequired": True, "methods": ["totp", "backup-code"]}
        return {"mfaRequired": False, "user": me_view(conn, u["user_id"])}


@router.post("/mfa/verify")
def mfa_verify(request: Request, response: Response, body: CodeIn):
    """Second step of sign-in. Accepts an authenticator code or a backup code."""
    note(request, "auth.mfa_verify")
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise IpamError("IPAM-SESSION-INVALID", "Sign in first", status=401)
    with autocommit() as conn:
        cfg = repo.settings(conn)
        s = conn.execute(
            """SELECT s.*, u.username, u.mfa_locked_until FROM user_session s JOIN app_user u USING (user_id)
               WHERE s.token_hash = %s AND s.state = 'mfa-pending' AND s.expires_at > now()""",
            (token_hash(token),),
        ).fetchone()
        if s is None:
            raise IpamError("IPAM-SESSION-INVALID", "That sign-in has expired. Start again.", status=401)
        request.state.audit["actorId"] = f"user:{s['username']}"
        if s["mfa_locked_until"] and s["mfa_locked_until"] > datetime.now(timezone.utc):
            raise IpamError("IPAM-MFA-LOCKED", "Too many wrong codes. Try again later.", status=429)
        method = verify_second_factor(conn, s["user_id"], body.code)
        if method is None:
            if record_mfa_failure(conn, s["user_id"], cfg):
                conn.execute("UPDATE user_session SET state = 'revoked' WHERE session_id = %s", (s["session_id"],))
            raise IpamError("IPAM-MFA-FAILED", "That code isn't right, or it's already been used", status=401)
        conn.execute("UPDATE app_user SET failed_mfa_attempts = 0 WHERE user_id = %s", (s["user_id"],))
        fresh = new_token()  # rotate on elevation
        hours = int(cfg["sessionAbsoluteHours"])
        conn.execute(
            """UPDATE user_session SET state = 'active', token_hash = %s, auth_method = %s, step_up_at = now(),
                   last_seen_at = now(), expires_at = now() + make_interval(hours => %s) WHERE session_id = %s""",
            (token_hash(fresh), f"password+{method}", hours, s["session_id"]),
        )
        _set_cookie(response, fresh, hours * 3600)
        request.state.audit["changes"] = {"method": method}
        return {"user": me_view(conn, s["user_id"])}


@router.post("/logout")
def logout(request: Request, response: Response):
    note(request, "auth.logout")
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with autocommit() as conn:
            row = conn.execute(
                """UPDATE user_session s SET state = 'revoked' FROM app_user u
                   WHERE s.token_hash = %s AND u.user_id = s.user_id RETURNING u.username""",
                (token_hash(token),),
            ).fetchone()
            if row:
                request.state.audit["actorId"] = f"user:{row['username']}"
    _clear_cookie(response)
    return {"signedOut": True}


@router.get("/me")
def me(request: Request, principal: Principal = Depends(signed_in)):
    note(request, "auth.me")
    if principal.actor_type != "user":
        return {"username": None, "actorType": principal.actor_type, "permissions": sorted(principal.permissions)}
    with autocommit() as conn:
        return me_view(conn, principal.user_id)


@router.post("/change-password")
def change_password(request: Request, body: PasswordIn, principal: Principal = Depends(signed_in)):
    note(request, "auth.change_password", objectType="user", objectKey=principal.username)
    if principal.actor_type != "user":
        raise IpamError("IPAM-BAD-REQUEST", "Only people have passwords")
    with tx() as conn:
        u = conn.execute("SELECT * FROM app_user WHERE user_id = %s FOR UPDATE", (principal.user_id,)).fetchone()
        if not verify_password(body.currentPassword, u["password_hash"]):
            raise IpamError("IPAM-PASSWORD-WRONG", "Your current password isn't right", status=403)
        problem = password_problem(body.newPassword, u["username"])
        if problem:
            raise IpamError("IPAM-PASSWORD-WEAK", problem)
        if verify_password(body.newPassword, u["password_hash"]):
            raise IpamError("IPAM-PASSWORD-WEAK", "Choose a password you haven't just used")
        conn.execute(
            "UPDATE app_user SET password_hash = %s, must_change_password = false, password_changed_at = now() WHERE user_id = %s",
            (hash_password(body.newPassword), principal.user_id),
        )
        # Sign out everywhere else.
        conn.execute(
            "UPDATE user_session SET state = 'revoked' WHERE user_id = %s AND session_id <> %s AND state <> 'revoked'",
            (principal.user_id, principal.session_id),
        )
        return me_view(conn, principal.user_id)


# --------------------------------------------------------------------------- #
# 2FA enrolment
# --------------------------------------------------------------------------- #


@router.post("/mfa/enrol")
def mfa_enrol_start(request: Request, principal: Principal = Depends(signed_in)):
    """Start setting up an authenticator app. Returns a QR code and the secret for manual entry."""
    note(request, "mfa.enrol_start", objectType="user", objectKey=principal.username)
    if principal.actor_type != "user":
        raise IpamError("IPAM-BAD-REQUEST", "Only people enrol 2FA")
    if principal.mfa_enrolled:
        # Replacing an existing authenticator is itself high-risk.
        require_step_up(request, principal, "mfa.replace")
    secret = new_totp_secret()
    with tx() as conn:
        conn.execute("DELETE FROM mfa_device WHERE user_id = %s AND status = 'pending'", (principal.user_id,))
        conn.execute(
            "INSERT INTO mfa_device (user_id, totp_secret, status) VALUES (%s, %s, 'pending')",
            (principal.user_id, seal(secret)),
        )
    return provisioning(secret, principal.username)


@router.post("/mfa/enrol/verify")
def mfa_enrol_verify(request: Request, body: CodeIn, principal: Principal = Depends(signed_in)):
    """Finish enrolment with the first code. Returns backup codes, shown once."""
    note(request, "mfa.enrol_complete", objectType="user", objectKey=principal.username)
    with tx() as conn:
        d = conn.execute(
            """SELECT * FROM mfa_device WHERE user_id = %s AND status = 'pending'
               AND created_at > now() - interval '15 minutes' ORDER BY created_at DESC LIMIT 1""",
            (principal.user_id,),
        ).fetchone()
        if d is None:
            raise IpamError("IPAM-MFA-ENROL-EXPIRED", "Start the set-up again; that QR code has expired")
        step = totp_step(unseal(d["totp_secret"]), body.code, None)
        if step is None:
            raise IpamError("IPAM-MFA-FAILED", "That code doesn't match. Check the time on your phone and try again.", status=401)
        conn.execute("UPDATE mfa_device SET status = 'revoked' WHERE user_id = %s AND status = 'active'", (principal.user_id,))
        conn.execute(
            "UPDATE mfa_device SET status = 'active', activated_at = now(), last_step = %s WHERE device_id = %s",
            (step, d["device_id"]),
        )
        codes = _replace_backup_codes(conn, principal.user_id)
        conn.execute(
            "UPDATE user_session SET auth_method = 'password+totp', step_up_at = now() WHERE session_id = %s",
            (principal.session_id,),
        )
        return {"backupCodes": codes, "user": me_view(conn, principal.user_id)}


@router.post("/mfa/backup-codes")
def regenerate_backup_codes(request: Request, principal: Principal = Depends(signed_in)):
    note(request, "mfa.backup_codes_regenerated", objectType="user", objectKey=principal.username)
    if not principal.mfa_enrolled:
        raise IpamError("IPAM-MFA-ENROLMENT-REQUIRED", "Set up 2FA first", status=403)
    require_step_up(request, principal, "mfa.replace")
    with tx() as conn:
        return {"backupCodes": _replace_backup_codes(conn, principal.user_id)}


def _replace_backup_codes(conn, user_id) -> list[str]:
    import bcrypt

    codes = new_backup_codes()
    conn.execute("DELETE FROM mfa_backup_code WHERE user_id = %s", (user_id,))
    for c in codes:
        h = bcrypt.hashpw(c.encode(), bcrypt.gensalt(rounds=BACKUP_HASH_ROUNDS)).decode()
        conn.execute("INSERT INTO mfa_backup_code (user_id, code_hash) VALUES (%s, %s)", (user_id, h))
    return codes


@router.get("/permissions", include_in_schema=False)
def permissions(_: Principal = Depends(require("read"))):
    return PERMISSIONS
