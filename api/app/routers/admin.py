"""Administration: local users and roles, API keys. Every change needs a fresh 2FA code (step-up)."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from psycopg import errors as pg_errors

from ..audit import note
from ..auth import KEY_RE, Principal, generate_key, hash_secret, require
from ..config import ALL_SCOPES
from ..db import tx
from ..errors import IpamError
from ..security import PERMISSIONS, generate_password, hash_password, password_problem

router = APIRouter(tags=["admin"])
USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


# --------------------------------------------------------------------------- #
# Roles
# --------------------------------------------------------------------------- #


@router.get("/roles")
def list_roles(request: Request, _: Principal = Depends(require("read"))):
    note(request, "role.list")
    with tx() as conn:
        roles = conn.execute("SELECT * FROM role ORDER BY is_system DESC, role_key").fetchall()
        perms = conn.execute("SELECT * FROM role_permission ORDER BY permission").fetchall()
        counts = {r["role_key"]: r["n"] for r in conn.execute("SELECT role_key, count(*) AS n FROM user_role GROUP BY role_key")}
    return {
        "permissions": PERMISSIONS,
        "roles": [
            {
                "key": r["role_key"], "name": r["name"], "description": r["description"], "system": r["is_system"],
                "permissions": [p["permission"] for p in perms if p["role_key"] == r["role_key"]],
                "users": counts.get(r["role_key"], 0),
            }
            for r in roles
        ],
    }


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #


class UserIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"username": "jsmith", "fullName": "Jo Smith", "email": "jo.smith@example.com", "roles": ["operator"]}]})
    username: str
    fullName: str | None = None
    email: str | None = None
    roles: list[str] = Field(default_factory=list)
    password: str | None = Field(None, description="Leave out to generate a temporary password (shown once)")


class UserPatch(BaseModel):
    fullName: str | None = None
    email: str | None = None
    roles: list[str] | None = None
    status: str | None = Field(None, pattern="^(active|disabled)$")


def _user_view(conn, u: dict[str, Any]) -> dict[str, Any]:
    roles = [r["role_key"] for r in conn.execute("SELECT role_key FROM user_role WHERE user_id = %s ORDER BY role_key", (u["user_id"],))]
    mfa = conn.execute("SELECT 1 FROM mfa_device WHERE user_id = %s AND status = 'active'", (u["user_id"],)).fetchone() is not None
    return {
        "username": u["username"], "fullName": u["full_name"], "email": u["email"], "status": u["status"],
        "roles": roles, "mfaEnrolled": mfa, "mustChangePassword": u["must_change_password"],
        "lockedUntil": u["locked_until"], "lastLoginAt": u["last_login_at"], "createdAt": u["created_at"], "createdBy": u["created_by"],
    }


def _get_user(conn, username: str, *, for_update: bool = False) -> dict[str, Any]:
    u = conn.execute(
        "SELECT * FROM app_user WHERE lower(username) = lower(%s)" + (" FOR UPDATE" if for_update else ""), (username,)
    ).fetchone()
    if u is None:
        raise IpamError("IPAM-NOT-FOUND", f"No user '{username}'", status=404)
    return u


def _check_roles(conn, roles: list[str]) -> list[str]:
    known = {r["role_key"] for r in conn.execute("SELECT role_key FROM role")}
    bad = [r for r in roles if r not in known]
    if bad:
        raise IpamError("IPAM-ROLE-UNKNOWN", f"Unknown role(s): {', '.join(bad)}", validRoles=sorted(known))
    return sorted(set(roles))


def _would_orphan_admins(conn, user_id, new_roles: list[str] | None, new_status: str | None) -> bool:
    """True if the change leaves no active administrator."""
    others = conn.execute(
        """SELECT count(*) AS n FROM app_user u JOIN user_role ur USING (user_id)
           WHERE ur.role_key = 'admin' AND u.status = 'active' AND u.user_id <> %s""",
        (user_id,),
    ).fetchone()["n"]
    if others:
        return False
    is_admin = conn.execute("SELECT 1 FROM user_role WHERE user_id = %s AND role_key = 'admin'", (user_id,)).fetchone() is not None
    stays_admin = (new_roles is None or "admin" in new_roles) and new_status != "disabled"
    return is_admin and not stays_admin


@router.get("/users")
def list_users(request: Request, _: Principal = Depends(require("users.manage"))):
    note(request, "user.list")
    with tx() as conn:
        return [_user_view(conn, u) for u in conn.execute("SELECT * FROM app_user ORDER BY username").fetchall()]


@router.post("/users", status_code=201)
def create_user(request: Request, body: UserIn, principal: Principal = Depends(require("users.manage", step_up="users.manage"))):
    username = body.username.strip().lower()
    note(request, "user.create", objectType="user", objectKey=username)
    if not USERNAME.match(username):
        raise IpamError("IPAM-USERNAME-INVALID", "Usernames are 2-64 characters: a-z, 0-9, '.', '_', '-'")
    temp = None
    password = body.password
    if password:
        problem = password_problem(password, username)
        if problem:
            raise IpamError("IPAM-PASSWORD-WEAK", problem)
    else:
        password = temp = generate_password()
    with tx() as conn:
        roles = _check_roles(conn, body.roles)
        try:
            u = conn.execute(
                """INSERT INTO app_user (username, full_name, email, password_hash, must_change_password, created_by)
                   VALUES (%s, %s, %s, %s, true, %s) RETURNING *""",
                (username, body.fullName, body.email, hash_password(password), principal.actor_id),
            ).fetchone()
        except pg_errors.UniqueViolation as exc:
            raise IpamError("IPAM-USER-EXISTS", f"User {username} already exists", status=409) from exc
        for r in roles:
            conn.execute("INSERT INTO user_role (user_id, role_key) VALUES (%s, %s)", (u["user_id"], r))
        view = _user_view(conn, u)
    request.state.audit["changes"] = {"after": {"roles": roles, "fullName": body.fullName}}
    return {**view, "temporaryPassword": temp}


@router.patch("/users/{username}")
def update_user(request: Request, username: str, body: UserPatch, principal: Principal = Depends(require("users.manage", step_up="users.manage"))):
    note(request, "user.update", objectType="user", objectKey=username.lower())
    with tx() as conn:
        u = _get_user(conn, username, for_update=True)
        before = _user_view(conn, u)
        roles = _check_roles(conn, body.roles) if body.roles is not None else None
        if _would_orphan_admins(conn, u["user_id"], roles, body.status):
            raise IpamError("IPAM-LAST-ADMIN", "That would leave no active administrator", status=409)
        conn.execute(
            """UPDATE app_user SET full_name = coalesce(%s, full_name), email = coalesce(%s, email), status = coalesce(%s, status)
               WHERE user_id = %s""",
            (body.fullName, body.email, body.status, u["user_id"]),
        )
        if roles is not None:
            conn.execute("DELETE FROM user_role WHERE user_id = %s", (u["user_id"],))
            for r in roles:
                conn.execute("INSERT INTO user_role (user_id, role_key) VALUES (%s, %s)", (u["user_id"], r))
        if body.status == "disabled" or roles is not None:
            # Permissions are read per request, but a disabled user's sessions end now.
            if body.status == "disabled":
                conn.execute("UPDATE user_session SET state = 'revoked' WHERE user_id = %s AND state <> 'revoked'", (u["user_id"],))
        after = _user_view(conn, _get_user(conn, username))
    request.state.audit["changes"] = {"before": {k: before[k] for k in ("roles", "status", "fullName", "email")},
                                      "after": {k: after[k] for k in ("roles", "status", "fullName", "email")}}
    return after


@router.post("/users/{username}:reset-password")
def reset_password(request: Request, username: str, principal: Principal = Depends(require("users.manage", step_up="users.manage"))):
    """Issue a temporary password (shown once). The user must change it at next sign-in; their sessions end."""
    note(request, "user.reset_password", objectType="user", objectKey=username.lower())
    temp = generate_password()
    with tx() as conn:
        u = _get_user(conn, username, for_update=True)
        conn.execute(
            """UPDATE app_user SET password_hash = %s, must_change_password = true, failed_login_attempts = 0, locked_until = NULL
               WHERE user_id = %s""",
            (hash_password(temp), u["user_id"]),
        )
        conn.execute("UPDATE user_session SET state = 'revoked' WHERE user_id = %s AND state <> 'revoked'", (u["user_id"],))
    return {"username": u["username"], "temporaryPassword": temp}


@router.post("/users/{username}:reset-mfa")
def reset_mfa(request: Request, username: str, principal: Principal = Depends(require("users.manage", step_up="users.manage"))):
    """Remove the user's authenticator and backup codes (lost phone). They enrol again at next sign-in."""
    note(request, "user.reset_mfa", objectType="user", objectKey=username.lower())
    with tx() as conn:
        u = _get_user(conn, username, for_update=True)
        conn.execute("UPDATE mfa_device SET status = 'revoked' WHERE user_id = %s AND status <> 'revoked'", (u["user_id"],))
        conn.execute("DELETE FROM mfa_backup_code WHERE user_id = %s", (u["user_id"],))
        conn.execute("UPDATE app_user SET failed_mfa_attempts = 0, mfa_locked_until = NULL WHERE user_id = %s", (u["user_id"],))
        conn.execute("UPDATE user_session SET state = 'revoked' WHERE user_id = %s AND state <> 'revoked'", (u["user_id"],))
        return _user_view(conn, _get_user(conn, username))


@router.post("/users/{username}:unlock")
def unlock_user(request: Request, username: str, principal: Principal = Depends(require("users.manage", step_up="users.manage"))):
    note(request, "user.unlock", objectType="user", objectKey=username.lower())
    with tx() as conn:
        u = _get_user(conn, username, for_update=True)
        conn.execute(
            """UPDATE app_user SET failed_login_attempts = 0, locked_until = NULL, failed_mfa_attempts = 0, mfa_locked_until = NULL
               WHERE user_id = %s""",
            (u["user_id"],),
        )
        return _user_view(conn, _get_user(conn, username))


# --------------------------------------------------------------------------- #
# API keys (spec §10.4)
# --------------------------------------------------------------------------- #


class KeyIn(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "owner": "Jo Smith", "purpose": "Site Delivery Wizard server", "clientName": "SiteDeliveryWizard",
        "scopes": ["read", "sites:deploy"], "expiresInDays": 90}]})
    owner: str = Field(min_length=2, description="A named person accountable for the key")
    purpose: str = Field(min_length=3)
    clientName: str | None = None
    scopes: list[str] = Field(min_length=1)
    expiresInDays: int = Field(90, ge=1, le=365)


def _key_view(k: dict[str, Any]) -> dict[str, Any]:
    return {
        "prefix": k["prefix"], "owner": k["owner"], "purpose": k["purpose"], "clientName": k["client_name"],
        "scopes": list(k["scopes"]), "createdAt": k["created_at"], "createdBy": k["created_by"], "expiresAt": k["expires_at"],
        "revokedAt": k["revoked_at"], "lastUsedAt": k["last_used_at"], "lastUsedIp": str(k["last_used_ip"]) if k["last_used_ip"] else None,
    }


@router.get("/api-keys")
def list_keys(request: Request, _: Principal = Depends(require("apikeys.manage"))):
    note(request, "apikey.list")
    with tx() as conn:
        return [_key_view(k) for k in conn.execute("SELECT * FROM api_key ORDER BY created_at DESC").fetchall()]


@router.post("/api-keys", status_code=201)
def create_key(request: Request, body: KeyIn, principal: Principal = Depends(require("apikeys.manage", step_up="apikeys.manage"))):
    """Issue a key. The full key is returned once and never stored; only its hash is."""
    bad = [s for s in body.scopes if s not in ALL_SCOPES]
    if bad:
        raise IpamError("IPAM-SCOPE-UNKNOWN", f"Unknown scope(s): {', '.join(bad)}", validScopes=ALL_SCOPES)
    key = generate_key()
    prefix, secret = KEY_RE.match(key).groups()
    note(request, "apikey.create", objectType="api-key", objectKey=prefix)
    with tx() as conn:
        row = conn.execute(
            """INSERT INTO api_key (prefix, secret_hash, owner, purpose, client_name, scopes, expires_at, created_by)
               VALUES (%s, %s, %s, %s, %s, %s, now() + make_interval(days => %s), %s) RETURNING *""",
            (prefix, hash_secret(secret), body.owner, body.purpose, body.clientName, sorted(set(body.scopes)), body.expiresInDays, principal.actor_id),
        ).fetchone()
    request.state.audit["changes"] = {"after": {"scopes": sorted(set(body.scopes)), "owner": body.owner, "expiresInDays": body.expiresInDays}}
    return {**_key_view(row), "key": key}


@router.post("/api-keys/{prefix}:revoke")
def revoke_key(request: Request, prefix: str, principal: Principal = Depends(require("apikeys.manage", step_up="apikeys.manage"))):
    note(request, "apikey.revoke", objectType="api-key", objectKey=prefix)
    with tx() as conn:
        row = conn.execute(
            "UPDATE api_key SET revoked_at = coalesce(revoked_at, now()) WHERE prefix = %s RETURNING *", (prefix,)
        ).fetchone()
        if row is None:
            raise IpamError("IPAM-NOT-FOUND", f"No API key {prefix}", status=404)
    return _key_view(row)
